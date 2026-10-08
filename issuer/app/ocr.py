"""Lecture automatique (OCR) d'une carte d'identité CEDEAO du Sénégal à partir des photos recto et verso.

Moteur : RapidOCR (Apache-2.0) avec les modèles PP-OCRv6 « small » de PaddleOCR (détection + reconnaissance,
ONNX Runtime), embarqués dans le paquet : une seule passe par face, ≈ 1 à 3 s sur un portable, texte accentué et
espaces conservés, robuste au fond guilloché. Tesseract (modèle OCR-B) ne sert plus qu'en secours pour la MRZ.
Tout est traité localement : aucune image ni donnée ne sort du serveur, et les images ne sont pas conservées.

Chaîne de traitement
  1. redressement : contour de la carte, perspective (format ID-1), orientation ;
  2. OCR de chaque face en une passe (lignes de texte + positions) ;
  3. verso : MRZ validée par les chiffres de contrôle ICAO 9303 (corrections O/0, I/1… si besoin) ;
  4. valeurs repérées sous leur libellé (« Lieu de naissance », « Commune »…), ou à sa droite (NIN, n° d'électeur) ;
  5. fusion : la MRZ fait foi pour n° de carte, nom, prénoms, sexe, dates de naissance et d'expiration ;
  6. photo : visage détecté (YuNet) sur le recto, recadré 3:4, JPEG ≤ 55 Ko.

Chaque champ renvoyé indique sa source (« mrz », « ocr », « déduit ») : l'agent vérifie avant d'enregistrer.
"""
from __future__ import annotations

import base64
import io
import itertools
import logging
import os
import re
import threading
import time
import unicodedata
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path

import cv2
import numpy as np
from PIL import Image, ImageOps

from .mrz import MRZError, TD1, check_digit, parse_td1

log = logging.getLogger("sn-id-issuer.ocr")
os.environ.setdefault("OMP_THREAD_LIMIT", "1")       # Tesseract (secours MRZ) : un seul fil OpenMP
FAST = "-c tessedit_do_invert=0"
TESSDATA = Path(__file__).parent / "ocr_data"          # mrz.traineddata (OCR-B, BSD-3), YuNet (MIT)
CARD_W, CARD_H = 1600, 1010                            # ID-1 : 85,6 × 54 mm
MAX_PHOTO_BYTES = 55_000

class OCRError(ValueError):
    pass


def fmt_card(n: str) -> str:      # mêmes formats que credential.py (module autonome, sans base de données)
    return f"{n[0]} {n[1:3]} {n[3:11]} {n[11:16]} {n[16:]}" if len(n) == 17 else n


def fmt_nin(n: str) -> str:
    return f"{n[0]} {n[1:4]} {n[4:8]} {n[8:]}" if len(n) == 13 else n


# ================================================================== images
def load_image(data: bytes) -> np.ndarray:
    try:
        im = Image.open(io.BytesIO(data))
        im = ImageOps.exif_transpose(im).convert("RGB")      # photos de téléphone : orientation EXIF
    except Exception as e:  # noqa: BLE001
        raise OCRError(f"image illisible ({e.__class__.__name__})")
    if max(im.size) > 2400:
        im.thumbnail((2400, 2400))
    if min(im.size) < 300:
        raise OCRError("image trop petite (300 px minimum)")
    return cv2.cvtColor(np.asarray(im), cv2.COLOR_RGB2BGR)


def _order(pts: np.ndarray) -> np.ndarray:
    s, d = pts.sum(axis=1), np.diff(pts, axis=1).ravel()
    return np.array([pts[np.argmin(s)], pts[np.argmin(d)], pts[np.argmax(s)], pts[np.argmax(d)]], dtype="float32")


def _quad_candidates(img: np.ndarray):
    # 1. carte posée sur un fond : écart de couleur au fond (estimé sur les bords de la photo)
    lab = cv2.cvtColor(cv2.GaussianBlur(img, (7, 7), 0), cv2.COLOR_BGR2LAB).astype(np.float32)
    border = np.concatenate([lab[:12].reshape(-1, 3), lab[-12:].reshape(-1, 3),
                             lab[:, :12].reshape(-1, 3), lab[:, -12:].reshape(-1, 3)])
    dist = np.linalg.norm(lab - np.median(border, axis=0), axis=2)
    dist = cv2.normalize(dist, None, 0, 255, cv2.NORM_MINMAX).astype(np.uint8)
    _, fg = cv2.threshold(dist, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    k = max(5, img.shape[1] // 60)
    fg = cv2.morphologyEx(fg, cv2.MORPH_CLOSE, np.ones((k, k), np.uint8))
    fg = cv2.morphologyEx(fg, cv2.MORPH_OPEN, np.ones((k, k), np.uint8))
    # 2. contours (bords nets), 3. seuillage de luminosité
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    blur = cv2.GaussianBlur(gray, (5, 5), 0)
    edges = cv2.dilate(cv2.Canny(blur, 30, 120), np.ones((7, 7), np.uint8), iterations=3)
    _, otsu = cv2.threshold(blur, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    for mask in (fg, edges, otsu, 255 - otsu):
        cnts, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        for c in sorted(cnts, key=cv2.contourArea, reverse=True)[:3]:
            yield c


def find_card(img: np.ndarray) -> tuple[np.ndarray, bool]:
    """Renvoie (carte redressée au format ID-1, carte détectée ?)."""
    h, w = img.shape[:2]
    for c in _quad_candidates(img):
        area = cv2.contourArea(c)
        if area < 0.15 * w * h or area > 0.98 * w * h:
            continue
        peri = cv2.arcLength(c, True)
        approx = cv2.approxPolyDP(c, 0.02 * peri, True)
        pts = approx.reshape(-1, 2) if len(approx) == 4 else cv2.boxPoints(cv2.minAreaRect(c))
        quad = _order(np.asarray(pts, dtype="float32"))
        tw = np.linalg.norm(quad[1] - quad[0]); th = np.linalg.norm(quad[3] - quad[0])
        ratio = max(tw, th) / max(1, min(tw, th))
        if not 1.35 < ratio < 1.85:          # ID-1 ≈ 1,585
            continue
        if th > tw:                           # carte posée en portrait : on la couche
            quad = np.roll(quad, -1, axis=0)
        m = cv2.getPerspectiveTransform(quad, np.float32([[0, 0], [CARD_W, 0], [CARD_W, CARD_H], [0, CARD_H]]))
        return cv2.warpPerspective(img, m, (CARD_W, CARD_H), flags=cv2.INTER_CUBIC), True
    # pas de contour exploitable : image supposée déjà cadrée (photo recadrée sur la carte)
    cropped = 1.4 < max(h, w) / min(h, w) < 1.8
    if h > w:
        img = cv2.rotate(img, cv2.ROTATE_90_CLOCKWISE)
    return cv2.resize(img, (CARD_W, int(CARD_W * img.shape[0] / img.shape[1])), interpolation=cv2.INTER_CUBIC), cropped


# ================================================================== MRZ
_TO_DIGIT = str.maketrans({"O": "0", "Q": "0", "D": "0", "U": "0", "I": "1", "L": "1", "T": "1", "Z": "2",
                           "S": "5", "G": "6", "B": "8", "A": "4", "E": "8", "K": "<"})
_TO_ALPHA = str.maketrans({"0": "O", "1": "I", "2": "Z", "5": "S", "6": "G", "8": "B", "4": "A"})
# gabarit TD1 par position : D code document, N chiffre, A lettre, S sexe, X chiffre ou remplissage
_TPL = ("DAAAA" + "X" * 25, "NNNNNNNSNNNNNNNAAA" + "X" * 11 + "N", "A" * 30)


def _fix(line: str, tpl: str) -> str:
    out = []
    for ch, t in zip(line, tpl):
        if t in "NX" and ch != "<":
            ch = ch.translate(_TO_DIGIT)
        elif t == "A" and ch != "<":
            ch = ch.translate(_TO_ALPHA)
        elif t == "D":
            ch = {"T": "I", "1": "I", "L": "I", "J": "I"}.get(ch, ch)
        elif t == "S":
            ch = {"H": "M", "N": "M", "P": "F", "E": "F"}.get(ch, ch)
        out.append(ch)
    return "".join(out)


def _clean_mrz_text(s: str) -> str:
    s = s.upper().replace(" ", "")
    for a in ("«", "‹", "(", "{", "[", "£", "€", "¢"):
        s = s.replace(a, "<")
    return re.sub(r"[^A-Z0-9<]", "", s)


def _fit30(line: str) -> list[str]:
    """Variantes de longueur 30 (un caractère lu en trop ou en moins)."""
    if len(line) == 30:
        return [line]
    if len(line) < 30:
        return [line.ljust(30, "<")]
    cands = [line[:30]]
    if set(line[30:]) <= {"<"}:
        return cands
    for i in range(len(line)):           # un caractère parasite
        v = line[:i] + line[i + 1:]
        if len(v) == 30:
            cands.append(v)
    return cands


def _try_parse(lines: list[str]) -> TD1 | None:
    try:
        return parse_td1(lines)
    except MRZError:
        return None


def _repair(l1: str, l2: str, l3: str) -> tuple[list[str], TD1 | None]:
    l3 = re.sub(r"K{3,}$", lambda m: "<" * len(m.group()), l3)      # remplissage lu « KKK »
    best = None
    for a, b, c in itertools.product(_fit30(l1)[:8], _fit30(l2)[:8], _fit30(l3)[:2]):
        lines = [_fix(a, _TPL[0]), _fix(b, _TPL[1]), _fix(c, _TPL[2])]
        td1 = _try_parse(lines)
        if td1:
            return lines, td1
        best = best or lines
    # dernier recours : un seul chiffre douteux par champ, corrigé par son chiffre de contrôle
    lines = best
    for li, (s, e, cdpos) in ((1, (0, 6, 6)), (1, (8, 14, 14))):
        seg, cd = lines[li][s:e], lines[li][cdpos]
        if check_digit(seg) != cd:
            for i in range(len(seg)):
                for d in "0123456789":
                    cand = seg[:i] + d + seg[i + 1:]
                    if check_digit(cand) == cd:
                        trial = list(lines)
                        trial[li] = trial[li][:s] + cand + trial[li][e:]
                        if _try_parse(trial):
                            return trial, parse_td1(trial)
    return lines, None


def _mrz_candidates(card: np.ndarray):
    h = card.shape[0]
    zone = card[int(h * 0.50):, :]
    gray = cv2.cvtColor(zone, cv2.COLOR_BGR2GRAY)
    gray = cv2.resize(gray, None, fx=1.3, fy=1.3, interpolation=cv2.INTER_CUBIC)
    yield gray
    yield cv2.threshold(cv2.GaussianBlur(gray, (3, 3), 0), 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1]
    yield cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 41, 15)


_WL = "-c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<"


def _tess_mrz(img: np.ndarray, engine: str) -> str:
    import pytesseract   # secours uniquement
    if engine == "mrz" and (TESSDATA / "mrz.traineddata").exists():
        return pytesseract.image_to_string(img, lang="mrz", config=f'--tessdata-dir "{TESSDATA}" --psm 6 {_WL} {FAST}')
    return pytesseract.image_to_string(img, lang="eng", config=f"--psm 6 {_WL} {FAST}")


def _triplet(text: str) -> list[str] | None:
    rows = [r for r in (_clean_mrz_text(x) for x in text.splitlines()) if len(r) >= 24]
    if len(rows) < 3 or sum("<<" in r for r in rows[-3:]) < 2:     # pas une MRZ (texte à l'envers, etc.)
        return None
    return rows[-3:]


def read_mrz(card: np.ndarray) -> tuple[list[str], TD1 | None, bool]:
    """Renvoie (lignes, MRZ validée ou None, zone MRZ repérée ?)."""
    triplets: list[list[str]] = []
    best: list[str] = []
    for img in _mrz_candidates(card):
        for engine in ("mrz", "eng"):              # modèle OCR-B dédié, puis modèle généraliste
            t = _triplet(_tess_mrz(img, engine))
            if not t:
                continue
            lines, td1 = _repair(*t)
            if td1:
                return lines, td1, True
            best = best or lines
            triplets.append(t)
        # lignes croisées entre lectures (chaque moteur se trompe rarement sur les mêmes caractères)
        for combo in itertools.product(*[[t[i] for t in triplets] for i in range(3)]):
            lines, td1 = _repair(*combo)
            if td1:
                return lines, td1, True
        if not triplets and img is not None:
            break                                    # aucune ligne de type MRZ : inutile d'insister
    return best, None, bool(triplets)



# ================================================================== utilitaires texte
def _norm(s: str) -> str:
    s = unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode().lower()
    return re.sub(r"[^a-z0-9]", "", s)



# ================================================================== moteur OCR (RapidOCR / PP-OCRv6)
_ENGINE = None
_ENGINE_LOCK = threading.Lock()


def engine():
    """Moteur chargé une seule fois (≈ 30 Mo de modèles), partagé et protégé par un verrou."""
    global _ENGINE
    with _ENGINE_LOCK:
        if _ENGINE is None:
            from rapidocr import RapidOCR
            threads = int(os.environ.get("OCR_THREADS", "0")) or max(1, min(4, os.cpu_count() or 2))
            _ENGINE = RapidOCR(params={"Global.log_level": "warning",
                                       "EngineConfig.onnxruntime.intra_op_num_threads": threads,
                                       "EngineConfig.onnxruntime.inter_op_num_threads": 1})
        return _ENGINE


def warm_up() -> None:
    """Charge les modèles au démarrage de l'issuer (le premier OCR n'attend pas)."""
    try:
        img = np.full((120, 480, 3), 255, np.uint8)
        cv2.putText(img, "SENEGAL 2026", (20, 80), cv2.FONT_HERSHEY_SIMPLEX, 1.6, (0, 0, 0), 3)
        engine()(img)
    except Exception as e:  # noqa: BLE001
        log.warning("Préchargement OCR impossible : %s", e)


@dataclass
class Line:
    text: str
    x0: int
    y0: int
    x1: int
    y1: int
    score: float

    @property
    def h(self) -> int:
        return max(1, self.y1 - self.y0)

    @property
    def norm(self) -> str:
        return _norm(self.text)


OCR_WIDTH = 1200     # largeur de travail : précision identique à 1600 px, ≈ 1,6 fois plus rapide


def read_lines(card: np.ndarray) -> list[Line]:
    k = OCR_WIDTH / card.shape[1]
    small = cv2.resize(card, (OCR_WIDTH, int(card.shape[0] * k)), interpolation=cv2.INTER_AREA) if k < 1 else card
    k = min(k, 1.0)
    res = engine()(small)
    out = []
    if res.boxes is None:
        return out
    for box, txt, sc in zip(res.boxes, res.txts, res.scores):
        xs, ys = [p[0] for p in box], [p[1] for p in box]
        if txt and txt.strip():
            out.append(Line(txt.strip(), int(min(xs) / k), int(min(ys) / k), int(max(xs) / k), int(max(ys) / k),
                            float(sc)))
    return sorted(out, key=lambda l: (l.y0, l.x0))


def flip_lines(lines: list[Line], w: int, h: int) -> list[Line]:
    """Carte photographiée à l'envers : le classifieur a déjà retourné le texte, on retourne les positions."""
    return sorted((Line(l.text, w - l.x1, h - l.y1, w - l.x0, h - l.y0, l.score) for l in lines),
                  key=lambda l: (l.y0, l.x0))


# ================================================================== libellés et valeurs
LABELS_RECTO = {
    "card_number": ["ndelacartedidentite", "numerodelacartedidentite", "ndelacarte"],
    "given_name": ["prenoms", "prenom"],
    "family_name": ["nom"],
    "date_of_birth": ["datedenaissance"],
    "sex": ["sexe"],
    "height": ["taille"],
    "place_of_birth": ["lieudenaissance"],
    "date_of_issue": ["datededelivrance"],
    "date_of_expiry": ["datedexpiration"],
    "registration_center": ["centredenregistrement"],
    "address": ["adressedudomicile", "adresse"],
}
LABELS_VERSO = {
    "country": ["codepays"],
    "voter_number": ["numerodelecteur", "ndelecteur", "nodelecteur"],
    "region": ["region"],
    "department": ["departement"],
    "arrondissement": ["arrondissement"],
    "commune": ["commune"],
    "polling_place": ["lieudevote"],
    "polling_station": ["bureaudevote", "bureau"],
    "nin": ["nin"],
}
MULTILINE = {"address", "polling_place"}
SAME_LINE = {"nin", "voter_number"}          # valeur imprimée à droite du libellé


def _label_match(line_norm: str, label: str) -> str | None:
    """Renvoie le reste de la ligne après le libellé (« » si la ligne n'est que le libellé), None sinon."""
    if line_norm == label:
        return ""
    if len(label) >= 6 and _lev(line_norm, label) <= 2:
        return ""
    if len(label) >= 3 and line_norm.startswith(label):
        return line_norm[len(label):]
    return None


def _find_labels(lines: list[Line], specs: dict) -> dict[str, tuple[Line, str]]:
    found: dict[str, tuple[Line, str]] = {}
    used: set[int] = set()
    for f, labels in sorted(specs.items(), key=lambda kv: -max(len(x) for x in kv[1])):   # plus longs d'abord
        for ln in lines:
            if id(ln) in used:
                continue
            for lab in labels:
                rest = _label_match(ln.norm, lab)
                if rest is None:
                    continue
                if lab in ("nom", "nin", "bureau") and rest and f not in SAME_LINE:
                    continue        # « Nom » doit être seul sur sa ligne (pas « Nombre… »)
                found[f] = (ln, rest)
                used.add(id(ln))
                break
            if f in found:
                break
    return found


def _label_lines(found) -> set[int]:
    return {id(ln) for ln, _ in found.values()}


def _value_for(f: str, label: Line, rest: str, lines: list[Line], labels: set[int]) -> str:
    h = label.h
    if rest and f in SAME_LINE:                      # « NIN 1 895 2000 01389 » sur une seule ligne
        raw = label.text
        idx = len(raw) - len(raw.lstrip())
        # retire le libellé du texte original (on garde les espaces de la valeur)
        m = re.match(r"^\s*(n\s*[°o]?\s*d.?\s*électeur|num[ée]ro\s+d.?\s*[ée]lecteur|nin)\s*[:.]?\s*", raw, re.I)
        return raw[m.end():] if m else raw[idx:]
    candidates = [l for l in lines if id(l) not in labels]
    if f in SAME_LINE:                               # valeur à droite, sur la même rangée
        right = [l for l in candidates if l.x0 > label.x1 and abs((l.y0 + l.y1) - (label.y0 + label.y1)) < 1.6 * h
                 and l.x0 - label.x1 < 20 * h]
        if right:
            return min(right, key=lambda l: l.x0).text
    below = [l for l in candidates if label.y1 - 0.4 * h <= l.y0 <= label.y1 + 2.2 * h
             and abs(l.x0 - label.x0) < 3 * h]
    if not below:
        return ""
    first = min(below, key=lambda l: l.y0)
    text = first.text
    if f in MULTILINE:
        nxt = [l for l in lines if first.y0 + 0.4 * first.h <= l.y0 <= first.y1 + 0.9 * first.h
               and abs(l.x0 - first.x0) < 3 * h and l is not first]
        nxt.sort(key=lambda l: l.y0)
        if nxt and id(nxt[0]) not in labels:
            text += " " + nxt[0].text
    return text


def read_labeled(lines: list[Line], specs: dict) -> dict[str, str]:
    found = _find_labels(lines, specs)
    labels = _label_lines(found)
    return {f: _value_for(f, ln, rest, lines, labels) for f, (ln, rest) in found.items()}


def mrz_from_lines(lines: list[Line]) -> tuple[list[str], TD1 | None, bool]:
    rows = [l for l in lines if len(_clean_mrz_text(l.text)) >= 24 and "<" in l.text]
    rows = sorted(rows, key=lambda l: l.y0)[-3:]
    if len(rows) < 3:
        return [], None, False
    lines3, td1 = _repair(*[_clean_mrz_text(l.text) for l in rows])
    return lines3, td1, True


def _side(lines: list[Line]) -> str:
    """« verso » si MRZ ou rubriques électorales, « recto » sinon."""
    t = " ".join(l.norm for l in lines)
    if sum(t.count(k) for k in ("<<", "commune", "lieudevote", "arrondissement", "electeur")) >= 2 or \
            sum("<<" in l.text for l in lines) >= 2:
        return "verso"
    return "recto"


def _upright(lines: list[Line], w: int, h: int, side: str) -> tuple[list[Line], bool]:
    """Repère une carte tête en bas : titre « RÉPUBLIQUE… » en bas, ou MRZ en haut du verso."""
    if side == "verso":
        mrz = [l for l in lines if l.text.count("<") >= 3]
        upside = bool(mrz) and sum(l.y0 for l in mrz) / len(mrz) < h * 0.4
    else:
        title = [l for l in lines if "republique" in l.norm]
        upside = bool(title) and title[0].y0 > h * 0.6
    return (flip_lines(lines, w, h), True) if upside else (lines, False)


# ================================================================== normalisation des valeurs
def _digits(s: str) -> str:
    return re.sub(r"\D", "", s.translate(str.maketrans("OoQDIl|SZB", "0000111528")))


def _num_run(s: str) -> str:
    """Premier groupe de mots numériques (« 121574303 Be » -> « 121574303 ») ; tolère O/I/l lus pour 0/1."""
    out = []
    for tok in s.split():
        t = re.sub(r"[.,;:)(\]\[]", "", tok).translate(str.maketrans("OoQDIl|", "0000111"))
        if t and sum(c.isdigit() for c in t) >= 0.7 * len(t):
            out.append(re.sub(r"\D", "", t))
        elif out:
            break
    return "".join(out)


def _date(s: str) -> date | None:
    m = re.search(r"(\d{2})\s*[/.\-]\s*(\d{2})\s*[/.\-]\s*(\d{4})", s.translate(str.maketrans("OoIl|", "00111")))
    if not m:
        return None
    try:
        return date(int(m.group(3)), int(m.group(2)), int(m.group(1)))
    except ValueError:
        return None


def _text(s: str) -> str:
    s = re.sub(r"[^A-Za-zÀ-ÿ0-9'/. \-]", " ", s)
    s = re.sub(r"(?<![A-Za-z0-9])[./]|[./](?![A-Za-z0-9])", " ", s)   # « / » et « . » isolés : bruit
    s = " ".join(t for t in s.split() if not (len(t) == 1 and not t.isascii()))   # « À » isolé : bruit
    return re.sub(r"\s+", " ", s).strip().upper()


def _lev(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _mrz_name(s: str) -> str:
    s = unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode().upper()
    return re.sub(r"[^A-Z]+", "<", s).strip("<")


def _years_back(d: date, years: int) -> date:
    try:
        return d.replace(year=d.year - years)
    except ValueError:      # 29 février
        return d.replace(year=d.year - years, day=28)


def _canon(field: str, raw: str) -> str:
    """Forme normalisée d'une valeur lue, vide si elle n'a pas la forme attendue pour ce champ."""
    if field.startswith("date_of"):
        d = _date(raw)
        return d.isoformat() if d else ""
    if field == "height":
        m = re.search(r"(?<!\d)(\d{3})(?!\d)", raw.translate(str.maketrans("OoIl", "0011")))
        return m.group(1) if m and 120 <= int(m.group(1)) <= 230 else ""
    if field == "sex":
        m = re.search(r"\b([MF])\b", raw.upper())
        return m.group(1) if m else ""
    if field == "nin":
        d = _num_run(raw)
        return d if len(d) == 13 else ""
    if field == "voter_number":
        d = _num_run(raw)
        return d if 6 <= len(d) <= 12 else ""
    if field == "polling_station":
        d = _num_run(raw)
        return d if 1 <= len(d) <= 3 else ""
    t = _text(raw)
    return t if len(re.sub(r"[^A-Z]", "", t)) >= 2 else ""


# ================================================================== analyse complète
def analyse(recto_bytes: bytes, verso_bytes: bytes) -> dict:
    t0 = time.monotonic()
    warnings: list[str] = []
    recto, recto_found = find_card(load_image(recto_bytes))
    verso, verso_found = find_card(load_image(verso_bytes))
    if not recto_found or not verso_found:
        warnings.append("Contour de la carte non détecté sur "
                        + " et ".join(n for n, ok in (("le recto", recto_found), ("le verso", verso_found)) if not ok)
                        + " : photographiez la carte entière sur un fond uni et contrasté.")

    r_lines, v_lines = read_lines(recto), read_lines(verso)
    swapped = False
    if _side(r_lines) == "verso" and _side(v_lines) == "recto":
        recto, verso, r_lines, v_lines, swapped = verso, recto, v_lines, r_lines, True
        warnings.append("Recto et verso inversés à l'import : corrigé automatiquement.")
    h, w = recto.shape[:2]
    r_lines, r_flip = _upright(r_lines, w, h, "recto")
    if r_flip:
        recto = cv2.rotate(recto, cv2.ROTATE_180)
    h, w = verso.shape[:2]
    v_lines, v_flip = _upright(v_lines, w, h, "verso")
    if v_flip:
        verso = cv2.rotate(verso, cv2.ROTATE_180)

    # MRZ : lecture du moteur principal, sinon Tesseract OCR-B en secours
    mrz_lines, td1, seen = mrz_from_lines(v_lines)
    if td1 is None:
        lines2, td2, seen2 = read_mrz(verso)
        if td2 or (seen2 and not mrz_lines):
            mrz_lines, td1 = lines2, td2
    if td1 is None:
        warnings.append("MRZ illisible : vérifiez la netteté du verso (zone des 3 lignes en bas), ou saisissez-la.")

    fields: dict[str, dict] = {}

    def put(name, value, source, conf=1.0):
        if value not in (None, ""):
            fields[name] = {"value": value, "source": source, "confidence": round(conf, 2)}

    if td1:
        if td1.issuing_state != "SEN":
            warnings.append(f"Carte émise par {td1.issuing_state} : seules les cartes du Sénégal sont acceptées.")
        put("card_number", fmt_card(td1.document_number), "mrz")
        put("family_name", td1.family_name, "mrz")
        put("given_name", td1.given_names, "mrz")
        put("sex", td1.sex, "mrz")
        put("date_of_birth", td1.date_of_birth.isoformat(), "mrz")
        put("date_of_expiry", td1.date_of_expiry.isoformat(), "mrz")
        put("nationality", td1.nationality, "mrz")
        put("mrz", "\n".join(mrz_lines), "mrz")
    elif mrz_lines:
        put("mrz", "\n".join(mrz_lines), "ocr", 0.3)

    r = read_labeled(r_lines, LABELS_RECTO)
    v = read_labeled(v_lines, LABELS_VERSO)
    recto_text = "\n".join(l.text for l in r_lines)
    verso_text = "\n".join(l.text for l in v_lines)

    # --- recto : noms (la MRZ n'a pas de chiffre de contrôle sur les noms)
    names_fixed = False
    for name in ("given_name", "family_name"):
        val = _canon(name, r.get(name, ""))
        if not val:
            continue
        mrz_val = fields.get(name, {}).get("value", "")
        label = "Prénoms" if name == "given_name" else "Nom"
        if not mrz_val:
            put(name, val, "ocr", 0.8)
        elif _norm(val) != _norm(mrz_val):
            if _norm(val).startswith(_norm(mrz_val)) and len(val) > len(mrz_val):
                put(name, val, "ocr", 0.9)        # nom tronqué dans la MRZ (30 caractères)
            elif _lev(_norm(val), _norm(mrz_val)) <= 2:
                put(name, val, "ocr", 0.8)
                names_fixed = True
                warnings.append(f"{label} : lu « {val} » au recto et « {mrz_val} » dans la MRZ — retenu : {val}.")
            else:
                warnings.append(f"{label} : la MRZ indique « {mrz_val} », le recto semble indiquer « {val} ».")
    if names_fixed and td1:
        l3 = (_mrz_name(fields["family_name"]["value"]) + "<<" + _mrz_name(fields["given_name"]["value"])).ljust(30, "<")
        if len(l3) == 30:
            mrz_lines = [mrz_lines[0], mrz_lines[1], l3]
            put("mrz", "\n".join(mrz_lines), "mrz")
    if "sex" not in fields:
        s = _canon("sex", r.get("sex", ""))
        if s:
            put("sex", s, "ocr", 0.8)
    for name in ("date_of_birth", "date_of_expiry"):
        d = _date(r.get(name, ""))
        if d and name not in fields:
            put(name, d.isoformat(), "ocr", 0.8)
        elif d and fields[name]["value"] != d.isoformat():
            warnings.append(f"{name} : le recto ({d.strftime('%d/%m/%Y')}) diffère de la MRZ.")
    hgt = _canon("height", r.get("height", ""))
    if hgt:
        put("height_cm", int(hgt), "ocr", 0.9)
    for name in ("place_of_birth", "registration_center", "address"):
        val = _canon(name, r.get(name, ""))
        if val:
            put(name, val, "ocr", 0.9)
    if "card_number" not in fields:
        digits = _digits(r.get("card_number", ""))
        if len(digits) == 17:
            put("card_number", fmt_card(digits), "ocr", 0.7)

    # date de délivrance : libellé, sinon expiration − 10 ans + 1 jour
    d_issue = _date(r.get("date_of_issue", ""))
    if d_issue:
        put("date_of_issue", d_issue.isoformat(), "ocr", 0.9)
    elif "date_of_expiry" in fields:
        exp = date.fromisoformat(fields["date_of_expiry"]["value"])
        put("date_of_issue", (_years_back(exp, 10) + timedelta(days=1)).isoformat(), "déduit", 0.4)
        warnings.append("Date de délivrance non lue : déduite de la date d'expiration (validité de 10 ans).")

    # --- verso
    nin = _canon("nin", v.get("nin", ""))
    if not nin:
        m = re.search(r"\b[12]\s?\d{3}\s?\d{4}\s?\d{5}\b", verso_text.translate(str.maketrans("OoIl", "0011")))
        nin = _digits(m.group()) if m else ""
    if len(nin) == 13:
        put("nin", fmt_nin(nin), "ocr", 0.9)
    voter = _canon("voter_number", v.get("voter_number", ""))
    if voter:
        put("voter_number", voter, "ocr", 0.9)
    for name in ("region", "department", "arrondissement", "commune", "polling_place"):
        val = _canon(name, v.get(name, ""))
        if val:
            put(name, val, "ocr", 0.9)
    st = _canon("polling_station", v.get("polling_station", ""))
    if st:
        put("polling_station", st.zfill(2), "ocr", 0.9)

    photo, photo_src = extract_photo(recto)
    values = {k: f["value"] for k, f in fields.items()}
    return {
        "values": values,
        "fields": fields,
        "mrz": {"lines": mrz_lines, "valid": td1 is not None},
        "photo_jpeg_base64": photo,
        "photo_source": photo_src,
        "card_detected": {"recto": recto_found, "verso": verso_found},
        "swapped": swapped,
        "warnings": warnings,
        "missing": [f for f in ("card_number", "given_name", "family_name", "date_of_birth", "sex", "date_of_issue",
                                "date_of_expiry", "nin", "mrz") if f not in values],
        "engine": "RapidOCR PP-OCRv6",
        "duration_ms": int((time.monotonic() - t0) * 1000),
    }


# ================================================================== photo
_FACE = None


def _face_cascade():
    global _FACE
    if _FACE is None and hasattr(cv2, "CascadeClassifier"):
        _FACE = cv2.CascadeClassifier(str(Path(cv2.data.haarcascades) / "haarcascade_frontalface_default.xml"))
    return _FACE


def _jpeg(img: np.ndarray) -> str:
    im = Image.fromarray(cv2.cvtColor(img, cv2.COLOR_BGR2RGB)).resize((240, 320), Image.LANCZOS)
    for q in (88, 80, 72, 64, 56, 48, 40):
        buf = io.BytesIO()
        im.save(buf, "JPEG", quality=q, optimize=True)
        if buf.tell() <= MAX_PHOTO_BYTES:
            break
    return base64.b64encode(buf.getvalue()).decode()


def _faces_yunet(img: np.ndarray) -> list[tuple[int, int, int, int]]:
    model = TESSDATA / "face_detection_yunet_2023mar.onnx"
    if not model.exists() or not hasattr(cv2, "FaceDetectorYN"):
        return []
    h, w = img.shape[:2]
    k = 640 / max(h, w)
    small = cv2.resize(img, (int(w * k), int(h * k)))
    det = cv2.FaceDetectorYN.create(str(model), "", (small.shape[1], small.shape[0]), 0.6, 0.3, 50)
    _, faces = det.detect(small)
    if faces is None:
        return []
    return [tuple(int(v / k) for v in f[:4]) for f in faces]


def extract_photo(recto: np.ndarray) -> tuple[str | None, str]:
    """Photo du titulaire : visage le plus grand de la moitié gauche du recto (YuNet, sinon Haar),
    recadrage portrait 3:4 ; à défaut, zone photo de la mise en page de la carte."""
    h, w = recto.shape[:2]
    left = recto[:, : int(w * 0.45)]
    faces = _faces_yunet(left)
    if not faces:
        cascade = _face_cascade()
        if cascade is not None:
            gray = cv2.equalizeHist(cv2.cvtColor(left, cv2.COLOR_BGR2GRAY))
            faces = [tuple(f) for f in cascade.detectMultiScale(gray, 1.1, 5, minSize=(int(h * 0.12),) * 2)]
    faces = [f for f in faces if f[3] > 0.1 * h]
    if faces:
        x, y, fw, fh = max(faces, key=lambda f: f[2] * f[3])
        cx, cy = x + fw / 2, y + fh * 0.62
        ch = fh * 2.3
        cw = ch * 3 / 4
        x0, y0 = int(max(0, cx - cw / 2)), int(max(0, cy - ch / 2))
        x1, y1 = int(min(left.shape[1], cx + cw / 2)), int(min(h, cy + ch / 2))
        return _jpeg(left[y0:y1, x0:x1]), "visage"
    # mise en page de la carte CEDEAO du Sénégal : photo à gauche, du tiers à 83 % de la hauteur
    ch = int(h * 0.48)
    cw = int(ch * 3 / 4)
    cx, y0 = int(w * 0.14), int(h * 0.35)
    return _jpeg(recto[y0:y0 + ch, max(0, cx - cw // 2):cx + cw // 2]), "zone"
