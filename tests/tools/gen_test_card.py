"""Génère des images recto / verso SYNTHÉTIQUES d'une carte d'identité CEDEAO (Sénégal) pour tester l'OCR.

Personne fictive, mise en page approchée (libellés français, photo à gauche, MRZ TD1 au verso).
Simule une prise de vue au téléphone : carte posée sur un fond, rotation, perspective, flou, JPEG.

    python3 tests/tools/gen_test_card.py tests/e2e/data [--scan]      (Pillow requis)
"""
import random
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageFont

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "issuer"))
from app.mrz import check_digit  # noqa: E402

W, H = 1600, 1010   # format ID-1 (85,6 × 54 mm)
SANS = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
SANS_B = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"

P = dict(card="20619850412003215", card_disp="2 06 19850412 00321 5", given="FATOU BINETOU", family="KANE",
         dob="12/04/1985", sex="F", height="168 cm", pob="ZIGUINCHOR", issue="03/02/2021", expiry="02/02/2031",
         centre="DAKAR-PLATEAU", address=("12 RUE CARNOT", "DAKAR"), nin="2 045 1985 01234", voter="204518765",
         region="DAKAR", department="DAKAR", arrondissement="DAKAR PLATEAU", commune="DAKAR-PLATEAU",
         polling_place=("ECOLE MANGUIERS", "UNITE 2"), polling_station="04")


def mrz_lines(p=P) -> list[str]:
    card = p["card"]
    dob = p["dob"][8:10] + p["dob"][3:5] + p["dob"][0:2]
    exp = p["expiry"][8:10] + p["expiry"][3:5] + p["expiry"][0:2]
    l1 = f"I<SEN{card[:9]}<{card[9:]}{check_digit(card)}".ljust(30, "<")
    l2 = f"{dob}{check_digit(dob)}{p['sex']}{exp}{check_digit(exp)}SEN".ljust(29, "<")
    l2 += check_digit(l1[5:30] + l2[0:7] + l2[8:15] + l2[18:29])
    l3 = f"{p['family']}<<{p['given'].replace(' ', '<')}".ljust(30, "<")
    return [l1, l2, l3]


def _font(path, size):
    return ImageFont.truetype(path, size)


def _label(d, x, y, text):
    d.text((x, y), text, font=_font(SANS, 25), fill=(60, 70, 80))


def _value(d, x, y, text, size=36):
    d.text((x, y), text, font=_font(SANS_B, size), fill=(15, 15, 20))


def _field(d, x, y, label, value):
    """Libellé en minuscules, valeur en MAJUSCULES juste dessous (une ou deux lignes)."""
    _label(d, x, y, label)
    for i, line in enumerate(value if isinstance(value, tuple) else (value,)):
        _value(d, x, y + 30 + i * 40, line)


def _base(title, subtitle):
    im = Image.new("RGB", (W, H), (238, 240, 228))
    d = ImageDraw.Draw(im)
    for i in range(0, W + H, 7):        # guilloché léger
        d.line([(i, 0), (i - 500, H)], fill=(225, 232, 214), width=1)
    d.text((310, 8), "RÉPUBLIQUE DU SÉNÉGAL", font=_font(SANS_B, 50), fill=(40, 40, 45))
    d.text((320, 68), title, font=_font(SANS_B, 38), fill=(40, 40, 45))
    d.text((320, 116), subtitle, font=_font(SANS, 20), fill=(60, 60, 60))
    return im, d


def recto(photo: Image.Image, p=P) -> Image.Image:
    """Mise en page de la carte CEDEAO du Sénégal (recto) : photo à gauche, champs en colonne."""
    im, d = _base("CARTE D'IDENTITÉ CEDEAO", "ECOWAS IDENTITY CARD / BILHETE DE IDENTIDADE CEDEAO")
    d.ellipse([60, 20, 230, 190], outline=(150, 40, 40), width=6)            # emblème CEDEAO (simplifié)
    d.rectangle([1340, 30, 1500, 140], fill=(0, 133, 63))
    d.rectangle([1393, 30, 1447, 140], fill=(253, 239, 66))
    d.rectangle([1447, 30, 1500, 140], fill=(227, 27, 35))
    d.regular_polygon((1420, 85, 18), 5, fill=(0, 133, 63))                  # étoile verte du drapeau
    im.paste(photo.convert("RGB").resize((330, 440)), (60, 360))
    x = 490
    _field(d, x, 190, "N° de la carte d'identité", p["card_disp"])
    _field(d, x, 285, "Prénoms", p["given"])
    _field(d, x, 380, "Nom", p["family"])
    _field(d, x, 475, "Date de naissance", p["dob"])
    _field(d, 950, 475, "Sexe", p["sex"])
    _field(d, 1140, 475, "Taille", p["height"])
    _field(d, x, 570, "Lieu de naissance", p["pob"])
    _field(d, x, 665, "Date de délivrance", p["issue"])
    _field(d, 940, 665, "Date d'expiration", p["expiry"])
    _field(d, x, 760, "Centre d'enregistrement", p["centre"])
    _field(d, x, 855, "Adresse du domicile", p["address"])
    d.line([(90, 880), (330, 850)], fill=(20, 20, 90), width=4)               # signature
    return im


def verso(p=P) -> Image.Image:
    """Verso : informations électorales (libellé au-dessus ou à gauche de la valeur), NIN, MRZ TD1."""
    im = Image.new("RGB", (W, H), (244, 246, 240))
    d = ImageDraw.Draw(im)
    d.text((620, 8), "R É P U B L I Q U E   D U   S É N É G A L", font=_font(SANS, 24), fill=(0, 120, 60))
    d.text((620, 40), "INFORMATIONS ÉLECTORALES", font=_font(SANS_B, 34), fill=(0, 120, 60))
    _field(d, 40, 50, "Code Pays", "SEN")
    _label(d, 40, 148, "Numéro d'électeur")
    _value(d, 400, 136, p["voter"])
    _field(d, 40, 195, "Région", p["region"])
    _field(d, 740, 195, "Département", p["department"])
    _field(d, 40, 292, "Arrondissement", p["arrondissement"])
    _field(d, 40, 389, "Commune", p["commune"])
    _field(d, 40, 486, "Lieu de vote", p["polling_place"])
    _field(d, 1040, 482, "Bureau", p["polling_station"])
    _label(d, 537, 604, "NIN")
    _value(d, 637, 598, p["nin"], 34)
    mono = _font(MONO, 62)
    for i, line in enumerate(mrz_lines(p)):
        d.text((30, 700 + i * 95), line, font=mono, fill=(10, 10, 10))
    return im


def photographed(card: Image.Image, seed: int) -> Image.Image:
    """Carte posée sur une table et photographiée de biais."""
    rnd = random.Random(seed)
    bg = Image.new("RGB", (2100, 1600), (92, 70, 52))
    dd = ImageDraw.Draw(bg)
    for _ in range(400):            # grain du bois
        y = rnd.randint(0, 1600)
        dd.line([(0, y), (2100, y + rnd.randint(-40, 40))], fill=(80 + rnd.randint(0, 30), 60, 45), width=2)
    c = card.copy()
    c.putalpha(255)
    c = c.rotate(rnd.uniform(-6, 6), expand=True, resample=Image.BICUBIC)
    bg.paste(c, (230 + rnd.randint(-40, 40), 260 + rnd.randint(-40, 40)), c)
    w, h = bg.size                  # légère perspective
    k = rnd.uniform(0.02, 0.05)
    bg = bg.transform((w, h), Image.QUAD, (int(w * k), 0, 0, h, w, h, int(w * (1 - k)), 0), resample=Image.BICUBIC)
    bg = bg.filter(ImageFilter.GaussianBlur(0.8)).resize((1600, int(1600 * h / w)))
    return bg


if __name__ == "__main__":
    out = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    photo = Image.open(ROOT / "tests" / "e2e" / "data" / "photo-test.jpg")
    photographed(recto(photo), 1).save(out / "carte-test-recto.jpg", quality=82)
    photographed(verso(), 2).save(out / "carte-test-verso.jpg", quality=82)
    if "--scan" in sys.argv:                 # variantes « scanner » (carte seule, sans fond)
        recto(photo).save(out / "carte-test-recto-scan.png")
        verso().save(out / "carte-test-verso-scan.png")
    print("\n".join(mrz_lines()))
