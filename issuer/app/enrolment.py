"""Module d'enrôlement : ajout de cartes d'identité CEDEAO (Sénégal) d'autres titulaires.

Interface web : GET /admin/  (connexion Keycloak, rôle issuer-admin)
API (jeton Bearer, rôle issuer-admin) :
  POST  /admin/ocr                             lecture automatique des photos recto + verso (multipart)
  POST  /admin/mrz/parse                       lecture + contrôle d'une MRZ TD1 (pré-remplissage du formulaire)
  POST  /admin/citizens/validate               contrôles complets sans écriture (erreurs + avertissements)
  PUT   /admin/citizens                        création / mise à jour d'un titulaire et de sa carte
                                               (+ compte Keycloak identifiant = NIN, mot de passe temporaire)
  GET   /admin/citizens                        liste (avec état du compte Keycloak)
  GET   /admin/citizens/{nin}/photo            photo JPEG
  PATCH /admin/citizens/{nin}                  statut ACTIVE / SUSPENDED / DECEASED (compte activé / désactivé)
  POST  /admin/citizens/{nin}/account          crée le compte ou réinitialise son mot de passe temporaire
  PATCH /admin/cards/{card_number}             statut de la carte ACTIVE / LOST / REVOKED
"""
import base64
import binascii
import logging
import re
from datetime import date
from pathlib import Path

from fastapi import APIRouter, Body, Depends, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, RedirectResponse, Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from . import keycloak_admin as kc
from .auth import require_admin
from .config import get_settings
from .credential import fmt_card, fmt_nin
from .db import ElectoralRegistration, IdCard, Person, SessionLocal
from .mrz import MRZError, consistency_errors, parse_td1

log = logging.getLogger("sn-id-issuer.enrolment")
router = APIRouter()
UI = Path(__file__).parent / "static" / "admin"
MAX_PHOTO_BYTES = 60_000   # la photo est embarquée dans le VC (data: URI) : rester léger pour le wallet


def _err(status: int, message: str, fields: dict[str, str] | None = None):
    raise HTTPException(status, {"error": "invalid_request", "error_description": message, "fields": fields or {}})


def _digits(v: str) -> str:
    return re.sub(r"[\s.-]", "", v or "")


# ------------------------------------------------------------------ modèles
class ElectoralIn(BaseModel):
    voter_number: str
    region: str | None = None
    department: str | None = None
    arrondissement: str | None = None
    commune: str | None = None
    polling_place: str | None = None
    polling_station: str | None = None

    @field_validator("*", mode="before")
    @classmethod
    def _upper(cls, v):
        return v.strip().upper() or None if isinstance(v, str) else v


class CitizenIn(BaseModel):
    nin: str = Field(description="NIN imprimé au verso (13 chiffres, espaces autorisés)")
    card_number: str = Field(description="N° de carte imprimé au recto (17 chiffres, espaces autorisés)")
    given_name: str
    family_name: str
    date_of_birth: date
    place_of_birth: str | None = None
    sex: str = Field(pattern="^[MF]$")
    height_cm: int | None = Field(default=None, ge=50, le=250)
    nationality: str = "SEN"
    address: str | None = None
    date_of_issue: date
    date_of_expiry: date
    registration_center: str | None = None
    mrz: list[str] = Field(min_length=3, max_length=3, description="Les 3 lignes de la MRZ du verso")
    electoral: ElectoralIn | None = None
    photo_jpeg_base64: str | None = None
    create_account: bool = Field(default=True, description="Créer le compte Keycloak du titulaire (NIN)")

    @field_validator("given_name", "family_name", "place_of_birth", "address", "registration_center",
                     "nationality", mode="before")
    @classmethod
    def _clean(cls, v):
        return re.sub(r"\s+", " ", v).strip().upper() or None if isinstance(v, str) else v

    @field_validator("nin", "card_number", mode="before")
    @classmethod
    def _nums(cls, v):
        return _digits(v) if isinstance(v, str) else v


class StatusIn(BaseModel):
    status: str


# ------------------------------------------------------------------ contrôles
def _photo_bytes(b64: str | None) -> bytes | None:
    if not b64:
        return None
    if b64.startswith("data:"):
        b64 = b64.split(",", 1)[-1]
    try:
        raw = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        _err(422, "Photo illisible (base64 invalide)", {"photo": "base64 invalide"})
    if raw[:3] != b"\xff\xd8\xff":
        _err(422, "La photo doit être au format JPEG", {"photo": "JPEG attendu"})
    if len(raw) > MAX_PHOTO_BYTES:
        _err(422, f"Photo trop lourde ({len(raw) // 1024} Ko > {MAX_PHOTO_BYTES // 1024} Ko)", {"photo": "trop lourde"})
    return raw


def check_citizen(body: CitizenIn) -> tuple[list[str], dict[str, str], list[str]]:
    """Renvoie (lignes MRZ normalisées, erreurs par champ, avertissements)."""
    errors: dict[str, str] = {}
    warnings: list[str] = []
    if not re.fullmatch(r"\d{13}", body.nin):
        errors["nin"] = "13 chiffres attendus (ex. 1 123 1990 00077)"
    if not re.fullmatch(r"\d{17}", body.card_number):
        errors["card_number"] = "17 chiffres attendus (ex. 1 05 19900315 00077 3)"
    if not body.given_name:
        errors["given_name"] = "obligatoire"
    if not body.family_name:
        errors["family_name"] = "obligatoire"
    if body.date_of_birth >= body.date_of_issue:
        errors["date_of_birth"] = "doit précéder la date de délivrance"
    if body.date_of_expiry <= body.date_of_issue:
        errors["date_of_expiry"] = "doit suivre la date de délivrance"
    if body.date_of_birth > date.today():
        errors["date_of_birth"] = "date future"
    if body.electoral and not re.fullmatch(r"\d{6,12}", body.electoral.voter_number or ""):
        errors["voter_number"] = "numéro d'électeur : 6 à 12 chiffres"

    lines: list[str] = []
    try:
        td1 = parse_td1(body.mrz)
        lines = list(td1.lines)
        if td1.issuing_state != "SEN":
            errors["mrz"] = f"pays émetteur {td1.issuing_state} : seules les cartes du Sénégal sont acceptées"
        bad = consistency_errors(td1, card_number=body.card_number, date_of_birth=body.date_of_birth,
                                 date_of_expiry=body.date_of_expiry, sex=body.sex,
                                 family_name=body.family_name or "", given_name=body.given_name or "")
        if bad:
            errors["mrz"] = "MRZ incohérente avec le recto : " + ", ".join(bad)
    except MRZError as e:
        errors["mrz"] = f"MRZ invalide : {e}"

    # Contrôles indicatifs sur la structure des numéros (avertissements, non bloquants)
    if "nin" not in errors:
        if body.nin[4:8] != f"{body.date_of_birth.year:04d}":
            warnings.append(f"NIN : l'année {body.nin[4:8]} ne correspond pas à l'année de naissance")
        if body.nin[0] != {"M": "1", "F": "2"}[body.sex]:
            warnings.append("NIN : le 1er chiffre ne correspond pas au sexe (1 = M, 2 = F)")
    if "card_number" not in errors and body.card_number[3:11] != body.date_of_birth.strftime("%Y%m%d"):
        warnings.append("N° de carte : la date AAAAMMJJ incluse ne correspond pas à la date de naissance")
    if body.date_of_expiry < date.today():
        warnings.append("Carte expirée : elle sera enregistrée mais aucun VC ne pourra être émis")
    return lines, errors, warnings


def _conflicts(db, body: CitizenIn) -> dict[str, str]:
    out = {}
    other = db.get(IdCard, body.card_number)
    if other is not None and other.nin != body.nin:
        out["card_number"] = f"déjà enregistrée pour le NIN {fmt_nin(other.nin)}"
    if body.electoral:
        e = db.scalar(select(ElectoralRegistration).where(
            ElectoralRegistration.voter_number == body.electoral.voter_number))
        if e is not None and e.nin != body.nin:
            out["voter_number"] = f"déjà attribué au NIN {fmt_nin(e.nin)}"
    return out


# ------------------------------------------------------------------ sorties
def _citizen_out(p: Person, accounts: dict[str, dict] | None = None) -> dict:
    out = {k: getattr(p, k) for k in ("nin", "given_name", "family_name", "date_of_birth", "place_of_birth", "sex",
                                      "height_cm", "nationality", "address", "status")}
    out["nin_display"] = fmt_nin(p.nin)
    out["has_photo"] = p.photo_jpeg is not None
    out["cards"] = [{**{k: getattr(c, k) for k in ("card_number", "date_of_issue", "date_of_expiry",
                                                   "registration_center", "status")},
                     "card_number_display": fmt_card(c.card_number),
                     "mrz": [c.mrz_line1, c.mrz_line2, c.mrz_line3]} for c in p.cards]
    e = p.electoral
    out["electoral"] = None if e is None else {k: getattr(e, k) for k in (
        "voter_number", "region", "department", "arrondissement", "commune", "polling_place", "polling_station")}
    if accounts is not None:
        u = accounts.get(p.nin)
        out["account"] = {"exists": u is not None, "enabled": bool(u and u.get("enabled"))}
    return out


def _load(db, nin: str) -> Person:
    p = db.scalar(select(Person).options(selectinload(Person.cards), selectinload(Person.electoral))
                  .where(Person.nin == nin))
    if p is None:
        raise HTTPException(404, {"error": "not_found", "error_description": "Titulaire introuvable"})
    return p


# ------------------------------------------------------------------ interface web
@router.get("/admin", include_in_schema=False)
def admin_root():
    return RedirectResponse("/admin/")


@router.get("/admin/", include_in_schema=False)
def admin_ui():
    return FileResponse(UI / "index.html", headers={"Cache-Control": "no-store"})


@router.get("/admin/app.js", include_in_schema=False)
def admin_js():
    return FileResponse(UI / "app.js", media_type="text/javascript", headers={"Cache-Control": "no-store"})


@router.get("/admin/config")
def admin_config():
    """Paramètres publics de connexion de l'interface (aucune donnée sensible)."""
    s = get_settings()
    return {"authority": s.keycloak_public_issuer, "client_id": s.admin_ui_client_id, "public_url": s.base,
            "offer_url": f"{s.base}/credential-offer", "admin_role": s.admin_role,
            "accounts_enabled": bool(s.issuer_backend_secret)}


# ------------------------------------------------------------------ API
MAX_UPLOAD = 15 * 1024 * 1024


@router.post("/admin/ocr")
def ocr_card(recto: UploadFile = File(..., description="Photo du recto"),
             verso: UploadFile = File(..., description="Photo du verso (avec la MRZ)"),
             claims: dict = Depends(require_admin)):
    """OCR local (Tesseract) : renvoie les valeurs lues, leur source (mrz / ocr / déduit) et la photo extraite.
    Rien n'est enregistré : l'agent vérifie puis enregistre avec PUT /admin/citizens. Les images ne sont pas conservées."""
    from . import ocr   # import différé : OpenCV n'est chargé qu'au premier usage
    data = {}
    for name, f in (("recto", recto), ("verso", verso)):
        raw = f.file.read(MAX_UPLOAD + 1)
        if len(raw) > MAX_UPLOAD:
            _err(413, f"Image du {name} trop lourde (15 Mo maximum)", {name: "trop lourde"})
        if not raw:
            _err(422, f"Image du {name} manquante", {name: "manquante"})
        data[name] = raw
    try:
        result = ocr.analyse(data["recto"], data["verso"])
    except ocr.OCRError as e:
        _err(422, f"Lecture impossible : {e}", {})
    log.info("OCR de carte par %s : MRZ %s, %d champs, %d ms", claims.get("preferred_username"),
             "valide" if result["mrz"]["valid"] else "illisible", len(result["values"]), result["duration_ms"])
    return result


@router.post("/admin/mrz/parse")
def mrz_parse(mrz: list[str] | str = Body(..., embed=True), _=Depends(require_admin)):
    try:
        td1 = parse_td1(mrz)
    except MRZError as e:
        _err(422, f"MRZ invalide : {e}", {"mrz": str(e)})
    return {"lines": list(td1.lines), "document_code": td1.document_code, "issuing_state": td1.issuing_state,
            "card_number": td1.document_number, "card_number_display": fmt_card(td1.document_number),
            "date_of_birth": td1.date_of_birth, "date_of_expiry": td1.date_of_expiry, "sex": td1.sex,
            "nationality": td1.nationality, "family_name": td1.family_name, "given_name": td1.given_names}


@router.post("/admin/citizens/validate")
def validate_citizen(body: CitizenIn, _=Depends(require_admin)):
    _photo_bytes(body.photo_jpeg_base64)
    lines, errors, warnings = check_citizen(body)
    with SessionLocal() as db:
        errors.update(_conflicts(db, body))
        exists = db.get(Person, body.nin) is not None
    return {"valid": not errors, "errors": errors, "warnings": warnings, "mrz": lines, "existing_citizen": exists}


@router.get("/admin/citizens")
def list_citizens(_=Depends(require_admin)):
    try:
        accounts = kc.all_users() if get_settings().issuer_backend_secret else None
    except kc.KeycloakAdminError as e:
        log.warning("Liste des comptes Keycloak indisponible : %s", e)
        accounts = None
    with SessionLocal() as db:
        q = select(Person).options(selectinload(Person.cards), selectinload(Person.electoral)).order_by(
            Person.family_name, Person.given_name)
        return [_citizen_out(p, accounts) for p in db.scalars(q)]


@router.put("/admin/citizens")
def upsert_citizen(body: CitizenIn, claims: dict = Depends(require_admin)):
    photo = _photo_bytes(body.photo_jpeg_base64)
    lines, errors, warnings = check_citizen(body)
    if errors:
        mrz_msg = errors.get("mrz", "")
        _err(422, mrz_msg if mrz_msg and len(errors) == 1 else "Formulaire incomplet ou incohérent : "
             + "; ".join(f"{k} : {v}" for k, v in errors.items()), errors)
    nin, card_number = body.nin, body.card_number

    with SessionLocal() as db:
        conflicts = _conflicts(db, body)
        if conflicts:
            _err(409, "Conflit : " + "; ".join(conflicts.values()), conflicts)
        created = db.get(Person, nin) is None
        p = db.get(Person, nin) or Person(nin=nin)
        for k in ("given_name", "family_name", "date_of_birth", "place_of_birth", "sex", "height_cm", "address"):
            setattr(p, k, getattr(body, k))
        p.nationality = body.nationality or "SEN"
        if photo:
            p.photo_jpeg = photo
        db.add(p)
        db.flush()
        c = db.get(IdCard, card_number) or IdCard(card_number=card_number, nin=nin)
        c.nin, c.date_of_issue, c.date_of_expiry = nin, body.date_of_issue, body.date_of_expiry
        c.registration_center, c.issuing_country = body.registration_center, "SEN"
        c.mrz_line1, c.mrz_line2, c.mrz_line3 = lines
        db.add(c)
        if body.electoral:
            e = db.get(ElectoralRegistration, nin) or ElectoralRegistration(nin=nin)
            for k, v in body.electoral.model_dump().items():
                setattr(e, k, v)
            db.add(e)
        db.commit()
        p = _load(db, nin)
        status = p.status

    account = None
    if body.create_account:
        account = _ensure_account(p, reset_password=False, enabled=status == "ACTIVE")
    log.info("Enrôlement %s du NIN %s (carte %s) par %s", "création" if created else "mise à jour", nin,
             card_number, claims.get("preferred_username"))
    return {**_citizen_out(p), "created": created, "warnings": warnings, "account": account}


def _ensure_account(p: Person, reset_password: bool, enabled: bool = True) -> dict:
    try:
        user, created = kc.ensure_user(p.nin, p.given_name, p.family_name, enabled=enabled)
        pwd = kc.set_temporary_password(user["id"]) if (created or reset_password) else None
    except kc.KeycloakAdminError as e:
        log.error("Compte Keycloak du NIN %s : %s", p.nin, e)
        return {"username": p.nin, "created": False, "error": str(e)}
    return {"username": p.nin, "created": created, "enabled": user.get("enabled"), "temporary_password": pwd}


@router.post("/admin/citizens/{nin}/account")
def account_reset(nin: str, _=Depends(require_admin)):
    with SessionLocal() as db:
        p = _load(db, _digits(nin))
    acc = _ensure_account(p, reset_password=True, enabled=p.status == "ACTIVE")
    if acc.get("error"):
        raise HTTPException(502, {"error": "keycloak_error", "error_description": acc["error"]})
    return acc


@router.get("/admin/citizens/{nin}/photo")
def citizen_photo(nin: str, _=Depends(require_admin)):
    with SessionLocal() as db:
        p = _load(db, _digits(nin))
        if not p.photo_jpeg:
            raise HTTPException(404, {"error": "not_found", "error_description": "Pas de photo"})
        return Response(p.photo_jpeg, media_type="image/jpeg", headers={"Cache-Control": "no-store"})


@router.patch("/admin/citizens/{nin}")
def citizen_status(nin: str, body: StatusIn, _=Depends(require_admin)):
    if body.status not in ("ACTIVE", "SUSPENDED", "DECEASED"):
        _err(422, "Statut attendu : ACTIVE, SUSPENDED ou DECEASED", {"status": "invalide"})
    with SessionLocal() as db:
        p = _load(db, _digits(nin))
        p.status = body.status
        db.commit()
        p = _load(db, p.nin)
    account_sync = None
    if get_settings().issuer_backend_secret:
        try:
            account_sync = kc.set_enabled(p.nin, body.status == "ACTIVE")
        except kc.KeycloakAdminError as e:
            log.error("Synchronisation du compte %s : %s", p.nin, e)
            account_sync = False
    return {**_citizen_out(p), "account_synced": account_sync}


@router.patch("/admin/cards/{card_number}")
def card_status(card_number: str, body: StatusIn, _=Depends(require_admin)):
    if body.status not in ("ACTIVE", "LOST", "REVOKED"):
        _err(422, "Statut attendu : ACTIVE, LOST ou REVOKED", {"status": "invalide"})
    with SessionLocal() as db:
        c = db.get(IdCard, _digits(card_number))
        if c is None:
            raise HTTPException(404, {"error": "not_found", "error_description": "Carte introuvable"})
        c.status = body.status
        db.commit()
        return {"card_number": c.card_number, "status": c.status}
