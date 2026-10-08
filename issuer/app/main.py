"""Issuer OpenID4VCI (draft 13 / compatible Inji-Mimoto) pour la carte d'identité CEDEAO du Sénégal."""
import base64
import logging
import uuid
from contextlib import asynccontextmanager
from datetime import date, datetime, timezone
from pathlib import Path

from fastapi import Body, Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import HTTPException as FastAPIHTTPException
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import or_, select, text
from sqlalchemy.orm import selectinload

from .auth import (OID4VCIError, new_c_nonce, require_admin, token_scopes, validate_access_token,
                   validate_proof)
from .config import get_settings
from .credential import (CONFIG_ID, DataIntegrityError, build_credential, check_card_integrity,
                         credential_configuration)
from .crypto import DID_V1, ED25519_2020_V1, key_store, sign_credential
from .db import ElectoralRegistration, IdCard, IssuedCredential, Person, SessionLocal
from .mrz import MRZError, consistency_errors, parse_td1
from .offer import credential_offer, offer_links, offer_page

log = logging.getLogger("sn-id-issuer")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
APP_DIR = Path(__file__).parent


@asynccontextmanager
async def lifespan(_app: FastAPI):
    key_store.load_or_create()
    s = get_settings()
    log.info("Issuer prêt — DID %s — base %s", s.did, s.base)
    yield


app = FastAPI(title="Issuer CNI CEDEAO Sénégal (Inji / OID4VCI)", version="2.0.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=APP_DIR / "static"), name="static")


@app.exception_handler(FastAPIHTTPException)
async def _http_exc(request: Request, exc: FastAPIHTTPException):
    # Erreurs OID4VCI renvoyées à plat : {"error": ..., "error_description": ...}
    body = exc.detail if isinstance(exc.detail, dict) else {"error": "error", "error_description": str(exc.detail)}
    headers = {"WWW-Authenticate": 'Bearer error="invalid_token"'} if exc.status_code == 401 else None
    return JSONResponse(body, status_code=exc.status_code, headers=headers)


# ------------------------------------------------------------------ métadonnées publiques
@app.get("/health")
def health():
    with SessionLocal() as db:
        db.execute(text("select 1"))
    return {"status": "UP"}


@app.get("/.well-known/openid-credential-issuer")
def issuer_metadata():
    s = get_settings()
    return {
        "credential_issuer": s.base,
        "authorization_servers": [s.keycloak_public_issuer],
        "credential_endpoint": f"{s.base}/v1/credential",
        "nonce_endpoint": f"{s.base}/v1/nonce",
        "display": [{"name": s.issuer_name, "locale": "fr",
                     "logo": {"url": f"{s.base}/static/logo.png", "alt_text": "Sénégal"}}],
        "credential_configurations_supported": {CONFIG_ID: credential_configuration()},
    }


@app.get("/.well-known/did.json")
def did_document():
    s = get_settings()
    vm = s.verification_method
    return JSONResponse({
        "@context": [DID_V1, ED25519_2020_V1],
        "id": s.did,
        "verificationMethod": [{"id": vm, "type": "Ed25519VerificationKey2020", "controller": s.did,
                                "publicKeyMultibase": key_store.public_multibase}],
        "assertionMethod": [vm],
        "authentication": [vm],
    }, media_type="application/did+json")


@app.get("/contexts/sn-national-id-v1.jsonld")
def sn_context():
    return FileResponse(APP_DIR / "contexts" / "sn-national-id-v1.jsonld", media_type="application/ld+json")


# ------------------------------------------------------------------ offre d'identifiant (Inji Wallet ≥ 0.22)
@app.get("/credential-offer", response_class=HTMLResponse)
def credential_offer_page():
    return HTMLResponse(offer_page(), headers={"Cache-Control": "no-store"})


@app.get("/credential-offer.json")
def credential_offer_json():
    return JSONResponse(credential_offer(), headers={"Cache-Control": "no-store"})


@app.get("/credential-offer/links")
def credential_offer_links():
    return offer_links()


# ------------------------------------------------------------------ OID4VCI
@app.post("/v1/nonce")
def nonce_endpoint():
    return JSONResponse({"c_nonce": new_c_nonce(), "c_nonce_expires_in": get_settings().c_nonce_ttl_seconds},
                        headers={"Cache-Control": "no-store"})


def _check_request(req: dict):
    cfg_id = req.get("credential_configuration_id") or req.get("credential_identifier")
    if cfg_id:
        if cfg_id != CONFIG_ID:
            raise OID4VCIError(400, "unsupported_credential_type", f"Configuration inconnue : {cfg_id}")
        return
    fmt = req.get("format")
    if fmt != "ldp_vc":
        raise OID4VCIError(400, "unsupported_credential_format", f"Format non supporté : {fmt}")
    types = (req.get("credential_definition") or {}).get("type") or []
    if "SenegalNationalIDCredential" not in types:
        raise OID4VCIError(400, "unsupported_credential_type", f"Type non supporté : {types}")


def _find_person(db, identifier: str) -> tuple[Person, IdCard]:
    ident = identifier.replace(" ", "")
    card = db.scalar(select(IdCard).options(selectinload(IdCard.person).selectinload(Person.electoral))
                     .where(or_(IdCard.card_number == ident, IdCard.nin == ident))
                     .where(IdCard.status == "ACTIVE").order_by(IdCard.date_of_issue.desc()).limit(1))
    if card is None:
        raise OID4VCIError(404, "invalid_request", "Aucune carte active enregistrée pour cet utilisateur")
    return card.person, card


@app.post("/v1/credential")
def credential_endpoint(req: dict = Body(...), claims: dict = Depends(validate_access_token)):
    s = get_settings()
    if s.credential_scope not in token_scopes(claims):
        raise OID4VCIError(403, "insufficient_scope", f"Le jeton doit porter le scope {s.credential_scope}")
    _check_request(req)
    holder_id = validate_proof(req.get("proof"), claims)

    with SessionLocal() as db:
        person, card = _find_person(db, str(claims.get(s.identity_claim, "")))
        if person.status != "ACTIVE":
            raise OID4VCIError(403, "access_denied", f"Identité au statut {person.status}")
        if card.date_of_expiry < date.today():
            raise OID4VCIError(403, "access_denied", "Carte expirée")
        try:
            check_card_integrity(person, card)
        except DataIntegrityError as e:
            log.error("Émission refusée pour %s : %s", card.card_number, e)
            raise OID4VCIError(500, "server_error", str(e))

        vc_id, unsigned = build_credential(person, card, holder_id)
        vc = sign_credential(unsigned)
        db.add(IssuedCredential(vc_id=vc_id, nin=person.nin, card_number=card.card_number,
                                configuration_id=CONFIG_ID, holder_id=holder_id,
                                keycloak_subject=claims.get("sub"), client_id=claims.get("azp"), credential=vc))
        db.commit()
    log.info("VC %s émis — NIN %s — client %s", vc_id, person.nin, claims.get("azp"))
    return JSONResponse({"format": "ldp_vc", "credential": vc, "c_nonce": new_c_nonce(),
                         "c_nonce_expires_in": s.c_nonce_ttl_seconds}, headers={"Cache-Control": "no-store"})


# ------------------------------------------------------------------ administration (rôle Keycloak issuer-admin)
class ElectoralIn(BaseModel):
    voter_number: str
    region: str | None = None
    department: str | None = None
    arrondissement: str | None = None
    commune: str | None = None
    polling_place: str | None = None
    polling_station: str | None = None


class CitizenIn(BaseModel):
    nin: str
    card_number: str = Field(description="N° de carte (espaces autorisés)")
    given_name: str
    family_name: str
    date_of_birth: date
    place_of_birth: str | None = None
    sex: str = Field(pattern="^[MF]$")
    height_cm: int | None = None
    nationality: str = "SEN"
    address: str | None = None
    date_of_issue: date
    date_of_expiry: date
    registration_center: str | None = None
    mrz: list[str] = Field(min_length=3, max_length=3, description="Les 3 lignes de la MRZ du verso")
    electoral: ElectoralIn | None = None
    photo_jpeg_base64: str | None = None


def _citizen_out(p: Person) -> dict:
    out = {k: getattr(p, k) for k in ("nin", "given_name", "family_name", "date_of_birth", "place_of_birth", "sex",
                                      "height_cm", "nationality", "address", "status")}
    out["has_photo"] = p.photo_jpeg is not None
    out["cards"] = [{k: getattr(c, k) for k in ("card_number", "date_of_issue", "date_of_expiry",
                                                "registration_center", "status")} for c in p.cards]
    e = p.electoral
    out["electoral"] = None if e is None else {k: getattr(e, k) for k in (
        "voter_number", "region", "department", "arrondissement", "commune", "polling_place", "polling_station")}
    return out


@app.get("/admin/citizens")
def list_citizens(_=Depends(require_admin)):
    with SessionLocal() as db:
        q = select(Person).options(selectinload(Person.cards), selectinload(Person.electoral)).order_by(Person.family_name)
        return [_citizen_out(p) for p in db.scalars(q)]


@app.put("/admin/citizens")
def upsert_citizen(body: CitizenIn, _=Depends(require_admin)):
    nin, card_number = body.nin.replace(" ", ""), body.card_number.replace(" ", "")
    try:
        td1 = parse_td1(body.mrz)
    except MRZError as e:
        raise HTTPException(422, f"MRZ invalide : {e}")
    errs = consistency_errors(td1, card_number=card_number, date_of_birth=body.date_of_birth,
                              date_of_expiry=body.date_of_expiry, sex=body.sex,
                              family_name=body.family_name, given_name=body.given_name)
    if errs:
        raise HTTPException(422, "MRZ incohérente avec le recto : " + ", ".join(errs))

    with SessionLocal() as db:
        p = db.get(Person, nin) or Person(nin=nin)
        for k in ("given_name", "family_name", "date_of_birth", "place_of_birth", "sex", "height_cm",
                  "nationality", "address"):
            setattr(p, k, getattr(body, k))
        if body.photo_jpeg_base64:
            p.photo_jpeg = base64.b64decode(body.photo_jpeg_base64)
        db.add(p)
        db.flush()
        c = db.get(IdCard, card_number) or IdCard(card_number=card_number, nin=nin)
        c.nin, c.date_of_issue, c.date_of_expiry = nin, body.date_of_issue, body.date_of_expiry
        c.registration_center = body.registration_center
        c.mrz_line1, c.mrz_line2, c.mrz_line3 = td1.lines
        db.add(c)
        if body.electoral:
            e = db.get(ElectoralRegistration, nin) or ElectoralRegistration(nin=nin)
            for k, v in body.electoral.model_dump().items():
                setattr(e, k, v)
            db.add(e)
        db.commit()
        db.refresh(p)
        return _citizen_out(p)


@app.get("/admin/credentials")
def list_credentials(_=Depends(require_admin)):
    with SessionLocal() as db:
        rows = db.scalars(select(IssuedCredential).order_by(IssuedCredential.issued_at.desc()).limit(200))
        return [{"id": str(r.id), "vc_id": r.vc_id, "nin": r.nin, "card_number": r.card_number,
                 "holder_id": r.holder_id, "client_id": r.client_id, "status": r.status,
                 "issued_at": r.issued_at, "revoked_at": r.revoked_at} for r in rows]


@app.post("/admin/credentials/{cred_id}/revoke")
def revoke(cred_id: str, _=Depends(require_admin)):
    try:
        key = uuid.UUID(cred_id)
    except ValueError:
        raise HTTPException(404, "Introuvable")
    with SessionLocal() as db:
        r = db.get(IssuedCredential, key)
        if not r:
            raise HTTPException(404, "Introuvable")
        r.status, r.revoked_at = "REVOKED", datetime.now(timezone.utc)
        db.commit()
        return {"id": cred_id, "status": r.status}
