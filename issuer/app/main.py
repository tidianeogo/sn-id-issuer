"""Issuer OpenID4VCI (draft 13 / compatible Inji-Mimoto) pour la carte d'identité CEDEAO du Sénégal."""
import logging
import uuid
from contextlib import asynccontextmanager
from datetime import date, datetime, timezone
from pathlib import Path

from fastapi import Body, Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import HTTPException as FastAPIHTTPException
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.responses import JSONResponse as _JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import or_, select, text
from sqlalchemy.orm import selectinload

from .auth import (OID4VCIError, new_c_nonce, require_admin, token_scopes, validate_access_token,
                   validate_proof)
from .config import get_settings
from .credential import (CONFIG_ID, DataIntegrityError, build_credential, check_card_integrity,
                         credential_configuration)
from .crypto import DID_V1, ED25519_2020_V1, key_store, sign_credential
from .db import IdCard, IssuedCredential, Person, SessionLocal
from .enrolment import router as enrolment_router
from .offer import credential_offer, offer_links, offer_page

log = logging.getLogger("sn-id-issuer")


class JSONResponse(_JSONResponse):
    """JSON en ASCII pur (é -> \\u00e9) avec charset explicite : Mimoto (Spring RestTemplate) lit un
    « application/json » sans charset en ISO-8859-1, ce qui transformait les accents en « Ã© » dans le wallet."""
    media_type = "application/json; charset=utf-8"

    def render(self, content) -> bytes:
        import json
        return json.dumps(content, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("ascii")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
APP_DIR = Path(__file__).parent


@asynccontextmanager
async def lifespan(_app: FastAPI):
    key_store.load_or_create()
    # préchargement des modèles OCR en tâche de fond (le premier « Lire la carte » n'attend pas)
    import threading
    from .ocr import warm_up
    threading.Thread(target=warm_up, daemon=True).start()
    s = get_settings()
    log.info("Issuer prêt — DID %s — base %s", s.did, s.base)
    yield


app = FastAPI(title="Issuer CNI CEDEAO Sénégal (Inji / OID4VCI)", version="3.6.1", lifespan=lifespan,
              default_response_class=JSONResponse)
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
app.include_router(enrolment_router)


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
