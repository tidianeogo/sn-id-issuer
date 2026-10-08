"""Validation du jeton d'accès Keycloak et de la preuve de possession (proof JWT OID4VCI)."""
import base64
import json
import secrets
import time
from datetime import datetime, timedelta, timezone

import jwt
from cryptography.exceptions import InvalidSignature
from fastapi import Depends, Header, HTTPException
from jwt import PyJWK, PyJWKClient

from .config import get_settings
from .db import CNonce, SessionLocal

_jwks_client: PyJWKClient | None = None
# Algorithmes acceptés pour la preuve de possession (Mimoto 0.22 et Inji Wallet 0.22 inclus)
SUPPORTED_PROOF_ALGS = {"ES256", "ES256K", "RS256", "PS256", "EdDSA", "Ed25519"}


def _jwks() -> PyJWKClient:
    global _jwks_client
    if _jwks_client is None:
        _jwks_client = PyJWKClient(get_settings().keycloak_jwks_url, cache_keys=True, lifespan=300)
    return _jwks_client


class OID4VCIError(HTTPException):
    def __init__(self, status: int, error: str, description: str, **extra):
        super().__init__(status_code=status, detail={"error": error, "error_description": description, **extra})


# ---------------------------------------------------------------- jeton d'accès Keycloak
def validate_access_token(authorization: str | None = Header(default=None)) -> dict:
    s = get_settings()
    if not authorization or not authorization.lower().startswith("bearer "):
        raise OID4VCIError(401, "invalid_token", "Jeton Bearer manquant")
    token = authorization.split(" ", 1)[1]
    try:
        key = _jwks().get_signing_key_from_jwt(token).key
        options = {"verify_aud": bool(s.expected_audience), "require": ["exp", "iat", "iss", "sub"]}
        return jwt.decode(token, key, algorithms=["RS256", "RS384", "RS512", "PS256", "ES256", "EdDSA"],
                          issuer=s.keycloak_public_issuer, audience=s.expected_audience or None,
                          options=options, leeway=30)
    except jwt.PyJWTError as e:
        raise OID4VCIError(401, "invalid_token", f"Jeton invalide : {e}")


def token_scopes(claims: dict) -> set[str]:
    return set((claims.get("scope") or "").split())


def require_admin(claims: dict = Depends(validate_access_token)) -> dict:
    roles = set(claims.get("realm_access", {}).get("roles", []))
    if get_settings().admin_role not in roles:
        raise HTTPException(403, "Rôle administrateur requis")
    return claims


# ---------------------------------------------------------------- c_nonce
def new_c_nonce() -> str:
    s = get_settings()
    n = secrets.token_urlsafe(24)
    with SessionLocal() as db:
        db.add(CNonce(nonce=n, expires_at=datetime.now(timezone.utc) + timedelta(seconds=s.c_nonce_ttl_seconds)))
        db.commit()
    return n


def _consume_nonce(n: str) -> bool:
    with SessionLocal() as db:
        row = db.get(CNonce, n)
        if not row or row.used or row.expires_at < datetime.now(timezone.utc):
            return False
        row.used = True
        db.commit()
        return True


# ---------------------------------------------------------------- proof JWT
def _b64url(d: bytes) -> str:
    return base64.urlsafe_b64encode(d).rstrip(b"=").decode()


def _jwk_from_did_jwk(kid: str) -> dict:
    did = kid.split("#")[0]
    if not did.startswith("did:jwk:"):
        raise ValueError("seuls did:jwk et jwk sont acceptés")
    enc = did[len("did:jwk:"):]
    return json.loads(base64.urlsafe_b64decode(enc + "=" * (-len(enc) % 4)))


def validate_proof(proof: dict | None, access_claims: dict) -> str:
    """Valide la preuve de possession et renvoie l'identifiant du détenteur (did:jwk)."""
    s = get_settings()
    if not proof or proof.get("proof_type") != "jwt" or not proof.get("jwt"):
        raise OID4VCIError(400, "invalid_proof", "proof.proof_type=jwt attendu", c_nonce=new_c_nonce(),
                           c_nonce_expires_in=s.c_nonce_ttl_seconds)
    token = proof["jwt"]
    try:
        header = jwt.get_unverified_header(token)
        if header.get("typ") != "openid4vci-proof+jwt":
            raise ValueError("typ doit valoir openid4vci-proof+jwt")
        if "jwk" in header:
            jwk = header["jwk"]
        elif "kid" in header:
            jwk = _jwk_from_did_jwk(header["kid"])
        else:
            raise ValueError("en-tête jwk ou kid (did:jwk) requis")
        if "d" in jwk:
            raise ValueError("la clé publique ne doit pas contenir de partie privée")
        alg = header.get("alg")
        if alg not in SUPPORTED_PROOF_ALGS:
            raise ValueError(f"alg {alg} non supporté")
        audience = [s.base, s.base + "/"]
        if alg == "Ed25519":
            # « Ed25519 » (RFC 9864, Nimbus ≥ 10 / Mimoto) = EdDSA sur Ed25519, inconnu de PyJWT :
            # vérification explicite de la signature, puis contrôle des claims.
            signing_input, _, sig = token.rpartition(".")
            PyJWK(jwk, algorithm="EdDSA").key.verify(base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4)),
                                                     signing_input.encode())
            claims = jwt.decode(token, options={"verify_signature": False, "verify_aud": True, "verify_exp": True,
                                                "require": ["iat", "aud"]}, audience=audience, leeway=30)
        else:
            key = PyJWK(jwk, algorithm=alg)
            claims = jwt.decode(token, key.key, algorithms=[alg], audience=audience,
                                options={"require": ["iat", "aud"]}, leeway=30)
        if abs(time.time() - claims["iat"]) > s.proof_max_age_seconds:
            raise ValueError("iat hors fenêtre")
        nonce = claims.get("nonce")
        if nonce:
            if not _consume_nonce(nonce):
                raise ValueError("c_nonce inconnu, expiré ou déjà utilisé")
        elif s.require_nonce:
            raise ValueError("c_nonce requis")
    except (jwt.PyJWTError, ValueError, KeyError, InvalidSignature) as e:
        raise OID4VCIError(400, "invalid_proof", f"Preuve invalide : {e}", c_nonce=new_c_nonce(),
                           c_nonce_expires_in=s.c_nonce_ttl_seconds)
    public = {k: v for k, v in jwk.items() if k in ("kty", "crv", "x", "y", "n", "e")}
    return "did:jwk:" + _b64url(json.dumps(public, separators=(",", ":")).encode())
