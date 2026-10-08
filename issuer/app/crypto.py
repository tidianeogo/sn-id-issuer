"""Clé de l'issuer (Ed25519) et suite de signature Ed25519Signature2020 (Data Integrity, JSON-LD)."""
import copy
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import base58
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pyld import jsonld

from .config import get_settings
from .db import IssuerKey, SessionLocal

CTX_DIR = Path(__file__).parent / "contexts"
CREDENTIALS_V1 = "https://www.w3.org/2018/credentials/v1"
ED25519_2020_V1 = "https://w3id.org/security/suites/ed25519-2020/v1"
DID_V1 = "https://www.w3.org/ns/did/v1"
ED25519_PUB_MULTICODEC = b"\xed\x01"

# ---------------------------------------------------------------- JSON-LD document loader (hors ligne)
_STATIC = {
    CREDENTIALS_V1: "credentials-v1.jsonld",
    ED25519_2020_V1: "ed25519-signature-2020-v1.jsonld",
    DID_V1: "did-v1.jsonld",
}
_cache: dict[str, dict] = {}


def _load(name: str) -> dict:
    if name not in _cache:
        _cache[name] = json.loads((CTX_DIR / name).read_text())
    return _cache[name]


def document_loader(url: str, options=None):
    """Résout les contextes localement : aucun appel réseau pendant la signature."""
    if url in _STATIC:
        doc = _load(_STATIC[url])
    elif url.endswith("/contexts/sn-national-id-v1.jsonld"):
        doc = _load("sn-national-id-v1.jsonld")
    else:
        raise jsonld.JsonLdError(f"Contexte non autorisé : {url}", "jsonld.LoadDocumentError",
                                 code="loading document failed")
    return {"contextUrl": None, "documentUrl": url, "document": doc}


def canonize(doc: dict) -> bytes:
    nq = jsonld.normalize(doc, {"algorithm": "URDNA2015", "format": "application/n-quads",
                                "documentLoader": document_loader, "safe": True})
    return nq.encode()


# ---------------------------------------------------------------- gestion de la clé
def _multibase_pub(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "z" + base58.b58encode(ED25519_PUB_MULTICODEC + raw).decode()


def public_key_from_multibase(mb: str) -> Ed25519PublicKey:
    raw = base58.b58decode(mb[1:])
    assert raw[:2] == ED25519_PUB_MULTICODEC
    return Ed25519PublicKey.from_public_bytes(raw[2:])


class IssuerKeyStore:
    def __init__(self):
        self._priv: Ed25519PrivateKey | None = None
        self.public_multibase: str | None = None

    def load_or_create(self):
        s = get_settings()
        pw = s.issuer_key_passphrase.encode()
        with SessionLocal() as db:
            row = db.query(IssuerKey).filter_by(active=True).order_by(IssuerKey.created_at.desc()).first()
            if row is None:
                priv = Ed25519PrivateKey.generate()
                pem = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.BestAvailableEncryption(pw))
                row = IssuerKey(kid="key-1", public_key_multibase=_multibase_pub(priv.public_key()),
                                private_key_pem=pem, active=True)
                db.add(row)
                db.commit()
            self._priv = serialization.load_pem_private_key(row.private_key_pem, password=pw)
            self.public_multibase = row.public_key_multibase

    def sign(self, data: bytes) -> bytes:
        return self._priv.sign(data)


key_store = IssuerKeyStore()


# ---------------------------------------------------------------- Ed25519Signature2020
def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sign_credential(credential: dict) -> dict:
    s = get_settings()
    proof = {
        "type": "Ed25519Signature2020",
        "created": _now(),
        "verificationMethod": s.verification_method,
        "proofPurpose": "assertionMethod",
    }
    proof_options = {"@context": credential["@context"], **proof}
    to_sign = hashlib.sha256(canonize(proof_options)).digest() + hashlib.sha256(canonize(credential)).digest()
    proof["proofValue"] = "z" + base58.b58encode(key_store.sign(to_sign)).decode()
    signed = copy.deepcopy(credential)
    signed["proof"] = proof
    return signed


def verify_credential(vc: dict, public_multibase: str) -> bool:
    vc = copy.deepcopy(vc)
    proof = vc.pop("proof")
    value = proof.pop("proofValue")
    proof_options = {"@context": vc["@context"], **proof}
    data = hashlib.sha256(canonize(proof_options)).digest() + hashlib.sha256(canonize(vc)).digest()
    try:
        public_key_from_multibase(public_multibase).verify(base58.b58decode(value[1:]), data)
        return True
    except Exception:
        return False
