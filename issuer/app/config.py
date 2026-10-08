from functools import lru_cache
from urllib.parse import urlparse, quote

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # URL publique de l'issuer (celle que voient Mimoto, Inji Web, les vérificateurs)
    public_base_url: str = "http://localhost:8000"
    # DID de l'issuer. Vide => did:web dérivé de public_base_url
    issuer_did: str = ""
    issuer_name: str = "Issuer CNI CEDEAO Sénégal (démonstration)"

    # PostgreSQL
    database_url: str = "postgresql+psycopg://issuer:issuer@postgres:5432/issuer"

    # Clé de signature Ed25519 (stockée chiffrée en base)
    issuer_key_passphrase: str = "change-me"

    # Keycloak (IAM / serveur d'autorisation)
    keycloak_public_issuer: str = "http://localhost:8080/realms/senegal"  # valeur du claim iss
    keycloak_jwks_url: str = "http://keycloak:8080/realms/senegal/protocol/openid-connect/certs"
    expected_audience: str = "sn-id-issuer"  # vide => audience non vérifiée
    identity_claim: str = "preferred_username"  # claim du jeton qui porte le n° de carte / NIN
    admin_role: str = "issuer-admin"
    # Enrôlement : comptes des titulaires (API d'administration Keycloak, réseau interne)
    realm: str = "senegal"
    keycloak_internal_url: str = "http://keycloak:8080/auth"
    issuer_backend_client_id: str = "issuer-backend"
    issuer_backend_secret: str = ""
    admin_ui_client_id: str = "issuer-admin-ui"   # client public (PKCE) de l'interface /admin/

    # OID4VCI
    credential_scope: str = "sn_national_id_vc"
    require_nonce: bool = False  # True => la preuve JWT doit contenir un c_nonce émis par l'issuer
    c_nonce_ttl_seconds: int = 600
    proof_max_age_seconds: int = 300

    @property
    def base(self) -> str:
        return self.public_base_url.rstrip("/")

    @property
    def did(self) -> str:
        if self.issuer_did:
            return self.issuer_did
        u = urlparse(self.base)
        host = quote(u.netloc, safe="")  # localhost:8000 -> localhost%3A8000
        path = [p for p in u.path.split("/") if p]
        return ":".join(["did:web", host, *path])

    @property
    def verification_method(self) -> str:
        return f"{self.did}#key-1"

    @property
    def sn_context_url(self) -> str:
        return f"{self.base}/contexts/sn-national-id-v1.jsonld"


@lru_cache
def get_settings() -> Settings:
    return Settings()
