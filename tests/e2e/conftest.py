"""Outillage commun des tests de bout en bout (pile docker compose démarrée).

Les clients de test reproduisent, d'après leur code source, les composants Inji réels :
  - MimotoLikeClient : Mimoto 0.22 (IdpServiceImpl, JoseUtil, CredentialRequestServiceImpl, SigningKeyUtil,
    LdpVcCredentialFormatHandler, IssuerConfigUtil) piloté comme le fait Inji Web 0.17 (api.ts) ;
  - InjiWalletOfferClient : Inji Wallet 0.22 en flux « offre d'identifiant » (VciClient.ts,
    IssuersService.ts, shared/openId4VCI/Utils.ts constructProofJWT).
"""
import base64
import hashlib
import html
import json
import os
import re
import secrets
import shlex
import subprocess
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlencode, urlparse

import jwt
import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from jwt.algorithms import ECAlgorithm, OKPAlgorithm, RSAAlgorithm

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "issuer"))  # pour app.mrz (génération de MRZ de test)


def _env_file() -> dict:
    env = {}
    f = ROOT / ".env"
    if f.exists():
        for line in f.read_text().splitlines():
            if line.strip() and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    return env


ENV = {**_env_file(), **os.environ}
PUBLIC_URL = ENV.get("PUBLIC_URL", "http://localhost:8088").rstrip("/")
ISSUER = PUBLIC_URL
KC = f"{PUBLIC_URL}/auth"
KC_ADMIN_BASE = ENV.get("KC_ADMIN_URL", "http://127.0.0.1:8080/auth").rstrip("/")
REALM = ENV.get("REALM", "senegal")
REALM_URL = f"{KC}/realms/{REALM}"
TOKEN_URL = f"{REALM_URL}/protocol/openid-connect/token"
COMPOSE = shlex.split(ENV.get("COMPOSE", "docker compose"))
SCOPE = "sn_national_id_vc"
CONFIG_ID = "SenegalNationalID_ldp"
NIN = ENV.get("CITIZEN_USERNAME", "1251195302325")
CITIZEN_PWD = ENV.get("CITIZEN_PASSWORD", "Citoyen#2026")
MIMOTO_CLIENT = ENV.get("MIMOTO_CLIENT_ID", "inji-mimoto")
INJI_WEB_REDIRECT = "http://localhost:3004/redirect"            # window.location.origin + "/redirect"
WALLET_CLIENT = "wallet"                                         # codé en dur dans Inji Wallet 0.22
WALLET_REDIRECT = "io.mosip.residentapp.inji://oauthredirect"    # idem
TEST_SECRET = ENV.get("TEST_CLIENT_SECRET", "test-secret-change-me")


def expected_did() -> str:
    u = urlparse(PUBLIC_URL)
    return ":".join(["did:web", quote(u.netloc, safe=""), *[p for p in u.path.split("/") if p]])


# ---------------------------------------------------------------- docker / base de données
def compose(*args: str, check=True) -> str:
    r = subprocess.run([*COMPOSE, *args], cwd=ROOT, capture_output=True, text=True, timeout=600)
    if check and r.returncode != 0:
        raise AssertionError(f"{' '.join(args)} a échoué : {r.stderr}\n{r.stdout}")
    return r.stdout


def psql(sql: str) -> list[list[str]]:
    out = compose("exec", "-T", "postgres", "psql", "-U", "issuer", "-d", "issuer", "-At", "-F", "|", "-c", sql)
    return [line.split("|") for line in out.strip().splitlines() if line]


def wait_http(url: str, timeout=180):
    end = time.time() + timeout
    while time.time() < end:
        try:
            if requests.get(url, timeout=3).status_code == 200:
                return
        except requests.RequestException:
            pass
        time.sleep(2)
    raise AssertionError(f"{url} indisponible")


# ---------------------------------------------------------------- Keycloak
def kc_admin_token() -> str:
    r = requests.post(f"{KC_ADMIN_BASE}/realms/master/protocol/openid-connect/token", data={
        "grant_type": "password", "client_id": "admin-cli",
        "username": ENV.get("KC_ADMIN", "admin"), "password": ENV.get("KC_ADMIN_PASSWORD", "admin-change-me")})
    r.raise_for_status()
    return r.json()["access_token"]


def kc_admin(method: str, path: str, **kw) -> requests.Response:
    r = requests.request(method, f"{KC_ADMIN_BASE}/admin/realms/{REALM}{path}",
                         headers={"Authorization": f"Bearer {kc_admin_token()}"}, **kw)
    r.raise_for_status()
    return r


def kc_client(client_id: str) -> dict:
    return kc_admin("GET", "/clients", params={"clientId": client_id}).json()[0]


def password_token(username: str, password: str, scope: str = f"openid {SCOPE}") -> dict:
    """Jeton via le client de test (grant password, DEV)."""
    return requests.post(TOKEN_URL, data={"grant_type": "password", "client_id": "issuer-test-cli",
                                          "client_secret": TEST_SECRET, "username": username,
                                          "password": password, "scope": scope}).json()


def claims_of(token: str) -> dict:
    return jwt.decode(token, options={"verify_signature": False})


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    return verifier, b64url(hashlib.sha256(verifier.encode()).digest())


def keycloak_login(auth_url: str, username: str, password: str, redirect_uri: str) -> tuple[str | None, dict, str]:
    """Ouvre l'URL d'autorisation, soumet le formulaire Keycloak. Renvoie (code, params_redirect, html_si_echec)."""
    s = requests.Session()
    page = s.get(auth_url)
    page.raise_for_status()
    m = re.search(r'<form[^>]+id="kc-form-login"[^>]+action="([^"]+)"', page.text)
    assert m, "formulaire de connexion Keycloak introuvable : " + page.text[:300]
    # Le cookiejar Python ignore les cookies de l'hôte « localhost » : on les renvoie explicitement.
    cookie = "; ".join(f"{c.name}={c.value}" for c in s.cookies)
    r = requests.post(html.unescape(m.group(1)), data={"username": username, "password": password, "credentialId": ""},
                      headers={"Cookie": cookie}, allow_redirects=False)
    if r.status_code != 302:
        return None, {}, r.text
    loc = urlparse(r.headers["Location"])
    assert f"{loc.scheme}://{loc.netloc}{loc.path}" == redirect_uri, r.headers["Location"]
    q = {k: v[0] for k, v in parse_qs(loc.query).items()}
    return q.get("code"), q, ""


def issuer_metadata() -> dict:
    return requests.get(f"{ISSUER}/.well-known/openid-credential-issuer").json()


def as_metadata(authorization_server: str) -> dict:
    """Découverte RFC 8414 comme Mimoto (IssuerConfigUtil.getAuthServerWellknown) et inji-vci-client."""
    r = requests.get(f"{authorization_server}/.well-known/oauth-authorization-server")
    r.raise_for_status()
    return r.json()


# ---------------------------------------------------------------- Mimoto 0.22 (piloté comme Inji Web 0.17)
def self_signed(key, cn: str) -> x509.Certificate:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=30)).sign(key, hashes.SHA256()))


MIMOTO_PRIORITY = ["ED25519", "ES256K", "ES256", "RS256"]   # signing.algorithms.priority.order (défaut)


class MimotoLikeClient:
    def __init__(self, key: rsa.RSAPrivateKey, cert: x509.Certificate):
        self.key, self.cert = key, cert

    @classmethod
    def from_inji_certs_or_new(cls) -> "MimotoLikeClient":
        p12 = ROOT / "inji" / "certs" / "oidckeystore.p12"
        if p12.exists():   # même clé que le vrai Mimoto (déjà déclarée dans Keycloak par keycloak-init)
            key, cert, _ = pkcs12.load_key_and_certificates(p12.read_bytes(),
                                                            ENV.get("MIMOTO_P12_PASSWORD", "dummypassword").encode())
            return cls(key, cert)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return cls(key, self_signed(key, "mimoto-test"))

    def register_certificate(self):
        """Ce que fait keycloak-init avec inji/certs/mimoto-client-cert.pem."""
        c = kc_client(MIMOTO_CLIENT)
        rep = kc_admin("GET", f"/clients/{c['id']}").json()
        der = self.cert.public_bytes(serialization.Encoding.DER)
        rep.setdefault("attributes", {}).update({"use.jwks.url": "false", "use.jwks.string": "false",
                                                 "jwt.credential.certificate": base64.b64encode(der).decode()})
        kc_admin("PUT", f"/clients/{c['id']}", json=rep)

    def configuration(self) -> tuple[dict, dict]:
        meta = issuer_metadata()
        asm = as_metadata(meta["authorization_servers"][0])
        return meta, asm

    def authorize(self, username: str, password: str) -> tuple[str | None, str, str]:
        """Requête d'autorisation construite comme Inji Web 0.17 (api.authorization)."""
        meta, asm = self.configuration()
        cfg = meta["credential_configurations_supported"][CONFIG_ID]
        verifier, challenge = pkce()
        state = secrets.token_urlsafe(12)
        url = (f"{asm['authorization_endpoint']}?response_type=code&client_id={MIMOTO_CLIENT}&scope={cfg['scope']}"
               f"&redirect_uri={INJI_WEB_REDIRECT}&state={state}&code_challenge={challenge}"
               f"&code_challenge_method=S256&ui_locales=fr")
        code, q, page = keycloak_login(url, username, password, INJI_WEB_REDIRECT)
        if code:
            assert q["state"] == state
        return code, verifier, page

    def client_assertion(self, audience: str, key=None) -> str:
        """JoseUtil.getJWT : RS256, SANS kid, iss=sub=client_id, aud=token_endpoint, exp=+120 s, jti."""
        now = int(time.time())
        return jwt.encode({"iss": MIMOTO_CLIENT, "sub": MIMOTO_CLIENT, "aud": audience, "exp": now + 120,
                           "iat": now, "jti": str(uuid.uuid4())}, key or self.key, "RS256", headers={"typ": "JWT"})

    def token(self, code: str, verifier: str, key=None) -> requests.Response:
        """IdpServiceImpl.getTokenResponse / constructGetTokenRequest."""
        _, asm = self.configuration()
        te = asm["token_endpoint"]
        return requests.post(te, data={"code": code, "client_id": MIMOTO_CLIENT, "grant_type": "authorization_code",
                                       "redirect_uri": INJI_WEB_REDIRECT, "client_assertion": self.client_assertion(te, key),
                                       "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                                       "code_verifier": verifier})

    @staticmethod
    def resolve_alg(meta: dict) -> str:
        """CredentialRequestServiceImpl.resolveAlgorithm."""
        supported = [a.upper() for a in meta["credential_configurations_supported"][CONFIG_ID]
                     ["proof_types_supported"]["jwt"]["proof_signing_alg_values_supported"]]
        return next((a for a in MIMOTO_PRIORITY if a in supported), "ED25519")

    def credential_request(self, access_token: str, c_nonce: str | None) -> tuple[requests.Response, str]:
        meta = issuer_metadata()
        cfg = meta["credential_configurations_supported"][CONFIG_ID]
        alg = self.resolve_alg(meta)
        key, jwk, jws_alg = holder_key(alg)
        now = int(time.time())
        claims = {"sub": MIMOTO_CLIENT, "aud": meta["credential_issuer"], "iss": MIMOTO_CLIENT, "iat": now,
                  "exp": now + 18000, "nonce": c_nonce}   # SigningKeyUtil.createClaims (nonce null si absent)
        proof = jwt.encode(claims, key, jws_alg, headers={"typ": "openid4vci-proof+jwt", "jwk": jwk})
        body = {"format": cfg["format"], "proof": {"proof_type": next(iter(cfg["proof_types_supported"])), "jwt": proof},
                "credential_definition": {"type": cfg["credential_definition"]["type"],
                                          "@context": cfg["credential_definition"]["@context"]}}
        return requests.post(meta["credential_endpoint"], json=body,
                             headers={"Authorization": f"Bearer {access_token}"}), alg


def holder_key(alg: str):
    """Clé de détenteur et JWK publique pour un algorithme (noms Mimoto/Inji)."""
    a = alg.upper()
    if a in ("ES256", "ES256K"):
        k = ec.generate_private_key(ec.SECP256R1() if a == "ES256" else ec.SECP256K1())
        return k, json.loads(ECAlgorithm.to_jwk(k.public_key())), a
    if a == "RS256":
        k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return k, json.loads(RSAAlgorithm.to_jwk(k.public_key())), "RS256"
    k = ed25519.Ed25519PrivateKey.generate()
    return k, json.loads(OKPAlgorithm.to_jwk(k.public_key())), "EdDSA"


# ---------------------------------------------------------------- Inji Wallet 0.22 (offre d'identifiant)
class InjiWalletOfferClient:
    def read_offer(self, link: str) -> dict:
        q = parse_qs(urlparse(link).query)
        if "credential_offer" in q:
            return json.loads(q["credential_offer"][0])
        r = requests.get(unquote(q["credential_offer_uri"][0]))
        r.raise_for_status()
        return r.json()

    def authorize(self, offer: dict, username: str, password: str, use_par=True) -> tuple[str | None, str, dict, str]:
        meta = requests.get(f"{offer['credential_issuer']}/.well-known/openid-credential-issuer").json()
        grant = offer["grants"]["authorization_code"]
        asm = as_metadata(grant.get("authorization_server") or meta["authorization_servers"][0])
        scope = meta["credential_configurations_supported"][offer["credential_configuration_ids"][0]]["scope"]
        verifier, challenge = pkce()
        params = {"response_type": "code", "client_id": WALLET_CLIENT, "redirect_uri": WALLET_REDIRECT, "scope": scope,
                  "state": secrets.token_urlsafe(12), "code_challenge": challenge, "code_challenge_method": "S256"}
        if use_par and asm.get("pushed_authorization_request_endpoint"):   # PAR utilisé s'il est annoncé
            r = requests.post(asm["pushed_authorization_request_endpoint"], data=params)
            assert r.status_code == 201, r.text
            url = f"{asm['authorization_endpoint']}?" + urlencode({"client_id": WALLET_CLIENT,
                                                                   "request_uri": r.json()["request_uri"]})
        else:
            url = f"{asm['authorization_endpoint']}?" + urlencode(params)
        code, q, page = keycloak_login(url, username, password, WALLET_REDIRECT)
        return code, verifier, asm, page

    def token(self, asm: dict, code: str, verifier: str) -> requests.Response:
        """IssuersService.sendTokenRequest : client public, pas d'authentification client."""
        return requests.post(asm["token_endpoint"], data={"grant_type": "authorization_code", "code": code,
                                                          "client_id": WALLET_CLIENT, "redirect_uri": WALLET_REDIRECT,
                                                          "code_verifier": verifier})

    def proof(self, key_type: str, issuer: str, c_nonce: str | None = None, alg_override: str | None = None):
        """constructProofJWT(isCredentialOfferFlow=true) : kid did:jwk:…#0, pas d'iss."""
        key, jwk, jws_alg = holder_key(key_type)
        jwk = {**jwk, "use": "sig"}
        header_alg = alg_override or jws_alg
        now = int(time.time())
        payload = {"aud": issuer, "iat": now, "exp": now + 18000}
        if c_nonce:
            payload["nonce"] = c_nonce
        kid = f"did:jwk:{b64url(json.dumps(jwk).encode())}#0"
        token = jwt.encode(payload, key, jws_alg, headers={"typ": "openid4vci-proof+jwt", "kid": kid})
        if header_alg != jws_alg:   # ex. alg « Ed25519 » (RFC 9864) : on réécrit l'en-tête et on re-signe
            h = {"alg": header_alg, "typ": "openid4vci-proof+jwt", "kid": kid}
            signing_input = f"{b64url(json.dumps(h).encode())}.{token.split('.')[1]}".encode()
            token = signing_input.decode() + "." + b64url(key.sign(signing_input))
        pub = {k: v for k, v in jwk.items() if k in ("kty", "crv", "x", "y", "n", "e")}
        return {"proof_type": "jwt", "jwt": token}, "did:jwk:" + b64url(json.dumps(pub, separators=(",", ":")).encode())

    def credential(self, meta: dict, access_token: str, config_id: str, proof: dict) -> requests.Response:
        cfg = meta["credential_configurations_supported"][config_id]
        body = {"format": cfg["format"], "credential_definition": {"type": cfg["credential_definition"]["type"],
                                                                     "@context": cfg["credential_definition"]["@context"]},
                "proof": proof}
        return requests.post(meta["credential_endpoint"], json=body, headers={"Authorization": f"Bearer {access_token}"})


# ---------------------------------------------------------------- client de test simple (wallet générique)
class Wallet:
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.jwk = json.loads(ECAlgorithm.to_jwk(self.key.public_key()))

    @property
    def did_jwk(self) -> str:
        pub = {k: self.jwk[k] for k in ("crv", "kty", "x", "y")}
        return "did:jwk:" + b64url(json.dumps(pub, separators=(",", ":")).encode())

    def proof(self, nonce: str | None = None, aud: str = ISSUER, typ="openid4vci-proof+jwt", iat=None) -> dict:
        c = {"aud": aud, "iat": iat or int(time.time()), "iss": MIMOTO_CLIENT}
        if nonce:
            c["nonce"] = nonce
        return {"proof_type": "jwt", "jwt": jwt.encode(c, self.key, "ES256", headers={"typ": typ, "jwk": self.jwk})}


def credential_request(token: str | None, body: dict) -> requests.Response:
    h = {"Authorization": f"Bearer {token}"} if token else {}
    return requests.post(f"{ISSUER}/v1/credential", json=body, headers=h)


def ldp_body(proof: dict, fmt="ldp_vc") -> dict:
    cdef = issuer_metadata()["credential_configurations_supported"][CONFIG_ID]["credential_definition"]
    return {"format": fmt, "credential_definition": {"@context": cdef["@context"], "type": cdef["type"]},
            "proof": proof}


def fresh_nonce() -> str:
    return requests.post(f"{ISSUER}/v1/nonce").json()["c_nonce"]


VERIFIER_DIR = ROOT / "tests" / "verifier"


def verify_vc(vc: dict, tmp_path: Path) -> dict:
    f = tmp_path / f"vc-{uuid.uuid4().hex}.json"
    f.write_text(json.dumps(vc))
    r = subprocess.run(["node", "verify.mjs", str(f)], cwd=VERIFIER_DIR, capture_output=True, text=True, timeout=60)
    assert r.stdout, r.stderr
    return json.loads(r.stdout.strip().splitlines()[-1])


@pytest.fixture(scope="session", autouse=True)
def stack_ready():
    wait_http(f"{ISSUER}/health")
    wait_http(f"{REALM_URL}/.well-known/openid-configuration")


@pytest.fixture(scope="session")
def mimoto():
    m = MimotoLikeClient.from_inji_certs_or_new()
    if not (ROOT / "inji" / "certs" / "oidckeystore.p12").exists():
        m.register_certificate()   # sinon : certificat déclaré par keycloak-init (chemin d'exploitation réel)
    return m


@pytest.fixture(scope="session")
def admin_token() -> str:
    t = password_token("issuer-admin", ENV.get("ISSUER_ADMIN_PASSWORD", "admin-issuer-change-me"), scope="openid")
    return t["access_token"]
