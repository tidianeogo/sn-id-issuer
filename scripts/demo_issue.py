#!/usr/bin/env python3
"""Parcours complet contre la pile docker compose : jeton Keycloak -> preuve détenteur -> VC.

    pip install requests "pyjwt[crypto]"
    python scripts/demo_issue.py            # utilise les valeurs de .env.example
"""
import json
import os
import time

import jwt
import requests
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm

ISSUER = os.getenv("ISSUER_PUBLIC_URL", "http://localhost:8000")
KC = os.getenv("KEYCLOAK_PUBLIC_URL", "http://localhost:8080")
REALM = os.getenv("REALM", "senegal")
USER = os.getenv("CITIZEN_USERNAME", "1251195302325")  # NIN
PWD = os.getenv("CITIZEN_PASSWORD", "Citoyen#2026")
SECRET = os.getenv("TEST_CLIENT_SECRET", "test-secret-change-me")

meta = requests.get(f"{ISSUER}/.well-known/openid-credential-issuer").json()
cfg_id, cfg = next(iter(meta["credential_configurations_supported"].items()))
print("1. Métadonnées OK — configuration", cfg_id, "scope", cfg["scope"])

tok = requests.post(f"{KC}/realms/{REALM}/protocol/openid-connect/token", data={
    "grant_type": "password", "client_id": "issuer-test-cli", "client_secret": SECRET,
    "username": USER, "password": PWD, "scope": f"openid {cfg['scope']}"}).json()
if "access_token" not in tok:
    raise SystemExit(f"Échec Keycloak : {tok}")
print("2. Jeton Keycloak obtenu (scope :", jwt.decode(tok["access_token"], options={"verify_signature": False})["scope"], ")")

nonce = requests.post(f"{ISSUER}/v1/nonce").json()["c_nonce"]
holder = ec.generate_private_key(ec.SECP256R1())
proof = jwt.encode({"aud": meta["credential_issuer"], "iat": int(time.time()), "nonce": nonce,
                    "iss": "issuer-test-cli"}, holder, "ES256",
                   headers={"typ": "openid4vci-proof+jwt", "jwk": json.loads(ECAlgorithm.to_jwk(holder.public_key()))})
print("3. Preuve de possession signée (ES256, c_nonce", nonce[:8] + "…)")

r = requests.post(meta["credential_endpoint"], headers={"Authorization": f"Bearer {tok['access_token']}"},
                  json={"format": "ldp_vc", "credential_definition": {"type": cfg["credential_definition"]["type"]},
                        "proof": {"proof_type": "jwt", "jwt": proof}})
r.raise_for_status()
vc = r.json()["credential"]
json.dump(vc, open("vc.json", "w"), indent=2, ensure_ascii=False)
print("4. VC émis et enregistré dans vc.json —", vc["credentialSubject"]["fullName"], "—", vc["proof"]["type"])
