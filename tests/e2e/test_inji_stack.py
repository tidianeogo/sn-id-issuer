"""Tests contre le VRAI Mimoto 0.22 et le vrai Inji Web 0.17 (profil « inji », tunnel HTTPS).

Activés par INJI_STACK=1 (./scripts/e2e.sh --inji) : nécessitent les images injistack/*, donc un poste
qui a accès à Docker Hub (votre Mac).
"""
import os

import pytest
import requests

from conftest import (CITIZEN_PWD, CONFIG_ID, INJI_WEB_REDIRECT, MIMOTO_CLIENT, NIN, PUBLIC_URL, MimotoLikeClient,
                      psql)

pytestmark = pytest.mark.skipif(os.environ.get("INJI_STACK") != "1", reason="pile Inji non demandée (INJI_STACK=1)")
INJI_WEB = "http://localhost:3004"
MIMOTO = f"{INJI_WEB}/v1/mimoto"   # comme MIMOTO_URL d'Inji Web (proxy nginx d'inji-web)


def test_url_publique_https():
    assert PUBLIC_URL.startswith("https://"), "le profil inji exige un tunnel HTTPS (did:web, Inji Wallet)"


def test_inji_web_repond():
    r = requests.get(INJI_WEB)
    assert r.status_code == 200 and "<div id=\"root\"" in r.text.replace("'", '"')


def test_mimoto_liste_l_emetteur():
    r = requests.get(f"{MIMOTO}/v2/issuers")
    assert r.status_code == 200, r.text
    assert "SenegalCNI" in r.text


def test_mimoto_lit_les_metadonnees_de_l_issuer_et_de_keycloak():
    """/issuers/{id}/configuration : Mimoto a validé le well-known ET la découverte RFC 8414 de Keycloak."""
    r = requests.get(f"{MIMOTO}/issuers/SenegalCNI/configuration")
    assert r.status_code == 200, r.text
    body = r.text
    assert CONFIG_ID in body and "authorization_endpoint" in body


def test_telechargement_pdf_comme_inji_web_invite():
    """Parcours invité d'Inji Web : login Keycloak puis POST /credentials/download -> PDF.
    Mimoto échange le code (client_assertion avec la clé du p12), appelle l'issuer, VÉRIFIE la signature
    du VC (did:web via le tunnel) et génère le PDF."""
    m = MimotoLikeClient.from_inji_certs_or_new()
    code, verifier, page = m.authorize(NIN, CITIZEN_PWD)
    assert code, page[:300]
    r = requests.post(f"{MIMOTO}/credentials/download", headers={"Accept": "application/pdf",
                                                                  "Accept-Language": "fr"},
                      data={"grant_type": "authorization_code", "code": code, "redirect_uri": INJI_WEB_REDIRECT,
                            "code_verifier": verifier, "issuer": "SenegalCNI", "credential": CONFIG_ID,
                            "vcStorageExpiryLimitInTimes": "-1"}, timeout=120)
    assert r.status_code == 200, r.text[:500]
    assert r.content[:4] == b"%PDF"
    n = psql(f"select count(*) from issuer.issued_credential where client_id = '{MIMOTO_CLIENT}'")[0][0]
    assert int(n) >= 1
