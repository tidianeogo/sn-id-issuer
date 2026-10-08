"""Contrat Inji Wallet 0.22 — flux « offre d'identifiant » (code source mosip/inji-wallet release-0.22.x).

Le wallet du store n'utilise pas de Mimoto local : il scanne l'offre, utilise le client public « wallet »
(redirect io.mosip.residentapp.inji://oauthredirect), PKCE, PAR s'il est annoncé, puis une preuve dont
l'en-tête porte kid = did:jwk:…#0.
"""
import json
import re

import pytest
import requests

from conftest import (CITIZEN_PWD, CONFIG_ID, ISSUER, NIN, REALM_URL, SCOPE, WALLET_CLIENT, WALLET_REDIRECT,
                      InjiWalletOfferClient, as_metadata, claims_of, issuer_metadata, pkce, verify_vc)

STATE: dict = {}
W = InjiWalletOfferClient()


def test_page_d_offre_avec_qr():
    r = requests.get(f"{ISSUER}/credential-offer")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
    assert "<svg" in r.text and "openid-credential-offer://?credential_offer=" in r.text
    if ISSUER.startswith("https://"):
        assert "Inji Wallet exige HTTPS" not in r.text
    else:
        assert "Inji Wallet exige HTTPS" in r.text   # avertissement en mode local


def test_offre_par_valeur_et_par_reference():
    links = requests.get(f"{ISSUER}/credential-offer/links").json()
    by_value, by_ref = W.read_offer(links["by_value"]), W.read_offer(links["by_reference"])
    assert by_value == by_ref == requests.get(f"{ISSUER}/credential-offer.json").json()
    meta = issuer_metadata()
    assert by_value["credential_issuer"] == meta["credential_issuer"] == ISSUER
    assert by_value["credential_configuration_ids"] == [CONFIG_ID]
    assert set(by_value["credential_configuration_ids"]) <= set(meta["credential_configurations_supported"])
    assert by_value["grants"]["authorization_code"]["authorization_server"] in meta["authorization_servers"]
    STATE["offer"] = by_value


def test_decouverte_du_serveur_d_autorisation_et_par():
    asm = as_metadata(STATE["offer"]["grants"]["authorization_code"]["authorization_server"])
    assert asm["issuer"] == REALM_URL
    assert "S256" in asm["code_challenge_methods_supported"]
    assert asm.get("pushed_authorization_request_endpoint")   # inji-vci-client l'utilisera


@pytest.mark.parametrize("use_par", [True, False], ids=["avec-PAR", "sans-PAR"])
def test_connexion_et_jeton_client_public(use_par):
    code, verifier, asm, page = W.authorize(STATE["offer"], NIN, CITIZEN_PWD, use_par=use_par)
    assert code, page[:300]
    r = W.token(asm, code, verifier)
    assert r.status_code == 200, r.text
    c = claims_of(r.json()["access_token"])
    assert c["azp"] == WALLET_CLIENT and c["preferred_username"] == NIN and SCOPE in c["scope"].split()
    assert "sn-id-issuer" in ([c["aud"]] if isinstance(c["aud"], str) else c["aud"])
    STATE["token"] = r.json()["access_token"]


@pytest.mark.parametrize("key_type, alg", [("ES256", None), ("ES256K", None), ("RS256", None),
                                           ("ED25519", None), ("ED25519", "Ed25519")],
                         ids=["ES256", "ES256K", "RS256", "Ed25519-EdDSA", "Ed25519-alg-RFC9864"])
def test_credential_avec_preuve_du_wallet(key_type, alg, tmp_path):
    meta = issuer_metadata()
    proof, did = W.proof(key_type, meta["credential_issuer"], alg_override=alg)
    r = W.credential(meta, STATE["token"], CONFIG_ID, proof)
    assert r.status_code == 200, r.text
    vc = r.json()["credential"]
    assert vc["credentialSubject"]["id"] == did
    if key_type == "ES256":
        assert verify_vc(vc, tmp_path)["verified"] is True


def test_affichage_pour_le_wallet():
    """Affichage de la carte et consentement de confiance : display fr/en, logo, couleurs, photo « face »."""
    cfg = issuer_metadata()["credential_configurations_supported"][CONFIG_ID]
    assert {d["locale"] for d in cfg["display"]} >= {"fr", "en"}
    assert "face" in cfg["credential_definition"]["credentialSubject"]
    assert requests.get(cfg["display"][0]["logo"]["url"]).headers["content-type"].startswith("image/png")


def test_pkce_impose_au_client_wallet():
    asm = as_metadata(STATE["offer"]["grants"]["authorization_code"]["authorization_server"])
    r = requests.get(asm["authorization_endpoint"], params={"response_type": "code", "client_id": WALLET_CLIENT,
                                                            "redirect_uri": WALLET_REDIRECT, "scope": SCOPE},
                     allow_redirects=False)
    assert r.status_code == 302 and "error=invalid_request" in r.headers["Location"]
    assert re.search(r"code_challenge", r.headers["Location"])


def test_redirection_inconnue_refusee():
    asm = as_metadata(STATE["offer"]["grants"]["authorization_code"]["authorization_server"])
    _, challenge = pkce()
    r = requests.get(asm["authorization_endpoint"], params={
        "response_type": "code", "client_id": WALLET_CLIENT, "redirect_uri": "https://pirate.example/cb",
        "scope": SCOPE, "code_challenge": challenge, "code_challenge_method": "S256"}, allow_redirects=False)
    assert r.status_code == 400


def test_client_wallet_sans_secret_ni_grant_password():
    r = requests.post(as_metadata(STATE["offer"]["grants"]["authorization_code"]["authorization_server"])["token_endpoint"],
                      data={"grant_type": "password", "client_id": WALLET_CLIENT, "username": NIN,
                            "password": CITIZEN_PWD, "scope": SCOPE})
    assert r.status_code in (400, 401) and r.json()["error"] in ("unauthorized_client", "invalid_client")
    assert json.dumps(r.json())  # réponse OAuth structurée


def test_preuve_ed25519_rfc9864_signature_alteree_rejetee():
    meta = issuer_metadata()
    proof, _ = W.proof("ED25519", meta["credential_issuer"], alg_override="Ed25519")
    h, p, sig = proof["jwt"].split(".")
    proof["jwt"] = f"{h}.{p}.{sig[:-4]}AAAA"
    r = W.credential(meta, STATE["token"], CONFIG_ID, proof)
    assert r.status_code == 400 and r.json()["error"] == "invalid_proof"
