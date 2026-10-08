"""Tests de bout en bout contre la pile docker compose réelle (Postgres + Keycloak + issuer + passerelle).

Ordre d'exécution significatif (pytest exécute les tests dans l'ordre du fichier).
"""
import base64
import copy
import json
import time

import pytest
import requests
from cryptography.hazmat.primitives.asymmetric import rsa

from conftest import (CITIZEN_PWD, ENV, ISSUER, KC, KC_ADMIN_BASE, MIMOTO_CLIENT, NIN, REALM_URL, SCOPE, WALLET_CLIENT,
                      WALLET_REDIRECT, Wallet, claims_of, compose, expected_did,
                      credential_request, fresh_nonce, kc_admin, ldp_body, password_token, psql, verify_vc,
                      wait_http)

STATE: dict = {}

RECTO_VERSO = {
    "fullName": "MOUHAMED TIDIANE SECK", "givenName": "MOUHAMED TIDIANE", "familyName": "SECK",
    "nin": "1 251 1953 02325", "cardNumber": "1 04 19531108 00001 6",
    "dateOfBirth": "1953-11-08", "placeOfBirth": "SAINT LOUIS", "gender": "M", "height": "180 cm",
    "nationality": "SEN", "address": "8619 N SACRE COEUR 2", "dateOfIssue": "2017-06-01",
    "dateOfExpiry": "2027-05-31", "registrationCenter": "PROD-DAF", "issuingCountry": "SEN",
    "voterNumber": "106567885", "electoralRegion": "DAKAR", "electoralDepartment": "DAKAR",
    "electoralArrondissement": "ALMADIES", "electoralCommune": "MERMOZ SACRE COEUR",
    "pollingPlace": "ECOLE LIBERTE 5", "pollingStation": "01",
    "mrz": "I<SEN104195311<080000164<<<<<<\n5311080M2705310SEN<<<<<<<<<<<4\nSECK<<MOUHAMED<TIDIANE<<<<<<<<",
}


# =========================================================== 1. Infrastructure
def test_services_sains():
    ps = compose("ps", "--all", "--format", "json")
    rows = [json.loads(line) for line in ps.splitlines() if line.strip()] if not ps.strip().startswith("[") else json.loads(ps)
    by = {r["Service"]: r for r in rows}
    for svc in ("postgres", "keycloak", "issuer", "gateway"):
        assert by[svc]["State"] == "running", by[svc]
        assert by[svc].get("Health") in ("healthy", ""), by[svc]
    assert by["keycloak-init"]["State"] == "exited" and by["keycloak-init"]["ExitCode"] == 0


def test_base_postgres_initialisee():
    tables = {r[0] for r in psql("select table_name from information_schema.tables where table_schema='issuer'")}
    assert {"person", "id_card", "electoral_registration", "issued_credential", "issuer_key", "c_nonce"} <= tables
    assert psql("select nin, given_name, family_name, length(photo_jpeg) > 1000 from issuer.person") == [
        ["1251195302325", "MOUHAMED TIDIANE", "SECK", "t"]]
    assert psql("select card_number, nin, mrz_line1 from issuer.id_card") == [
        ["10419531108000016", "1251195302325", "I<SEN104195311<080000164<<<<<<"]]
    assert psql("select voter_number, commune, polling_place from issuer.electoral_registration") == [
        ["106567885", "MERMOZ SACRE COEUR", "ECOLE LIBERTE 5"]]
    # base Keycloak hébergée sur la même instance, peuplée par Keycloak
    out = compose("exec", "-T", "postgres", "psql", "-U", "issuer", "-d", "keycloak", "-At", "-c",
                  "select count(*) from realm where name='senegal'")
    assert out.strip() == "1"


def test_cle_issuer_chiffree_en_base():
    rows = psql("select kid, public_key_multibase, position('ENCRYPTED' in convert_from(private_key_pem,'UTF8')) > 0 "
                "from issuer.issuer_key where active")
    assert len(rows) == 1 and rows[0][2] == "t"
    STATE["pub"] = rows[0][1]


def test_realm_keycloak_configure():
    realm = kc_admin("GET", "").json()
    assert realm["displayName"] == "Identité numérique – Sénégal (démo)"  # accents préservés (UTF-8)
    scopes = {c["name"] for c in kc_admin("GET", "/client-scopes").json()}
    assert SCOPE in scopes
    cli = kc_admin("GET", "/clients", params={"clientId": MIMOTO_CLIENT}).json()[0]
    assert cli["clientAuthenticatorType"] == "client-jwt" and cli["publicClient"] is False
    assert cli["attributes"]["pkce.code.challenge.method"] == "S256"
    assert cli["directAccessGrantsEnabled"] is False
    assert set(cli["redirectUris"]) == {"http://localhost:3004/redirect", WALLET_REDIRECT}
    w = kc_admin("GET", "/clients", params={"clientId": WALLET_CLIENT}).json()[0]
    assert w["publicClient"] is True and w["redirectUris"] == [WALLET_REDIRECT]
    assert w["attributes"]["pkce.code.challenge.method"] == "S256" and w["directAccessGrantsEnabled"] is False
    users = kc_admin("GET", "/users", params={"username": NIN, "exact": "true"}).json()
    assert len(users) == 1 and users[0]["lastName"] == "SECK"


def test_passerelle_bloque_l_administration_keycloak():
    """La console et le realm master ne sont jamais exposés par l'URL publique (tunnel)."""
    for path in ("/auth/admin/master/console/", "/auth/admin/realms/senegal/users",
                 "/auth/realms/master/protocol/openid-connect/token"):
        assert requests.get(f"{KC}{path[5:]}").status_code == 403, path
    assert requests.get(f"{KC_ADMIN_BASE}/realms/master/.well-known/openid-configuration").status_code == 200


# =========================================================== 2. Métadonnées publiques
def test_metadonnees_oid4vci():
    m = requests.get(f"{ISSUER}/.well-known/openid-credential-issuer").json()
    assert m["credential_issuer"] == ISSUER
    assert m["authorization_servers"] == [REALM_URL]
    assert m["credential_endpoint"] == f"{ISSUER}/v1/credential"
    cfg = m["credential_configurations_supported"]["SenegalNationalID_ldp"]
    assert cfg["format"] == "ldp_vc" and cfg["scope"] == SCOPE
    assert cfg["credential_definition"]["type"] == ["VerifiableCredential", "SenegalNationalIDCredential"]
    assert set(RECTO_VERSO) <= set(cfg["credential_definition"]["credentialSubject"])
    assert cfg["order"][0] == "fullName"
    # serveur d'autorisation annoncé = Keycloak réellement joignable
    oidc = requests.get(f"{REALM_URL}/.well-known/openid-configuration").json()
    assert oidc["issuer"] == REALM_URL
    assert requests.get(cfg["display"][0]["logo"]["url"]).status_code == 200


def test_did_web_et_contexte():
    d = requests.get(f"{ISSUER}/.well-known/did.json")
    assert d.headers["content-type"].startswith("application/did+json")
    doc = d.json()
    assert doc["id"] == expected_did()
    assert doc["verificationMethod"][0]["publicKeyMultibase"] == STATE["pub"]
    assert doc["assertionMethod"] == [doc["id"] + "#key-1"]
    ctx = requests.get(f"{ISSUER}/contexts/sn-national-id-v1.jsonld").json()
    assert "voterNumber" in ctx["@context"] and "nin" in ctx["@context"]


# =========================================================== 3. Parcours Mimoto / Inji Web complet
def test_login_keycloak_et_jeton_comme_mimoto(mimoto):
    code, verifier, page = mimoto.authorize(NIN, CITIZEN_PWD)
    assert code, "connexion Keycloak refusée : " + page[:300]
    r = mimoto.token(code, verifier)
    assert r.status_code == 200, r.text
    tok = r.json()
    c = claims_of(tok["access_token"])
    assert c["iss"] == REALM_URL
    assert c["azp"] == MIMOTO_CLIENT
    assert c["preferred_username"] == NIN
    assert SCOPE in c["scope"].split()
    assert "sn-id-issuer" in ([c["aud"]] if isinstance(c["aud"], str) else c["aud"])
    STATE.update(code=code, verifier=verifier, access_token=tok["access_token"])


def test_code_autorisation_a_usage_unique(mimoto):
    r = mimoto.token(STATE["code"], STATE["verifier"])
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"


def test_pkce_obligatoire(mimoto):
    code, _, _ = mimoto.authorize(NIN, CITIZEN_PWD)
    r = mimoto.token(code, "mauvais-verifier-" + "x" * 40)
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"


def test_authentification_client_private_key_jwt(mimoto):
    """Un client qui signe avec une autre clé que celle déclarée est refusé."""
    code, verifier, _ = mimoto.authorize(NIN, CITIZEN_PWD)
    r = mimoto.token(code, verifier, key=rsa.generate_private_key(public_exponent=65537, key_size=2048))
    assert r.status_code in (400, 401) and r.json()["error"] in ("invalid_client", "unauthorized_client")


def test_mauvais_mot_de_passe(mimoto):
    code, _, page = mimoto.authorize(NIN, "mauvais")
    assert code is None and "kc-form-login" in page


def test_emission_vc_avec_c_nonce(tmp_path):
    wallet = Wallet()
    r = credential_request(STATE["access_token"], ldp_body(wallet.proof(fresh_nonce())))
    assert r.status_code == 200, r.text
    assert r.headers["cache-control"] == "no-store"
    body = r.json()
    assert body["format"] == "ldp_vc" and body["c_nonce"]
    vc = body["credential"]
    STATE["vc"], STATE["wallet"] = vc, wallet
    assert vc["issuer"] == expected_did()
    assert vc["type"] == ["VerifiableCredential", "SenegalNationalIDCredential"]
    assert vc["expirationDate"] == "2027-05-31T23:59:59Z"
    assert vc["proof"]["type"] == "Ed25519Signature2020"
    assert vc["proof"]["verificationMethod"] == expected_did() + "#key-1"


def test_contenu_vc_recto_et_verso():
    s = STATE["vc"]["credentialSubject"]
    for k, v in RECTO_VERSO.items():
        assert s[k] == v, k
    assert s["id"] == STATE["wallet"].did_jwk  # VC lié à la clé du wallet
    photo = base64.b64decode(s["face"].split(",", 1)[1])
    assert s["face"].startswith("data:image/jpeg;base64,") and photo[:2] == b"\xff\xd8"


def test_verification_independante(tmp_path):
    """Vérification par les bibliothèques Digital Bazaar, avec résolution did:web en HTTP."""
    res = verify_vc(STATE["vc"], tmp_path)
    assert res["verified"] is True, res


@pytest.mark.parametrize("champ, valeur", [("dateOfBirth", "1960-01-01"), ("voterNumber", "000000000"),
                                            ("nin", "1 999 1999 99999")])
def test_vc_altere_rejete(tmp_path, champ, valeur):
    vc = copy.deepcopy(STATE["vc"])
    vc["credentialSubject"][champ] = valeur
    assert verify_vc(vc, tmp_path)["verified"] is False


def test_vc_journalise_en_base():
    rows = psql(f"select nin, card_number, client_id, holder_id, status, credential->>'id' "
                f"from issuer.issued_credential where vc_id = '{STATE['vc']['id']}'")
    assert rows == [["1251195302325", "10419531108000016", MIMOTO_CLIENT, STATE["wallet"].did_jwk, "VALID",
                     STATE["vc"]["id"]]]


def test_emission_par_credential_configuration_id():
    r = credential_request(STATE["access_token"], {"credential_configuration_id": "SenegalNationalID_ldp",
                                                    "proof": Wallet().proof()})
    assert r.status_code == 200, r.text


# =========================================================== 4. Contrôles de sécurité de l'issuer
def _err(r, status, error):
    assert r.status_code == status, r.text
    assert r.json()["error"] == error, r.text


def test_sans_jeton():
    r = credential_request(None, ldp_body(Wallet().proof()))
    _err(r, 401, "invalid_token")
    assert "WWW-Authenticate" in r.headers


def test_jeton_falsifie():
    t = STATE["access_token"]
    h, p, sig = t.split(".")
    claims = claims_of(t)
    claims["preferred_username"] = "9999999999999"
    p2 = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    _err(credential_request(f"{h}.{p2}.{sig}", ldp_body(Wallet().proof())), 401, "invalid_token")


def test_jeton_d_un_autre_realm():
    r = requests.post(f"{KC_ADMIN_BASE}/realms/master/protocol/openid-connect/token", data={
        "grant_type": "password", "client_id": "admin-cli", "username": "admin",
        "password": ENV.get("KC_ADMIN_PASSWORD", "admin-change-me")})
    _err(credential_request(r.json()["access_token"], ldp_body(Wallet().proof())), 401, "invalid_token")


def test_scope_manquant():
    t = password_token(NIN, CITIZEN_PWD, scope="openid")["access_token"]
    assert SCOPE not in claims_of(t)["scope"]
    _err(credential_request(t, ldp_body(Wallet().proof())), 403, "insufficient_scope")


def test_preuve_absente():
    body = ldp_body(Wallet().proof())
    body.pop("proof")
    r = credential_request(STATE["access_token"], body)
    _err(r, 400, "invalid_proof")
    assert r.json()["c_nonce"]


@pytest.mark.parametrize("cas", ["aud", "typ", "iat", "nonce_inconnu"])
def test_preuve_invalide(cas):
    w = Wallet()
    proof = {"aud": w.proof(aud="https://autre-issuer.example"), "typ": w.proof(typ="JWT"),
             "iat": w.proof(iat=int(time.time()) - 3600), "nonce_inconnu": w.proof(nonce="inconnu")}[cas]
    _err(credential_request(STATE["access_token"], ldp_body(proof)), 400, "invalid_proof")


def test_rejeu_du_c_nonce():
    w, n = Wallet(), fresh_nonce()
    assert credential_request(STATE["access_token"], ldp_body(w.proof(n))).status_code == 200
    _err(credential_request(STATE["access_token"], ldp_body(w.proof(n))), 400, "invalid_proof")


def test_format_et_type_non_supportes():
    w = Wallet()
    _err(credential_request(STATE["access_token"], ldp_body(w.proof(), fmt="vc+sd-jwt")), 400,
         "unsupported_credential_format")
    body = ldp_body(w.proof())
    body["credential_definition"]["type"] = ["VerifiableCredential", "DrivingLicense"]
    _err(credential_request(STATE["access_token"], body), 400, "unsupported_credential_type")
    _err(credential_request(STATE["access_token"], {"credential_configuration_id": "Autre", "proof": w.proof()}),
         400, "unsupported_credential_type")


def test_utilisateur_keycloak_sans_identite():
    kc_admin("POST", "/users", json={"username": "sans-identite", "enabled": True, "firstName": "A", "lastName": "B",
                                     "email": "sans-identite@test.local", "emailVerified": True,
                                     "credentials": [{"type": "password", "value": "Passe#123", "temporary": False}]})
    t = password_token("sans-identite", "Passe#123")["access_token"]
    _err(credential_request(t, ldp_body(Wallet().proof())), 404, "invalid_request")


def test_integrite_mrz_controlee_a_l_emission():
    """Une MRZ corrompue en base bloque l'émission (aucun VC incohérent n'est signé)."""
    psql("update issuer.id_card set mrz_line2 = '5311080M2705310SEN<<<<<<<<<<<5' where card_number='10419531108000016'")
    try:
        _err(credential_request(STATE["access_token"], ldp_body(Wallet().proof())), 500, "server_error")
    finally:
        psql("update issuer.id_card set mrz_line2 = '5311080M2705310SEN<<<<<<<<<<<4' where card_number='10419531108000016'")
    assert credential_request(STATE["access_token"], ldp_body(Wallet().proof())).status_code == 200


def test_identite_suspendue():
    psql("update issuer.person set status='SUSPENDED' where nin='1251195302325'")
    try:
        _err(credential_request(STATE["access_token"], ldp_body(Wallet().proof())), 403, "access_denied")
    finally:
        psql("update issuer.person set status='ACTIVE' where nin='1251195302325'")


# =========================================================== 5. API d'administration
def _adm(method, path, token, **kw):
    return requests.request(method, f"{ISSUER}{path}", headers={"Authorization": f"Bearer {token}"}, **kw)


def test_admin_reserve_au_role(admin_token):
    assert _adm("GET", "/admin/citizens", STATE["access_token"]).status_code == 403
    r = _adm("GET", "/admin/citizens", admin_token)
    assert r.status_code == 200
    me = next(c for c in r.json() if c["nin"] == "1251195302325")
    assert me["electoral"]["voter_number"] == "106567885" and me["cards"][0]["card_number"] == "10419531108000016"


def _mrz_for(card, dob, sex, exp, family, given):
    from app.mrz import check_digit
    l1 = f"I<SEN{card[:9]}<{card[9:]}{check_digit(card)}".ljust(30, "<")
    l2 = f"{dob}{check_digit(dob)}{sex}{exp}{check_digit(exp)}SEN".ljust(29, "<")
    l2 += check_digit(l1[5:30] + l2[0:7] + l2[8:15] + l2[18:29])
    l3 = f"{family}<<{given.replace(' ', '<')}".ljust(30, "<")
    return [l1, l2, l3]


FICTIF = dict(nin="2999200001234", card_number="2 99 20000101 00042 7", given_name="AWA", family_name="DIOP",
              date_of_birth="2000-01-01", place_of_birth="THIES", sex="F", height_cm=165, address="RUE 10 THIES",
              date_of_issue="2024-01-15", date_of_expiry="2034-01-14", registration_center="TEST",
              electoral={"voter_number": "900000001", "region": "THIES", "department": "THIES",
                         "arrondissement": "THIES NORD", "commune": "THIES EST", "polling_place": "ECOLE TEST",
                         "polling_station": "02"})


def test_admin_rejette_mrz_incoherente(admin_token):
    mrz = _mrz_for("29920000101000427", "000101", "F", "340114", "DIOP", "AWA")
    r = _adm("PUT", "/admin/citizens", admin_token, json={**FICTIF, "date_of_birth": "2000-01-02", "mrz": mrz})
    assert r.status_code == 422 and "date de naissance" in r.text
    bad = list(mrz)
    bad[0] = bad[0][:23] + str((int(bad[0][23]) + 1) % 10) + bad[0][24:]  # chiffre de contrôle du n° de carte
    r = _adm("PUT", "/admin/citizens", admin_token, json={**FICTIF, "mrz": bad})
    assert r.status_code == 422 and "MRZ invalide" in r.text


def test_enrolement_nouveau_citoyen_puis_emission(admin_token, mimoto, tmp_path):
    mrz = _mrz_for("29920000101000427", "000101", "F", "340114", "DIOP", "AWA")
    r = _adm("PUT", "/admin/citizens", admin_token, json={**FICTIF, "mrz": mrz})
    assert r.status_code == 200, r.text
    kc_admin("POST", "/users", json={"username": FICTIF["nin"], "enabled": True, "firstName": "AWA",
                                     "lastName": "DIOP", "email": "awa.diop@test.local", "emailVerified": True,
                                     "credentials": [{"type": "password", "value": "Awa#2026", "temporary": False}]})
    code, verifier, page = mimoto.authorize(FICTIF["nin"], "Awa#2026")
    assert code, page[:300]
    tok = mimoto.token(code, verifier).json()["access_token"]
    vc = credential_request(tok, ldp_body(Wallet().proof(fresh_nonce()))).json()["credential"]
    s = vc["credentialSubject"]
    assert (s["fullName"], s["nin"], s["cardNumber"], s["electoralCommune"]) == (
        "AWA DIOP", "2 999 2000 01234", "2 99 20000101 00042 7", "THIES EST")
    assert "face" not in s  # pas de photo enrôlée
    assert verify_vc(vc, tmp_path)["verified"] is True


def test_revocation(admin_token):
    lst = _adm("GET", "/admin/credentials", admin_token).json()
    target = next(c for c in lst if c["vc_id"] == STATE["vc"]["id"])
    r = _adm("POST", f"/admin/credentials/{target['id']}/revoke", admin_token)
    assert r.json()["status"] == "REVOKED"
    assert psql(f"select status, revoked_at is not null from issuer.issued_credential where id='{target['id']}'") == [
        ["REVOKED", "t"]]
    assert _adm("POST", "/admin/credentials/pas-un-uuid/revoke", admin_token).status_code == 404


# =========================================================== 6. Persistance et redémarrages
def test_redemarrage_issuer_conserve_la_cle(tmp_path):
    compose("restart", "issuer")
    wait_http(f"{ISSUER}/health")
    doc = requests.get(f"{ISSUER}/.well-known/did.json").json()
    assert doc["verificationMethod"][0]["publicKeyMultibase"] == STATE["pub"]
    assert verify_vc(STATE["vc"], tmp_path)["verified"] is True  # VC émis avant redémarrage toujours valide


def test_arret_relance_pile_conserve_les_donnees(tmp_path):
    n_before = psql("select count(*) from issuer.issued_credential")[0][0]
    compose("down")  # sans -v : le volume pgdata est conservé
    compose("up", "-d")
    wait_http(f"{ISSUER}/health", timeout=240)
    wait_http(f"{REALM_URL}/.well-known/openid-configuration", timeout=240)
    assert psql("select count(*) from issuer.issued_credential")[0][0] == n_before
    assert requests.get(f"{ISSUER}/.well-known/did.json").json()["verificationMethod"][0]["publicKeyMultibase"] == STATE["pub"]
    # keycloak-init rejoué : idempotent, realm conservé, le citoyen se connecte toujours
    t = password_token(NIN, CITIZEN_PWD)
    assert "access_token" in t, t
    w = Wallet()
    r = credential_request(t["access_token"], ldp_body(w.proof(fresh_nonce())))
    assert r.status_code == 200 and verify_vc(r.json()["credential"], tmp_path)["verified"] is True
