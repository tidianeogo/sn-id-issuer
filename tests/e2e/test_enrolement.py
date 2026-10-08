"""Module d'enrôlement (v3.4) : interface /admin/, API d'ajout de cartes, comptes Keycloak des titulaires."""
import base64
import os
import re
from pathlib import Path

import pytest
import requests

from conftest import (CITIZEN_PWD, ISSUER, NIN, PUBLIC_URL, REALM_URL, Wallet, compose, credential_request,
                      fresh_nonce, kc_admin, kc_client, ldp_body, password_token, psql, verify_vc)

PHOTO = (Path(__file__).parent / "data" / "photo-test.jpg").read_bytes()
NOUVEAU = dict(nin="1 123 1990 00077", card_number="1 05 19900315 00077 3", given_name="Moussa Ibrahima",
               family_name="ndiaye", date_of_birth="1990-03-15", place_of_birth="KAOLACK", sex="M", height_cm=176,
               address="CITE KEUR GORGUI VILLA 12", date_of_issue="2022-05-02", date_of_expiry="2032-05-01",
               registration_center="DAKAR-PLATEAU",
               electoral={"voter_number": "123456789", "region": "DAKAR", "department": "DAKAR",
                          "arrondissement": "GRAND DAKAR", "commune": "SICAP LIBERTE",
                          "polling_place": "ECOLE SICAP 1", "polling_station": "03"})
NIN2 = "1123199000077"


def mrz_for(card, dob, sex, exp, family, given):
    from app.mrz import check_digit
    l1 = f"I<SEN{card[:9]}<{card[9:]}{check_digit(card)}".ljust(30, "<")
    l2 = f"{dob}{check_digit(dob)}{sex}{exp}{check_digit(exp)}SEN".ljust(29, "<")
    l2 += check_digit(l1[5:30] + l2[0:7] + l2[8:15] + l2[18:29])
    l3 = f"{family}<<{given.replace(' ', '<')}".ljust(30, "<")
    return [l1, l2, l3]


MRZ2 = mrz_for("10519900315000773", "900315", "M", "320501", "NDIAYE", "MOUSSA IBRAHIMA")
SEED_MRZ = ["I<SEN104195311<080000164<<<<<<", "5311080M2705310SEN<<<<<<<<<<<4", "SECK<<MOUHAMED<TIDIANE<<<<<<<<"]


def adm(method, path, token, **kw):
    return requests.request(method, f"{ISSUER}{path}", headers={"Authorization": f"Bearer {token}"}, **kw)


def kc_user(username):
    users = kc_admin("GET", "/users", params={"username": username, "exact": "true"}).json()
    return users[0] if users else None


def purge(nin):
    psql(f"delete from issuer.issued_credential where nin='{nin}'; delete from issuer.electoral_registration "
         f"where nin='{nin}'; delete from issuer.id_card where nin='{nin}'; delete from issuer.person where nin='{nin}'")
    u = kc_user(nin)
    if u:
        kc_admin("DELETE", f"/users/{u['id']}")


@pytest.fixture(scope="module", autouse=True)
def _clean():
    for n in (NIN2, "1088198800012"):
        purge(n)
    yield


# ------------------------------------------------------------------ interface et configuration
def test_interface_web_servie():
    r = requests.get(f"{ISSUER}/admin", allow_redirects=False)
    assert r.status_code in (302, 307) and r.headers["location"].endswith("/admin/")
    r = requests.get(f"{ISSUER}/admin/")
    assert r.status_code == 200 and "Enrôlement des cartes" in r.text and "/admin/app.js" in r.text
    js = requests.get(f"{ISSUER}/admin/app.js")
    assert js.status_code == 200 and "code_challenge_method" in js.text
    cfg = requests.get(f"{ISSUER}/admin/config").json()
    assert cfg == {"authority": REALM_URL, "client_id": "issuer-admin-ui", "public_url": PUBLIC_URL,
                   "offer_url": f"{PUBLIC_URL}/credential-offer", "admin_role": "issuer-admin",
                   "accounts_enabled": True}


def test_clients_keycloak_de_l_enrolement():
    ui = kc_client("issuer-admin-ui")
    assert ui["publicClient"] and ui["standardFlowEnabled"] and not ui["directAccessGrantsEnabled"]
    assert ui["attributes"]["pkce.code.challenge.method"] == "S256"
    assert f"{PUBLIC_URL}/admin/*" in ui["redirectUris"] and "http://localhost:8088/admin/*" in ui["redirectUris"]
    assert any(m["protocolMapper"] == "oidc-audience-mapper" and
               m["config"]["included.custom.audience"] == "sn-id-issuer" for m in ui["protocolMappers"])
    be = kc_client("issuer-backend")
    assert be["serviceAccountsEnabled"] and not be["publicClient"] and not be["standardFlowEnabled"]
    sa = kc_admin("GET", f"/clients/{be['id']}/service-account-user").json()
    rm = kc_client("realm-management")
    roles = {r["name"] for r in kc_admin("GET", f"/users/{sa['id']}/role-mappings/clients/{rm['id']}").json()}
    assert {"manage-users", "view-users", "query-users"} <= roles


def test_api_reservee_au_role_admin():
    assert requests.post(f"{ISSUER}/admin/mrz/parse", json={"mrz": SEED_MRZ}).status_code == 401
    citizen = password_token(NIN, CITIZEN_PWD, scope="openid")["access_token"]
    for m, p, body in (("POST", "/admin/mrz/parse", {"mrz": SEED_MRZ}), ("GET", "/admin/citizens", None),
                       ("POST", "/admin/citizens/validate", {**NOUVEAU, "mrz": MRZ2}),
                       ("POST", f"/admin/citizens/{NIN}/account", None), ("GET", f"/admin/citizens/{NIN}/photo", None),
                       ("PATCH", f"/admin/citizens/{NIN}", {"status": "SUSPENDED"})):
        assert adm(m, p, citizen, json=body).status_code == 403, p


# ------------------------------------------------------------------ MRZ et contrôles
def test_lecture_mrz_pour_pre_remplissage(admin_token):
    r = adm("POST", "/admin/mrz/parse", admin_token, json={"mrz": " i<sen104195311<080000164\n5311080M2705310SEN<<<<<<<<<<<4\nSECK<<MOUHAMED<TIDIANE"})
    assert r.status_code == 200, r.text
    m = r.json()
    assert (m["card_number"], m["card_number_display"], m["date_of_birth"], m["date_of_expiry"], m["sex"],
            m["family_name"], m["given_name"], m["issuing_state"]) == (
        "10419531108000016", "1 04 19531108 00001 6", "1953-11-08", "2027-05-31", "M", "SECK", "MOUHAMED TIDIANE", "SEN")
    assert m["lines"] == SEED_MRZ          # lignes complétées à 30 caractères
    bad = list(SEED_MRZ)
    bad[1] = bad[1][:6] + "9" + bad[1][7:]  # chiffre de contrôle de la date de naissance
    r = adm("POST", "/admin/mrz/parse", admin_token, json={"mrz": bad})
    assert r.status_code == 422 and "date de naissance" in r.json()["error_description"]


def test_validation_signale_erreurs_conflits_et_avertissements(admin_token):
    ok = adm("POST", "/admin/citizens/validate", admin_token, json={**NOUVEAU, "mrz": MRZ2}).json()
    assert ok == {"valid": True, "errors": {}, "warnings": [], "mrz": MRZ2, "existing_citizen": False}
    # n° de carte et n° d'électeur déjà attribués à un autre NIN ; NIN mal formé
    seed_card = {**NOUVEAU, "card_number": "1 04 19531108 00001 6", "date_of_birth": "1953-11-08",
                 "date_of_expiry": "2027-05-31", "family_name": "SECK", "given_name": "MOUHAMED TIDIANE",
                 "mrz": SEED_MRZ, "electoral": {**NOUVEAU["electoral"], "voter_number": "106567885"}}
    v = adm("POST", "/admin/citizens/validate", admin_token, json=seed_card).json()
    assert not v["valid"] and set(v["errors"]) == {"card_number", "voter_number"}
    assert "1 251 1953 02325" in v["errors"]["card_number"]
    assert any("année" in w for w in v["warnings"])
    r = adm("PUT", "/admin/citizens", admin_token, json=seed_card)
    assert r.status_code == 409 and set(r.json()["fields"]) == {"card_number", "voter_number"}
    v = adm("POST", "/admin/citizens/validate", admin_token, json={**NOUVEAU, "nin": "12345", "mrz": MRZ2}).json()
    assert v["errors"] == {"nin": "13 chiffres attendus (ex. 1 123 1990 00077)"}
    # avertissements non bloquants : sexe / année du NIN, carte expirée
    v = adm("POST", "/admin/citizens/validate", admin_token,
            json={**NOUVEAU, "nin": "2123198800077", "mrz": MRZ2}).json()
    assert v["valid"] and len(v["warnings"]) == 2
    # pays émetteur autre que le Sénégal : refusé
    civ = [MRZ2[0].replace("I<SEN", "I<CIV"), MRZ2[1], MRZ2[2]]
    from app.mrz import check_digit
    civ[1] = civ[1][:29] + check_digit(civ[0][5:30] + civ[1][0:7] + civ[1][8:15] + civ[1][18:29])
    v = adm("POST", "/admin/citizens/validate", admin_token, json={**NOUVEAU, "mrz": civ}).json()
    assert "CIV" in v["errors"]["mrz"]


def test_photo_refusee_si_pas_jpeg_ou_trop_lourde(admin_token):
    png = base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"0" * 100).decode()
    r = adm("PUT", "/admin/citizens", admin_token, json={**NOUVEAU, "mrz": MRZ2, "photo_jpeg_base64": png})
    assert r.status_code == 422 and r.json()["fields"] == {"photo": "JPEG attendu"}
    big = base64.b64encode(b"\xff\xd8\xff" + os.urandom(70_000)).decode()
    r = adm("PUT", "/admin/citizens", admin_token, json={**NOUVEAU, "mrz": MRZ2, "photo_jpeg_base64": big})
    assert r.status_code == 422 and "trop lourde" in r.json()["error_description"]
    assert psql(f"select count(*) from issuer.person where nin='{NIN2}'") == [["0"]]


# ------------------------------------------------------------------ enrôlement complet
def test_enrolement_avec_compte_photo_puis_emission_inji(admin_token, mimoto, tmp_path):
    body = {**NOUVEAU, "mrz": MRZ2, "photo_jpeg_base64": base64.b64encode(PHOTO).decode()}
    r = adm("PUT", "/admin/citizens", admin_token, json=body)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["created"] is True and out["warnings"] == []
    assert (out["nin"], out["given_name"], out["family_name"], out["has_photo"]) == (
        NIN2, "MOUSSA IBRAHIMA", "NDIAYE", True)          # NIN sans espaces, noms en majuscules
    acc = out["account"]
    assert acc["created"] and acc["enabled"] and acc["username"] == NIN2
    assert re.fullmatch(r"[A-Za-z2-9]{4}-[A-Za-z2-9]{4}-[A-Za-z2-9]{4}", acc["temporary_password"])
    u = kc_user(NIN2)
    assert u["enabled"] and (u["firstName"], u["lastName"]) == ("MOUSSA IBRAHIMA", "NDIAYE")
    assert "UPDATE_PASSWORD" in u["requiredActions"]
    assert adm("GET", f"/admin/citizens/{NIN2}/photo", admin_token).content == PHOTO

    # Le titulaire se connecte (changement imposé du mot de passe temporaire) et reçoit sa carte
    code, verifier, page = mimoto.authorize(NIN2, acc["temporary_password"], new_password="Moussa#2026")
    assert code, page[:400]
    tok = mimoto.token(code, verifier).json()["access_token"]
    r = credential_request(tok, ldp_body(Wallet().proof(fresh_nonce())))
    assert r.status_code == 200, r.text
    vc = r.json()["credential"]
    s = vc["credentialSubject"]
    assert (s["fullName"], s["nin"], s["cardNumber"], s["voterNumber"], s["electoralCommune"], s["height"]) == (
        "MOUSSA IBRAHIMA NDIAYE", "1 123 1990 00077", "1 05 19900315 00077 3", "123456789", "SICAP LIBERTE", "176 cm")
    assert s["face"] == "data:image/jpeg;base64," + base64.b64encode(PHOTO).decode()
    assert s["mrz"] == "\n".join(MRZ2)
    assert verify_vc(vc, tmp_path)["verified"] is True
    assert "UPDATE_PASSWORD" not in kc_user(NIN2)["requiredActions"]

    # Mise à jour : pas de nouveau mot de passe, compte conservé
    r = adm("PUT", "/admin/citizens", admin_token, json={**body, "address": "NOUVELLE ADRESSE", "photo_jpeg_base64": None})
    out = r.json()
    assert r.status_code == 200 and out["created"] is False and out["address"] == "NOUVELLE ADRESSE"
    assert out["account"]["created"] is False and out["account"]["temporary_password"] is None
    assert adm("GET", f"/admin/citizens/{NIN2}/photo", admin_token).content == PHOTO   # photo conservée

    lst = adm("GET", "/admin/citizens", admin_token).json()
    me = next(c for c in lst if c["nin"] == NIN2)
    assert me["account"] == {"exists": True, "enabled": True} and me["cards"][0]["mrz"] == MRZ2
    seed = next(c for c in lst if c["nin"] == NIN)
    assert seed["account"]["exists"] is True


def test_reinitialisation_suspension_et_carte_perdue(admin_token, mimoto):
    r = adm("POST", f"/admin/citizens/{NIN2}/account", admin_token)
    assert r.status_code == 200 and r.json()["temporary_password"] and r.json()["created"] is False
    assert "UPDATE_PASSWORD" in kc_user(NIN2)["requiredActions"]
    code, verifier, _ = mimoto.authorize(NIN2, "Moussa#2026")            # ancien mot de passe : refusé
    assert code is None
    code, verifier, page = mimoto.authorize(NIN2, r.json()["temporary_password"], new_password="Moussa#2027")
    assert code, page[:300]
    tok = mimoto.token(code, verifier).json()["access_token"]

    r = adm("PATCH", f"/admin/citizens/{NIN2}", admin_token, json={"status": "SUSPENDED"})
    assert r.status_code == 200 and r.json()["status"] == "SUSPENDED" and r.json()["account_synced"] is True
    assert kc_user(NIN2)["enabled"] is False
    r = credential_request(tok, ldp_body(Wallet().proof(fresh_nonce())))
    assert r.status_code == 403 and "SUSPENDED" in r.json()["error_description"]
    assert adm("PATCH", f"/admin/citizens/{NIN2}", admin_token, json={"status": "ACTIVE"}).json()["account_synced"]
    assert kc_user(NIN2)["enabled"] is True

    assert adm("PATCH", "/admin/cards/10519900315000773", admin_token, json={"status": "LOST"}).json()["status"] == "LOST"
    r = credential_request(tok, ldp_body(Wallet().proof(fresh_nonce())))
    assert r.status_code == 404                                           # plus de carte active
    assert adm("PATCH", "/admin/cards/1 05 19900315 00077 3", admin_token, json={"status": "ACTIVE"}).status_code == 200
    assert credential_request(tok, ldp_body(Wallet().proof(fresh_nonce()))).status_code == 200
    assert adm("PATCH", "/admin/cards/10519900315000773", admin_token, json={"status": "PERDUE"}).status_code == 422
    assert adm("PATCH", "/admin/citizens/0000000000000", admin_token, json={"status": "ACTIVE"}).status_code == 404


# ------------------------------------------------------------------ parcours réel dans un navigateur
def test_parcours_navigateur_interface_enrolement(tmp_path):
    """Chromium headless : connexion Keycloak (PKCE), lecture MRZ, saisie, photo, enregistrement."""
    pw = pytest.importorskip("playwright.sync_api")
    from conftest import ENV
    nin, card = "1088198800012", "10519881224000128"
    mrz = mrz_for(card, "881224", "F", "330110", "FALL", "AMINATA")
    photo = tmp_path / "photo.jpg"
    photo.write_bytes(PHOTO)
    dialogs = []
    with pw.sync_playwright() as p:
        try:
            browser = p.chromium.launch()
        except Exception as e:  # navigateur non installé sur ce poste
            pytest.skip(f"Chromium indisponible : {e}")
        page = browser.new_context(ignore_https_errors=True, locale="fr-FR").new_page()
        page.on("dialog", lambda d: (dialogs.append(d.message), d.accept()))
        page.goto(f"{PUBLIC_URL}/admin/")
        page.click("#login")
        page.fill("#username", "issuer-admin")
        page.fill("#password", ENV.get("ISSUER_ADMIN_PASSWORD", "admin-issuer-change-me"))
        page.click("#kc-login")
        page.wait_for_selector("text=SECK", timeout=30_000)
        assert page.text_content("#who") == "issuer-admin"
        page.click("#new")
        page.fill("textarea[name=mrz]", "\n".join(l.rstrip("<") for l in mrz))   # saisie sans les « < » finaux
        page.click("#read-mrz")
        page.wait_for_selector(".msg.ok")
        assert page.input_value("input[name=card_number]") == "1 05 19881224 00012 8"
        assert (page.input_value("input[name=family_name]"), page.input_value("input[name=given_name]"),
                page.input_value("select[name=sex]"), page.input_value("input[name=date_of_birth]")) == (
            "FALL", "AMINATA", "F", "1988-12-24")
        for k, v in {"place_of_birth": "ZIGUINCHOR", "height_cm": "168", "date_of_issue": "2023-01-11",
                     "registration_center": "ZIGUINCHOR", "address": "QUARTIER BOUCOTTE", "nin": "1 088 1988 00012",
                     "voter_number": "555666777", "region": "ZIGUINCHOR", "commune": "ZIGUINCHOR"}.items():
            page.fill(f"[name={k}]", v)
        page.set_input_files("#photo", str(photo))
        page.wait_for_function("document.querySelector('#photo-preview').src.startsWith('data:image/jpeg')")
        page.click("#check")
        page.wait_for_selector("text=Tout est cohérent")
        page.click("#save")
        page.wait_for_selector("#pwd", timeout=20_000)
        pwd = page.text_content("#pwd")
        assert re.fullmatch(r"[A-Za-z2-9]{4}-[A-Za-z2-9]{4}-[A-Za-z2-9]{4}", pwd)
        page.click("#result-close")
        page.fill("#search", "fall")
        page.wait_for_selector("tr[data-nin='1088198800012']")
        browser.close()
    # le NIN 1 088 1988 … commence par 1 alors que le sexe est F : avertissement confirmé par l'agent
    assert any("1er chiffre" in d for d in dialogs)
    rows = psql(f"select p.sex, p.place_of_birth, length(p.photo_jpeg) > 1000, c.card_number "
                f"from issuer.person p join issuer.id_card c using (nin) where p.nin='{nin}'")
    assert rows == [["F", "ZIGUINCHOR", "t", card]]
    assert kc_user(nin)["enabled"] is True
