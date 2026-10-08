"""Lecture automatique (OCR) des photos recto / verso d'une carte CEDEAO (v3.5).

Images de test SYNTHÉTIQUES (personne fictive) générées par tests/tools/gen_test_card.py : carte posée sur une
table, photographiée de biais (rotation, perspective, flou, JPEG).
"""
import base64
import re
from pathlib import Path

import pytest
import requests

from conftest import ENV, ISSUER, NIN, CITIZEN_PWD, PUBLIC_URL, kc_admin, password_token, psql

DATA = Path(__file__).parent / "data"
RECTO = (DATA / "carte-test-recto.jpg").read_bytes()
VERSO = (DATA / "carte-test-verso.jpg").read_bytes()
NIN_OCR = "2045198501234"
ATTENDU = {
    "card_number": "2 06 19850412 00321 5", "family_name": "KANE", "given_name": "FATOU BINETOU", "sex": "F",
    "date_of_birth": "1985-04-12", "date_of_expiry": "2031-02-02", "date_of_issue": "2021-02-03",
    "place_of_birth": "ZIGUINCHOR", "height_cm": 168, "registration_center": "DAKAR-PLATEAU",
    "address": "12 RUE CARNOT DAKAR", "nin": "2 045 1985 01234", "voter_number": "204518765", "region": "DAKAR",
    "department": "DAKAR", "arrondissement": "DAKAR PLATEAU", "commune": "DAKAR-PLATEAU",
    "polling_place": "ECOLE MANGUIERS UNITE 2", "polling_station": "04",
    "mrz": "I<SEN206198504<120032157<<<<<<\n8504124F3102020SEN<<<<<<<<<<<6\nKANE<<FATOU<BINETOU<<<<<<<<<<<",
}


def ocr(token, recto=RECTO, verso=VERSO, **kw):
    files = {"recto": ("recto.jpg", recto, "image/jpeg"), "verso": ("verso.jpg", verso, "image/jpeg")}
    return requests.post(f"{ISSUER}/admin/ocr", headers={"Authorization": f"Bearer {token}"} if token else {},
                         files=files, timeout=120, **kw)


@pytest.fixture(scope="module", autouse=True)
def _clean():
    psql(f"delete from issuer.issued_credential where nin='{NIN_OCR}'; delete from issuer.electoral_registration "
         f"where nin='{NIN_OCR}'; delete from issuer.id_card where nin='{NIN_OCR}'; "
         f"delete from issuer.person where nin='{NIN_OCR}'")
    for u in kc_admin("GET", "/users", params={"username": NIN_OCR, "exact": "true"}).json():
        kc_admin("DELETE", f"/users/{u['id']}")
    yield


def test_ocr_lit_toute_la_carte(admin_token):
    r = ocr(admin_token)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["values"] | {} == {**ATTENDU, "nationality": "SEN"}, d["values"]
    assert d["mrz"]["valid"] is True and d["missing"] == [] and d["warnings"] == []
    assert d["card_detected"] == {"recto": True, "verso": True} and d["swapped"] is False
    src = {k: f["source"] for k, f in d["fields"].items()}
    assert {k for k, s in src.items() if s == "mrz"} == {"card_number", "family_name", "given_name", "sex",
                                                         "date_of_birth", "date_of_expiry", "nationality", "mrz"}
    photo = base64.b64decode(d["photo_jpeg_base64"])
    assert photo[:3] == b"\xff\xd8\xff" and 1000 < len(photo) <= 55_000
    assert d["duration_ms"] < 60_000


def test_ocr_puis_validation_sans_ressaisie(admin_token):
    """Les valeurs lues passent tels quels les contrôles d'enregistrement (MRZ ↔ recto, formats)."""
    v = ocr(admin_token).json()["values"]
    body = {k: v[k] for k in ("nin", "card_number", "given_name", "family_name", "date_of_birth", "place_of_birth",
                              "sex", "height_cm", "address", "date_of_issue", "date_of_expiry", "registration_center")}
    body["mrz"] = v["mrz"].split("\n")
    body["electoral"] = {k: v[k] for k in ("voter_number", "region", "department", "arrondissement", "commune",
                                           "polling_place", "polling_station")}
    r = requests.post(f"{ISSUER}/admin/citizens/validate", headers={"Authorization": f"Bearer {admin_token}"}, json=body)
    assert r.json() == {"valid": True, "errors": {}, "warnings": [], "mrz": body["mrz"], "existing_citizen": False}


def test_ocr_faces_inversees_corrigees(admin_token):
    d = ocr(admin_token, recto=VERSO, verso=RECTO).json()
    assert d["swapped"] is True and any("inversés" in w for w in d["warnings"])
    assert {k: d["values"].get(k) for k in ATTENDU} == ATTENDU


def test_ocr_refus(admin_token):
    assert ocr(None).status_code == 401
    citizen = password_token(NIN, CITIZEN_PWD, scope="openid")["access_token"]
    assert ocr(citizen).status_code == 403
    r = ocr(admin_token, recto=b"pas une image")
    assert r.status_code == 422 and "illisible" in r.json()["error_description"]
    r = requests.post(f"{ISSUER}/admin/ocr", headers={"Authorization": f"Bearer {admin_token}"},
                      files={"recto": ("r.jpg", RECTO, "image/jpeg")})
    assert r.status_code == 422


def test_parcours_navigateur_ocr_puis_enregistrement(tmp_path):
    """Chromium : dépôt des 2 photos → « Lire la carte » → champs pré-remplis → Enregistrer → mot de passe."""
    pw = pytest.importorskip("playwright.sync_api")
    (tmp_path / "r.jpg").write_bytes(RECTO)
    (tmp_path / "v.jpg").write_bytes(VERSO)
    with pw.sync_playwright() as p:
        try:
            browser = p.chromium.launch()
        except Exception as e:  # noqa: BLE001
            pytest.skip(f"Chromium indisponible : {e}")
        page = browser.new_context(ignore_https_errors=True, locale="fr-FR").new_page()
        page.on("dialog", lambda d: d.accept())
        page.goto(f"{PUBLIC_URL}/admin/")
        page.click("#login")
        page.fill("#username", "issuer-admin")
        page.fill("#password", ENV.get("ISSUER_ADMIN_PASSWORD", "admin-issuer-change-me"))
        page.click("#kc-login")
        page.wait_for_selector("text=SECK", timeout=30_000)
        page.click("#new")
        assert page.is_disabled("#ocr")
        page.set_input_files("#scan-recto", str(tmp_path / "r.jpg"))
        page.set_input_files("#scan-verso", str(tmp_path / "v.jpg"))
        page.wait_for_function("!document.querySelector('#ocr').disabled")
        page.click("#ocr")
        page.wait_for_selector("#ocr-msg .msg.ok", timeout=90_000)
        assert "MRZ valide" in page.text_content("#ocr-msg")
        got = {k: page.input_value(f"[name={k}]") for k in ("card_number", "family_name", "given_name", "nin",
                                                            "date_of_issue", "place_of_birth", "commune", "voter_number")}
        assert got == {"card_number": "2 06 19850412 00321 5", "family_name": "KANE", "given_name": "FATOU BINETOU",
                       "nin": "2 045 1985 01234", "date_of_issue": "2021-02-03", "place_of_birth": "ZIGUINCHOR",
                       "commune": "DAKAR-PLATEAU", "voter_number": "204518765"}
        assert page.input_value("select[name=sex]") == "F"
        assert page.locator(".src.mrz").count() >= 6 and page.locator(".ocr-filled").count() >= 15
        assert page.get_attribute("#photo-preview", "src").startswith("data:image/jpeg;base64,")
        page.click("#save")
        page.wait_for_selector("#pwd", timeout=30_000)
        assert re.fullmatch(r"[A-Za-z2-9]{4}-[A-Za-z2-9]{4}-[A-Za-z2-9]{4}", page.text_content("#pwd"))
        browser.close()
    rows = psql(f"select p.given_name, p.family_name, length(p.photo_jpeg) > 1000, c.card_number, e.voter_number "
                f"from issuer.person p join issuer.id_card c using (nin) "
                f"join issuer.electoral_registration e using (nin) where p.nin='{NIN_OCR}'")
    assert rows == [["FATOU BINETOU", "KANE", "t", "20619850412003215", "204518765"]]
