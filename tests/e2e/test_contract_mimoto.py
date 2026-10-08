"""Contrat Mimoto 0.22 / Inji Web 0.17 (contraintes tirées du code source de mosip/mimoto release-0.22.x).

Ces tests rejouent exactement ce que fait Mimoto, sans Mimoto : ils détectent avant tout déploiement
une incompatibilité de métadonnées, d'authentification client ou de requête de crédential.
"""
import json
import re
from urllib.parse import urlparse

import pytest
import requests

from conftest import (CITIZEN_PWD, CONFIG_ID, ENV, MIMOTO_CLIENT, NIN, PUBLIC_URL, REALM, REALM_URL, ROOT,
                      SCOPE, MimotoLikeClient, as_metadata, claims_of, issuer_metadata, psql, verify_vc)

STATE: dict = {}


def _url(v) -> bool:
    try:
        u = urlparse(v)
        return u.scheme in ("http", "https") and bool(u.netloc)
    except Exception:
        return False


def _blank(v) -> bool:
    return not isinstance(v, str) or not v.strip()


# ------------------------------------------------------------------ métadonnées (validation Bean de Mimoto)
def test_well_known_respecte_les_DTO_de_mimoto():
    """CredentialIssuerWellKnownResponse + CredentialsSupportedResponse + CredentialSupportedDisplayResponse."""
    m = issuer_metadata()
    assert _url(m["credential_issuer"])
    assert m["authorization_servers"] and all(_url(a) for a in m["authorization_servers"])
    assert re.fullmatch(r"https?://.*?/credential", m["credential_endpoint"])          # @Pattern
    assert m["credential_configurations_supported"]
    for cid, c in m["credential_configurations_supported"].items():
        assert not _blank(cid) and not _blank(c["format"]) and not _blank(c["scope"])
        assert c["proof_types_supported"]
        for pt, v in c["proof_types_supported"].items():
            assert not _blank(pt) and v["proof_signing_alg_values_supported"]
        assert c["display"]
        for d in c["display"]:
            for k in ("name", "locale", "background_color", "text_color"):
                assert not _blank(d[k]), k
            assert d["logo"] and _url(d["logo"]["url"])
        cd = c["credential_definition"]
        assert cd["type"] and all(not _blank(t) for t in cd["type"])
        assert isinstance(cd["@context"], list) and all(not _blank(x) for x in cd["@context"])   # List<String>
        for k, v in cd["credentialSubject"].items():
            assert not _blank(k) and v["display"]


def test_metadonnees_du_serveur_d_autorisation_rfc8414():
    """IssuerConfigUtil.getAuthServerWellknown : {authorization_servers[0]}/.well-known/oauth-authorization-server."""
    asm = as_metadata(issuer_metadata()["authorization_servers"][0])
    assert _url(asm["authorization_endpoint"]) and _url(asm["token_endpoint"])
    assert "authorization_code" in asm["grant_types_supported"]
    assert asm["issuer"] == REALM_URL
    assert asm["token_endpoint"].startswith(PUBLIC_URL)   # joignable par Mimoto via l'URL publique


def test_configuration_des_emetteurs_rendue_valide(tmp_path):
    """IssuerDTO : le gabarit inji/mimoto-issuers-config.template.json rendu avec l'URL publique courante."""
    tpl = (ROOT / "inji" / "mimoto-issuers-config.template.json").read_text()
    rendered = (tpl.replace("__PUBLIC_URL__", PUBLIC_URL).replace("__REALM__", REALM)
                .replace("__MIMOTO_CLIENT_ID__", MIMOTO_CLIENT)
                .replace("__MIMOTO_CLIENT_ALIAS__", ENV.get("MIMOTO_CLIENT_ALIAS", "sn-cni-mimoto-client")))
    issuer = json.loads(rendered)["issuers"][0]
    for k in ("issuer_id", "protocol", "client_id", "client_alias", "enabled", "token_endpoint", "credential_issuer_host"):
        assert not _blank(issuer[k]), k
    for k in ("wellknown_endpoint", "token_endpoint", "proxy_token_endpoint", "credential_issuer_host"):
        assert _url(issuer[k]), k
    assert issuer["protocol"] == "OpenId4VCI" and issuer["qr_code_type"] in ("OnlineSharing", "EmbeddedVC")
    assert requests.get(issuer["wellknown_endpoint"]).json()["credential_issuer"] == issuer["credential_issuer_host"]
    assert issuer["proxy_token_endpoint"] == as_metadata(issuer_metadata()["authorization_servers"][0])["token_endpoint"]
    for d in issuer["display"]:
        assert {"name", "logo", "title", "description", "language"} <= set(d)
        assert requests.get(d["logo"]["url"]).status_code == 200


# ------------------------------------------------------------------ parcours Inji Web -> Mimoto -> Keycloak -> issuer
def test_autorisation_comme_inji_web(mimoto):
    """scope = scope de la configuration seul (pas « openid »), redirect_uri = http://localhost:3004/redirect."""
    code, verifier, page = mimoto.authorize(NIN, CITIZEN_PWD)
    assert code, page[:300]
    STATE.update(code=code, verifier=verifier)


def test_jeton_avec_client_assertion_sans_kid(mimoto):
    """JoseUtil : assertion RS256 sans kid, aud = token_endpoint ; Keycloak la vérifie par certificat."""
    r = mimoto.token(STATE["code"], STATE["verifier"])
    assert r.status_code == 200, r.text
    tok = r.json()
    assert tok["access_token"] and tok["token_type"].lower() == "bearer" and isinstance(tok["expires_in"], int)
    c = claims_of(tok["access_token"])
    assert c["azp"] == MIMOTO_CLIENT and c["preferred_username"] == NIN and SCOPE in c["scope"].split()
    STATE["token"] = tok


def test_algorithme_de_preuve_choisi_par_mimoto():
    """Priorité ED25519 > ES256K > ES256 > RS256 parmi proof_signing_alg_values_supported."""
    assert MimotoLikeClient.resolve_alg(issuer_metadata()) == "ES256K"


def test_requete_de_credential_de_mimoto(mimoto, tmp_path):
    """LdpVcCredentialFormatHandler + SigningKeyUtil : nonce null (Keycloak ne renvoie pas de c_nonce)."""
    assert STATE["token"].get("c_nonce") is None
    r, alg = mimoto.credential_request(STATE["token"]["access_token"], STATE["token"].get("c_nonce"))
    assert r.status_code == 200, r.text
    body = r.json()
    assert "credential" in body   # VerifiableCredentialResponse.getCredential()
    vc = body["credential"]
    assert vc["credentialSubject"]["id"].startswith("did:jwk:")
    assert verify_vc(vc, tmp_path)["verified"] is True
    STATE["vc"] = vc


@pytest.mark.parametrize("locale", ["fr", "en"])
def test_affichage_des_champs_par_mimoto(locale):
    """loadDisplayPropertiesFromWellknown : chaque champ du VC a un libellé dans la langue, et figure dans « order »."""
    cfg = issuer_metadata()["credential_configurations_supported"][CONFIG_ID]
    subj = cfg["credential_definition"]["credentialSubject"]
    fields = [k for k in STATE["vc"]["credentialSubject"] if k != "id"]
    for k in fields:
        assert any(d["locale"] == locale and d["name"] for d in subj[k]["display"]), k
        assert k in cfg["order"] or k == "face", k   # photo : portrait, hors liste des champs


def test_vc_de_mimoto_journalise():
    rows = psql(f"select client_id, status from issuer.issued_credential where vc_id = '{STATE['vc']['id']}'")
    assert rows == [[MIMOTO_CLIENT, "VALID"]]


def test_cle_p12_de_mimoto_lisible():
    """Si scripts/inji-up.sh a généré la clé : alias attendu présent (P12KeyStoreManager.loadP12)."""
    p12 = ROOT / "inji" / "certs" / "oidckeystore.p12"
    if not p12.exists():
        pytest.skip("clé Mimoto non générée (profil inji non utilisé)")
    from cryptography.hazmat.primitives.serialization import pkcs12
    k = pkcs12.load_pkcs12(p12.read_bytes(), ENV.get("MIMOTO_P12_PASSWORD", "dummypassword").encode())
    assert k.key is not None and k.cert is not None
    assert k.cert.friendly_name.decode() == ENV.get("MIMOTO_CLIENT_ALIAS", "sn-cni-mimoto-client")


def test_json_en_ascii_pour_mimoto():
    """Mimoto (RestTemplate) décode un « application/json » sans charset en ISO-8859-1 : les réponses de l'issuer
    sont en ASCII pur (accents échappés \\u00e9) avec charset=utf-8, et la photo n'est pas listée comme champ texte."""
    import json as _json
    import requests as _rq
    from conftest import ISSUER
    r = _rq.get(f"{ISSUER}/.well-known/openid-credential-issuer")
    assert "charset=utf-8" in r.headers["content-type"]
    r.content.decode("ascii")                                   # aucun octet non ASCII
    meta = _json.loads(r.content)
    cfg = meta["credential_configurations_supported"][CONFIG_ID]
    assert cfg["display"][0]["name"] == "Carte d'identité CEDEAO – Sénégal"   # accents intacts après décodage
    assert "face" not in cfg["order"] and "face" in cfg["credential_definition"]["credentialSubject"]
    tpl = (ROOT / "inji" / "mimoto-issuers-config.template.json").read_bytes()
    tpl.decode("ascii")
