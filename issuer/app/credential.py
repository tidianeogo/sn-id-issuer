"""Définition du type d'identifiant et construction du VC à partir de la base."""
import base64
import uuid
from datetime import datetime, timezone

from .config import get_settings
from .crypto import CREDENTIALS_V1, ED25519_2020_V1
from .db import IdCard, Person
from .mrz import MRZError, consistency_errors, parse_td1

CONFIG_ID = "SenegalNationalID_ldp"
VC_TYPE = ["VerifiableCredential", "SenegalNationalIDCredential"]

# (clé, libellé fr, libellé en) — l'ordre est celui d'affichage dans Inji
FIELDS = [
    ("fullName", "Nom complet", "Full name"),
    ("givenName", "Prénoms", "Given names"),
    ("familyName", "Nom", "Family name"),
    ("nin", "NIN", "National identification number"),
    ("cardNumber", "N° de la carte d'identité", "ID card number"),
    ("dateOfBirth", "Date de naissance", "Date of birth"),
    ("placeOfBirth", "Lieu de naissance", "Place of birth"),
    ("gender", "Sexe", "Sex"),
    ("height", "Taille", "Height"),
    ("nationality", "Nationalité", "Nationality"),
    ("address", "Adresse du domicile", "Home address"),
    ("dateOfIssue", "Date de délivrance", "Date of issue"),
    ("dateOfExpiry", "Date d'expiration", "Date of expiry"),
    ("registrationCenter", "Centre d'enregistrement", "Registration centre"),
    ("documentType", "Type de document", "Document type"),
    ("issuingCountry", "Pays de délivrance", "Issuing country"),
    ("voterNumber", "Numéro d'électeur", "Voter number"),
    ("electoralRegion", "Région", "Region"),
    ("electoralDepartment", "Département", "Department"),
    ("electoralArrondissement", "Arrondissement", "Arrondissement"),
    ("electoralCommune", "Commune", "Municipality"),
    ("pollingPlace", "Lieu de vote", "Polling place"),
    ("pollingStation", "Bureau de vote", "Polling station"),
    ("mrz", "Zone de lecture automatique (MRZ)", "Machine readable zone"),
    # photo : Mimoto (clés image,face,photo…) et Inji Wallet l'affichent comme portrait, pas comme texte
    ("face", "Photo", "Photo"),
]


class DataIntegrityError(Exception):
    pass


def contexts() -> list[str]:
    return [CREDENTIALS_V1, get_settings().sn_context_url, ED25519_2020_V1]


def credential_configuration() -> dict:
    s = get_settings()
    display = lambda name, loc: {"name": name, "locale": loc,  # noqa: E731
                                 "logo": {"url": f"{s.base}/static/logo.png", "alt_text": "Sénégal"},
                                 "background_color": "#E8F3EC", "text_color": "#0B3D2E"}
    return {
        "format": "ldp_vc",
        "scope": s.credential_scope,
        "cryptographic_binding_methods_supported": ["did:jwk"],
        "credential_signing_alg_values_supported": ["Ed25519Signature2020"],
        # Mimoto 0.22 choisit dans l'ordre ED25519 > ES256K > ES256 > RS256 parmi cette liste ;
        # Inji Wallet 0.22 croise la liste avec ses types de clé (ES256, ES256K, RS256, Ed25519 → « EdDSA »).
        "proof_types_supported": {"jwt": {"proof_signing_alg_values_supported": ["ES256", "ES256K", "RS256", "EdDSA"]}},
        "credential_definition": {
            "@context": contexts(),
            "type": VC_TYPE,
            "credentialSubject": {
                k: {"display": [{"name": fr, "locale": "fr"}, {"name": en, "locale": "en"}]} for k, fr, en in FIELDS
            },
        },
        "display": [display("Carte d'identité CEDEAO – Sénégal", "fr"), display("ECOWAS Identity Card – Senegal", "en")],
        # « face » reste déclaré (Mimoto, PDF) mais hors de « order » : Inji Wallet affiche alors la photo en
        # portrait au lieu d'imprimer sa valeur base64 dans la liste des champs
        "order": [k for k, _, _ in FIELDS if k != "face"],
    }


def fmt_card(n: str) -> str:
    # 10419531108000016 -> "1 04 19531108 00001 6" (format imprimé au recto)
    return f"{n[0]} {n[1:3]} {n[3:11]} {n[11:16]} {n[16:]}" if len(n) == 17 else n


def fmt_nin(n: str) -> str:
    # 1251195302325 -> "1 251 1953 02325" (format imprimé au verso)
    return f"{n[0]} {n[1:4]} {n[4:8]} {n[8:]}" if len(n) == 13 else n


def check_card_integrity(p: Person, card: IdCard) -> None:
    """Refuse d'émettre si la MRZ du verso ne correspond pas aux données du recto."""
    try:
        td1 = parse_td1([card.mrz_line1, card.mrz_line2, card.mrz_line3])
    except MRZError as e:
        raise DataIntegrityError(f"MRZ invalide : {e}")
    errs = consistency_errors(td1, card_number=card.card_number, date_of_birth=p.date_of_birth,
                              date_of_expiry=card.date_of_expiry, sex=p.sex,
                              family_name=p.family_name, given_name=p.given_name)
    if errs:
        raise DataIntegrityError("MRZ incohérente avec le recto : " + ", ".join(errs))


def build_credential(p: Person, card: IdCard, holder_id: str | None) -> tuple[str, dict]:
    s = get_settings()
    e = p.electoral
    now = datetime.now(timezone.utc).replace(microsecond=0)
    subject = {
        "fullName": f"{p.given_name} {p.family_name}",
        "givenName": p.given_name,
        "familyName": p.family_name,
        "nin": fmt_nin(p.nin),
        "cardNumber": fmt_card(card.card_number),
        "dateOfBirth": p.date_of_birth.isoformat(),
        "placeOfBirth": p.place_of_birth,
        "gender": p.sex,
        "height": f"{p.height_cm} cm" if p.height_cm else None,
        "nationality": p.nationality,
        "address": p.address,
        "dateOfIssue": card.date_of_issue.isoformat(),
        "dateOfExpiry": card.date_of_expiry.isoformat(),
        "registrationCenter": card.registration_center,
        "documentType": "Carte d'identité CEDEAO",
        "issuingCountry": card.issuing_country,
        "voterNumber": e.voter_number if e else None,
        "electoralRegion": e.region if e else None,
        "electoralDepartment": e.department if e else None,
        "electoralArrondissement": e.arrondissement if e else None,
        "electoralCommune": e.commune if e else None,
        "pollingPlace": e.polling_place if e else None,
        "pollingStation": e.polling_station if e else None,
        "mrz": "\n".join([card.mrz_line1, card.mrz_line2, card.mrz_line3]),
    }
    if p.photo_jpeg:
        subject["face"] = "data:image/jpeg;base64," + base64.b64encode(p.photo_jpeg).decode()
    subject = {k: v for k, v in subject.items() if v not in (None, "")}
    if holder_id:
        subject = {"id": holder_id, **subject}
    vc_id = f"urn:uuid:{uuid.uuid4()}"
    return vc_id, {
        "@context": contexts(),
        "id": vc_id,
        "type": VC_TYPE,
        "issuer": s.did,
        "issuanceDate": now.isoformat().replace("+00:00", "Z"),
        "expirationDate": f"{card.date_of_expiry.isoformat()}T23:59:59Z",
        "credentialSubject": subject,
    }
