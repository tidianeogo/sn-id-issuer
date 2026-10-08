"""Lecture et contrôle de la MRZ TD1 (ICAO 9303, partie 5) de la carte d'identité CEDEAO.

Le n° de carte sénégalais fait 17 caractères (> 9) : il est réparti entre le champ « numéro de
document » (9 caractères, suivi de '<' à la place du chiffre de contrôle) et le début du champ
optionnel, terminé par son chiffre de contrôle (règle des numéros de document longs).
"""
from dataclasses import dataclass
from datetime import date

_WEIGHTS = (7, 3, 1)


class MRZError(ValueError):
    pass


def check_digit(s: str) -> str:
    def val(c: str) -> int:
        if c.isdigit():
            return int(c)
        if c == "<":
            return 0
        if "A" <= c <= "Z":
            return ord(c) - 55
        raise MRZError(f"caractère MRZ invalide : {c!r}")
    return str(sum(val(c) * _WEIGHTS[i % 3] for i, c in enumerate(s)) % 10)


def _yymmdd(s: str, pivot_future: bool) -> date:
    yy, mm, dd = int(s[:2]), int(s[2:4]), int(s[4:6])
    this = date.today().year % 100
    if pivot_future:  # date d'expiration : toujours >= 2000 dans ce contexte
        century = 2000
    else:  # date de naissance : jamais dans le futur
        century = 1900 if yy > this else 2000
    return date(century + yy, mm, dd)


@dataclass
class TD1:
    document_code: str
    issuing_state: str
    document_number: str
    date_of_birth: date
    sex: str
    date_of_expiry: date
    nationality: str
    family_name: str
    given_names: str
    lines: tuple[str, str, str]


def normalize(lines: list[str] | str) -> tuple[str, str, str]:
    if isinstance(lines, str):
        lines = lines.splitlines()
    lines = [ln.strip().replace(" ", "").upper() for ln in lines if ln.strip()]
    if len(lines) != 3:
        raise MRZError("une MRZ TD1 compte 3 lignes")
    out = []
    for ln in lines:
        if len(ln) > 30 and set(ln[30:]) == {"<"}:  # remplissage en trop (saisie / OCR)
            ln = ln[:30]
        out.append(ln.ljust(30, "<"))
    return tuple(out)  # type: ignore


def parse_td1(lines: list[str] | str) -> TD1:
    l1, l2, l3 = normalize(lines)
    if any(len(x) != 30 for x in (l1, l2, l3)):
        raise MRZError("chaque ligne TD1 doit faire 30 caractères")

    doc_field, doc_cd, optional1 = l1[5:14], l1[14], l1[15:30]
    if doc_cd == "<":  # numéro long : suite dans le champ optionnel, puis chiffre de contrôle
        rest = optional1.split("<", 1)[0]
        if len(rest) < 2:
            raise MRZError("numéro de document long mal formé")
        number, doc_cd = doc_field + rest[:-1], rest[-1]
    else:
        number = doc_field.rstrip("<")
    if check_digit(number) != doc_cd:
        raise MRZError("chiffre de contrôle du numéro de document invalide")

    dob, dob_cd, sex, exp, exp_cd = l2[0:6], l2[6], l2[7], l2[8:14], l2[14]
    if check_digit(dob) != dob_cd:
        raise MRZError("chiffre de contrôle de la date de naissance invalide")
    if check_digit(exp) != exp_cd:
        raise MRZError("chiffre de contrôle de la date d'expiration invalide")
    composite = l1[5:30] + l2[0:7] + l2[8:15] + l2[18:29]
    if check_digit(composite) != l2[29]:
        raise MRZError("chiffre de contrôle composite invalide")

    names = l3.rstrip("<").split("<<", 1)
    family = names[0].replace("<", " ").strip()
    given = names[1].replace("<", " ").strip() if len(names) > 1 else ""
    return TD1(document_code=l1[0:2].rstrip("<"), issuing_state=l1[2:5], document_number=number,
               date_of_birth=_yymmdd(dob, False), sex=sex, date_of_expiry=_yymmdd(exp, True),
               nationality=l2[15:18], family_name=family, given_names=given, lines=(l1, l2, l3))


def consistency_errors(td1: TD1, *, card_number: str, date_of_birth: date, date_of_expiry: date,
                       sex: str, family_name: str, given_name: str) -> list[str]:
    """Compare la MRZ (verso) aux données imprimées (recto)."""
    errs = []
    if td1.document_number != card_number:
        errs.append("n° de carte")
    if td1.date_of_birth != date_of_birth:
        errs.append("date de naissance")
    if td1.date_of_expiry != date_of_expiry:
        errs.append("date d'expiration")
    if td1.sex != sex:
        errs.append("sexe")
    if td1.family_name != family_name.upper():
        errs.append("nom")
    if td1.given_names != given_name.upper():
        errs.append("prénoms")
    return errs
