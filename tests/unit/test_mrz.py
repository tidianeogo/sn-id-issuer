"""Tests unitaires de la MRZ (exécutables sans Docker : pytest tests/unit)."""
import sys
from datetime import date
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "issuer"))
from app.mrz import MRZError, check_digit, consistency_errors, parse_td1  # noqa: E402

VERSO = ["I<SEN104195311<080000164<<<<<<",
         "5311080M2705310SEN<<<<<<<<<<<4",
         "SECK<<MOUHAMED<TIDIANE<<<<<<<<<"]


def test_check_digits_icao_example():
    # Exemple de la norme ICAO 9303 (partie 5)
    assert check_digit("D23145890") == "7"
    assert check_digit("740812") == "2"


def test_parse_verso_carte():
    td1 = parse_td1(VERSO)
    assert td1.document_code == "I"
    assert td1.issuing_state == "SEN"
    assert td1.document_number == "10419531108000016"  # n° long reconstitué = n° du recto
    assert td1.date_of_birth == date(1953, 11, 8)
    assert td1.date_of_expiry == date(2027, 5, 31)
    assert td1.sex == "M"
    assert td1.nationality == "SEN"
    assert td1.family_name == "SECK"
    assert td1.given_names == "MOUHAMED TIDIANE"


def test_coherence_recto_verso():
    td1 = parse_td1(VERSO)
    ok = dict(card_number="10419531108000016", date_of_birth=date(1953, 11, 8), date_of_expiry=date(2027, 5, 31),
              sex="M", family_name="SECK", given_name="MOUHAMED TIDIANE")
    assert consistency_errors(td1, **ok) == []
    assert consistency_errors(td1, **{**ok, "date_of_birth": date(1953, 11, 9)}) == ["date de naissance"]


@pytest.mark.parametrize("line, idx", [
    ("I<SEN104195311<080000165<<<<<<", 0),   # chiffre de contrôle du n° de carte
    ("5311081M2705310SEN<<<<<<<<<<<4", 1),   # chiffre de contrôle date de naissance
    ("5311080M2705311SEN<<<<<<<<<<<4", 1),   # chiffre de contrôle date d'expiration
    ("5311080M2705310SEN<<<<<<<<<<<5", 1),   # chiffre composite
])
def test_mrz_alteree_rejetee(line, idx):
    lines = list(VERSO)
    lines[idx] = line
    with pytest.raises(MRZError):
        parse_td1(lines)
