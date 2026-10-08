"""Génère la clé client de Mimoto auprès de Keycloak (authentification private_key_jwt).

    python -m app.tools.mimoto_keys <dossier> <alias> <mot_de_passe_p12>

Produit dans <dossier> :
  - oidckeystore.p12        keystore PKCS#12 lu par Mimoto (alias = client_alias de mimoto-issuers-config.json)
  - mimoto-client-cert.pem  certificat public, déclaré sur le client Keycloak « inji-mimoto »
  - mimoto-client-jwks.json même clé publique au format JWKS (information)
Ne régénère rien si le keystore existe déjà (Mimoto y ajoute ses propres clés au démarrage).
"""
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from jwt.algorithms import RSAAlgorithm


def main(out: Path, alias: str, password: str) -> None:
    p12 = out / "oidckeystore.p12"
    if p12.exists():
        print(f"{p12} existe déjà : conservé")
        return
    out.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "inji-mimoto"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "sn-id-issuer (demo)")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    enc = (serialization.PrivateFormat.PKCS12.encryption_builder().kdf_rounds(50000)
           .key_cert_algorithm(pkcs12.PBES.PBESv2SHA256AndAES256CBC).hmac_hash(hashes.SHA256())
           .build(password.encode()))
    p12.write_bytes(pkcs12.serialize_key_and_certificates(alias.encode(), key, cert, None, enc))
    (out / "mimoto-client-cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update(use="sig", alg="RS256", kid=alias)
    (out / "mimoto-client-jwks.json").write_text(json.dumps({"keys": [jwk]}, indent=2))
    print(f"Clé Mimoto générée dans {out} (alias {alias})")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    main(Path(sys.argv[1]), sys.argv[2], sys.argv[3])
