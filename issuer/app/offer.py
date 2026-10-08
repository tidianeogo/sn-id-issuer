"""Offre d'identifiant OpenID4VCI (flux initié par l'émetteur) pour Inji Wallet ≥ 0.22.

Le wallet scanne le QR, découvre l'issuer et Keycloak, ouvre la page de connexion Keycloak
(client public « wallet », PKCE), échange le code puis demande le VC.
"""
import html
import json
from urllib.parse import quote

import segno

from .config import get_settings
from .credential import CONFIG_ID


def credential_offer() -> dict:
    s = get_settings()
    return {
        "credential_issuer": s.base,
        "credential_configuration_ids": [CONFIG_ID],
        "grants": {"authorization_code": {"authorization_server": s.keycloak_public_issuer}},
    }


def offer_links() -> dict[str, str]:
    s = get_settings()
    by_value = "openid-credential-offer://?credential_offer=" + quote(
        json.dumps(credential_offer(), separators=(",", ":")), safe="")
    by_reference = "openid-credential-offer://?credential_offer_uri=" + quote(f"{s.base}/credential-offer.json", safe="")
    return {"by_value": by_value, "by_reference": by_reference}


def offer_page() -> str:
    s = get_settings()
    links = offer_links()
    qr = segno.make(links["by_value"], error="m").svg_inline(scale=6, border=2)
    warn = "" if s.base.startswith("https://") else (
        "<p class='warn'>⚠️ URL publique en HTTP : Inji Wallet exige HTTPS. Démarrez la pile avec un tunnel "
        "(scripts/inji-up.sh) pour scanner ce QR depuis un téléphone.</p>")
    return f"""<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Carte d'identité numérique – offre</title>
<style>body{{font-family:system-ui,sans-serif;max-width:720px;margin:24px auto;padding:0 16px;color:#0B3D2E}}
.qr{{background:#fff;display:inline-block;padding:8px;border:1px solid #ccc}} code{{word-break:break-all;font-size:12px}}
.warn{{background:#fff4e5;border:1px solid #f0b46c;padding:8px}} ol li{{margin:6px 0}}</style></head><body>
<h1>Carte d'identité CEDEAO – Sénégal</h1>
<p>Émetteur : <b>{html.escape(s.issuer_name)}</b><br><small>{html.escape(s.base)}</small></p>
{warn}
<div class="qr">{qr}</div>
<ol>
<li>Dans Inji Wallet, touchez <b>+</b> puis <b>Scanner un QR code d'offre</b> et scannez ce code.</li>
<li>Acceptez de faire confiance à cet émetteur.</li>
<li>Connectez-vous sur la page Keycloak avec votre <b>NIN</b> et votre mot de passe.</li>
<li>La carte est téléchargée, vérifiée puis ajoutée au wallet.</li>
</ol>
<details><summary>Liens de l'offre</summary>
<p>Par valeur : <code>{html.escape(links['by_value'])}</code></p>
<p>Par référence : <code>{html.escape(links['by_reference'])}</code></p></details>
</body></html>"""
