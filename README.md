# sn-id-issuer v3 — Issuer Inji pour la carte d'identité CEDEAO du Sénégal

Issuer **OpenID4VCI** (draft 13) qui émet un **`ldp_vc`** signé **Ed25519Signature2020** (`did:web`),
avec **Keycloak** comme IAM et **PostgreSQL** comme base. La v3 ajoute **Mimoto 0.22 + Inji Web 0.17**,
un **tunnel HTTPS** et l'**offre d'identifiant (QR)** pour **Inji Wallet 0.22** du store.

```
                 ┌──────────────────────── tunnel HTTPS (cloudflared | ngrok) ────────────────────────┐
 Téléphone ──────┤  https://<URL publique>                                                            │
 (Inji Wallet)   └──────────────┬─────────────────────────────────────────────────────────────────────┘
                                │
 Mac ── http://localhost:8088 ─ gateway (nginx) ─┬─ /auth/*        → keycloak  (realm « senegal »)
                                                 ├─ /v1/mimoto/*   → mimoto-service
                                                 └─ /*             → issuer ── postgres (issuer + keycloak)
 Mac ── http://localhost:3004 ─ inji-web ── /v1/mimoto → mimoto-service ── postgres-mimoto, datashare, minio
 Mac ── http://127.0.0.1:8080/auth/admin ── console Keycloak (jamais exposée par le tunnel)
```

## Démarrage sur le Mac

Prérequis : Docker Desktop. Pour les tests : python3 et Node ≥ 18.

```bash
cp .env.example .env            # changer les mots de passe ; TUNNEL=cloudflared par défaut
./scripts/inji-up.sh            # tunnel → URL publique → clé Mimoto → config Mimoto → démarrage
```

Le script affiche à la fin :

- l'**offre d'identifiant** (QR pour Inji Wallet) : `<URL publique>/credential-offer`
- **Inji Web** : http://localhost:3004
- la **console Keycloak** (local) : http://127.0.0.1:8080/auth/admin
- le **compte citoyen** : NIN `1251195302325` / `CITIZEN_PASSWORD`

Premier démarrage : comptez quelques minutes (les images MOSIP sont en `linux/amd64`, émulées sur Apple Silicon).

### Choisir le tunnel (`TUNNEL` dans `.env`)

| Valeur | URL publique | Remarque |
|---|---|---|
| `cloudflared` (défaut) | `https://xxxx.trycloudflare.com` | sans compte ; **change à chaque redémarrage du tunnel** |
| `ngrok` | `https://<NGROK_DOMAIN>` | compte ngrok gratuit + domaine fixe (`NGROK_AUTHTOKEN`, `NGROK_DOMAIN`) — **recommandé** |
| `external` | `PUBLIC_URL` déjà en `https://` | votre propre reverse proxy / domaine |
| `none` | `http://localhost:8088` | sans Inji (HTTPS requis par le wallet et par la vérification `did:web` de Mimoto) |

⚠️ Le DID de l'issuer dérive de l'URL publique (`did:web:<hôte>`). Si l'URL change, les VC déjà émis ne sont
plus vérifiables : relancez `./scripts/inji-up.sh` et réémettez. D'où l'intérêt d'un domaine fixe (ngrok).

## Tester avec Inji Web (navigateur du Mac)

1. http://localhost:3004 → émetteur **« Carte d'identité CEDEAO – Sénégal (démo) »** → **Carte d'identité CEDEAO**.
2. Page de connexion Keycloak : NIN + mot de passe.
3. Mimoto échange le code (`private_key_jwt`, clé `inji/certs/oidckeystore.p12`), télécharge le VC, **vérifie sa
   signature** (did:web via le tunnel) et renvoie le **PDF**.

Mode invité uniquement : la connexion Google d'Inji Web demande de vrais identifiants OAuth Google
(`GOOGLE_OAUTH_CLIENT_ID/SECRET`), non fournis.

## Tester avec Inji Wallet 0.22 (téléphone)

Le wallet du store est branché sur le Mimoto de MOSIP : il ne voit pas cet émetteur dans sa liste.
La voie prévue par la 0.22 est **l'offre d'identifiant** (flux initié par l'émetteur) :

1. Ouvrez `<URL publique>/credential-offer` sur le Mac.
2. Dans Inji Wallet : **+** → **scanner un QR code d'offre** → scannez le QR.
3. Acceptez de **faire confiance à l'émetteur**.
4. Connectez-vous sur la page Keycloak (NIN / mot de passe) ; la carte est téléchargée, vérifiée et ajoutée.

Côté Keycloak, le wallet utilise le client **public `wallet`** (redirection `io.mosip.residentapp.inji://oauthredirect`,
PKCE S256, PAR) — valeurs codées en dur dans Inji Wallet 0.22, créées par `keycloak-init`.
Le client **`inji-mimoto`** (confidentiel, certificat) sert à Inji Web et à un Inji Wallet que vous compileriez
sur votre propre Mimoto (`MIMOTO_HOST`).

## Ce qui change dans la v3

- **Passerelle unique** (`gateway/default.conf`) : une seule URL publique pour l'issuer, Keycloak (`/auth`) et Mimoto.
- **Keycloak derrière proxy** : `KC_HTTP_RELATIVE_PATH=/auth`, `KC_HOSTNAME=<URL publique>/auth`,
  `KC_PROXY_HEADERS=xforwarded`, `sslRequired=external` ; console et realm `master` **bloqués** sur la passerelle.
- **`keycloak-init` rejouable** : crée le realm une fois, puis remet en conformité à chaque démarrage les clients
  `inji-mimoto` (redirections Inji Web + mobile, **certificat** de Mimoto — Mimoto signe son `client_assertion`
  **sans `kid`**) et `wallet`.
- **Issuer** : offre d'identifiant (`/credential-offer`, `/credential-offer.json`), algorithmes de preuve
  `ES256`, `ES256K`, `RS256`, `EdDSA` (+ en-tête `Ed25519` RFC 9864), champ `face` déclaré pour l'affichage,
  logo PNG, outil `app.tools.mimoto_keys` (keystore PKCS#12 lisible par Java/Mimoto).
- **Mimoto 0.22 / Inji Web 0.17 / datashare / minio** : composition reprise de `mosip/inji-web` (master),
  configuration dans `inji/` (`mimoto-issuers-config.json` rendu depuis le gabarit par `inji-up.sh`).

## Tests

```bash
./scripts/e2e.sh          # pile de base en local + contrats Mimoto/Wallet          (pas d'image MOSIP requise)
./scripts/e2e.sh --inji   # pile complète avec tunnel + VRAIS Mimoto et Inji Web    (à lancer sur le Mac)
```

| Suite | Contenu |
|---|---|
| `tests/unit` | MRZ (ICAO 9303) |
| `tests/e2e/test_e2e.py` | infrastructure, Keycloak, passerelle, émission, vérification indépendante, sécurité, admin, persistance |
| `tests/e2e/test_contract_mimoto.py` | rejoue **Mimoto 0.22** d'après son code : contraintes des DTO du well-known, découverte RFC 8414, configuration des émetteurs, `client_assertion` sans `kid`, choix d'algorithme, requête de crédential avec `nonce: null`, libellés fr/en, keystore |
| `tests/e2e/test_contract_inji_wallet.py` | rejoue **Inji Wallet 0.22** (offre) : QR, offre par valeur/référence, PAR, client public, preuves `kid=did:jwk…#0` en ES256/ES256K/RS256/EdDSA/Ed25519 |
| `tests/e2e/test_inji_stack.py` | **vrais** Mimoto + Inji Web : liste des émetteurs, configuration, téléchargement PDF invité (avec vérification de signature par Mimoto) |

Rapports : `tests/RAPPORT-E2E-local.txt` (HTTP local) et `tests/RAPPORT-E2E-https.txt` (tunnel HTTPS simulé).

`ci/` sert aux environnements sans accès aux registres d'images : reconstruction des images de base
(`ci/base-images/build.sh`), surcharge réseau/AC de build (`ci/docker-compose.ci.yml`) et simulation de tunnel
HTTPS (`ci/docker-compose.tls-sim.yml`, `ci/tls-sim/gen-certs.sh`, hôte `sn-id.test` dans `/etc/hosts`).

## Données

Recto + verso de la carte (NIN, MRZ, informations électorales, photo) dans `db/03-seed.sql`.
⚠️ Données personnelles réelles : ne jamais publier `db/03-seed.sql`, `.env` ni `inji/certs/`.

## Limites connues

- La révocation est enregistrée en base mais pas publiée (`credentialStatus` à venir).
- Keycloak ne fournit pas de `c_nonce` : garder `REQUIRE_NONCE=false` (Mimoto et le wallet envoient alors une preuve sans nonce).
- Si vous régénérez `inji/certs/oidckeystore.p12`, supprimez le volume `mimoto-pgdata` (clés Mimoto chiffrées en base).
- Les VC émis sont des démonstrations signées par cet issuer, pas par l'autorité officielle de délivrance.
