# sn-id-issuer v3.6.1 — Issuer Inji pour la carte d'identité CEDEAO du Sénégal

Issuer **OpenID4VCI** (draft 13) qui émet un **`ldp_vc`** signé **Ed25519Signature2020** (`did:web`),
avec **Keycloak** comme IAM et **PostgreSQL** comme base. La v3 ajoute **Mimoto 0.22 + Inji Web 0.17**,
un **tunnel HTTPS** et l'**offre d'identifiant (QR)** pour **Inji Wallet 0.22** du store. La v3.4 ajoute le
**module d'enrôlement** (`/admin/`) pour ajouter les cartes d'autres titulaires et leur créer un compte ; la v3.5 y
ajoute la **lecture automatique (OCR) des photos recto / verso** de la carte.

```
                 ┌──────────────────────── tunnel HTTPS (cloudflared | ngrok) ────────────────────────┐
 Téléphone ──────┤  https://<URL publique>                                                            │
 (Inji Wallet)   └──────────────┬─────────────────────────────────────────────────────────────────────┘
                                │
 Mac ── http://localhost:8088 ─ gateway (nginx) ─┬─ /auth/*        → keycloak  (realm « senegal »)
                                                 ├─ /v1/mimoto/*   → mimoto-service
                                                 ├─ /admin/        → issuer : interface d'enrôlement (rôle issuer-admin)
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
| `external` + ngrok sur le Mac | `https://<votre-domaine>.ngrok-free.dev` | **recommandé** : domaine fixe gratuit, voir ci-dessous |
| `ngrok` | `https://<NGROK_DOMAIN>` | ngrok dans un conteneur (`NGROK_AUTHTOKEN`, `NGROK_DOMAIN` = domaine seul) |
| `none` | `http://localhost:8088` | sans Inji (HTTPS requis par le wallet et par la vérification `did:web` de Mimoto) |

#### ngrok lancé sur le Mac (plan gratuit, domaine fixe)

```bash
ngrok config add-authtoken <votre_token>   # une seule fois
ngrok http 8088                            # terminal dédié, à laisser ouvert
```

Le plan gratuit attribue d'office **votre** domaine fixe : relevez-le sur la ligne `Forwarding` (ou dans
dashboard.ngrok.com → *Domains*). Les comptes récents ont un domaine en **`.ngrok-free.dev`**, les plus anciens en
`.ngrok-free.app`. Ne passez pas `--url` avec un autre nom : ngrok le prendrait pour un sous-domaine personnalisé,
réservé aux plans payants (`ERR_NGROK_313`). Puis dans `.env` :

```
TUNNEL=external
PUBLIC_URL=https://<votre-domaine>.ngrok-free.dev
```

et `./scripts/inji-up.sh`. Le script corrige les saisies courantes (`https://` répété, `/` final, guillemets) et
refuse une URL invalide (gabarit `<…>` non remplacé, `localhost`). Vérification :

```bash
D=https://<votre-domaine>.ngrok-free.dev
curl -s -o /dev/null -w "issuer   : %{http_code}\n" $D/.well-known/openid-credential-issuer
curl -s -o /dev/null -w "keycloak : %{http_code}\n" $D/auth/realms/senegal/.well-known/oauth-authorization-server
curl -s -A okhttp -o /dev/null -w "mimoto   : %{http_code}\n" $D/v1/mimoto/issuers
```

Trois `200` attendus. Un `404` avec une page HTML ngrok = agent ngrok arrêté (`ERR_NGROK_3200`) ; `000` = URL mal
écrite.

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

## Enrôler d'autres cartes (module `/admin/`)

Ouvrez **`<URL publique>/admin/`** (avec un tunnel HTTPS, l'interface y redirige d'elle-même : la connexion
Keycloak et l'interface doivent partager la même origine). Connectez-vous avec `issuer-admin` /
`ISSUER_ADMIN_PASSWORD`.

1. **+ Nouvelle carte** → déposez (ou prenez au téléphone) la **photo du recto** et celle du **verso** →
   **Lire la carte**. En quelques secondes, tout le formulaire est rempli et la **photo du titulaire** est extraite :
   - la **MRZ** du verso est lue et validée par ses chiffres de contrôle : n° de carte, nom, prénoms, sexe, dates de
     naissance et d'expiration en viennent (étiquette verte **MRZ ✓**) ;
   - le reste est lu sous les libellés du recto et du verso (étiquette jaune **lu**) : lieu de naissance, taille,
     date de délivrance, centre, adresse, NIN, n° d'électeur, région… ;
   - ce qui n'a pu qu'être déduit est signalé (étiquette rouge **déduit**, ex. date de délivrance = expiration − 10 ans
     + 1 jour) ; les champs non lus sont listés.

   Les champs surlignés sont **à vérifier sur la carte**. Recto et verso inversés, carte à l'envers ou de biais :
   corrigés automatiquement. Pour une bonne lecture : carte entière, à plat, sur un fond uni contrasté, sans reflet.
   Sans photos, la saisie manuelle reste possible (MRZ collée puis **Lire la MRZ et pré-remplir**).
2. Complétez ou corrigez ce qui manque.
3. **Vérifier** : contrôles complets sans écriture. Bloquants : MRZ ↔ recto, formats (NIN 13 chiffres, carte
   17 chiffres), dates, n° de carte ou d'électeur déjà attribué à un autre NIN. Avertissements (confirmés par
   l'agent) : année et 1er chiffre du NIN, date incluse dans le n° de carte, carte expirée.
4. **Enregistrer** : la carte est écrite dans PostgreSQL et le **compte Keycloak** du titulaire est créé
   (identifiant = NIN). Un **mot de passe temporaire** s'affiche une seule fois : remettez-le au titulaire, qui le
   changera à sa première connexion dans Inji Wallet.

**OCR local et souverain** : **RapidOCR** (Apache-2.0) avec les modèles **PP-OCRv6** de PaddleOCR (ONNX Runtime,
embarqués dans le paquet, aucun téléchargement à l'exécution), une passe par face ; visage détecté par YuNet (MIT) ;
Tesseract (modèle OCR-B) en simple secours pour la MRZ. Aucune image ni donnée n'est envoyée à un service externe, et les
images ne sont pas conservées (seule la photo recadrée l'est, à l'enregistrement). Code : `issuer/app/ocr.py`.

Depuis la liste : **Modifier**, **Nouveau mot de passe** (ou **Créer le compte**), **Suspendre / Réactiver**
(désactive aussi le compte Keycloak ; plus aucune émission), **Carte perdue / Carte valide**.

Côté Keycloak, `keycloak-init` crée deux clients : `issuer-admin-ui` (public, PKCE S256, redirections
`<URL publique>/admin/*` et `http://localhost:8088/admin/*`) et `issuer-backend` (compte de service, rôles
`manage-users`, `view-users`, `query-users` de `realm-management`, secret `ISSUER_BACKEND_SECRET` généré dans `.env`
par les scripts s'il manque). L'API d'administration Keycloak reste joignable uniquement sur le réseau Docker.

API équivalente (jeton du rôle `issuer-admin`) : `POST /admin/ocr` (multipart `recto`, `verso`), `POST /admin/mrz/parse`, `POST /admin/citizens/validate`,
`PUT /admin/citizens`, `GET /admin/citizens`, `GET /admin/citizens/{nin}/photo`, `PATCH /admin/citizens/{nin}`,
`POST /admin/citizens/{nin}/account`, `PATCH /admin/cards/{n°}` (détail dans `issuer/app/enrolment.py`, schéma
sur `/docs`).

## Ce qui change dans la v3.6.1

- **Accents dans Inji Wallet** : Mimoto (Spring RestTemplate) lisait les réponses « application/json » sans charset
  en ISO-8859-1 (« Ã© »). L'issuer répond désormais en JSON ASCII pur (`\u00e9`) avec `charset=utf-8`, et la
  configuration des émetteurs de Mimoto est elle aussi échappée.
- **Photo** : `face` reste déclarée mais sort de la liste « order » des champs : le wallet l'affiche en portrait au
  lieu d'imprimer sa valeur base64.
- Après mise à jour : **supprimez la carte du wallet puis téléchargez-la de nouveau** (le wallet garde en cache la
  carte et les métadonnées de l'émetteur).

## Ce qui change dans la v3.6

- **Nouveau moteur OCR : RapidOCR + PP-OCRv6** (PaddleOCR en ONNX) à la place de l'assemblage de lectures
  Tesseract : une seule passe par face, **≈ 3 s pour une carte** (contre plusieurs dizaines de lectures Tesseract),
  bien plus précis sur le fond guilloché, accents et espaces conservés. Sur les deux vraies cartes testées :
  **tous les champs justes** (19/19 et 21/21), MRZ validée, visage extrait. Modèles chargés au démarrage de l'issuer.
- Mémoire : ≈ 300 Mo pour l'OCR. Avec la pile Inji complète (Mimoto, datashare… émulés en amd64), donnez au moins
  **6 Go** à Docker Desktop (Settings → Resources → Memory).

## Ce qui change dans la v3.5.2

- Correction du **HTTP 504** à la lecture des cartes : les Tesseract lancés en parallèle se disputaient les cœurs
  (OpenMP) — un seul fil chacun (`OMP_THREAD_LIMIT=1`) et pas de passe « négatif » : lecture 2 à 5 fois plus
  rapide. La passerelle laisse 180 s à `/admin/ocr` (60 s par défaut), et l'OCR saute la relecture ciblée au-delà
  de 40 s sur une machine lente.

## Ce qui change dans la v3.5.1

- OCR calé sur la mise en page réelle de la carte : pré-traitements multiples (black-hat morphologique contre le
  guilloché) lus en parallèle avec **vote par champ**, **relecture ciblée** et nettoyée de chaque valeur sous son
  libellé, valeurs sur deux lignes (adresse, lieu de vote), libellés en minuscules écartés des valeurs (en majuscules),
  **détection de visage YuNet** (OpenCV, modèle MIT embarqué) pour la photo, photo déjà recadrée acceptée sans alerte.
- Carte de test synthétique refaite sur la mise en page réelle (`tests/tools/gen_test_card.py`).

## Ce qui change dans la v3.5

- **OCR des photos recto / verso** dans l'enrôlement (`POST /admin/ocr`, `issuer/app/ocr.py`) : redressement de la
  carte, MRZ validée par chiffres de contrôle, champs repérés sous leurs libellés, photo extraite, faces inversées
  ou carte retournée corrigées. Image issuer : `tesseract-ocr`, `tesseract-ocr-fra`, OpenCV ; passerelle : envois
  jusqu'à 25 Mo.
- Tests : `tests/e2e/test_ocr.py` sur des cartes **synthétiques** (personne fictive, `tests/tools/gen_test_card.py`).

## Ce qui change dans la v3.4

- **Module d'enrôlement** (`/admin/`, `issuer/app/enrolment.py`, `keycloak_admin.py`) : décrit ci-dessus.
- **`inji-up.sh`** : normalise `PUBLIC_URL` / `NGROK_DOMAIN` (`https://https://…`, `/` final, guillemets) et refuse
  les URL invalides ; génère `ISSUER_BACKEND_SECRET` s'il manque ; affiche l'adresse de l'enrôlement.
- **Documentation ngrok natif** (`TUNNEL=external`, domaines `.ngrok-free.dev`).

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
| `tests/e2e/test_enrolement.py` | **module d'enrôlement** : interface et clients Keycloak, droits, lecture MRZ, contrôles (conflits, avertissements, pays), photo, enrôlement complet → compte Keycloak → changement du mot de passe temporaire → VC avec photo vérifié, réinitialisation, suspension, carte perdue ; **parcours réel dans Chromium headless** (Playwright, ignoré s'il n'est pas installé) |
| `tests/e2e/test_ocr.py` | **OCR** : lecture complète d'une carte synthétique photographiée de biais (20 champs, MRZ validée, photo), valeurs acceptées telles quelles par les contrôles d'enregistrement, faces inversées, refus (droits, image illisible), parcours navigateur dépôt des photos → lecture → enregistrement |
| `tests/e2e/test_inji_stack.py` | **vrais** Mimoto + Inji Web : liste des émetteurs, configuration, téléchargement PDF invité (avec vérification de signature par Mimoto) |

Rapports : `tests/RAPPORT-E2E-local.txt` (HTTP local) et `tests/RAPPORT-E2E-https.txt` (tunnel HTTPS simulé).

`ci/` sert aux environnements sans accès aux registres d'images : reconstruction des images de base
(`ci/base-images/build.sh`), surcharge réseau/AC de build (`ci/docker-compose.ci.yml`) et simulation de tunnel
HTTPS (`ci/docker-compose.tls-sim.yml`, `ci/tls-sim/gen-certs.sh`, hôte `sn-id.test` dans `/etc/hosts`).

## Données

Recto + verso de la carte (NIN, MRZ, informations électorales, photo) dans `db/03-seed.sql` ; les cartes
ajoutées par l'enrôlement sont dans le volume `pgdata`.
⚠️ Données personnelles réelles : ne jamais publier `db/03-seed.sql`, `.env` ni `inji/certs/`.

## Limites connues

- La révocation est enregistrée en base mais pas publiée (`credentialStatus` à venir).
- Keycloak ne fournit pas de `c_nonce` : garder `REQUIRE_NONCE=false` (Mimoto et le wallet envoient alors une preuve sans nonce).
- OCR : sur de vraies cartes (photos recadrées 700 × 1080 px), tous les champs lus justes ; restez attentif aux photos
  floues ou avec reflet sur l'hologramme. Les tests automatiques utilisent une carte **synthétique** (personne
  fictive) : aucune image de vraie carte n'est livrée.
- Mise à jour depuis la v3.3 / v3.4 : `docker compose up -d --build` puis `./scripts/inji-up.sh` (rejoue `keycloak-init`
  qui crée les nouveaux clients). Aucune migration de base : le schéma est inchangé.
- Si vous régénérez `inji/certs/oidckeystore.p12`, supprimez le volume `mimoto-pgdata` (clés Mimoto chiffrées en base).
- Les VC émis sont des démonstrations signées par cet issuer, pas par l'autorité officielle de délivrance.
