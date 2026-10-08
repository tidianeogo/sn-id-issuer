#!/bin/bash
# Démarre la pile complète pour Inji Web / Inji Wallet :
#   1. démarre la passerelle et le tunnel HTTPS choisi (TUNNEL dans .env : cloudflared | ngrok | none) ;
#   2. récupère l'URL publique et l'écrit dans .env (PUBLIC_URL) ;
#   3. génère la clé client de Mimoto (inji/certs/oidckeystore.p12) si elle n'existe pas ;
#   4. rend inji/config/mimoto-issuers-config.json avec l'URL publique ;
#   5. démarre tout (profil inji) et attend que les services soient prêts.
# Options : --no-inji       pile de base + tunnel seulement
#           --prepare-only  URL, clé Mimoto et configuration seulement (aucun démarrage)
# TUNNEL=external : URL publique HTTPS déjà fournie par votre propre proxy (PUBLIC_URL dans .env).
# Compatible bash 3.2 (macOS).
set -euo pipefail
cd "$(dirname "$0")/.."
COMPOSE=${COMPOSE:-"docker compose"}
export COMPOSE_PROJECT_NAME=${COMPOSE_PROJECT_NAME:-sn-id-issuer}
[ -f .env ] || cp .env.example .env
envval() { grep -E "^$1=" .env | tail -1 | cut -d= -f2-; }
setenv() {  # portable macOS / Linux (pas de sed -i)
  awk -v k="$1" -v v="$2" 'BEGIN{d=0} $0 ~ "^"k"=" {print k"="v; d=1; next} {print} END{if(!d) print k"="v}' .env > .env.tmp && mv .env.tmp .env
}

WITH_INJI=1; START=1
for a in "$@"; do case "$a" in --no-inji) WITH_INJI=0;; --prepare-only) START=0;; esac; done
TUNNEL=${TUNNEL:-$(envval TUNNEL)}; TUNNEL=${TUNNEL:-cloudflared}
PROFILES=()

echo "==> Tunnel : $TUNNEL"
case "$TUNNEL" in
  cloudflared)
    PROFILES+=(--profile cloudflared)
    $COMPOSE --profile cloudflared up -d gateway tunnel-cloudflared
    URL=""
    for _ in $(seq 1 60); do
      URL=$($COMPOSE --profile cloudflared logs tunnel-cloudflared 2>/dev/null | grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' | tail -1 || true)
      [ -n "$URL" ] && break; sleep 2
    done
    [ -n "$URL" ] || { echo "URL du tunnel introuvable"; $COMPOSE --profile cloudflared logs tunnel-cloudflared | tail -20; exit 1; }
    ;;
  ngrok)
    PROFILES+=(--profile ngrok)
    D=$(envval NGROK_DOMAIN); [ -n "$D" ] && [ -n "$(envval NGROK_AUTHTOKEN)" ] || { echo "NGROK_DOMAIN et NGROK_AUTHTOKEN requis dans .env"; exit 1; }
    $COMPOSE --profile ngrok up -d gateway tunnel-ngrok
    URL="https://$D"
    ;;
  external)
    URL=$(envval PUBLIC_URL)
    case "$URL" in https://*) ;; *) echo "TUNNEL=external exige PUBLIC_URL en https:// dans .env"; exit 1;; esac
    ;;
  none)
    URL="http://localhost:8088"
    echo "    ⚠️  sans tunnel : Inji Wallet (HTTPS obligatoire) et la vérification did:web par Mimoto ne fonctionneront pas."
    ;;
  *) echo "TUNNEL inconnu : $TUNNEL"; exit 1 ;;
esac
OLD=$(envval PUBLIC_URL)
setenv PUBLIC_URL "$URL"
echo "    URL publique : $URL"
[ "$OLD" != "$URL" ] && [ -n "$OLD" ] && echo "    (précédente : $OLD — le DID de l'issuer change : les VC déjà émis ne seront plus vérifiables)"

echo "==> Attente de l'URL publique"
if [ "$TUNNEL" = cloudflared ]; then   # le tunnel est prêt quand cloudflared a enregistré sa connexion
  for _ in $(seq 1 30); do
    $COMPOSE --profile cloudflared logs tunnel-cloudflared 2>/dev/null | grep -q "Registered tunnel connection" && { echo "    ✓ tunnel connecté"; break; }
    sleep 2
  done
fi
if [ $START = 1 ] && [ "$TUNNEL" != none ]; then
  OK=0
  for _ in $(seq 1 10); do   # depuis le Mac (timeout court : une URL toute neuve peut ne pas encore se résoudre)
    curl -fsS -m 5 --connect-timeout 5 -o /dev/null "$URL/gateway-health" 2>/dev/null && { OK=1; break; }; sleep 3
  done
  if [ $OK = 1 ]; then echo "    ✓ $URL joignable depuis le Mac"
  else
    echo "    ⚠️  $URL pas encore joignable depuis le Mac (souvent le cache DNS de macOS sur une URL neuve)."
    echo "       On continue ; les services se joignent entre eux sans passer par ce cache. Si besoin :"
    echo "       sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder"
  fi
fi

if [ $WITH_INJI = 1 ]; then
  PROFILES+=(--profile inji)
  echo "==> Clé client de Mimoto"
  mkdir -p inji/certs
  $COMPOSE build issuer >/dev/null
  $COMPOSE run --rm --no-deps -u 0 -v "$PWD/inji/certs:/out" issuer \
    python -m app.tools.mimoto_keys /out "$(envval MIMOTO_CLIENT_ALIAS)" "$(envval MIMOTO_P12_PASSWORD)"

  echo "==> Configuration des émetteurs de Mimoto"
  sed -e "s#__PUBLIC_URL__#$URL#g" -e "s#__REALM__#$(envval REALM)#g" \
      -e "s#__MIMOTO_CLIENT_ID__#$(envval MIMOTO_CLIENT_ID)#g" -e "s#__MIMOTO_CLIENT_ALIAS__#$(envval MIMOTO_CLIENT_ALIAS)#g" \
      inji/mimoto-issuers-config.template.json > inji/config/mimoto-issuers-config.json
fi

if [ $START = 0 ]; then echo "Préparation terminée (--prepare-only)."; exit 0; fi

echo "==> Démarrage"
$COMPOSE ${PROFILES[@]+"${PROFILES[@]}"} up -d --build
# keycloak-init rejoue la mise en conformité (certificat Mimoto, redirections) à chaque démarrage
$COMPOSE ${PROFILES[@]+"${PROFILES[@]}"} up -d --force-recreate keycloak-init >/dev/null
[ $WITH_INJI = 1 ] && $COMPOSE ${PROFILES[@]+"${PROFILES[@]}"} restart mimoto-service >/dev/null   # vide ses caches d'émetteurs

echo "==> Attente des services"
# URL publique testée depuis un conteneur (comme Mimoto la joindra), URL locale depuis le Mac ; jamais bloquant.
probe() {
  case "$1" in
    http://localhost*|http://127.0.0.1*) curl -fsS -m 5 --connect-timeout 5 -o /dev/null "$1" 2>/dev/null ;;
    *) $COMPOSE exec -T issuer python -c "import sys,urllib.request;urllib.request.urlopen(sys.argv[1],timeout=5)" "$1" >/dev/null 2>&1 ;;
  esac
}
wait_url() { for _ in $(seq 1 "${3:-60}"); do probe "$1" && { echo "    ✓ $2"; return 0; }; sleep 4; done; echo "    ✗ $2 ($1) — voir : $COMPOSE logs"; return 0; }
wait_url "$URL/.well-known/openid-credential-issuer" "issuer"
wait_url "$URL/auth/realms/$(envval REALM)/.well-known/oauth-authorization-server" "Keycloak"
if [ $WITH_INJI = 1 ]; then
  wait_url "http://localhost:3004/" "Inji Web"
  wait_url "http://localhost:3004/v1/mimoto/issuers/SenegalCNI" "Mimoto (émetteur SenegalCNI chargé)" 120
fi

cat <<EOF

Prêt.
  Offre d'identifiant (QR pour Inji Wallet) : $URL/credential-offer
  Inji Web (navigateur du Mac)              : http://localhost:3004
  Métadonnées de l'issuer                   : $URL/.well-known/openid-credential-issuer
  Console Keycloak (local uniquement)       : http://127.0.0.1:8080/auth/admin
  Compte citoyen                            : $(envval CITIZEN_USERNAME) / $(envval CITIZEN_PASSWORD)
EOF
