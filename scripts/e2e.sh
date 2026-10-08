#!/bin/bash
# Campagne de tests de bout en bout.
#   ./scripts/e2e.sh            pile de base en local (http://localhost:8088) : issuer, Keycloak, passerelle,
#                               + contrats Mimoto 0.22 / Inji Wallet 0.22 rejoués par les clients de test
#   ./scripts/e2e.sh --inji     pile complète via scripts/inji-up.sh (tunnel HTTPS + VRAIS Mimoto et Inji Web),
#                               puis les mêmes tests + tests/e2e/test_inji_stack.py
#   KEEP=1 ./scripts/e2e.sh     laisse la pile tourner à la fin
# Prérequis hôte : docker compose, python3 (+ pip), node >= 18. Compatible bash 3.2 (macOS).
set -euo pipefail
cd "$(dirname "$0")/.."
COMPOSE=${COMPOSE:-"docker compose"}
export COMPOSE_PROJECT_NAME=${COMPOSE_PROJECT_NAME:-sn-id-issuer}
export COMPOSE
MODE=base; [ "${1:-}" = "--inji" ] && { MODE=inji; shift; }
[ -f .env ] || cp .env.example .env
envval() { grep -E "^$1=" .env | tail -1 | cut -d= -f2-; }
if [ -z "$(envval ISSUER_BACKEND_SECRET)" ]; then   # .env antérieur à la v3.4
  printf '\nISSUER_BACKEND_SECRET=%s\n' "$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32)" >> .env
fi

echo "==> Dépendances de test"
python3 -m pip install -q -r tests/requirements.txt 2>/dev/null || python3 -m pip install -q --break-system-packages -r tests/requirements.txt
(cd tests/verifier && npm ci --no-audit --no-fund --silent)

cleanup() {
  status=$?
  $COMPOSE --profile inji --profile cloudflared --profile ngrok logs --no-color > e2e-logs.txt 2>&1 || true
  if [ -z "${KEEP:-}" ]; then $COMPOSE --profile inji --profile cloudflared --profile ngrok down -v >/dev/null 2>&1 || true; fi
  exit $status
}

echo "==> Pile propre"
$COMPOSE --profile inji --profile cloudflared --profile ngrok down -v --remove-orphans >/dev/null 2>&1 || true
trap cleanup EXIT

if [ $MODE = inji ]; then
  ./scripts/inji-up.sh
  export INJI_STACK=1
  # pour les commandes compose des tests (redémarrages) : mêmes profils que inji-up
  T=$(envval TUNNEL); case "$T" in cloudflared|ngrok) export COMPOSE="$COMPOSE --profile inji --profile $T";; *) export COMPOSE="$COMPOSE --profile inji";; esac
else
  export PUBLIC_URL=${PUBLIC_URL:-http://localhost:8088}
  $COMPOSE build
  $COMPOSE up -d
  echo "==> Attente de la configuration Keycloak"
  for _ in $(seq 1 90); do
    state=$($COMPOSE ps -a --format '{{.Service}} {{.State}} {{.ExitCode}}' | awk '$1=="keycloak-init"{print $2" "$3}')
    [ "$state" = "exited 0" ] && break
    if [[ "$state" == exited* ]]; then $COMPOSE logs keycloak-init; exit 1; fi
    sleep 4
  done
  $COMPOSE logs --no-log-prefix keycloak-init | tail -3
fi

echo "==> Tests (URL publique : ${PUBLIC_URL:-$(envval PUBLIC_URL)})"
python3 -m pytest -v tests/unit tests/e2e "$@"
