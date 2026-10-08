#!/bin/bash
# Configure Keycloak pour l'issuer. Rejouable (service « keycloak-init ») :
#  1. création unique du realm, du scope OID4VCI, des comptes et du client de test ;
#  2. mise en conformité à chaque démarrage des clients Inji (redirections, clé de Mimoto, client « wallet »).
set -euo pipefail
KC=/opt/keycloak/bin/kcadm.sh
R=${REALM:-senegal}

$KC config credentials --server "$KC_URL" --realm master --user "$KC_ADMIN" --password "$KC_ADMIN_PASSWORD"

# NB : l'image officielle Keycloak (UBI micro) ne contient ni awk, ni grep, ni head, ni tr :
#      uniquement du bash pur + kcadm.sh dans ce script.
first_line() { local l; IFS= read -r l || true; printf '%s' "$l"; }
client_id_of() { $KC get clients -r "$R" -q clientId="$1" --fields id --format csv --noquotes | first_line; }
scope_id_of() {
  local id name
  while IFS=, read -r id name; do [ "$name" = "$1" ] && { printf '%s' "$id"; return; }; done \
    < <($KC get client-scopes -r "$R" --fields id,name --format csv --noquotes)
}
json_array() { local IFS=,; local out=""; for v in $1; do out+="\"$v\","; done; echo "[${out%,}]"; }
pem_body() {  # contenu base64 d'un certificat PEM, sans en-têtes ni retours à la ligne
  local l out=""
  while IFS= read -r l || [ -n "$l" ]; do
    l=${l%$'\r'}; case "$l" in -----*) ;; *) out+="$l" ;; esac
  done < "$1"
  printf '%s' "$out"
}

# ------------------------------------------------------------------ 1. création unique
if ! $KC get "realms/$R" >/dev/null 2>&1; then
  echo "==> Realm $R"
  $KC create realms -s realm="$R" -s enabled=true -s sslRequired="${SSL_REQUIRED:-external}" \
    -s displayName="Identité numérique – Sénégal (démo)" -s accessTokenLifespan=600 \
    -s internationalizationEnabled=true -s 'supportedLocales=["fr","en"]' -s defaultLocale=fr

  echo "==> Scope OID4VCI $CREDENTIAL_SCOPE"
  SID=$($KC create client-scopes -r "$R" -i -s name="$CREDENTIAL_SCOPE" -s protocol=openid-connect \
    -s 'attributes."include.in.token.scope"=true' \
    -s 'attributes."display.on.consent.screen"=true' \
    -s 'attributes."consent.screen.text"=Obtenir ma carte d'"'"'identité numérique')
  $KC create "client-scopes/$SID/protocol-mappers/models" -r "$R" -s name=issuer-audience \
    -s protocol=openid-connect -s protocolMapper=oidc-audience-mapper \
    -s "config.\"included.custom.audience\"=$ISSUER_AUDIENCE" \
    -s 'config."access.token.claim"=true' -s 'config."id.token.claim"=false'

  echo "==> Client de test (mot de passe, DEV UNIQUEMENT)"
  TID=$($KC create clients -r "$R" -i -s clientId=issuer-test-cli -s protocol=openid-connect \
    -s publicClient=false -s secret="$TEST_CLIENT_SECRET" -s standardFlowEnabled=false \
    -s directAccessGrantsEnabled=true -s serviceAccountsEnabled=false)
  $KC update "clients/$TID/optional-client-scopes/$SID" -r "$R"
  $KC create "clients/$TID/protocol-mappers/models" -r "$R" -s name=issuer-audience \
    -s protocol=openid-connect -s protocolMapper=oidc-audience-mapper \
    -s "config.\"included.custom.audience\"=$ISSUER_AUDIENCE" \
    -s 'config."access.token.claim"=true' -s 'config."id.token.claim"=false'

  echo "==> Rôle et compte administrateur de l'issuer"
  $KC create roles -r "$R" -s name=issuer-admin -s 'description=Gestion des citoyens et des VC émis'
  $KC create users -r "$R" -s username=issuer-admin -s enabled=true -s firstName=Admin -s lastName=Issuer \
    -s email=issuer-admin@issuer.local -s emailVerified=true
  $KC set-password -r "$R" --username issuer-admin --new-password "$ISSUER_ADMIN_PASSWORD"
  $KC add-roles -r "$R" --uusername issuer-admin --rolename issuer-admin

  echo "==> Citoyen de démonstration (identifiant = NIN)"
  $KC create users -r "$R" -s username="$CITIZEN_USERNAME" -s enabled=true \
    -s firstName="MOUHAMED TIDIANE" -s lastName=SECK \
    -s email="$CITIZEN_USERNAME@citoyens.local" -s emailVerified=true
  $KC set-password -r "$R" --username "$CITIZEN_USERNAME" --new-password "$CITIZEN_PASSWORD"
else
  echo "Realm $R présent : mise en conformité seulement."
fi

# ------------------------------------------------------------------ 2. mise en conformité (à chaque démarrage)
$KC update "realms/$R" -s sslRequired="${SSL_REQUIRED:-external}"
SID=$(scope_id_of "$CREDENTIAL_SCOPE")

echo "==> Client Mimoto / Inji Web « $MIMOTO_CLIENT_ID » (private_key_jwt, PKCE)"
MID=$(client_id_of "$MIMOTO_CLIENT_ID")
if [ -z "$MID" ]; then
  MID=$($KC create clients -r "$R" -i -s clientId="$MIMOTO_CLIENT_ID" -s protocol=openid-connect \
    -s publicClient=false -s clientAuthenticatorType=client-jwt -s standardFlowEnabled=true \
    -s directAccessGrantsEnabled=false)
  $KC update "clients/$MID/optional-client-scopes/$SID" -r "$R"
fi
$KC update "clients/$MID" -r "$R" -s "redirectUris=$(json_array "$MIMOTO_REDIRECT_URIS")" -s 'webOrigins=["+"]' \
  -s 'attributes."pkce.code.challenge.method"=S256'
CERT_FILE=${MIMOTO_CERT_FILE:-/inji-certs/mimoto-client-cert.pem}
if [ -s "$CERT_FILE" ]; then
  # Mimoto signe son client_assertion sans « kid » : la clé est déclarée par certificat.
  CERT=$(pem_body "$CERT_FILE")
  $KC update "clients/$MID" -r "$R" -s 'attributes."use.jwks.url"=false' -s 'attributes."use.jwks.string"=false' \
    -s "attributes.\"jwt.credential.certificate\"=$CERT"
  echo "    certificat de Mimoto enregistré ($CERT_FILE)"
elif [ -n "${MIMOTO_JWKS:-}" ]; then
  $KC update "clients/$MID" -r "$R" -s 'attributes."use.jwks.string"=true' -s "attributes.\"jwks.string\"=$MIMOTO_JWKS"
  echo "    JWKS de Mimoto enregistré (MIMOTO_JWKS)"
fi

echo "==> Client public « $WALLET_CLIENT_ID » (Inji Wallet, offre d'identifiant, PKCE S256)"
WID=$(client_id_of "$WALLET_CLIENT_ID")
if [ -z "$WID" ]; then
  WID=$($KC create clients -r "$R" -i -s clientId="$WALLET_CLIENT_ID" -s protocol=openid-connect \
    -s publicClient=true -s standardFlowEnabled=true -s directAccessGrantsEnabled=false)
  $KC update "clients/$WID/optional-client-scopes/$SID" -r "$R"
fi
$KC update "clients/$WID" -r "$R" -s "redirectUris=$(json_array "$WALLET_REDIRECT_URIS")" \
  -s 'attributes."pkce.code.challenge.method"=S256'

echo "==> Interface d'enrôlement : client public « ${ADMIN_UI_CLIENT_ID:=issuer-admin-ui} » (PKCE S256)"
AID=$(client_id_of "$ADMIN_UI_CLIENT_ID")
if [ -z "$AID" ]; then
  AID=$($KC create clients -r "$R" -i -s clientId="$ADMIN_UI_CLIENT_ID" -s protocol=openid-connect \
    -s name="Enrôlement des cartes (issuer)" -s publicClient=true -s standardFlowEnabled=true \
    -s directAccessGrantsEnabled=false -s fullScopeAllowed=true)
  $KC create "clients/$AID/protocol-mappers/models" -r "$R" -s name=issuer-audience \
    -s protocol=openid-connect -s protocolMapper=oidc-audience-mapper \
    -s "config.\"included.custom.audience\"=$ISSUER_AUDIENCE" \
    -s 'config."access.token.claim"=true' -s 'config."id.token.claim"=false'
fi
ADMIN_UI_REDIRECTS="http://localhost:8088/admin/*,http://127.0.0.1:8088/admin/*"
case "${PUBLIC_URL:-}" in http*://*) ADMIN_UI_REDIRECTS="${PUBLIC_URL%/}/admin/*,$ADMIN_UI_REDIRECTS";; esac
$KC update "clients/$AID" -r "$R" -s "redirectUris=$(json_array "$ADMIN_UI_REDIRECTS")" -s 'webOrigins=["+"]' \
  -s 'attributes."post.logout.redirect.uris"=+' \
  -s 'attributes."pkce.code.challenge.method"=S256'

if [ -n "${ISSUER_BACKEND_SECRET:-}" ]; then
  echo "==> Compte de service « issuer-backend » (création des comptes des titulaires)"
  BID=$(client_id_of issuer-backend)
  if [ -z "$BID" ]; then
    BID=$($KC create clients -r "$R" -i -s clientId=issuer-backend -s protocol=openid-connect \
      -s publicClient=false -s standardFlowEnabled=false -s directAccessGrantsEnabled=false \
      -s serviceAccountsEnabled=true)
  fi
  $KC update "clients/$BID" -r "$R" -s secret="$ISSUER_BACKEND_SECRET"
  $KC add-roles -r "$R" --uusername service-account-issuer-backend --cclientid realm-management \
    --rolename manage-users --rolename view-users --rolename query-users
else
  echo "    ISSUER_BACKEND_SECRET vide : enrôlement sans création automatique des comptes"
fi

echo "Keycloak configuré."
