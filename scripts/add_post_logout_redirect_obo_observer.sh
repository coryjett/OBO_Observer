#!/usr/bin/env bash
# Add post_logout_redirect_uri to the obo-observer Keycloak client so logout clears
# the Keycloak session and redirects back to the app (otherwise user appears still logged in).
# Run with Keycloak port-forward: kubectl port-forward -n keycloak svc/keycloak 8081:8080
set -euo pipefail

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8081}"
REALM="${KEYCLOAK_REALM:-oidc-realm}"
CLIENT_ID="obo-observer"
POST_LOGOUT_URI="${POST_LOGOUT_REDIRECT_URI:-http://localhost:8080/}"

ADMIN_TOKEN=$(curl -s -X POST "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
  -d "username=admin" -d "password=admin" -d "grant_type=password" -d "client_id=admin-cli" | jq -r '.access_token // empty')
if [ -z "${ADMIN_TOKEN}" ]; then
  echo "ERROR: Could not get Keycloak admin token. Is Keycloak at ${KEYCLOAK_URL}?"
  exit 1
fi

CLIENT_UUID=$(curl -s "${KEYCLOAK_URL}/admin/realms/${REALM}/clients?clientId=${CLIENT_ID}" -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq -r '.[0].id // empty')
if [ -z "${CLIENT_UUID}" ]; then
  echo "ERROR: Client ${CLIENT_ID} not found in realm ${REALM}"
  exit 1
fi

# Get current client and set attributes["post.logout.redirect.uris"] (Keycloak client attribute)
CURRENT=$(curl -s "${KEYCLOAK_URL}/admin/realms/${REALM}/clients/${CLIENT_UUID}" -H "Authorization: Bearer ${ADMIN_TOKEN}")
# Value "+" means use redirect URIs; or set a specific URI. Use our app root so logout redirects there.
UPDATED=$(echo "${CURRENT}" | jq --arg uri "${POST_LOGOUT_URI}" '
  .attributes = ((.attributes // {}) + {"post.logout.redirect.uris": $uri})
')
curl -s -X PUT "${KEYCLOAK_URL}/admin/realms/${REALM}/clients/${CLIENT_UUID}" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" -H "Content-Type: application/json" -d "${UPDATED}"
echo "Set post.logout.redirect.uris to ${POST_LOGOUT_URI} for ${CLIENT_ID}. Logout should now clear the session and return to the app."