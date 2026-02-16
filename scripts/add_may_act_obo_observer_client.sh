#!/usr/bin/env bash
# Add may_act protocol mapper to the obo-observer Keycloak client so "Exchange via STS"
# succeeds when you log in via the app (subject token must contain may_act for delegation).
# Run with Keycloak port-forward active: kubectl port-forward -n keycloak svc/keycloak 8081:8080
# After running, log out and log in again in the OBO Observer UI to get a new token with may_act.
set -euo pipefail

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8081}"
REALM="${KEYCLOAK_REALM:-oidc-realm}"
CLIENT_ID="obo-observer"

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

HAS=$(curl -s "${KEYCLOAK_URL}/admin/realms/${REALM}/clients/${CLIENT_UUID}/protocol-mappers/models" -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq '[.[] | select(.name == "may_act")] | length')
if [ "${HAS}" != "0" ]; then
  echo "may_act mapper already present on ${CLIENT_ID}. Done."
  exit 0
fi

MAY_ACT_VALUE='{"sub": "system:serviceaccount:obo-observer:obo-observer"}'
curl -s -X POST "${KEYCLOAK_URL}/admin/realms/${REALM}/clients/${CLIENT_UUID}/protocol-mappers/models" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" -H "Content-Type: application/json" \
  -d "{
    \"name\": \"may_act\",
    \"protocol\": \"openid-connect\",
    \"protocolMapper\": \"oidc-hardcoded-claim-mapper\",
    \"config\": {
      \"claim.name\": \"may_act\",
      \"claim.value\": $(echo "${MAY_ACT_VALUE}" | jq -Rs .),
      \"jsonType.label\": \"JSON\",
      \"access.token.claim\": \"true\",
      \"id.token.claim\": \"false\",
      \"userinfo.token.claim\": \"false\"
    }
  }"
echo "Added may_act mapper to ${CLIENT_ID}. Log out and log in again in the OBO Observer UI, then try Exchange via STS."