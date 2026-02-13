#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "${SCRIPT_DIR}/.env" ]; then
  set -a
  # shellcheck source=/dev/null
  source "${SCRIPT_DIR}/.env"
  set +a
fi
# Use current context unless KUBE_CONTEXT is set (e.g. in .env or export)
if [ -z "${KUBE_CONTEXT:-}" ]; then
  KUBE_CONTEXT="$(kubectl config current-context)"
fi
AGENTGATEWAY_LICENSE_KEY="${AGENTGATEWAY_LICENSE_KEY:-}"
ENTERPRISE_AGENTGATEWAY_VERSION="${ENTERPRISE_AGENTGATEWAY_VERSION:-2.1.0}"
GATEWAY_API_VERSION="${GATEWAY_API_VERSION:-v1.4.0}"
KEYCLOAK_REALM="${KEYCLOAK_REALM:-oidc-realm}"
KEYCLOAK_CLIENT_ID="${KEYCLOAK_CLIENT_ID:-agw-client}"
KEYCLOAK_CLIENT_SECRET="${KEYCLOAK_CLIENT_SECRET:-agw-client-secret}"
KEYCLOAK_USERNAME="${KEYCLOAK_USERNAME:-testuser}"
KEYCLOAK_PASSWORD="${KEYCLOAK_PASSWORD:-testuser}"
KAGENT_TOOLS_VERSION="${KAGENT_TOOLS_VERSION:-0.0.13}"

if [ -z "${AGENTGATEWAY_LICENSE_KEY}" ] || [ "${AGENTGATEWAY_LICENSE_KEY}" = "REPLACE_WITH_SOLO_ENTERPRISE_LICENSE_KEY" ]; then
  echo "ERROR: Set AGENTGATEWAY_LICENSE_KEY before running (e.g. export AGENTGATEWAY_LICENSE_KEY=\"<your-license-key>\")"
  exit 1
fi

echo "Using Kubernetes context: ${KUBE_CONTEXT}"
kubectl config use-context "${KUBE_CONTEXT}"

echo "Applying demo_env.yaml..."
kubectl apply -f "${SCRIPT_DIR}/demo_env.yaml"

echo "Installing Gateway API CRDs..."
kubectl apply -f "https://github.com/kubernetes-sigs/gateway-api/releases/download/${GATEWAY_API_VERSION}/standard-install.yaml"

echo "Waiting for Postgres..."
kubectl wait -n keycloak deployment/postgres --for=condition=Available --timeout=120s

echo "Waiting for Keycloak (pod ready)..."
kubectl wait -n keycloak -l app=keycloak --for=condition=Ready pod --timeout=420s

echo "Starting Keycloak port-forward and creating realm, client, user..."
pkill -f "port-forward -n keycloak svc/keycloak 8081:8080" 2>/dev/null || true
kubectl port-forward -n keycloak svc/keycloak 8081:8080 &
KEYCLOAK_PF_PID=$!
trap "kill ${KEYCLOAK_PF_PID} 2>/dev/null || true" EXIT

KEYCLOAK_URL="http://localhost:8081"
for i in $(seq 1 60); do
  if curl -fsS -X POST "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
    -d "username=admin" -d "password=admin" -d "grant_type=password" -d "client_id=admin-cli" >/tmp/obo-demo-admin-token.json 2>/dev/null; then
    break
  fi
  sleep 2
done
ADMIN_TOKEN=$(jq -r '.access_token // empty' /tmp/obo-demo-admin-token.json 2>/dev/null || true)
if [ -z "${ADMIN_TOKEN}" ]; then
  echo "ERROR: Could not obtain Keycloak admin token"
  exit 1
fi

curl -s -X POST "${KEYCLOAK_URL}/admin/realms" -H "Authorization: Bearer ${ADMIN_TOKEN}" -H "Content-Type: application/json" -d "{\"realm\":\"${KEYCLOAK_REALM}\",\"enabled\":true}" || true
curl -s -X POST "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients" -H "Authorization: Bearer ${ADMIN_TOKEN}" -H "Content-Type: application/json" -d "{\"clientId\":\"${KEYCLOAK_CLIENT_ID}\",\"enabled\":true,\"clientAuthenticatorType\":\"client-secret\",\"secret\":\"${KEYCLOAK_CLIENT_SECRET}\",\"directAccessGrantsEnabled\":true,\"serviceAccountsEnabled\":false}" || true
# User with requiredActions=[] so token grant does not return "Account is not fully set up" (see Agentgateway-OIDC-MCP-OBO.md Step 2)
curl -s -X POST "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/users" -H "Authorization: Bearer ${ADMIN_TOKEN}" -H "Content-Type: application/json" -d "{\"username\":\"${KEYCLOAK_USERNAME}\",\"email\":\"${KEYCLOAK_USERNAME}@example.com\",\"emailVerified\":true,\"firstName\":\"Test\",\"lastName\":\"User\",\"enabled\":true,\"requiredActions\":[],\"credentials\":[{\"type\":\"password\",\"value\":\"${KEYCLOAK_PASSWORD}\",\"temporary\":false}]}" || true

# Add may_act claim to agw-client so STS OBO exchange succeeds (subject token must contain may_act for delegation)
# See: docs.solo.io/agentgateway OBO token exchange; sub = system:serviceaccount:obo-observer:obo-observer
AGW_CLIENT_UUID=$(curl -s "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients?clientId=${KEYCLOAK_CLIENT_ID}" -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq -r '.[0].id // empty')
if [ -n "${AGW_CLIENT_UUID}" ]; then
  HAS_MAY_ACT=$(curl -s "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients/${AGW_CLIENT_UUID}/protocol-mappers/models" -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq -r '[.[] | select(.name == "may_act")] | length')
  if [ "${HAS_MAY_ACT}" = "0" ]; then
    MAY_ACT_VALUE='{"sub": "system:serviceaccount:obo-observer:obo-observer"}'
    curl -s -X POST "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients/${AGW_CLIENT_UUID}/protocol-mappers/models" \
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
      }" || true
  fi
fi

trap - EXIT
kill ${KEYCLOAK_PF_PID} 2>/dev/null || true

KEYCLOAK_JWKS_URL="http://keycloak.keycloak.svc.cluster.local:8080/realms/${KEYCLOAK_REALM}/protocol/openid-connect/certs"
echo "Installing Enterprise Agentgateway (CRDs + control plane with STS)..."
helm upgrade -i enterprise-agentgateway-crds oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway-crds \
  --create-namespace --namespace agentgateway-system --version "${ENTERPRISE_AGENTGATEWAY_VERSION}"
helm upgrade -i enterprise-agentgateway oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway \
  --namespace agentgateway-system --version "${ENTERPRISE_AGENTGATEWAY_VERSION}" \
  --set-string licensing.licenseKey="${AGENTGATEWAY_LICENSE_KEY}" \
  --set tokenExchange.enabled=true \
  --set tokenExchange.issuer="enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777" \
  --set tokenExchange.tokenExpiration=24h \
  --set tokenExchange.subjectValidator.validatorType=remote \
  --set "tokenExchange.subjectValidator.remoteConfig.url=${KEYCLOAK_JWKS_URL}" \
  --set tokenExchange.actorValidator.validatorType=k8s

echo "Creating agentgateway-proxy Gateway..."
kubectl apply -f - <<'EOF'
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: agentgateway-proxy
  namespace: agentgateway-system
spec:
  gatewayClassName: enterprise-agentgateway
  listeners:
    - name: http
      protocol: HTTP
      port: 80
      allowedRoutes:
        namespaces:
          from: All
EOF

echo "Applying access logging policy for agentgateway-proxy (AccessLog API)..."
# AccessLog: https://agentgateway.dev/docs/kubernetes/latest/reference/api/#accesslog
# filter=true emits a log for every request; use a CEL expression to restrict (e.g. request.path.startsWith("/mcp")).
# attributes.add can add custom key-value pairs (name + CEL expression).
kubectl apply -f - <<'EOF'
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayPolicy
metadata:
  name: proxy-access-log
  namespace: agentgateway-system
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: Gateway
      name: agentgateway-proxy
  frontend:
    accessLog:
      filter: "true"
EOF

echo "Installing kagent-tools and MCP route..."
helm upgrade -i -n default kagent-tools oci://ghcr.io/kagent-dev/tools/helm/kagent-tools --version "${KAGENT_TOOLS_VERSION}"
kubectl wait -n default deployment/kagent-tools --for=condition=Available --timeout=180s
kubectl patch svc kagent-tools -n default --type=merge -p '{"spec":{"ports":[{"name":"tools","port":8084,"targetPort":8084,"appProtocol":"kgateway.dev/mcp"}]}}'

kubectl apply -f - <<'EOF'
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: enterprise-agentgateway
  namespace: default
spec:
  gatewayClassName: enterprise-agentgateway
  listeners:
    - name: http
      port: 80
      protocol: HTTP
      allowedRoutes:
        namespaces:
          from: All
---
apiVersion: agentgateway.dev/v1alpha1
kind: AgentgatewayBackend
metadata:
  name: mcp-backend
  namespace: default
spec:
  mcp:
    targets:
      - name: mcp-target
        static:
          host: kagent-tools.default.svc.cluster.local
          port: 8084
          protocol: StreamableHTTP
          path: /mcp
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: mcp-route
  namespace: default
spec:
  parentRefs:
    - name: enterprise-agentgateway
      namespace: default
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /mcp
      backendRefs:
        - name: mcp-backend
          group: agentgateway.dev
          kind: AgentgatewayBackend
    - matches:
        - path:
            type: PathPrefix
            value: /.well-known/oauth-protected-resource/mcp
        - path:
            type: PathPrefix
            value: /.well-known/oauth-authorization-server/mcp
      backendRefs:
        - name: mcp-backend
          group: agentgateway.dev
          kind: AgentgatewayBackend
EOF

echo "Applying access log policy for enterprise-agentgateway (emit request URL, backend name, Authorization header)..."
kubectl apply -f - <<'EOF'
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayPolicy
metadata:
  name: mcp-access-log-backend
  namespace: default
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: Gateway
      name: enterprise-agentgateway
  frontend:
    accessLog:
      filter: "true"
      attributes:
        add:
          - name: "request.uri"
            expression: "request.uri"
          - name: "backend.name"
            expression: "backend.name"
          - name: "authorization"
            expression: 'default(request.headers["authorization"], "")'
EOF

# In-cluster MCP URL so the displayer pod can call MCP without a port-forward; OBO token audience matches.
MCP_AUDIENCE="http://enterprise-agentgateway.default.svc.cluster.local/mcp"
echo "Applying MCP STS auth policy (audience ${MCP_AUDIENCE})..."
kubectl apply -f - <<EOF
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayPolicy
metadata:
  name: mcp-sts-authn
  namespace: default
spec:
  targetRefs:
    - group: agentgateway.dev
      kind: AgentgatewayBackend
      name: mcp-backend
  backend:
    mcp:
      authentication:
        issuer: "enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777"
        jwks:
          backendRef:
            kind: Service
            name: enterprise-agentgateway
            namespace: agentgateway-system
            port: 7777
          jwksPath: .well-known/jwks.json
        provider: Keycloak
        resourceMetadata:
          resource: "${MCP_AUDIENCE}"
        audiences:
          - "${MCP_AUDIENCE}"
        mode: Strict
EOF

echo "Starting single port-forward (obo-observer only)..."
echo "  Keycloak, STS, and MCP are reached by the displayer pod via in-cluster URLs; no port-forwards needed for them."
pkill -f "port-forward -n obo-observer svc/obo-observer 8080:80" 2>/dev/null || true
sleep 1
kubectl port-forward -n obo-observer svc/obo-observer 8080:80 &
sleep 2

echo "Demo environment ready."
echo "  OBO Observer:  http://localhost:8080  (only port-forward; use the UI to run the OBO flow)"
echo "Verify: kubectl get pods -n keycloak; kubectl get pods -n agentgateway-system; kubectl get gateway -n agentgateway-system agentgateway-proxy; kubectl get gateway,agentgatewaybackend,httproute -n default"
