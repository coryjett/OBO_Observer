#!/usr/bin/env bash
# Deploy OBO Observer to a real (multi-node) Kubernetes cluster.
#
# Unlike the k3d/kind demo (k8s/obo-observer.yaml + local image import), this builds a
# registry image, pushes it, and exposes the app via a Service (LoadBalancer by default).
# It observes whichever agentgateway data plane you point it at.
#
# Usage:
#   IMAGE=docker.io/you/obo-observer:latest \
#   GATEWAY_NAMESPACE=ingress \
#   GATEWAY_LABEL_SELECTOR='gateway.networking.k8s.io/gateway-name=internal-gateway' \
#   ./scripts/deploy-k8s.sh
#
#   # skip build/push (image already in registry):
#   BUILD=0 IMAGE=docker.io/you/obo-observer:latest GATEWAY_NAMESPACE=ingress ./scripts/deploy-k8s.sh
#
# Env vars (with defaults):
#   IMAGE                   (required) registry image ref to build/push and deploy
#   BUILD                   1 = docker buildx build+push (default 1); 0 = deploy only
#   PLATFORM                build platform (default linux/amd64 — most cluster nodes)
#   IMAGE_PULL_POLICY       Always (default) | IfNotPresent
#   SERVICE_TYPE            LoadBalancer (default) | ClusterIP | NodePort
#   GATEWAY_NAMESPACE       namespace of the agentgateway data-plane pods (default: default)
#   GATEWAY_LABEL_SELECTOR  pod label selector for the log source
#                           (default: app.kubernetes.io/name=enterprise-agentgateway)
#   CLIENT_RESOLVE_NAMESPACES  "*" (default) or comma-separated namespaces
#   KUBE_CONTEXT            kubectl context to use (default: current)
#   Optional interactive-flow vars (leave empty for Observer-only):
#     BASE_URL KEYCLOAK_URL KEYCLOAK_INTERNAL_URL KEYCLOAK_REALM
#     OAUTH2_CLIENT_ID OAUTH2_CLIENT_SECRET OPENAI_BASE_URL
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
MANIFEST="${REPO_DIR}/k8s/obo-observer-cluster.yaml"

: "${IMAGE:?Set IMAGE to a registry ref, e.g. docker.io/you/obo-observer:latest}"
export IMAGE
export BUILD="${BUILD:-1}"
export PLATFORM="${PLATFORM:-linux/amd64}"
export IMAGE_PULL_POLICY="${IMAGE_PULL_POLICY:-Always}"
export SERVICE_TYPE="${SERVICE_TYPE:-LoadBalancer}"
export GATEWAY_NAMESPACE="${GATEWAY_NAMESPACE:-default}"
export GATEWAY_LABEL_SELECTOR="${GATEWAY_LABEL_SELECTOR:-app.kubernetes.io/name=enterprise-agentgateway}"
export CLIENT_RESOLVE_NAMESPACES="${CLIENT_RESOLVE_NAMESPACES:-*}"
export BASE_URL="${BASE_URL:-}"
export KEYCLOAK_URL="${KEYCLOAK_URL:-}"
export KEYCLOAK_INTERNAL_URL="${KEYCLOAK_INTERNAL_URL:-}"
export KEYCLOAK_REALM="${KEYCLOAK_REALM:-}"
export OAUTH2_CLIENT_ID="${OAUTH2_CLIENT_ID:-}"
export OAUTH2_CLIENT_SECRET="${OAUTH2_CLIENT_SECRET:-}"
export OPENAI_BASE_URL="${OPENAI_BASE_URL:-}"

KCTL="kubectl"
[ -n "${KUBE_CONTEXT:-}" ] && KCTL="kubectl --context ${KUBE_CONTEXT}"

command -v envsubst >/dev/null || { echo "envsubst not found (install gettext)"; exit 1; }

if [ "${BUILD}" = "1" ]; then
  echo "==> Building + pushing ${IMAGE} (${PLATFORM})"
  # --platform=$BUILDPLATFORM in the Dockerfile cross-compiles natively (no QEMU).
  docker buildx build --platform "${PLATFORM}" -t "${IMAGE}" --push "${REPO_DIR}"
else
  echo "==> Skipping build (BUILD=0); expecting ${IMAGE} already in registry"
fi

echo "==> Rendering + applying manifest"
echo "    gateway logs : ${GATEWAY_NAMESPACE} / ${GATEWAY_LABEL_SELECTOR}"
echo "    service type : ${SERVICE_TYPE}"
# Only substitute our known vars so stray $... in the YAML is left intact.
VARS='$IMAGE $IMAGE_PULL_POLICY $SERVICE_TYPE $GATEWAY_NAMESPACE $GATEWAY_LABEL_SELECTOR $CLIENT_RESOLVE_NAMESPACES $BASE_URL $KEYCLOAK_URL $KEYCLOAK_INTERNAL_URL $KEYCLOAK_REALM $OAUTH2_CLIENT_ID $OAUTH2_CLIENT_SECRET $OPENAI_BASE_URL'
envsubst "${VARS}" < "${MANIFEST}" | ${KCTL} apply -f -

echo "==> Waiting for rollout"
${KCTL} rollout status deploy/obo-observer -n obo-observer --timeout=120s

if [ "${SERVICE_TYPE}" = "LoadBalancer" ]; then
  echo "==> Waiting for LoadBalancer IP"
  for _ in $(seq 1 30); do
    IP="$(${KCTL} get svc obo-observer -n obo-observer -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || true)"
    [ -n "${IP}" ] && break
    sleep 2
  done
  if [ -n "${IP:-}" ]; then
    echo ""
    echo "OBO Observer is up:  http://${IP}"
  else
    echo "LoadBalancer IP not assigned yet; check: ${KCTL} get svc -n obo-observer"
  fi
else
  echo ""
  echo "Service type ${SERVICE_TYPE}. Reach it via:"
  echo "  ${KCTL} port-forward -n obo-observer svc/obo-observer 8080:80   # then http://127.0.0.1:8080"
fi
