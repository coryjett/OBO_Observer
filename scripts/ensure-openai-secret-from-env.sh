#!/usr/bin/env bash
# If OPENAI_API_KEY is set (e.g. from .env), create or update the obo-observer-openai
# secret in the obo-observer namespace so the deployed app hides the API key field in the UI.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${PROJECT_ROOT}/.env"

if [ -f "${ENV_FILE}" ]; then
  set -a
  # shellcheck source=/dev/null
  source "${ENV_FILE}"
  set +a
fi

if [ -z "${OPENAI_API_KEY:-}" ]; then
  exit 0
fi

kubectl create namespace obo-observer --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1 || true
kubectl create secret generic obo-observer-openai -n obo-observer \
  --from-literal=OPENAI_API_KEY="${OPENAI_API_KEY}" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "Created/updated secret obo-observer-openai in namespace obo-observer (from .env OPENAI_API_KEY)."
