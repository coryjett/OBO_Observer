#!/usr/bin/env bash
# Port-forward Keycloak so OBO Observer login works (http://localhost:8081)
# Run this in your own terminal and leave it open. Stop with Ctrl+C.

set -e
echo "Starting Keycloak port-forward (leave this terminal open)..."
echo "Keycloak will be at: http://localhost:8081"
echo "  (OBO Observer uses this for Log in / OAuth2)"
echo ""
kubectl port-forward -n keycloak svc/keycloak 8081:8080
