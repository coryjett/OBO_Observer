#!/usr/bin/env bash
# Port-forward OBO Observer so you can open http://localhost:8080
# Run this in your own terminal and leave it open. Stop with Ctrl+C.

set -e
echo "Starting port-forward (leave this terminal open)..."
echo "Open in your browser: http://localhost:8080"
echo ""
kubectl port-forward -n obo-observer svc/obo-observer 8080:80
