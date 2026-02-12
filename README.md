# OBO Observer

Visualizes Agentgateway proxy activity: contexts hit, trace graph (client → proxy → backend), and request headers. Dark UI.

- **Log source:** `LOG_MODE=kubernetes` (default) or `LOG_MODE=file` with `LOG_FILE_PATH=/path/to/access.log`
- **Parser:** JSON and key/value access logs

## Local run

```bash
go run .
```

Open **http://localhost:8080**.

## Container build

```bash
docker build -t obo-observer:latest .
# Apple Silicon:  docker build --build-arg TARGETARCH=arm64 -t obo-observer:latest .
```

## Deploy to Kubernetes

```bash
kubectl apply -f k8s/obo-observer.yaml
# kind:  kind load docker-image obo-observer:latest
# k3d:   k3d image import obo-observer:latest -c <cluster-name>
```

```bash
kubectl port-forward -n obo-observer svc/obo-observer 8080:80
```

Then **http://localhost:8080**. For other clusters: push image to a registry and set `image` / `imagePullPolicy` in the manifest.

## Demo environment

Prereqs: `kubectl`, `helm`, `curl`, `jq`. Set your Solo license key:

```bash
export AGENTGATEWAY_LICENSE_KEY="<your-license-key>"
./demo_env.sh
```

Optional env: `KUBE_CONTEXT`, `ENTERPRISE_AGENTGATEWAY_VERSION`, `GATEWAY_API_VERSION`, `KEYCLOAK_*`, `KAGENT_TOOLS_VERSION`. See `.env.example`.

**UI — OBO flow:** (1) Generate User JWT, (2) Exchange via STS, (3) Call MCP tools/list. UI uses in-cluster URLs when running in Kubernetes.

## Cleanup

```bash
pkill -f "port-forward.*8080:80"
kubectl delete -f k8s/obo-observer.yaml
```

Full demo: delete namespaces `obo-observer`, `keycloak`, `agentgateway-system` (or `k3d cluster delete <name>`).

---

[AccessLog](https://docs.solo.io/agentgateway/2.1.x/reference/api/solo/#accesslog) · [OBO token exchange](https://docs.solo.io/agentgateway/2.1.x/security/obo-elicitations/obo/) · [MCP + OBO workshop](https://github.com/coryjett/solo-misc-workshops/blob/main/Agentgateway-OIDC-MCP-OBO.md)
# OBO_Observer
