package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// newInClusterHTTPClient builds an HTTP client configured for in-cluster Kubernetes API access.
// Returns the client, base URL (e.g. "https://10.0.0.1:443"), and bearer token.
// Returns nil, "", "", nil when not running in a cluster (missing env vars or service-account files).
func newInClusterHTTPClient() (*http.Client, string, string, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, "", "", nil
	}

	tokenBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return nil, "", "", nil
	}
	token := strings.TrimSpace(string(tokenBytes))

	caBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		return nil, "", "", nil
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caBytes) {
		return nil, "", "", fmt.Errorf("failed to append Kubernetes CA cert")
	}

	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: caPool},
		},
	}

	return httpClient, "https://" + host + ":" + port, token, nil
}

// BackendResolver resolves a backend target (e.g. "default/mcp-backend") to the actual
// Kubernetes service (e.g. "default/kagent-tools") by looking up AgentgatewayBackend resources.
type BackendResolver interface {
	Resolve(ctx context.Context, backendTarget string) string
}

// ClientResolver resolves a client address (e.g. "10.42.1.63:58808" from src.addr) to a
// display name (e.g. "obo-observer") by looking up the pod in the configured namespace.
type ClientResolver interface {
	ResolveClient(ctx context.Context, clientAddr string) string
}

// KubernetesBackendResolver uses the Kubernetes API to resolve AgentgatewayBackend
// resources to namespace/service from the first target's host.
type KubernetesBackendResolver struct {
	client  *http.Client
	baseURL string
	token   string
	mu      sync.RWMutex
	cache   map[string]string
}

// AgentgatewayBackend CR structure (subset we need).
type agentgatewayBackendSpec struct {
	MCP *struct {
		Targets []struct {
			Static *struct {
				Host string `json:"host"`
			} `json:"static"`
		} `json:"targets"`
	} `json:"mcp"`
}

type agentgatewayBackendList struct {
	Spec agentgatewayBackendSpec `json:"spec"`
}

// NewKubernetesBackendResolver builds an in-cluster Kubernetes client and returns a resolver.
// Returns nil if not running in a cluster (missing env or token).
func NewKubernetesBackendResolver() (*KubernetesBackendResolver, error) {
	httpClient, baseURL, token, err := newInClusterHTTPClient()
	if err != nil {
		return nil, err
	}
	if httpClient == nil {
		return nil, nil
	}

	return &KubernetesBackendResolver{
		client:  httpClient,
		baseURL: baseURL,
		token:   token,
		cache:   make(map[string]string),
	}, nil
}

// Resolve returns "namespace/svc" for a backend target "namespace/name" by looking up
// the AgentgatewayBackend and reading the first target's host (e.g. kagent-tools.default.svc.cluster.local -> kagent-tools).
func (r *KubernetesBackendResolver) Resolve(ctx context.Context, backendTarget string) string {
	backendTarget = strings.TrimSpace(backendTarget)
	if backendTarget == "" {
		return ""
	}
	parts := strings.SplitN(backendTarget, "/", 2)
	if len(parts) != 2 {
		return ""
	}
	namespace, name := parts[0], parts[1]

	r.mu.RLock()
	if cached, ok := r.cache[backendTarget]; ok {
		r.mu.RUnlock()
		return cached
	}
	r.mu.RUnlock()

	resolved := r.fetchBackend(ctx, namespace, name)
	if resolved != "" {
		r.mu.Lock()
		r.cache[backendTarget] = resolved
		r.mu.Unlock()
	}
	return resolved
}

func (r *KubernetesBackendResolver) fetchBackend(ctx context.Context, namespace, name string) string {
	path := fmt.Sprintf("/apis/agentgateway.dev/v1alpha1/namespaces/%s/agentgatewaybackends/%s",
		url.PathEscape(namespace), url.PathEscape(name))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.baseURL+path, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+r.token)

	resp, err := r.client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}

	var obj agentgatewayBackendList
	if err := json.NewDecoder(resp.Body).Decode(&obj); err != nil {
		return ""
	}

	host := ""
	if obj.Spec.MCP != nil && len(obj.Spec.MCP.Targets) > 0 && obj.Spec.MCP.Targets[0].Static != nil {
		host = strings.TrimSpace(obj.Spec.MCP.Targets[0].Static.Host)
	}
	if host == "" {
		return ""
	}

	// host is e.g. "kagent-tools.default.svc.cluster.local" -> first segment is service name
	firstSegment := strings.SplitN(host, ".", 2)[0]
	if firstSegment == "" {
		return ""
	}
	return namespace + "/" + firstSegment
}

// KubernetesClientResolver resolves client IP (e.g. from src.addr) to a workload name by
// listing pods in the configured namespaces and matching status.podIP.
type KubernetesClientResolver struct {
	client        *http.Client
	baseURL       string
	token         string
	namespaces    []string
	allNamespaces bool // when true, list /api/v1/pods (cluster-wide)
	mu            sync.RWMutex
	cache         map[string]string
}

type podList struct {
	Items []struct {
		Metadata struct {
			Namespace string            `json:"namespace"`
			Labels    map[string]string `json:"labels"`
			Name      string            `json:"name"`
		} `json:"metadata"`
		Status struct {
			PodIP string `json:"podIP"`
		} `json:"status"`
	} `json:"items"`
}

// NewKubernetesClientResolver builds an in-cluster client that resolves client IPs to
// workload names (namespace/app or namespace/pod) by listing pods.
// namespaces: "*" = list pods in all namespaces (cluster-scoped); otherwise comma-separated (e.g. "obo-observer,default").
// Returns nil if not in cluster or namespaces is empty.
func NewKubernetesClientResolver(namespaces string) (*KubernetesClientResolver, error) {
	raw := strings.TrimSpace(namespaces)
	if raw == "" {
		return nil, nil
	}
	allNamespaces := raw == "*"
	var list []string
	if !allNamespaces {
		for _, p := range strings.Split(raw, ",") {
			p = strings.TrimSpace(p)
			if p != "" && p != "*" {
				list = append(list, p)
			}
		}
		if len(list) == 0 {
			return nil, nil
		}
	}
	httpClient, baseURL, token, err := newInClusterHTTPClient()
	if err != nil {
		return nil, err
	}
	if httpClient == nil {
		return nil, nil
	}
	return &KubernetesClientResolver{
		client:        httpClient,
		baseURL:       baseURL,
		token:         token,
		namespaces:    list,
		allNamespaces: allNamespaces,
		cache:         make(map[string]string),
	}, nil
}

func (r *KubernetesClientResolver) ResolveClient(ctx context.Context, clientAddr string) string {
	clientAddr = strings.TrimSpace(clientAddr)
	if clientAddr == "" {
		return ""
	}
	ip := clientAddr
	if idx := strings.LastIndex(clientAddr, ":"); idx >= 0 {
		ip = strings.TrimSpace(clientAddr[:idx])
	}
	if ip == "" {
		return ""
	}
	r.mu.RLock()
	if cached, ok := r.cache[ip]; ok {
		r.mu.RUnlock()
		return cached
	}
	r.mu.RUnlock()
	resolved := r.lookupPodByIP(ctx, ip)
	if resolved != "" {
		r.mu.Lock()
		r.cache[ip] = resolved
		r.mu.Unlock()
	}
	return resolved
}

func (r *KubernetesClientResolver) lookupPodByIP(ctx context.Context, podIP string) string {
	if r.allNamespaces {
		return r.lookupPodAllNamespaces(ctx, podIP)
	}
	for _, ns := range r.namespaces {
		if name := r.lookupPodInNamespace(ctx, ns, podIP); name != "" {
			return ns + "/" + name
		}
	}
	return ""
}

func (r *KubernetesClientResolver) lookupPodAllNamespaces(ctx context.Context, podIP string) string {
	path := "/api/v1/pods"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.baseURL+path, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+r.token)
	resp, err := r.client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var list podList
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return ""
	}
	for _, pod := range list.Items {
		if pod.Status.PodIP == podIP {
			ns := pod.Metadata.Namespace
			if ns == "" {
				ns = "default"
			}
			name := pod.Metadata.Name
			if app, ok := pod.Metadata.Labels["app.kubernetes.io/name"]; ok && app != "" {
				name = app
			} else if app, ok := pod.Metadata.Labels["app"]; ok && app != "" {
				name = app
			}
			return ns + "/" + name
		}
	}
	return ""
}

func (r *KubernetesClientResolver) lookupPodInNamespace(ctx context.Context, namespace, podIP string) string {
	path := fmt.Sprintf("/api/v1/namespaces/%s/pods", url.PathEscape(namespace))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.baseURL+path, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+r.token)
	resp, err := r.client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var list podList
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return ""
	}
	for _, pod := range list.Items {
		if pod.Status.PodIP == podIP {
			name := pod.Metadata.Name
			if app, ok := pod.Metadata.Labels["app.kubernetes.io/name"]; ok && app != "" {
				name = app
			} else if app, ok := pod.Metadata.Labels["app"]; ok && app != "" {
				name = app
			}
			return name
		}
	}
	return ""
}
