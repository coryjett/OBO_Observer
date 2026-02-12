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
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, nil
	}

	tokenBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return nil, nil
	}
	token := strings.TrimSpace(string(tokenBytes))

	caPath := "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	caBytes, err := os.ReadFile(caPath)
	if err != nil {
		return nil, nil
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caBytes) {
		return nil, fmt.Errorf("failed to append Kubernetes CA cert")
	}

	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: caPool},
		},
	}

	return &KubernetesBackendResolver{
		client:  httpClient,
		baseURL: "https://" + host + ":" + port,
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

// KubernetesClientResolver resolves client IP (e.g. from src.addr) to an app name by
// listing pods in the configured namespace and matching status.podIP.
type KubernetesClientResolver struct {
	client    *http.Client
	baseURL   string
	token     string
	namespace string
	mu        sync.RWMutex
	cache     map[string]string
}

type podList struct {
	Items []struct {
		Metadata struct {
			Labels map[string]string `json:"labels"`
			Name   string            `json:"name"`
		} `json:"metadata"`
		Status struct {
			PodIP string `json:"podIP"`
		} `json:"status"`
	} `json:"items"`
}

// NewKubernetesClientResolver builds an in-cluster client that resolves client IPs to
// pod app labels in the given namespace (e.g. obo-observer). Returns nil if not in cluster.
func NewKubernetesClientResolver(namespace string) (*KubernetesClientResolver, error) {
	if namespace == "" {
		return nil, nil
	}
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, nil
	}
	tokenBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return nil, nil
	}
	token := strings.TrimSpace(string(tokenBytes))
	caPath := "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	caBytes, err := os.ReadFile(caPath)
	if err != nil {
		return nil, nil
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caBytes) {
		return nil, fmt.Errorf("failed to append Kubernetes CA cert")
	}
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: caPool},
		},
	}
	return &KubernetesClientResolver{
		client:    httpClient,
		baseURL:   "https://" + host + ":" + port,
		token:     token,
		namespace: namespace,
		cache:     make(map[string]string),
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
	path := fmt.Sprintf("/api/v1/namespaces/%s/pods", url.PathEscape(r.namespace))
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
			if app, ok := pod.Metadata.Labels["app"]; ok && app != "" {
				name = app
			}
			return r.namespace + "/" + name
		}
	}
	return ""
}
