package main

import (
	"bufio"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type LogSource interface {
	Start(ctx context.Context, out chan<- string) error
}

type FileLogSource struct {
	path string
}

func (s *FileLogSource) Start(ctx context.Context, out chan<- string) error {
	var offset int64

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		file, err := os.Open(s.path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				time.Sleep(2 * time.Second)
				continue
			}
			return fmt.Errorf("open log file: %w", err)
		}

		stat, err := file.Stat()
		if err != nil {
			_ = file.Close()
			return fmt.Errorf("stat log file: %w", err)
		}
		if stat.Size() < offset {
			offset = 0
		}

		_, err = file.Seek(offset, io.SeekStart)
		if err != nil {
			_ = file.Close()
			return fmt.Errorf("seek log file: %w", err)
		}

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				_ = file.Close()
				return nil
			case out <- scanner.Text():
			}
		}
		if err := scanner.Err(); err != nil {
			_ = file.Close()
			return fmt.Errorf("scan log file: %w", err)
		}

		newOffset, err := file.Seek(0, io.SeekCurrent)
		if err == nil {
			offset = newOffset
		}
		_ = file.Close()

		time.Sleep(1500 * time.Millisecond)
	}
}

// SampleLogSource emits sample log lines for local demo (no k8s or file needed).
type SampleLogSource struct {
	interval time.Duration
}

func (s *SampleLogSource) Start(ctx context.Context, out chan<- string) error {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	samples := []map[string]string{
		{"context": "/mcp", "client": "10.42.0.1:12345", "proxy": "enterprise-agentgateway", "backend": "default/kagent-tools", "trace_id": "sample-1", "span_id": "span-1"},
		{"context": "/mcp", "client": "obo-observer/obo-observer", "proxy": "enterprise-agentgateway", "backend": "default/kagent-tools", "trace_id": "sample-2", "span_id": "span-2"},
		{"context": "/health", "client": "10.42.0.2:54321", "proxy": "enterprise-agentgateway", "backend": "default/echo", "trace_id": "sample-3", "span_id": "span-3"},
	}
	n := 0
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			fields := samples[n%len(samples)]
			fields["timestamp"] = time.Now().UTC().Format(time.RFC3339Nano)
			line, err := json.Marshal(fields)
			if err != nil {
				continue
			}
			select {
			case out <- string(line):
			case <-ctx.Done():
				return nil
			}
			n++
		}
	}
}

type KubernetesLogSource struct {
	namespace     string
	labelSelector string
	container     string
	tailLines     int
	client        *http.Client
	baseURL       string
	token         string
}

func NewKubernetesLogSource(namespace, labelSelector, container string, tailLines int) (*KubernetesLogSource, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, errors.New("kubernetes service host/port environment variables missing")
	}

	tokenBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return nil, fmt.Errorf("read serviceaccount token: %w", err)
	}
	token := strings.TrimSpace(string(tokenBytes))

	caPath := "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	caBytes, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert %s: %w", filepath.Clean(caPath), err)
	}
	caPool := x509.NewCertPool()
	if ok := caPool.AppendCertsFromPEM(caBytes); !ok {
		return nil, errors.New("failed to append Kubernetes CA cert")
	}

	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caPool,
			},
		},
	}

	return &KubernetesLogSource{
		namespace:     namespace,
		labelSelector: labelSelector,
		container:     container,
		tailLines:     tailLines,
		client:        httpClient,
		baseURL:       "https://" + host + ":" + port,
		token:         token,
	}, nil
}

func (s *KubernetesLogSource) Start(ctx context.Context, out chan<- string) error {
	seen := map[string]time.Time{}

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		pods, err := s.listPods(ctx)
		if err == nil {
			for _, pod := range pods {
				logs, logErr := s.fetchPodLogs(ctx, pod)
				if logErr != nil {
					continue
				}
				for _, line := range splitLines(logs) {
					signature := hashLine(pod + "|" + line)
					if _, exists := seen[signature]; exists {
						continue
					}
					seen[signature] = time.Now()
					select {
					case <-ctx.Done():
						return nil
					case out <- line:
					}
				}
			}
		}

		cutoff := time.Now().Add(-7 * time.Minute)
		for key, observed := range seen {
			if observed.Before(cutoff) {
				delete(seen, key)
			}
		}

		time.Sleep(2500 * time.Millisecond)
	}
}

func (s *KubernetesLogSource) listPods(ctx context.Context) ([]string, error) {
	apiPath := fmt.Sprintf("/api/v1/namespaces/%s/pods?labelSelector=%s", url.PathEscape(s.namespace), url.QueryEscape(s.labelSelector))
	req, err := s.newRequest(ctx, apiPath)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list pods status=%d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var parsed struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, err
	}

	result := make([]string, 0, len(parsed.Items))
	for _, item := range parsed.Items {
		if item.Metadata.Name != "" {
			result = append(result, item.Metadata.Name)
		}
	}
	return result, nil
}

func (s *KubernetesLogSource) fetchPodLogs(ctx context.Context, pod string) (string, error) {
	query := url.Values{}
	if s.container != "" {
		query.Set("container", s.container)
	}
	query.Set("tailLines", strconv.Itoa(s.tailLines))
	query.Set("timestamps", "true")

	apiPath := fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/log?%s", url.PathEscape(s.namespace), url.PathEscape(pod), query.Encode())
	req, err := s.newRequest(ctx, apiPath)
	if err != nil {
		return "", err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("pod logs status=%d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func (s *KubernetesLogSource) newRequest(ctx context.Context, apiPath string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.baseURL+apiPath, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	return req, nil
}

func splitLines(input string) []string {
	raw := strings.Split(input, "\n")
	result := make([]string, 0, len(raw))
	for _, line := range raw {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func hashLine(value string) string {
	sum := sha1.Sum([]byte(value))
	return hex.EncodeToString(sum[:])
}
