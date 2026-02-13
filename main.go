package main

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

//go:embed web/*
var webFS embed.FS

// noCacheJS wraps a handler to set Cache-Control: no-cache for .js (and .css) so dev always gets latest.
func noCacheJS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "" {
			if strings.HasSuffix(r.URL.Path, ".js") || strings.HasSuffix(r.URL.Path, ".css") {
				w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			}
		}
		h.ServeHTTP(w, r)
	})
}

func main() {
	addr := getEnv("HTTP_ADDR", ":8080")
	runObserverMode(addr)
}

func runObserverMode(addr string) {
	logMode := strings.ToLower(getEnv("LOG_MODE", "kubernetes"))
	if logMode == "kubernetes" && os.Getenv("KUBERNETES_SERVICE_HOST") == "" {
		logMode = "sample"
		log.Printf("Not in cluster (KUBERNETES_SERVICE_HOST unset); using LOG_MODE=sample. Set LOG_MODE=file and LOG_FILE_PATH for a log file, or run in-cluster for kubernetes.")
	}
	bufferSize := getEnvInt("EVENT_BUFFER_SIZE", 500)

	store := NewEventStore(bufferSize)
	logBuffer := NewLogBuffer(bufferSize)
	logBroadcaster := NewLogBroadcaster()
	lines := make(chan string, 1024)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverStartTime := time.Now()

	source, err := createSource(logMode)
	if err != nil {
		log.Fatalf("failed to configure log source: %v", err)
	}

	var backendResolver BackendResolver
	var clientResolver ClientResolver
	if logMode == "kubernetes" {
		if r, err := NewKubernetesBackendResolver(); err == nil && r != nil {
			backendResolver = r
		}
		clientNS := getEnv("CLIENT_RESOLVE_NAMESPACE", "obo-observer")
		if r, err := NewKubernetesClientResolver(clientNS); err == nil && r != nil {
			clientResolver = r
		}
	}

	go func() {
		if err := source.Start(ctx, lines); err != nil {
			log.Printf("log source stopped: %v", err)
		}
	}()

	// Only show contexts that arrive after app start (skip initial tail burst from k8s/file)
	const acceptEventsAfter = 2 * time.Second
	go func() {
		for line := range lines {
			logBuffer.Add(line)
			logBroadcaster.Broadcast(line)
			event, ok := ParseLine(line)
			if !ok {
				continue
			}
			if time.Since(serverStartTime) <= acceptEventsAfter {
				continue
			}
			event.ID = hashLine(event.Timestamp.Format(time.RFC3339Nano) + "|" + event.RawLine)
			store.Add(event)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/api/info", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, map[string]string{"log_mode": logMode})
	})
	mux.HandleFunc("/api/events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		limit := 100
		if parsed, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && parsed > 0 && parsed <= 1000 {
			limit = parsed
		}

		events := store.List(limit)
		if backendResolver != nil {
			for i := range events {
				if events[i].BackendTarget != "" && events[i].ResolvedBackendService == "" {
					events[i].ResolvedBackendService = backendResolver.Resolve(r.Context(), events[i].BackendTarget)
				}
			}
		}
		if clientResolver != nil {
			for i := range events {
				if events[i].Client != "" && events[i].ResolvedClient == "" {
					events[i].ResolvedClient = clientResolver.ResolveClient(r.Context(), events[i].Client)
				}
			}
		}

		writeJSON(w, map[string]any{
			"events": events,
		})
	})
	mux.HandleFunc("/api/events/clear", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodGet {
			http.Error(w, "", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		store.Clear()
		writeJSON(w, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/api/logs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		limit := 200
		if parsed, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && parsed > 0 && parsed <= 1000 {
			limit = parsed
		}
		writeJSON(w, map[string]any{"lines": logBuffer.List(limit)})
	})
	mux.HandleFunc("/api/logs/stream", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Accel-Buffering", "no")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		sub := logBroadcaster.Subscribe()
		defer logBroadcaster.Unsubscribe(sub)
		writeSSELine := func(line string) {
			b, _ := json.Marshal(map[string]string{"line": line})
			w.Write([]byte("data: "))
			w.Write(b)
			w.Write([]byte("\n\n"))
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
		for _, line := range logBuffer.List(200) {
			writeSSELine(line)
		}
		for {
			select {
			case <-r.Context().Done():
				return
			case line, ok := <-sub:
				if !ok {
					return
				}
				writeSSELine(line)
			}
		}
	})
	mux.HandleFunc("/api/obo/user-jwt", handleUserJWT)
	mux.HandleFunc("/api/obo/exchange", handleExchange)
	mux.HandleFunc("/api/obo/mcp-tools", handleMCPTools)

	staticFS, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatalf("failed to build web filesystem: %v", err)
	}
	mux.Handle("/", noCacheJS(http.FileServer(http.FS(staticFS))))

	server := &http.Server{
		Addr:              addr,
		Handler:           withCORS(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("obo displayer listening on %s (log mode: %s)", addr, logMode)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server failure: %v", err)
	}
}

func createSource(mode string) (LogSource, error) {
	switch mode {
	case "file":
		return &FileLogSource{path: getEnv("LOG_FILE_PATH", "/tmp/obo-access.log")}, nil
	case "sample":
		interval := 5 * time.Second
		if i := getEnvInt("SAMPLE_INTERVAL_SEC", 5); i > 0 {
			interval = time.Duration(i) * time.Second
		}
		return &SampleLogSource{interval: interval}, nil
	case "kubernetes":
		namespace := getEnv("K8S_NAMESPACE", "agentgateway-system")
		selector := getEnv("K8S_POD_LABEL_SELECTOR", "app=agentgateway-proxy")
		container := getEnv("K8S_CONTAINER", "")
		tailLines := getEnvInt("K8S_TAIL_LINES", 200)
		return NewKubernetesLogSource(namespace, selector, container, tailLines)
	default:
		return nil, fmt.Errorf("LOG_MODE must be 'kubernetes', 'file', or 'sample' (got %q)", mode)
	}
}

func getEnv(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func getEnvInt(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}

func writeJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	data, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, `{"error":"marshal failure"}`, http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(data)
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
