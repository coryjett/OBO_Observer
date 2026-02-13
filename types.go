package main

import "time"

type Event struct {
	ID            string            `json:"id"`
	Timestamp     time.Time         `json:"timestamp"`
	RawLine       string            `json:"rawLine"`
	Context       string            `json:"context"`
	InboundJWT    string            `json:"inboundJwt"`
	ExchangedJWT  string            `json:"exchangedJwt"`
	Client         string            `json:"client"`
	ResolvedClient string            `json:"resolvedClient,omitempty"` // e.g. obo-observer when client IP matches our namespace pod
	Proxy          string            `json:"proxy"`
	Backend               string            `json:"backend"`               // request URL (source)
	BackendTarget         string            `json:"backendTarget"`         // backend resource name from logs (e.g. default/mcp-backend)
	ResolvedBackendService string          `json:"resolvedBackendService"` // actual K8s namespace/service (e.g. default/kagent-tools)
	Route                 string            `json:"route"`                 // HTTP route name (fallback)
	TraceID       string            `json:"traceId"`
	ParentSpanID  string            `json:"parentSpanId"`
	CurrentSpanID string            `json:"currentSpanId"`
	Headers       map[string]string `json:"headers"` // all key-value pairs parsed from the log (request/response attributes)
	BlockedByPolicy bool `json:"blockedByPolicy,omitempty"` // true when log indicates 401 or 403 (denied/blocked at gateway)
}
