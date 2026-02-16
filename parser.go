package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

var (
	keyValuePattern   = regexp.MustCompile(`([a-zA-Z0-9_.-]+)=("([^"]*)"|[^"\s]+)`)
	jwtLikePattern    = regexp.MustCompile(`[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
	bearerTokenInLine = regexp.MustCompile(`(?i)bearer\s+([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)`)
)

func ParseLine(raw string) (Event, bool) {
	line := strings.TrimSpace(raw)
	if line == "" {
		return Event{}, false
	}

	fields := map[string]string{}
	if strings.HasPrefix(line, "{") && strings.HasSuffix(line, "}") {
		jsonFields := map[string]any{}
		if err := json.Unmarshal([]byte(line), &jsonFields); err == nil {
			flattenJSONIntoFields(jsonFields, fields, "")
		}
	}

	for _, match := range keyValuePattern.FindAllStringSubmatch(line, -1) {
		if len(match) < 4 {
			continue
		}
		key := strings.ToLower(match[1])
		value := strings.Trim(match[2], `"`)
		fields[key] = value
	}

	event := Event{
		Timestamp: parseTimestamp(fields),
		RawLine:   line,
		Context:   firstNonEmpty(fields, "context", "path", "http.path", "uri", "request_path", "requestpath", "url", "route"),
		InboundJWT: cleanupToken(firstNonEmpty(
			fields,
			"inbound_jwt",
			"inboundjwt",
			"auth_jwt",
			"inbound_authentication_jwt",
			"authorization",
			"request.authorization",
			"http.authorization",
		)),
		ExchangedJWT: cleanupToken(firstNonEmpty(
			fields,
			"obo_jwt",
			"exchanged_jwt",
			"obo_token",
			"token_exchange_jwt",
			"x_obo_jwt",
		)),
		Client:        firstNonEmpty(fields, "client", "source", "src.addr", "downstream", "caller", "downstream_service"),
		Proxy:         firstNonEmpty(fields, "proxy", "gateway", "proxy_name", "workload"),
		Backend:       firstNonEmpty(fields, "request.uri", "request_uri", "backend.name", "backend", "endpoint", "upstream", "route", "service", "target", "upstream_cluster"),
		BackendTarget: firstNonEmpty(fields, "backend.name", "backend", "endpoint", "upstream", "service", "target", "upstream_cluster"),
		Route:         firstNonEmpty(fields, "route", "route_name", "http_route"),
		TraceID:       firstNonEmpty(fields, "trace_id", "x_b3_traceid", "traceid"),
		ParentSpanID:  firstNonEmpty(fields, "parent_span_id", "parentspanid", "x_b3_parentspanid"),
		CurrentSpanID: firstNonEmpty(fields, "span_id", "spanid", "x_b3_spanid"),
	}

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	if event.Proxy == "" {
		event.Proxy = "agentgateway-proxy"
	}

	// Key=value stops at space for unquoted values, so "authorization=Bearer eyJ..." only captures "Bearer".
	// Extract full JWT from raw line when we see "Bearer <jwt>".
	if event.InboundJWT == "" {
		if submatch := bearerTokenInLine.FindStringSubmatch(line); len(submatch) > 1 && looksLikeJWT(submatch[1]) {
			event.InboundJWT = submatch[1]
		}
	}
	// Fallback: scan for real JWTs only (avoid matching IPs like 10.42.1.63 or type_url values like type.googleapis.com).
	if event.InboundJWT == "" || event.ExchangedJWT == "" {
		tokens := jwtLikePattern.FindAllString(line, -1)
		var realJWTs []string
		for _, t := range tokens {
			if looksLikeJWT(t) {
				realJWTs = append(realJWTs, t)
			}
		}
		if len(realJWTs) > 0 && event.InboundJWT == "" {
			event.InboundJWT = realJWTs[0]
		}
		if len(realJWTs) > 1 && event.ExchangedJWT == "" {
			event.ExchangedJWT = realJWTs[1]
		}
	}

	// Expose all parsed fields as headers so the UI can show everything received by Agentgateway (no duplicate inbound_jwt; keep authorization only)
	event.Headers = make(map[string]string, len(fields))
	bodyKeys := map[string]bool{
		"response.body": true, "response_body": true, "response_body_content": true,
		"request.body": true, "request_body": true, "body": true,
	}
	for k, v := range fields {
		keyLower := strings.ToLower(k)
		if bodyKeys[keyLower] && v != "" {
			v = tryDecompressBodyValue(v)
		}
		event.Headers[k] = v
	}

	// Blocked/denied at gateway: 401 (no/invalid token) or 403 (policy). Show blocked icon for both.
	code := responseCodeFromFields(fields)
	event.BlockedByPolicy = (code == 401 || code == 403) || rawLineContains4xxBlocked(line)

	// Accept any line that looks like a request: path/context, JWTs, trace, or request metadata (client/backend)
	interesting := event.Context != "" || event.InboundJWT != "" || event.ExchangedJWT != "" || event.TraceID != "" ||
		event.Client != "" || event.Backend != "" || event.Route != ""
	return event, interesting
}

func parseTimestamp(fields map[string]string) time.Time {
	value := firstNonEmpty(fields, "timestamp", "ts", "@timestamp", "time")
	if value == "" {
		return time.Time{}
	}

	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.000Z07:00",
		"2006-01-02 15:04:05",
	}

	for _, layout := range layouts {
		if t, err := time.Parse(layout, value); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// tryDecompressBodyValue returns decompressed UTF-8 if v is base64-encoded gzip; otherwise returns v unchanged.
func tryDecompressBodyValue(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return v
	}
	raw, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		// try URL-safe base64 (e.g. from JSON)
		raw, err = base64.URLEncoding.DecodeString(v)
		if err != nil {
			return v
		}
	}
	if len(raw) < 2 || raw[0] != 0x1f || raw[1] != 0x8b {
		return v
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return v
	}
	defer zr.Close()
	out, err := io.ReadAll(zr)
	if err != nil {
		return v
	}
	return string(out)
}

// flattenJSONIntoFields writes JSON object keys into fields with dot-separated names (e.g. http.status).
func flattenJSONIntoFields(obj map[string]any, fields map[string]string, prefix string) {
	for k, v := range obj {
		key := strings.ToLower(strings.TrimSpace(k))
		if key == "" {
			continue
		}
		fullKey := key
		if prefix != "" {
			fullKey = prefix + "." + key
		}
		switch val := v.(type) {
		case map[string]any:
			flattenJSONIntoFields(val, fields, fullKey)
		default:
			fields[fullKey] = anyToString(v)
		}
	}
}

func firstNonEmpty(fields map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(fields[strings.ToLower(key)]); value != "" {
			return value
		}
	}
	return ""
}

// responseCodeFromFields returns the HTTP response code from log fields. Agentgateway uses http.status; Envoy uses response_code.
func responseCodeFromFields(fields map[string]string) int {
	value := firstNonEmpty(fields, "http.status", "response_code", "response_code_number", "response_code_number_value", "status", "http_status_code", "http_status")
	if value == "" {
		return 0
	}
	var code int
	if _, err := fmt.Sscanf(value, "%d", &code); err != nil {
		return 0
	}
	return code
}

// rawLineContains4xxBlocked returns true if the raw log line indicates HTTP 401 or 403 (denied/blocked at gateway).
func rawLineContains4xxBlocked(line string) bool {
	line = strings.TrimSpace(line)
	if line == "" {
		return false
	}
	for _, code := range []string{"401", "403"} {
		if strings.Contains(line, "http.status="+code) || strings.Contains(line, "response_code="+code) ||
			strings.Contains(line, "status="+code) || strings.Contains(line, "http_status="+code) {
			return true
		}
		if strings.Contains(line, " "+code+" ") || strings.HasSuffix(line, " "+code) || strings.HasPrefix(line, code+" ") {
			return true
		}
	}
	return false
}

func anyToString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case float64:
		return fmt.Sprintf("%v", typed)
	case bool:
		if typed {
			return "true"
		}
		return "false"
	default:
		data, err := json.Marshal(value)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(strings.ReplaceAll(strings.Trim(string(data), `"`), "\n", " "))
	}
}

func cleanupToken(value string) string {
	trimmed := strings.TrimSpace(strings.Trim(value, `"`))
	if strings.HasPrefix(strings.ToLower(trimmed), "bearer ") {
		trimmed = strings.TrimSpace(trimmed[7:])
	}
	return trimmed
}

// looksLikeJWT returns true if s looks like a JWT (base64url header.payload.signature), not an IP or type_url.
func looksLikeJWT(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < 50 {
		return false
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return false
	}
	// JWT header is typically eyJ (alg HS256) or eyI/eyH etc.; avoid numeric or short segments (e.g. 10.42.1 from IP)
	first := parts[0]
	if len(first) < 4 {
		return false
	}
	switch {
	case strings.HasPrefix(first, "eyJ"), strings.HasPrefix(first, "eyI"), strings.HasPrefix(first, "eyH"):
		return true
	default:
		// Allow other base64url-looking starts if the token is long enough
		for _, c := range first {
			if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
				continue
			}
			return false
		}
		return len(first) >= 10
	}
}
