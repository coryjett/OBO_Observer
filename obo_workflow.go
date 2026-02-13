package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type userJWTRequest struct {
	KeycloakURL  string `json:"keycloakUrl"`
	Realm        string `json:"realm"`
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	Username     string `json:"username"`
	Password     string `json:"password"`
}

type exchangeRequest struct {
	STSURL       string `json:"stsUrl"`
	UserJWT      string `json:"userJwt"`
	ActorToken   string `json:"actorToken"`
	ExchangeMode string `json:"exchangeMode"` // "impersonation" (subject only) or "delegation" (subject + actor)
}

type mcpToolsRequest struct {
	MCPURL     string `json:"mcpUrl"`
	OBOJWT     string `json:"oboJwt"`
	UserJWT    string `json:"userJwt"`
	UseUserJWT bool   `json:"useUserJwt"`
}

func handleUserJWT(w http.ResponseWriter, r *http.Request) {
	var req userJWTRequest
	if err := decodeRequest(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.KeycloakURL == "" || req.Realm == "" || req.ClientID == "" || req.ClientSecret == "" || req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "missing required fields")
		return
	}

	form := url.Values{}
	form.Set("username", req.Username)
	form.Set("password", req.Password)
	form.Set("grant_type", "password")
	form.Set("client_id", req.ClientID)
	form.Set("client_secret", req.ClientSecret)

	tokenURL := strings.TrimRight(req.KeycloakURL, "/") + "/realms/" + req.Realm + "/protocol/openid-connect/token"
	body, status, err := postForm(tokenURL, form, "")
	if err != nil {
		writeError(w, http.StatusBadGateway, "keycloak token request failed: "+err.Error())
		return
	}
	if status < 200 || status > 299 {
		writeError(w, http.StatusBadGateway, "keycloak token request status "+http.StatusText(status))
		return
	}

	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		writeError(w, http.StatusBadGateway, "invalid keycloak response")
		return
	}

	accessToken, _ := parsed["access_token"].(string)
	if accessToken == "" {
		writeError(w, http.StatusBadGateway, "keycloak response did not include access_token")
		return
	}

	writeJSON(w, map[string]any{
		"userJwt": accessToken,
	})
}

func handleExchange(w http.ResponseWriter, r *http.Request) {
	var req exchangeRequest
	if err := decodeRequest(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.STSURL == "" || req.UserJWT == "" {
		writeError(w, http.StatusBadRequest, "missing required fields")
		return
	}

	exchangeMode := strings.TrimSpace(strings.ToLower(req.ExchangeMode))
	if exchangeMode == "" {
		exchangeMode = "delegation"
	}

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	form.Set("subject_token", req.UserJWT)
	form.Set("subject_token_type", "urn:ietf:params:oauth:token-type:jwt")

	if exchangeMode == "delegation" {
		actorToken := strings.TrimSpace(req.ActorToken)
		if actorToken == "" {
			data, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
			if err == nil {
				actorToken = strings.TrimSpace(string(data))
			}
		}
		if actorToken == "" {
			writeError(w, http.StatusBadRequest, "delegation requires an actor token; provide actorToken or run in Kubernetes")
			return
		}
		form.Set("actor_token", actorToken)
		form.Set("actor_token_type", "urn:ietf:params:oauth:token-type:jwt")
	}
	// impersonation: subject_token only (no actor_token)

	body, status, err := postForm(strings.TrimRight(req.STSURL, "/")+"/token", form, "Bearer "+req.UserJWT)
	if err != nil {
		writeError(w, http.StatusBadGateway, "sts exchange failed: "+err.Error())
		return
	}
	if status < 200 || status > 299 {
		writeError(w, http.StatusBadGateway, "sts exchange status "+http.StatusText(status))
		return
	}

	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		writeError(w, http.StatusBadGateway, "invalid sts response")
		return
	}

	oboToken, _ := parsed["access_token"].(string)
	if oboToken == "" {
		writeError(w, http.StatusBadGateway, "sts response did not include access_token")
		return
	}

	writeJSON(w, map[string]any{
		"oboJwt":      oboToken,
		"stsResponse": parsed,
	})
}

func handleMCPTools(w http.ResponseWriter, r *http.Request) {
	var req mcpToolsRequest
	if err := decodeRequest(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.MCPURL == "" {
		writeError(w, http.StatusBadRequest, "missing mcpUrl")
		return
	}

	var token string
	if req.UseUserJWT && strings.TrimSpace(req.UserJWT) != "" {
		token = strings.TrimSpace(req.UserJWT)
	} else {
		token = strings.TrimSpace(req.OBOJWT)
	}

	sessionID, statusCode, err := initializeMCP(strings.TrimRight(req.MCPURL, "/"), token)
	if err != nil {
		if statusCode == http.StatusUnauthorized {
			if req.UseUserJWT {
				writeError(w, http.StatusUnauthorized, "MCP returned 401 Unauthorized (User JWT not accepted; gateway expects OBO token). Run step 2 to exchange for an OBO JWT.")
			} else {
				writeError(w, http.StatusUnauthorized, "MCP returned 401 Unauthorized (no or invalid OBO token). Run steps 1 and 2 to get an OBO JWT.")
			}
			return
		}
		writeError(w, http.StatusBadGateway, "mcp initialize failed: "+err.Error())
		return
	}

	if err := mcpNotificationInitialized(strings.TrimRight(req.MCPURL, "/"), token, sessionID); err != nil {
		writeError(w, http.StatusBadGateway, "mcp notifications/initialized failed: "+err.Error())
		return
	}

	toolsPayload, err := mcpToolsList(strings.TrimRight(req.MCPURL, "/"), token, sessionID)
	if err != nil {
		writeError(w, http.StatusBadGateway, "mcp tools/list failed: "+err.Error())
		return
	}

	toolNames := collectToolNames(toolsPayload)
	writeJSON(w, map[string]any{
		"sessionId": sessionID,
		"tools":     toolNames,
		"raw":       toolsPayload,
	})
}

func postForm(endpoint string, form url.Values, authHeader string) ([]byte, int, error) {
	client := &http.Client{Timeout: 20 * time.Second}
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return body, resp.StatusCode, err
}

func initializeMCP(mcpURL, oboJWT string) (string, int, error) {
	client := &http.Client{Timeout: 20 * time.Second}
	body := `{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"obo-observer","version":"1.0"}},"id":1}`
	req, err := http.NewRequest(http.MethodPost, mcpURL, strings.NewReader(body))
	if err != nil {
		return "", 0, err
	}
	if oboJWT != "" {
		req.Header.Set("Authorization", "Bearer "+oboJWT)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", resp.StatusCode, errors.New("status " + http.StatusText(resp.StatusCode))
	}
	sessionID := strings.TrimSpace(resp.Header.Get("Mcp-Session-Id"))
	if sessionID == "" {
		return "", 0, errors.New("Mcp-Session-Id header missing")
	}
	return sessionID, 0, nil
}

func mcpNotificationInitialized(mcpURL, oboJWT, sessionID string) error {
	client := &http.Client{Timeout: 20 * time.Second}
	body := `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	req, err := http.NewRequest(http.MethodPost, mcpURL, strings.NewReader(body))
	if err != nil {
		return err
	}
	if oboJWT != "" {
		req.Header.Set("Authorization", "Bearer "+oboJWT)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Session-Id", sessionID)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return errors.New("status " + http.StatusText(resp.StatusCode))
	}
	return nil
}

func mcpToolsList(mcpURL, oboJWT, sessionID string) (map[string]any, error) {
	client := &http.Client{Timeout: 20 * time.Second}
	body := `{"jsonrpc":"2.0","method":"tools/list","id":2}`
	req, err := http.NewRequest(http.MethodPost, mcpURL, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	if oboJWT != "" {
		req.Header.Set("Authorization", "Bearer "+oboJWT)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Session-Id", sessionID)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, errors.New("status " + http.StatusText(resp.StatusCode))
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	text := strings.TrimSpace(string(data))
	if strings.HasPrefix(text, "data:") {
		lines := strings.Split(text, "\n")
		for _, line := range lines {
			if strings.HasPrefix(strings.TrimSpace(line), "data:") {
				text = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "data:"))
				break
			}
		}
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(text), &payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func collectToolNames(payload map[string]any) []string {
	result := []string{}
	resultNode, ok := payload["result"].(map[string]any)
	if !ok {
		return result
	}
	rawTools, ok := resultNode["tools"].([]any)
	if !ok {
		return result
	}
	for _, raw := range rawTools {
		tool, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		name, _ := tool["name"].(string)
		if strings.TrimSpace(name) != "" {
			result = append(result, name)
		}
	}
	return result
}

func decodeRequest(r *http.Request, out any) error {
	if r.Method != http.MethodPost {
		return errors.New("method must be POST")
	}
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(out)
}

func writeError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
