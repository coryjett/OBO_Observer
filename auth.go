package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

const (
	sessionCookieName = "obo_session"
	sessionMaxAge     = 24 * time.Hour
)

type sessionData struct {
	AccessToken string    `json:"access_token"`
	Expiry      time.Time `json:"expiry,omitempty"`
}

func getOAuth2Config() (*oauth2.Config, string, bool) {
	baseURL := strings.TrimRight(strings.TrimSpace(os.Getenv("BASE_URL")), "/")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}
	keycloakURL := strings.TrimRight(strings.TrimSpace(os.Getenv("KEYCLOAK_URL")), "/")
	realm := strings.TrimSpace(os.Getenv("KEYCLOAK_REALM"))
	if realm == "" {
		realm = "oidc-realm"
	}
	clientID := strings.TrimSpace(os.Getenv("OAUTH2_CLIENT_ID"))
	if clientID == "" {
		clientID = strings.TrimSpace(os.Getenv("KEYCLOAK_CLIENT_ID"))
	}
	if clientID == "" {
		clientID = "obo-observer"
	}
	clientSecret := strings.TrimSpace(os.Getenv("OAUTH2_CLIENT_SECRET"))
	if clientSecret == "" {
		clientSecret = strings.TrimSpace(os.Getenv("KEYCLOAK_CLIENT_SECRET"))
	}
	if keycloakURL == "" || clientID == "" || clientSecret == "" {
		return nil, "", false
	}
	// Server must reach Keycloak for token exchange; when app is in-cluster and user uses port-forward,
	// KEYCLOAK_URL is browser-reachable (e.g. localhost:8081). Use KEYCLOAK_INTERNAL_URL for token endpoint.
	tokenBase := strings.TrimRight(strings.TrimSpace(os.Getenv("KEYCLOAK_INTERNAL_URL")), "/")
	if tokenBase == "" {
		tokenBase = keycloakURL
	}
	config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  baseURL + "/auth/callback",
		Scopes:       []string{"openid", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:   keycloakURL + "/realms/" + realm + "/protocol/openid-connect/auth",
			TokenURL:  tokenBase + "/realms/" + realm + "/protocol/openid-connect/token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}
	return config, baseURL, true
}

func getSessionSecret() []byte {
	secret := os.Getenv("SESSION_SECRET")
	if secret == "" {
		secret = "obo-observer-default-session-secret-change-in-production"
	}
	// Use first 32 bytes for AES-256
	b := []byte(secret)
	if len(b) > 32 {
		return b[:32]
	}
	padded := make([]byte, 32)
	copy(padded, b)
	return padded
}

func encryptSession(data *sessionData) (string, error) {
	plain, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	key := getSessionSecret()
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, plain, nil)
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func decryptSession(cookieVal string) (*sessionData, error) {
	if cookieVal == "" {
		return nil, errors.New("empty session")
	}
	ciphertext, err := base64.URLEncoding.DecodeString(cookieVal)
	if err != nil {
		return nil, err
	}
	key := getSessionSecret()
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	var data sessionData
	if err := json.Unmarshal(plain, &data); err != nil {
		return nil, err
	}
	return &data, nil
}

func setSessionCookie(w http.ResponseWriter, tok *oauth2.Token) {
	data := &sessionData{
		AccessToken: tok.AccessToken,
		Expiry:      tok.Expiry,
	}
	val, err := encryptSession(data)
	if err != nil {
		http.Error(w, "session encode error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    val,
		Path:     "/",
		MaxAge:   int(sessionMaxAge.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   strings.HasPrefix(os.Getenv("BASE_URL"), "https://"),
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func getSessionToken(r *http.Request) string {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie == nil || cookie.Value == "" {
		return ""
	}
	data, err := decryptSession(cookie.Value)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(data.AccessToken)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	config, _, ok := getOAuth2Config()
	if !ok {
		http.Error(w, "OAuth2 not configured (set KEYCLOAK_URL, OAUTH2_CLIENT_ID, OAUTH2_CLIENT_SECRET)", http.StatusServiceUnavailable)
		return
	}
	state := "obo-" + randomString(16)
	// Store state in cookie for verification on callback (optional; we could use a server-side store)
	http.SetCookie(w, &http.Cookie{
		Name:     "obo_oauth_state",
		Value:    state,
		Path:     "/",
		MaxAge:   600,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	url := config.AuthCodeURL(state, oauth2.AccessTypeOnline)
	http.Redirect(w, r, url, http.StatusFound)
}

func handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	config, baseURL, ok := getOAuth2Config()
	if !ok {
		http.Error(w, "OAuth2 not configured", http.StatusServiceUnavailable)
		return
	}
	stateCookie, _ := r.Cookie("obo_oauth_state")
	if stateCookie == nil || stateCookie.Value == "" {
		http.Redirect(w, r, baseURL+"/login", http.StatusFound)
		return
	}
	state := r.URL.Query().Get("state")
	if state == "" || state != stateCookie.Value {
		http.Redirect(w, r, baseURL+"/login", http.StatusFound)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Redirect(w, r, baseURL+"/login", http.StatusFound)
		return
	}
	tok, err := config.Exchange(r.Context(), code)
	if err != nil {
		http.Redirect(w, r, baseURL+"/login", http.StatusFound)
		return
	}
	setSessionCookie(w, tok)
	// Clear state cookie
	http.SetCookie(w, &http.Cookie{Name: "obo_oauth_state", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, baseURL+"/", http.StatusFound)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	config, baseURL, ok := getOAuth2Config()
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}
	clearSessionCookie(w)
	// Redirect to Keycloak logout so the IdP session is cleared; then when user clicks
	// Log in they are sent to Keycloak and see the login form instead of being auto signed in.
	if ok && config != nil {
		keycloakURL := strings.TrimRight(strings.TrimSpace(os.Getenv("KEYCLOAK_URL")), "/")
		realm := strings.TrimSpace(os.Getenv("KEYCLOAK_REALM"))
		if realm == "" {
			realm = "oidc-realm"
		}
		if keycloakURL != "" && config.ClientID != "" {
			logoutURL := keycloakURL + "/realms/" + realm + "/protocol/openid-connect/logout"
			params := url.Values{}
			params.Set("post_logout_redirect_uri", baseURL+"/")
			params.Set("client_id", config.ClientID)
			http.Redirect(w, r, logoutURL+"?"+params.Encode(), http.StatusFound)
			return
		}
	}
	http.Redirect(w, r, baseURL+"/", http.StatusFound)
}

func handleMe(w http.ResponseWriter, r *http.Request) {
	_, _, authEnabled := getOAuth2Config()
	if !authEnabled {
		writeJSON(w, map[string]any{"username": nil})
		return
	}
	token := getSessionToken(r)
	if token == "" {
		w.WriteHeader(http.StatusUnauthorized)
		writeJSON(w, map[string]string{"error": "not authenticated"})
		return
	}
	// Decode JWT payload for preferred_username / sub (no verify for display)
	payload := decodeJWTPayloadInsecure(token)
	if payload == nil {
		writeJSON(w, map[string]any{"username": "unknown", "sub": ""})
		return
	}
	username, _ := payload["preferred_username"].(string)
	if username == "" {
		username, _ = payload["sub"].(string)
	}
	if username == "" {
		username = "unknown"
	}
	sub, _ := payload["sub"].(string)
	writeJSON(w, map[string]any{"username": username, "sub": sub, "accessToken": token})
}

func decodeJWTPayloadInsecure(token string) map[string]any {
	parts := strings.SplitN(strings.TrimSpace(token), ".", 3)
	if len(parts) != 3 {
		return nil
	}
	// Base64url decode middle part
	b := parts[1]
	b = strings.ReplaceAll(b, "-", "+")
	b = strings.ReplaceAll(b, "_", "/")
	switch len(b) % 4 {
	case 2:
		b += "=="
	case 3:
		b += "="
	}
	decoded, err := base64.StdEncoding.DecodeString(b)
	if err != nil {
		return nil
	}
	var out map[string]any
	if json.Unmarshal(decoded, &out) != nil {
		return nil
	}
	return out
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = letters[int(b[i])%len(letters)]
	}
	return string(b)
}

func requireAuth(next http.Handler) http.Handler {
	return next
}

