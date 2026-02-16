// Agent chat: OpenAI Chat Completions API with MCP tools.
package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type agentChatRequest struct {
	OpenAIAPIKey string `json:"openaiApiKey"`
	Message      string `json:"message"`
	MCPURL       string `json:"mcpUrl"`
	OBOToken     string `json:"oboToken"`
}

// Completions API types (POST /v1/chat/completions).
type completionTool struct {
	Type     string         `json:"type"`
	Function completionFunc `json:"function"`
}

type completionFunc struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Parameters  map[string]any `json:"parameters,omitempty"`
}

type completionRequest struct {
	Model      string           `json:"model"`
	Messages   []map[string]any `json:"messages"`
	Tools      []completionTool `json:"tools,omitempty"`
	ToolChoice string           `json:"tool_choice,omitempty"`
}

type completionToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type completionMessage struct {
	Role      string               `json:"role"`
	Content   *string              `json:"content"`
	ToolCalls []completionToolCall `json:"tool_calls,omitempty"`
}

type completionChoice struct {
	Message completionMessage `json:"message"`
}

type completionResponse struct {
	Choices []completionChoice `json:"choices"`
	Error   *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func handleAgentChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method must be POST")
		return
	}
	var req agentChatRequest
	if err := decodeRequest(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	apiKey := strings.TrimSpace(req.OpenAIAPIKey)
	if apiKey == "" {
		writeError(w, http.StatusBadRequest, "openaiApiKey is required")
		return
	}
	message := strings.TrimSpace(req.Message)
	if message == "" {
		writeError(w, http.StatusBadRequest, "message is required")
		return
	}
	mcpURL := strings.TrimRight(strings.TrimSpace(req.MCPURL), "/")
	if mcpURL == "" {
		writeError(w, http.StatusBadRequest, "mcpUrl is required")
		return
	}
	oboToken := strings.TrimSpace(req.OBOToken)

	openAIBase := strings.TrimRight(strings.TrimSpace(os.Getenv("OPENAI_BASE_URL")), "/")
	if openAIBase == "" {
		openAIBase = "https://api.openai.com"
	}

	client := &http.Client{Timeout: 30 * time.Second}

	var tools []completionTool
	var sessionID string
	if oboToken != "" {
		// 1) MCP session + tools when OBO token is present
		var statusCode int
		var err error
		sessionID, statusCode, err = initializeMCP(mcpURL, oboToken)
		if err != nil {
			if statusCode == http.StatusForbidden {
				writeErrorBlockedByPolicy(w, "MCP request blocked by policy (403).")
				return
			}
			if statusCode == http.StatusUnauthorized {
				writeError(w, http.StatusUnauthorized, "MCP returned 401 (invalid or missing OBO token).")
				return
			}
			writeError(w, http.StatusBadGateway, "mcp initialize: "+err.Error())
			return
		}
		if err := mcpNotificationInitialized(mcpURL, oboToken, sessionID); err != nil {
			writeError(w, http.StatusBadGateway, "mcp notifications/initialized: "+err.Error())
			return
		}
		toolsPayload, statusCode, err := mcpToolsList(mcpURL, oboToken, sessionID)
		if err != nil {
			if statusCode == http.StatusForbidden {
				writeErrorBlockedByPolicy(w, "MCP tools/list blocked (403).")
				return
			}
			writeError(w, http.StatusBadGateway, "mcp tools/list: "+err.Error())
			return
		}
		tools = convertMcpToCompletionsTools(toolsPayload)
	}

	// 3) Chat Completions API loop
	completionsURL := openAIBase + "/v1/chat/completions"
	model := "gpt-4o"
	messages := []map[string]any{
		{"role": "user", "content": message},
	}
	var finalText string
	const maxRounds = 50
	for i := 0; i < maxRounds; i++ {
		reqBody := completionRequest{
			Model:      model,
			Messages:   messages,
			Tools:      tools,
			ToolChoice: "auto",
		}
		bodyBytes, _ := json.Marshal(reqBody)
		httpReq, err := http.NewRequest(http.MethodPost, completionsURL, bytes.NewReader(bodyBytes))
		if err != nil {
			writeError(w, http.StatusInternalServerError, "build request: "+err.Error())
			return
		}
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
		resp, err := client.Do(httpReq)
		if err != nil {
			writeError(w, http.StatusBadGateway, "OpenAI request failed: "+err.Error())
			return
		}
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var oaiResp completionResponse
		_ = json.Unmarshal(respBody, &oaiResp)
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			if oaiResp.Error != nil {
				writeError(w, http.StatusBadRequest, "OpenAI: "+oaiResp.Error.Message)
				return
			}
			msg := "OpenAI returned " + http.StatusText(resp.StatusCode)
			if resp.StatusCode == http.StatusNotFound {
				msg += " — use OPENAI_BASE_URL with /openai prefix and apply k8s/agentgateway-openai-route.yaml"
			}
			if resp.StatusCode == http.StatusServiceUnavailable {
				msg += " — gateway or upstream may be overloaded or unreachable; check gateway logs or try again"
				if len(respBody) > 0 && len(respBody) < 500 {
					msg += "; body: " + strings.TrimSpace(string(respBody))
				} else if len(respBody) >= 500 {
					msg += "; body (truncated): " + strings.TrimSpace(string(respBody[:500]))
				}
			}
			writeError(w, http.StatusBadGateway, msg)
			return
		}
		if oaiResp.Error != nil {
			writeError(w, http.StatusBadRequest, "OpenAI: "+oaiResp.Error.Message)
			return
		}
		if len(oaiResp.Choices) == 0 {
			writeJSON(w, map[string]any{"text": finalText})
			return
		}
		msg := oaiResp.Choices[0].Message
		if msg.Content != nil && *msg.Content != "" {
			finalText = *msg.Content
		}
		if len(msg.ToolCalls) == 0 {
			writeJSON(w, map[string]any{"text": finalText})
			return
		}
		// Append assistant message (with tool_calls) to history
		assistantMsg := map[string]any{
			"role":       "assistant",
			"content":    msg.Content,
			"tool_calls": msg.ToolCalls,
		}
		messages = append(messages, assistantMsg)
		for _, tc := range msg.ToolCalls {
			var args map[string]any
			if tc.Function.Arguments != "" {
				_ = json.Unmarshal([]byte(tc.Function.Arguments), &args)
			}
			result, statusCode, err := mcpToolsCall(mcpURL, oboToken, sessionID, tc.Function.Name, args)
			if err != nil {
				result = "error: " + err.Error()
			}
			if statusCode == http.StatusForbidden {
				writeErrorBlockedByPolicy(w, "MCP tool call blocked (403).")
				return
			}
			messages = append(messages, map[string]any{
				"role":         "tool",
				"content":      result,
				"tool_call_id": tc.ID,
			})
		}
	}
	// Hit round limit
	if finalText != "" {
		writeJSON(w, map[string]any{"text": finalText + "\n\n(Stopped after maximum tool-call rounds.)"})
		return
	}
	writeError(w, http.StatusBadGateway, "too many tool-call rounds")
}

// schemaOrBoolKeys: values for these must be schema object or boolean, not the string "object".
var schemaOrBoolKeys = map[string]bool{
	"additionalProperties": true, "additional_properties": true,
	"items": true, "contains": true, "propertyNames": true,
	"not": true, "contentSchema": true,
}

// isObjectOrBooleanString returns true if s is "object" or "boolean" (case-insensitive).
func isObjectOrBooleanString(s string) bool {
	return strings.EqualFold(s, "object") || strings.EqualFold(s, "boolean")
}

// normalizeToolSchema ensures object schemas have "properties" and fixes string "object" where object/boolean required.
func normalizeToolSchema(input map[string]any) map[string]any {
	if input == nil {
		return map[string]any{"type": "object", "properties": map[string]any{}}
	}
	out := make(map[string]any)
	for k, v := range input {
		out[k] = normalizeSchemaValue(k, v)
	}
	if _, hasType := out["type"]; !hasType {
		out["type"] = "object"
	}
	if out["type"] == "object" {
		if _, hasProps := out["properties"]; !hasProps {
			out["properties"] = map[string]any{}
		}
	}
	// Post-pass: replace any remaining string "object"/"boolean" (except under "type" or "enum").
	return deepFixObjectBooleanStrings(out).(map[string]any)
}

// deepFixObjectBooleanStrings walks v and replaces string "object"/"boolean" with a schema when key is not "type"/"enum".
func deepFixObjectBooleanStrings(v any) any {
	return deepFixObjectBooleanStringsWithKey("", v)
}

func deepFixObjectBooleanStringsWithKey(key string, v any) any {
	if key != "type" && key != "enum" && key != "required" {
		if s, ok := v.(string); ok && isObjectOrBooleanString(s) {
			return map[string]any{"type": "object", "properties": map[string]any{}}
		}
	}
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any)
		for k, val := range x {
			out[k] = deepFixObjectBooleanStringsWithKey(k, val)
		}
		return out
	case []any:
		arr := make([]any, len(x))
		for i, item := range x {
			arr[i] = deepFixObjectBooleanStringsWithKey(key, item)
		}
		return arr
	default:
		return v
	}
}

func normalizeSchemaValue(key string, v any) any {
	if schemaOrBoolKeys[key] {
		if s, ok := v.(string); ok && isObjectOrBooleanString(s) {
			return map[string]any{"type": "object", "properties": map[string]any{}}
		}
	}
	if key != "type" && key != "enum" {
		if s, ok := v.(string); ok && isObjectOrBooleanString(s) {
			return map[string]any{"type": "object", "properties": map[string]any{}}
		}
	}
	switch x := v.(type) {
	case map[string]any:
		return normalizeToolSchema(x)
	case []any:
		arr := make([]any, len(x))
		for i, item := range x {
			arr[i] = normalizeSchemaValue("", item)
		}
		return arr
	default:
		return v
	}
}

// minimalSafeParameters returns a schema with only type, properties, and required. Never sends string "object"/"boolean" as a value.
func minimalSafeParameters(schema map[string]any) map[string]any {
	emptyObj := map[string]any{"type": "object", "properties": map[string]any{}}
	if schema == nil {
		return emptyObj
	}
	out := make(map[string]any)
	if t, ok := schema["type"]; ok {
		if _, isStr := t.(string); isStr {
			out["type"] = t
		} else {
			out["type"] = "object"
		}
	} else {
		out["type"] = "object"
	}
	if out["type"] == "object" {
		props, _ := schema["properties"].(map[string]any)
		if props == nil {
			out["properties"] = map[string]any{}
		} else {
			cleanProps := make(map[string]any)
			for k, v := range props {
				if sub, ok := v.(map[string]any); ok {
					cleanProps[k] = minimalSafeParameters(sub)
				} else if s, ok := v.(string); ok && isObjectOrBooleanString(s) {
					cleanProps[k] = emptyObj
				} else {
					cleanProps[k] = v
				}
			}
			out["properties"] = cleanProps
		}
	}
	if req, ok := schema["required"].([]any); ok && len(req) > 0 {
		out["required"] = req
	}
	return out
}

func convertMcpToCompletionsTools(payload map[string]any) []completionTool {
	var tools []completionTool
	resultNode, ok := payload["result"].(map[string]any)
	if !ok {
		return tools
	}
	rawTools, ok := resultNode["tools"].([]any)
	if !ok {
		return tools
	}
	emptyParams := map[string]any{"type": "object", "properties": map[string]any{}}
	for _, raw := range rawTools {
		tool, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		name, _ := tool["name"].(string)
		desc, _ := tool["description"].(string)
		if name == "" {
			continue
		}
		tools = append(tools, completionTool{
			Type: "function",
			Function: completionFunc{
				Name:        name,
				Description: desc,
				Parameters:  emptyParams,
			},
		})
	}
	return tools
}
