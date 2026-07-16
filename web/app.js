// OBO Observer streaming-ui (contexts added one-by-one with delay)
const POLL_MS = 1500;
const POLL_FETCH_TIMEOUT_MS = 40000;
const INFO_FETCH_TIMEOUT_MS = 15000;
const MAX_CONTEXTS = 120;
/** Max chars to pretty-print per body; larger bodies are truncated to avoid freezing the UI on first render. */
const BODY_FORMAT_MAX_CHARS = 8000;
const STORAGE_KEY_IMPERSONATION_OBO = "obo-observer-impersonation-obo-jwt";

const state = {
  events: [],
  selectedId: null,
  healthy: false,
  logMode: null,
  user: null, // { username, sub } when logged in via Keycloak
  workflow: {
    userJwt: "",
    oboJwt: "",
    lastExchangeMode: "", // "impersonation" | "delegation" | "" — set when step 2 completes
    /** OBO JWT from the last impersonation exchange; used only for "Impersonation JWT" badge. Persisted so refresh keeps labels. */
    impersonationOboJwt: "",
    blockedByPolicy: false,
    stsUrl: "",
    mcpUrl: "",
    actorToken: "",
  },
  agentChat: { messages: [], inputHistory: [], inputHistoryIndex: -1, inputDraft: "" },
  openaiApiKeyConfigured: false,
};

function loadPersistedImpersonationOboJwt() {
  try {
    const s = typeof localStorage !== "undefined" && localStorage.getItem(STORAGE_KEY_IMPERSONATION_OBO);
    if (s && String(s).trim()) state.workflow.impersonationOboJwt = String(s).trim();
  } catch (_) {}
}
function savePersistedImpersonationOboJwt() {
  try {
    const v = (state.workflow.impersonationOboJwt || "").trim();
    if (v) localStorage.setItem(STORAGE_KEY_IMPERSONATION_OBO, v);
    else localStorage.removeItem(STORAGE_KEY_IMPERSONATION_OBO);
  } catch (_) {}
}

const refs = {
  status: document.getElementById("status"),
  userDisplay: document.getElementById("user-display"),
  loginLink: document.getElementById("login-link"),
  logoutLink: document.getElementById("logout-link"),
  contextList: document.getElementById("context-list"),
  contextsClear: document.getElementById("contexts-clear"),
  headersRequestDisplay: document.getElementById("headers-request"),
  headersResponseDisplay: document.getElementById("headers-response"),
  bodyRequestDisplay: document.getElementById("body-request"),
  bodyResponseDisplay: document.getElementById("body-response"),
  traceSvg: document.getElementById("trace-svg"),
  traceGraphWrap: document.getElementById("trace-graph-wrap"),
  eventMeta: document.getElementById("event-meta"),
  wfStatus: document.getElementById("wf-status"),
  wfUserJwt: document.getElementById("wf-user-jwt"),
  wfOboJwt: document.getElementById("wf-obo-jwt"),
  wfSessionTokenCheck: document.getElementById("wf-session-token-check"),
  wfOboTokenCheck: document.getElementById("wf-obo-token-check"),
  wfTools: document.getElementById("wf-tools"),
  agentgatewayLogs: document.getElementById("agentgateway-logs"),
  wfStep2: document.getElementById("wf-step-2"),
  wfStep3: document.getElementById("wf-step-3"),
  wfMcpTokenType: document.getElementById("wf-mcp-token-type"),
  wfClearJwts: document.getElementById("wf-clear-jwts"),
  wfTokensToggle: document.getElementById("wf-tokens-toggle"),
  wfTokensWrapper: document.getElementById("wf-tokens-wrapper"),
  wfExchangeMode: document.getElementById("wf-exchange-mode"),
  agentOpenaiToken: document.getElementById("agent-openai-token"),
  agentChatTokenRow: document.getElementById("agent-chat-token-row"),
  agentChatServerKeyNote: document.getElementById("agent-chat-server-key-note"),
  agentChatMessages: document.getElementById("agent-chat-messages"),
  agentChatInput: document.getElementById("agent-chat-input"),
  agentChatSend: document.getElementById("agent-chat-send"),
  agentChatError: document.getElementById("agent-chat-error"),
  agentChatWidget: document.getElementById("agent-chat-widget"),
  agentChatBubble: document.getElementById("agent-chat-bubble"),
  agentChatPanel: document.getElementById("agent-chat-panel"),
  agentChatClose: document.getElementById("agent-chat-close"),
  agentChatResizeHandle: document.getElementById("agent-chat-resize-handle"),
};

/** Check session: set state.user and session token in Session Token from /api/me (no redirect). */
async function checkAuth() {
  try {
    const res = await fetch("/api/me", { cache: "no-store", credentials: "include" });
    if (res.ok) {
      const data = await res.json();
      state.user = data.username != null ? { username: data.username, sub: data.sub || "" } : null;
      if (state.user && data.accessToken) {
        state.workflow.userJwt = data.accessToken;
        if (refs.wfUserJwt) refs.wfUserJwt.textContent = formatJwtDisplay(state.workflow.userJwt, "(empty session token)");
      }
    } else {
      state.user = null;
    }
  } catch (_) {
    state.user = null;
  }
  updateTokenCheckmarks();
  renderUser();
}

function renderUser() {
  if (!refs.userDisplay || !refs.logoutLink) return;
  if (state.user && state.user.username) {
    refs.userDisplay.textContent = state.user.username;
    refs.userDisplay.setAttribute("aria-hidden", "false");
    refs.logoutLink.style.display = "";
    if (refs.loginLink) refs.loginLink.style.display = "none";
  } else {
    refs.userDisplay.textContent = "";
    refs.userDisplay.setAttribute("aria-hidden", "true");
    refs.logoutLink.style.display = "none";
    if (refs.loginLink) refs.loginLink.style.display = "";
  }
}

function updateTokenCheckmarks() {
  if (refs.wfSessionTokenCheck) {
    const has = !!(state.workflow.userJwt && state.workflow.userJwt.trim());
    refs.wfSessionTokenCheck.textContent = has ? "\u2713" : "";
    refs.wfSessionTokenCheck.setAttribute("aria-hidden", has ? "false" : "true");
  }
  if (refs.wfOboTokenCheck) {
    const has = !!(state.workflow.oboJwt && state.workflow.oboJwt.trim());
    refs.wfOboTokenCheck.textContent = has ? "\u2713" : "";
    refs.wfOboTokenCheck.setAttribute("aria-hidden", has ? "false" : "true");
  }
}

function setStatusFromHealthy() {
  if (!refs.status) return;
  refs.status.className = `status ${state.healthy ? "status-ok" : "status-warn"}`;
  const modeLabel = state.logMode === "kubernetes" ? " (Agentgateway)" : state.logMode === "file" ? " (file)" : state.logMode === "sample" ? " (Sample)" : "";
  refs.status.textContent = state.healthy ? "Live" + modeLabel : refs.status.textContent || "Disconnected";
}

async function fetchLogMode() {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), INFO_FETCH_TIMEOUT_MS);
    const res = await fetch("/api/info", { cache: "no-store", signal: controller.signal });
    clearTimeout(timeoutId);
    if (res.ok) {
      const data = await res.json();
      state.logMode = data.log_mode || null;
      if (data.sts_url != null) state.workflow.stsUrl = data.sts_url;
      if (data.mcp_url != null) state.workflow.mcpUrl = data.mcp_url;
      if (data.actor_token != null) state.workflow.actorToken = data.actor_token;
      state.openaiApiKeyConfigured = !!data.openai_api_key_configured;
      if (refs.agentChatTokenRow) refs.agentChatTokenRow.style.display = state.openaiApiKeyConfigured ? "none" : "block";
      if (refs.agentChatServerKeyNote) refs.agentChatServerKeyNote.style.display = state.openaiApiKeyConfigured ? "block" : "none";
      state.healthy = true;
      setStatusFromHealthy();
    } else if (refs.status && refs.status.textContent === "Connecting...") {
      state.healthy = false;
      refs.status.className = "status status-warn";
      refs.status.textContent = "Disconnected (backend error)";
    }
  } catch (_) {
    state.logMode = null;
    if (!state.healthy && refs.status) {
      state.healthy = false;
      refs.status.className = "status status-warn";
      refs.status.textContent = "Disconnected (backend unreachable)";
    }
  }
}

let renderPending = false;

async function poll() {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), POLL_FETCH_TIMEOUT_MS);
    const response = await fetch("/api/events?limit=200", { cache: "no-store", signal: controller.signal });
    clearTimeout(timeoutId);
    if (!response.ok) {
      throw new Error(`status ${response.status}`);
    }

    const text = await response.text();
    await new Promise((resolve) => {
      scheduleIdle(() => {
        try {
          const payload = JSON.parse(text);
          const newEvents = (payload.events || []).slice(0, MAX_CONTEXTS);
          const oldLen = state.events.length;
          const oldFirstId = state.events[0] && state.events[0].id;
          state.events = newEvents;
          state.healthy = true;
          if (state.logMode === null) {
            fetchLogMode();
          }
          const eventsChanged = newEvents.length !== oldLen || (newEvents[0] && newEvents[0].id !== oldFirstId);
          if (eventsChanged) {
            if (renderInProgress) {
              renderPending = true;
            } else {
              requestAnimationFrame(() => render());
            }
          }
        } catch (_) {
          state.healthy = false;
          state.logMode = null;
          if (refs.status) {
            refs.status.className = "status status-warn";
            refs.status.textContent = "Disconnected (parse error)";
          }
        }
        resolve();
      }, { timeout: 80 });
    });
  } catch (error) {
    state.healthy = false;
    state.logMode = null;
    refs.status.className = "status status-warn";
    const msg = error.name === "AbortError" ? "request timeout" : error.message;
    refs.status.textContent = `Disconnected (${msg})`;
  }
}

const LOG_STREAM_MAX_LINES = 500;

function startLogStream() {
  if (!refs.agentgatewayLogs) return;
  const pre = refs.agentgatewayLogs;
  let lineCount = 0;
  function appendLine(line) {
    const trimmed = String(line).trimEnd();
    if (!trimmed) return;
    if (lineCount === 0) pre.textContent = trimmed;
    else pre.textContent += "\n" + trimmed;
    lineCount++;
    if (lineCount > LOG_STREAM_MAX_LINES) {
      const lines = pre.textContent.split("\n");
      pre.textContent = lines.slice(-LOG_STREAM_MAX_LINES).join("\n");
      lineCount = LOG_STREAM_MAX_LINES;
    }
    pre.scrollTop = pre.scrollHeight;
  }
  const url = new URL("/api/logs/stream", window.location.origin).href;
  const es = new EventSource(url);
  es.onopen = () => {
    pre.textContent = "";
    lineCount = 0;
  };
  es.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      if (data && typeof data.line === "string") appendLine(data.line);
    } catch (_) {}
  };
  es.onerror = () => {
    if (es.readyState === EventSource.CLOSED) return;
    pre.textContent = (pre.textContent || "(connecting)") + "\n(log stream disconnected; reconnecting…)";
    pre.scrollTop = pre.scrollHeight;
  };
}

function scheduleIdle(cb, opts) {
  if (typeof requestIdleCallback !== "undefined") {
    return requestIdleCallback(cb, opts || { timeout: 100 });
  }
  return setTimeout(cb, 0);
}

let renderInProgress = false;

function render() {
  if (renderInProgress) return;
  renderInProgress = true;

  refs.status.className = `status ${state.healthy ? "status-ok" : "status-warn"}`;
  const modeLabel = state.logMode === "kubernetes" ? " (Agentgateway)" : state.logMode === "file" ? " (file)" : state.logMode === "sample" ? " (Sample)" : "";
  refs.status.textContent = state.healthy ? "Live" + modeLabel : "Disconnected";

  if (!state.selectedId && state.events.length > 0) {
    state.selectedId = state.events[0].id;
  }

  const selected = state.events.find((event) => event.id === state.selectedId) || state.events[0] || null;
  if (selected) {
    state.selectedId = selected.id;
  }

  function done() {
    renderInProgress = false;
    if (renderPending) {
      renderPending = false;
      render();
    }
  }

  requestAnimationFrame(() => {
    renderContexts(selected);
    requestAnimationFrame(() => {
      renderTokens(selected);
      requestAnimationFrame(() => {
        renderTrace(selected);
        done();
      });
    });
  });
}

function isHttpEvent(event) {
  const ctx = event.context && String(event.context).trim();
  if (ctx) return true; // any path/context
  const h = event.headers;
  if (h && typeof h === "object") {
    if (h["http.path"] || h["request_path"] || h["requestpath"] || h["uri"] || h["path"]) return true;
  }
  // show request-like events that have client or backend (e.g. from laptop to gateway)
  if ((event.client || event.backend || event.route) && (event.headers && Object.keys(event.headers).length > 0)) return true;
  return false;
}

function buildContextListItem(event, selected) {
  const li = document.createElement("li");
  if (selected && selected.id === event.id) {
    li.className = "selected";
  }
  const button = document.createElement("button");
  button.type = "button";
  button.addEventListener("click", () => {
    state.selectedId = event.id;
    render();
  });
  const inboundToken = event.inboundJwt && String(event.inboundJwt).trim();
  const usedObo = inboundToken && isOboToken(inboundToken);
  const usedUserJwt = inboundToken && !usedObo;
  const usedImpersonation = usedUserJwt && isImpersonationContext(event);
  const openAIContext = isOpenAIContext(event);
  const badge = usedObo
    ? '<span class="obo-jwt-badge">OBO Token</span>'
    : openAIContext && inboundToken
      ? '<span class="openai-api-badge">OpenAI API key</span>'
      : usedImpersonation
        ? '<span class="impersonation-jwt-badge">Impersonation JWT</span>'
        : usedUserJwt
          ? '<span class="jwt-badge">Session Token</span>'
          : '';
  let timeStr = "";
  if (event.timestamp) {
    const d = new Date(event.timestamp);
    if (!Number.isNaN(d.getTime())) {
      timeStr = d.toLocaleTimeString();
    }
  }
  button.innerHTML = `
    <div class="path-row">
      <span class="path">${escapeHtml(event.context || "(context missing)")}</span>
    </div>
    <div class="small">${escapeHtml(event.resolvedClient || event.client || "unknown source")} → ${escapeHtml(event.resolvedBackendService || formatBackendDisplay(event.backendTarget) || event.route || "unknown destination")}</div>
    <div class="context-footer">
      <span class="small context-time">${escapeHtml(timeStr || "—")}</span>
      ${badge}
    </div>
  `;
  li.appendChild(button);
  return li;
}

/** Fingerprint of event IDs from the last full context-list build. */
let _lastContextIds = "";

function renderContexts(selected) {
  const httpEvents = state.events.filter(isHttpEvent);
  const ids = httpEvents.map(e => e.id).join(",");
  const selectedId = selected ? selected.id : null;

  if (ids === _lastContextIds) {
    // Events unchanged — just update the selection highlight.
    const items = refs.contextList.children;
    for (let i = 0; i < items.length; i++) {
      items[i].className = (i < httpEvents.length && httpEvents[i].id === selectedId) ? "selected" : "";
    }
    return;
  }

  // Full rebuild needed.
  _lastContextIds = ids;
  const frag = document.createDocumentFragment();
  for (const event of httpEvents) {
    frag.appendChild(buildContextListItem(event, selected));
  }
  refs.contextList.innerHTML = "";
  refs.contextList.appendChild(frag);
}

/** Get first header value by key (checks multiple possible keys, case-insensitive). */
function getHeaderValue(headers, keys) {
  if (!headers || typeof headers !== "object") return "";
  const lower = {};
  for (const [k, v] of Object.entries(headers)) lower[k.toLowerCase()] = v;
  for (const key of keys) {
    const v = lower[key.toLowerCase()];
    if (v != null && String(v).trim() !== "") return String(v).trim();
  }
  return "";
}

/** Try to decode base64 to UTF-8 string. Returns decoded string or null if not valid base64. */
function tryDecodeBase64(s) {
  if (typeof s !== "string" || s.length === 0) return null;
  const b64 = /^[A-Za-z0-9+/_-]*=*$/;
  const decodeOne = (tok) => {
    const norm = tok.replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(norm);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  };
  // Reject a decode that came out mostly non-text: binary/gzip payloads, or a
  // false positive where a plain word happened to be valid base64 characters.
  const isMostlyText = (str) => {
    if (!str) return false;
    const n = Math.min(str.length, 4096);
    let bad = 0;
    for (let i = 0; i < n; i++) {
      const c = str.charCodeAt(i);
      if (c === 0xfffd || c < 0x09 || (c > 0x0d && c < 0x20)) bad++;
    }
    return bad / n < 0.05;
  };
  // Strategy 1: one logical base64 blob wrapped across lines at an arbitrary
  // width (MIME wrap, or a <pre> visually wrapping one long line). Strip ALL
  // whitespace and decode the concatenation — the only correct way when a line
  // can end mid-quantum (per-line atob would garble or bail on those).
  const joined = s.replace(/\s+/g, "");
  if (joined.length > 0 && joined.length % 4 !== 1 && b64.test(joined)) {
    try {
      const out = decodeOne(joined);
      if (isMostlyText(out)) return out;
    } catch (_) {
      /* fall through to per-frame */
    }
  }
  // Strategy 2: whitespace-separated INDEPENDENT base64 frames (one per streamed
  // SSE chunk, each base64'd on its own). Decode each and concatenate.
  const tokens = s.trim().split(/\s+/).filter(Boolean);
  if (tokens.length <= 1) return null;
  let out = "";
  for (const tok of tokens) {
    if (!b64.test(tok) || tok.length % 4 === 1) return null;
    try {
      out += decodeOne(tok);
    } catch (_) {
      return null;
    }
  }
  return isMostlyText(out) ? out : null;
}

/** Fallback: add newlines and indentation to JSON-like text when parse fails (best effort, skips inside strings). */
function prettyPrintJsonLike(str) {
  if (typeof str !== "string" || str.length === 0) return str;
  const out = [];
  let depth = 0;
  const indent = () => "  ".repeat(depth);
  let i = 0;
  let inString = false;
  let quote = "";
  let afterCommaOrBrace = false;
  while (i < str.length) {
    const c = str[i];
    if (inString) {
      if (c === "\\" && (quote === '"' || quote === "'")) {
        out.push(c);
        if (i + 1 < str.length) out.push(str[i + 1]);
        i += 2;
        continue;
      }
      if (c === quote) inString = false;
      out.push(c);
      i++;
      continue;
    }
    if (c === '"' || c === "'") {
      inString = true;
      quote = c;
      out.push(c);
      i++;
      continue;
    }
    if (c === " " || c === "\t") {
      out.push(c);
      i++;
      continue;
    }
    if (c === "\n" || c === "\r") {
      out.push(c);
      afterCommaOrBrace = false;
      i++;
      continue;
    }
    if (c === ",") {
      out.push(c, "\n", indent());
      afterCommaOrBrace = true;
      i++;
      continue;
    }
    if (c === "{" || c === "[") {
      if (!afterCommaOrBrace && out.length > 0 && out[out.length - 1] !== "\n") out.push("\n");
      out.push(c, "\n");
      depth++;
      out.push(indent());
      afterCommaOrBrace = false;
      i++;
      continue;
    }
    if (c === "}" || c === "]") {
      depth = Math.max(0, depth - 1);
      out.push("\n", indent(), c);
      afterCommaOrBrace = false;
      i++;
      continue;
    }
    out.push(c);
    i++;
  }
  return out.join("").trim();
}

/** Strip SSE/data-stream style prefix (e.g. "data: ") so the remainder can be parsed as JSON. */
function stripDataPrefix(str) {
  const t = str.trim();
  // SSE stream: collect every `data:` line payload (skip event:/id:/comments),
  // join them (a JSON-RPC result spans one or more data lines). Falls back to a
  // simple single-prefix strip.
  if (/(^|\n)\s*data:/i.test(t)) {
    const payloads = t
      .split(/\r?\n/)
      .filter((l) => /^\s*data:/i.test(l))
      .map((l) => l.replace(/^\s*data:\s?/i, ""));
    if (payloads.length) return payloads.join("").trim();
  }
  if (/^data:\s*/i.test(t)) return t.replace(/^data:\s*/i, "").trim();
  return str;
}

/** Format body for display: decode base64, normalize, then pretty-print JSON when possible. */
function formatBodyDisplay(raw) {
  if (raw == null || String(raw).trim() === "") return null;
  let s = String(raw).trim();
  // Remove BOM if present
  if (s.charCodeAt(0) === 0xfeff) s = s.slice(1);
  const decoded = tryDecodeBase64(s);
  if (decoded != null) s = decoded;
  s = stripDataPrefix(s);
  let truncateNote = "";
  if (s.length > BODY_FORMAT_MAX_CHARS) {
    const origLen = s.length;
    s = s.slice(0, BODY_FORMAT_MAX_CHARS);
    truncateNote = "\n\n… (truncated for display; " + (origLen - BODY_FORMAT_MAX_CHARS) + " more chars)";
  }
  function tryPrettyJson(str) {
    try {
      const parsed = JSON.parse(str);
      return JSON.stringify(parsed, null, 2);
    } catch (_) {
      return null;
    }
  }
  // Try parse first (handles valid minified JSON without touching it)
  let out = tryPrettyJson(s);
  if (out != null) return out + truncateNote;
  // Unescape literal \n, \t, \r so single-line JSON from logs parses; handle escaped backslashes
  s = s.replace(/\\\\/g, "\u0000").replace(/\\n/g, "\n").replace(/\\t/g, "\t").replace(/\\r/g, "\r").replace(/\u0000/g, "\\");
  out = tryPrettyJson(s);
  if (out != null) return out + truncateNote;
  // Fix common invalid JSON: trailing comma before ] or }
  const fixed = s.replace(/,\s*([\]}])/g, "$1");
  out = tryPrettyJson(fixed);
  if (out != null) return out + truncateNote;
  // Unwrap and pretty-print: handle double/triple encoded JSON strings
  let current = fixed;
  for (let depth = 0; depth < 5; depth++) {
    out = tryPrettyJson(current);
    if (out != null) return out + truncateNote;
    try {
      const parsed = JSON.parse(current);
      if (typeof parsed === "string") {
        current = parsed.trim();
        continue;
      }
      return JSON.stringify(parsed, null, 2) + truncateNote;
    } catch (_) {
      break;
    }
  }
  // Fallback: if it looks like JSON (starts with { or [), apply best-effort pretty print
  const trimmed = current.trim();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    return prettyPrintJsonLike(current) + truncateNote;
  }
  return s + truncateNote;
}

function renderTokens(selected) {
  const emptyMsg = "Select a context to view headers.";
  const bodyEmptyMsg = "Select a context to view body.";
  if (!selected?.headers) {
    if (refs.headersRequestDisplay) refs.headersRequestDisplay.textContent = emptyMsg;
    if (refs.headersResponseDisplay) refs.headersResponseDisplay.textContent = emptyMsg;
    if (refs.bodyRequestDisplay) refs.bodyRequestDisplay.textContent = bodyEmptyMsg;
    if (refs.bodyResponseDisplay) refs.bodyResponseDisplay.textContent = bodyEmptyMsg;
  } else {
    const { requestHeaders, responseHeaders } = splitRequestResponseHeaders(selected.headers);
    if (refs.headersRequestDisplay) {
      refs.headersRequestDisplay.textContent = formatHeaders(requestHeaders) ?? "(none in log)";
    }
    if (refs.headersResponseDisplay) {
      refs.headersResponseDisplay.textContent = formatHeaders(responseHeaders) ?? "(none in log)";
    }
    const requestBodyRaw = getHeaderValue(selected.headers, ["request.body", "request_body", "body"]);
    const responseBodyRaw = getHeaderValue(selected.headers, ["response.body", "response_body", "response_body_content"]);
    const requestBodyText = formatBodyDisplay(requestBodyRaw) ?? "(not in log)";
    const responseBodyText = formatBodyDisplay(responseBodyRaw) ?? "(not in log)";
    if (refs.bodyRequestDisplay) refs.bodyRequestDisplay.textContent = requestBodyText;
    if (refs.bodyResponseDisplay) refs.bodyResponseDisplay.textContent = responseBodyText;
  }

  if (!selected) {
    refs.eventMeta.textContent = "No event selected";
    return;
  }

  const timestamp = selected.timestamp ? new Date(selected.timestamp).toLocaleString() : "unknown time";
  refs.eventMeta.textContent = `${timestamp} | trace=${selected.traceId || "n/a"} | span=${selected.currentSpanId || "n/a"}`;
}

/** Content bounds for trace graph (nodes at 130,450,770 y=130; no labels above). */
const TRACE_VIEW_WIDTH = 900;
const TRACE_VIEW_HEIGHT = 170;
const EMPTY_VIEW_WIDTH = 400;
const EMPTY_VIEW_HEIGHT = 120;

/** Extract MCP method/tool from event request body (JSON-RPC). Returns e.g. "tools/list", "tools/call: my_tool", or null. */
function getMcpToolLabel(event) {
  if (!event?.headers) return null;
  const raw = getHeaderValue(event.headers, ["request.body", "request_body", "body"]);
  if (!raw || raw.length > 20000) return null;
  let s = raw.trim();
  const decoded = tryDecodeBase64(s);
  if (decoded != null) s = decoded;
  try {
    const obj = typeof s === "string" ? JSON.parse(s) : s;
    if (!obj || typeof obj !== "object") return null;
    const method = obj.method;
    if (typeof method !== "string" || !method) return null;
    if (method === "tools/list") return "tools/list";
    if (method === "tools/call") {
      const name = obj.params && typeof obj.params.name === "string" ? obj.params.name : "";
      return name ? "tools/call: " + name : "tools/call";
    }
    if (/^tools\./.test(method)) return method.replace(/^tools\./, "tools/");
    return null;
  } catch (_) {
    return null;
  }
}

function setTracePanelSize(width, height) {
  const wrap = refs.traceGraphWrap;
  if (!wrap) return;
  const maxW = wrap.parentElement ? wrap.parentElement.clientWidth : width;
  const w = maxW > 0 ? Math.min(width, maxW) : width;
  const h = Math.round((height / width) * w);
  wrap.style.width = w + "px";
  wrap.style.height = h + "px";
}

function renderTrace(selected) {
  const svg = refs.traceSvg;
  while (svg.firstChild) {
    svg.removeChild(svg.firstChild);
  }

  if (!selected) {
    drawEmptyGraph(svg);
    svg.setAttribute("viewBox", `0 0 ${EMPTY_VIEW_WIDTH} ${EMPTY_VIEW_HEIGHT}`);
    setTracePanelSize(EMPTY_VIEW_WIDTH, EMPTY_VIEW_HEIGHT);
    return;
  }

  const sourceLabel = selected.resolvedClient || selected.client || "source";
  const sourceNodeLabelRaw = stripNamespace(sourceLabel) || sourceLabel;
  const sourceNodeLabel = sourceNodeLabelRaw.length > 28 ? sourceNodeLabelRaw.slice(0, 25) + "…" : sourceNodeLabelRaw;
  const proxyLabel = stripNamespace(selected.proxy || "agentgateway-proxy");
  const backendLabel = stripNamespace(selected.resolvedBackendService || formatBackendDisplay(selected.backendTarget) || selected.route || "destination");
  const nodes = [
    { id: "source", x: 130, y: 130, label: sourceNodeLabel, color: "#2ab8ff" },
    { id: "proxy", x: 450, y: 130, label: proxyLabel, color: "#7a5cff" },
    { id: "backend", x: 770, y: 130, label: backendLabel, color: "#2ed18c" },
  ];

  for (let i = 0; i < nodes.length - 1; i += 1) {
    drawEdge(svg, nodes[i], nodes[i + 1]);
  }
  for (const node of nodes) {
    drawNode(svg, node);
  }
  if (nodes[1]) {
    if (isEventBlocked(selected)) {
      drawBlockedOverlay(svg, nodes[1]);
    } else {
      drawSuccessOverlay(svg, nodes[1]);
    }
  }

  const mcpToolLabel = getMcpToolLabel(selected);
  if (mcpToolLabel && nodes[2]) {
    const toolText = document.createElementNS("http://www.w3.org/2000/svg", "text");
    toolText.setAttribute("x", String(nodes[2].x));
    toolText.setAttribute("y", "198");
    toolText.setAttribute("text-anchor", "middle");
    toolText.setAttribute("font-size", "12");
    toolText.setAttribute("fill", "#98b0d7");
    toolText.setAttribute("class", "trace-mcp-tool-label");
    toolText.textContent = mcpToolLabel;
    svg.appendChild(toolText);
  }

  // ViewBox: room for nodes (y=130) and optional tool label below (y=198)
  const nodeCenterY = 130;
  const viewBoxH = mcpToolLabel ? 185 : 170;
  const viewBoxY = nodeCenterY - 85; // show from 45 so label at 198 is visible when viewBoxH=185
  svg.setAttribute("viewBox", `0 ${viewBoxY} ${TRACE_VIEW_WIDTH} ${viewBoxH}`);
  setTracePanelSize(TRACE_VIEW_WIDTH, viewBoxH);
}

const NODE_BOX_WIDTH = 230;
const NODE_BOX_HEIGHT = 84;
const NODE_BOX_RX = 14;
const NODE_HALF_WIDTH = NODE_BOX_WIDTH / 2;  // 115
const EDGE_INSET = 4;   // gap so line doesn't sit on box stroke
const ARROW_HEAD_LEN = 20;  // arrow tip to base, so line stops before box

function drawNode(svg, node) {
  const group = document.createElementNS("http://www.w3.org/2000/svg", "g");

  const rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
  rect.setAttribute("x", String(node.x - NODE_BOX_WIDTH / 2));
  rect.setAttribute("y", String(node.y - NODE_BOX_HEIGHT / 2));
  rect.setAttribute("width", String(NODE_BOX_WIDTH));
  rect.setAttribute("height", String(NODE_BOX_HEIGHT));
  rect.setAttribute("rx", String(NODE_BOX_RX));
  rect.setAttribute("fill", "rgba(13, 20, 35, 0.9)");
  rect.setAttribute("stroke", node.color);
  rect.setAttribute("stroke-width", "2");
  group.appendChild(rect);

  const fo = document.createElementNS("http://www.w3.org/2000/svg", "foreignObject");
  fo.setAttribute("x", String(node.x - NODE_BOX_WIDTH / 2));
  fo.setAttribute("y", String(node.y - NODE_BOX_HEIGHT / 2));
  fo.setAttribute("width", String(NODE_BOX_WIDTH));
  fo.setAttribute("height", String(NODE_BOX_HEIGHT));
  const div = document.createElementNS("http://www.w3.org/1999/xhtml", "div");
  div.setAttribute("style",
    "width:100%;height:100%;display:flex;align-items:center;justify-content:center;padding:10px;box-sizing:border-box;" +
    "word-wrap:break-word;overflow-wrap:break-word;text-align:center;font-size:14px;line-height:1.3;color:#dfeaff;font-family:ui-sans-serif,system-ui,sans-serif;");
  div.textContent = node.label;
  fo.appendChild(div);
  group.appendChild(fo);

  svg.appendChild(group);
}

function drawEdge(svg, fromNode, toNode) {
  const x1 = fromNode.x + NODE_HALF_WIDTH + EDGE_INSET;
  const x2 = toNode.x - NODE_HALF_WIDTH - ARROW_HEAD_LEN;
  const tipX = toNode.x - NODE_HALF_WIDTH;
  const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
  line.setAttribute("x1", String(x1));
  line.setAttribute("y1", String(fromNode.y));
  line.setAttribute("x2", String(x2));
  line.setAttribute("y2", String(toNode.y));
  line.setAttribute("stroke", "#98b0d7");
  line.setAttribute("stroke-width", "2");
  svg.appendChild(line);

  const marker = document.createElementNS("http://www.w3.org/2000/svg", "polygon");
  marker.setAttribute("points", `${x2},${toNode.y - 6} ${tipX},${toNode.y} ${x2},${toNode.y + 6}`);
  marker.setAttribute("fill", "#98b0d7");
  svg.appendChild(marker);
}

function drawBlockedOverlay(svg, node) {
  const g = document.createElementNS("http://www.w3.org/2000/svg", "g");
  const size = 52;
  const r = size / 2;
  // Center icon horizontally on node; shift down slightly so it sits in lower half and doesn't cover the label
  const offsetY = 38;
  g.setAttribute("transform", `translate(${node.x},${node.y + offsetY})`);
  g.setAttribute("class", "trace-blocked-overlay");
  const title = document.createElementNS("http://www.w3.org/2000/svg", "title");
  title.textContent = "Blocked or denied at gateway (401/403)";
  g.appendChild(title);

  const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
  circle.setAttribute("r", String(r));
  circle.setAttribute("fill", "#c53030");
  circle.setAttribute("stroke", "#fff");
  circle.setAttribute("stroke-width", "3");
  g.appendChild(circle);

  const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
  line.setAttribute("x1", String(-r * 0.7));
  line.setAttribute("y1", String(-r * 0.7));
  line.setAttribute("x2", String(r * 0.7));
  line.setAttribute("y2", String(r * 0.7));
  line.setAttribute("stroke", "#fff");
  line.setAttribute("stroke-width", "4");
  line.setAttribute("stroke-linecap", "round");
  g.appendChild(line);

  svg.appendChild(g);
}

function drawSuccessOverlay(svg, node) {
  const g = document.createElementNS("http://www.w3.org/2000/svg", "g");
  const size = 52;
  const r = size / 2;
  const offsetY = 38;
  g.setAttribute("transform", `translate(${node.x},${node.y + offsetY})`);
  g.setAttribute("class", "trace-success-overlay");

  const title = document.createElementNS("http://www.w3.org/2000/svg", "title");
  title.textContent = "Call succeeded";
  g.appendChild(title);

  const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
  circle.setAttribute("r", String(r));
  circle.setAttribute("fill", "#2ed18c");
  circle.setAttribute("stroke", "#fff");
  circle.setAttribute("stroke-width", "3");
  g.appendChild(circle);

  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("d", "M -14,-2 L -4,10 L 16,-14");
  path.setAttribute("stroke", "#fff");
  path.setAttribute("stroke-width", "4");
  path.setAttribute("stroke-linecap", "round");
  path.setAttribute("stroke-linejoin", "round");
  path.setAttribute("fill", "none");
  g.appendChild(path);

  svg.appendChild(g);
}

function drawEmptyGraph(svg) {
  const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
  text.setAttribute("x", String(EMPTY_VIEW_WIDTH / 2));
  text.setAttribute("y", String(EMPTY_VIEW_HEIGHT / 2));
  text.setAttribute("text-anchor", "middle");
  text.setAttribute("font-size", "16");
  text.setAttribute("fill", "#98a9ca");
  text.textContent = "Waiting for trace events...";
  svg.appendChild(text);
}

/** True when this context/event represents a request denied/blocked at gateway (401 or 403). */
function isEventBlocked(event) {
  if (!event) return false;
  if (event.blockedByPolicy) return true;
  const h = event.headers;
  if (h && typeof h === "object") {
    const statusKeys = ["http.status", "response_code", "response_code_number", "status", "http_status_code", "http_status"];
    for (const k of statusKeys) {
      const val = String((h[k] ?? "")).trim();
      if (val === "401" || val === "403") return true;
    }
    for (const [k, v] of Object.entries(h)) {
      const key = (k || "").toLowerCase();
      const val = String(v || "").trim();
      if ((val === "401" || val === "403") && (key.includes("status") || key.includes("code"))) return true;
    }
  }
  return false;
}

/** Strip leading "namespace/" for trace graph (e.g. default/kagent-tools -> kagent-tools). */
function stripNamespace(s) {
  if (!s) return "";
  const i = String(s).indexOf("/");
  return i >= 0 ? String(s).slice(i + 1) : String(s);
}

/** For trace graph source: show only host (no scheme or port). e.g. http://localhost:8888/mcp -> localhost */
function urlHostOnly(s) {
  if (!s) return "";
  const str = String(s).trim();
  try {
    const url = str.startsWith("http://") || str.startsWith("https://") ? str : "http://" + str;
    return new URL(url).hostname;
  } catch {
    return str;
  }
}

/** Show namespace/service for backend (e.g. service/default/kagent-tools:8084 -> default/kagent-tools). */
function formatBackendDisplay(backend) {
  if (!backend) return "";
  const s = String(backend).trim();
  const m = s.match(/^service\/([^/]+)\/([^:]+)(?::\d+)?$/);
  if (m) return `${m[1]}/${m[2]}`;
  return s;
}

function escapeHtml(input) {
  return String(input)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

/**
 * Decode JWT payload (middle part). Returns parsed object or null if invalid.
 */
function decodeJwtPayloadObject(token) {
  if (!token || typeof token !== "string") return null;
  const parts = token.trim().split(".");
  if (parts.length !== 3) return null;
  try {
    const base64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, "=");
    const json = atob(padded);
    return JSON.parse(json);
  } catch {
    return null;
  }
}

/**
 * Decode JWT payload (middle part). Returns formatted JSON string or null if invalid.
 */
function decodeJwtPayload(token) {
  const payload = decodeJwtPayloadObject(token);
  return payload ? JSON.stringify(payload, null, 2) : null;
}

/** True if the token is an OBO/delegated token (has act claim per RFC 8693). */
function isOboToken(token) {
  const payload = decodeJwtPayloadObject(token);
  return payload != null && "act" in payload;
}

/** True if this context is an OpenAI API request (path indicates Completions/Responses route). */
function isOpenAIContext(event) {
  if (!event?.context) return false;
  const ctx = String(event.context).toLowerCase();
  return ctx.includes("openai") || ctx.includes("v1/chat/completions") || ctx.includes("v1/responses");
}

/** True if this context used an impersonation token (matches the OBO JWT we got from an impersonation exchange). */
function isImpersonationContext(event) {
  if (!event) return false;
  const oboJwt = (state.workflow.impersonationOboJwt || "").trim();
  const inbound = (event.inboundJwt && String(event.inboundJwt).trim()) || "";
  if (!oboJwt || !inbound) return false;
  if (inbound === oboJwt) return true;
  if (inbound.length >= 50 && oboJwt.length >= 50 && inbound.slice(0, 50) === oboJwt.slice(0, 50)) return true;
  return false;
}

/** Format token for display: show decoded payload, or raw if decode fails. */
function formatJwtDisplay(rawToken, fallbackLabel) {
  if (!rawToken) return fallbackLabel || "(none)";
  const decoded = decodeJwtPayload(rawToken);
  if (decoded) return decoded;
  return rawToken;
}

/** Keys to omit from the Headers section (shown only in Body). */
const BODY_HEADER_KEYS = new Set([
  "request.body", "request_body", "response.body", "response_body", "response_body_content", "body",
].map((s) => s.toLowerCase()));

/** Split parsed log attributes into request (left) vs response (right). Response keys: status, duration, error, etc. Omits body keys (shown in Body section). */
function splitRequestResponseHeaders(headers) {
  const requestHeaders = {};
  const responseHeaders = {};
  if (!headers || typeof headers !== "object") {
    return { requestHeaders, responseHeaders };
  }
  const responseKeys = new Set([
    "http.status", "duration", "response_code", "response_code_number", "response_code_number_value",
    "status", "http_status_code", "http_status", "error",
  ]);
  for (const [k, v] of Object.entries(headers)) {
    const keyLower = (k || "").toLowerCase();
    if (BODY_HEADER_KEYS.has(keyLower)) continue;
    if (responseKeys.has(keyLower) || keyLower.includes("response") || keyLower === "duration") {
      responseHeaders[k] = v;
    } else {
      requestHeaders[k] = v;
    }
  }
  return { requestHeaders, responseHeaders };
}

/** Format headers map as key: value lines (sorted by key). Returns null for empty. Authorization value is truncated to 20 chars. */
function formatHeaders(headers) {
  if (!headers || typeof headers !== "object") return null;
  const keys = Object.keys(headers).sort();
  if (keys.length === 0) return "(none in log)";
  return keys
    .map((k) => {
      let v = headers[k];
      const keyLower = k.toLowerCase();
      const isAuth = keyLower === "authorization" || keyLower.endsWith(".authorization");
      if (typeof v === "string" && isAuth && v.length > 20) {
        v = v.slice(0, 20) + "...";
      }
      return `${k}: ${v}`;
    })
    .join("\n");
}

const WORKFLOW_TOAST_DURATION_MS = 10000;
const WORKFLOW_TOAST_FADEOUT_MS = 400;

let workflowStatusClearTimer = null;
let workflowStatusFadeOutTimer = null;

function setWorkflowStatus(message, isError = false) {
  if (workflowStatusClearTimer) clearTimeout(workflowStatusClearTimer);
  if (workflowStatusFadeOutTimer) clearTimeout(workflowStatusFadeOutTimer);
  refs.wfStatus.classList.remove("workflow-status-toast--fade-out");
  if (isError) refs.wfStatus.classList.add("workflow-status-toast--error");
  else refs.wfStatus.classList.remove("workflow-status-toast--error");
  refs.wfStatus.textContent = message;
  refs.wfStatus.style.color = isError ? "#ff9ca4" : "";
  refs.wfStatus.classList.add("workflow-status-toast--visible");
  workflowStatusClearTimer = setTimeout(() => {
    workflowStatusClearTimer = null;
    refs.wfStatus.classList.add("workflow-status-toast--fade-out");
    workflowStatusFadeOutTimer = setTimeout(() => {
      workflowStatusFadeOutTimer = null;
      refs.wfStatus.textContent = "";
      refs.wfStatus.style.color = "";
      refs.wfStatus.classList.remove("workflow-status-toast--visible", "workflow-status-toast--fade-out", "workflow-status-toast--error");
    }, WORKFLOW_TOAST_FADEOUT_MS);
  }, WORKFLOW_TOAST_DURATION_MS);
}

function setWorkflowBusy(isBusy) {
  if (refs.wfStep2) refs.wfStep2.disabled = isBusy;
  if (refs.wfStep3) refs.wfStep3.disabled = isBusy;
  if (refs.wfMcpTokenType) refs.wfMcpTokenType.disabled = isBusy;
}

function collectWorkflowInputs() {
  return {
    stsUrl: (state.workflow.stsUrl || "").trim(),
    exchangeMode: (refs.wfExchangeMode && refs.wfExchangeMode.value) || "delegation",
    actorToken: (state.workflow.actorToken || "").trim(),
    mcpUrl: (state.workflow.mcpUrl || "").trim(),
  };
}

async function postJSON(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    credentials: "include",
  });

  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const err = new Error(payload.error || `Request failed (${response.status})`);
    err.payload = payload;
    err.status = response.status;
    throw err;
  }
  return payload;
}

async function handleStep2() {
  setWorkflowBusy(true);
  setWorkflowStatus("Exchanging token via STS...");
  try {
    const input = collectWorkflowInputs();
    const useSessionToken = state.user && !state.workflow.userJwt;
    if (!useSessionToken && !state.workflow.userJwt) {
      throw new Error("Log in first (top right) to use Exchange via STS");
    }

    const payload = await postJSON("/api/obo/exchange", {
      stsUrl: input.stsUrl,
      userJwt: state.workflow.userJwt || "",
      exchangeMode: input.exchangeMode,
      actorToken: input.actorToken,
    });
    state.workflow.oboJwt = payload.oboJwt || "";
    state.workflow.lastExchangeMode = (input.exchangeMode || "").toLowerCase().trim() || "delegation";
    const isImpersonation = state.workflow.lastExchangeMode === "impersonation";
    if (isImpersonation) {
      state.workflow.impersonationOboJwt = state.workflow.oboJwt;
      savePersistedImpersonationOboJwt();
    }
    if (refs.wfOboJwt) refs.wfOboJwt.textContent = formatJwtDisplay(state.workflow.oboJwt, "(empty OBO Token)");
    updateTokenCheckmarks();
    setWorkflowStatus("Step 2 complete: STS returned OBO Token.");
  } catch (error) {
    setWorkflowStatus(`Step 2 failed: ${error.message}`, true);
  } finally {
    setWorkflowBusy(false);
  }
}

async function callMCPTools(tokenType) {
  setWorkflowBusy(true);
  state.workflow.blockedByPolicy = false;
  const input = collectWorkflowInputs();
  const useUserJwt = tokenType === "user-jwt";
  const useOboJwt = tokenType === "obo-jwt";
  const oboJwt = useOboJwt ? (state.workflow.oboJwt || "") : "";
  const userJwt = useUserJwt ? (state.workflow.userJwt || "") : "";
  const labels = { "no-jwt": "No JWT", "user-jwt": "Session Token", "obo-jwt": "OBO Token" };
  const label = labels[tokenType] || tokenType;
  const hasToken = tokenType === "no-jwt" ? false : tokenType === "user-jwt" ? !!userJwt : !!oboJwt;
  setWorkflowStatus(
    tokenType === "no-jwt"
      ? "Calling MCP with no JWT (expect 401)..."
      : hasToken
        ? `Calling MCP with ${label}...`
        : `Calling MCP with ${label} (none set — expect 401)...`
  );
  await new Promise((r) => setTimeout(r, 0));
  try {
    const payload = await postJSON("/api/obo/mcp-tools", {
      mcpUrl: input.mcpUrl,
      oboJwt,
      userJwt,
      useUserJwt,
    });

    setWorkflowStatus("Step 3 complete: MCP tools listed.");
    setWorkflowBusy(false);
    const tools = Array.isArray(payload.tools) ? payload.tools : [];
    const toolsText = tools.length ? tools.join("\n") : "(no tools returned)";
    requestAnimationFrame(() => {
      let rawText = "";
      try {
        rawText = JSON.stringify(payload.raw || {});
      } catch (_) {
        rawText = String(payload.raw || "");
      }
      const maxRaw = 6000;
      if (rawText.length > maxRaw) {
        rawText = rawText.slice(0, maxRaw) + "\n\n… (truncated, " + (rawText.length - maxRaw) + " chars)";
      }
      refs.wfTools.textContent = `Tools:\n${toolsText}\n\nRaw:\n${rawText}`;
    });
  } catch (error) {
    if (error.status === 403 || (error.payload && error.payload.blockedByPolicy)) {
      state.workflow.blockedByPolicy = true;
      render();
    }
    setWorkflowStatus(`Step 3 failed: ${error.message}`, true);
    const hint =
      tokenType === "no-jwt"
        ? "(No JWT sent; gateway returns 401.)"
        : tokenType === "user-jwt"
          ? "(Session Token is not accepted by the gateway; use step 2 to get an OBO Token.)"
          : "(Call with No JWT to demonstrate 401 Unauthorized.)";
    refs.wfTools.textContent = `Error: ${error.message}\n\n${hint}`;
  } finally {
    setWorkflowBusy(false);
    setTimeout(() => {
      poll().then(() => requestAnimationFrame(() => selectMostRecentContext()));
    }, 0);
  }
}

function selectMostRecentContext() {
  const httpEvents = state.events.filter(isHttpEvent);
  const mostRecent = httpEvents.length > 0 ? httpEvents[0] : state.events[0];
  if (mostRecent) {
    state.selectedId = mostRecent.id;
    requestAnimationFrame(() => render());
  }
}

async function handleStep3() {
  const tokenType = (refs.wfMcpTokenType && refs.wfMcpTokenType.value) || "obo-jwt";
  await callMCPTools(tokenType);
}

function handleClearJWTs() {
  state.workflow.oboJwt = "";
  state.workflow.lastExchangeMode = "";
  state.workflow.impersonationOboJwt = "";
  savePersistedImpersonationOboJwt();
  state.workflow.blockedByPolicy = false;
  if (refs.wfOboJwt) refs.wfOboJwt.textContent = "(not exchanged yet)";
  updateTokenCheckmarks();
  setWorkflowStatus("OBO Token cleared.");
}

async function handleContextsClear() {
  try {
    const response = await fetch("/api/events/clear", { method: "POST" });
    if (!response.ok) return;
    state.events = [];
    state.selectedId = null;
    _lastContextIds = "";
    render();
  } catch (_) {}
}

function updateExchangeModeUI() {
  state.workflow.oboJwt = "";
  if (refs.wfOboJwt) refs.wfOboJwt.textContent = "(not exchanged yet)";
  updateTokenCheckmarks();
}

/** Escape HTML and apply simple formatting: line breaks before numbered list items, **bold**. */
function formatAgentMessageContent(text) {
  const raw = (text || "").trim();
  if (!raw) return "";
  const escaped = raw
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
  let out = escaped
    .replace(/\n/g, "<br>")
    .replace(/: 1\. /g, ":<br><br>1. ");
  for (let n = 2; n <= 99; n++) {
    out = out.replace(new RegExp(" " + n + "\\. ", "g"), "<br><br>" + n + ". ");
  }
  out = out.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  return out;
}

function renderAgentChat() {
  if (!refs.agentChatMessages) return;
  refs.agentChatMessages.innerHTML = "";
  for (const m of state.agentChat.messages) {
    const wrap = document.createElement("div");
    wrap.className = "agent-chat-message agent-chat-message--" + m.role;
    const label = document.createElement("span");
    label.className = "agent-chat-message-label";
    label.textContent = m.role === "user" ? "You:" : "Assistant:";
    const body = document.createElement("div");
    body.className = "agent-chat-message-body";
    body.innerHTML = formatAgentMessageContent(m.content);
    wrap.appendChild(label);
    wrap.appendChild(body);
    refs.agentChatMessages.appendChild(wrap);
  }
  refs.agentChatMessages.scrollTop = refs.agentChatMessages.scrollHeight;
}

function appendAgentChatTypingIndicator() {
  if (!refs.agentChatMessages) return;
  const wrap = document.createElement("div");
  wrap.className = "agent-chat-message agent-chat-message--assistant agent-chat-typing";
  wrap.setAttribute("aria-live", "polite");
  const label = document.createElement("span");
  label.className = "agent-chat-message-label";
  label.textContent = "Assistant:";
  const body = document.createElement("div");
  body.className = "agent-chat-message-body agent-chat-typing-dots";
  body.setAttribute("aria-hidden", "true");
  body.innerHTML = "<span></span><span></span><span></span>";
  wrap.appendChild(label);
  wrap.appendChild(body);
  refs.agentChatMessages.appendChild(wrap);
  refs.agentChatMessages.scrollTop = refs.agentChatMessages.scrollHeight;
}

async function handleAgentChatSend() {
  const input = refs.agentChatInput;
  const sendBtn = refs.agentChatSend;
  const errEl = refs.agentChatError;
  const msg = (input && input.value || "").trim();
  if (!msg) return;
  const mcpUrl = (state.workflow.mcpUrl || "").trim();
  if (!mcpUrl) {
    if (errEl) errEl.textContent = "Set MCP_URL in .env and restart the app.";
    return;
  }
  const openaiKey = (state.openaiApiKeyConfigured ? "" : (refs.agentOpenaiToken && refs.agentOpenaiToken.value || "")).trim();
  if (!state.openaiApiKeyConfigured && !openaiKey) {
    if (errEl) errEl.textContent = "Enter your OpenAI API key first (or set OPENAI_API_KEY server-side).";
    return;
  }
  if (errEl) errEl.textContent = "";
  state.agentChat.messages.push({ role: "user", content: msg });
  const history = state.agentChat.inputHistory || [];
  if (history[history.length - 1] !== msg) history.push(msg);
  state.agentChat.inputHistory = history;
  state.agentChat.inputHistoryIndex = -1;
  state.agentChat.inputDraft = "";
  if (input) input.value = "";
  renderAgentChat();
  appendAgentChatTypingIndicator();
  if (sendBtn) sendBtn.disabled = true;
  try {
    const payload = await postJSON("/api/agent-chat", {
      message: msg,
      openaiApiKey: openaiKey,
      mcpUrl,
      oboToken: (state.workflow.oboJwt || "").trim(),
    });
    const text = (payload.text || "").trim();
    state.agentChat.messages.push({ role: "assistant", content: text || "(no response)" });
  } catch (err) {
    state.agentChat.messages.push({ role: "assistant", content: "Error: " + (err.message || String(err)) });
    if (errEl) errEl.textContent = err.message || String(err);
  }
  renderAgentChat();
  if (sendBtn) sendBtn.disabled = false;
}

function initWorkflow() {
  if (refs.wfStep2) refs.wfStep2.addEventListener("click", handleStep2);
  if (refs.wfStep3) refs.wfStep3.addEventListener("click", handleStep3);
  if (refs.wfClearJwts) refs.wfClearJwts.addEventListener("click", handleClearJWTs);
  if (refs.wfTokensToggle && refs.wfTokensWrapper) {
    refs.wfTokensToggle.addEventListener("click", function () {
      const collapsed = refs.wfTokensWrapper.classList.toggle("is-collapsed");
      refs.wfTokensToggle.setAttribute("aria-expanded", String(!collapsed));
    });
  }
  if (refs.wfExchangeMode) {
    refs.wfExchangeMode.addEventListener("change", updateExchangeModeUI);
    updateExchangeModeUI();
  }
  if (refs.wfUserJwt) refs.wfUserJwt.textContent = state.workflow.userJwt ? formatJwtDisplay(state.workflow.userJwt, "(empty session token)") : "(not generated yet)";
  if (refs.wfOboJwt) refs.wfOboJwt.textContent = state.workflow.oboJwt ? formatJwtDisplay(state.workflow.oboJwt, "(empty OBO Token)") : "(not exchanged yet)";
  updateTokenCheckmarks();
  if (refs.agentChatSend) refs.agentChatSend.addEventListener("click", handleAgentChatSend);
  if (refs.agentChatInput) {
    refs.agentChatInput.addEventListener("keydown", function (e) {
      if (e.key === "Enter") {
        handleAgentChatSend();
        return;
      }
      const history = state.agentChat.inputHistory || [];
      if (history.length === 0) return;
      if (e.key === "ArrowUp") {
        e.preventDefault();
        if (state.agentChat.inputHistoryIndex === -1) {
          state.agentChat.inputDraft = refs.agentChatInput.value;
          state.agentChat.inputHistoryIndex = history.length - 1;
          refs.agentChatInput.value = history[state.agentChat.inputHistoryIndex];
        } else if (state.agentChat.inputHistoryIndex > 0) {
          state.agentChat.inputHistoryIndex--;
          refs.agentChatInput.value = history[state.agentChat.inputHistoryIndex];
        }
        return;
      }
      if (e.key === "ArrowDown") {
        e.preventDefault();
        if (state.agentChat.inputHistoryIndex === -1) return;
        state.agentChat.inputHistoryIndex++;
        if (state.agentChat.inputHistoryIndex >= history.length) {
          state.agentChat.inputHistoryIndex = -1;
          refs.agentChatInput.value = state.agentChat.inputDraft || "";
        } else {
          refs.agentChatInput.value = history[state.agentChat.inputHistoryIndex];
        }
        return;
      }
    });
  }
  if (refs.agentChatBubble) {
    refs.agentChatBubble.addEventListener("click", function () {
      const isOpen = refs.agentChatWidget && refs.agentChatWidget.classList.contains("is-open");
      if (isOpen) {
        if (refs.agentChatWidget) refs.agentChatWidget.classList.remove("is-open");
        if (refs.agentChatPanel) refs.agentChatPanel.setAttribute("aria-hidden", "true");
        if (refs.agentChatBubble) {
          refs.agentChatBubble.setAttribute("aria-expanded", "false");
          refs.agentChatBubble.setAttribute("aria-label", "Open agent chat");
        }
      } else {
        if (refs.agentChatWidget) refs.agentChatWidget.classList.add("is-open");
        if (refs.agentChatPanel) refs.agentChatPanel.setAttribute("aria-hidden", "false");
        if (refs.agentChatBubble) {
          refs.agentChatBubble.setAttribute("aria-expanded", "true");
          refs.agentChatBubble.setAttribute("aria-label", "Close agent chat");
        }
      }
    });
  }
  if (refs.agentChatClose) {
    refs.agentChatClose.addEventListener("click", function () {
      if (refs.agentChatWidget) refs.agentChatWidget.classList.remove("is-open");
      if (refs.agentChatPanel) refs.agentChatPanel.setAttribute("aria-hidden", "true");
      if (refs.agentChatBubble) refs.agentChatBubble.setAttribute("aria-expanded", "false");
    });
  }
  if (refs.agentChatResizeHandle && refs.agentChatPanel) {
    refs.agentChatResizeHandle.addEventListener("mousedown", function (e) {
      e.preventDefault();
      const panel = refs.agentChatPanel;
      const startX = e.clientX;
      const startY = e.clientY;
      const startW = panel.offsetWidth;
      const startH = panel.offsetHeight;
      const minW = 280;
      const maxW = Math.min(window.innerWidth - 40, 800);
      const minH = 200;
      const maxH = Math.min(480, window.innerHeight - 100);
      function onMove(e) {
        const dx = e.clientX - startX;
        const dy = e.clientY - startY;
        const w = Math.max(minW, Math.min(maxW, startW - dx));
        const h = Math.max(minH, Math.min(maxH, startH - dy));
        panel.style.width = w + "px";
        panel.style.height = h + "px";
      }
      function onUp() {
        document.removeEventListener("mousemove", onMove);
        document.removeEventListener("mouseup", onUp);
      }
      document.addEventListener("mousemove", onMove);
      document.addEventListener("mouseup", onUp);
    });
  }
}

if (refs.contextsClear) {
  refs.contextsClear.addEventListener("click", handleContextsClear);
}

(async function init() {
  await checkAuth();
  loadPersistedImpersonationOboJwt();
  initWorkflow();
  updateTokenCheckmarks();
  fetchLogMode();
  poll();
  setInterval(poll, POLL_MS);
  startLogStream();
  setTimeout(function connectingHint() {
    if (refs.status && refs.status.textContent === "Connecting..." && !state.healthy) {
      refs.status.textContent = "Connecting… (check backend)";
    }
  }, 4000);
})();
