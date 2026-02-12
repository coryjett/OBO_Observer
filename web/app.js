const POLL_MS = 1500;
const MAX_CONTEXTS = 120;

const state = {
  events: [],
  selectedId: null,
  healthy: false,
  logMode: null,
  workflow: {
    userJwt: "",
    oboJwt: "",
  },
};

const refs = {
  status: document.getElementById("status"),
  contextList: document.getElementById("context-list"),
  contextsClear: document.getElementById("contexts-clear"),
  headersDisplay: document.getElementById("headers-display"),
  traceSvg: document.getElementById("trace-svg"),
  traceGraphWrap: document.getElementById("trace-graph-wrap"),
  eventMeta: document.getElementById("event-meta"),
  wfStatus: document.getElementById("wf-status"),
  wfUserJwt: document.getElementById("wf-user-jwt"),
  wfOboJwt: document.getElementById("wf-obo-jwt"),
  wfTools: document.getElementById("wf-tools"),
  agentgatewayLogs: document.getElementById("agentgateway-logs"),
  wfStep1: document.getElementById("wf-step-1"),
  wfStep2: document.getElementById("wf-step-2"),
  wfStep3: document.getElementById("wf-step-3"),
  wfMcpTokenType: document.getElementById("wf-mcp-token-type"),
  wfClearJwts: document.getElementById("wf-clear-jwts"),
  wfKeycloakUrl: document.getElementById("wf-keycloak-url"),
  wfRealm: document.getElementById("wf-realm"),
  wfClientId: document.getElementById("wf-client-id"),
  wfClientSecret: document.getElementById("wf-client-secret"),
  wfUsername: document.getElementById("wf-username"),
  wfPassword: document.getElementById("wf-password"),
  wfStsUrl: document.getElementById("wf-sts-url"),
  wfActorToken: document.getElementById("wf-actor-token"),
  wfMcpUrl: document.getElementById("wf-mcp-url"),
};

async function fetchLogMode() {
  try {
    const res = await fetch("/api/info", { cache: "no-store" });
    if (res.ok) {
      const data = await res.json();
      state.logMode = data.log_mode || null;
    }
  } catch (_) {
    state.logMode = null;
  }
}

async function poll() {
  try {
    const response = await fetch("/api/events?limit=200", { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`status ${response.status}`);
    }

    const payload = await response.json();
    state.events = (payload.events || []).slice(0, MAX_CONTEXTS);
    state.healthy = true;
    if (state.logMode === null) {
      await fetchLogMode();
    }
    render();
  } catch (error) {
    state.healthy = false;
    state.logMode = null;
    refs.status.className = "status status-warn";
    refs.status.textContent = `Disconnected (${error.message})`;
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

function render() {
  refs.status.className = `status ${state.healthy ? "status-ok" : "status-warn"}`;
  const modeLabel = state.logMode === "kubernetes" ? " (Agentgateway)" : state.logMode === "file" ? " (file)" : "";
  refs.status.textContent = state.healthy ? "Live" + modeLabel : "Disconnected";

  if (!state.selectedId && state.events.length > 0) {
    state.selectedId = state.events[0].id;
  }

  const selected = state.events.find((event) => event.id === state.selectedId) || state.events[0] || null;
  if (selected) {
    state.selectedId = selected.id;
  }

  renderContexts(selected);
  renderTokens(selected);
  renderTrace(selected);
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

function renderContexts(selected) {
  refs.contextList.innerHTML = "";
  const httpEvents = state.events.filter(isHttpEvent);

  for (const event of httpEvents) {
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
    const badge = usedObo
      ? '<span class="obo-jwt-badge">OBO JWT</span>'
      : usedUserJwt
        ? '<span class="jwt-badge">User JWT</span>'
        : '';
    button.innerHTML = `
      <div class="path-row">
        <span class="path">${escapeHtml(event.context || "(context missing)")}</span>
        ${badge}
      </div>
      <div class="small">${escapeHtml(event.resolvedClient || event.client || "unknown source")} → ${escapeHtml(event.resolvedBackendService || formatBackendDisplay(event.backendTarget) || event.route || "unknown destination")}</div>
    `;

    li.appendChild(button);
    refs.contextList.appendChild(li);
  }
}

function renderTokens(selected) {
  if (refs.headersDisplay) {
    refs.headersDisplay.textContent = formatHeaders(selected?.headers);
  }

  if (!selected) {
    refs.eventMeta.textContent = "No event selected";
    return;
  }

  const timestamp = selected.timestamp ? new Date(selected.timestamp).toLocaleString() : "unknown time";
  refs.eventMeta.textContent = `${timestamp} | trace=${selected.traceId || "n/a"} | span=${selected.currentSpanId || "n/a"}`;
}

/** Content bounds for trace graph: left, top, width, height (nodes at 130,450,770 y=130; labels at 44,64). */
const TRACE_VIEW_WIDTH = 900;
const TRACE_VIEW_HEIGHT = 200;
const EMPTY_VIEW_WIDTH = 400;
const EMPTY_VIEW_HEIGHT = 160;

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

  drawLabel(svg, 450, 44, selected.context || "(context missing)");
  const sourceForLabel = selected.resolvedClient || selected.client;
  if (sourceForLabel) {
    const sourceDisplay = sourceForLabel.length > 52 ? sourceForLabel.slice(0, 49) + "…" : sourceForLabel;
    drawLabel(svg, 450, 64, sourceDisplay, "Source: ");
  }

  svg.setAttribute("viewBox", `0 0 ${TRACE_VIEW_WIDTH} ${TRACE_VIEW_HEIGHT}`);
  setTracePanelSize(TRACE_VIEW_WIDTH, TRACE_VIEW_HEIGHT);
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

function drawLabel(svg, x, y, textValue, prefix = "Context: ") {
  const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
  text.setAttribute("x", String(x));
  text.setAttribute("y", String(y));
  text.setAttribute("text-anchor", "middle");
  text.setAttribute("font-size", prefix === "Context: " ? 15 : 13);
  text.setAttribute("fill", "#b8c9e8");
  text.textContent = prefix + textValue;
  svg.appendChild(text);
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

/** Format token for display: show decoded payload, or raw if decode fails. */
function formatJwtDisplay(rawToken, fallbackLabel) {
  if (!rawToken) return fallbackLabel || "(none)";
  const decoded = decodeJwtPayload(rawToken);
  if (decoded) return decoded;
  return rawToken;
}

/** Format headers map as key: value lines (sorted by key). */
function formatHeaders(headers) {
  if (!headers || typeof headers !== "object") return "Select a context to view headers.";
  const keys = Object.keys(headers).sort();
  if (keys.length === 0) return "(no headers in log)";
  return keys.map((k) => `${k}: ${headers[k]}`).join("\n");
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
  refs.wfStep1.disabled = isBusy;
  refs.wfStep2.disabled = isBusy;
  refs.wfStep3.disabled = isBusy;
  if (refs.wfMcpTokenType) refs.wfMcpTokenType.disabled = isBusy;
}

function collectWorkflowInputs() {
  return {
    keycloakUrl: refs.wfKeycloakUrl.value.trim(),
    realm: refs.wfRealm.value.trim(),
    clientId: refs.wfClientId.value.trim(),
    clientSecret: refs.wfClientSecret.value,
    username: refs.wfUsername.value.trim(),
    password: refs.wfPassword.value,
    stsUrl: refs.wfStsUrl.value.trim(),
    actorToken: refs.wfActorToken.value.trim(),
    mcpUrl: refs.wfMcpUrl.value.trim(),
  };
}

async function postJSON(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.error || `Request failed (${response.status})`);
  }
  return payload;
}

async function handleStep1() {
  setWorkflowBusy(true);
  setWorkflowStatus("Generating user JWT...");
  try {
    const input = collectWorkflowInputs();
    const payload = await postJSON("/api/obo/user-jwt", {
      keycloakUrl: input.keycloakUrl,
      realm: input.realm,
      clientId: input.clientId,
      clientSecret: input.clientSecret,
      username: input.username,
      password: input.password,
    });

    state.workflow.userJwt = payload.userJwt || "";
    refs.wfUserJwt.textContent = formatJwtDisplay(state.workflow.userJwt, "(empty user JWT)");
    setWorkflowStatus("Step 1 complete: user JWT generated.");
  } catch (error) {
    setWorkflowStatus(`Step 1 failed: ${error.message}`, true);
  } finally {
    setWorkflowBusy(false);
  }
}

async function handleStep2() {
  setWorkflowBusy(true);
  setWorkflowStatus("Exchanging user JWT via STS...");
  try {
    const input = collectWorkflowInputs();
    if (!state.workflow.userJwt) {
      throw new Error("Generate user JWT first");
    }

    const payload = await postJSON("/api/obo/exchange", {
      stsUrl: input.stsUrl,
      userJwt: state.workflow.userJwt,
      actorToken: input.actorToken,
    });
    state.workflow.oboJwt = payload.oboJwt || "";
    refs.wfOboJwt.textContent = formatJwtDisplay(state.workflow.oboJwt, "(empty OBO JWT)");
    setWorkflowStatus("Step 2 complete: STS returned OBO JWT.");
  } catch (error) {
    setWorkflowStatus(`Step 2 failed: ${error.message}`, true);
  } finally {
    setWorkflowBusy(false);
  }
}

async function callMCPTools(tokenType) {
  setWorkflowBusy(true);
  const input = collectWorkflowInputs();
  const useUserJwt = tokenType === "user-jwt";
  const useOboJwt = tokenType === "obo-jwt";
  const oboJwt = useOboJwt ? (state.workflow.oboJwt || "") : "";
  const userJwt = useUserJwt ? (state.workflow.userJwt || "") : "";
  const labels = { "no-jwt": "No JWT", "user-jwt": "User JWT", "obo-jwt": "OBO JWT" };
  const label = labels[tokenType] || tokenType;
  const hasToken = tokenType === "no-jwt" ? false : tokenType === "user-jwt" ? !!userJwt : !!oboJwt;
  setWorkflowStatus(
    tokenType === "no-jwt"
      ? "Calling MCP with no JWT (expect 401)..."
      : hasToken
        ? `Calling MCP with ${label}...`
        : `Calling MCP with ${label} (none set — expect 401)...`
  );
  try {
    const payload = await postJSON("/api/obo/mcp-tools", {
      mcpUrl: input.mcpUrl,
      oboJwt,
      userJwt,
      useUserJwt,
    });

    const tools = Array.isArray(payload.tools) ? payload.tools : [];
    const toolsText = tools.length ? tools.join("\n") : "(no tools returned)";
    const rawText = JSON.stringify(payload.raw || {}, null, 2);
    refs.wfTools.textContent = `Tools:\n${toolsText}\n\nRaw:\n${rawText}`;
    setWorkflowStatus("Step 3 complete: MCP tools listed.");
  } catch (error) {
    setWorkflowStatus(`Step 3 failed: ${error.message}`, true);
    const hint =
      tokenType === "no-jwt"
        ? "(No JWT sent; gateway returns 401.)"
        : tokenType === "user-jwt"
          ? "(User JWT is not accepted by the gateway; use step 2 to get an OBO JWT.)"
          : "(Call with No JWT to demonstrate 401 Unauthorized.)";
    refs.wfTools.textContent = `Error: ${error.message}\n\n${hint}`;
  } finally {
    setWorkflowBusy(false);
  }
}

async function handleStep3() {
  const tokenType = (refs.wfMcpTokenType && refs.wfMcpTokenType.value) || "obo-jwt";
  await callMCPTools(tokenType);
}

function handleClearJWTs() {
  state.workflow.userJwt = "";
  state.workflow.oboJwt = "";
  refs.wfUserJwt.textContent = "(not generated yet)";
  refs.wfOboJwt.textContent = "(not exchanged yet)";
  setWorkflowStatus("User and OBO JWTs cleared. You can run step 3 without a JWT to see 401.");
}

async function handleContextsClear() {
  try {
    const response = await fetch("/api/events/clear", { method: "POST" });
    if (!response.ok) return;
    state.events = [];
    state.selectedId = null;
    render();
  } catch (_) {}
}

function initWorkflow() {
  refs.wfStep1.addEventListener("click", handleStep1);
  refs.wfStep2.addEventListener("click", handleStep2);
  refs.wfStep3.addEventListener("click", handleStep3);
  if (refs.wfClearJwts) refs.wfClearJwts.addEventListener("click", handleClearJWTs);
}

if (refs.contextsClear) {
  refs.contextsClear.addEventListener("click", handleContextsClear);
}
initWorkflow();
poll();
setInterval(poll, POLL_MS);
startLogStream();
