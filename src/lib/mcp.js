/**
 * HeaderGuard remote MCP server (v0.4.0). Hand-rolled JSON-RPC 2.0 over Streamable HTTP; no SDK, no dependencies.
 * Adapted from DnsGuard's src/lib/mcp.js (agent-ready recipe §2): transport, era handling and caps are unchanged;
 * SERVER_INFO, instructions, TOOLS, callTool()/summarizeScan(), the error-meta prefix and pass-through headers differ.
 *
 * Dual-era and stateless:
 *  - Modern (MCP 2026-07-28): every request carries params._meta["io.modelcontextprotocol/protocolVersion"] plus the
 *    MCP-Protocol-Version / Mcp-Method / Mcp-Name headers. Methods: server/discover, tools/list, tools/call.
 *  - Legacy (2025-11-25, 2025-06-18, 2025-03-26, 2024-11-05): initialize handshake, notifications/initialized, ping,
 *    tools/list, tools/call. JSON-RPC batches (max 10 messages, at most one tools/call) are accepted for legacy clients.
 *  - No sessions: no Mcp-Session-Id is ever issued; one sent by a client is ignored. GET/DELETE → 405 (no SSE stream).
 *  - Responses are always application/json (no SSE).
 *
 * Auth + limits are NOT implemented here: the router passes in authenticate() and runCheck() from app.js, the exact
 * functions behind GET /api/scan, so key handling, the result cache and the per-minute limiters are identical.
 * One tools/call = one scan. initialize / tools/list / ping / server/discover never touch scan quota; they have a
 * light per-isolate cap per IP bucket (DISCOVERY_PER_MIN; IPv6 is bucketed by /64).
 */
import { VERSION } from './scan.js';
import { WEIGHTS, LEAK_PENALTY_MAX, NO_HTTPS_CAP } from './analyze.js';

export const MODERN_VERSIONS = ['2026-07-28'];
export const LEGACY_VERSIONS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
export const SUPPORTED_VERSIONS = [...MODERN_VERSIONS, ...LEGACY_VERSIONS];
export const MAX_BODY_BYTES = 64 * 1024;
export const MAX_BATCH = 10;
export const MAX_CHECKS_PER_REQUEST = 1; // bounds CPU/subrequests per invocation and keeps 1 HTTP request ≈ 1 scan
export const DISCOVERY_PER_MIN = 120; // per IP per isolate, for non-check messages (initialize, tools/list, ping, …)
const PASS_HEADERS = ['retry-after', 'x-cache', 'x-plan']; // what GET /api/scan sends
const META_VERSION = 'io.modelcontextprotocol/protocolVersion';
const META_CAPS = 'io.modelcontextprotocol/clientCapabilities';
const META_SERVER = 'io.modelcontextprotocol/serverInfo';

// JSON-RPC / MCP error codes
export const E = {
  PARSE: -32700, INVALID_REQUEST: -32600, METHOD_NOT_FOUND: -32601, INVALID_PARAMS: -32602, INTERNAL: -32603,
  SERVER: -32000, // implementation-defined (auth, rate limit, body too large, forbidden origin)
  HEADER_MISMATCH: -32020, UNSUPPORTED_VERSION: -32022,
};

export const MCP_CORS = {
  // License keys are explicit headers (never ambient cookies), so a wildcard origin without credentials is safe and
  // lets browser-based MCP inspectors work. Same policy as /api/scan.
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'POST, OPTIONS', // GET/DELETE → 405 (no SSE stream, no sessions)
  'access-control-allow-headers': 'content-type, accept, authorization, x-license-key, mcp-protocol-version, mcp-method, mcp-name',
  'access-control-expose-headers': ['mcp-protocol-version', ...PASS_HEADERS].join(', '),
  'access-control-max-age': '86400',
};

const W = WEIGHTS;
export const SERVER_INFO = { name: 'headerguard', title: 'HeaderGuard', version: VERSION };
export const instructions = (L = {}) => 'HeaderGuard scans the HTTP security headers of a public website (HTTPS redirect, HSTS, Content-Security-Policy, X-Frame-Options / frame-ancestors, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP/CORP/COEP, cookie flags, version leaks) and returns a 0–100 score, an A+–F grade, per-header findings and copy-paste fixes. Call scan_headers with a URL or a bare domain such as example.com. Only public http(s) hosts on ports 80, 443, 8080 and 8443 can be scanned; private, loopback and internal addresses are refused. If the site blocks or challenges the scanner, no grade is given (gradeWithheld: true). Results are cached for 2 minutes. Without a key, use is limited to about ' + (L.anonPerMin ?? 30) + ' scans per minute per IP; send "Authorization: Bearer <HeaderGuard Pro license key>" (or X-License-Key) for about ' + (L.proPerMin ?? 120) + ' per minute.';

const findingSchema = {
  type: 'object',
  properties: {
    id: { type: 'string', description: 'https, hsts, csp, framing, xcto, referrer, permissions, coop, corp, cookies, coep, xxss or leaks' },
    name: { type: 'string' },
    status: { type: 'string', enum: ['pass', 'warn', 'fail', 'info'] },
    points: { type: 'number' },
    max: { type: 'number' },
    summary: { type: 'string' },
    notes: { type: 'array', items: { type: 'object', properties: { level: { type: 'string', enum: ['pass', 'info', 'warn', 'fail'] }, text: { type: 'string' } }, required: ['level', 'text'] } },
  },
  required: ['id', 'name', 'status', 'points', 'max', 'notes'],
};
const fixSchema = {
  type: 'object',
  properties: {
    id: { type: 'string' },
    title: { type: 'string' },
    header: { type: 'string', description: 'Header to send (omitted for non-header fixes such as the HTTPS redirect)' },
    value: { type: 'string', description: 'Recommended value (a fixed, conservative constant)' },
    note: { type: 'string' },
  },
  required: ['id', 'title'],
};

export const TOOLS = [{
  name: 'scan_headers',
  title: 'Scan a website\'s HTTP security headers (HSTS, CSP, framing, COOP/CORP/COEP, cookies)',
  description: `Scan the HTTP security headers of a public website. Returns a 0–100 score and A+–F grade (HTTPS ${W.https}, HSTS ${W.hsts}, CSP ${W.csp}, framing ${W.framing}, X-Content-Type-Options ${W.xcto}, Referrer-Policy ${W.referrer}, Permissions-Policy ${W.permissions}, COOP ${W.coop}, CORP ${W.corp}, cookies ${W.cookies}, minus up to ${LEAK_PENALTY_MAX} for version-leak headers; without HTTPS the score is capped at ${NO_HTTPS_CAP}), each header's status and notes, recommended fix headers, and a link to the full report with copy-paste snippets for nginx, Apache, Cloudflare, Netlify, Vercel and Express. Read-only: it sends ordinary GET requests to the site (following up to 10 redirects, each safety-checked) and never reads page bodies. Same engine and scoring as the HeaderGuard JSON API (GET /api/scan).`,
  inputSchema: {
    type: 'object',
    properties: {
      url: { type: 'string', minLength: 1, maxLength: 2048, description: 'URL or bare domain to scan, e.g. example.com or https://example.com/login. A bare domain is scanned as https://<domain>/ (plain HTTP if HTTPS does not answer).' },
      include_raw: { type: 'boolean', default: false, description: 'Also return the full /api/scan JSON (redirect chain, all response headers with cookie values redacted, per-platform fix snippets) in structuredContent.raw. Larger output.' },
    },
    required: ['url'],
    additionalProperties: false,
  },
  outputSchema: {
    type: 'object',
    properties: {
      url: { type: 'string', description: 'Normalized URL that was scanned' },
      finalUrl: { type: 'string' },
      finalStatus: { type: 'number' },
      redirectCount: { type: 'number' },
      score: { type: 'number', description: 'Omitted when the grade is withheld' },
      grade: { type: 'string', enum: ['A+', 'A', 'B', 'C', 'D', 'F'], description: 'Omitted when the grade is withheld' },
      gradeWithheld: { type: 'boolean', description: 'true when the site blocked, rate-limited or challenged the scanner' },
      gradeWithheldReason: { type: 'string' },
      reliability: { type: 'string', enum: ['ok', 'blocked_or_challenged'] },
      findings: { type: 'array', items: findingSchema },
      fixes: { type: 'array', items: fixSchema },
      notes: { type: 'array', items: { type: 'string' } },
      scannedAt: { type: 'string' },
      cached: { type: 'boolean' },
      plan: { type: 'string', enum: ['free', 'pro'] },
      reportUrl: { type: 'string' },
      apiUrl: { type: 'string' },
      version: { type: 'string' },
      raw: { type: 'object', description: 'Full /api/scan response (only when include_raw is true)' },
    },
    required: ['url', 'finalUrl', 'gradeWithheld', 'reliability', 'findings', 'fixes', 'plan', 'reportUrl'],
  },
  annotations: { title: 'Scan security headers', readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
}];
const TOOL_ARGS = new Set(Object.keys(TOOLS[0].inputSchema.properties)); // inputSchema says additionalProperties: false; enforced in callTool

const clip = (s, n) => (typeof s === 'string' && s.length > n ? `${s.slice(0, n - 1)}…` : s);
const str = (v, n) => clip(String(v ?? ''), n);

/** Concise, schema-conforming summary of a full /api/scan body. Remote data is always clipped and capped. */
export function summarizeScan(body, { origin, input, cached, includeRaw }) {
  const q = `url=${encodeURIComponent(input)}`;
  const out = {
    url: str(body.url, 600),
    finalUrl: str(body.finalUrl, 600),
    ...(typeof body.finalStatus === 'number' ? { finalStatus: body.finalStatus } : {}),
    redirectCount: Array.isArray(body.redirects) ? Math.max(0, body.redirects.length - 1) : 0,
    ...(typeof body.score === 'number' ? { score: body.score } : {}),
    ...(typeof body.grade === 'string' ? { grade: body.grade } : {}),
    gradeWithheld: !!body.gradeWithheld,
    ...(typeof body.gradeWithheldReason === 'string' ? { gradeWithheldReason: str(body.gradeWithheldReason, 600) } : {}),
    reliability: body.reliability === 'blocked_or_challenged' ? 'blocked_or_challenged' : 'ok',
    findings: (Array.isArray(body.findings) ? body.findings : []).slice(0, 16).map((f) => ({
      id: str(f.id, 40),
      name: str(f.name, 80),
      status: ['pass', 'warn', 'fail', 'info'].includes(f.status) ? f.status : 'info',
      points: Number(f.points) || 0,
      max: Number(f.max) || 0,
      ...(f.summary ? { summary: str(f.summary, 300) } : {}),
      notes: (Array.isArray(f.notes) ? f.notes : []).slice(0, 6).map((n) => ({ level: ['pass', 'info', 'warn', 'fail'].includes(n && n.level) ? n.level : 'info', text: str(n && n.text, 300) })),
    })),
    fixes: ((body.fixes && Array.isArray(body.fixes.items)) ? body.fixes.items : []).slice(0, 12).map((x) => ({
      id: str(x.id, 40),
      title: str(x.title, 120),
      ...(x.header ? { header: str(x.header, 120) } : {}),
      ...(x.value ? { value: str(x.value, 600) } : {}),
      ...(x.note ? { note: str(x.note, 600) } : {}),
    })),
    notes: (Array.isArray(body.notes) ? body.notes : []).slice(0, 8).map((n) => str(n && typeof n === 'object' ? n.text : n, 400)),
    ...(body.meta && body.meta.scannedAt ? { scannedAt: String(body.meta.scannedAt) } : {}),
    cached: !!cached,
    plan: body.plan === 'pro' ? 'pro' : 'free',
    reportUrl: `${origin}/?${q}`,
    apiUrl: `${origin}/api/scan?${q}`,
    version: (body.meta && body.meta.version) || VERSION,
  };
  if (includeRaw) out.raw = body;
  return out;
}

/** Human/LLM-readable text version of the summary (also the content[0] block). */
export function summaryText(s) {
  const head = s.gradeWithheld
    ? `HeaderGuard scan of ${s.finalUrl}: not graded (the site blocked or challenged the scanner, so the headers below belong to a block page).`
    : `HeaderGuard scan of ${s.finalUrl}: ${s.score}/100 (grade ${s.grade}).`;
  const lines = [head];
  for (const f of s.findings) {
    const worst = f.notes.find((n) => n.level === 'fail') || f.notes.find((n) => n.level === 'warn') || f.notes[0];
    lines.push(`- ${f.name}: ${f.status.toUpperCase()} ${f.points}/${f.max}${f.summary ? ` (${f.summary})` : ''}${worst && f.status !== 'pass' ? ` — ${worst.text}` : ''}`);
  }
  const fixes = s.fixes.map((x) => (x.header ? `- ${x.title}: ${x.header}: ${x.value}` : `- ${x.title}`));
  if (fixes.length) lines.push('', 'Recommended fixes (copy-paste snippets per platform in the full report):', ...fixes.slice(0, 8));
  if (s.notes.length) lines.push('', 'Notes:', ...s.notes.map((n) => `- ${n}`));
  lines.push('', `Full report: ${s.reportUrl}`);
  return lines.join('\n');
}

function toolError(message, data, extra = {}) {
  return { content: [{ type: 'text', text: message }], isError: true, ...(data ? { _meta: { 'headerguard/error': data } } : {}), ...extra };
}

/** tools/call for scan_headers. Returns { result } or { error } (protocol error), plus HTTP headers to surface. */
async function callTool(params, deps, auth) {
  const { name } = params;
  const args = params.arguments === undefined ? {} : params.arguments;
  if (name !== 'scan_headers') return { error: { code: E.INVALID_PARAMS, message: `Unknown tool: ${clip(String(name), 80)}` } };
  if (!args || typeof args !== 'object' || Array.isArray(args)) return { error: { code: E.INVALID_PARAMS, message: 'arguments must be an object' } };
  // Input problems are tool-execution errors (isError) so the model can correct itself.
  const unknown = Object.keys(args).filter((k) => !TOOL_ARGS.has(k));
  if (unknown.length) {
    return { result: toolError(`Unknown argument(s): ${clip(unknown.slice(0, 5).join(', '), 80)}. Allowed: ${[...TOOL_ARGS].join(', ')}.`, { code: 'invalid_arguments', httpStatus: 400 }) };
  }
  if (args.url !== undefined && typeof args.url !== 'string') return { result: toolError('url must be a string.', { code: 'invalid_url', httpStatus: 400 }) };
  if (args.include_raw !== undefined && typeof args.include_raw !== 'boolean') return { result: toolError('include_raw must be true or false.', { code: 'invalid_arguments', httpStatus: 400 }) };
  const input = typeof args.url === 'string' ? args.url : '';
  // Same validation, cache and limiter as GET /api/scan (runCheck). Empty / bad / private URLs → invalid_url, blocked_target, …
  const r = await deps.runCheck({ input: { url: input }, auth, env: deps.env, ctx: deps.ctx, ip: deps.ip, doFetch: deps.doFetch, selfHosts: deps.selfHosts });
  const headers = { ...(r.headers || {}) };
  if (!r.ok) {
    const retry = r.headers && r.headers['retry-after'] ? Number(r.headers['retry-after']) : undefined;
    const msg = `${r.message}${retry ? ` (retry after ${retry} seconds)` : ''}`;
    const upgradeUrl = r.code === 'rate_limited' && r.more && r.more.upgradeUrl ? r.more.upgradeUrl : undefined;
    return { result: toolError(msg, { code: r.code, httpStatus: r.status, ...(retry ? { retryAfterSeconds: retry } : {}), ...(upgradeUrl ? { upgradeUrl } : {}) }), headers };
  }
  const summary = summarizeScan(r.body, { origin: deps.origin, input: input.trim(), cached: r.cached, includeRaw: args.include_raw === true });
  return { result: { content: [{ type: 'text', text: summaryText(summary) }], structuredContent: summary, isError: false }, headers };
}

// ---------- transport helpers ----------

/** Origin policy: absent = OK (CLI / server-side clients). Present: must be a bare https origin or an http loopback
 * origin, or (if MCP_ALLOWED_ORIGINS is set) same-origin / listed. Malformed, "null" and plain-http remote → 403. */
export function originAllowed(origin, selfOrigin, allowList) {
  if (origin === null || origin === undefined) return true;
  if (origin === selfOrigin) return true;
  if (allowList) return String(allowList).split(',').map((s) => s.trim()).filter(Boolean).includes(origin);
  let u;
  try { u = new URL(origin); } catch { return false; }
  if (u.origin !== origin) return false;
  if (u.protocol === 'https:') return true;
  return u.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
}

async function readCapped(request, cap) {
  const cl = Number(request.headers.get('content-length'));
  if (Number.isFinite(cl) && cl > cap) return null;
  if (!request.body) return '';
  const reader = request.body.getReader();
  const chunks = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > cap) { try { await reader.cancel(); } catch { /* ignore */ } return null; }
    chunks.push(value);
  }
  const buf = new Uint8Array(size);
  let o = 0;
  for (const c of chunks) { buf.set(c, o); o += c.byteLength; }
  return new TextDecoder().decode(buf);
}

function decodeHeaderValue(v) {
  if (v == null) return v;
  const m = /^=\?base64\?([A-Za-z0-9+/=]*)\?=$/.exec(v);
  if (!m) return v;
  try { return new TextDecoder().decode(Uint8Array.from(atob(m[1]), (ch) => ch.charCodeAt(0))); } catch { return null; }
}

const isId = (id) => typeof id === 'string' || (typeof id === 'number' && Number.isFinite(id));
const rpcError = (id, code, message, data) => ({ jsonrpc: '2.0', ...(id !== undefined ? { id } : {}), error: { code, message, ...(data !== undefined ? { data } : {}) } });
const rpcResult = (id, result) => ({ jsonrpc: '2.0', id, result });

/**
 * Handle one JSON-RPC message. Returns { response?, status?, headers?, isCheck? }.
 * `response` undefined = notification accepted (202 when it's the whole request).
 */
async function handleMessage(msg, { modern, request, deps, auth, checkBudget }) {
  if (!msg || typeof msg !== 'object' || Array.isArray(msg)) return { response: rpcError(null, E.INVALID_REQUEST, 'Invalid Request'), status: 400 };
  const hasId = Object.prototype.hasOwnProperty.call(msg, 'id');
  if (msg.jsonrpc !== '2.0') return { response: rpcError(hasId && isId(msg.id) ? msg.id : null, E.INVALID_REQUEST, 'Invalid Request: jsonrpc must be "2.0"'), status: 400 };
  if (typeof msg.method !== 'string') {
    // A JSON-RPC response or garbage. Legacy clients may POST responses → accept like a notification.
    if (!modern && hasId && ('result' in msg || 'error' in msg)) return {};
    return { response: rpcError(hasId && isId(msg.id) ? msg.id : null, E.INVALID_REQUEST, 'Invalid Request: method is required'), status: 400 };
  }
  if (!hasId) return {}; // notification (notifications/initialized, cancelled, …): accepted, nothing to do
  if (!isId(msg.id)) return { response: rpcError(null, E.INVALID_REQUEST, 'Invalid Request: id must be a string or number'), status: 400 };
  const { id, method } = msg;
  const params = msg.params === undefined ? {} : msg.params;
  if (!params || typeof params !== 'object' || Array.isArray(params)) return { response: rpcError(id, E.INVALID_PARAMS, 'params must be an object') };

  const done = (result) => ({ response: rpcResult(id, modern ? { resultType: 'complete', ...result, _meta: { ...(result._meta || {}), [META_SERVER]: SERVER_INFO } } : result) });
  const notFound = () => ({ response: rpcError(id, E.METHOD_NOT_FOUND, `Method not found: ${clip(method, 80)}`), status: modern ? 404 : 200 });

  if (modern) {
    // MCP 2026-07-28 per-request validation (version, capabilities, mirrored headers).
    const hName = decodeHeaderValue(request.headers.get('mcp-name'));
    if (request.headers.get('mcp-method') !== method) return { response: rpcError(id, E.HEADER_MISMATCH, 'Header mismatch: Mcp-Method header is missing or does not match the body method'), status: 400 };
    if (!params._meta || typeof params._meta[META_CAPS] !== 'object' || params._meta[META_CAPS] === null) {
      return { response: rpcError(id, E.INVALID_PARAMS, `Missing required _meta field ${META_CAPS}`), status: 400 };
    }
    if (method === 'tools/call' && hName !== params.name) return { response: rpcError(id, E.HEADER_MISMATCH, 'Header mismatch: Mcp-Name header is missing or does not match params.name'), status: 400 };
    if (method === 'server/discover') {
      return done({ supportedVersions: SUPPORTED_VERSIONS, capabilities: { tools: { listChanged: false } }, instructions: instructions(deps.limits), ttlMs: 3_600_000, cacheScope: 'public' });
    }
    if (method === 'tools/list') return done({ tools: TOOLS, ttlMs: 3_600_000, cacheScope: 'public' });
    if (method !== 'tools/call') return notFound(); // includes initialize and ping (removed in 2026-07-28)
  } else {
    if (method === 'initialize') {
      const req = params.protocolVersion;
      const protocolVersion = LEGACY_VERSIONS.includes(req) ? req : LEGACY_VERSIONS[0];
      return done({ protocolVersion, capabilities: { tools: { listChanged: false } }, serverInfo: SERVER_INFO, instructions: instructions(deps.limits) });
    }
    if (method === 'ping') return done({});
    if (method === 'tools/list') return done({ tools: TOOLS });
    if (method === 'server/discover') return done({ supportedVersions: SUPPORTED_VERSIONS, capabilities: { tools: { listChanged: false } }, serverInfo: SERVER_INFO, instructions: instructions(deps.limits) });
    if (method !== 'tools/call') return notFound();
  }

  // tools/call
  if (typeof params.name !== 'string') return { response: rpcError(id, E.INVALID_PARAMS, 'params.name (tool name) is required') };
  if (checkBudget.used >= MAX_CHECKS_PER_REQUEST) {
    return { response: rpcError(id, E.INVALID_REQUEST, `At most ${MAX_CHECKS_PER_REQUEST} tools/call per HTTP request; send each call as its own request.`) };
  }
  checkBudget.used++;
  const r = await callTool(params, deps, auth);
  if (r.error) return { response: rpcError(id, r.error.code, r.error.message), isCheck: true };
  return { ...done(r.result), headers: r.headers, isCheck: true };
}

/** Entry point from the router for every request to /mcp. */
export async function handleMcp(request, env, ctx, deps) {
  const base = { ...deps.cors, ...deps.security };
  const reply = (status, body, extra = {}) => new Response(body === null ? null : JSON.stringify(body), {
    status,
    headers: { ...(body === null ? {} : { 'content-type': 'application/json; charset=utf-8' }), 'cache-control': 'no-store', ...base, ...extra },
  });
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: { ...deps.cors } });
  if (!originAllowed(request.headers.get('origin'), deps.origin, deps.allowedOrigins)) {
    return reply(403, rpcError(undefined, E.SERVER, 'Forbidden: Origin not allowed'));
  }
  if (request.method !== 'POST') {
    return reply(405, rpcError(undefined, E.SERVER, 'Method not allowed. This MCP endpoint is stateless: POST JSON-RPC messages (no SSE stream, no sessions). Docs: /llms.txt'), { allow: 'POST, OPTIONS' });
  }
  const text = await readCapped(request, MAX_BODY_BYTES);
  if (text === null) return reply(413, rpcError(undefined, E.INVALID_REQUEST, `Request body too large (max ${MAX_BODY_BYTES} bytes)`));
  let payload;
  try { payload = JSON.parse(text); } catch { return reply(400, rpcError(null, E.PARSE, 'Parse error: body must be valid JSON')); }

  // Era detection. Modern = per-request _meta version or a modern MCP-Protocol-Version header.
  const hVer = request.headers.get('mcp-protocol-version');
  const single = !Array.isArray(payload);
  const metaVer = single && payload && typeof payload === 'object' && payload.params && typeof payload.params === 'object'
    && payload.params._meta && typeof payload.params._meta === 'object' ? payload.params._meta[META_VERSION] : undefined;
  const modern = metaVer !== undefined || MODERN_VERSIONS.includes(hVer);
  const idOf = (p) => (p && typeof p === 'object' && isId(p.id) ? p.id : null);
  if (modern) {
    if (!single) return reply(400, rpcError(null, E.INVALID_REQUEST, 'JSON-RPC batches are not supported in protocol 2026-07-28; send one message per POST'));
    if (payload && typeof payload === 'object' && Object.prototype.hasOwnProperty.call(payload, 'id')) {
      if (metaVer === undefined && typeof payload.method === 'string') {
        return reply(400, rpcError(idOf(payload), E.INVALID_PARAMS, `Missing required _meta field ${META_VERSION}`));
      }
      if (metaVer !== undefined && !SUPPORTED_VERSIONS.includes(metaVer)) {
        return reply(400, rpcError(idOf(payload), E.UNSUPPORTED_VERSION, 'Unsupported protocol version', { supported: SUPPORTED_VERSIONS, requested: clip(String(metaVer), 40) }));
      }
      if (metaVer !== undefined && !MODERN_VERSIONS.includes(metaVer)) {
        return reply(400, rpcError(idOf(payload), E.UNSUPPORTED_VERSION, `Protocol version ${metaVer} uses the initialize handshake; per-request _meta requires one of: ${MODERN_VERSIONS.join(', ')}`, { supported: SUPPORTED_VERSIONS, requested: metaVer }));
      }
      if (hVer !== metaVer) return reply(400, rpcError(idOf(payload), E.HEADER_MISMATCH, 'Header mismatch: MCP-Protocol-Version header is missing or does not match _meta protocolVersion'));
    }
  } else if (hVer && !LEGACY_VERSIONS.includes(hVer)) {
    return reply(400, rpcError(single ? idOf(payload) : null, E.UNSUPPORTED_VERSION, 'Unsupported protocol version', { supported: SUPPORTED_VERSIONS, requested: clip(hVer, 40) }));
  }

  const msgs = single ? [payload] : payload;
  if (!msgs.length) return reply(400, rpcError(null, E.INVALID_REQUEST, 'Invalid Request: empty batch'));
  if (msgs.length > MAX_BATCH) return reply(400, rpcError(null, E.INVALID_REQUEST, `Batch too large (max ${MAX_BATCH} messages)`));

  // Light per-IP-bucket cap on non-check messages (scans are governed by the /api/scan limits inside runCheck).
  const nonCheck = msgs.filter((m) => !(m && m.method === 'tools/call')).length;
  for (let i = 0; i < nonCheck; i++) {
    if (!deps.memLimit(`mcp:${deps.ipBucket ?? deps.ip}`, DISCOVERY_PER_MIN, 60_000)) {
      return reply(429, rpcError(single ? idOf(payload) : null, E.SERVER, `Too many MCP requests from your IP (about ${DISCOVERY_PER_MIN} per minute). Retry in a minute.`, { code: 'rate_limited', retryAfterSeconds: 60 }), { 'retry-after': '60' });
    }
  }

  // Same key gate as /api/scan, evaluated once per HTTP request (a bad key fails every method with the /api status).
  const auth = await deps.authenticate(request, env);
  if (!auth.ok) {
    // No WWW-Authenticate on /mcp: MCP clients treat a 401 Bearer challenge as "start OAuth discovery", which this
    // server doesn't offer; the JSON-RPC error body (data.code = license_invalid, …) is the useful signal.
    // The masked keyHint that /api returns is deliberately left out here.
    const extra = { ...(auth.headers || {}) };
    const upgradeUrl = auth.more && auth.more.upgradeUrl;
    return reply(auth.status, rpcError(single ? idOf(payload) : null, E.SERVER, auth.message, { code: auth.code, httpStatus: auth.status, ...(upgradeUrl ? { upgradeUrl } : {}) }), extra);
  }

  const mdeps = { ...deps, env, ctx };
  const checkBudget = { used: 0 };
  const responses = [];
  let status = 200;
  let headers = {};
  for (const m of msgs) {
    let out;
    try {
      out = await handleMessage(m, { modern, request, deps: mdeps, auth, checkBudget });
    } catch {
      out = { response: rpcError(idOf(m), E.INTERNAL, 'Internal error') };
    }
    if (out.response) responses.push(out.response);
    if (single) status = out.status || 200;
    if (out.headers) headers = out.headers; // at most one tools/call per request, so batches surface its headers too
  }
  if (!responses.length) return reply(202, null);
  const exposed = {};
  for (const h of PASS_HEADERS) if (headers[h]) exposed[h] = headers[h];
  return reply(status, single ? responses[0] : responses, exposed);
}
