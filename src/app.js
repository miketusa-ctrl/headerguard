// Request router. Kept free of Worker-only imports so it can be unit-tested in Node.
import { scan, ScanError, VERSION } from './lib/scan.js';
import { normalizeTarget, TargetError } from './lib/target.js';
import {
  normalizeBadgeHost, renderBadgeSvg, badgeLabelFromScan, badgeCacheKey,
  BADGE_CACHE_TTL_OK_S, BADGE_CACHE_TTL_ERR_S, BADGE_BROWSER_MAX_AGE_S, BADGE_LIMIT_PER_MIN,
} from './lib/badge.js';
import { validateFleetLicense, clearFleetLicenseCache, maskLicenseKey } from './lib/fleet-license.js';
import {
  PRO_PRODUCT_SLUG, DEFAULT_PRO_SCAN_LIMIT_PER_MIN, BATCH_MAX_URLS,
  extractLicenseKey, hashLicenseKey, checkoutUrl, portalUrl, licenseErrorResponse,
} from './lib/pro.js';
import { limitsFor } from './lib/limits.js';
import { handleMcp, MCP_CORS } from './lib/mcp.js';
import { isRapidApiPath, handleRapidApi } from './lib/rapidapi.js';
import { countVisitor } from './lib/visitors.js';
import { llmsTxt, openApiSpec, serverCard } from './lib/agentdocs.js';

export const GLAMA_CLAIM = '{"$schema":"https://glama.ai/mcp/schemas/connector.json","claim":"<GLAMA_CLAIM_TOKEN>"}';
export const CANONICAL_HOST = 'headerguard.mike-tusa.workers.dev';
const CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, POST, OPTIONS',
  'access-control-allow-headers': 'content-type, authorization, x-license-key',
  'access-control-max-age': '86400',
};
const SECURITY = {
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'x-frame-options': 'DENY',
  'permissions-policy': 'camera=(), microphone=(), geolocation=(), usb=(), payment=()',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin',
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
};
// API responses must be readable cross-origin (CORS), so they get CORP cross-origin instead of same-origin.
const API_SECURITY = { ...SECURITY, 'cross-origin-resource-policy': 'cross-origin' };
export const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
// SVG badges: no scripts; inline style only for the shields gradient. CORP cross-origin so READMEs can embed them.
export const BADGE_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; font-src 'none'; connect-src 'none'; script-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
const BADGE_SECURITY = {
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'content-security-policy': BADGE_CSP,
  'cross-origin-resource-policy': 'cross-origin',
  'x-frame-options': 'DENY',
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
};

// Per-isolate best-effort state (the Workers Rate Limiting binding is authoritative when bound).
const memLimits = new Map();
const resultCache = new Map();
export const CACHE_TTL_MS = 120_000;
export function _resetForTests() { memLimits.clear(); resultCache.clear(); clearFleetLicenseCache(); }

function memLimit(key, limit, periodMs) {
  const now = Date.now();
  const e = memLimits.get(key);
  if (!e || now - e.start > periodMs) { memLimits.set(key, { start: now, n: 1 }); if (memLimits.size > 5000) memLimits.clear(); return true; }
  e.n++;
  return e.n <= limit;
}

function json(body, status = 200, extra = {}) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...CORS, ...API_SECURITY, ...extra },
  });
}
const apiError = (status, code, message, extra = {}, more = {}) => json({ error: { code, message, ...more } }, status, extra);

export function staging(env) { return String(env.PUBLIC_LAUNCH || 'false') !== 'true'; }

async function rateLimited(env, key, limit, kind = 'scan', bindingName = 'SCAN_LIMITER') {
  const binding = env[bindingName];
  if (binding && typeof binding.limit === 'function') {
    try { const { success } = await binding.limit({ key: `${kind}:${key}` }); return !success; } catch { /* fall back */ }
  }
  return !memLimit(`${kind}:${key}`, limit, 60_000);
}

/** IPv4 as is; IPv6 → its /64 (one subscriber controls a whole /64). Same output as workdayapi's (agent-ready recipe §1). */
export function ipBucket(ip) {
  const s = String(ip || 'unknown').trim().toLowerCase();
  if (!s.includes(':')) return s;
  if (s.includes('.')) return s.slice(s.lastIndexOf(':') + 1); // IPv4-mapped ::ffff:a.b.c.d
  const [h, t] = s.split('::'), head = h ? h.split(':') : [], tail = t ? t.split(':') : [];
  const parts = t === undefined ? head : [...head, ...Array(Math.max(0, 8 - head.length - tail.length)).fill('0'), ...tail];
  return parts.slice(0, 4).map((x) => x.replace(/^0+(?=.)/, '') || '0').join(':') + '::/64';
}

/**
 * v0.4.0: the key gate shared by every /api route and POST /mcp (identical behaviour = auth parity).
 * No key → { ok:true, plan:'free' }. Valid HDRG license → { ok:true, plan:'pro', licenseHash }.
 * A key that is not a valid HeaderGuard Pro license → { ok:false, status 401|403, code, message, headers, more }.
 * Never returns, logs or echoes the raw key (more.keyHint is the masked form used by /api since v0.3.0).
 */
export async function authenticate(request, env = {}) {
  const key = extractLicenseKey(request);
  if (!key) return { ok: true, plan: 'free', licenseHash: null };
  const result = await validateFleetLicense(env.LICENSES, key, PRO_PRODUCT_SLUG);
  if (!result.valid) {
    // A key was sent but is not valid for HeaderGuard Pro — do not silently fall back to free.
    const err = licenseErrorResponse(result.reason, env);
    return {
      ok: false, status: err.status, code: err.code, message: err.message, headers: {},
      more: { plan: 'free', reason: result.reason, upgradeUrl: err.upgradeUrl, keyHint: maskLicenseKey(key) },
    };
  }
  return { ok: true, plan: 'pro', licenseHash: await hashLicenseKey(key) };
}

function withPlan(body, plan) {
  if (body && typeof body === 'object' && !Array.isArray(body)) return { ...body, plan };
  return body;
}

function rateLimitInfo(env, { plan, limit }) {
  const buy = checkoutUrl(env);
  const message = plan === 'pro'
    ? `Too many Pro scans for this license (about ${limit} per minute). Please wait a minute.`
    : `Too many scans from your IP (about ${limit} per minute). Please wait a minute, or get HeaderGuard Pro for higher limits: ${buy}`;
  return { status: 429, code: 'rate_limited', message, headers: { 'retry-after': '60' }, more: { plan, limitPerMin: limit, upgradeUrl: buy } };
}

function rateLimitError(env, opts) {
  const r = rateLimitInfo(env, opts);
  return apiError(r.status, r.code, r.message, r.headers, r.more);
}

/**
 * v0.4.0: one scan with the result cache and the per-plan per-minute limit applied exactly like GET /api/scan.
 * Used by /api/scan and by MCP tools/call, so one MCP tool call = one scan against the same counters and cache.
 * Order: input check → cache HIT (no limiter) → limiter (free: ipBucket(ip); Pro: license-key hash) → scan.
 * Returns { ok:true, body, headers, cached } | { ok:false, status, code, message, headers, more }.
 */
export async function runCheck({ input, auth, env = {}, ctx = {}, ip = 'local', doFetch, selfHosts = [CANONICAL_HOST] }) {
  void ctx;
  const plan = auth.plan;
  const raw = input && typeof input.url === 'string' ? input.url : '';
  const fail = (status, code, message, headers = {}, more = {}) => ({ ok: false, status, code, message, headers, more });
  let target;
  try { target = normalizeTarget(raw, { selfHosts }); } catch (e) {
    if (e instanceof TargetError) return fail(e.httpStatus, e.code, e.message, {}, { plan });
    throw e;
  }
  const cacheKey = (plan === 'pro' ? 'pro|' : '') + target.url.href + (target.explicitScheme ? '' : '|bare');
  const hit = resultCache.get(cacheKey);
  if (hit && Date.now() - hit.t < CACHE_TTL_MS) {
    return { ok: true, body: withPlan(hit.body, plan), headers: { 'x-cache': 'HIT', 'x-plan': plan }, cached: true };
  }
  const L = limitsFor(env);
  if (plan === 'rapidapi') {
    // v0.5.0: RapidAPI plan limit on its own per-tier binding (see src/lib/rapidapi.js); never the free pool or a Pro license.
    if (await auth.rapidLimited()) return fail(429, 'rate_limited', 'Too many requests for this RapidAPI plan.', { 'retry-after': '60' }, { plan });
  } else if (plan === 'pro') {
    if (await rateLimited(env, auth.licenseHash, L.proPerMin, 'pro-scan', 'PRO_SCAN_LIMITER')) {
      return { ok: false, ...rateLimitInfo(env, { plan: 'pro', limit: L.proPerMin }) };
    }
  } else if (await rateLimited(env, ipBucket(ip), L.anonPerMin, 'scan', 'SCAN_LIMITER')) {
    return { ok: false, ...rateLimitInfo(env, { plan: 'free', limit: L.anonPerMin }) };
  }
  try {
    const body = withPlan(await scan(raw, { fetchImpl: doFetch, selfHosts }), plan);
    resultCache.set(cacheKey, { t: Date.now(), body });
    if (resultCache.size > 300) resultCache.delete(resultCache.keys().next().value);
    return { ok: true, body, headers: { 'x-cache': 'MISS', 'x-plan': plan }, cached: false };
  } catch (e) {
    const more = e.chain && e.chain.length ? { redirects: e.chain } : {};
    if (e instanceof TargetError || e instanceof ScanError) return fail(e.httpStatus, e.code, e.message, {}, { ...more, plan });
    return fail(500, 'internal_error', 'Unexpected error while scanning.', {}, { plan });
  }
}

/** Scan each URL in order (no cache, like v0.3.0 batch). Shared by /api/scan/batch and /rapidapi/v1/scan/batch. */
async function scanBatch(urls, plan, { doFetch, selfHosts }) {
  const results = [];
  for (const raw of urls) {
    const entry = { input: typeof raw === 'string' ? raw : String(raw ?? '') };
    try {
      const body = await scan(entry.input, { fetchImpl: doFetch, selfHosts });
      results.push(withPlan({ ok: true, ...body }, plan));
    } catch (e) {
      if (e instanceof TargetError || e instanceof ScanError) {
        results.push({ ok: false, input: entry.input, error: { code: e.code, message: e.message }, plan });
      } else {
        results.push({ ok: false, input: entry.input, error: { code: 'internal_error', message: 'Unexpected error while scanning.' }, plan });
      }
    }
  }
  return results;
}

export function createApp({ html, docs, js, css, fetchImpl, cache } = {}) {
  const route = createRouter({ html, docs, js, css, fetchImpl, cache });
  return async function handle(request, env = {}, ctx = {}) {
    let res;
    try {
      res = await route(request, env, ctx);
    } catch {
      // Safety net: never let an exception become a Workers 1101 page.
      res = apiError(500, 'internal_error', 'Unexpected server error. Please retry.');
    }
    // Staging (PUBLIC_LAUNCH !== "true"): every response carries noindex. Public: the header is removed everywhere.
    if (staging(env)) res.headers.set('x-robots-tag', 'noindex, nofollow');
    else res.headers.delete('x-robots-tag');
    return res;
  };
}

function createRouter({ html, docs, js, css, fetchImpl, cache }) {
  return async function route(request, env = {}, ctx = {}) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, '') || '/';
    const ip = request.headers.get('cf-connecting-ip') || 'local';
    const doFetch = fetchImpl || ((...a) => fetch(...a)); // never pass bare `fetch` (Illegal invocation on Workers)
    const selfHosts = [url.hostname.toLowerCase(), CANONICAL_HOST];
    // Workers Cache API (caches.default) when available; tests inject a Map-backed fake via createApp({ cache }).
    const cacheStore = cache || (typeof caches !== 'undefined' && caches.default) || null;
    const waitUntil = (p) => { try { if (ctx && typeof ctx.waitUntil === 'function') ctx.waitUntil(p); else Promise.resolve(p).catch(() => {}); } catch { /* ignore */ } };

    if (request.method === 'OPTIONS' && path.startsWith('/api/')) return new Response(null, { status: 204, headers: { ...CORS } });

    // v0.5.0 daily unique visitors (shared pattern, src/lib/visitors.js): human/API entry points only; off unless VISITOR_SALT is
    // set.
    if ((request.method === 'GET' && (path === '/' || path === '/api/scan')) || (request.method === 'POST' && path === '/mcp')) {
      countVisitor(request, env, ctx, ipBucket(ip));
    }

    // v0.5.0 RapidAPI marketplace route: proxy-secret gate first (constant time), then the same scan/cache/SSRF as /api/scan.
    // Routed before the Polar key gate: RapidAPI callers are authenticated by the proxy secret, not by an HDRG key.
    if (isRapidApiPath(path)) {
      return handleRapidApi(request, env, ctx, path, url, {
        json, apiError, runCheck, rateLimited, ip, ipBucket: ipBucket(ip), doFetch, selfHosts, version: VERSION, batchMax: BATCH_MAX_URLS,
        scanBatch: (urls, plan) => scanBatch(urls, plan, { doFetch, selfHosts }),
      });
    }

    // v0.4.0: remote MCP server (Streamable HTTP, stateless, JSON responses). Same key gate, cache and limits as /api/scan.
    // Routed before the global key gate so MCP's own order applies (Origin → method → body cap → parse → discovery cap → key).
    if (path === '/mcp') {
      return handleMcp(request, env, ctx, {
        authenticate, runCheck, ip, ipBucket: ipBucket(ip), doFetch, origin: url.origin, memLimit, selfHosts,
        cors: MCP_CORS, security: SECURITY, allowedOrigins: env.MCP_ALLOWED_ORIGINS, limits: limitsFor(env),
      });
    }

    // v0.4.0: agent-discovery documents. Plain text / JSON (no HTML, so no page CSP needed); never key-gated.
    if (path === '/llms.txt' || path === '/openapi.json' || path === '/.well-known/mcp/server-card.json' || path === '/.well-known/mcp-registry-auth' || path === '/.well-known/glama.json') {
      if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: { ...CORS } });
      if (request.method !== 'GET' && request.method !== 'HEAD') return apiError(405, 'method_not_allowed', 'Use GET.', { allow: 'GET, HEAD, OPTIONS' });
      const head = request.method === 'HEAD';
      const doc = (body, type, cache = 'public, max-age=3600') => new Response(head ? null : body, { headers: { 'content-type': type, 'cache-control': cache, ...CORS, ...API_SECURITY } });
      // Glama connector ownership claim, served at /.well-known/glama.json. Replace the placeholder with your own claim token from glama.ai.
      if (path === '/.well-known/glama.json') return doc(GLAMA_CLAIM, 'application/json');
      if (path === '/llms.txt') return doc(llmsTxt(url.origin, limitsFor(env)), 'text/plain; charset=utf-8');
      if (path === '/openapi.json') return doc(JSON.stringify(openApiSpec(url.origin, limitsFor(env)), null, 2), 'application/json; charset=utf-8');
      if (path === '/.well-known/mcp/server-card.json') return doc(JSON.stringify(serverCard(url.origin, limitsFor(env)), null, 2), 'application/json; charset=utf-8');
      // Official MCP Registry HTTP namespace proof. Only the PUBLIC key lives in a wrangler var; 404 until it is set.
      const proof = String(env.MCP_REGISTRY_AUTH || '').trim();
      if (/^v=MCPv1; k=(ed25519|ecdsap384); p=[A-Za-z0-9+/=]{20,120}$/.test(proof)) return doc(`${proof}\n`, 'text/plain; charset=utf-8', 'no-store');
      return new Response('Not found', { status: 404, headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store', ...SECURITY } });
    }
    // We don't implement MCP OAuth: clients probing for it must get a 404, never an HTML 200.
    if (path === '/.well-known/oauth-protected-resource' || path.startsWith('/.well-known/oauth-protected-resource/') || path === '/.well-known/oauth-authorization-server') {
      return new Response('Not found', { status: 404, headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store', ...SECURITY } });
    }

    // ---- Key gate (free by default; Pro when a valid HDRG key is presented). Shared with /mcp via authenticate(). ----
    const auth = await authenticate(request, env);
    if (!auth.ok) return apiError(auth.status, auth.code, auth.message, auth.headers, auth.more);
    const plan = auth.plan;

    if (path === '/api/scan/batch') {
      if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: { ...CORS } });
      if (request.method !== 'POST') return apiError(405, 'method_not_allowed', 'Use POST /api/scan/batch with JSON { "urls": [...] }.', { allow: 'POST, OPTIONS' });
      if (plan !== 'pro') {
        const buy = checkoutUrl(env);
        return apiError(401, 'pro_required', `Batch scanning is a HeaderGuard Pro feature. Get Pro at ${buy}`, {}, { plan: 'free', upgradeUrl: buy });
      }
      let payload;
      try { payload = await request.json(); } catch {
        return apiError(400, 'invalid_json', 'Body must be JSON: { "urls": ["example.com", ...] }.');
      }
      const urls = payload && Array.isArray(payload.urls) ? payload.urls : null;
      if (!urls || urls.length === 0) return apiError(400, 'invalid_urls', 'Provide a non-empty "urls" array.');
      if (urls.length > BATCH_MAX_URLS) {
        return apiError(400, 'batch_too_large', `Batch is limited to ${BATCH_MAX_URLS} URLs per request (keeps each call inside the Workers subrequest budget).`, {}, { max: BATCH_MAX_URLS });
      }
      const proLimit = Number(env.PRO_SCAN_LIMIT_PER_MIN || DEFAULT_PRO_SCAN_LIMIT_PER_MIN);
      // Count each URL against the Pro per-key limit.
      for (let i = 0; i < urls.length; i++) {
        if (await rateLimited(env, auth.licenseHash, proLimit, 'pro-scan', 'PRO_SCAN_LIMITER')) {
          return rateLimitError(env, { plan: 'pro', limit: proLimit });
        }
      }
      const results = await scanBatch(urls, 'pro', { doFetch, selfHosts });
      return json({ plan: 'pro', count: results.length, results }, 200);
    }

    if (path === '/api/scan') {
      if (request.method !== 'GET' && request.method !== 'HEAD') return apiError(405, 'method_not_allowed', 'Use GET /api/scan?url=…', { allow: 'GET, OPTIONS' });
      const raw = url.searchParams.get('url') ?? url.searchParams.get('domain') ?? '';
      // Auth already ran above (before the cache), so an invalid key never gets a free cache HIT.
      const r = await runCheck({ input: { url: raw }, auth, env, ctx, ip, doFetch, selfHosts });
      if (!r.ok) return apiError(r.status, r.code, r.message, r.headers, r.more);
      return json(r.body, 200, r.headers);
    }

    // ---- Embeddable grade badge: GET /badge/<host>.svg ----
    const badgeMatch = /^\/badge\/(.+)\.svg$/i.exec(path);
    if (badgeMatch) {
      if (request.method !== 'GET' && request.method !== 'HEAD') {
        return new Response('Method not allowed', { status: 405, headers: { allow: 'GET, HEAD', 'content-type': 'text/plain; charset=utf-8', ...BADGE_SECURITY } });
      }
      const svgHeaders = (cacheControl, extra = {}) => ({
        'content-type': 'image/svg+xml; charset=utf-8',
        'cache-control': cacheControl,
        ...BADGE_SECURITY,
        ...CORS,
        ...extra,
      });
      const respondSvg = (svg, { ttlS, status = 'ok', cache = 'MISS' }) => {
        const browser = Math.min(BADGE_BROWSER_MAX_AGE_S, ttlS);
        const cc = `public, max-age=${browser}, s-maxage=${ttlS}`;
        return new Response(request.method === 'HEAD' ? null : svg, { status: 200, headers: svgHeaders(cc, { 'x-badge-status': status, 'x-cache': cache }) });
      };
      let host;
      try { host = normalizeBadgeHost(badgeMatch[1], { selfHosts }); }
      catch (e) {
        // Invalid / blocked hosts still return a grey 200 badge so README embeds don't break.
        const label = (e instanceof TargetError && (e.code === 'blocked_target' || e.code === 'blocked_port')) ? 'not graded' : 'unknown';
        return respondSvg(renderBadgeSvg(label), { ttlS: BADGE_CACHE_TTL_ERR_S, status: e.code || 'invalid' });
      }
      const keyUrl = badgeCacheKey(host);
      if (cacheStore && typeof cacheStore.match === 'function') {
        try {
          const hit = await cacheStore.match(keyUrl);
          if (hit) {
            // Re-wrap so we can set x-cache: HIT without mutating the stored response.
            const headers = new Headers(hit.headers);
            headers.set('x-cache', 'HIT');
            return new Response(request.method === 'HEAD' ? null : hit.body, { status: 200, headers });
          }
        } catch { /* cache miss / unavailable */ }
      }
      // Uncached badge: count against a separate per-IP badge limit (does not share the scan counter key).
      const badgeLimited = await rateLimited(env, ip, Number(env.BADGE_LIMIT_PER_MIN || BADGE_LIMIT_PER_MIN), 'badge');
      if (badgeLimited) return respondSvg(renderBadgeSvg('try later'), { ttlS: 60, status: 'rate_limited' });
      let label = 'unknown';
      let ttlS = BADGE_CACHE_TTL_ERR_S;
      let status = 'error';
      try {
        const result = await scan(host, { fetchImpl: doFetch, selfHosts });
        label = badgeLabelFromScan(result);
        if (label !== 'not graded' && label !== 'unknown') { ttlS = BADGE_CACHE_TTL_OK_S; status = 'graded'; }
        else { status = label === 'not graded' ? 'not_graded' : 'error'; }
      } catch (e) {
        // Scan failures (SSRF on a redirect hop, DNS, timeout, …): grey "unknown", short cache.
        label = 'unknown';
        status = (e && e.code) || 'error';
      }
      const svg = renderBadgeSvg(label);
      const res = respondSvg(svg, { ttlS, status, cache: 'MISS' });
      if (cacheStore && typeof cacheStore.put === 'function') {
        waitUntil(cacheStore.put(keyUrl, res.clone()).catch(() => {}));
      }
      return res;
    }

    if (path === '/api/health') {
      // v0.2.3: deploy identifier from the Workers version-metadata binding (free; wrangler >= 3.x). null when absent (tests, wrangler dev).
      const md = env.CF_VERSION_METADATA;
      const deployId = md && typeof md.id === 'string' && md.id ? md.id : null;
      return json({ ok: true, service: 'headerguard', version: VERSION, publicLaunch: !staging(env), build: deployId ? deployId.slice(0, 8) : null, deployId, deployedAt: (md && md.timestamp) || null });
    }
    if (path.startsWith('/api/')) return apiError(404, 'not_found', 'Unknown API endpoint. See /docs.');

    if (request.method !== 'GET' && request.method !== 'HEAD') {
      return new Response('Method not allowed', { status: 405, headers: { 'content-type': 'text/plain; charset=utf-8', allow: 'GET, HEAD', ...SECURITY } });
    }
    const page = (body, type, cache = 'public, max-age=300', status = 200) => new Response(request.method === 'HEAD' ? null : body, {
      status, headers: { 'content-type': type, 'cache-control': cache, ...SECURITY, 'content-security-policy': CSP },
    });
    if (path === '/') return page(html, 'text/html; charset=utf-8');
    if (path === '/docs') return page(docs, 'text/html; charset=utf-8');
    if (path === '/app.js') return page(js, 'text/javascript; charset=utf-8');
    if (path === '/style.css') return page(css, 'text/css; charset=utf-8');
    if (path === '/robots.txt') {
      return page(staging(env) ? 'User-agent: *\nDisallow: /\n' : `User-agent: *\nAllow: /\nDisallow: /api/\nDisallow: /badge/\n\nSitemap: ${url.origin}/sitemap.xml\n`, 'text/plain; charset=utf-8');
    }
    if (path === '/sitemap.xml' && !staging(env)) {
      return page(`<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n  <url><loc>${url.origin}/</loc></url>\n  <url><loc>${url.origin}/docs</loc></url>\n</urlset>\n`, 'application/xml; charset=utf-8');
    }
    if (path === '/favicon.ico' || path === '/favicon.svg') {
      return page('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="7" fill="#1e3a8a"/><path d="M16 6l8 3v6c0 5-3.4 9.4-8 11-4.6-1.6-8-6-8-11V9z" fill="#fff"/><path d="M12 16h8M12 12h8M12 20h5" stroke="#1e3a8a" stroke-width="2"/></svg>', 'image/svg+xml', 'public, max-age=86400');
    }
    return page('Not found', 'text/plain; charset=utf-8', 'no-store', 404);
  };
}
