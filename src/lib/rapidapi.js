/**
 * v0.5.0 RapidAPI marketplace route /rapidapi/v1/* (shared pattern: DnsGuard v0.8.0 src/lib/rapidapi.js, itself from MeetZone).
 * RapidAPI's proxy adds X-RapidAPI-Proxy-Secret (must equal the Worker secret RAPIDAPI_PROXY_SECRET), X-RapidAPI-Subscription
 * (BASIC/PRO) and X-RapidAPI-User. Compare is constant time (SHA-256 digests + XOR). Secret unset → 503; wrong/missing → 401. Hard
 * per-tier limits: RapidAPI enforces the monthly quota (hard limit, no overage) and the Worker enforces the per-minute plan limit
 * per RapidAPI user on its own bindings (RAPIDAPI_BASIC_LIMITER / RAPIDAPI_PRO_LIMITER, keyspace "rapidapi-<tier>:<hash>"), so
 * RapidAPI traffic never eats the free per-IP pool (SCAN_LIMITER) or a Polar Pro license's budget (PRO_SCAN_LIMITER). Same
 * normalizeTarget/scan (SSRF) and the same 2-minute result cache as /api/scan, via runCheck(). /api/*, /mcp and Polar HDRG- keys are
 * untouched. Error codes emitted only here: rapidapi_not_configured, unauthorized, plan_required, not_found.
 */
export const RAPIDAPI_PREFIX = '/rapidapi';
export const RAPIDAPI_TIERS = ['BASIC', 'PRO'];
/** Per-minute plan limits */
export const RAPIDAPI_PER_MIN = { BASIC: 10, PRO: 120 };
/** Monthly hard quotas, enforced by RapidAPI (Studio plan settings). */
export const RAPIDAPI_PER_MONTH = { BASIC: 100, PRO: 50_000 };
export const RAPIDAPI_PRICE_USD = { BASIC: 0, PRO: 15 };
export const RAPIDAPI_BINDING = { BASIC: 'RAPIDAPI_BASIC_LIMITER', PRO: 'RAPIDAPI_PRO_LIMITER' };

export function isRapidApiPath(path) { return path === RAPIDAPI_PREFIX || path.startsWith(`${RAPIDAPI_PREFIX}/`); }

async function digest(s) { return new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(s)))); }

/** Constant-time equality: compares fixed-length SHA-256 digests, so neither content nor length leaks via timing. */
export async function safeEqual(a, b) {
  const [x, y] = await Promise.all([digest(a), digest(b)]);
  let d = 0;
  for (let i = 0; i < x.length; i++) d |= x[i] ^ y[i];
  return d === 0;
}

export function rapidTier(request) {
  const t = String(request.headers.get('x-rapidapi-subscription') || '').trim().toUpperCase();
  return RAPIDAPI_TIERS.includes(t) ? t : 'BASIC';
}

/** Limiter key (16 hex): hashed X-RapidAPI-User (fallback: the caller's IP bucket). Never stores the raw username. */
export async function rapidUserKey(request, fallback) {
  const u = String(request.headers.get('x-rapidapi-user') || '').trim().slice(0, 128);
  const src = u ? `u:${u}` : `ip:${fallback}`;
  return [...(await digest(src))].slice(0, 8).map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Returns null when allowed, or { status, code, message } to reject. Never echoes the secret. */
export async function rapidGate(request, env) {
  const secret = typeof env.RAPIDAPI_PROXY_SECRET === 'string' ? env.RAPIDAPI_PROXY_SECRET : '';
  if (!secret) return { status: 503, code: 'rapidapi_not_configured', message: 'The RapidAPI route is not configured yet. Use the free API at /api/scan directly.' };
  const presented = request.headers.get('x-rapidapi-proxy-secret');
  if (!presented || !(await safeEqual(presented, secret))) {
    return { status: 401, code: 'unauthorized', message: 'Missing or invalid RapidAPI proxy secret. Subscribe on RapidAPI, or use the free public API at /api/scan.' };
  }
  return null;
}

/**
 * Route handler. h = { json, apiError, runCheck, scanBatch, rateLimited, ip, ipBucket, doFetch, selfHosts, version, batchMax }.
 * Response bodies are the same JSON as /api/scan and /api/scan/batch, with plan "rapidapi" and header x-headerguard-tier.
 */
export async function handleRapidApi(request, env, ctx, path, url, h) {
  const denied = await rapidGate(request, env);
  if (denied) return h.apiError(denied.status, denied.code, denied.message);
  const tier = rapidTier(request);
  const tierHeaders = { 'x-headerguard-tier': `rapidapi-${tier.toLowerCase()}` };
  const perMin = RAPIDAPI_PER_MIN[tier];
  const limited = (async () => {
    const userKey = await rapidUserKey(request, h.ipBucket);
    return () => h.rateLimited(env, userKey, perMin, `rapidapi-${tier.toLowerCase()}`, RAPIDAPI_BINDING[tier]);
  })();
  const rateErr = () => h.apiError(429, 'rate_limited', `Too many requests for your RapidAPI ${tier} plan (about ${perMin} scans per minute). Please wait a minute.`, { 'retry-after': '60', ...tierHeaders }, { plan: 'rapidapi', tier, limitPerMin: perMin });

  if (path === '/rapidapi/v1/health') {
    if (request.method !== 'GET' && request.method !== 'HEAD') return h.apiError(405, 'method_not_allowed', 'Use GET /rapidapi/v1/health.', { allow: 'GET', ...tierHeaders });
    return h.json({ ok: true, service: 'headerguard', version: h.version, tier }, 200, tierHeaders);
  }
  if (path === '/rapidapi/v1/scan') {
    if (request.method !== 'GET' && request.method !== 'HEAD') return h.apiError(405, 'method_not_allowed', 'Use GET /rapidapi/v1/scan?url=…', { allow: 'GET', ...tierHeaders });
    const raw = url.searchParams.get('url') ?? url.searchParams.get('domain') ?? '';
    const check = await limited;
    const auth = { ok: true, plan: 'rapidapi', licenseHash: null, rapidLimited: check };
    const r = await h.runCheck({ input: { url: raw }, auth, env, ctx, ip: h.ip, doFetch: h.doFetch, selfHosts: h.selfHosts });
    if (!r.ok) {
      if (r.code === 'rate_limited') return rateErr();
      return h.apiError(r.status, r.code, r.message, { ...r.headers, ...tierHeaders }, r.more);
    }
    return h.json(r.body, 200, { ...r.headers, ...tierHeaders });
  }
  if (path === '/rapidapi/v1/scan/batch') {
    if (request.method !== 'POST') return h.apiError(405, 'method_not_allowed', 'Use POST /rapidapi/v1/scan/batch with JSON { "urls": [...] }.', { allow: 'POST', ...tierHeaders });
    if (tier !== 'PRO') return h.apiError(403, 'plan_required', 'Batch scanning needs the RapidAPI PRO plan. Use GET /rapidapi/v1/scan on BASIC.', tierHeaders, { plan: 'rapidapi', tier });
    let payload;
    try { payload = await request.json(); } catch { return h.apiError(400, 'invalid_json', 'Body must be JSON: { "urls": ["example.com", ...] }.', tierHeaders); }
    const urls = payload && Array.isArray(payload.urls) ? payload.urls : null;
    if (!urls || urls.length === 0) return h.apiError(400, 'invalid_urls', 'Provide a non-empty "urls" array.', tierHeaders);
    if (urls.length > h.batchMax) return h.apiError(400, 'batch_too_large', `Batch is limited to ${h.batchMax} URLs per request.`, tierHeaders, { max: h.batchMax });
    // Like /api/scan/batch: every URL counts against the per-minute plan limit, before any scan runs.
    const check = await limited;
    for (let i = 0; i < urls.length; i++) if (await check()) return rateErr();
    const results = await h.scanBatch(urls, 'rapidapi');
    return h.json({ plan: 'rapidapi', tier, count: results.length, results }, 200, tierHeaders);
  }
  return h.apiError(404, 'not_found', 'Unknown RapidAPI endpoint. Use /rapidapi/v1/scan, /rapidapi/v1/scan/batch or /rapidapi/v1/health.', tierHeaders);
}
