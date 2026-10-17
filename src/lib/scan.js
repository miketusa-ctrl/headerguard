// Scan orchestrator: SSRF-checked manual redirect chain → header analysis → grades → fixes.
import { normalizeTarget, checkUrl, TargetError } from './target.js';
import { HostResolver } from './dns.js';
import { analyzeResponse, clip, getSetCookies } from './analyze.js';
import { buildFixes } from './fixes.js';

export const VERSION = '0.5.1';
export const MAX_REDIRECTS = 10; // v0.2.0 (Workers Paid): was 5
export const HOP_TIMEOUT_MS = 5000;
export const SCAN_DEADLINE_MS = 20000; // v0.2.0: was 15 s (wall time is not billed on Workers Standard)
// v0.2.0 (Workers Paid, 1000 subrequests/request): was 40 under the Free plan's 50. Worst case now:
// 11 main hops + 2x5 HTTP-check hops + 2 DoH per distinct host (<= 22 hosts x 2) + DoH fallbacks ~= 75. Kept
// well below 1000 so one scan can never fan out into many requests to third parties.
export const SUBREQUEST_BUDGET = 100;
export const USER_AGENT = 'Mozilla/5.0 (compatible; HeaderGuard/0.1; +https://headerguard.mike-tusa.workers.dev/docs)';

export class ScanError extends Error {
  constructor(code, message, httpStatus = 502, extra = {}) { super(message); this.code = code; this.httpStatus = httpStatus; Object.assign(this, extra); }
}

class Budget {
  constructor(max) { this.max = max; this.used = 0; }
  take() { if (++this.used > this.max) throw new ScanError('budget_exceeded', 'This scan needed too many requests and was stopped.', 502); }
}

async function fetchHeadersOnly(fetchImpl, url, { timeoutMs, budget, deadline }) {
  budget.take();
  const remaining = deadline - Date.now();
  if (remaining <= 0) throw new ScanError('timeout', 'The scan took too long. The site may be slow; please retry.', 504);
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), Math.min(timeoutMs, remaining));
  const t0 = Date.now();
  try {
    const res = await fetchImpl(url, {
      method: 'GET', redirect: 'manual', signal: ctl.signal,
      headers: { 'user-agent': USER_AGENT, accept: 'text/html,application/xhtml+xml,*/*;q=0.8', 'accept-language': 'en' },
    });
    // Headers only: never read the body (no remote HTML is stored, parsed, or echoed).
    try { await res.body?.cancel(); } catch { /* already closed */ }
    return { res, ms: Date.now() - t0 };
  } catch (e) {
    if (e instanceof ScanError) throw e;
    if (ctl.signal.aborted) throw new ScanError('timeout', `No response from ${new URL(url).host} within ${Math.round(Math.min(timeoutMs, remaining) / 1000)} s.`, 504);
    throw new ScanError('fetch_failed', `Could not connect to ${new URL(url).host} (connection, DNS or TLS error).`, 502);
  } finally { clearTimeout(t); }
}

/** Follows up to MAX_REDIRECTS manually, re-checking every hop for SSRF. */
export async function fetchChain(startUrl, { fetchImpl, resolver, budget, deadline, selfHosts }) {
  const chain = [];
  let url = startUrl;
  for (let hop = 0; ; hop++) {
    try {
      checkUrl(url, { selfHosts });
      await resolver.assertPublic(url.hostname);
    } catch (e) {
      if (e instanceof TargetError && hop > 0) {
        if (['blocked_target', 'blocked_port', 'invalid_scheme', 'invalid_url'].includes(e.code)) { e.code = 'blocked_redirect'; e.httpStatus = 403; }
        e.message = `Redirect blocked: ${e.message}`;
      }
      e.chain = chain;
      throw e;
    }
    let r;
    try { r = await fetchHeadersOnly(fetchImpl, url.href, { timeoutMs: HOP_TIMEOUT_MS, budget, deadline }); } catch (e) { e.chain = chain; throw e; }
    const { res, ms } = r;
    const loc = res.headers.get('location');
    const isRedirect = [301, 302, 303, 307, 308].includes(res.status) && loc;
    const entry = { url: url.href, status: res.status, ms };
    if (isRedirect) {
      let next;
      try { next = new URL(loc, url); } catch { entry.location = clip(loc, 300); chain.push(entry); throw new ScanError('bad_redirect', 'The site sent an invalid redirect Location.', 502, { chain }); }
      next.hash = '';
      entry.location = clip(next.href, 2048);
      chain.push(entry);
      if (hop >= MAX_REDIRECTS) throw new ScanError('too_many_redirects', `More than ${MAX_REDIRECTS} redirects; stopped.`, 502, { chain });
      if (chain.some((c) => c.url === next.href)) throw new ScanError('redirect_loop', 'The site redirects in a loop.', 502, { chain });
      url = next;
      continue;
    }
    chain.push(entry);
    return { res, finalUrl: url, chain };
  }
}

export const HTTP_CHECK_MAX_HOPS = 5; // v0.2.0: was 3

/**
 * Probes http://host/ to see whether plain HTTP ends up on HTTPS. Follows up to HTTP_CHECK_MAX_HOPS
 * plain-HTTP redirects (e.g. http://apex -> http://www -> https://www), re-applying the SSRF checks
 * (URL rules + DNS) before every hop. Never throws.
 */
async function checkHttpRedirect(host, { fetchImpl, resolver, budget, deadline, selfHosts }) {
  const start = `http://${host}/`;
  const hops = [];
  let url = new URL(start);
  const done = (extra) => {
    const last = hops[hops.length - 1] || {};
    return { url: start, status: last.status ?? null, location: last.location ?? null, hops, ...extra };
  };
  for (let i = 0; i < HTTP_CHECK_MAX_HOPS; i++) {
    if (i > 0) {
      try { checkUrl(url, { selfHosts }); await resolver.assertPublic(url.hostname); }
      catch (e) { return done({ redirectsToHttps: false, error: e.code === 'blocked_target' || e.code === 'blocked_port' ? 'blocked_redirect' : (e.code || 'error') }); }
    }
    let res;
    try { ({ res } = await fetchHeadersOnly(fetchImpl, url.href, { timeoutMs: 4000, budget, deadline })); }
    catch (e) {
      if (e instanceof ScanError && e.code === 'budget_exceeded') return done({ redirectsToHttps: false, error: 'skipped' });
      return i === 0 ? done({ unreachable: true, redirectsToHttps: false, error: e.code || 'fetch_failed' }) : done({ redirectsToHttps: false, error: e.code || 'fetch_failed' });
    }
    const loc = res.headers.get('location');
    const hop = { url: url.href, status: res.status, location: null };
    hops.push(hop);
    if (![301, 302, 303, 307, 308].includes(res.status) || !loc) return done({ redirectsToHttps: false });
    let next;
    try { next = new URL(loc, url); } catch { return done({ redirectsToHttps: false, error: 'bad_redirect' }); }
    hop.location = clip(next.href, 300);
    if (next.protocol === 'https:') return done({ redirectsToHttps: true });
    if (next.protocol !== 'http:') return done({ redirectsToHttps: false, error: 'bad_redirect' });
    url = next;
  }
  return done({ redirectsToHttps: false, error: 'too_many_http_redirects' });
}

function redactedHeaders(headers) {
  const out = [];
  for (const [k, v] of headers) {
    if (k === 'set-cookie') continue;
    out.push([k, clip(v, 2048)]);
    if (out.length >= 80) break;
  }
  for (const c of getSetCookies(headers).slice(0, 30)) {
    // Keep cookie name + attributes, drop the value (it may be a session token).
    const [first, ...attrs] = c.split(';');
    const name = first.split('=')[0].trim();
    out.push(['set-cookie', clip(`${name}=<redacted>${attrs.length ? ';' + attrs.join(';') : ''}`, 512)]);
  }
  return out;
}

export async function scan(input, { fetchImpl, selfHosts = [], resolver } = {}) {
  const started = Date.now();
  const deadline = started + SCAN_DEADLINE_MS;
  const doFetch = fetchImpl || ((...a) => fetch(...a));
  const budget = new Budget(SUBREQUEST_BUDGET);
  const res0 = resolver || new HostResolver({ fetchImpl: doFetch, budget });
  if (!res0.budget) res0.budget = budget;
  const { url, explicitScheme } = normalizeTarget(input, { selfHosts });
  const notes = [];
  const opts = { fetchImpl: doFetch, resolver: res0, budget, deadline, selfHosts };

  // Run the main chain and the plain-HTTP check in parallel (same host, so DNS is shared).
  const httpPromise = url.protocol === 'https:'
    // v0.2.3: keep the real error type if the pre-check lookup fails, so a failed lookup (dns_error, budget) counts as
    // "couldn't check" by the shared rule, while a blocked or non-existent host keeps its penalty.
    ? res0.assertPublic(url.hostname).then(() => checkHttpRedirect(url.host, opts), (e) => ({
      url: `http://${url.host}/`, status: null, location: null, hops: [], redirectsToHttps: false,
      error: e.code === 'blocked_target' || e.code === 'blocked_port' ? 'blocked_redirect' : (e.code || 'not_checked'),
    }))
    : null;
  let result;
  try {
    result = await fetchChain(url, opts);
  } catch (e) {
    // Bare domain: if HTTPS cannot connect at all, fall back to plain HTTP so http-only sites still get a report.
    if (!explicitScheme && e instanceof ScanError && (e.code === 'fetch_failed' || e.code === 'timeout') && (!e.chain || !e.chain.length)) {
      const httpUrl = new URL(url.href); httpUrl.protocol = 'http:';
      notes.push({ level: 'warn', text: `HTTPS on ${url.host} did not answer (${e.code}); scanned plain HTTP instead.` });
      result = await fetchChain(httpUrl, opts);
    } else throw e;
  }
  let httpCheck = httpPromise ? await httpPromise : null;
  if (!httpCheck) {
    const first = result.chain[0];
    if (first && first.url.startsWith('http://')) {
      // The user typed an http:// URL: reuse the main chain (already SSRF-checked per hop), up to HTTP_CHECK_MAX_HOPS.
      const httpHops = [];
      for (const h of result.chain.slice(0, HTTP_CHECK_MAX_HOPS)) { if (!h.url.startsWith('http://')) break; httpHops.push({ url: h.url, status: h.status, location: h.location || null }); }
      const last = httpHops[httpHops.length - 1];
      httpCheck = { url: first.url, status: last.status, location: last.location, hops: httpHops, redirectsToHttps: !!(last.location && last.location.startsWith('https://')) };
    } else httpCheck = { url: `http://${url.host}/`, error: 'not_checked' };
  }
  const finalUrl = result.finalUrl.href;
  // v0.2.0: if the scan ended on a different host (e.g. apex -> www), also check that http://<final host>/
  // redirects to HTTPS. Same SSRF rules: the final host was already checked by fetchChain, and every
  // further hop is re-checked inside checkHttpRedirect.
  const finalHostDiffers = result.finalUrl.host !== url.host && result.finalUrl.protocol === 'https:';
  if (finalHostDiffers && httpCheck) httpCheck.finalHost = await checkHttpRedirect(result.finalUrl.host, opts);
  if (result.finalUrl.protocol === 'http:' && result.chain.some((c) => c.url.startsWith('https://'))) {
    notes.push({ level: 'fail', text: 'A redirect downgrades from HTTPS to plain HTTP.' });
  }
  const analysis = analyzeResponse(result.res.headers, { finalUrl, httpCheck });
  const status = result.res.status;
  const hdrs = result.res.headers;
  const challenged = [401, 403, 429, 503].includes(status) || !!hdrs.get('cf-mitigated')
    || result.chain.some((c) => /\/sorry\/|captcha|__cf_chl|\/challenge/i.test(c.location || ''));
  const withheldReason = challenged
    ? `The site blocked, rate-limited or challenged our scanner (final HTTP ${status}${hdrs.get('cf-mitigated') ? ', bot challenge' : ''}${result.chain.some((c) => /\/sorry\/|captcha|__cf_chl|\/challenge/i.test(c.location || '')) ? ', redirected to a captcha/challenge page' : ''}). The headers we received belong to that block page, not the real site, so no grade is given.`
    : null;
  if (challenged) {
    notes.unshift({ level: 'warn', text: `Not graded: ${withheldReason} Some large sites do this to cloud IP ranges. Try again later, or scan a specific page URL. The findings below describe the block page only.` });
  } else if (status >= 400) notes.push({ level: 'info', text: `The final response was HTTP ${status}. Headers were analyzed anyway, but error pages sometimes send different headers than normal pages.` });
  const fixes = buildFixes(analysis.findings, { host: result.finalUrl.hostname });
  return {
    input: clip(String(input), 300),
    url: url.href,
    finalUrl,
    finalStatus: status,
    redirects: result.chain,
    httpCheck,
    // No letter or score for blocked/challenged scans. rawScore is kept only for debugging and is NOT a grade of the site.
    score: challenged ? null : analysis.score,
    grade: challenged ? null : analysis.grade,
    gradeWithheld: challenged,
    gradeWithheldReason: withheldReason,
    ...(challenged ? { unreliableRawScore: { score: analysis.score, note: 'UNRELIABLE: computed from the block/challenge page, not the real site. Do not display as a grade.' } } : {}),
    scoring: analysis.scoring,
    findings: analysis.findings,
    reliability: challenged ? 'blocked_or_challenged' : 'ok',
    notes,
    fixes,
    headers: redactedHeaders(result.res.headers),
    meta: { version: VERSION, scannedAt: new Date().toISOString(), durationMs: Date.now() - started, subrequests: budget.used },
  };
}
