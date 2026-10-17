// Per-header analyzers + overall scoring. Pure functions: input is a Headers-like object plus context.
import { analyzeCsp, CSP_MAX } from './csp.js';

// Transparent scoring table. Sum = 100.
export const WEIGHTS = {
  https: 10,            // 5 final URL is HTTPS + 5 plain HTTP redirects to HTTPS
  hsts: 15,
  csp: CSP_MAX,         // 25
  framing: 10,          // X-Frame-Options or CSP frame-ancestors
  xcto: 10,             // X-Content-Type-Options: nosniff
  referrer: 10,
  permissions: 5,
  coop: 5,
  corp: 5,
  cookies: 5,
};
export const LEAK_PENALTY_EACH = 2;
export const LEAK_PENALTY_MAX = 5;
export const NO_HTTPS_CAP = 39;
export const GRADE_BANDS = [['A+', 95], ['A', 85], ['B', 70], ['C', 55], ['D', 40], ['F', 0]];

export function letterFor(score) {
  for (const [l, min] of GRADE_BANDS) if (score >= min) return l;
  return 'F';
}

const MAX_VALUE_LEN = 1024;
export const clip = (v, n = MAX_VALUE_LEN) => (v == null ? null : (String(v).length > n ? String(v).slice(0, n) + '…' : String(v)));

/** Returns all Set-Cookie header values (Workers, Node and fallbacks). */
export function getSetCookies(headers) {
  if (typeof headers.getSetCookie === 'function') { const a = headers.getSetCookie(); if (a.length) return a; }
  if (typeof headers.getAll === 'function') { try { return headers.getAll('set-cookie'); } catch { /* not supported */ } }
  const v = headers.get('set-cookie');
  return v ? v.split(/,(?=\s*[^;,=\s]+=)/) : [];
}

function finding(id, name, extra) {
  return { id, name, present: false, value: null, status: 'fail', points: 0, max: WEIGHTS[id] ?? 0, summary: '', notes: [], ...extra };
}

// v0.2.1/v0.2.2: plain-HTTP check errors that mean "we could not check" rather than "it does not redirect".
// Used for BOTH the first-host check (httpCheck) and the final-host check (httpCheck.finalHost): info note,
// no deduction. A failure of the very first hop is still reported as `unreachable` by checkHttpRedirect
// (plain HTTP did not answer) and handled as before; it is never in this set's path.
export const HTTP_CHECK_COULD_NOT_CHECK = new Set(['skipped', 'budget_exceeded', 'timeout', 'fetch_failed', 'dns_error']);
export const FINAL_HOST_COULD_NOT_CHECK = HTTP_CHECK_COULD_NOT_CHECK; // v0.2.1 name, kept for compatibility
const COULD_NOT_CHECK_TEXT = {
  skipped: 'scan request budget used up', budget_exceeded: 'scan request budget used up',
  timeout: 'a redirect hop timed out', fetch_failed: 'a redirect hop could not be reached', dns_error: 'a DNS lookup failed',
};
const couldNotCheck = (c) => !!c && !c.redirectsToHttps && !c.unreachable && HTTP_CHECK_COULD_NOT_CHECK.has(c.error);
const reasonText = (c) => COULD_NOT_CHECK_TEXT[c.error] || c.error;

export function analyzeHttps({ finalUrl, httpCheck }) {
  const f = finding('https', 'HTTPS & HTTP→HTTPS redirect', { present: true });
  const finalHttps = finalUrl.startsWith('https://');
  if (finalHttps) { f.points += 5; f.notes.push({ level: 'pass', text: 'The final page is served over HTTPS.' }); }
  else f.notes.push({ level: 'fail', text: 'The final page is served over plain HTTP. Traffic can be read and modified in transit. The overall score is capped at ' + NO_HTTPS_CAP + ' (F).' });
  const hc = httpCheck || {};
  const via = hc.hops && hc.hops.length > 1 ? ` via ${hc.hops.length} redirects (${hc.hops.map((h) => h.url).join(' → ')} → ${hc.location})` : ` (${hc.status})`;
  const hcCouldNotCheck = couldNotCheck(hc);
  if (hc.redirectsToHttps) { f.points += 5; f.notes.push({ level: 'pass', text: `${hc.url} redirects to HTTPS${via}.` }); }
  else if (hcCouldNotCheck) {
    // v0.2.2: same "couldn't check" rule as the final host. No deduction (only meaningful when the final page is HTTPS,
    // exactly like the unreachable case: a plain-HTTP final page never earns redirect points).
    f.points += finalHttps ? 5 : 0;
    f.notes.push({ level: 'info', text: `Could not check whether ${hc.url} redirects to HTTPS (${reasonText(hc)}${hc.hops && hc.hops.length ? ` after ${hc.hops.length} plain-HTTP redirect(s)` : ''}). No points were deducted for it.` });
  }
  else if (hc.unreachable) { f.points += finalHttps ? 5 : 0; f.notes.push({ level: 'info', text: `Plain HTTP (${hc.url}) did not answer, so nothing is served without encryption there.` }); }
  else if (hc.error === 'blocked_redirect') f.notes.push({ level: 'warn', text: `${hc.url} redirects to an address we may not fetch, so the HTTPS redirect could not be confirmed.` });
  else if (hc.error === 'bad_redirect') f.notes.push({ level: finalHttps ? 'warn' : 'fail', text: `${hc.url} sends a broken or non-HTTP(S) redirect, so it never reaches HTTPS.` });
  else if (hc.error === 'dns_not_found') f.notes.push({ level: finalHttps ? 'warn' : 'fail', text: `${hc.url} redirects to a host that does not exist, so it never reaches HTTPS.` });
  else if (hc.error === 'too_many_http_redirects') f.notes.push({ level: 'warn', text: `${hc.url} still had not reached HTTPS after ${hc.hops.length} plain-HTTP redirects.` });
  else if (hc.status) f.notes.push({ level: finalHttps ? 'warn' : 'fail', text: `${hc.url} answered ${hc.status}${hc.hops && hc.hops.length > 1 ? ` after ${hc.hops.length - 1} plain-HTTP redirect(s)` : ''} without redirecting to HTTPS. Visitors who type the bare domain stay on unencrypted HTTP.` });
  else f.notes.push({ level: 'info', text: 'The plain-HTTP redirect could not be checked.' });
  // v0.2.0: when the scan ended on another host (apex -> www), that host's plain HTTP must redirect too.
  const fh = hc.finalHost;
  if (fh && finalHttps) {
    // errors that mean "we couldn't check" (subrequest budget used up, timeout, connection or DNS failure on a
    // later hop) are not evidence of a missing redirect: info note, no deduction.
    const fhCouldNotCheck = couldNotCheck(fh);
    const okFinal = fh.redirectsToHttps || fh.unreachable || fhCouldNotCheck;
    if (fhCouldNotCheck) f.notes.push({ level: 'info', text: `Could not check whether ${fh.url} (the final host) redirects to HTTPS (${reasonText(fh)}). No points were deducted for it.` });
    else if (fh.redirectsToHttps) f.notes.push({ level: 'pass', text: `${fh.url} (the final host) also redirects to HTTPS.` });
    else if (fh.unreachable) f.notes.push({ level: 'info', text: `Plain HTTP on the final host (${fh.url}) did not answer.` });
    else if (fh.error === 'blocked_redirect') f.notes.push({ level: 'warn', text: `${fh.url} (the final host) redirects to an address we may not fetch, so its HTTPS redirect could not be confirmed.` });
    else if (fh.error === 'bad_redirect') f.notes.push({ level: 'warn', text: `${fh.url} (the final host) sends a broken or non-HTTP(S) redirect, so it never reaches HTTPS.` });
    else if (fh.error === 'dns_not_found') f.notes.push({ level: 'warn', text: `${fh.url} (the final host) redirects to a host that does not exist, so it never reaches HTTPS.` });
    else f.notes.push({ level: 'warn', text: `${fh.url} (the final host) ${fh.status ? `answered ${fh.status}` : 'could not be checked'} without redirecting to HTTPS.` });
    if (!okFinal && (hc.redirectsToHttps || hc.unreachable || hcCouldNotCheck)) f.points -= 5;
  }
  f.status = f.points === 10 ? 'pass' : finalHttps ? 'warn' : 'fail';
  f.summary = !finalHttps ? 'Not HTTPS' : f.points === 10 ? 'HTTPS with redirect' : 'HTTPS, but HTTP does not redirect';
  return f;
}

export function analyzeHsts(headers, { finalUrl }) {
  const v = headers.get('strict-transport-security');
  const f = finding('hsts', 'Strict-Transport-Security', { present: !!v, value: clip(v) });
  if (!finalUrl.startsWith('https://')) {
    f.notes.push({ level: 'fail', text: 'HSTS only works on HTTPS responses; this site is not served over HTTPS.' });
    f.summary = 'Not applicable without HTTPS';
    return f;
  }
  if (!v) { f.summary = 'Missing'; f.notes.push({ level: 'fail', text: 'No HSTS header. Browsers may still try plain HTTP first, which allows SSL-stripping attacks.' }); return f; }
  const first = v.split(',')[0];
  const m = /(?:^|;)\s*max-age\s*=\s*"?(\d+)"?/i.exec(first);
  const maxAge = m ? Number(m[1]) : null;
  const sub = /(?:^|;)\s*includesubdomains\s*(?:;|$)/i.test(first);
  const preload = /(?:^|;)\s*preload\s*(?:;|$)/i.test(first);
  f.details = { maxAge, includeSubDomains: sub, preload };
  if (maxAge == null) { f.status = 'fail'; f.summary = 'Invalid (no max-age)'; f.notes.push({ level: 'fail', text: 'The header has no valid max-age, so browsers ignore it.' }); return f; }
  if (maxAge === 0) { f.status = 'fail'; f.summary = 'Disabled (max-age=0)'; f.notes.push({ level: 'fail', text: 'max-age=0 tells browsers to forget HSTS for this host.' }); return f; }
  if (maxAge >= 31536000) f.points = 12; else if (maxAge >= 15552000) f.points = 9; else f.points = 4;
  const days = Math.round(maxAge / 86400);
  f.notes.push({ level: maxAge >= 31536000 ? 'pass' : 'warn', text: `max-age is ${maxAge} seconds (about ${days} days).${maxAge < 31536000 ? ' At least 31536000 (1 year) is recommended.' : ''}` });
  if (sub) { f.points += 2; f.notes.push({ level: 'pass', text: 'includeSubDomains is set.' }); }
  else f.notes.push({ level: 'warn', text: 'includeSubDomains is not set, so subdomains are not covered. Add it once every subdomain supports HTTPS.' });
  if (preload) {
    if (maxAge >= 31536000 && sub) { f.points += 1; f.notes.push({ level: 'pass', text: 'preload is set. Check the domain status at hstspreload.org.' }); }
    else f.notes.push({ level: 'warn', text: 'preload is set, but the preload list requires max-age ≥ 31536000 and includeSubDomains.' });
  } else f.notes.push({ level: 'info', text: 'preload is not set. Optional: only add it after reading the requirements at hstspreload.org, because removal is slow.' });
  f.present = true;
  f.status = f.points >= 14 ? 'pass' : 'warn';
  f.summary = f.status === 'pass' ? 'Strong' : 'Present, could be stronger';
  return f;
}

export function analyzeCspHeader(headers) {
  const enforced = headers.get('content-security-policy');
  const ro = headers.get('content-security-policy-report-only');
  const r = analyzeCsp(enforced, ro);
  return {
    ...finding('csp', 'Content-Security-Policy'),
    present: !!enforced, value: clip(enforced, 4096), reportOnlyValue: clip(ro, 4096),
    status: r.status, points: r.points, max: r.max, summary: r.summary, notes: r.notes,
    details: { enforced: r.enforced, reportOnly: r.reportOnly, checks: r.checks }, frameAncestors: r.frameAncestors,
  };
}

export function analyzeFraming(headers, { cspFrameAncestors }) {
  const v = headers.get('x-frame-options');
  const f = finding('framing', 'X-Frame-Options / frame-ancestors', { present: !!v || cspFrameAncestors, value: clip(v) });
  const val = (v || '').split(',')[0].trim().toUpperCase();
  const xfoOk = val === 'DENY' || val === 'SAMEORIGIN';
  if (cspFrameAncestors) { f.points = 10; f.notes.push({ level: 'pass', text: 'CSP frame-ancestors controls who may frame this page (it takes precedence over X-Frame-Options in modern browsers).' }); }
  if (xfoOk) { f.points = 10; f.notes.push({ level: 'pass', text: `X-Frame-Options: ${val}.` }); }
  else if (v && val.startsWith('ALLOW-FROM')) f.notes.push({ level: 'warn', text: 'X-Frame-Options ALLOW-FROM is obsolete and ignored by modern browsers. Use CSP frame-ancestors instead.' });
  else if (v) f.notes.push({ level: 'warn', text: `X-Frame-Options has an invalid value (${clip(v, 80)}); browsers ignore it.` });
  if (!f.points && !v) f.notes.push({ level: 'fail', text: 'Neither X-Frame-Options nor CSP frame-ancestors is set, so other sites can frame this page (clickjacking).' });
  f.status = f.points ? 'pass' : 'fail';
  f.summary = f.points ? (cspFrameAncestors ? 'Protected (frame-ancestors)' : `Protected (${val})`) : (v ? 'Invalid' : 'Missing');
  return f;
}

export function analyzeXcto(headers) {
  const v = headers.get('x-content-type-options');
  const f = finding('xcto', 'X-Content-Type-Options', { present: !!v, value: clip(v) });
  if (v && v.split(',')[0].trim().toLowerCase() === 'nosniff') { f.points = 10; f.status = 'pass'; f.summary = 'nosniff'; f.notes.push({ level: 'pass', text: 'MIME-type sniffing is disabled.' }); }
  else { f.summary = v ? 'Invalid value' : 'Missing'; f.notes.push({ level: 'fail', text: v ? `Value must be exactly "nosniff" (got ${clip(v, 80)}).` : 'Missing. Browsers may "sniff" content types and run uploaded files as scripts or styles.' }); }
  return f;
}

const REFERRER_STRONG = new Set(['no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin']);
const REFERRER_OK = new Set(['origin', 'origin-when-cross-origin']);
const REFERRER_ALL = new Set([...REFERRER_STRONG, ...REFERRER_OK, 'no-referrer-when-downgrade', 'unsafe-url']);
export function analyzeReferrer(headers) {
  const v = headers.get('referrer-policy');
  const f = finding('referrer', 'Referrer-Policy', { present: !!v, value: clip(v) });
  if (!v) { f.points = 5; f.status = 'warn'; f.summary = 'Missing (browser default applies)'; f.notes.push({ level: 'warn', text: 'Not set. Modern browsers default to strict-origin-when-cross-origin, but setting it explicitly protects older browsers and documents intent.' }); return f; }
  // Browsers use the last policy value they understand.
  const tokens = v.split(',').map((t) => t.trim().toLowerCase()).filter((t) => REFERRER_ALL.has(t));
  const eff = tokens[tokens.length - 1];
  f.details = { effective: eff || null };
  if (!eff) { f.summary = 'Invalid value'; f.notes.push({ level: 'fail', text: 'No recognized policy value; browsers fall back to their default.' }); f.points = 5; f.status = 'warn'; return f; }
  if (REFERRER_STRONG.has(eff)) { f.points = 10; f.status = 'pass'; f.summary = eff; f.notes.push({ level: 'pass', text: `${eff}: full URLs are not leaked to other sites.` }); }
  else if (REFERRER_OK.has(eff)) { f.points = 6; f.status = 'warn'; f.summary = eff; f.notes.push({ level: 'warn', text: `${eff} sends your origin even from HTTPS to HTTP. strict-origin-when-cross-origin is safer.` }); }
  else if (eff === 'no-referrer-when-downgrade') { f.points = 3; f.status = 'warn'; f.summary = eff; f.notes.push({ level: 'warn', text: 'no-referrer-when-downgrade sends the full URL (path and query) to every HTTPS site.' }); }
  else { f.points = 0; f.status = 'fail'; f.summary = eff; f.notes.push({ level: 'fail', text: 'unsafe-url sends the full URL, including over plain HTTP. Avoid it.' }); }
  return f;
}

export function analyzePermissions(headers) {
  const v = headers.get('permissions-policy');
  const legacy = headers.get('feature-policy');
  const f = finding('permissions', 'Permissions-Policy', { present: !!v, value: clip(v) });
  if (v) {
    const items = v.split(',').map((s) => s.trim()).filter((s) => /^[a-z0-9-]+=/.test(s));
    f.details = { features: items.map((s) => s.split('=')[0]) };
    if (items.length) { f.points = 5; f.status = 'pass'; f.summary = `${items.length} feature${items.length > 1 ? 's' : ''} restricted`; f.notes.push({ level: 'pass', text: `Restricts: ${f.details.features.slice(0, 20).join(', ')}${items.length > 20 ? '…' : ''}.` }); }
    else { f.status = 'warn'; f.summary = 'Unparseable'; f.notes.push({ level: 'warn', text: 'The value does not use the feature=(allowlist) syntax.' }); }
    if (items.length && items.every((s) => s.startsWith('interest-cohort='))) { f.points = 2; f.status = 'warn'; f.summary = 'Only interest-cohort'; f.notes.push({ level: 'info', text: 'interest-cohort (FLoC) is obsolete. Restrict real features such as camera, microphone and geolocation.' }); }
    return f;
  }
  if (legacy) { f.points = 2; f.status = 'warn'; f.summary = 'Legacy Feature-Policy only'; f.value = clip(legacy); f.notes.push({ level: 'warn', text: 'Only the old Feature-Policy header is set. Use Permissions-Policy.' }); return f; }
  f.status = 'warn'; f.summary = 'Missing'; f.notes.push({ level: 'warn', text: 'Not set. Permissions-Policy turns off powerful browser features (camera, microphone, geolocation…) that your site and embedded content do not need.' });
  return f;
}

export function analyzeCoop(headers) {
  const v = headers.get('cross-origin-opener-policy');
  const f = finding('coop', 'Cross-Origin-Opener-Policy', { present: !!v, value: clip(v) });
  const val = (v || '').split(';')[0].trim().toLowerCase();
  if (val === 'same-origin') { f.points = 5; f.status = 'pass'; f.summary = val; f.notes.push({ level: 'pass', text: 'Cross-origin windows cannot keep a reference to this page (protects against XS-Leaks / tabnabbing).' }); }
  else if (val === 'same-origin-allow-popups' || val === 'noopener-allow-popups') { f.points = 4; f.status = 'pass'; f.summary = val; f.notes.push({ level: 'pass', text: `${val}: isolated, while still allowing popups you open (e.g. OAuth or payments).` }); }
  else if (val === 'unsafe-none') { f.status = 'warn'; f.summary = 'unsafe-none'; f.notes.push({ level: 'warn', text: 'unsafe-none is the default (no isolation).' }); }
  else { f.status = 'warn'; f.summary = v ? 'Invalid value' : 'Missing'; f.notes.push({ level: 'warn', text: v ? 'Unrecognized value.' : 'Not set. same-origin isolates your window from cross-origin pages; use same-origin-allow-popups if you rely on OAuth/payment popups.' }); }
  return f;
}

export function analyzeCorp(headers) {
  const v = headers.get('cross-origin-resource-policy');
  const f = finding('corp', 'Cross-Origin-Resource-Policy', { present: !!v, value: clip(v) });
  const val = (v || '').trim().toLowerCase();
  if (val === 'same-origin' || val === 'same-site') { f.points = 5; f.status = 'pass'; f.summary = val; f.notes.push({ level: 'pass', text: `Other sites cannot embed this resource with no-cors requests (${val}).` }); }
  else if (val === 'cross-origin') { f.points = 2; f.status = 'info'; f.summary = 'cross-origin'; f.notes.push({ level: 'info', text: 'cross-origin explicitly allows any site to load this resource. Fine for public assets and APIs, but same-origin is safer for pages.' }); }
  else { f.status = 'warn'; f.summary = v ? 'Invalid value' : 'Missing'; f.notes.push({ level: 'warn', text: v ? 'Unrecognized value.' : 'Not set. same-origin (or same-site) stops other sites from loading this response as an image/script (Spectre-style leaks).' }); }
  return f;
}

export function analyzeCoep(headers) {
  const v = headers.get('cross-origin-embedder-policy');
  const val = (v || '').split(';')[0].trim().toLowerCase();
  const f = finding('coep', 'Cross-Origin-Embedder-Policy', { present: !!v, value: clip(v), max: 0, status: 'info' });
  if (val === 'require-corp' || val === 'credentialless') { f.status = 'pass'; f.summary = val; f.notes.push({ level: 'pass', text: `${val}: with COOP same-origin this enables cross-origin isolation.` }); }
  else { f.summary = v ? val || 'Set' : 'Not set'; f.notes.push({ level: 'info', text: 'Optional (not scored). Only needed for cross-origin isolation (SharedArrayBuffer, precise timers). It can break third-party embeds, so add it only if you need it.' }); }
  return f;
}

export function analyzeCookies(headers, { finalUrl }) {
  const raw = getSetCookies(headers);
  const f = finding('cookies', 'Cookie flags (Set-Cookie)', { present: raw.length > 0 });
  if (!raw.length) { f.points = 5; f.status = 'pass'; f.summary = 'No cookies set'; f.notes.push({ level: 'info', text: 'This response sets no cookies (other pages may).' }); return f; }
  const https = finalUrl.startsWith('https://');
  const cookies = raw.slice(0, 30).map((c) => {
    const parts = c.split(';').map((s) => s.trim());
    const name = clip((parts[0].split('=')[0] || '(unnamed)').trim(), 64);
    const attrs = parts.slice(1).map((a) => a.toLowerCase());
    const sameSiteAttr = attrs.find((a) => a.startsWith('samesite='));
    const sameSite = sameSiteAttr ? sameSiteAttr.split('=')[1].trim() : null;
    const secure = attrs.includes('secure');
    return { name, secure, httpOnly: attrs.includes('httponly'), sameSite: sameSite ? sameSite[0].toUpperCase() + sameSite.slice(1) : null };
  });
  // Cookie values are never returned (they can be session tokens).
  f.details = { count: raw.length, cookies };
  let good = 0;
  for (const c of cookies) {
    const problems = [];
    if (!c.secure) problems.push('Secure');
    if (!c.sameSite) problems.push('SameSite');
    if (c.sameSite && c.sameSite.toLowerCase() === 'none' && !c.secure) problems.push('SameSite=None requires Secure');
    if (!problems.length) good++;
    else f.notes.push({ level: 'warn', text: `Cookie "${c.name}" is missing: ${problems.join(', ')}.` });
    if (!c.httpOnly) f.notes.push({ level: 'info', text: `Cookie "${c.name}" is readable by JavaScript (no HttpOnly). Fine for non-sensitive cookies; session cookies should be HttpOnly.` });
  }
  f.points = https ? Math.round((5 * good) / cookies.length) : 0;
  f.status = good === cookies.length && https ? 'pass' : good ? 'warn' : 'fail';
  f.summary = `${good}/${cookies.length} cookie${cookies.length > 1 ? 's' : ''} with Secure + SameSite`;
  if (!https) f.notes.push({ level: 'fail', text: 'Cookies sent over plain HTTP can be intercepted.' });
  return f;
}

export function analyzeXxss(headers) {
  const v = headers.get('x-xss-protection');
  const f = finding('xxss', 'X-XSS-Protection', { present: !!v, value: clip(v), max: 0, status: 'info' });
  const val = (v || '').trim();
  if (!v) { f.status = 'pass'; f.summary = 'Not set (fine)'; f.notes.push({ level: 'info', text: 'Deprecated header; leaving it out is fine. Rely on CSP instead.' }); }
  else if (val === '0') { f.status = 'pass'; f.summary = '0 (recommended)'; f.notes.push({ level: 'pass', text: 'Set to 0, which disables the legacy XSS auditor (recommended).' }); }
  else { f.status = 'warn'; f.summary = clip(val, 40); f.notes.push({ level: 'warn', text: 'Deprecated. The old XSS auditor could itself be abused to leak data; set it to 0 or remove it and rely on CSP. (Not scored.)' }); }
  return f;
}

const LEAK_HEADERS = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator', 'x-drupal-cache', 'x-runtime', 'x-version'];
export function analyzeLeaks(headers) {
  const items = [];
  for (const h of LEAK_HEADERS) {
    const v = headers.get(h);
    if (!v) continue;
    const hasVersion = /\d+\.\d+/.test(v) || /\/\d/.test(v);
    const penalized = h === 'server' ? hasVersion : ['x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version'].includes(h);
    items.push({ header: h, value: clip(v, 200), penalized });
  }
  const penalty = Math.min(LEAK_PENALTY_MAX, items.filter((i) => i.penalized).length * LEAK_PENALTY_EACH);
  const f = finding('leaks', 'Information-leak headers', { max: 0, present: items.length > 0, status: penalty ? 'warn' : 'pass', penalty, details: { headers: items } });
  f.points = -penalty;
  f.summary = items.length ? (penalty ? `${items.filter((i) => i.penalized).length} version/stack header(s) (−${penalty})` : 'No version details') : 'None found';
  for (const i of items) f.notes.push({ level: i.penalized ? 'warn' : 'info', text: i.penalized ? `${i.header} reveals software/version details: "${i.value}". Remove it or strip the version.` : `${i.header}: "${i.value}" (no version number; fine).` });
  if (!items.length) f.notes.push({ level: 'pass', text: 'No Server version, X-Powered-By or X-AspNet-Version headers.' });
  return f;
}

/** Runs every analyzer and computes the overall score. */
export function analyzeResponse(headers, { finalUrl, httpCheck }) {
  const csp = analyzeCspHeader(headers);
  const findings = [
    analyzeHttps({ finalUrl, httpCheck }),
    analyzeHsts(headers, { finalUrl }),
    csp,
    analyzeFraming(headers, { cspFrameAncestors: csp.frameAncestors }),
    analyzeXcto(headers),
    analyzeReferrer(headers),
    analyzePermissions(headers),
    analyzeCoop(headers),
    analyzeCorp(headers),
    analyzeCookies(headers, { finalUrl }),
    analyzeCoep(headers),
    analyzeXxss(headers),
    analyzeLeaks(headers),
  ];
  delete csp.frameAncestors;
  const base = findings.filter((f) => f.max > 0).reduce((a, f) => a + f.points, 0);
  const leaks = findings.find((f) => f.id === 'leaks');
  let score = Math.max(0, base - leaks.penalty);
  const capped = !finalUrl.startsWith('https://') && score > NO_HTTPS_CAP;
  if (capped) score = NO_HTTPS_CAP;
  return {
    score, grade: letterFor(score),
    scoring: { base, leakPenalty: leaks.penalty, cappedNoHttps: capped, max: 100 },
    findings,
  };
}
