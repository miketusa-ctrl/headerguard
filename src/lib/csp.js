// Content-Security-Policy parsing + evaluation. Multiple enforced policies (comma-separated or repeated
// headers) are all enforced by browsers, so a check passes if ANY policy satisfies it.

export const CSP_POINTS = {
  present: 6, scriptRestricted: 3, noUnsafeInline: 5, noUnsafeEval: 3, noWildcard: 3,
  objectSrc: 2, baseUri: 1, frameAncestors: 1, defaultSrc: 1,
};
export const CSP_MAX = Object.values(CSP_POINTS).reduce((a, b) => a + b, 0); // 25
export const CSP_REPORT_ONLY_POINTS = 3;

const NONCE_HASH_RE = /^'(nonce-[^']+|sha(256|384|512)-[^']+)'$/i;
const BROAD_SOURCES = new Set(['*', 'http:', 'https:', 'data:', 'blob:', 'filesystem:']);

/** Parses one serialized policy into an ordered Map(directive -> tokens). First occurrence wins (per spec). */
export function parsePolicy(str) {
  const map = new Map();
  for (const part of String(str || '').split(';')) {
    const tokens = part.trim().split(/[\t\n\f\r ]+/).filter(Boolean);
    if (!tokens.length) continue;
    const name = tokens[0].toLowerCase();
    if (!/^[a-z0-9-]+$/.test(name) || map.has(name)) continue;
    map.set(name, tokens.slice(1).map((t) => (t.startsWith("'") ? t.toLowerCase() : t)));
  }
  return map;
}

/** Splits a header value that may contain several comma-joined policies. */
export function splitPolicies(value) {
  if (!value) return [];
  return String(value).split(',').map((s) => s.trim()).filter(Boolean);
}

export function evaluatePolicy(map) {
  const script = map.get('script-src') ?? map.get('default-src');
  const scriptRestricted = Array.isArray(script);
  const s = script || [];
  const hasNonceOrHash = s.some((t) => NONCE_HASH_RE.test(t));
  const strictDynamic = s.includes("'strict-dynamic'");
  const unsafeInlineListed = s.includes("'unsafe-inline'");
  // CSP2+: a nonce or hash in the list makes browsers ignore 'unsafe-inline'. CSP3 'strict-dynamic' also ignores host/scheme allowlists.
  const unsafeInline = !scriptRestricted || (unsafeInlineListed && !hasNonceOrHash);
  const unsafeEval = !scriptRestricted || s.includes("'unsafe-eval'");
  const broad = s.filter((t) => BROAD_SOURCES.has(t.toLowerCase()));
  const wildcard = !scriptRestricted || (!strictDynamic && broad.length > 0);
  const obj = map.get('object-src') ?? map.get('default-src');
  const objectSrc = Array.isArray(obj) && obj.length === 1 && obj[0] === "'none'";
  return {
    scriptSource: map.has('script-src') ? 'script-src' : map.has('default-src') ? 'default-src' : null,
    scriptRestricted, hasNonceOrHash, strictDynamic, unsafeInlineListed, unsafeInline, unsafeEval,
    broadSources: broad, wildcard,
    objectSrc, objectSrcValue: obj ? obj.join(' ') : null,
    baseUri: map.has('base-uri'), defaultSrc: map.has('default-src'),
    frameAncestors: map.has('frame-ancestors'), frameAncestorsValue: map.has('frame-ancestors') ? map.get('frame-ancestors').join(' ') : null,
    defaultSrcWildcard: (map.get('default-src') || []).includes('*'),
    reportTo: map.has('report-uri') || map.has('report-to'),
    upgradeInsecure: map.has('upgrade-insecure-requests'),
  };
}

/**
 * Analyzes enforced and report-only CSP header values.
 * Returns { status, points, max, summary, notes[], directives, enforced, reportOnly, frameAncestors }.
 */
export function analyzeCsp(enforcedValue, reportOnlyValue) {
  const notes = [];
  const enforced = splitPolicies(enforcedValue).map((p) => ({ raw: p, map: parsePolicy(p) })).filter((p) => p.map.size);
  const ro = splitPolicies(reportOnlyValue).map((p) => ({ raw: p, map: parsePolicy(p) })).filter((p) => p.map.size);
  const directives = (list) => list.map((p) => Object.fromEntries(p.map));

  if (!enforced.length) {
    if (ro.length) {
      notes.push({ level: 'warn', text: 'Only Content-Security-Policy-Report-Only is set. Browsers report violations but block nothing. Switch to the enforcing Content-Security-Policy header once the reports are clean.' });
      const ev = evaluatePolicy(ro[0].map);
      if (ev.unsafeInline && ev.scriptRestricted) notes.push({ level: 'info', text: "The report-only policy allows 'unsafe-inline' scripts; it will not protect against XSS even once enforced." });
      return { status: 'warn', points: CSP_REPORT_ONLY_POINTS, max: CSP_MAX, summary: 'Report-Only (not enforced)', notes, enforced: [], reportOnly: directives(ro), frameAncestors: false, checks: null };
    }
    notes.push({ level: 'fail', text: 'No Content-Security-Policy header. CSP is the main browser-side defense against cross-site scripting (XSS) and data injection.' });
    notes.push({ level: 'info', text: 'A CSP set in a <meta> tag is not visible to this header-only scan.' });
    return { status: 'fail', points: 0, max: CSP_MAX, summary: 'Missing', notes, enforced: [], reportOnly: [], frameAncestors: false, checks: null };
  }

  const evs = enforced.map((p) => evaluatePolicy(p.map));
  const any = (k) => evs.some((e) => e[k]);
  const all = (k) => evs.every((e) => e[k]);
  const checks = {
    scriptRestricted: any('scriptRestricted'),
    noUnsafeInline: !all('unsafeInline'),
    noUnsafeEval: !all('unsafeEval'),
    noWildcard: !all('wildcard'),
    objectSrc: any('objectSrc'),
    baseUri: any('baseUri'),
    frameAncestors: any('frameAncestors'),
    defaultSrc: any('defaultSrc'),
  };
  let points = CSP_POINTS.present;
  for (const [k, ok] of Object.entries(checks)) if (ok) points += CSP_POINTS[k];

  if (enforced.length > 1) notes.push({ level: 'info', text: `${enforced.length} enforced policies were found. Browsers apply all of them, so each check passes if any policy satisfies it.` });
  if (!checks.scriptRestricted) notes.push({ level: 'fail', text: 'Neither script-src nor default-src is set, so the policy does not restrict scripts at all.' });
  else {
    if (!checks.noUnsafeInline) notes.push({ level: 'warn', text: "script-src allows 'unsafe-inline' without a nonce or hash, which largely defeats CSP's XSS protection. Move inline scripts to files, or use nonces/hashes (optionally with 'strict-dynamic')." });
    else if (evs.some((e) => e.unsafeInlineListed && e.hasNonceOrHash)) notes.push({ level: 'info', text: "'unsafe-inline' is listed but ignored by modern browsers because a nonce or hash is present (backward-compatible pattern)." });
    if (!checks.noUnsafeEval) notes.push({ level: 'warn', text: "script-src allows 'unsafe-eval' (eval(), new Function()). Remove it if your code and libraries allow." });
    if (!checks.noWildcard) {
      const b = [...new Set(evs.flatMap((e) => e.broadSources))].join(' ');
      notes.push({ level: 'warn', text: `script-src allows very broad sources (${b}), so scripts can load from almost anywhere. List specific hosts, or use nonces with 'strict-dynamic'.` });
    }
    if (evs.some((e) => e.strictDynamic)) notes.push({ level: 'info', text: "'strict-dynamic' is used: CSP3 browsers ignore host and scheme allowlists in script-src and trust nonce/hash-loaded scripts." });
  }
  if (!checks.defaultSrc) notes.push({ level: 'warn', text: 'default-src is missing. Without it, resource types you did not list (images, fonts, connections, frames…) are unrestricted.' });
  else if (evs.some((e) => e.defaultSrcWildcard)) notes.push({ level: 'warn', text: "default-src contains '*', which allows almost any origin." });
  if (!checks.objectSrc) notes.push({ level: 'warn', text: "object-src is not 'none' (directly or via default-src 'none'). Plugins (<object>, <embed>) can be an XSS vector; set object-src 'none'." });
  if (!checks.baseUri) notes.push({ level: 'warn', text: "base-uri is missing (it does not fall back to default-src). Set base-uri 'self' or 'none' to stop <base> tag injection." });
  if (!checks.frameAncestors) notes.push({ level: 'info', text: 'frame-ancestors is missing (it does not fall back to default-src). It is the modern replacement for X-Frame-Options.' });
  if (ro.length) notes.push({ level: 'info', text: 'A Content-Security-Policy-Report-Only policy is also set (good for testing a stricter policy).' });
  if (!evs.some((e) => e.reportTo)) notes.push({ level: 'info', text: 'No report-uri / report-to directive, so you will not hear about violations. Optional.' });

  const status = points >= 22 ? 'pass' : 'warn';
  const summary = status === 'pass' ? 'Strong policy' : (!checks.scriptRestricted ? 'Present, but scripts unrestricted' : !checks.noUnsafeInline ? "Present, allows 'unsafe-inline'" : 'Present, could be stricter');
  return { status, points, max: CSP_MAX, summary, notes, enforced: directives(enforced), reportOnly: directives(ro), frameAncestors: checks.frameAncestors, checks };
}
