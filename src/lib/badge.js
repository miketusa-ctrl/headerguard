// Embeddable shields-style grade badge. Pure SVG builders + host validation (no I/O).
import { blockedIp, blockedHostname, TargetError } from './target.js';

export const BADGE_LABEL = 'security headers';
export const BADGE_CACHE_TTL_OK_S = 86_400;   // ~24h for graded results (s-maxage)
export const BADGE_CACHE_TTL_ERR_S = 3_600;   // ~1h for errors / grey
export const BADGE_BROWSER_MAX_AGE_S = 3_600; // browsers / camo: 1h
export const BADGE_LIMIT_PER_MIN = 30;        // uncached badge scans per IP

// shields.io flat palette (approx), keyed by grade letter or grey status.
export const GRADE_COLORS = {
  'A+': '#4c1',
  A: '#4c1',
  B: '#97ca00',
  C: '#dfb317',
  D: '#fe7d37',
  F: '#e05d44',
  'not graded': '#9f9f9f',
  unknown: '#9f9f9f',
  'try later': '#9f9f9f',
};

/** Escape text for use inside an SVG / XML attribute or text node. */
export function escapeXml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}

/** Approximate rendered width of a string in the DejaVu Sans / Verdana family at 11px (shields heuristic). */
function textWidth(s) {
  // Slightly generous so long labels (e.g. "not graded") never clip.
  let w = 0;
  for (const ch of String(s)) w += /[ilI1.'|]/.test(ch) ? 4.5 : /[MW@]/.test(ch) ? 9.5 : 7;
  return Math.ceil(w);
}

/**
 * Normalize a badge path segment into a bare lowercase hostname.
 * Rejects paths, ports, userinfo, schemes, brackets and ANY IP literal (public or private).
 * Applies the same hostname SSRF denylist as the scanner (localhost, *.local, self, …).
 */
export function normalizeBadgeHost(raw, { selfHosts = [] } = {}) {
  let h = String(raw ?? '').trim();
  if (!h) throw new TargetError('invalid_url', 'Badge host is empty.', 400);
  try { h = decodeURIComponent(h); } catch { throw new TargetError('invalid_url', 'Badge host is not valid percent-encoding.', 400); }
  h = h.trim().toLowerCase();
  if (!h || h.length > 253) throw new TargetError('invalid_url', 'Badge host is empty or too long.', 400);
  // Bare host only: no scheme, path, query, fragment, port, userinfo, brackets or whitespace.
  if (/[\/\\?#@:\s\[\]]/.test(h) || h.includes('..') || h.startsWith('.') || h.endsWith('..')) {
    throw new TargetError('invalid_url', 'Badge accepts a bare hostname only (no path, port, userinfo or IP).', 400);
  }
  h = h.replace(/\.$/, '');
  // Reject every IP literal, including public ones (badge is hostname-only).
  if (blockedIp(h) !== undefined) {
    throw new TargetError('blocked_target', 'Badge accepts a hostname, not an IP address.', 403);
  }
  if (!/^[a-z0-9.-]+$/.test(h) || h.split('.').some((l) => !l || l.length > 63 || l.startsWith('-') || l.endsWith('-'))) {
    throw new TargetError('invalid_url', 'Badge host contains invalid characters.', 400);
  }
  const why = blockedHostname(h, { selfHosts });
  if (why) throw new TargetError('blocked_target', `That host is not allowed (${why}).`, 403);
  return h;
}

/**
 * Build a shields-style flat SVG. `right` is the grade letter or a grey status string.
 * Every text piece is XML-escaped. Styles are inline (SVG CSP allows style-src 'unsafe-inline').
 */
export function renderBadgeSvg(right, { label = BADGE_LABEL } = {}) {
  const color = GRADE_COLORS[right] || GRADE_COLORS.unknown;
  const left = String(label);
  const rightText = String(right);
  const lw = textWidth(left) + 14;
  const rw = textWidth(rightText) + 14;
  const w = lw + rw;
  const ls = escapeXml(left);
  const rs = escapeXml(rightText);
  // Template mirrors shields.io flat: left slate, right grade colour, white text with a soft shadow.
  return `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="20" role="img" aria-label="${ls}: ${rs}">
<title>${ls}: ${rs}</title>
<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
<clipPath id="r"><rect width="${w}" height="20" rx="3" fill="#fff"/></clipPath>
<g clip-path="url(#r)">
  <rect width="${lw}" height="20" fill="#555"/>
  <rect x="${lw}" width="${rw}" height="20" fill="${color}"/>
  <rect width="${w}" height="20" fill="url(#s)"/>
</g>
<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
  <text aria-hidden="true" x="${lw / 2 * 10}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="${(lw - 14) * 10}">${ls}</text>
  <text x="${lw / 2 * 10}" y="140" transform="scale(.1)" textLength="${(lw - 14) * 10}">${ls}</text>
  <text aria-hidden="true" x="${(lw + rw / 2) * 10}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="${(rw - 14) * 10}">${rs}</text>
  <text x="${(lw + rw / 2) * 10}" y="140" transform="scale(.1)" textLength="${(rw - 14) * 10}">${rs}</text>
</g>
</svg>`;
}

/** Map a scan result (or failure) to the badge's right-hand label. */
export function badgeLabelFromScan(result) {
  if (!result) return 'unknown';
  if (result.gradeWithheld === true || result.grade == null) return 'not graded';
  if (typeof result.grade === 'string' && GRADE_COLORS[result.grade]) return result.grade;
  return 'unknown';
}

/** Cache key URL for the Workers Cache API (must be an absolute http(s) URL). */
export function badgeCacheKey(host) {
  return `https://badge-cache.headerguard.invalid/v1/${encodeURIComponent(host)}`;
}
