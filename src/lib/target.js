// Target URL normalization + SSRF guards. Pure functions (no I/O) so they are easy to unit-test.

export class TargetError extends Error {
  constructor(code, message, httpStatus = 400) { super(message); this.code = code; this.httpStatus = httpStatus; }
}

export const ALLOWED_PORTS = new Set(['', '80', '443', '8080', '8443']);

// Hostname suffixes / names that only make sense on private networks.
const BLOCKED_NAMES = new Set(['localhost', 'localhost.localdomain', 'ip6-localhost', 'ip6-loopback', 'broadcasthost', 'metadata', 'instance-data', 'metadata.google.internal']);
const BLOCKED_SUFFIXES = ['.localhost', '.local', '.internal', '.intranet', '.lan', '.home', '.home.arpa', '.corp', '.localdomain', '.private', '.priv', '.test', '.invalid', '.example', '.onion', '.arpa', '.alt'];

// ---------- IPv4 ----------
export function parseIPv4(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  const p = m.slice(1).map(Number);
  if (p.some((n) => n > 255)) return null;
  return p;
}

const V4_BLOCKS = [
  ['0.0.0.0', 8, 'this-network'],
  ['10.0.0.0', 8, 'private'],
  ['100.64.0.0', 10, 'carrier-grade NAT / shared (incl. 100.100.100.200 metadata)'],
  ['127.0.0.0', 8, 'loopback'],
  ['169.254.0.0', 16, 'link-local / cloud metadata'],
  ['172.16.0.0', 12, 'private'],
  ['192.0.0.0', 24, 'IETF protocol assignments'],
  ['192.0.2.0', 24, 'documentation'],
  ['192.88.99.0', 24, '6to4 relay'],
  ['192.168.0.0', 16, 'private'],
  ['198.18.0.0', 15, 'benchmarking'],
  ['198.51.100.0', 24, 'documentation'],
  ['203.0.113.0', 24, 'documentation'],
  ['224.0.0.0', 4, 'multicast'],
  ['240.0.0.0', 4, 'reserved / broadcast'],
  ['168.63.129.16', 32, 'Azure platform metadata'],
];
const v4int = (p) => ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
const V4_COMPILED = V4_BLOCKS.map(([ip, bits, why]) => {
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return { net: (v4int(parseIPv4(ip)) & mask) >>> 0, mask, why };
});

/** Returns a reason string if the IPv4 address (array of 4 octets) is non-public, else null. */
export function blockedIPv4(p) {
  const n = v4int(p);
  for (const b of V4_COMPILED) if (((n & b.mask) >>> 0) === b.net) return b.why;
  return null;
}

// ---------- IPv6 ----------
/** Parses an IPv6 literal (no brackets, no zone) into 8 16-bit groups, or null. Supports embedded IPv4. */
export function parseIPv6(s) {
  if (!s || s.includes('%')) return null;
  let str = s.toLowerCase();
  if (str.includes('.')) {
    // Embedded IPv4 in the last 32 bits (e.g. ::ffff:127.0.0.1): rewrite it as two hex groups.
    const i = str.lastIndexOf(':');
    const v4 = parseIPv4(str.slice(i + 1));
    if (!v4) return null;
    str = str.slice(0, i + 1) + ((v4[0] << 8) | v4[1]).toString(16) + ':' + ((v4[2] << 8) | v4[3]).toString(16);
  }
  const halves = str.split('::');
  if (halves.length > 2) return null;
  const parse = (part) => (part === '' ? [] : part.split(':'));
  const head = parse(halves[0]);
  const rest = halves.length === 2 ? parse(halves[1]) : [];
  if (![...head, ...rest].every((x) => /^[0-9a-f]{1,4}$/.test(x))) return null;
  let groups;
  if (halves.length === 2) {
    const fill = 8 - head.length - rest.length;
    if (fill < 1) return null;
    groups = [...head, ...Array(fill).fill('0'), ...rest];
  } else {
    if (head.length !== 8) return null;
    groups = head;
  }
  return groups.map((g) => parseInt(g, 16));
}

/** Returns a reason string if the IPv6 address (8 groups) is non-public, else null. */
export function blockedIPv6(g) {
  const v4of = (hi, lo) => [hi >> 8, hi & 255, lo >> 8, lo & 255];
  if (g.every((x) => x === 0)) return 'unspecified';
  if (g.slice(0, 7).every((x) => x === 0) && g[7] === 1) return 'loopback';
  // IPv4-mapped ::ffff:a.b.c.d and IPv4-compatible ::a.b.c.d
  if (g.slice(0, 5).every((x) => x === 0) && (g[5] === 0xffff || g[5] === 0)) {
    return blockedIPv4(v4of(g[6], g[7])) ? 'IPv4-mapped non-public address' : (g[5] === 0 ? 'deprecated IPv4-compatible address' : null);
  }
  // NAT64 64:ff9b::/96 (embeds IPv4) and local-use 64:ff9b:1::/48
  if (g[0] === 0x64 && g[1] === 0xff9b) {
    if (g[2] === 1) return 'NAT64 local-use';
    if (g.slice(2, 6).every((x) => x === 0)) return blockedIPv4(v4of(g[6], g[7])) ? 'NAT64 to non-public IPv4' : null;
  }
  if (g[0] === 0x100 && g[1] === 0 && g[2] === 0 && g[3] === 0) return 'discard-only';
  if (g[0] === 0x2001 && g[1] < 0x200) return 'IETF special-purpose (incl. Teredo)';
  if (g[0] === 0x2001 && g[1] === 0xdb8) return 'documentation';
  if (g[0] === 0x2002) return blockedIPv4(v4of(g[1], g[2])) ? '6to4 to non-public IPv4' : null;
  if ((g[0] & 0xfe00) === 0xfc00) return 'unique-local (incl. fd00:ec2::254 metadata)';
  if ((g[0] & 0xffc0) === 0xfe80) return 'link-local';
  if ((g[0] & 0xffc0) === 0xfec0) return 'site-local';
  if ((g[0] & 0xff00) === 0xff00) return 'multicast';
  return null;
}

/** Returns a reason if an IP string (v4 or v6, brackets allowed) is non-public; null if public; undefined if not an IP. */
export function blockedIp(ip) {
  const s = String(ip).replace(/^\[|\]$/g, '');
  const v4 = parseIPv4(s);
  if (v4) return blockedIPv4(v4);
  if (s.includes(':')) {
    const v6 = parseIPv6(s);
    if (!v6) return 'unparseable IPv6 literal';
    return blockedIPv6(v6);
  }
  return undefined;
}

/** Returns a reason if the hostname is a private/special-use name, else null. Expects a lowercased hostname. */
export function blockedHostname(host, { selfHosts = [] } = {}) {
  const h = host.replace(/\.$/, '');
  if (!h) return 'empty host';
  if (BLOCKED_NAMES.has(h)) return 'local hostname';
  for (const suf of BLOCKED_SUFFIXES) if (h.endsWith(suf)) return `special-use name (*${suf})`;
  if (!h.includes('.') && !h.includes(':')) return 'single-label hostname';
  if (selfHosts.some((s) => s && h === String(s).toLowerCase())) return 'this scanner itself';
  return null;
}

/**
 * Normalizes user input ("example.com", "https://x.y/path") into a URL and runs all static checks.
 * Throws TargetError. Returns { url: URL, explicitScheme: boolean }.
 */
export function normalizeTarget(input, opts = {}) {
  let raw = String(input ?? '').trim();
  if (!raw) throw new TargetError('invalid_url', 'Enter a URL or domain, e.g. example.com or https://example.com/.');
  if (raw.length > 2048) throw new TargetError('invalid_url', 'URL is too long (max 2048 characters).');
  if (/[\u0000-\u001f\u007f\s]/.test(raw)) throw new TargetError('invalid_url', 'URL must not contain spaces or control characters.');
  const explicitScheme = /^[a-z][a-z0-9+.-]*:/i.test(raw) && !/^[^/:]+:\d+(\/|$)/.test(raw);
  if (!explicitScheme) {
    if (raw.startsWith('//')) raw = raw.slice(2);
    raw = 'https://' + raw;
  }
  let url;
  try { url = new URL(raw); } catch { throw new TargetError('invalid_url', 'That does not look like a valid URL or domain.'); }
  checkUrl(url, opts);
  url.hash = '';
  return { url, explicitScheme };
}

/** Static checks for any URL we are about to fetch (initial URL and every redirect hop). Throws TargetError. */
export function checkUrl(url, opts = {}) {
  if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new TargetError('invalid_scheme', 'Only http:// and https:// URLs can be scanned.');
  if (url.username || url.password) throw new TargetError('invalid_url', 'URLs with embedded credentials (user:pass@) are not allowed.');
  if (!ALLOWED_PORTS.has(url.port)) throw new TargetError('blocked_port', 'Only the default ports (80/443) and 8080/8443 are allowed.', 403);
  const host = url.hostname.toLowerCase();
  const ipReason = blockedIp(host);
  if (ipReason) throw new TargetError('blocked_target', `That address is not allowed (${ipReason}). HeaderGuard only scans public websites.`, 403);
  if (ipReason === undefined) {
    if (host.length > 253 || !/^[a-z0-9.-]+$/.test(host)) {
      throw new TargetError('invalid_url', 'Hostname contains invalid characters.');
    }
    if (host.replace(/\.$/, '').split('.').some((l) => l.length === 0 || l.length > 63)) throw new TargetError('invalid_url', 'Hostname has an empty or too-long label.');
    const nameReason = blockedHostname(host, opts);
    if (nameReason) throw new TargetError('blocked_target', `That host is not allowed (${nameReason}). HeaderGuard only scans public websites.`, 403);
  }
  return true;
}
