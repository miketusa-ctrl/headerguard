// DNS-over-HTTPS lookups used only to make sure a hostname does not resolve to a private address
// (defense in depth: Workers cannot reach private networks anyway, but DNS-rebinding names like
// 127.0.0.1.nip.io are rejected with a clear message).
import { blockedIp, TargetError } from './target.js';

const RESOLVERS = ['https://cloudflare-dns.com/dns-query', 'https://dns.google/resolve'];

// DNS response codes that are a real answer: NOERROR (0) and NXDOMAIN (3). Anything else is a resolver failure.
export const DEFINITIVE_STATUS = new Set([0, 3]);
const RCODE = { 1: 'FORMERR', 2: 'SERVFAIL', 4: 'NOTIMP', 5: 'REFUSED' };

export class HostResolver {
  constructor({ fetchImpl, timeoutMs = 2500, budget } = {}) {
    this.fetchImpl = fetchImpl || ((...a) => fetch(...a));
    this.timeoutMs = timeoutMs;
    this.budget = budget;
    this.cache = new Map();
  }

  async query(name, type) {
    let lastErr, lastResult;
    for (const base of RESOLVERS) {
      const ctl = new AbortController();
      const t = setTimeout(() => ctl.abort(), this.timeoutMs);
      try {
        this.budget?.take();
        const res = await this.fetchImpl(`${base}?name=${encodeURIComponent(name)}&type=${type}`, { headers: { accept: 'application/dns-json' }, signal: ctl.signal });
        if (!res.ok) throw new Error(`DoH HTTP ${res.status}`);
        const j = await res.json();
        const out = { status: j.Status, answers: (j.Answer || []).filter((a) => a.type === (type === 'A' ? 1 : 28)).map((a) => String(a.data)) };
        // a resolver failure (SERVFAIL, REFUSED, ...) with no answers is not an answer; try the next resolver, and if
        // all fail that way, return the failure so assertPublic reports dns_error ("couldn't check").
        if (!out.answers.length && !DEFINITIVE_STATUS.has(out.status)) { lastResult = out; continue; }
        return out;
      } catch (e) {
        if (e instanceof TargetError) throw e;
        lastErr = e;
      } finally { clearTimeout(t); }
    }
    if (lastResult) return lastResult;
    throw lastErr || new Error('DoH failed');
  }

  /** Throws TargetError unless every A/AAAA answer is a public address. IP literals are checked statically elsewhere. */
  async assertPublic(hostname) {
    const host = hostname.replace(/\.$/, '').toLowerCase();
    if (blockedIp(host) !== undefined) return { addresses: [host] };
    if (this.cache.has(host)) return this.cache.get(host);
    const p = (async () => {
      // allSettled, so a private address returned by one record type wins over the other type's outright failure
      // (blocked_target, not dns_error). Only then do failures surface.
      const settled = await Promise.allSettled([this.query(host, 'A'), this.query(host, 'AAAA')]);
      for (const r of settled) {
        if (r.status !== 'fulfilled') continue;
        for (const ip of r.value.answers) {
          const why = blockedIp(ip);
          if (why) throw new TargetError('blocked_target', `${host} resolves to a non-public address (${why}). HeaderGuard only scans public websites.`, 403);
        }
      }
      for (const r of settled) if (r.status === 'rejected' && r.reason instanceof TargetError) throw r.reason;
      if (settled.some((r) => r.status === 'rejected')) {
        throw new TargetError('dns_error', `Could not resolve ${host} (DNS lookup failed). Please retry.`, 502);
      }
      const [a, aaaa] = settled.map((r) => r.value);
      const addresses = [...a.answers, ...aaaa.answers];
      if (!addresses.length) {
        // only NXDOMAIN (3) or an empty NOERROR (0) means "does not exist". SERVFAIL (2), REFUSED (5) or any other
        // resolver status means the lookup failed: dns_error (couldn't check), not dns_not_found.
        const nx = a.status === 3 || aaaa.status === 3;
        if (!nx && (!DEFINITIVE_STATUS.has(a.status) || !DEFINITIVE_STATUS.has(aaaa.status))) {
          const st = !DEFINITIVE_STATUS.has(a.status) ? a.status : aaaa.status;
          throw new TargetError('dns_error', `Could not resolve ${host} (DNS lookup failed: ${RCODE[st] || 'status ' + st}). Please retry.`, 502);
        }
        throw new TargetError('dns_not_found', `${host} does not resolve to any address (${nx ? 'NXDOMAIN' : 'no A/AAAA records'}).`, 422);
      }
      for (const ip of addresses) {
        const why = blockedIp(ip);
        if (why) throw new TargetError('blocked_target', `${host} resolves to a non-public address (${why}). HeaderGuard only scans public websites.`, 403);
      }
      return { addresses };
    })();
    this.cache.set(host, p);
    try { return await p; } catch (e) { this.cache.delete(host); throw e; }
  }
}
