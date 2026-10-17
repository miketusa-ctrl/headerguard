/**
 * Dependency-free shared license validator for tool Workers. Canonical source: the
 * license gateway/client/fleet-license.ts
 *
 * Reads lic:<full_key> from the shared LICENSES KV (written by the license gateway).
 * Never calls Polar. Never log full keys — use maskLicenseKey().
 */

/** @typedef {{ get: (key: string, options?: { type?: string, cacheTtl?: number }) => Promise<unknown> }} FleetLicenseKv */

/**
 * @typedef {object} FleetLicenseRecord
 * @property {string} key
 * @property {string} status
 * @property {string} plan
 * @property {string} product_slug
 * @property {string|null} expires_at
 */

/**
 * @typedef {object} FleetLicenseResult
 * @property {boolean} valid
 * @property {string} reason
 * @property {string} [slug]
 * @property {string|null} [expiresAt]
 * @property {string} [plan]
 */

/**
 * @typedef {object} ValidateFleetLicenseOpts
 * @property {number} [nowMs]
 * @property {boolean} [requirePrefix]
 * @property {number} [positiveTtlMs]
 * @property {number} [negativeTtlMs]
 * @property {number} [maxCacheSize]
 * @property {number} [kvCacheTtlSeconds]
 */

export const LIC_PREFIX = "lic:";

/** product_slug → Polar license-key prefix (ops/PRODUCTS.md). */
export const SLUG_PREFIX = {
  "dnsguard-pro": "DNSG",
  "robotsgate-pro": "RBTG",
  "headerguard-pro": "HDRG",
};

const DEFAULT_POSITIVE_TTL_MS = 60_000;
const DEFAULT_NEGATIVE_TTL_MS = 30_000;
const DEFAULT_MAX_CACHE = 512;
const DEFAULT_KV_CACHE_TTL = 60;
const MIN_KEY_LEN = 8;
const MAX_KEY_LEN = 256;

/** @type {Map<string, { record: FleetLicenseRecord|null, expiresAt: number }>} */
const isolateCache = new Map();

export function clearFleetLicenseCache() {
  isolateCache.clear();
}

export function invalidateFleetLicenseCache(licenseKey) {
  isolateCache.delete(licenseKey);
}

/** Mask a license key for logs: product prefix (if present) + last 4. */
export function maskLicenseKey(key) {
  if (!key) return "(empty)";
  const trimmed = key.trim();
  if (trimmed.length <= 4) return "****";
  const prefix = trimmed.split("-")[0] || "";
  const last4 = trimmed.slice(-4);
  if (prefix && prefix.length <= 8 && prefix !== trimmed) {
    return `${prefix}…${last4}`;
  }
  return `…${last4}`;
}

export function licenseKvKey(licenseKey) {
  return `${LIC_PREFIX}${licenseKey}`;
}

export function isWellFormedLicenseKey(key) {
  if (!key || typeof key !== "string") return false;
  if (key !== key.trim()) return false;
  if (key.length < MIN_KEY_LEN || key.length > MAX_KEY_LEN) return false;
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(key)) return false;
  return true;
}

export function expectedPrefixForSlug(slug) {
  return SLUG_PREFIX[slug] ?? null;
}

export function keyMatchesSlugPrefix(key, slug) {
  const prefix = expectedPrefixForSlug(slug);
  if (!prefix) return true;
  const head = key.split("-")[0] || "";
  return head.toUpperCase() === prefix.toUpperCase();
}

export function isRecordExpired(record, nowMs = Date.now()) {
  if (!record.expires_at) return false;
  const t = Date.parse(record.expires_at);
  if (!Number.isFinite(t)) return false;
  return t <= nowMs;
}

function fromCache(key, now) {
  const hit = isolateCache.get(key);
  if (!hit) return undefined;
  if (hit.expiresAt <= now) {
    isolateCache.delete(key);
    return undefined;
  }
  return hit.record;
}

function toCache(key, record, ttlMs, now, maxSize) {
  if (isolateCache.size >= maxSize) {
    const first = isolateCache.keys().next().value;
    if (first !== undefined) isolateCache.delete(first);
  }
  isolateCache.delete(key);
  isolateCache.set(key, { record, expiresAt: now + ttlMs });
}

function decide(record, expectedSlug, nowMs) {
  if (!record) {
    return { valid: false, reason: "not_found" };
  }
  const slug = record.product_slug;
  const expiresAt = record.expires_at ?? null;
  const plan = record.plan;

  if (record.status !== "granted") {
    return { valid: false, reason: `status_${record.status}`, slug, expiresAt, plan };
  }
  if (isRecordExpired(record, nowMs)) {
    return { valid: false, reason: "expired", slug, expiresAt, plan };
  }
  if (slug !== expectedSlug) {
    return { valid: false, reason: "product_mismatch", slug, expiresAt, plan };
  }
  if (plan === "unknown" || slug === "unknown") {
    return { valid: false, reason: "unknown_product", slug, expiresAt, plan };
  }
  return { valid: true, reason: "ok", slug, expiresAt, plan };
}

/**
 * Validate a Polar Pro license key against shared KV.
 * @param {FleetLicenseKv|null|undefined} kv
 * @param {string|null|undefined} key
 * @param {string} expectedSlug
 * @param {ValidateFleetLicenseOpts} [opts]
 * @returns {Promise<FleetLicenseResult>}
 */
export async function validateFleetLicense(kv, key, expectedSlug, opts = {}) {
  const nowMs = opts.nowMs ?? Date.now();
  const requirePrefix = opts.requirePrefix !== false;
  const positiveTtlMs = opts.positiveTtlMs ?? DEFAULT_POSITIVE_TTL_MS;
  const negativeTtlMs = opts.negativeTtlMs ?? DEFAULT_NEGATIVE_TTL_MS;
  const maxCacheSize = opts.maxCacheSize ?? DEFAULT_MAX_CACHE;
  const kvCacheTtlSeconds = opts.kvCacheTtlSeconds ?? DEFAULT_KV_CACHE_TTL;

  if (key == null || (typeof key === "string" && key.trim() === "")) {
    return { valid: false, reason: "missing_key" };
  }
  if (typeof key !== "string" || !isWellFormedLicenseKey(key)) {
    return { valid: false, reason: "malformed_key" };
  }
  if (!expectedSlug || typeof expectedSlug !== "string") {
    return { valid: false, reason: "missing_slug" };
  }
  if (requirePrefix && !keyMatchesSlugPrefix(key, expectedSlug)) {
    return { valid: false, reason: "prefix_mismatch" };
  }
  if (!kv || typeof kv.get !== "function") {
    return { valid: false, reason: "kv_unavailable" };
  }

  let record = fromCache(key, nowMs);
  if (record === undefined) {
    let raw = null;
    try {
      raw = await kv.get(licenseKvKey(key), {
        type: "json",
        cacheTtl: kvCacheTtlSeconds,
      });
    } catch {
      return { valid: false, reason: "kv_error" };
    }
    if (raw && typeof raw === "object") {
      record = raw;
    } else {
      record = null;
    }
    const ttl = record ? positiveTtlMs : negativeTtlMs;
    toCache(key, record, ttl, nowMs, maxCacheSize);
  }

  return decide(record, expectedSlug, nowMs);
}

export function fleetLicenseCacheSize() {
  return isolateCache.size;
}
