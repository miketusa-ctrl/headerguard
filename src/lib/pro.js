// HeaderGuard Pro: license extraction, rate-key hashing, public product constants.
// Never log or return full license keys — use maskLicenseKey from fleet-license.js.

export const PRO_PRODUCT_SLUG = 'headerguard-pro';
export const PRO_PRICE_LABEL = '$9/mo';
export const DEFAULT_PRO_SCAN_LIMIT_PER_MIN = 120;
export const DEFAULT_FREE_SCAN_LIMIT_PER_MIN = 30;
/** Max URLs in POST /api/scan/batch. Worst case ~5 × ~20 subrequests ≪ 1000 Paid cap. */
export const BATCH_MAX_URLS = 5;
export const DEFAULT_PRO_CHECKOUT_URL = 'https://buy.polar.sh/polar_cl_isRRVJTATDI60ftjw6GnmlDneRdw46fI2cQcm0n6pnD';
export const DEFAULT_PRO_PORTAL_URL = 'https://polar.sh/digital-promo/portal';
export const PRO_SUPPORT_EMAIL = 'digitalpromohub.support@gmail.com';

/** Extract a license key from X-License-Key or Authorization: Bearer. Returns null if absent. */
export function extractLicenseKey(request) {
  const xl = request.headers.get('x-license-key');
  if (xl && xl.trim()) return xl.trim();
  const auth = request.headers.get('authorization') || '';
  const m = /^Bearer\s+(\S+)/i.exec(auth);
  return m ? m[1].trim() : null;
}

/** SHA-256 hex prefix for rate-limit keys (never store/log the raw license). */
export async function hashLicenseKey(key) {
  const data = new TextEncoder().encode(String(key));
  const subtle = globalThis.crypto && globalThis.crypto.subtle;
  if (!subtle) {
    // Deterministic fallback for exotic runtimes (tests always have webcrypto in Node 20+).
    let h = 2166136261;
    for (let i = 0; i < key.length; i++) { h ^= key.charCodeAt(i); h = Math.imul(h, 16777619); }
    return ('00000000' + (h >>> 0).toString(16)).slice(-8);
  }
  const buf = await subtle.digest('SHA-256', data);
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, 16);
}

export function checkoutUrl(env = {}) {
  return String(env.PRO_CHECKOUT_URL || DEFAULT_PRO_CHECKOUT_URL);
}
export function portalUrl(env = {}) {
  return String(env.PRO_PORTAL_URL || DEFAULT_PRO_PORTAL_URL);
}

/** Map validateFleetLicense reason → HTTP status + public message (no key material). */
export function licenseErrorResponse(reason, env = {}) {
  const buy = checkoutUrl(env);
  const base = {
    upgradeUrl: buy,
    product: PRO_PRODUCT_SLUG,
    support: PRO_SUPPORT_EMAIL,
  };
  if (reason === 'expired') {
    return { status: 403, code: 'license_expired', message: `That HeaderGuard Pro license has expired. Renew at ${buy}`, ...base };
  }
  if (reason === 'status_revoked') {
    return { status: 403, code: 'license_revoked', message: `That HeaderGuard Pro license was revoked. Get a new key at ${buy}`, ...base };
  }
  if (String(reason).startsWith('status_')) {
    return { status: 403, code: 'license_inactive', message: `That HeaderGuard Pro license is not active (${reason.replace(/^status_/, '')}). Get Pro at ${buy}`, ...base };
  }
  if (reason === 'product_mismatch' || reason === 'prefix_mismatch' || reason === 'unknown_product') {
    return { status: 403, code: 'license_wrong_product', message: `That key is not a HeaderGuard Pro license. Get one at ${buy}`, ...base };
  }
  // missing_key is handled as free; malformed / not_found / kv_* → 401
  return { status: 401, code: 'license_invalid', message: `Invalid or unknown HeaderGuard Pro license key. Get Pro at ${buy}`, ...base };
}
