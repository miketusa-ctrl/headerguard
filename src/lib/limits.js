// v0.4.0: one place that turns env vars into the limits the router enforces, so /api, /mcp, /llms.txt and
// /openapi.json all state the same numbers. Same parsing as v0.3.0 (Number(env.X || default)).
import { DEFAULT_FREE_SCAN_LIMIT_PER_MIN, DEFAULT_PRO_SCAN_LIMIT_PER_MIN, BATCH_MAX_URLS, PRO_PRICE_LABEL, checkoutUrl } from './pro.js';
import { BADGE_LIMIT_PER_MIN } from './badge.js';

export function limitsFor(env = {}) {
  return {
    anonPerMin: Number(env.SCAN_LIMIT_PER_MIN || DEFAULT_FREE_SCAN_LIMIT_PER_MIN),
    proPerMin: Number(env.PRO_SCAN_LIMIT_PER_MIN || DEFAULT_PRO_SCAN_LIMIT_PER_MIN),
    badgePerMin: Number(env.BADGE_LIMIT_PER_MIN || BADGE_LIMIT_PER_MIN),
    batchMax: BATCH_MAX_URLS,
    proPrice: PRO_PRICE_LABEL,
    checkoutUrl: checkoutUrl(env),
  };
}
