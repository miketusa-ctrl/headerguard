/** Cloudflare Worker env bindings (ambient). */
interface Env {
  /** Shared Polar Pro licenses KV (the license gateway). Optional until Pro gating is wired. */
  LICENSES?: KVNamespace;
}
