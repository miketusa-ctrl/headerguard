/**
 * Agent-discovery documents (since v0.4.0): /llms.txt (llmstxt.org format), /openapi.json (OpenAPI 3.1) and
 * /.well-known/mcp/server-card.json (static MCP server card, SEP-1649 shape; Smithery's scan fallback).
 * Generated from code constants and limitsFor(env), so limits / versions / URLs can't drift from what the Worker
 * enforces. test/agent.test.js checks them against the real router (paths, statuses, headers, error codes).
 */
import { VERSION, MAX_REDIRECTS } from './scan.js';
import { PRO_PRICE_LABEL } from './pro.js';
import { BADGE_CACHE_TTL_OK_S, BADGE_CACHE_TTL_ERR_S } from './badge.js';
import { TOOLS, SERVER_INFO, SUPPORTED_VERSIONS, MAX_BODY_BYTES, MAX_BATCH, DISCOVERY_PER_MIN, instructions } from './mcp.js';

export const CONTACT_EMAIL = 'digitalpromohub.support@gmail.com';
const fmt = (n) => n.toLocaleString('en-US');

export function mcpClientConfig(origin) {
  return { mcpServers: { headerguard: { type: 'http', url: `${origin}/mcp` } } };
}

export function llmsTxt(origin, L) {
  const tool = TOOLS[0];
  return `# HeaderGuard

> Free website security-headers scanner for developers and site owners: HTTPS redirect, HSTS, Content-Security-Policy, X-Frame-Options / frame-ancestors, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP/CORP/COEP, cookie flags and version leaks. Returns a 0–100 score, an A+–F grade, per-header findings and copy-paste fixes. Public JSON API plus a remote MCP server for AI agents.

HeaderGuard only sends ordinary GET requests to the site you name (following up to ${MAX_REDIRECTS} redirects, each safety-checked) and reads response headers, never page bodies. Only public http(s) hosts on ports 80, 443, 8080 and 8443 can be scanned. If the site blocks or challenges the scanner, no grade is given. Results are kept in memory for 2 minutes; scanned URLs are not stored.

## For AI agents

- [MCP server](${origin}/mcp): remote MCP over Streamable HTTP at \`${origin}/mcp\` (POST only, stateless, JSON responses, no sessions). Protocol versions: ${SUPPORTED_VERSIONS.join(', ')} (2026-07-28 per-request \`_meta\`; older versions use \`initialize\`). One tool: \`${tool.name}\` with \`url\` (required) and \`include_raw\` (optional). Read-only. Client config (most MCP clients accept this; some use a different format, for example VS Code uses a \`servers\` key): \`${JSON.stringify(mcpClientConfig(origin))}\`
- [OpenAPI 3.1 spec](${origin}/openapi.json): machine-readable description of the JSON API
- [MCP server card](${origin}/.well-known/mcp/server-card.json): static description of the MCP server and its tool
- [API docs](${origin}/docs): human-readable API reference, scoring table and examples

## JSON API

- \`GET ${origin}/api/scan?url=example.com\` (\`domain=\` is an alias): full scan as JSON (\`score\`, \`grade\`, \`gradeWithheld\`, \`reliability\`, \`findings[]\` each with \`id\`, \`status\`, \`points\`, \`max\`, \`notes\`, plus \`fixes\`, \`redirects\`, \`httpCheck\`, \`headers\`, \`plan\`). CORS enabled.
- \`POST ${origin}/api/scan/batch\` with \`{ "urls": [...] }\` (HeaderGuard Pro only, at most ${L.batchMax} URLs): \`{ "plan": "pro", "count", "results": [...] }\`
- \`GET ${origin}/badge/<host>.svg\`: embeddable grade badge (SVG, always HTTP 200; graded badges cached about ${Math.round(BADGE_CACHE_TTL_OK_S / 3600)} hours, errors about ${Math.round(BADGE_CACHE_TTL_ERR_S / 3600)} hour)
- \`GET ${origin}/api/health\`: \`{ "ok": true, "service": "headerguard", "version": "${VERSION}", ... }\`
- Errors: \`{ "error": { "code", "message", "plan" } }\` with HTTP 400 \`invalid_url\`/\`invalid_scheme\`, 401 \`license_invalid\`/\`pro_required\`, 403 \`blocked_target\`/\`blocked_port\`/\`license_expired\`/\`license_revoked\`/\`license_inactive\`/\`license_wrong_product\`, 422 \`dns_not_found\`, 429 \`rate_limited\` (see \`Retry-After\`), 502 \`fetch_failed\`/\`dns_error\`/\`too_many_redirects\`/\`redirect_loop\`/\`bad_redirect\`/\`budget_exceeded\`, 504 \`timeout\`.

## Limits, keys and pricing

- No key: about ${L.anonPerMin} scans per minute per IP (IPv6 counted per /64). Uncached badges: about ${L.badgePerMin} per minute per IP.
- HeaderGuard Pro, ${L.proPrice || PRO_PRICE_LABEL} via Polar: about ${L.proPerMin} scans per minute per license, plus batch scans of up to ${L.batchMax} URLs. Send \`Authorization: Bearer HDRG-…\` or \`X-License-Key: HDRG-…\`. [Get Pro](${L.checkoutUrl})
- The MCP endpoint uses the same keys and the same counters: each \`tools/call\` is one scan. \`initialize\`, \`tools/list\` and other non-scan messages don't count as scans, but have a light cap of about ${DISCOVERY_PER_MIN} per minute per IP (over it: HTTP 429 with \`Retry-After\`). Over a limit, the tool result has \`isError: true\` with the reason and \`retryAfterSeconds\`. A key that is not a valid HeaderGuard Pro license returns HTTP 401 (or 403 when expired, revoked or for another product). Results are cached for 2 minutes and cache hits don't count.
- MCP request caps: ${fmt(MAX_BODY_BYTES)}-byte body, JSON-RPC batches (legacy versions only) of at most ${MAX_BATCH} messages with at most one \`tools/call\`.

## Optional

- [Homepage and scanner](${origin}/)
- [HeaderGuard Pro](${origin}/docs#pro)
- [Badge docs](${origin}/docs#badge)
- [Privacy](${origin}/#privacy)
- Contact: ${CONTACT_EMAIL}
`;
}

const errorSchema = { $ref: '#/components/schemas/Error' };
const errResp = (description, extraHeaders) => ({
  description,
  ...(extraHeaders ? { headers: extraHeaders } : {}),
  content: { 'application/json': { schema: errorSchema } },
});
const mcpNotAllowed = (m) => ({
  tags: ['mcp'],
  operationId: `mcp_${m}_not_allowed`,
  summary: 'Not supported (stateless server: no SSE stream, no sessions)',
  responses: {
    405: { description: 'Always 405 with `Allow: POST, OPTIONS` and a JSON-RPC error body', headers: { Allow: { schema: { type: 'string', const: 'POST, OPTIONS' } } }, content: { 'application/json': { schema: { type: 'object' } } } },
  },
});
const retryAfter = { 'Retry-After': { description: 'Seconds to wait before retrying', schema: { type: 'integer' } } };
const keyAuth = [{}, { bearerAuth: [] }, { licenseKeyHeader: [] }];
// Every route behind the key gate (all /api routes and badges) fails the same way when a bad key is sent.
const badKey401 = 'Key sent but not a valid HeaderGuard Pro license: `license_invalid`';
const badKey403 = 'Key sent but `license_expired`, `license_revoked`, `license_inactive` or `license_wrong_product`';

export function openApiSpec(origin, L) {
  const scanHeaders = {
    'x-cache': { description: '`HIT` (served from the 2-minute result cache; no quota used) or `MISS`', schema: { type: 'string', enum: ['HIT', 'MISS'] } },
    'x-plan': { description: '`free` or `pro`', schema: { type: 'string', enum: ['free', 'pro'] } },
  };
  return {
    openapi: '3.1.0',
    info: {
      title: 'HeaderGuard API',
      version: VERSION,
      summary: 'Website security-headers scanner: HSTS, CSP, framing, COOP/CORP/COEP, cookies, version leaks.',
      description: `Free JSON API behind ${origin}. No key needed: about ${L.anonPerMin} scans per minute per IP (IPv6 per /64). HeaderGuard Pro (${L.proPrice || PRO_PRICE_LABEL}, ${L.checkoutUrl}) allows about ${L.proPerMin} scans per minute per license and batch scans of up to ${L.batchMax} URLs. Results are cached for 2 minutes per edge isolate; cache hits do not count. There are no X-RateLimit-* headers; a 429 carries Retry-After. A key that is not a valid HeaderGuard Pro license is rejected (401/403) on every route instead of falling back to the free plan. AI agents can also use the remote MCP server at ${origin}/mcp (see /llms.txt).`,
      contact: { name: 'HeaderGuard', email: CONTACT_EMAIL, url: origin },
    },
    servers: [{ url: origin }],
    externalDocs: { description: 'Human-readable API docs', url: `${origin}/docs` },
    tags: [{ name: 'scan' }, { name: 'badge' }, { name: 'meta' }, { name: 'mcp' }],
    components: {
      securitySchemes: {
        bearerAuth: { type: 'http', scheme: 'bearer', description: 'HeaderGuard Pro license key (prefix `HDRG`). Optional.' },
        licenseKeyHeader: { type: 'apiKey', in: 'header', name: 'X-License-Key', description: 'Same license key as bearerAuth, alternative header.' },
      },
      schemas: {
        Error: {
          type: 'object', required: ['error'],
          properties: {
            error: {
              type: 'object', required: ['code', 'message'],
              additionalProperties: true,
              properties: {
                code: { type: 'string' }, message: { type: 'string' }, plan: { type: 'string', enum: ['free', 'pro'] },
                upgradeUrl: { type: 'string', format: 'uri' }, limitPerMin: { type: 'integer' },
                keyHint: { type: 'string', description: 'Masked form of the key that was sent (never the full key)' },
                redirects: { type: 'array', items: { type: 'object' } },
              },
            },
          },
        },
        Note: { type: 'object', required: ['level', 'text'], properties: { level: { type: 'string', enum: ['pass', 'info', 'warn', 'fail'] }, text: { type: 'string' } } },
        Finding: {
          type: 'object', required: ['id', 'name', 'status', 'points', 'max', 'notes'], additionalProperties: true,
          properties: {
            id: { type: 'string', enum: ['https', 'hsts', 'csp', 'framing', 'xcto', 'referrer', 'permissions', 'coop', 'corp', 'cookies', 'coep', 'xxss', 'leaks'] },
            name: { type: 'string' }, present: { type: 'boolean' }, value: { type: ['string', 'null'] },
            status: { type: 'string', enum: ['pass', 'warn', 'fail', 'info'] },
            points: { type: 'number' }, max: { type: 'number' }, summary: { type: 'string' },
            notes: { type: 'array', items: { $ref: '#/components/schemas/Note' } },
          },
        },
        ScanResult: {
          type: 'object',
          required: ['input', 'url', 'finalUrl', 'finalStatus', 'redirects', 'httpCheck', 'score', 'grade', 'gradeWithheld', 'gradeWithheldReason', 'scoring', 'findings', 'reliability', 'notes', 'fixes', 'headers', 'meta', 'plan'],
          properties: {
            input: { type: 'string' }, url: { type: 'string' }, finalUrl: { type: 'string' }, finalStatus: { type: 'integer' },
            redirects: { type: 'array', items: { type: 'object' } },
            httpCheck: { type: 'object', description: 'Whether plain http:// redirects to HTTPS (and, if the scan ended on another host, `finalHost`)' },
            score: { type: ['integer', 'null'], minimum: 0, maximum: 100, description: 'null when gradeWithheld' },
            grade: { type: ['string', 'null'], enum: ['A+', 'A', 'B', 'C', 'D', 'F', null] },
            gradeWithheld: { type: 'boolean' }, gradeWithheldReason: { type: ['string', 'null'] },
            unreliableRawScore: { type: 'object', description: 'Only when gradeWithheld; never display as a grade' },
            scoring: { type: 'object', properties: { base: { type: 'integer' }, leakPenalty: { type: 'integer' }, cappedNoHttps: { type: 'boolean' }, max: { type: 'integer', const: 100 } } },
            findings: { type: 'array', items: { $ref: '#/components/schemas/Finding' } },
            reliability: { type: 'string', enum: ['ok', 'blocked_or_challenged'] },
            notes: { type: 'array', items: { $ref: '#/components/schemas/Note' } },
            fixes: { type: 'object', properties: { items: { type: 'array', items: { type: 'object' } }, combined: { type: ['object', 'null'] }, platforms: { type: 'object' } } },
            headers: { type: 'object', description: 'Response headers of the final page (cookie values redacted)' },
            meta: { type: 'object', properties: { version: { type: 'string' }, scannedAt: { type: 'string', format: 'date-time' }, durationMs: { type: 'integer' }, subrequests: { type: 'integer' } } },
            plan: { type: 'string', enum: ['free', 'pro'] },
          },
        },
        JsonRpcMessage: {
          type: 'object', required: ['jsonrpc'],
          properties: { jsonrpc: { const: '2.0' }, id: { type: ['string', 'integer'] }, method: { type: 'string' }, params: { type: 'object' } },
        },
      },
    },
    paths: {
      '/api/scan': {
        get: {
          tags: ['scan'],
          operationId: 'scanHeaders',
          summary: 'Scan a website\'s HTTP security headers',
          security: keyAuth,
          parameters: [
            { name: 'url', in: 'query', required: false, description: 'URL or bare domain (required unless `domain` is given). A bare domain is scanned as https://<domain>/, falling back to plain HTTP if HTTPS does not answer.', schema: { type: 'string', maxLength: 2048 }, example: 'example.com' },
            { name: 'domain', in: 'query', required: false, description: 'Alias for `url`.', schema: { type: 'string', maxLength: 2048 } },
          ],
          responses: {
            200: { description: 'Scan result', headers: scanHeaders, content: { 'application/json': { schema: { $ref: '#/components/schemas/ScanResult' } } } },
            400: errResp('`invalid_url` or `invalid_scheme`'),
            401: errResp(badKey401),
            403: errResp(`\`blocked_target\` or \`blocked_port\` (private, internal or non-standard-port targets), or ${badKey403}`),
            405: errResp('`method_not_allowed`: use GET'),
            422: errResp('`dns_not_found`: the host does not resolve (NXDOMAIN or no A/AAAA records)'),
            429: errResp('`rate_limited` (per-minute limit for your IP or Pro license; includes `upgradeUrl` and `limitPerMin`)', retryAfter),
            500: errResp('`internal_error`'),
            502: errResp('`fetch_failed`, `dns_error`, `too_many_redirects`, `redirect_loop`, `bad_redirect` or `budget_exceeded`'),
            504: errResp('`timeout`: the site did not answer in time'),
          },
        },
      },
      '/api/scan/batch': {
        post: {
          tags: ['scan'],
          operationId: 'scanBatch',
          summary: `HeaderGuard Pro: scan up to ${L.batchMax} URLs in one request`,
          security: [{ bearerAuth: [] }, { licenseKeyHeader: [] }],
          requestBody: {
            required: true,
            content: { 'application/json': { schema: { type: 'object', required: ['urls'], properties: { urls: { type: 'array', minItems: 1, maxItems: L.batchMax, items: { type: 'string', maxLength: 2048 } } } } } },
          },
          responses: {
            200: {
              description: 'One result per URL (each `ok: true` with the scan fields, or `ok: false` with `error`). Each URL counts against the Pro per-minute limit.',
              content: { 'application/json': { schema: { type: 'object', required: ['plan', 'count', 'results'], properties: { plan: { const: 'pro' }, count: { type: 'integer' }, results: { type: 'array', items: { type: 'object' } } } } } },
            },
            400: errResp('`invalid_json`, `invalid_urls` or `batch_too_large`'),
            401: errResp(`\`pro_required\` (no key sent) or ${badKey401}`),
            403: errResp(badKey403),
            405: errResp('`method_not_allowed`: use POST'),
            429: errResp('`rate_limited` (Pro per-minute limit)', retryAfter),
            500: errResp('`internal_error`'),
          },
        },
      },
      '/api/health': {
        get: {
          tags: ['meta'], operationId: 'health', summary: 'Liveness and deployed version', security: [{}],
          responses: {
            200: {
              description: 'OK',
              content: {
                'application/json': {
                  schema: {
                    type: 'object', required: ['ok', 'service', 'version', 'publicLaunch', 'build', 'deployId', 'deployedAt'],
                    properties: {
                      ok: { const: true }, service: { const: 'headerguard' }, version: { type: 'string', examples: [VERSION] }, publicLaunch: { type: 'boolean' },
                      build: { type: ['string', 'null'] }, deployId: { type: ['string', 'null'] }, deployedAt: { type: ['string', 'null'] },
                    },
                  },
                },
              },
            },
            401: errResp(badKey401),
            403: errResp(badKey403),
          },
        },
      },
      '/badge/{host}.svg': {
        get: {
          tags: ['badge'], operationId: 'badge', summary: 'Embeddable grade badge (SVG)', security: [{}],
          parameters: [{ name: 'host', in: 'path', required: true, description: 'Bare hostname (no scheme, path, port or IP literal)', schema: { type: 'string', maxLength: 253 }, example: 'example.com' }],
          responses: {
            200: {
              description: `Always 200 so embeds don't break: the grade, or a grey \`not graded\` / \`unknown\` / \`try later\` badge. Graded badges are cached about ${Math.round(BADGE_CACHE_TTL_OK_S / 3600)} h, errors about ${Math.round(BADGE_CACHE_TTL_ERR_S / 3600)} h. Uncached badges count against a per-IP badge limit of about ${L.badgePerMin}/min.`,
              headers: {
                'x-cache': { schema: { type: 'string', enum: ['HIT', 'MISS'] } },
                'x-badge-status': { description: '`graded`, `not_graded`, `rate_limited` or an error code', schema: { type: 'string' } },
              },
              content: { 'image/svg+xml': { schema: { type: 'string' } } },
            },
            401: errResp(badKey401),
            403: errResp(badKey403),
          },
        },
      },
      '/mcp': {
        post: {
          tags: ['mcp'],
          operationId: 'mcp',
          summary: 'Remote MCP server (Streamable HTTP, JSON-RPC 2.0)',
          description: `Model Context Protocol endpoint. Stateless, JSON responses only (no SSE, no Mcp-Session-Id). Supported protocol versions: ${SUPPORTED_VERSIONS.join(', ')}. Modern (2026-07-28) requests carry params._meta and the MCP-Protocol-Version, Mcp-Method and Mcp-Name headers; legacy clients use initialize. Tool: ${TOOLS[0].name}. Same keys, cache and limits as /api/scan; each tools/call counts as one scan. Body max ${MAX_BODY_BYTES} bytes; legacy batches max ${MAX_BATCH} messages with at most one tools/call.`,
          security: keyAuth,
          parameters: [
            { name: 'MCP-Protocol-Version', in: 'header', required: false, schema: { type: 'string', enum: SUPPORTED_VERSIONS } },
            { name: 'Mcp-Method', in: 'header', required: false, description: 'Required for 2026-07-28; must equal the body method', schema: { type: 'string' } },
            { name: 'Mcp-Name', in: 'header', required: false, description: 'Required for 2026-07-28 tools/call; must equal params.name', schema: { type: 'string' } },
          ],
          requestBody: {
            required: true,
            content: { 'application/json': { schema: { oneOf: [{ $ref: '#/components/schemas/JsonRpcMessage' }, { type: 'array', maxItems: MAX_BATCH, items: { $ref: '#/components/schemas/JsonRpcMessage' } }] } } },
          },
          responses: {
            200: { description: 'JSON-RPC response (or batch of responses). Tool failures, including rate limits, are results with isError: true (and a Retry-After header when rate limited).', headers: { ...scanHeaders, ...retryAfter }, content: { 'application/json': { schema: { type: ['object', 'array'] } } } },
            202: { description: 'Notification(s) accepted; no body' },
            400: { description: 'Parse error (-32700), invalid request (-32600), header mismatch (-32020), unsupported protocol version (-32022) or missing _meta (-32602)', content: { 'application/json': { schema: { type: 'object' } } } },
            401: { description: 'Key sent but not a valid HeaderGuard Pro license (JSON-RPC error -32000, data.code = license_invalid)', content: { 'application/json': { schema: { type: 'object' } } } },
            403: { description: 'Origin header present but not allowed, or a license that is expired, revoked, inactive or for another product (data.code = license_*)', content: { 'application/json': { schema: { type: 'object' } } } },
            404: { description: 'Unknown method in a 2026-07-28 request (-32601)', content: { 'application/json': { schema: { type: 'object' } } } },
            413: { description: 'Body larger than the cap', content: { 'application/json': { schema: { type: 'object' } } } },
            429: { description: 'Too many non-scan MCP messages from this IP', headers: retryAfter, content: { 'application/json': { schema: { type: 'object' } } } },
            500: errResp('Unexpected internal error (`internal_error`); per-message failures are JSON-RPC -32603 inside a 200 response instead'),
            503: { description: 'Service temporarily unavailable (Cloudflare platform error; the Worker itself does not emit 503)', headers: retryAfter, content: { 'application/json': { schema: { type: 'object' } } } },
          },
        },
        get: mcpNotAllowed('get'),
        delete: mcpNotAllowed('delete'),
      },
    },
  };
}

/** Static MCP server card (SEP-1649 shape). Generated from the same TOOLS constant as tools/list. */
export function serverCard(origin, L) {
  return {
    serverInfo: SERVER_INFO,
    description: `Scan any public website's HTTP security headers (HSTS, CSP, framing, COOP/CORP/COEP, cookies): 0–100 score, A+–F grade and copy-paste fixes. Free: about ${L.anonPerMin} scans per minute per IP; HeaderGuard Pro ${L.proPrice || PRO_PRICE_LABEL} for about ${L.proPerMin} per minute.`,
    homepage: `${origin}/`,
    contact: { email: CONTACT_EMAIL },
    transport: { type: 'streamable-http', url: `${origin}/mcp` },
    protocolVersions: SUPPORTED_VERSIONS,
    capabilities: { tools: { listChanged: false } },
    authentication: { required: false, schemes: ['bearer'] },
    instructions: instructions(L),
    tools: TOOLS,
    resources: [],
    prompts: [],
  };
}
