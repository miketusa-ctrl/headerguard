// Copy-paste fix snippets. All header values are fixed, conservative constants (never derived from remote data).
// The only interpolated value is the scanned hostname, which has already been validated as [a-z0-9.-].

export const PLATFORMS = [
  ['nginx', 'nginx'],
  ['apache', 'Apache (.htaccess)'],
  ['cloudflare', 'Cloudflare (_headers / Workers)'],
  ['netlify', 'Netlify _headers'],
  ['vercel', 'Vercel vercel.json'],
  ['express', 'Express + helmet'],
];

export const CSP_STARTER = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'";

// Recommended header per finding id. `header` may differ from the scanned one (CSP starts in Report-Only).
export const RECOMMENDED = {
  hsts: {
    header: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains',
    note: 'Send it on HTTPS responses only. Before adding includeSubDomains, make sure every subdomain serves HTTPS. Add "; preload" only after reading the requirements at hstspreload.org, because removal from the preload list is slow. Tip: test with a short max-age (e.g. 300) first.',
    helmet: 'app.use(helmet.strictTransportSecurity({ maxAge: 31536000, includeSubDomains: true }));',
  },
  csp: {
    header: 'Content-Security-Policy-Report-Only', value: CSP_STARTER,
    note: 'This is a safe STARTER policy and it needs tuning: it allows only your own origin, so inline scripts/styles and third-party resources (analytics, fonts, CDNs) will be reported until you add them. It is sent as Content-Security-Policy-Report-Only so nothing breaks: watch the browser console (or add a report-to endpoint), adjust the policy, then rename the header to Content-Security-Policy to enforce it. Prefer nonces or hashes over \'unsafe-inline\'.',
    helmet: `app.use(helmet.contentSecurityPolicy({
  useDefaults: false,
  reportOnly: true, // switch to false once tuned
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'"],
    imgSrc: ["'self'", "data:"],
    fontSrc: ["'self'"],
    connectSrc: ["'self'"],
    objectSrc: ["'none'"],
    baseUri: ["'self'"],
    formAction: ["'self'"],
    frameAncestors: ["'self'"],
  },
}));`,
  },
  framing: {
    header: 'X-Frame-Options', value: 'SAMEORIGIN',
    note: "SAMEORIGIN still lets your own pages frame this one. Use DENY if you never frame it. The modern equivalent is the CSP directive frame-ancestors 'self' (included in the CSP starter policy).",
    helmet: 'app.use(helmet.xFrameOptions({ action: "sameorigin" }));',
  },
  xcto: {
    header: 'X-Content-Type-Options', value: 'nosniff',
    note: 'Safe for almost every site. Make sure your server sends correct Content-Type headers for scripts and styles.',
    helmet: 'app.use(helmet.xContentTypeOptions());',
  },
  referrer: {
    header: 'Referrer-Policy', value: 'strict-origin-when-cross-origin',
    note: 'Sends only your origin (no path or query) to other sites, and nothing from HTTPS to HTTP. Use no-referrer or same-origin for stricter privacy.',
    helmet: 'app.use(helmet.referrerPolicy({ policy: "strict-origin-when-cross-origin" }));',
  },
  permissions: {
    header: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()',
    note: 'Turns these features off for your pages and every embedded frame. Remove any feature your site actually uses (or allow it with e.g. geolocation=(self)). Add others you do not use, such as usb=() or payment=().',
    helmet: '// helmet has no Permissions-Policy middleware; set it directly:\napp.use((req, res, next) => {\n  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");\n  next();\n});',
  },
  coop: {
    header: 'Cross-Origin-Opener-Policy', value: 'same-origin',
    note: 'If you rely on popups that talk back to your page (OAuth sign-in, payment windows), use same-origin-allow-popups instead.',
    helmet: 'app.use(helmet.crossOriginOpenerPolicy({ policy: "same-origin" }));',
  },
  corp: {
    header: 'Cross-Origin-Resource-Policy', value: 'same-origin',
    note: 'Right for HTML pages. For images, scripts, fonts or APIs that OTHER sites must load, send same-site or cross-origin on those responses instead.',
    helmet: 'app.use(helmet.crossOriginResourcePolicy({ policy: "same-origin" }));',
  },
  xxss: {
    header: 'X-XSS-Protection', value: '0',
    note: 'Disables the deprecated XSS auditor (or simply remove the header). Rely on Content-Security-Policy instead.',
    helmet: 'app.use(helmet.xXssProtection()); // sets X-XSS-Protection: 0',
  },
};

const js = (s) => JSON.stringify(s);

export function setHeaderSnippets(items) {
  const helmetLines = items.map((i) => i.helmet || `app.use((req, res, next) => { res.setHeader(${js(i.header)}, ${js(i.value)}); next(); });`);
  const needsHelmet = helmetLines.some((l) => l.includes('helmet.'));
  return {
    nginx: `# server { } block. "always" also adds the header to error responses.\n# Note: add_header in a location { } replaces inherited ones; repeat them there.\n${items.map((i) => `add_header ${i.header} "${i.value}" always;`).join('\n')}`,
    apache: `# .htaccess (needs mod_headers)\n<IfModule mod_headers.c>\n${items.map((i) => `  Header always set ${i.header} "${i.value}"`).join('\n')}\n</IfModule>`,
    cloudflare: `# Cloudflare Pages: add to a file named _headers in your build output\n/*\n${items.map((i) => `  ${i.header}: ${i.value}`).join('\n')}\n\n// Cloudflare Workers: set headers on the response you return\nconst res = new Response(response.body, response);\n${items.map((i) => `res.headers.set(${js(i.header)}, ${js(i.value)});`).join('\n')}\nreturn res;\n\n# Proxied site (no code): Rules > Transform Rules > Modify Response Header`,
    netlify: `# _headers file in your publish directory\n/*\n${items.map((i) => `  ${i.header}: ${i.value}`).join('\n')}`,
    vercel: JSON.stringify({ headers: [{ source: '/(.*)', headers: items.map((i) => ({ key: i.header, value: i.value })) }] }, null, 2),
    express: `${needsHelmet ? '// npm install helmet\nimport helmet from "helmet";\n\n' : ''}${helmetLines.join('\n')}`,
  };
}

export function redirectSnippets(host) {
  return {
    nginx: `server {\n  listen 80;\n  listen [::]:80;\n  server_name ${host};\n  return 301 https://$host$request_uri;\n}`,
    apache: `# .htaccess (needs mod_rewrite). Behind a proxy/CDN, check X-Forwarded-Proto instead of %{HTTPS}.\nRewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]`,
    cloudflare: '# Dashboard: SSL/TLS > Edge Certificates > "Always Use HTTPS" = On\n# (Pages and workers.dev already serve HTTPS; custom domains need this switch.)',
    netlify: '# Netlify redirects HTTP to HTTPS automatically once the certificate is provisioned:\n# Domain management > HTTPS > Verify DNS configuration / Provision certificate.',
    vercel: '# Vercel redirects HTTP to HTTPS automatically for every deployment and custom domain.\n# If you still see HTTP, check that the domain points at Vercel (not another proxy).',
    express: `// Behind a proxy (Heroku, Render, nginx…) so req.secure reads X-Forwarded-Proto:\napp.set("trust proxy", 1);\napp.use((req, res, next) => {\n  if (req.secure) return next();\n  res.redirect(301, "https://${host}" + req.originalUrl);\n});`,
  };
}

const CANONICAL = { 'x-powered-by': 'X-Powered-By', 'x-aspnet-version': 'X-AspNet-Version', 'x-aspnetmvc-version': 'X-AspNetMvc-Version', server: 'Server' };

export function leakSnippets(headers) {
  const names = headers.map((h) => CANONICAL[h.header] || h.header);
  const powered = names.filter((n) => n !== 'Server');
  const unsetLines = (fmt) => powered.map(fmt).join('\n');
  return {
    nginx: `# http { } block\nserver_tokens off;   # hides the nginx version in Server\n${powered.length ? `# Headers added by your app/upstream:\n${unsetLines((n) => `proxy_hide_header ${n};     # proxied apps\nfastcgi_hide_header ${n};   # PHP-FPM`)}` : ''}`.trim(),
    apache: `# httpd.conf / vhost (NOT allowed in .htaccess):\nServerTokens Prod\nServerSignature Off\n${powered.length ? `\n# .htaccess (needs mod_headers):\n<IfModule mod_headers.c>\n${unsetLines((n) => `  Header always unset ${n}\n  Header unset ${n}`)}\n</IfModule>\n# PHP: set expose_php = Off in php.ini` : ''}`.trim(),
    cloudflare: `# Cloudflare Pages _headers (a "!" line removes a header; static assets only):\n/*\n${powered.map((n) => `  ! ${n}`).join('\n') || '  # (Server is set by Cloudflare and cannot be removed)'}\n\n// Workers:\n${powered.map((n) => `res.headers.delete(${js(n)});`).join('\n') || '// Server is set by Cloudflare itself.'}`,
    netlify: '# Netlify _headers cannot remove headers. These come from your framework or functions:\n# disable them there (e.g. Express: app.disable("x-powered-by"); PHP: expose_php = Off).',
    vercel: '# vercel.json cannot remove headers. They come from your framework or functions:\n# Next.js: set poweredByHeader: false in next.config.js; Express: app.disable("x-powered-by").',
    express: 'app.disable("x-powered-by"); // or: app.use(helmet.xPoweredBy())\n// IIS / ASP.NET (web.config): <httpRuntime enableVersionHeader="false" /> and\n// <httpProtocol><customHeaders><remove name="X-Powered-By" /></customHeaders></httpProtocol>',
  };
}

export function cookieSnippets() {
  return {
    nginx: '# nginx 1.19.3+ (reverse proxy): add flags to cookies from the upstream app\nproxy_cookie_flags ~ secure samesite=lax;\n# Add httponly too for session cookies, e.g.: proxy_cookie_flags session_id secure httponly samesite=lax;',
    apache: '# Best fixed where the cookie is created (your app/framework settings).\n# PHP (php.ini): session.cookie_secure = 1, session.cookie_httponly = 1, session.cookie_samesite = "Lax"',
    cloudflare: '// Workers: set flags when you create cookies\nres.headers.append("Set-Cookie", "name=value; Path=/; Secure; HttpOnly; SameSite=Lax");',
    netlify: '# Netlify _headers cannot rewrite Set-Cookie. Set Secure; HttpOnly; SameSite=Lax where your\n# functions or framework create the cookie.',
    vercel: '# vercel.json cannot rewrite Set-Cookie. Set Secure; HttpOnly; SameSite=Lax where your\n# functions or framework create the cookie (e.g. Next.js cookies().set(name, value, { secure: true, httpOnly: true, sameSite: "lax" })).',
    express: 'res.cookie("name", value, { secure: true, httpOnly: true, sameSite: "lax" });\n// express-session: session({ cookie: { secure: true, httpOnly: true, sameSite: "lax" } })',
  };
}

/** Builds fix items for failing/weak findings plus a combined snippet per platform. */
export function buildFixes(findings, { host }) {
  const byId = Object.fromEntries(findings.map((f) => [f.id, f]));
  const items = [];
  const headerItems = [];
  const weak = (f) => f && (f.status === 'fail' || f.status === 'warn');

  if (weak(byId.https) && byId.https.points < 10) {
    items.push({ id: 'https', title: 'Redirect HTTP to HTTPS', header: null, value: null, note: 'Serve the site over HTTPS (free certificates: Let\'s Encrypt, or your host/CDN) and permanently redirect plain HTTP to it.', snippets: redirectSnippets(host) });
  }
  for (const id of ['hsts', 'csp', 'framing', 'xcto', 'referrer', 'permissions', 'coop', 'corp', 'xxss']) {
    const f = byId[id];
    if (!weak(f)) continue;
    const rec = RECOMMENDED[id];
    let note = rec.note;
    if (id === 'csp' && f.present) note = 'Your site already sends a CSP; fix the issues listed above in your existing policy. The starter policy below is only a reference point. ' + rec.note;
    if (id === 'framing' && f.value) note = 'Replace the current value. ' + rec.note;
    items.push({ id, title: `${f.present ? 'Fix' : 'Add'} ${rec.header}`, header: rec.header, value: rec.value, note, snippets: setHeaderSnippets([rec]) });
    headerItems.push(rec);
  }
  const leakHeaders = (byId.leaks?.details?.headers || []).filter((h) => h.penalized);
  if (leakHeaders.length) items.push({ id: 'leaks', title: 'Hide version / technology headers', header: null, value: null, note: 'Version numbers help attackers pick exploits. Removing them is low-risk.', snippets: leakSnippets(leakHeaders) });
  if (weak(byId.cookies)) items.push({ id: 'cookies', title: 'Add cookie flags', header: null, value: null, note: 'Mark cookies Secure and give them a SameSite value (Lax is a safe default). Add HttpOnly to session cookies so JavaScript (and XSS) cannot read them.', snippets: cookieSnippets() });

  return { items, combined: headerItems.length ? setHeaderSnippets(headerItems) : null, platforms: Object.fromEntries(PLATFORMS) };
}
