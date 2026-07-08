// VibeSnitch — detection logic. Pure functions, no network. Unit-testable offline.
// Precision > recall: we would rather miss a leak than falsely accuse (trust is the product).

// ---- helpers ----
function b64urlDecode(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  try { return Buffer.from(s, "base64").toString("utf8"); } catch { return ""; }
}

// Redact a secret so a *public* dossier link never leaks the full key.
export function redact(v) {
  if (!v) return "";
  const s = String(v).trim();
  if (s.length <= 12) return s.slice(0, 2) + "…";
  return s.slice(0, 7) + "…" + s.slice(-4) + `  (${s.length} chars)`;
}

// ---- secret detectors ----
// Each returns {sev, kind, sample} or null. `sample` is the raw match (redacted later).
const SECRET_RULES = [
  { kind: "Stripe secret key (LIVE)", sev: "critical",
    re: /\bsk_live_[0-9a-zA-Z]{20,}\b/g,
    why: "Anyone can charge, refund and read your Stripe account. This is your cash register key, in public.",
    fix: "Roll the key in Stripe now. Move all Stripe calls server-side; the browser must only ever see pk_ keys." },
  { kind: "Stripe restricted key (LIVE)", sev: "critical",
    re: /\brk_live_[0-9a-zA-Z]{20,}\b/g,
    why: "A live restricted Stripe key is exposed. Its scopes can be abused by anyone who reads your JS.",
    fix: "Roll it in Stripe and keep it server-side only." },
  { kind: "Stripe secret key (TEST)", sev: "high",
    re: /\bsk_(test)_[0-9a-zA-Z]{20,}\b/g,
    why: "A test secret key is public. No money at risk, but it exposes your integration and habits.",
    fix: "Roll it and stop shipping any sk_ key to the client." },
  { kind: "OpenAI API key", sev: "critical",
    re: /\bsk-proj-[A-Za-z0-9_\-]{20,}\b|\bsk-[A-Za-z0-9]{48}\b/g,
    why: "Anyone can spend your OpenAI credits until the bill or the quota kills you.",
    fix: "Revoke it in the OpenAI dashboard and proxy calls through your backend." },
  { kind: "Anthropic API key", sev: "critical",
    re: /\bsk-ant-[A-Za-z0-9_\-]{20,}\b/g,
    why: "Anyone can spend your Anthropic credits on your dime.",
    fix: "Revoke it in the Anthropic console and call Claude from your server, not the browser." },
  { kind: "AWS access key id", sev: "critical",
    re: /\bAKIA[0-9A-Z]{16}\b/g,
    why: "An AWS key id is in your bundle. Paired with its secret it can own your cloud.",
    fix: "Deactivate the key in IAM immediately and rotate. Never ship AWS creds to the client." },
  { kind: "GitHub token", sev: "critical",
    re: /\bghp_[0-9A-Za-z]{36}\b|\bgithub_pat_[0-9A-Za-z_]{22,}\b/g,
    why: "A GitHub token grants access to your repos — possibly private ones.",
    fix: "Revoke it in GitHub settings now and rotate anything it touched." },
  { kind: "Slack token", sev: "critical",
    re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g,
    why: "A Slack token can read and post in your workspace.",
    fix: "Revoke it in Slack app settings." },
  { kind: "SendGrid API key", sev: "critical",
    re: /\bSG\.[\w\-]{20,}\.[\w\-]{30,}\b/g,
    why: "Anyone can send email as you — great for phishing your own users.",
    fix: "Delete the key in SendGrid and issue a new one server-side." },
  { kind: "Google API key", sev: "medium",
    re: /\bAIza[0-9A-Za-z_\-]{35}\b/g,
    why: "A Google API key is public. Often intentional (Maps), but unrestricted keys get abused and billed.",
    fix: "Restrict the key by HTTP referrer / API in the Google Cloud console." },
  { kind: "Private key block", sev: "critical",
    re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g,
    why: "A private key is embedded in client code. That is game over for whatever it signs or decrypts.",
    fix: "Rotate the key pair and never bundle private keys into the frontend." },
  { kind: "Supabase service_role variable", sev: "critical",
    re: /SUPABASE_SERVICE_ROLE(?:_KEY)?/g,
    why: "The service_role name is in your bundle — its value is likely nearby. service_role bypasses every RLS rule.",
    fix: "Remove it from client code. Only the anon key belongs in the browser." },
];

// JWT scan: find service_role tokens precisely (decode the payload, check the role claim).
// Critically: the Supabase ANON key is ALSO a JWT and is MEANT to be public — we must NOT flag it.
function scanJwts(text) {
  const out = [];
  const re = /\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b/g;
  let m;
  const seen = new Set();
  while ((m = re.exec(text))) {
    const tok = m[0];
    if (seen.has(tok)) continue;
    seen.add(tok);
    const payload = b64urlDecode(tok.split(".")[1] || "");
    let role = "";
    try { role = (JSON.parse(payload) || {}).role || ""; } catch { /* not a role JWT */ }
    if (role === "service_role") {
      out.push({
        kind: "Supabase service_role key",
        sev: "critical",
        sample: tok,
        why: "This JWT decodes to role=service_role. It bypasses ALL your Row Level Security. Anyone can read, edit or wipe your entire database.",
        fix: "Rotate the service_role key in Supabase now. The browser must only ever hold the anon key.",
      });
    }
    // role === 'anon' is public by design → intentionally NOT flagged.
  }
  return out;
}

// Find the Supabase ANON key: the JWT whose decoded payload has role==="anon".
// Public by design (the browser needs it to log a user in) — same regex as scanJwts.
// Returns the first anon token, or "" (never returns a service_role token).
export function findAnonKey(text) {
  const re = /\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b/g;
  let m;
  while ((m = re.exec(text || ""))) {
    const tok = m[0];
    const payload = b64urlDecode(tok.split(".")[1] || "");
    let role = "";
    try { role = (JSON.parse(payload) || {}).role || ""; } catch { /* not a role JWT */ }
    if (role === "anon") return tok;
  }
  return "";
}

// Auto-discover API route literals baked into the bundle JS (e.g. "/api/ddpp", "/rest/v1/foo").
// Strips dynamic segments (/:id, /${...}), dedups, caps at 15. The deep scan probes these so it can
// test endpoints it would otherwise never know existed.
export function extractApiRoutes(text) {
  const t = text || "";
  const out = [];
  const seen = new Set();
  const patterns = [
    /["'`](\/api\/[A-Za-z0-9_\-\/]+)["'`]/g,
    /["'`](\/(?:rest|auth|functions)\/v1\/[A-Za-z0-9_\-\/]+)["'`]/g,
  ];
  for (const re of patterns) {
    let m;
    re.lastIndex = 0;
    while ((m = re.exec(t))) {
      const p = m[1]
        .replace(/\/:[A-Za-z0-9_\-]+/g, "")   // drop /:id style params
        .replace(/\/\$\{[^}]*\}/g, "")         // drop /${...} template segments
        .replace(/\/+$/, "");                   // trailing slash
      if (!p || seen.has(p)) continue;
      seen.add(p);
      out.push(p);
      if (out.length >= 15) return out;
    }
  }
  return out;
}

// Run all secret detectors over a blob of text (html or js). Returns array of raw findings.
export function findSecrets(text, sourceLabel) {
  const findings = [];
  for (const rule of SECRET_RULES) {
    const seen = new Set();
    let m;
    rule.re.lastIndex = 0;
    while ((m = rule.re.exec(text))) {
      const val = m[0];
      if (seen.has(val)) continue;
      seen.add(val);
      findings.push({ kind: rule.kind, sev: rule.sev, sample: val, why: rule.why, fix: rule.fix, source: sourceLabel });
    }
  }
  for (const j of scanJwts(text)) findings.push({ ...j, source: sourceLabel });
  return findings;
}

// ---- security headers ----
const HEADER_RULES = [
  { name: "content-security-policy", sev: "high", label: "Content-Security-Policy",
    why: "No CSP. If any input is reflected, an attacker can inject scripts (XSS) with nothing stopping them.",
    fix: "Add a Content-Security-Policy header, even a strict-ish default-src 'self' to start." },
  { name: "x-frame-options", sev: "high", label: "X-Frame-Options",
    why: "Your app can be embedded in an invisible iframe (clickjacking) to trick users into clicking things.",
    fix: "Send X-Frame-Options: DENY (or frame-ancestors 'none' in your CSP)." },
  { name: "strict-transport-security", sev: "medium", label: "Strict-Transport-Security",
    why: "No HSTS. A first visit over http can be downgraded/intercepted before https kicks in.",
    fix: "Add Strict-Transport-Security: max-age=31536000; includeSubDomains." },
  { name: "x-content-type-options", sev: "low", label: "X-Content-Type-Options",
    why: "Browsers may MIME-sniff responses, occasionally turning an upload into executable content.",
    fix: "Add X-Content-Type-Options: nosniff." },
  { name: "referrer-policy", sev: "low", label: "Referrer-Policy",
    why: "Full URLs (with tokens in query strings) can leak to third parties via the Referer header.",
    fix: "Add Referrer-Policy: strict-origin-when-cross-origin." },
];

export function checkHeaders(headersObj) {
  // headersObj: plain object with lowercased keys
  const findings = [];
  for (const r of HEADER_RULES) {
    if (!headersObj[r.name]) {
      findings.push({
        sev: r.sev,
        title: `Missing ${r.label} header`,
        evidence: `${r.label}: (not set)`,
        source: "response headers",
        why: r.why,
        fix: r.fix,
      });
    }
  }
  return findings;
}

// ---- html parsing (regex-based, dependency-free) ----
export function extractAssets(html, baseUrl) {
  const scripts = new Set();
  const links = new Set();
  const assets = new Set();
  const abs = (u) => { try { return new URL(u, baseUrl).href; } catch { return null; } };

  let m;
  const scriptRe = /<script[^>]+src=["']([^"']+)["']/gi;
  while ((m = scriptRe.exec(html))) { const u = abs(m[1]); if (u) scripts.add(u); }

  const linkRe = /<link[^>]+href=["']([^"']+)["']/gi;
  while ((m = linkRe.exec(html))) { const u = abs(m[1]); if (u) assets.add(u); }

  const aRe = /<a[^>]+href=["']([^"'#]+)["']/gi;
  while ((m = aRe.exec(html))) { const u = abs(m[1]); if (u && !u.startsWith("mailto:") && !u.startsWith("tel:")) links.add(u); }

  const imgRe = /<img[^>]+src=["']([^"']+)["']/gi;
  while ((m = imgRe.exec(html))) { const u = abs(m[1]); if (u) assets.add(u); }

  // inline scripts (for secrets baked straight into the HTML)
  const inline = [];
  const inlineRe = /<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi;
  while ((m = inlineRe.exec(html))) { if (m[1] && m[1].trim().length > 8) inline.push(m[1]); }

  return { scripts: [...scripts], links: [...links], assets: [...assets], inline };
}

export const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// ---- stack fingerprint (real signals from html + headers + bundle) ----
export function fingerprintStack(html, headers, jsText) {
  const hits = new Set();
  const H = headers || {};
  const text = (html || "") + "\n" + (jsText || "");
  const server = (H["server"] || "").toLowerCase();
  const powered = (H["x-powered-by"] || "").toLowerCase();
  const add = (c) => hits.add(c);

  if (H["x-vercel-id"] || H["x-vercel-cache"] || server.includes("vercel")) add("Vercel");
  if (H["x-nf-request-id"] || server.includes("netlify")) add("Netlify");
  if (H["cf-ray"] || server.includes("cloudflare")) add("Cloudflare");
  if (powered.includes("next") || /\/_next\//.test(text) || /__NEXT_DATA__/.test(text)) add("Next.js");
  if (/_nuxt\//.test(text)) add("Nuxt");
  if (powered.includes("express")) add("Express");
  if (/\/@vite\/client/.test(text) || /assets\/index-[A-Za-z0-9]+\.js/.test(text)) add("Vite");
  if (/data-reactroot|react-dom|React\.createElement|__REACT_DEVTOOLS/.test(text) || /\/_next\//.test(text)) add("React");
  if (/__vue__|vue\.runtime|data-v-[0-9a-f]{6,}/.test(text)) add("Vue");
  if (/\bsvelte\b|__svelte|svelte-/.test(text)) add("Svelte");
  if (/supabase/i.test(text)) add("Supabase");
  if (/firebaseio\.com|firebaseapp\.com|firebaseConfig|firebase\/app/.test(text)) add("Firebase");
  if (/js\.stripe\.com|Stripe\(/.test(text)) add("Stripe");
  if (/clerk\.(com|dev|accounts)|__clerk|clerk-js/.test(text)) add("Clerk");
  if (/auth0\.com|@auth0/.test(text)) add("Auth0");
  if (/js\.sentry|sentry-cdn|Sentry\.init|@sentry/.test(text)) add("Sentry");
  if (/googletagmanager|gtag\(/.test(text)) add("Google Analytics");
  if (/posthog/i.test(text)) add("PostHog");
  if (/cdn\.tailwindcss|tailwind/.test(text)) add("Tailwind");
  return [...hits];
}

// ---- grade (transparent, testable). Exposed secrets dominate → automatic F ----
export function computeGrade(findings) {
  let score = 100, hasCriticalSecret = false;
  for (const f of findings) {
    if (f.sev === "critical") { if (f.secret) { hasCriticalSecret = true; score -= 70; } else score -= 40; }
    else if (f.sev === "high") score -= 12;
    else if (f.sev === "medium") score -= 5;
    else if (f.sev === "low") score -= 2;
  }
  score = Math.max(0, Math.min(100, score));
  let grade;
  if (hasCriticalSecret) grade = "F";
  else if (score >= 90) grade = "A";
  else if (score >= 78) grade = "B";
  else if (score >= 62) grade = "C";
  else if (score >= 45) grade = "D";
  else grade = "F";
  const blurb = {
    A: "Locked down. This app kept its secrets.",
    B: "Solid. A couple of things to tighten.",
    C: "Leaky in places. Nothing on fire, but fix these.",
    D: "Exposed. Real gaps an attacker would enjoy.",
    F: "Wide open. Something critical is leaking right now.",
  }[grade];
  return { score, grade, blurb };
}
