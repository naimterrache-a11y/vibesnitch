// VibeSnitch scan (Netlify Functions v2). Native fetch only — zero npm deps.
// Two phases: ?phase=recon (fast facts for the live theater) and deep (full scan + grade).
import { findSecrets, checkHeaders, extractAssets, redact, SEV_ORDER, fingerprintStack, computeGrade, findAnonKey, extractApiRoutes } from "./lib/detectors.mjs";

const LIMITS = {
  // maxBytes 5MB: Vite bundles routinely exceed 2.5MB and were getting truncated.
  // maxScripts trimmed 12→8 so the larger per-bundle cap doesn't blow the function timeout. perFetchMs unchanged.
  perFetchMs: 6000, maxScripts: 8, maxBytes: 5_000_000, maxLinks: 12, maxUserRoutes: 12,
  probePaths: ["/login", "/signup", "/api/health", "/api", "/admin"],
};
const UA = "VibeSnitch/1.0 (+https://vibesnitch.netlify.app) black-box scanner";
const AUTH_URL_RE = /\/(login|signin|sign-in|log-in|auth|authenticate|account\/login)(\/|$|\?)/i;

async function grab(url, { method = "GET", headers = {} } = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), LIMITS.perFetchMs);
  try { return await fetch(url, { method, redirect: "follow", signal: ctrl.signal, headers: { "user-agent": UA, "accept": "*/*", ...headers } }); }
  finally { clearTimeout(t); }
}
async function readCapped(res) {
  const reader = res.body?.getReader(); if (!reader) return await res.text();
  let received = 0; const dec = new TextDecoder(); let out = "";
  while (true) { const { done, value } = await reader.read(); if (done) break; received += value.length; out += dec.decode(value, { stream: true }); if (received >= LIMITS.maxBytes) { try { await reader.cancel(); } catch {} break; } }
  return out;
}
function normalizeUrl(raw) { let u = (raw || "").trim(); if (!u) return null; if (!/^https?:\/\//i.test(u)) u = "https://" + u; try { const p = new URL(u); if (!/^https?:$/.test(p.protocol)) return null; return p.href; } catch { return null; } }
function headersToObj(h) { const o = {}; for (const [k, v] of h.entries()) o[k.toLowerCase()] = v; return o; }
function parseRoutes(input) { if (!input) return []; const parts = Array.isArray(input) ? input : String(input).split(/[\s,]+/); return parts.map(s => s.trim()).filter(Boolean).slice(0, LIMITS.maxUserRoutes); }
function looksLikeLoginHtml(html) { return /<input[^>]+type=["']password["']/i.test(html); }
function authHeadersFrom(body) {
  const a = {};
  if (body.cookie) a["cookie"] = String(body.cookie).replace(/^cookie:\s*/i, "");
  if (body.bearer) a["authorization"] = "Bearer " + String(body.bearer).trim().replace(/^authorization:\s*/i, "").replace(/^bearer\s+/i, "");
  if (body.basicAuth) a["authorization"] = "Basic " + Buffer.from(String(body.basicAuth)).toString("base64");
  return a;
}
function countJwts(text) {
  const re = /\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b/g;
  const s = new Set(); let m; while ((m = re.exec(text))) s.add(m[0]); return s.size;
}

export default async (req) => {
  const started = Date.now();
  let body = {}; try { body = await req.json(); } catch {}
  const target = normalizeUrl(body.url);
  if (!target) return json({ ok: false, error: "That doesn't look like a URL. Try https://app.your-saas.com" }, 400);
  const authHeaders = authHeadersFrom(body);
  const url = new URL(req.url);
  const phase = body.phase || url.searchParams.get("phase") || "deep";

  // ---------- RECON ----------
  if (phase === "recon") {
    let res, html = "", H = {}, finalUrl = target;
    try { res = await grab(target, { headers: authHeaders }); finalUrl = res.url || target; H = headersToObj(res.headers); html = await readCapped(res); }
    catch (e) { return json({ ok: true, phase: "recon", reachable: false, target, note: (e && e.name) === "AbortError" ? "timeout" : "unreachable" }); }
    const { scripts } = extractAssets(html, finalUrl);
    const jsUrls = scripts.filter(s => /\.(js|mjs|cjs)(\?|$)/i.test(s) || s.includes("/_next/") || s.includes("/assets/"));
    // fetch the first real bundle to get honest line/byte/jwt counts
    let biggestFile = "", biggestLines = 0, sampledBytes = html.length, jwtCount = countJwts(html);
    let bundleTxt = "";
    const first = jsUrls[0];
    if (first) {
      try { const r = await grab(first); const txt = await readCapped(r); bundleTxt = txt; biggestFile = new URL(first).pathname.split("/").pop() || first; biggestLines = (txt.match(/\n/g) || []).length + 1; sampledBytes += txt.length; jwtCount += countJwts(txt); }
      catch {}
    }
    // Fingerprint against the real bundle JS too — Supabase/Stripe/etc. often only appear in the JS, not the HTML. Reuses the txt we already fetched (no extra request).
    const stack = fingerprintStack(html, H, bundleTxt);
    // Expose the Supabase project URL + anon key so the front-end can log the user in client-side (password never touches our server).
    const hay = html + "\n" + bundleTxt;
    const supMatch = hay.match(/https:\/\/[a-z0-9]+\.supabase\.co/);
    const supabaseUrl = supMatch ? supMatch[0] : "";
    const supabaseAnonKey = findAnonKey(hay);
    const gated = (AUTH_URL_RE.test(finalUrl) && !AUTH_URL_RE.test(target)) || looksLikeLoginHtml(html);
    return json({
      ok: true, phase: "recon", reachable: true, target, finalUrl,
      status: res.status, ms: Date.now() - started, host: new URL(finalUrl).hostname,
      stack, bundleCount: jsUrls.length, sampledBytes, biggestFile, biggestLines, jwtCount, gated,
      supabaseUrl, supabaseAnonKey,
    });
  }

  // ---------- DEEP ----------
  const userRoutes = parseRoutes(body.routes);
  const hasAuth = Object.keys(authHeaders).length > 0;
  const host = new URL(target).hostname;
  const findings = []; const checksRun = []; const push = (f) => findings.push(f);

  let rootRes, rootHtml = "", rootHeaders = {}, finalUrl = target;
  try { rootRes = await grab(target, { headers: authHeaders }); finalUrl = rootRes.url || target; rootHeaders = headersToObj(rootRes.headers); rootHtml = await readCapped(rootRes); checksRun.push("reachability"); }
  catch (e) {
    return json({ ok: true, report: report(target, started, [{ sev: "critical", title: "App is unreachable", evidence: `${(e && e.name) === "AbortError" ? "Timed out" : "Connection failed"} for ${target}`, source: "network", why: "The scanner couldn't load your app at all.", fix: "Confirm the URL is public and up." }], ["reachability"], { gated: false, hadAuth: hasAuth }) });
  }

  const gated = (AUTH_URL_RE.test(finalUrl) && !AUTH_URL_RE.test(target)) || looksLikeLoginHtml(rootHtml);
  if (rootRes.status >= 500) push({ sev: "critical", title: `Homepage returns ${rootRes.status}`, evidence: `GET ${target} → ${rootRes.status}`, source: "http", why: "Your front door is throwing a server error. Every visitor hits this.", fix: "Check server logs for the stack trace behind this 5xx." });

  for (const f of checkHeaders(rootHeaders)) push(f);
  checksRun.push("security-headers");

  const { scripts, links, inline } = extractAssets(rootHtml, finalUrl);
  const secretHits = [];
  for (const code of inline) secretHits.push(...findSecrets(code, "inline <script>"));
  secretHits.push(...findSecrets(rootHtml, "page HTML"));
  const jsToScan = scripts.filter(s => /\.(js|mjs|cjs)(\?|$)/i.test(s) || s.includes("/_next/") || s.includes("/assets/")).slice(0, LIMITS.maxScripts);
  let stackJs = "";
  const jsResults = await Promise.allSettled(jsToScan.map(async (s) => { const r = await grab(s); const txt = await readCapped(r); return { txt, hits: findSecrets(txt, fileLabel(s)) }; }));
  for (const r of jsResults) if (r.status === "fulfilled") { secretHits.push(...r.value.hits); if (stackJs.length < 400000) stackJs += r.value.txt.slice(0, 200000); }
  checksRun.push("exposed-secrets");
  const stack = fingerprintStack(rootHtml, rootHeaders, stackJs);

  const seen = new Map();
  for (const h of secretHits) { const key = h.kind + "|" + (h.sample || ""); if (seen.has(key)) { seen.get(key).count++; continue; } seen.set(key, { ...h, count: 1 }); }
  for (const h of seen.values()) push({ sev: h.sev, title: `Exposed ${h.kind}`, evidence: `${redact(h.sample || h.kind)}  ·  found in ${h.source}${h.count > 1 ? ` (+${h.count - 1} more)` : ""}`, source: h.source, why: h.why, fix: h.fix, secret: true });

  // Auto-discover API routes baked into the bundle JS and probe them alongside the user's manual routes.
  // Merge manual + auto, dedup on the absolute URL, cap the user-side list at 15. Auto routes are marked so
  // we only surface their real signal (5xx) and stay quiet on the expected 401/403/404 of protected endpoints.
  const autoRoutes = extractApiRoutes(stackJs);
  const userRouteObjs = []; const seenRouteUrl = new Set();
  for (const p of [...userRoutes.map(x => ({ p: x, auto: false })), ...autoRoutes.map(x => ({ p: x, auto: true }))]) {
    const u = absOn(finalUrl, p.p); if (!u || seenRouteUrl.has(u)) continue;
    seenRouteUrl.add(u); userRouteObjs.push({ url: u, user: true, auto: p.auto });
    if (userRouteObjs.length >= 15) break;
  }
  const routeTargets = [...userRouteObjs, ...LIMITS.probePaths.map(p => ({ url: absOn(finalUrl, p), user: false, auto: false }))].filter(x => x.url);
  const routeResults = await Promise.allSettled(routeTargets.map(async (x) => { const r = await grab(x.url, { headers: authHeaders }); return { ...x, status: r.status, land: r.url }; }));
  let authRejections = 0; // manual routes only — drives the "your routes need a login" messaging below
  for (const r of routeResults) {
    if (r.status !== "fulfilled") continue;
    const { url: u, user, auto, status, land } = r.value; const path = safePath(u);
    if (status >= 500) push({ sev: "critical", title: `${path} returns ${status}`, evidence: `GET ${path} → ${status}`, source: "http", why: "This route is crashing with a server error — exactly the kind of silent 500 that runs for weeks unnoticed.", fix: "Open the server logs for this route and fix the exception." });
    else if (user && (status === 401 || status === 403 || AUTH_URL_RE.test(land || ""))) { if (!auto) authRejections++; } // auto 401/403 counted-and-ignored (protected endpoint = expected)
    else if (user && !auto && status === 404) push({ sev: "medium", title: `${path} not found (404)`, evidence: `GET ${path} → 404`, source: "http", why: "You asked to test this route and it doesn't exist.", fix: "Check the path." });
  }
  checksRun.push("route-tests");
  if (userRoutes.length && authRejections === userRoutes.length && !hasAuth) push({ sev: "info", title: "Your routes need a login — no session was provided", evidence: `${authRejections} route(s) returned 401/403 or bounced to login`, source: "auth", why: "The routes you listed are protected. Without a session, VibeSnitch can only knock on the door.", fix: "Add your Cookie or Bearer token and re-scan." });
  else if (hasAuth && userRoutes.length && authRejections === userRoutes.length) push({ sev: "high", title: "Your session didn't authenticate", evidence: `every protected route still returned 401/403 with the token you pasted`, source: "auth", why: "The Cookie/Bearer you gave is expired, wrong, or for a different domain.", fix: "Grab a fresh Cookie/Authorization header while logged in, and re-scan." });

  const internal = links.filter(l => { try { return new URL(l).hostname === host; } catch { return false; } }).filter((v, i, a) => a.indexOf(v) === i).slice(0, LIMITS.maxLinks);
  const linkResults = await Promise.allSettled(internal.map(async (u) => { const r = await grab(u, { headers: authHeaders }); return { u, status: r.status }; }));
  for (const r of linkResults) { if (r.status !== "fulfilled") continue; const { u, status } = r.value; const path = safePath(u);
    if (status >= 500) push({ sev: "high", title: `Broken link → ${path} (${status})`, evidence: `GET ${path} → ${status}`, source: "http", why: "A link on the page leads to a server error.", fix: "Fix or remove the route." });
    else if (status === 404) push({ sev: "medium", title: `Dead link → ${path}`, evidence: `GET ${path} → 404`, source: "http", why: "A link on the page points nowhere.", fix: "Update or remove the link." }); }
  checksRun.push("dead-links");

  return json({ ok: true, report: report(target, started, findings, checksRun, { gated, hadAuth: hasAuth, testedRoutes: userRoutes.length, stack }) });
};

function absOn(base, p) { try { return new URL(p, base).href; } catch { return null; } }
function safePath(u) { try { const x = new URL(u); return (x.pathname || "/") + (x.search || ""); } catch { return u; } }
function fileLabel(url) { try { return new URL(url).pathname.split("/").pop() || url; } catch { return url; } }

function report(target, started, findings, checksRun, meta = {}) {
  findings.sort((a, b) => (SEV_ORDER[a.sev] - SEV_ORDER[b.sev]));
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) if (counts[f.sev] != null) counts[f.sev]++;
  const total = findings.filter(f => f.sev !== "info").length;
  const { score, grade, blurb } = computeGrade(findings);
  let verdict;
  if (counts.critical) verdict = `${counts.critical} thing${counts.critical > 1 ? "s" : ""} your app is leaking or breaking right now.`;
  else if (total) verdict = `${total} issue${total > 1 ? "s" : ""} worth fixing. Nothing on fire.`;
  else verdict = "Nothing incriminating on the surface. Your app kept its mouth shut.";
  return {
    target, scannedAt: new Date().toISOString(), ms: Date.now() - started,
    counts, total, verdict, findings, checksRun, grade, score, gradeBlurb: blurb,
    stack: meta.stack || [], gated: !!meta.gated, hadAuth: !!meta.hadAuth, testedRoutes: meta.testedRoutes || 0,
    notScanned: [
      "Endpoint auto-discovery behind the login (needs a headless browser — V1.5). Until then, list your routes to test.",
      "JavaScript console errors (needs a headless browser — V1.5).",
      "Row-Level-Security holes (needs two test accounts — V1.5).",
    ],
  };
}
function json(obj, status = 200) { return new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } }); }
