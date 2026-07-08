# VibeSnitch

Black-box QA for vibecoders. Paste your app's URL → it scans from the outside →
you get a **Snitch Score (A–F)** and a prioritized bug dossier with a shareable link.
No access to your code. Open-source (MIT).

## Files
```
index.html                          # front-end: landing, live-scan theater, scorecard, share
og-card.svg                         # social share image
netlify/functions/scan.mjs          # scan — recon + deep phases (native fetch, no deps)
netlify/functions/badge.mjs         # SVG grade badge for READMEs
netlify/functions/lib/detectors.mjs # secrets, headers, stack fingerprint, grade (unit-tested)
netlify.toml · LICENSE
```
No build step, no npm install, no database, no auth.

## Deploy
- **Drag & drop:** zip the folder → drop on https://app.netlify.com/drop
- **Git (recommended, open-source):** push to GitHub → Netlify → Import from Git →
  build command empty, publish `.`. Enable **Forms** in the Netlify UI for the email capture.

Then edit two things:
1. `index.html` → the `#ghLink` href → your real GitHub repo.
2. (optional) rename the site in Netlify → Site settings → Change site name.

## How the scan works
- **recon phase** (fast) — fetches the app, fingerprints the stack (Next/Vite/Supabase/
  Stripe/Vercel…), counts bundles/lines/JWTs. Feeds the live "interrogation" theater with
  *real* data while the deep scan runs in parallel.
- **deep phase** — the 5 checks below → findings → **Snitch Score**.

### The 5 checks (black-box)
1. HTTP status / 5xx on the homepage and probed routes
2. Security headers (CSP, X-Frame-Options, HSTS…)
3. **Exposed secrets** ★ — `sk_live_`, Supabase `service_role` JWTs (decoded; the public
   `anon` key is *not* flagged), OpenAI/Anthropic/AWS/GitHub/Slack/SendGrid, private keys
4. Critical paths + **your own routes** (list them) — flagged on 5xx
5. Dead links

Secrets are **redacted** in the report, so a shared public link never leaks the real key.

### Grade
100 minus deductions (leaked secret = auto **F**; 5xx = heavy; missing header = light).
`A ≥90 · B ≥78 · C ≥62 · D ≥45 · F <45`.

## Deep scan (behind a login)
Switch to **🔒 Deep scan**, point at your **app** subdomain, and paste a **Cookie** or
**Bearer** token (DevTools → Network → any request → copy the header). List your routes
(`/api/ddpp, /api/export`) — the scanner hits them *with your session* and flags 5xx.

## Badge
After a scan, copy the README snippet:
`[![VibeSnitch](https://YOUR-SITE/.netlify/functions/badge?g=A)](https://YOUR-SITE)`

## Not in V1 (stated in every report)
- Endpoint auto-discovery behind login · JS console errors · RLS holes → all need a
  headless browser or two test accounts (V1.5).
- **Dynamic per-grade OG image** → needs a PNG renderer (small deps); the tweet text
  carries the grade meanwhile.

## Tests
```
node test/detectors.test.mjs   # grade thresholds, fingerprint, secret precision
```
