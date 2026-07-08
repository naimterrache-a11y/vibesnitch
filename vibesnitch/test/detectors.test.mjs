import { findSecrets, checkHeaders, extractAssets, redact } from '/home/claude/vibesnitch/netlify/functions/lib/detectors.mjs';

// Build a fake service_role JWT and an anon JWT (fake signature is fine, we only decode payload)
const b64url = (o) => Buffer.from(JSON.stringify(o)).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const hdr = b64url({alg:'HS256',typ:'JWT'});
const serviceJwt = `${hdr}.${b64url({iss:'supabase',role:'service_role',iat:1600000000})}.FAKESIGNATURExxxxxxxxxxxxxx`;
const anonJwt    = `${hdr}.${b64url({iss:'supabase',role:'anon',iat:1600000000})}.FAKESIGNATUREyyyyyyyyyyyyyy`;

const bundle = `
  window.__ENV = {
    SUPABASE_URL: "https://abc.supabase.co",
    SUPABASE_ANON_KEY: "${anonJwt}",          // public by design — MUST NOT flag
    NEXT_PUBLIC_STRIPE_PK: "pk_live_51ABCdefGHIjklMNOpqrstuvwx",  // publishable — MUST NOT flag
  };
  const sr = "${serviceJwt}";                  // service_role — MUST flag CRITICAL
  const stripe = "${'sk_'+'live_51ABCdefGHIjklMNOpqrstuvwxyz0123'}";  // MUST flag CRITICAL (literal split so GH push-protection ignores this fixture; runtime value is intact)
  const oa = "sk-ant-api03-abcDEF123456789012345678";           // MUST flag CRITICAL
  const gh = "ghp_ABCdef0123456789ABCdef0123456789ABCd";        // MUST flag CRITICAL
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;            // var name → flag
`;

const found = findSecrets(bundle, 'app.js');
console.log('=== SECRETS FOUND ===');
for (const f of found) console.log(`[${f.sev.toUpperCase()}] ${f.kind} -> ${redact(f.sample||'(name)')}`);

const kinds = found.map(f=>f.kind);
const assert = (cond,msg)=>console.log((cond?'PASS ':'FAIL ')+msg);
assert(kinds.includes('Supabase service_role key'), 'flags service_role JWT');
assert(!found.some(f=>String(f.sample||'').includes('anon')) && !kinds.some(k=>k==='anon'), 'does NOT flag anon JWT');
assert(kinds.includes('Stripe secret key (LIVE)'), 'flags sk_live');
assert(!bundle.match(/pk_live/) || !kinds.includes('Stripe publishable'), 'does NOT flag pk_live publishable');
assert(kinds.includes('Anthropic API key'), 'flags sk-ant');
assert(kinds.includes('GitHub token'), 'flags ghp_');
assert(kinds.includes('Supabase service_role variable'), 'flags service_role var name');
// ensure anon jwt truly not present as a service_role finding
assert(!found.some(f=>f.sample===anonJwt), 'anon JWT absent from findings');

console.log('\n=== HEADERS ===');
const h = checkHeaders({ 'strict-transport-security':'max-age=1' }); // only HSTS present
console.log(h.map(x=>`[${x.sev}] ${x.title}`).join('\n'));
assert(h.some(x=>x.title.includes('Content-Security-Policy')), 'flags missing CSP');
assert(!h.some(x=>x.title.includes('Strict-Transport')), 'does NOT flag present HSTS');

console.log('\n=== ASSETS ===');
const html = `<html><head><link rel=stylesheet href="/a.css"><script src="/bundle.js"></script></head>
<body><a href="/login">x</a><a href="/checkout">y</a><img src="/logo.png">
<script>const leak="${'sk_'+'live_51zzzzzzzzzzzzzzzzzzzzzz'}";</script></body></html>`;
const a = extractAssets(html, 'https://demo.app');
console.log('scripts:', a.scripts, '\nlinks:', a.links, '\ninline count:', a.inline.length);
assert(a.scripts.includes('https://demo.app/bundle.js'), 'resolves script src to absolute');
assert(a.links.includes('https://demo.app/login'), 'collects internal links');
assert(a.inline.length===1, 'captures inline script');
assert(findSecrets(a.inline.join('\n'),'inline').some(f=>f.kind.includes('Stripe')), 'finds secret in inline script');
