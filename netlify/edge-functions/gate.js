// The sign-in check for a site under strategicdoinginitiatives.com (energy., manufuture., synapse. …).
// Netlify runs it on every request to the site, before any page or file is served.
//
// One sign-in covers the main site and every site under it. People sign in on the main site
// (https://strategicdoinginitiatives.com/login). That writes one session cookie, "sdi-auth", for
// the whole domain, so this site receives it too. This check:
//   1. reads that cookie; with none, it sends the person to the main sign-in page and back here;
//   2. checks the sign-in is genuine and current, renewing it when it has run out (the renewed
//      cookie is written back for the whole domain);
//   3. asks Supabase what this person may open here (site_access_for_me), from the one access
//      list that the administrator edits on https://strategicdoinginitiatives.com/admin/access.
//      The answer is kept for a minute, so a page and its files do not each ask again.
//
// The reference copy of this file is docs/shared-sign-in/gate.js in the sdi-portfolio
// repository, with its tests. Each site's copy is the same file; only the settings in the last
// lines differ. Netlify settings each site needs: SUPABASE_URL and SUPABASE_PUBLIC_KEY (the
// project's publishable key). The old ALLOWED_EMAILS and WORKSPACE_EMAILS settings are no longer
// read.

const MAIN = 'https://strategicdoinginitiatives.com';
const COOKIE = 'sdi-auth';                       // must match AUTH_COOKIE_NAME in sdi-portfolio src/lib/signIn.ts
const COOKIE_DOMAIN = '.strategicdoinginitiatives.com';
const CHUNK = 3180;                              // the cookie part size @supabase/ssr uses
const ACCESS_CACHE_MS = 60e3;
const RENEW_EARLY_S = 30;                        // renew a sign-in this close to running out

const enc = new TextEncoder(), dec = new TextDecoder();
const b64uToBytes = (s) => {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  s += '='.repeat((4 - (s.length % 4)) % 4);
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
};
const bytesToB64u = (bytes) => {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// ---- the session cookie (same format as @supabase/ssr on the main site) ----

export function readSession(getCookie) {
  let raw = getCookie(COOKIE);
  if (!raw) {
    const parts = [];
    for (let i = 0; i < 20; i++) { const p = getCookie(COOKIE + '.' + i); if (!p) break; parts.push(p); }
    raw = parts.join('');
  }
  if (!raw) return null;
  try {
    const json = raw.startsWith('base64-') ? dec.decode(b64uToBytes(raw.slice(7))) : raw;
    const s = JSON.parse(json);
    return s && typeof s.access_token === 'string' ? s : null;
  } catch { return null; }
}

// Set-Cookie headers that store `session` for the whole domain, and clear parts left over from a
// longer earlier value.
export function sessionCookies(session, presentNames) {
  const value = 'base64-' + bytesToB64u(enc.encode(JSON.stringify(session)));
  const attrs = `; Domain=${COOKIE_DOMAIN}; Path=/; Max-Age=${400 * 24 * 3600}; SameSite=Lax; Secure`;
  const clear = (name) => `${name}=; Domain=${COOKIE_DOMAIN}; Path=/; Max-Age=0; SameSite=Lax; Secure`;
  const out = [], written = new Set();
  if (value.length <= CHUNK) {
    out.push(`${COOKIE}=${value}${attrs}`); written.add(COOKIE);
  } else {
    for (let i = 0, n = 0; i < value.length; i += CHUNK, n++) {
      out.push(`${COOKIE}.${n}=${value.slice(i, i + CHUNK)}${attrs}`); written.add(`${COOKIE}.${n}`);
    }
  }
  for (const name of presentNames) {
    if ((name === COOKIE || name.startsWith(COOKIE + '.')) && !written.has(name)) out.push(clear(name));
  }
  return out;
}

// ---- checking the sign-in ----

let jwks = null, jwksAt = 0;
const keys = new Map(); // kid -> CryptoKey

async function keyFor(base, kid) {
  if (keys.has(kid)) return keys.get(kid);
  if (!jwks || Date.now() - jwksAt > 3600e3 || !jwks.keys?.some((k) => k.kid === kid)) {
    const r = await fetch(base + '/auth/v1/.well-known/jwks.json');
    if (!r.ok) return null;
    jwks = await r.json(); jwksAt = Date.now();
  }
  const jwk = (jwks.keys || []).find((k) => k.kid === kid);
  if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256') return null;
  const key = await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, ext: true },
    { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  keys.set(kid, key);
  return key;
}

// { email } for a good token; { expired: true } for a genuine one that has run out (or is about
// to); { bad: true } for anything else; null when this token cannot be checked here, and Supabase
// must be asked instead.
export async function checkToken(token, base) {
  const parts = String(token).split('.');
  if (parts.length !== 3) return { bad: true };
  let head, claims, sig;
  try {
    head = JSON.parse(dec.decode(b64uToBytes(parts[0])));
    claims = JSON.parse(dec.decode(b64uToBytes(parts[1])));
    sig = b64uToBytes(parts[2]);
  } catch { return { bad: true }; }
  if (head.alg !== 'ES256' || !head.kid) return null;
  const key = await keyFor(base, head.kid);
  if (!key) return null;
  const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, sig, enc.encode(parts[0] + '.' + parts[1]));
  if (!ok) return { bad: true };
  if (claims.iss && claims.iss !== base + '/auth/v1') return { bad: true };
  if (claims.role && claims.role !== 'authenticated') return { bad: true };
  if (!claims.exp || claims.exp - RENEW_EARLY_S <= Date.now() / 1000) return { expired: true };
  return { email: String(claims.email || '').toLowerCase() };
}

async function askSupabase(token, base, publicKey) {
  const r = await fetch(base + '/auth/v1/user', { headers: { apikey: publicKey, Authorization: 'Bearer ' + token } });
  if (r.status === 401 || r.status === 403) return { expired: true };
  if (!r.ok) throw new Error('auth ' + r.status);
  const u = await r.json();
  return { email: String(u.email || '').toLowerCase() };
}

// Renewals in progress, by refresh token, so the page and its files renewing at the same moment
// share one call.
const renewing = new Map();
async function renew(session, base, publicKey) {
  const rt = session.refresh_token;
  if (!rt) return null;
  if (!renewing.has(rt)) {
    renewing.set(rt, (async () => {
      const r = await fetch(base + '/auth/v1/token?grant_type=refresh_token', {
        method: 'POST', headers: { apikey: publicKey, 'content-type': 'application/json' },
        body: JSON.stringify({ refresh_token: rt }),
      });
      if (!r.ok) return null;
      const s = await r.json();
      return s && s.access_token ? s : null;
    })().finally(() => setTimeout(() => renewing.delete(rt), 10e3)));
  }
  return renewing.get(rt);
}

// ---- what this person may open here ----

const accessCache = new Map(); // email|site -> { at, areas }
async function accessFor(site, email, token, base, publicKey) {
  const k = email + '|' + site, hit = accessCache.get(k);
  if (hit && Date.now() - hit.at < ACCESS_CACHE_MS) return hit.areas;
  const r = await fetch(base + '/rest/v1/rpc/site_access_for_me', {
    method: 'POST',
    headers: { apikey: publicKey, Authorization: 'Bearer ' + token, 'content-type': 'application/json' },
    body: JSON.stringify({ p_site: site }),
  });
  if (!r.ok) throw new Error('access ' + r.status);
  const areas = await r.json();
  const list = Array.isArray(areas) ? areas.map(String) : [];
  accessCache.set(k, { at: Date.now(), areas: list });
  return list;
}

// ---- responses ----

function redirect(location, cookies = []) {
  const h = new Headers({ Location: location, 'Cache-Control': 'no-store' });
  for (const c of cookies) h.append('Set-Cookie', c);
  return new Response(null, { status: 302, headers: h });
}

function page(status, title, body, cookies = []) {
  const h = new Headers({ 'content-type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
  for (const c of cookies) h.append('Set-Cookie', c);
  return new Response(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex, nofollow"><title>${esc(title)}</title>
<style>body{margin:0;font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;background:#f4f6f7;color:#1d2a30}main{max-width:520px;margin:64px auto;padding:0 16px}.card{background:#fff;border:1px solid #d9e0e3;border-radius:12px;padding:28px}h1{font-size:22px;margin:0 0 12px;color:#0b4f5c}p{margin:0 0 14px}a,button.link{color:#0b4f5c}button.link{background:none;border:0;padding:0;font:inherit;text-decoration:underline;cursor:pointer}</style></head>
<body><main><div class="card">${body}</div></main></body></html>`, { status, headers: h });
}

const signOutForm = (label) =>
  `<form action="${MAIN}/auth/signout" method="post" style="display:inline"><button class="link" type="submit">${esc(label)}</button></form>`;

// ---- the check itself ----

/**
 * Build the check for one site.
 *   site      the site's key in public.sites ('energy', 'manufuture', 'synapse' …)
 *   name      how the refusal page names it ('the energy workspace')
 *   areaPath  for a site whose parts can be granted on their own: a pattern whose first group is
 *             the part's key (Synapse Proto: /^\/w\/([a-z0-9_-]+)(\/|$)/i). A person given only
 *             some parts may open those, and is sent from the front page to their first one.
 */
export function makeGate({ site, name, areaPath = null }) {
  return async (request, context) => {
    const url = new URL(request.url);
    const env = (k) => (globalThis.Netlify ? Netlify.env.get(k) : undefined);
    const base = String(env('SUPABASE_URL') || '').replace(/\/+$/, ''), publicKey = env('SUPABASE_PUBLIC_KEY');
    const toSignIn = () => redirect(MAIN + '/login?next=' + encodeURIComponent(url.href));

    const cookieHeader = request.headers.get('cookie') || '';
    const present = cookieHeader.split(';').map((c) => c.split('=')[0].trim()).filter(Boolean);
    const getCookie = (n) => context.cookies.get(n);

    let session = readSession(getCookie);
    if (!session) return toSignIn();

    let setCookies = [];
    let who;
    try {
      who = (await checkToken(session.access_token, base)) || (await askSupabase(session.access_token, base, publicKey));
      if (who.expired) {
        const fresh = await renew(session, base, publicKey);
        if (!fresh) return toSignIn();
        session = fresh;
        setCookies = sessionCookies(fresh, present);
        who = (await checkToken(session.access_token, base)) || (await askSupabase(session.access_token, base, publicKey));
      }
    } catch {
      return page(503, 'Try again shortly', '<h1>Sign-in is not available right now</h1><p>Try again in a minute.</p>');
    }
    if (!who || who.bad || who.expired) return toSignIn();
    if (!who.email) {
      return page(403, 'No access', `<h1>No access to ${esc(name)}</h1><p>This sign-in has no email address. Sign in with your email address or your @strategicdoing.net Google account.</p><p>${signOutForm('Sign out')}</p>`, setCookies);
    }

    let areas;
    try { areas = await accessFor(site, who.email, session.access_token, base, publicKey); }
    catch { return page(503, 'Try again shortly', '<h1>Access cannot be checked right now</h1><p>Try again in a minute.</p>', setCookies); }

    const whole = areas.includes('*');
    // A person given only some workspaces: refuse any address with an encoded slash, backslash
    // or dot, so "/w/rik/..%2Fcore/" cannot pass the check for "rik" and then be read as another
    // workspace's page.
    if (!whole && areaPath && /%2f|%5c|%2e/i.test(url.pathname)) {
      return page(400, 'Not found', '<h1>That address is not valid</h1>', setCookies);
    }
    if (!whole) {
      const m = areaPath ? url.pathname.match(areaPath) : null;
      if (m && areas.includes(m[1].toLowerCase())) {
        if (!m[2]) return redirect(new URL('/w/' + m[1] + '/', url).href, setCookies);
      } else if (areaPath && areas.length && (url.pathname === '/' || url.pathname === '/index.html')) {
        return redirect(new URL('/w/' + areas[0] + '/', url).href, setCookies);
      } else {
        return page(403, 'No access',
          `<h1>No access to ${esc(name)}</h1>
<p>You are signed in as <strong>${esc(who.email)}</strong>. That account does not have access to ${areas.length ? 'this page of ' : ''}${esc(name)}.</p>
<p>Ask Brad Beach for access.</p>
<p><a href="${MAIN}/sites">See the sites you can open</a> · ${signOutForm('Sign in as someone else')}</p>`, setCookies);
      }
    }

    const res = await context.next();
    const out = new Response(res.body, res);
    // Pages are never cached; other files may be kept in this browser for an hour.
    const isPage = /\.html?$/.test(url.pathname) || url.pathname.endsWith('/');
    out.headers.set('Cache-Control', isPage ? 'private, no-store' : 'private, max-age=3600');
    for (const c of setCookies) out.headers.append('Set-Cookie', c);
    return out;
  };
}

// ---- this site ----
export default makeGate({ site: 'manufuture', name: 'the ManuFuture workspace' });
// The sign-in and account pages only send people to the main site, so they need no check.
export const config = { path: '/*', excludedPath: ['/login.html', '/account.html', '/auth.js', '/robots.txt', '/vendor/*', '/brand/*'] };
