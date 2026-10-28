// Every request to the workspace passes through here. A request is served only when it
// carries a valid Supabase sign-in for an address on ALLOWED_EMAILS (set in Netlify).
export default async (request, context) => {
  const url = new URL(request.url);
  const toLogin = () => Response.redirect(new URL('/login.html?next=' + encodeURIComponent(url.pathname + url.search), url), 302);
  const token = context.cookies.get('manufuture_at');
  if (!token) return toLogin();
  const base = Netlify.env.get('SUPABASE_URL'), key = Netlify.env.get('SUPABASE_PUBLIC_KEY');
  const allowed = (Netlify.env.get('ALLOWED_EMAILS') || '').toLowerCase().split(',').map(s => s.trim()).filter(Boolean);
  let user;
  try {
    const r = await fetch(base + '/auth/v1/user', { headers: { apikey: key, Authorization: 'Bearer ' + token } });
    if (!r.ok) return toLogin();
    user = await r.json();
  } catch { return new Response('Sign-in service unavailable. Try again shortly.', { status: 503 }); }
  if (!allowed.includes(String(user.email || '').toLowerCase())) {
    return new Response('This address does not have access to the ManuFuture workspace. Ask Brad Beach for access.', { status: 403, headers: { 'content-type': 'text/plain; charset=utf-8' } });
  }
  const res = await context.next();
  const out = new Response(res.body, res);
  out.headers.set('Cache-Control', 'private, no-store');
  return out;
};
export const config = { path: '/*', excludedPath: ['/login.html', '/auth.js', '/robots.txt', '/vendor/*', '/brand/*'] };
