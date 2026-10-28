// Sign-in for manufuture.strategicdoinginitiatives.com. The Netlify edge function
// (netlify/edge-functions/gate.js) checks the cookie set here on every request.
window.WORKSPACE_AUTH = (() => {
  const SUPABASE_URL = 'https://pwwlpvbttmrvrlzrandz.supabase.co';
  const SUPABASE_KEY = 'sb_publishable_QjkngvDN0APbVVFOBDA9xg_p9bWhBEo'; // the project's public (anon / publishable) key
  const COOKIE = 'manufuture_at';
  const sb = window.supabase.createClient(SUPABASE_URL, SUPABASE_KEY, {
    auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: true, flowType: 'implicit', storageKey: 'manufuture-auth' }
  });
  function setCookie(session) {
    if (!session) { document.cookie = COOKIE + '=; Path=/; Max-Age=0; Secure; SameSite=Lax'; return; }
    const age = Math.max(60, (session.expires_at || 0) - Math.floor(Date.now() / 1000));
    document.cookie = COOKIE + '=' + session.access_token + '; Path=/; Max-Age=' + age + '; Secure; SameSite=Lax';
  }
  sb.auth.onAuthStateChange((_e, session) => setCookie(session));
  async function signOut() { await sb.auth.signOut(); setCookie(null); location.href = '/login.html'; }
  return { sb, setCookie, signOut };
})();
