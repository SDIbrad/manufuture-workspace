# manufuture.strategicdoinginitiatives.com

Private workspace for the ManuFuture work: ManuFuture NEO in Northeast Ohio and Purdue ManuFuture. The front page has a tile for each ManuFuture initiative in Brad's working folder. A tile links to a workspace when one exists.

- `/` — front page, one tile per initiative
- `/neo-sessions/` — ManuFuture NEO workstream sessions and attendance, 1 May to 28 October 2026
- `/login.html` — sends people to the shared sign-in page on strategicdoinginitiatives.com

## How access works
One sign-in covers strategicdoinginitiatives.com and every site under it. People sign in on the main site (https://strategicdoinginitiatives.com/login): Strategic Doing Institute staff with Google, everyone else with email and password or an emailed sign-in link. That sets one session cookie for the whole domain.

Every request here goes through `netlify/edge-functions/gate.js`. It reads that cookie, renews it when it has run out, and asks Supabase whether the person may open this site. The answer comes from the one access list that Brad, as administrator, edits at https://strategicdoinginitiatives.com/admin/access. To add or remove a person, use that page; nothing here needs changing and nothing needs redeploying.

`login.html` and `account.html` only send people to the main site's sign-in and set-password pages. `auth.js` gives the pages a "Sign out" that signs out of every site at once.

Netlify environment variables:
- `SUPABASE_URL` = https://pwwlpvbttmrvrlzrandz.supabase.co
- `SUPABASE_PUBLIC_KEY` = the project's public (anon or publishable) key

The `ALLOWED_EMAILS` setting is no longer read and can be deleted in Netlify. The reference copy of `gate.js`, with its tests and the full steps, is `docs/shared-sign-in/` and `docs/SHARED-SIGN-IN.md` in the sdi-portfolio repository.

The pages name the people who attended sessions. Keep this repository private.
