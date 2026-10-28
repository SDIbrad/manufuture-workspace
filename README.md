# manufuture.strategicdoinginitiatives.com

Private workspace for the ManuFuture work: ManuFuture NEO in Northeast Ohio and Purdue ManuFuture. The front page has a tile for each ManuFuture initiative in Brad's working folder. A tile links to a workspace when one exists.

- `/` — front page, one tile per initiative
- `/neo-sessions/` — ManuFuture NEO workstream sessions and attendance, 1 May to 28 October 2026
- `/login.html` — sign-in (email link, Supabase project shared with strategicdoinginitiatives.com)

## How access works
Every request goes through `netlify/edge-functions/gate.js`. It reads the sign-in cookie, asks Supabase who the person is, and serves the page only if their address is in the Netlify environment variable `ALLOWED_EMAILS`. Anyone else is sent to the sign-in page or refused.

To add or remove a person: edit `ALLOWED_EMAILS` in Netlify (Site configuration › Environment variables) and redeploy. A new person also needs a user in the Supabase project (Authentication › Users › Invite user), because the sign-in page does not create users.

Netlify environment variables:
- `SUPABASE_URL` = https://pwwlpvbttmrvrlzrandz.supabase.co
- `SUPABASE_PUBLIC_KEY` = the project's public (anon or publishable) key
- `ALLOWED_EMAILS` = comma-separated list of addresses

The pages name the people who attended sessions. Keep this repository private.
