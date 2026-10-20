# AlphaProtector

AlphaProtector is a static web app that can be deployed on Vercel. It includes hosted Supabase email/password authentication, the prototype's sample login monitoring dashboard, and separate email/password security tools. Email breach lookup uses the free, keyless XposedOrNot community API. Password exposure checks use Have I Been Pwned's free Pwned Passwords range API.

## Configure free hosted sign-in

1. Create a free Supabase project and enable Email authentication.
2. In Supabase project settings, copy the **Project URL** and **publishable key** (or legacy `anon` key) into `supabase-config.js` as `url` and `publishableKey`.
3. In Supabase Authentication URL settings, set the Site URL and allowed redirect URLs to include your local preview (`http://127.0.0.1:8501/**`) and deployed Vercel address.
4. Reload the app. Create an account with your name and email. If email confirmation is enabled, verify your address before signing in.

Only the project URL and public publishable/anon key belong in `supabase-config.js`. Never put a Supabase secret or service-role key in browser code. After authentication, the dashboard displays the user's `display_name` metadata, then full name/name, then email as a fallback. The browser auth SDK loads from esm.sh; Vercel's content security policy allows the Supabase project API and that SDK host.

## Run locally

```powershell
python dev_server.py
```

Open <http://127.0.0.1:8501>. The local server only serves the app's HTML, CSS, and JavaScript files; it does not expose the project's JSON or Python files.

## Deploy on Vercel

Import this project directory in Vercel, keep the project root at this directory, and deploy it as a static site. `index.html` is the entry point. Configure the Supabase Auth Site URL and redirect allowlist with your deployed Vercel domain. `vercel.json` sets security headers and permits connections to Supabase and the two lookup APIs.

## Free services and limits

- XposedOrNot free community endpoint: no API key; published rate limit is 25 checks per hour and 100 per day per IP. The email address is sent directly from the browser to XposedOrNot.
- HIBP Pwned Passwords: free range endpoint. Password strength scoring is local. The browser sends only the first five characters of the password's SHA-1 hash to HIBP and compares returned hash suffixes locally.
- Behind the Email and Epieos buttons open their provider websites. AlphaProtector does not call their APIs or require provider API credentials; each provider controls its own free access and limits.

The previous Streamlit prototype remains in `app.py`; Vercel serves the static app from `index.html`.
The Streamlit prototype's local file-based sign-in is for local demonstration only and is not a production authentication service. Its password hashes now use salted PBKDF2; old prototype hashes are upgraded after a successful sign-in. Use Supabase Auth for deployed accounts.

## Login dashboard data

The login counts, charts, alerts, account failure counts, and records reproduce the prototype's sample events. They are not live authentication logs and do not track real users. The dashboard does not collect, store, or display login IP addresses. Real Supabase sign-in activity is available in the Supabase project Auth logs; exposing it in this static browser app would require a secured backend and carefully scoped access.

## Data handling

- The static app does not store email or password checks in an AlphaProtector database. The email breach lookup sends the entered address to XposedOrNot; the optional HIBP password lookup sends only a five-character SHA-1 hash prefix. See the in-app notes before using those tools.
- The email lookup now requires an explicit checkbox before sending the address. Password strength can be checked locally without network access; HIBP exposure lookup requires its own separate consent checkbox.
- Supabase browser sessions are kept in `sessionStorage` and end with the browser tab session instead of being persisted in `localStorage`.
- Supabase processes sign-in credentials and may retain authentication/network metadata in its service logs. Vercel may also process connection metadata. This app cannot prevent those infrastructure providers from recording operational logs.
- `supabase-config.js` may contain only the public project URL and publishable/anon key. Never expose a service-role or secret key in frontend code. Keep Supabase tables private with Row Level Security if tables are added later.
- Local prototype account files (`users.json` and `users_meta.json`) are ignored by Git and are not served by `dev_server.py`; do not upload them or add them to a deployment.
