# InfinityInfo client portal

The portal runs alongside the existing static site. The server serves the original `index.html` and its assets unchanged at `/`, the sign-in page at `/client`, account creation at `/client/signup`, and a protected account page at `/client/dashboard`.

## Run locally

From this directory, run:

```powershell
python portal_server.py
```

Open `http://127.0.0.1:8000/client`. The site landing page remains at `http://127.0.0.1:8000/`. Account records and sessions are created in `../../data/client-portal.sqlite3` by default. Set `CLIENT_PORTAL_DB` to choose a different persistent database file, and `HOST` / `PORT` to change the bind address and port.

## Deploy

Run `portal_server.py` as a persistent Python 3.10+ service behind a TLS-terminating reverse proxy. Configure the proxy to overwrite `X-Forwarded-Proto` with the original request scheme, route the domain to this service, and preserve the `Host` header. Keep the SQLite file on persistent storage and back it up. Set `CLIENT_PORTAL_DB` to that persistent path. For a single-machine deployment, bind the app to `127.0.0.1` and let the reverse proxy handle public traffic and HTTPS.

The service uses only the Python standard library. Passwords are stored as salted PBKDF2-HMAC-SHA256 hashes. Session identifiers are random, only their hashes are stored in SQLite, and browser cookies are HttpOnly and SameSite=Lax; the Secure flag is enabled on HTTPS requests. Login and signup requests require a matching same-origin `Origin` header, and authentication attempts are rate-limited.

Account creation is open to visitors. Password reset is not automated because this project has no email delivery service configured; the “Forgot password?” link contacts InfinityInfo support.
