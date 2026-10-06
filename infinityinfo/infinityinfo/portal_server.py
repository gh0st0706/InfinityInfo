"""InfinityInfo client sign-in service. Run with: python portal_server.py"""
from __future__ import annotations

import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
import sqlite3
import time
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import unquote, urlparse

APP_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("CLIENT_PORTAL_DB", APP_DIR.parents[1] / "data" / "client-portal.sqlite3"))
PBKDF2_ROUNDS = 600_000
SESSION_SHORT = 8 * 60 * 60
SESSION_REMEMBER = 30 * 24 * 60 * 60
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


@contextmanager
def database():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    try:
        with db:
            yield db
    finally:
        db.close()


def init_database():
    with database() as db:
        db.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS clients (
          id INTEGER PRIMARY KEY,
          name TEXT NOT NULL,
          company_name TEXT NOT NULL,
          email TEXT NOT NULL UNIQUE COLLATE NOCASE,
          password_hash TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'active',
          created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );
        CREATE TABLE IF NOT EXISTS client_sessions (
          token_hash TEXT PRIMARY KEY,
          client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
          expires_at INTEGER NOT NULL,
          created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS client_sessions_expiry ON client_sessions(expires_at);
        CREATE TABLE IF NOT EXISTS auth_attempts (
          subject_hash TEXT NOT NULL,
          attempted_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS auth_attempts_lookup ON auth_attempts(subject_hash, attempted_at);
        """)


def password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${PBKDF2_ROUNDS}${salt.hex()}${derived.hex()}"


def check_password(password: str, encoded: str) -> bool:
    try:
        algorithm, rounds, salt_hex, expected = encoded.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(rounds)).hex()
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


class PortalHandler(BaseHTTPRequestHandler):
    server_version = "InfinityInfoClient/1.0"

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} - {fmt % args}")

    def headers_common(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Cache-Control", "no-store")

    def reply(self, status: int, body: bytes | str, content_type="text/html; charset=utf-8", headers=None):
        payload = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.headers_common()
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)

    def redirect(self, location: str, cookie: str | None = None):
        self.send_response(303)
        self.send_header("Location", location)
        self.headers_common()
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def json_reply(self, status: int, payload: dict, headers=None):
        return self.reply(status, json.dumps(payload), "application/json; charset=utf-8", headers)

    def request_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 8192:
                return None
            value = json.loads(self.rfile.read(length))
            return value if isinstance(value, dict) else None
        except (ValueError, UnicodeDecodeError):
            return None

    def same_origin(self):
        origin = self.headers.get("Origin")
        if not origin:
            return False
        parsed = urlparse(origin)
        forwarded_proto = self.headers.get("X-Forwarded-Proto", "").split(",", 1)[0].strip()
        scheme = forwarded_proto or ("https" if self.connection_is_tls() else "http")
        return parsed.netloc.lower() == self.headers.get("Host", "").lower() and parsed.scheme == scheme

    def connection_is_tls(self):
        return isinstance(self.connection, __import__("ssl").SSLSocket)

    def session(self, db):
        jar = cookies.SimpleCookie(self.headers.get("Cookie", ""))
        morsel = jar.get("ii_client_session")
        if not morsel:
            return None
        token_digest = hashlib.sha256(morsel.value.encode()).hexdigest()
        row = db.execute("""SELECT c.id,c.name,c.company_name,c.email,c.created_at
                            FROM client_sessions s JOIN clients c ON c.id=s.client_id
                            WHERE s.token_hash=? AND s.expires_at>? AND c.status='active'""",
                         (token_digest, int(time.time()))).fetchone()
        return dict(row) if row else None

    def safe_cookie(self, token: str, max_age: int) -> str:
        secure = self.headers.get("X-Forwarded-Proto", "").split(",", 1)[0].strip() == "https" or self.connection_is_tls()
        value = f"ii_client_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}"
        return value + ("; Secure" if secure else "")

    @staticmethod
    def clean_text(value, limit):
        return " ".join(value.strip().split())[:limit] if isinstance(value, str) else ""

    def rate_limited(self, db, email):
        ip = self.client_address[0]
        key = hashlib.sha256((ip + "|" + email.casefold()).encode()).hexdigest()
        now = int(time.time())
        db.execute("DELETE FROM auth_attempts WHERE attempted_at<?", (now - 3600,))
        count = db.execute("SELECT COUNT(*) FROM auth_attempts WHERE subject_hash=? AND attempted_at>?", (key, now - 900)).fetchone()[0]
        db.execute("INSERT INTO auth_attempts(subject_hash,attempted_at) VALUES(?,?)", (key, now))
        return count >= 12

    def create_session(self, db, client_id, remember):
        token = secrets.token_urlsafe(32)
        lifetime = SESSION_REMEMBER if remember else SESSION_SHORT
        now = int(time.time())
        db.execute("DELETE FROM client_sessions WHERE expires_at<=?", (now,))
        db.execute("INSERT INTO client_sessions(token_hash,client_id,expires_at,created_at) VALUES(?,?,?,?)",
                   (hashlib.sha256(token.encode()).hexdigest(), client_id, now + lifetime, now))
        return self.safe_cookie(token, lifetime)

    def do_GET(self):
        path = unquote(urlparse(self.path).path)
        if path in ("/client", "/client/", "/client/signup"):
            with database() as db:
                user = self.session(db)
                if user:
                    return self.redirect("/client/dashboard")
            page = (APP_DIR / "client.html").read_bytes()
            return self.reply(200, page)
        if path == "/client/dashboard":
            with database() as db:
                user = self.session(db)
            if not user:
                return self.redirect("/client")
            return self.dashboard(user)
        if path in ("/", "/index.html"):
            path = "/index.html"
        if path.startswith(("/assets/", "/vendor/")) or path == "/index.html":
            relative = (APP_DIR / path.lstrip("/")).resolve()
            if APP_DIR.resolve() not in relative.parents or not relative.is_file():
                return self.reply(404, "Not found")
            mime = mimetypes.guess_type(relative.name)[0] or "application/octet-stream"
            if mime.startswith("text/") or mime == "application/javascript":
                mime += "; charset=utf-8"
            cache = "no-cache" if path == "/index.html" else "public, max-age=86400"
            return self.reply(200, relative.read_bytes(), mime, {"Cache-Control": cache})
        if path == "/favicon.ico":
            return self.reply(204, b"", "image/x-icon")
        return self.reply(404, "Not found")

    def do_POST(self):
        path = urlparse(self.path).path
        if not self.same_origin():
            return self.json_reply(403, {"error": "This request could not be verified. Refresh the page and try again."})
        if path in ("/api/client/login", "/api/client/signup"):
            return self.authenticate(path.endswith("signup"))
        if path == "/api/client/logout":
            jar = cookies.SimpleCookie(self.headers.get("Cookie", ""))
            morsel = jar.get("ii_client_session")
            if morsel:
                with database() as db:
                    db.execute("DELETE FROM client_sessions WHERE token_hash=?", (hashlib.sha256(morsel.value.encode()).hexdigest(),))
            return self.json_reply(200, {"ok": True}, {"Set-Cookie": self.safe_cookie("", 0)})
        return self.json_reply(404, {"error": "Not found"})

    def authenticate(self, signup):
        data = self.request_json()
        if data is None:
            return self.json_reply(400, {"error": "Please check the form and try again."})
        email = self.clean_text(data.get("email"), 254).lower()
        password = data.get("password") if isinstance(data.get("password"), str) else ""
        if not EMAIL_RE.fullmatch(email):
            return self.json_reply(400, {"error": "Enter a valid email address."})
        if len(password) > 256 or (len(password) < 10 if signup else not password):
            return self.json_reply(400, {"error": "Use a password with at least 10 characters." if signup else "Enter your password."})
        with database() as db:
            if self.rate_limited(db, email):
                return self.json_reply(429, {"error": "Too many attempts. Wait a few minutes and try again."})
            if signup:
                name = self.clean_text(data.get("name"), 120)
                company = self.clean_text(data.get("company"), 160)
                if len(name) < 2 or len(company) < 2:
                    return self.json_reply(400, {"error": "Enter your name and company to create an account."})
                try:
                    cursor = db.execute("INSERT INTO clients(name,company_name,email,password_hash) VALUES(?,?,?,?)",
                                        (name, company, email, password_hash(password)))
                except sqlite3.IntegrityError:
                    return self.json_reply(409, {"error": "An account with this email already exists. Sign in instead."})
                client_id = cursor.lastrowid
                remember = True
            else:
                user = db.execute("SELECT id,password_hash,status FROM clients WHERE email=?", (email,)).fetchone()
                valid = user and user["status"] == "active" and check_password(password, user["password_hash"])
                if not valid:
                    return self.json_reply(401, {"error": "That email and password combination wasn’t recognized."})
                client_id = user["id"]
                remember = data.get("remember") is True
            cookie = self.create_session(db, client_id, remember)
        return self.json_reply(200, {"ok": True}, {"Set-Cookie": cookie})

    def dashboard(self, user):
        name = user["name"]
        company = user["company_name"]
        html = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#202b33"><title>Client workspace | InfinityInfo</title><link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet"><style>*{{box-sizing:border-box}}body{{background:#f6f8f9;color:#2a2a2a;font-family:Poppins,Arial,sans-serif;margin:0;min-height:100vh}}header{{align-items:center;background:#202b33;color:#fff;display:flex;justify-content:space-between;padding:17px clamp(22px,6vw,90px)}}header img{{display:block;height:auto;width:180px}}button{{background:#4da6e7;border:0;border-radius:4px;color:white;cursor:pointer;font:500 12px Poppins,Arial;padding:10px 16px}}main{{margin:10vh auto;max-width:790px;padding:25px}}.eyebrow{{color:#4da6e7;font-size:10px;letter-spacing:1.4px}}h1{{font-size:clamp(28px,5vw,42px);font-weight:500;letter-spacing:-1.4px;margin:12px 0}}p{{color:#777;font-size:13px;line-height:1.8}}.workspace{{background:#fff;border:1px solid #e6e9eb;border-radius:5px;margin-top:30px;padding:24px}}.workspace h2{{font-size:15px;font-weight:500;margin:0 0 9px}}.detail{{border-top:1px solid #eee;margin-top:18px;padding-top:15px}}.detail span{{color:#888;display:block;font-size:10px;margin-bottom:5px}}.detail b{{font-size:12px;font-weight:500}}@media(max-width:480px){{header img{{width:145px}}main{{margin:5vh auto;padding:19px}}}}</style></head><body><header><a href="/client/dashboard"><img src="/assets/images/logo-v3-dark.png" alt="InfinityInfo"></a><button id="logout">Sign out</button></header><main><div class="eyebrow">CLIENT WORKSPACE</div><h1>Welcome, {self.escape(name)}.</h1><p>Your InfinityInfo client access is active. This secure workspace is linked to your account.</p><section class="workspace"><h2>Account</h2><p>You're signed in to the client portal. Contact your InfinityInfo account manager if you need help with your lead delivery.</p><div class="detail"><span>COMPANY</span><b>{self.escape(company)}</b></div><div class="detail"><span>ACCOUNT EMAIL</span><b>{self.escape(user['email'])}</b></div></section></main><script>document.getElementById('logout').addEventListener('click',async()=>{{const button=document.getElementById('logout');button.disabled=true;try{{await fetch('/api/client/logout',{{method:'POST',credentials:'same-origin'}})}}finally{{location.replace('/client')}}}})</script></body></html>'''
        return self.reply(200, html)

    @staticmethod
    def escape(value):
        return (str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace('"', "&quot;").replace("'", "&#x27;"))


def main():
    init_database()
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    print(f"InfinityInfo client portal listening on http://{host}:{port}/client")
    try:
        ThreadingHTTPServer((host, port), PortalHandler).serve_forever()
    except KeyboardInterrupt:
        print("\nPortal server stopped.")


if __name__ == "__main__":
    main()
