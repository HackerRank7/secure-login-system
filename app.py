"""
Secure Login System (Flask + SQLite + bcrypt + optional TOTP 2FA)
Run:  pip install -r requirements.txt  ->  python app.py  ->  open http://127.0.0.1:5000
"""
import base64, io, os, re, secrets, sqlite3          # Standard-library helpers (encoding, files, regex, random tokens, database)
from datetime import datetime, timedelta              # Used for session lifetime and account lockout timing
from functools import wraps                           # Lets us build the @login_required decorator

import bcrypt                                         # Password hashing (slow + salted, so brute-forcing is hard)
import pyotp                                          # Generates/verifies 2FA codes (Google Authenticator compatible)
import qrcode                                         # Creates the QR code for the 2FA setup page
from flask import (Flask, abort, flash, g, redirect,  # Flask web framework pieces we need
                   render_template_string, request, session, url_for)
from markupsafe import Markup                         # Marks our own HTML as safe to insert into the layout

SESSION_MINUTES = int(os.environ.get("SESSION_MINUTES", "30"))   # Session length in minutes (default 30; set SESSION_MINUTES=1 to test quickly)
app = Flask(__name__)                                 # Create the web application
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", secrets.token_hex(32)),  # Key that signs session cookies (set SECRET_KEY in production!)
    SESSION_COOKIE_HTTPONLY=True,                     # JavaScript cannot read the session cookie (blocks XSS cookie theft)
    SESSION_COOKIE_SAMESITE="Lax",                    # Browser won't send the cookie on cross-site POSTs (CSRF defence)
    SESSION_COOKIE_SECURE=os.environ.get("HTTPS") == "1",  # Send cookie only over HTTPS when you set HTTPS=1 in production
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=SESSION_MINUTES),  # Sessions automatically expire after SESSION_MINUTES
    SESSION_REFRESH_EACH_REQUEST=False,               # Do NOT extend the session on every click (fixed 30 minutes from login)
)

DB_PATH = "users.db"                                  # SQLite database file name
MAX_FAILED = 5                                        # Wrong passwords allowed before the account is locked
LOCK_MINUTES = 10                                     # How long the lock lasts
DUMMY_HASH = bcrypt.hashpw(b"dummy", bcrypt.gensalt())  # Fake hash so unknown usernames take the same time as real ones


# ---------------------------------------------------------------- Database helpers
def get_db():
    if "db" not in g:                                 # Open one connection per request
        g.db = sqlite3.connect(DB_PATH)               # Connect to the database file
        g.db.row_factory = sqlite3.Row                # Lets us read columns by name (user["username"])
    return g.db

@app.teardown_appcontext
def close_db(_):
    db = g.pop("db", None)                            # Grab the connection if it exists
    if db:
        db.close()                                    # Always close it when the request ends

def init_db():
    with sqlite3.connect(DB_PATH) as db:              # Create the users table the first time the app runs
        db.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,            -- Unique login name (case-sensitive: "Gaurav_1" and "gaurav_1" are different users)
            password_hash BLOB NOT NULL,              -- bcrypt hash (the real password is NEVER stored)
            recovery_hash BLOB,                       -- bcrypt hash of the one-time recovery key (also never stored in plain text)
            totp_secret TEXT,                         -- Secret used for 2FA codes
            totp_enabled INTEGER DEFAULT 0,           -- 1 once the user has confirmed 2FA setup
            failed_attempts INTEGER DEFAULT 0,        -- Counter of wrong passwords in a row
            locked_until TEXT                         -- Time until which the account is locked
        )""")


# ---------------------------------------------------------------- Security helpers
def csrf_token():
    if "csrf" not in session:                         # Make one random token per session
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]

@app.before_request
def check_csrf():
    if request.method == "POST":                      # Every form submission must carry the secret token
        sent = request.form.get("csrf_token", "")     # Token sent by the form
        expected = session.get("csrf")                # Token stored in the user's session
        if not expected or not secrets.compare_digest(sent, expected):  # Missing token = blocked; otherwise constant-time comparison
            abort(400, "Invalid form token. Please go back and try again.")

@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"        # Stops browsers guessing file types
    resp.headers["X-Frame-Options"] = "DENY"                  # Prevents clickjacking (no embedding in iframes)
    resp.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'"  # Only load our own content
    resp.headers["Cache-Control"] = "no-store"                # Don't cache private pages
    return resp

def login_required(view):
    @wraps(view)
    def wrapper(*a, **kw):
        if "user_id" not in session:                  # Not logged in?
            flash("Please log in first.", "error")
            return redirect(url_for("login"))         # Send them to the login page
        limit = app.config["PERMANENT_SESSION_LIFETIME"].total_seconds()       # Allowed session length (30 minutes)
        if datetime.now().timestamp() - session.get("login_time", 0) > limit:  # Has 30 minutes passed since login?
            session.clear()                           # Yes: destroy the session (automatic logout)
            flash(f"Your session expired after {SESSION_MINUTES} minutes. Please log in again.", "error")
            return redirect(url_for("login"))
        return view(*a, **kw)
    return wrapper

def validate_credentials(username, password):
    """Returns an error message, or None if the input is valid."""
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{3,19}", username):   # Starts with a letter; then letters, numbers, underscore (4-20 chars total)
        return "Invalid username. Use 4-20 characters, start with a letter, and use only letters, numbers or underscore (for example: test_21)."
    if not re.search(r"[0-9_]", username):            # A plain name like "test" is not allowed: it needs a number or underscore
        return "Username must include at least one number or underscore (for example: test_21)."
    if not 8 <= len(password) <= 64:                  # 64 max keeps us under bcrypt's 72-byte limit
        return "Password must be between 8 and 64 characters."
    if not re.search(r"[a-z]", password):             # At least one lowercase letter
        return "Password must include at least one lowercase letter (a-z)."
    if not re.search(r"[A-Z]", password):             # At least one uppercase letter
        return "Password must include at least one uppercase letter (A-Z)."
    if not re.search(r"[^A-Za-z0-9\s]", password):    # At least one special character such as ! @ # $ % & *
        return "Password must include at least one special character (for example: ! @ # $ % & *)."
    if username.lower() in password.lower():          # Password must not contain the username (too easy to guess)
        return "Password must not contain your username."
    return None


# ---------------------------------------------------------------- Page rendering (HTML kept in this file for simplicity)
BASE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{{ title }} - Secure Login</title>
<style>
body{font-family:system-ui,sans-serif;background:#f1f5f9;display:flex;justify-content:center;padding:40px 16px;margin:0}
.card{background:#fff;max-width:380px;width:100%;padding:28px;border-radius:12px;box-shadow:0 2px 12px #0002}
input,button{width:100%;padding:10px;margin:6px 0 14px;border-radius:8px;border:1px solid #cbd5e1;font-size:16px;box-sizing:border-box}
button{background:#2563eb;color:#fff;border:0;cursor:pointer}.link{background:#64748b}
.msg{padding:10px;border-radius:8px;margin-bottom:12px}.error{background:#fee2e2}.success{background:#dcfce7}
img{display:block;margin:auto;max-width:100%}
@media print{body{background:#fff;padding:0}.card{box-shadow:none;max-width:100%}.noprint{display:none!important}}  /* When printing: plain white page, hide buttons */
</style></head><body><div class="card"><h2>{{ title }}</h2>
{% for cat, m in messages %}<div class="msg {{ cat }}">{{ m }}</div>{% endfor %}
{{ body }}</div></body></html>"""

def page(title, body, **ctx):
    inner = render_template_string(body, csrf=csrf_token(), **ctx)   # Render the page body (auto-escapes user data = XSS safe)
    msgs = session.pop("_flashes", [])                # Collect flash messages to show once
    return render_template_string(BASE, title=title, body=Markup(inner), messages=msgs)


# ---------------------------------------------------------------- Routes
@app.route("/")
def home():
    return redirect(url_for("dashboard" if "user_id" in session else "login"))  # Send visitors to the right page

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()       # Read and trim the username
        password = request.form.get("password", "")               # Read the password
        error = validate_credentials(username, password)          # Check the input rules
        if error:
            flash(error, "error")
        elif password != request.form.get("confirm", ""):         # Both passwords must match
            flash("Passwords do not match.", "error")
        else:
            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))  # Hash with a random salt
            key, key_hash = new_recovery_key()                    # Make a recovery key (plain text + its hash)
            try:
                get_db().execute("INSERT INTO users (username, password_hash, recovery_hash) VALUES (?, ?, ?)",
                                 (username, hashed, key_hash))    # '?' placeholders = SQL injection protection
                get_db().commit()                                 # Save the new user
                return page("Account created", RECOVERY_PAGE, username=username, key=key, reset=False)  # Show key ONCE
            except sqlite3.IntegrityError:                        # Username already exists
                flash("That username is already taken. Please choose a different one.", "error")
    return page("Create account", """
<form method="post"><input type="hidden" name="csrf_token" value="{{ csrf }}">
<label>Username</label><input name="username" required maxlength="20" autocomplete="username">
<label>Password</label><input name="password" type="password" required autocomplete="new-password">
<label>Confirm password</label><input name="confirm" type="password" required autocomplete="new-password">
<button>Register</button></form><a href="{{ url_for('login') }}">Already have an account? Log in</a>""")

LOGIN_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Log in - Secure Login</title>
<style>
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;font-family:system-ui,sans-serif;
  background:radial-gradient(circle at 15% 20%,#c7d2fe 0,transparent 40%),radial-gradient(circle at 85% 80%,#fbcfe8 0,transparent 40%),#eef2ff}  /* Soft colourful background */
.box{display:flex;width:100%;max-width:880px;background:#fff;border-radius:20px;overflow:hidden;box-shadow:0 20px 50px #1e1b4b33}  /* Card with two halves */
.side{flex:1;padding:44px 36px;color:#fff;background:linear-gradient(145deg,#4f46e5,#7c3aed 55%,#db2777)}  /* Left colourful panel */
.side h1{margin:18px 0 10px;font-size:30px}.side p{opacity:.92;line-height:1.6}
.side li{margin:12px 0;list-style:none}.side ul{padding:0;margin-top:26px}
.logo{font-size:44px}
.form{flex:1;padding:44px 36px}
.form h2{margin:0 0 4px;font-size:26px;color:#1e1b4b}.sub{margin:0 0 22px;color:#64748b}
label{font-size:14px;font-weight:600;color:#334155}
.field{position:relative;margin:6px 0 16px}
.field span.ic{position:absolute;left:12px;top:50%;transform:translateY(-50%)}
.field input{width:100%;padding:12px 70px 12px 40px;border:1.5px solid #cbd5e1;border-radius:10px;font-size:16px;outline:none;transition:.2s}
.field input:focus{border-color:#6366f1;box-shadow:0 0 0 4px #6366f133}  /* Glow when typing */
#toggle-pw{position:absolute;right:8px;top:50%;transform:translateY(-50%);border:0;background:none;color:#6366f1;font-weight:600;cursor:pointer}
.go{width:100%;padding:13px;border:0;border-radius:10px;font-size:16px;font-weight:600;color:#fff;cursor:pointer;
  background:linear-gradient(90deg,#4f46e5,#7c3aed);transition:transform .15s,box-shadow .15s}
.go:hover{transform:translateY(-2px);box-shadow:0 8px 20px #4f46e555}
.row{display:flex;justify-content:space-between;margin-top:18px;font-size:14px}
.row a{color:#4f46e5;text-decoration:none;font-weight:600}.row a:hover{text-decoration:underline}
.msg{padding:11px 14px;border-radius:10px;margin-bottom:16px;font-size:14px}
.error{background:#fee2e2;color:#991b1b}.success{background:#dcfce7;color:#166534}
@media(max-width:700px){.side{display:none}.form{padding:32px 24px}}  /* Hide the left panel on phones */
</style></head><body>
<div class="box">
  <div class="side"><div class="logo">&#128274;</div><h1>Welcome back!</h1>
    <p>Log in to reach your account. Your data is protected with industry-standard security.</p>
    <ul><li>&#128273; Passwords stored as secure hashes</li><li>&#128241; Optional two-factor protection</li>
        <li>&#128737; Automatic lock after failed attempts</li></ul></div>
  <div class="form"><h2>Log in</h2><p class="sub">Enter your details to continue</p>
    {% for cat, m in messages %}<div class="msg {{ cat }}">{{ m }}</div>{% endfor %}
    <form method="post"><input type="hidden" name="csrf_token" value="{{ csrf }}">
      <label>Username</label>
      <div class="field"><span class="ic">&#128100;</span><input name="username" required autofocus autocomplete="username" placeholder="Your username"></div>
      <label>Password</label>
      <div class="field"><span class="ic">&#128273;</span><input id="pw" name="password" type="password" required autocomplete="current-password" placeholder="Your password">
        <button type="button" id="toggle-pw">Show</button></div>
      <button class="go">Log in</button></form>
    <div class="row"><a href="{{ url_for('forgot_password') }}">Forgot password?</a>
      <a href="{{ url_for('register') }}">Create account</a></div></div>
</div>
<script src="{{ url_for('toggle_js') }}"></script></body></html>"""

@app.route("/toggle.js")
def toggle_js():
    js = ("var b=document.getElementById('toggle-pw'),p=document.getElementById('pw');"      # Find the button and the password box
          "b.addEventListener('click',function(){var s=p.type==='password';"                  # On click: is the password hidden right now?
          "p.type=s?'text':'password';b.textContent=s?'Hide':'Show';});")                     # Switch between hidden and visible
    return app.response_class(js, mimetype="application/javascript")   # Served from our own site (allowed by security policy)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").encode()
        user = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()  # Safe parameterised query
        generic = "Incorrect username or password."               # Same message for both cases so attackers learn nothing

        if user and user["locked_until"] and datetime.fromisoformat(user["locked_until"]) > datetime.now():
            flash(f"Account temporarily locked. Try again in a few minutes.", "error")   # Brute-force protection
        else:
            ok = bcrypt.checkpw(password, user["password_hash"] if user else DUMMY_HASH)  # Compare password with stored hash
            if user and ok:
                get_db().execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?", (user["id"],))
                get_db().commit()                                 # Reset the failure counter
                session.clear()                                   # Drop any old session (prevents session fixation)
                if user["totp_enabled"]:
                    session["pending_2fa"] = user["id"]           # Password OK, but 2FA code still needed
                    return redirect(url_for("verify_2fa"))
                session["user_id"], session["username"] = user["id"], user["username"]  # Fully logged in
                session["login_time"] = datetime.now().timestamp()   # Remember WHEN the user logged in (for the 30-minute limit)
                session.permanent = True                          # Apply the 30-minute lifetime
                return redirect(url_for("dashboard"))
            if user:                                              # Wrong password for a real user: count it
                fails = user["failed_attempts"] + 1
                lock = (datetime.now() + timedelta(minutes=LOCK_MINUTES)).isoformat() if fails >= MAX_FAILED else None
                get_db().execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?",
                                 (0 if lock else fails, lock, user["id"]))
                get_db().commit()
            flash(generic, "error")
    return render_template_string(LOGIN_HTML, csrf=csrf_token(),   # Show the full-page login design
                                  messages=session.pop("_flashes", []))   # One-time messages (errors / success)

def new_recovery_key():
    key = "-".join(secrets.token_hex(2).upper() for _ in range(5))   # Random key like 3FA9-0C1B-77DE-92AA-BC04
    return key, bcrypt.hashpw(key.encode(), bcrypt.gensalt(rounds=12))   # Return the key and its safe hash

RECOVERY_PAGE = """
<p>{{ 'Your password was reset successfully.' if reset else 'Welcome! Your account is ready.' }}</p>
<p><b>Username:</b> {{ username }}</p>
<p><b>Recovery key:</b></p>
<p style="font-size:20px;font-weight:700;letter-spacing:1px;background:#f1f5f9;padding:12px;border-radius:8px;text-align:center">{{ key }}</p>
<div class="msg error"><b>Save this now!</b> Write down your username and recovery key, or store them in a safe place.
This key is shown only once. If you forget your password, this key is the only way to get back in.</div>
<button type="button" id="print-btn" class="link noprint">&#128424; Print / Save as PDF</button>
<a class="noprint" href="{{ url_for('login') }}"><button type="button">I have saved it. Go to login</button></a>
<script src="{{ url_for('print_js') }}"></script>"""   # Loads the tiny script below (inline scripts are blocked by our security policy)

@app.route("/print.js")
def print_js():
    js = "document.getElementById('print-btn').addEventListener('click', function () { window.print(); });"  # Open the print dialog on click
    return app.response_class(js, mimetype="application/javascript")   # Served from our own site, so the security policy allows it

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form.get("username", "").strip()           # Username of the account to recover
        key = request.form.get("recovery_key", "").strip().upper()[:40]   # Recovery key (trimmed, upper-case, length-capped)
        new_pw = request.form.get("password", "")                     # The new password the user wants
        user = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()  # Safe query
        if user and user["locked_until"] and datetime.fromisoformat(user["locked_until"]) > datetime.now():
            flash("Too many wrong attempts. Please try again in a few minutes.", "error")   # Stops guessing the key
        else:
            stored = user["recovery_hash"] if user and user["recovery_hash"] else DUMMY_HASH   # Fake hash if user is unknown
            if not (bcrypt.checkpw(key.encode(), stored) and user):   # Key (or username) is wrong
                if user:                                              # Count the failure for real users
                    fails = user["failed_attempts"] + 1
                    lock = (datetime.now() + timedelta(minutes=LOCK_MINUTES)).isoformat() if fails >= MAX_FAILED else None
                    get_db().execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?",
                                     (0 if lock else fails, lock, user["id"]))
                    get_db().commit()
                flash("Username or recovery key is incorrect.", "error")   # Same message for both cases
            else:
                error = validate_credentials(username, new_pw)        # New password must follow the same rules
                if error:
                    flash(error, "error")
                elif new_pw != request.form.get("confirm", ""):
                    flash("Passwords do not match.", "error")
                else:
                    new_key, new_hash = new_recovery_key()            # The old key is now used up, so make a new one
                    hashed = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt(rounds=12))   # Hash the new password
                    get_db().execute("UPDATE users SET password_hash=?, recovery_hash=?, failed_attempts=0, locked_until=NULL WHERE id=?",
                                     (hashed, new_hash, user["id"]))
                    get_db().commit()
                    session.clear()                                   # Clear any old session
                    return page("Password reset", RECOVERY_PAGE, username=username, key=new_key, reset=True)
    return page("Reset password", """
<p>Enter your username and the recovery key you saved when you registered.</p>
<form method="post"><input type="hidden" name="csrf_token" value="{{ csrf }}">
<label>Username</label><input name="username" required autocomplete="username">
<label>Recovery key</label><input name="recovery_key" required placeholder="XXXX-XXXX-XXXX-XXXX-XXXX" autocomplete="off">
<label>New password</label><input name="password" type="password" required autocomplete="new-password">
<label>Confirm new password</label><input name="confirm" type="password" required autocomplete="new-password">
<button>Reset password</button></form><a href="{{ url_for('login') }}">Back to login</a>""")

@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    uid = session.get("pending_2fa")                              # Only users who passed the password step
    if not uid:
        return redirect(url_for("login"))
    if request.method == "POST":
        user = get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        code = request.form.get("code", "").strip()
        if pyotp.TOTP(user["totp_secret"]).verify(code, valid_window=1):   # Accept the current code (+/- 30 seconds)
            session.clear()
            session["user_id"], session["username"] = user["id"], user["username"]   # Login complete
            session["login_time"] = datetime.now().timestamp()   # Remember WHEN the user logged in (for the 30-minute limit)
            session.permanent = True
            return redirect(url_for("dashboard"))
        flash("Invalid code. Please try again.", "error")
    return page("Two-factor check", """
<p>Enter the 6-digit code from your authenticator app.</p>
<form method="post"><input type="hidden" name="csrf_token" value="{{ csrf }}">
<input name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required autofocus>
<button>Verify</button></form>""")

SECURITY_TIPS = [                                                 # A new tip is shown each day (picked by day of the year)
    "Use a long, unique password for every website. A password manager makes this easy.",
    "Turn on two-factor authentication (2FA) everywhere it is offered.",
    "Never share your login codes with anyone, even if they claim to be support staff.",
    "Be careful with links in emails or messages. Check the web address before you log in.",
    "Log out when you use a shared or public computer.",
    "Keep your phone and computer updated so security fixes are installed.",
]

WELCOME_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Welcome - Secure Login</title>
<meta http-equiv="refresh" content="{{ remaining }};url={{ url_for('dashboard') }}">  <!-- Reloads at expiry; the server then logs the user out -->
<style>
*{box-sizing:border-box}body{margin:0;font-family:system-ui,sans-serif;background:#f1f5f9;color:#0f172a}
nav{display:flex;justify-content:space-between;align-items:center;padding:14px 24px;background:#fff;box-shadow:0 1px 6px #0001}
nav b{font-size:18px}nav form{margin:0}
.btn{display:inline-block;padding:10px 18px;border:0;border-radius:8px;background:#2563eb;color:#fff;font-size:15px;cursor:pointer;text-decoration:none}
.btn.out{background:#ef4444}.btn.green{background:#16a34a}
.hero{background:linear-gradient(135deg,#2563eb,#7c3aed);color:#fff;padding:48px 24px;text-align:center}
.hero h1{margin:0 0 8px;font-size:32px}.hero p{margin:0;opacity:.9}
.wrap{max-width:960px;margin:-28px auto 40px;padding:0 16px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px}
.card{background:#fff;border-radius:14px;padding:22px;box-shadow:0 2px 12px #0001}
.card h3{margin:0 0 10px}.badge{padding:4px 12px;border-radius:99px;font-size:13px;font-weight:600}
.on{background:#dcfce7;color:#166534}.off{background:#fef3c7;color:#92400e}
.msg{max-width:960px;margin:16px auto 0;padding:12px 16px;border-radius:8px;background:#dcfce7}
ul{padding-left:18px;line-height:1.7;margin:0}footer{text-align:center;color:#64748b;padding:20px;font-size:14px}
</style></head><body>
<nav><b>&#128274; Secure Login</b>
  <form method="post" action="{{ url_for('logout') }}">
    <input type="hidden" name="csrf_token" value="{{ csrf }}"><button class="btn out">Log out</button></form></nav>

<div class="hero"><h1>{{ greeting }}, {{ name }}! &#128075;</h1>
  <p>You are securely logged in. Glad to have you here.</p></div>

<div class="wrap">
  {% for cat, m in messages %}<div class="msg">{{ m }}</div>{% endfor %}
  <div class="grid">
    <div class="card"><h3>&#128737; Account security</h3>
      <p>Two-factor authentication:
        <span class="badge {{ 'on' if on else 'off' }}">{{ 'ON' if on else 'OFF' }}</span></p>
      {% if on %}<p>Great job! Your account has an extra layer of protection.</p>
      {% else %}<p>Add a second step to your login for much stronger protection.</p>
        <a class="btn green" href="{{ url_for('setup_2fa') }}">Enable 2FA</a>{% endif %}</div>

    <div class="card"><h3>&#128100; Your session</h3>
      <p><b>Username:</b> {{ name }}</p>
      <p><b>Logged in at:</b> {{ now }}</p>
      <p>For your safety, you will be logged out automatically at <b>{{ expires }}</b> ({{ minutes }} minutes after login).</p></div>

    <div class="card"><h3>&#128161; Tip of the day</h3><p>{{ tip }}</p></div>
  </div>

  <div class="card" style="margin-top:16px"><h3>&#9989; What keeps you safe here</h3>
    <ul><li>Your password is stored as a secure bcrypt hash, never as plain text.</li>
      <li>Too many wrong attempts will temporarily lock the account.</li>
      <li>Every form is protected against fake requests (CSRF).</li>
      <li>Your session ends when you log out or after 30 minutes.</li></ul></div>
</div>
<footer>Secure Login Demo &middot; Stay safe online</footer></body></html>"""

@app.route("/dashboard")
@login_required
def dashboard():
    user = get_db().execute("SELECT totp_enabled FROM users WHERE id=?", (session["user_id"],)).fetchone()  # Is 2FA on?
    end = session["login_time"] + app.config["PERMANENT_SESSION_LIFETIME"].total_seconds()   # Moment the session ends
    remaining = max(int(end - datetime.now().timestamp()) + 1, 1)  # Seconds left (used by the auto-redirect)
    expires = datetime.fromtimestamp(end).strftime("%I:%M %p")    # Friendly time, e.g. "03:45 PM"
    hour = datetime.now().hour                                    # Current hour (0-23) for the greeting
    greeting = "Good morning" if hour < 12 else "Good afternoon" if hour < 17 else "Good evening"  # Pick greeting by time
    tip = SECURITY_TIPS[datetime.now().timetuple().tm_yday % len(SECURITY_TIPS)]  # One tip per day
    return render_template_string(                                # Render the full-width welcome page
        WELCOME_HTML, csrf=csrf_token(), name=session["username"], on=user["totp_enabled"],
        greeting=greeting, tip=tip, remaining=remaining, expires=expires, minutes=SESSION_MINUTES, now=datetime.now().strftime("%d %b %Y, %I:%M %p"),  # e.g. "06 Oct 2026, 03:45 PM"
        messages=session.pop("_flashes", []))                     # Show one-time messages (e.g. "2FA enabled")

@app.route("/setup-2fa", methods=["GET", "POST"])
@login_required
def setup_2fa():
    db = get_db()
    if request.method == "POST":
        secret = session.get("new_totp")                          # Secret generated on the GET request
        if secret and pyotp.TOTP(secret).verify(request.form.get("code", "").strip(), valid_window=1):
            db.execute("UPDATE users SET totp_secret=?, totp_enabled=1 WHERE id=?", (secret, session["user_id"]))
            db.commit()                                           # Save 2FA only after the user proves the app works
            session.pop("new_totp", None)
            flash("Two-factor authentication is now enabled.", "success")
            return redirect(url_for("dashboard"))
        flash("That code was not correct. Please try again.", "error")
    secret = session.setdefault("new_totp", pyotp.random_base32())   # Create a fresh random secret
    uri = pyotp.TOTP(secret).provisioning_uri(name=session["username"], issuer_name="Secure Login Demo")
    buf = io.BytesIO(); qrcode.make(uri).save(buf, format="PNG")     # Draw the QR code in memory
    qr = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()   # Embed it directly in the page
    return page("Enable 2FA", """
<p>1. Scan this QR code with Google Authenticator, Authy or Microsoft Authenticator.</p>
<img src="{{ qr }}" alt="2FA QR code"><p>Or type this key manually: <code>{{ secret }}</code></p>
<p>2. Enter the 6-digit code to confirm:</p>
<form method="post"><input type="hidden" name="csrf_token" value="{{ csrf }}">
<input name="code" inputmode="numeric" maxlength="6" required><button>Confirm</button></form>""", qr=qr, secret=secret)

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()                                               # Destroy the whole session
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()                                                     # Make sure the database exists
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "5000")), debug=False)  # HOST/PORT can be changed with environment variables;                                          # debug=False is important for security
