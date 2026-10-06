# 🔐 Secure Login System

A secure, user-friendly login web app built with **Flask**, **SQLite**, **bcrypt** and optional **TOTP two-factor authentication (2FA)**.
Every line of code is commented to explain what it does, so it is also a good learning project.

## ✨ Features

| Area | What is included |
|---|---|
| **Registration & login** | Passwords hashed with **bcrypt** (salted, 12 rounds). Plain passwords are never stored. |
| **Input validation** | Username and password rules checked on the server with clear error messages. |
| **SQL injection protection** | Every database query uses parameterised placeholders (`?`). |
| **Session management** | Secure cookie (`HttpOnly`, `SameSite`), 30-minute expiry, session reset on login/logout. |
| **Logout** | Protected POST logout that destroys the whole session. |
| **2FA (optional)** | Time-based one-time codes (Google Authenticator, Authy, Microsoft Authenticator) with QR-code setup. |
| **Password recovery** | One-time **recovery key** shown at registration (printable / save as PDF) and used to reset a forgotten password. |
| **Brute-force protection** | Account locks for 10 minutes after 5 wrong attempts (login and recovery). |
| **Extra hardening** | CSRF tokens on all forms, security headers (CSP, `X-Frame-Options`, `nosniff`, `no-store`), identical error messages for wrong username/password, constant-time checks. |
| **UI** | Modern login page, welcome dashboard with daily security tip, mobile-friendly layout. |

## 📋 Input rules

**Username**: 4–20 characters, starts with a letter, only letters / numbers / underscore, must contain at least one number or underscore (e.g. `test_21`). Usernames are unique and **case-sensitive** (`Test_1` and `test_1` are different).

**Password**: 8–64 characters with at least one uppercase letter, one lowercase letter and one special character (e.g. `Test@1234`). It must not contain the username.

## 🚀 Quick start

### Linux / macOS (including Kali)
```bash
git clone https://github.com/<your-username>/secure-login-system.git
cd secure-login-system

sudo apt update && sudo apt install -y python3-venv python3-pip   # Debian/Kali only
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

### Windows (PowerShell)
```powershell
git clone https://github.com/<your-username>/secure-login-system.git
cd secure-login-system

python -m venv venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass   # only if activate is blocked
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Then open **http://127.0.0.1:5000** in your browser.

> The database file `users.db` is created automatically on first run. If you change the database structure, delete `users.db` and restart.

## ⚙️ Configuration

| Environment variable | Purpose |
|---|---|
| `SECRET_KEY` | Key that signs session cookies. **Set a fixed random value in production**, otherwise everyone is logged out on each restart. Generate one with `python -c "import secrets; print(secrets.token_hex(32))"`. |
| `HTTPS=1` | Marks the session cookie as `Secure` (sent over HTTPS only). Set this when serving over HTTPS. |

Example:
```bash
export SECRET_KEY="paste-your-random-key-here"
python app.py
```

## 🧪 Run the automated tests

```bash
pip install pytest
pytest -v
```

The tests cover validation rules, registration, duplicate usernames, login, lockout, logout, CSRF protection, SQL-injection attempts and the recovery-key flow.

## 🔍 Manual security checklist

| Test | Expected result |
|---|---|
| Register with `test` | Rejected (needs a number or underscore) |
| Register with password `Test1234` | Rejected (needs a special character) |
| Username `' OR '1'='1` on login | Rejected, no login |
| 5 wrong passwords in a row | Account locked for 10 minutes |
| Submit a form without `csrf_token` | `400 Invalid form token` |
| Open `/dashboard` after logout | Redirected to login |
| Enable 2FA, log out, log in again | 6-digit code is asked after the password |
| Forgot password with the saved recovery key | Password reset and a new key is issued; old key stops working |

## 🗂️ Project structure

```
secure-login-system/
├── app.py              # The whole application (routes, security, HTML templates)
├── requirements.txt    # Python dependencies
├── tests/
│   └── test_app.py     # Automated tests (pytest)
├── .gitignore          # Keeps the database, venv and secrets out of Git
├── LICENSE             # MIT licence
└── README.md
```

## 🏭 Before deploying to production

- Set a fixed `SECRET_KEY` and `HTTPS=1`, and serve the app over **HTTPS**.
- Run it with a production server such as **gunicorn** instead of `python app.py`.
- Put it behind a reverse proxy (nginx) and consider adding rate limiting per IP.
- Back up or migrate the database properly (SQLite is fine for demos and small apps).

## ⚠️ Known limitations

- A forgotten **username** cannot be recovered (no email is linked to accounts).
- If both the password **and** the recovery key are lost, the account cannot be recovered.
- Losing the 2FA authenticator app is not handled yet (backup codes are a planned improvement).

## 🛣️ Ideas for future improvements

Email-based recovery, 2FA backup codes, "disable 2FA", login history, dark mode, Argon2 hashing option.

## 📄 Licence

Released under the [MIT Licence](LICENSE). Use only on systems you own or have permission to test.
