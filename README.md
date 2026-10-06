# 🔐 Secure Login System

A secure, user-friendly login web app built with **Flask**, **SQLite**, **bcrypt** and optional **TOTP two-factor authentication (2FA)**.
Works on **Linux, Kali, macOS and Windows**. Every line of code is commented to explain what it does, so it is also a good learning project.

![Tests](https://github.com/HackerRank7/secure-login-system/actions/workflows/tests.yml/badge.svg)

## ✨ Features

| Area | What is included |
|---|---|
| **Registration & login** | Passwords hashed with **bcrypt** (salted, 12 rounds). Plain passwords are never stored. |
| **Input validation** | Username and password rules checked on the server with clear error messages. |
| **SQL injection protection** | Every database query uses parameterised placeholders (`?`). |
| **Session management** | Secure cookie (`HttpOnly`, `SameSite`), fixed 30-minute limit from login (enforced on the server, not extended by activity), automatic redirect to login when time is up. |
| **Logout** | Protected POST logout that destroys the whole session. |
| **2FA (optional)** | Time-based one-time codes (Google Authenticator, Authy, Microsoft Authenticator) with QR-code setup. |
| **Password recovery** | One-time **recovery key** shown at registration (print / save as PDF) and used to reset a forgotten password. |
| **Brute-force protection** | Account locks for 10 minutes after 5 wrong attempts (login and recovery). |
| **Extra hardening** | CSRF tokens on all forms, security headers (CSP, `X-Frame-Options`, `nosniff`, `no-store`), identical error messages for wrong username/password. |
| **UI** | Modern login page with show/hide password, welcome dashboard with daily security tip, mobile-friendly layout. |

## 📋 Input rules

**Username**: 4–20 characters, starts with a letter, only letters / numbers / underscore, must contain at least one number or underscore (e.g. `test_21`). Usernames are unique and **case-sensitive** (`Test_1` and `test_1` are different).

**Password**: 8–64 characters with at least one uppercase letter, one lowercase letter and one special character (e.g. `Test@1234`). It must not contain the username.

## 🚀 Quick start

Requirements: **Python 3.10 or newer** and **Git**.

```bash
git clone https://github.com/HackerRank7/secure-login-system.git
cd secure-login-system
```

### 🐧 Linux / Kali / macOS

```bash
chmod +x setup.sh run.sh test.sh     # only needed if the scripts are not executable
./setup.sh                           # one time: creates venv and installs everything
./run.sh                             # starts the app
```
On Debian/Kali, if `setup.sh` complains about venv: `sudo apt install -y python3-venv python3-pip`

### 🪟 Windows

Double-click **`setup.bat`** once, then double-click **`run.bat`**. Or from Command Prompt / PowerShell:
```
.\setup.bat
.\run.bat
```
The `.bat` files call the virtual environment's Python directly, so you do **not** need to change any PowerShell execution policy.

Then open **http://127.0.0.1:5000** in your browser.

<details>
<summary>Prefer to do it manually?</summary>

```bash
# Linux / macOS                          # Windows (PowerShell)
python3 -m venv venv                     python -m venv venv
source venv/bin/activate                 Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
pip install -r requirements.txt          venv\Scripts\activate
python app.py                            pip install -r requirements.txt
                                         python app.py
```
</details>

## ⚙️ Configuration (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `SECRET_KEY` | auto-saved in `.secret_key` by the run scripts | Signs session cookies. Use a fixed random value in production. Generate: `python -c "import secrets; print(secrets.token_hex(32))"` |
| `SESSION_MINUTES` | `30` | Session length. Set `1` to quickly test the automatic logout. |
| `HTTPS` | off | Set `HTTPS=1` to mark the cookie `Secure` when serving over HTTPS. |
| `HOST` | `127.0.0.1` | Set `0.0.0.0` to reach the app from another device on your network (use only on a trusted test network). |
| `PORT` | `5000` | Port to listen on. |

Examples:
```bash
SESSION_MINUTES=1 ./run.sh                 # Linux/macOS: 1-minute session
```
```
set SESSION_MINUTES=1 && run.bat           REM Windows (Command Prompt)
```

## 🧪 Run the automated tests

```bash
./test.sh          # Linux / macOS
test.bat           # Windows
```
Or manually: `python -m pytest -v`. The **25 tests** cover validation, registration, duplicate and case-sensitive usernames, bcrypt hashing, login, lockout, logout, session expiry, CSRF, SQL-injection attempts, security headers and the recovery-key flow.

GitHub Actions (`.github/workflows/tests.yml`) runs the same tests automatically on **Ubuntu and Windows** with Python 3.10 and 3.12 for every push.

## 🔍 Manual security checklist

| Test | Expected result |
|---|---|
| Register with `test` | Rejected (needs a number or underscore) |
| Register with password `Test1234` | Rejected (needs a special character) |
| Username `' OR '1'='1` on login | Rejected, no login |
| 5 wrong passwords in a row | Account locked for 10 minutes |
| Submit a form without `csrf_token` | `400 Invalid form token` |
| Open `/dashboard` after logout | Redirected to login |
| Run with `SESSION_MINUTES=1`, stay on dashboard | Automatically sent to login after 1 minute |
| Enable 2FA, log out, log in again | 6-digit code is asked after the password |
| Forgot password with the saved recovery key | Password reset, new key issued, old key stops working |

## 🗂️ Project structure

```
secure-login-system/
├── app.py                 # The whole application (routes, security, HTML templates)
├── requirements.txt       # Runtime dependencies
├── requirements-dev.txt   # + pytest for testing
├── setup.sh / setup.bat   # One-time setup (Linux/macOS | Windows)
├── run.sh / run.bat       # Start the app
├── test.sh / test.bat     # Run the tests
├── tests/test_app.py      # Automated tests (pytest)
├── .github/workflows/     # CI: tests on Ubuntu + Windows
├── .gitignore  .gitattributes
├── LICENSE
└── README.md
```

## 🛠️ Troubleshooting

| Problem | Fix |
|---|---|
| `externally-managed-environment` (Kali/Debian) | Use `./setup.sh` (it uses a virtual environment) instead of plain `pip install`. |
| `venv\Scripts\activate` blocked in PowerShell | Use `run.bat`, or run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` first. |
| `python` not found on Windows | Install Python from python.org and tick **Add Python to PATH**, then reopen the terminal. |
| `Address already in use` | Another program uses port 5000. Start with a different port, e.g. `PORT=5050 ./run.sh`. |
| Changes in code are not visible | Stop the server (`Ctrl + C`), start it again, and hard-refresh the browser (`Ctrl + F5`). |
| Want a clean start | Stop the app and delete `users.db` (this removes all users). |

## 🏭 Before deploying to production

- Set a fixed `SECRET_KEY` and `HTTPS=1`, and serve the app over **HTTPS**.
- Run it with a production server such as **gunicorn** (Linux) or **waitress** (Windows) instead of `python app.py`.
- Put it behind a reverse proxy (nginx) and consider per-IP rate limiting.
- SQLite is fine for demos and small apps; use PostgreSQL/MySQL for larger deployments.

## ⚠️ Known limitations

- A forgotten **username** cannot be recovered (no email is linked to accounts).
- If both the password **and** the recovery key are lost, the account cannot be recovered.
- Losing the 2FA authenticator app is not handled yet (backup codes are a planned improvement).

## 🛣️ Ideas for future improvements

Email-based recovery, 2FA backup codes, "disable 2FA", login history, dark mode, Argon2 hashing option.

## 📄 Licence

Released under the [MIT Licence](LICENSE). Use only on systems you own or have permission to test.
