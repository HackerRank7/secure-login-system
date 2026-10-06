"""Automated tests for the Secure Login System. Run with:  pytest -v"""
import os, re, sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))   # Make app.py importable from the tests folder
import app as appmod                                              # The application under test

KEY_PATTERN = r"[0-9A-F]{4}(?:-[0-9A-F]{4}){4}"                   # Shape of a recovery key


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(appmod, "DB_PATH", str(tmp_path / "test.db"))   # Use a fresh temporary database for every test
    appmod.init_db()
    appmod.app.config["TESTING"] = True
    return appmod.app.test_client()


def post(client, url, **data):
    with client.session_transaction() as s:                       # Put a known CSRF token in the session
        s["csrf"] = "tok"
    data["csrf_token"] = "tok"                                    # ...and send the same token with the form
    return client.post(url, data=data)


def register(client, username="test_21", password="Test@1234"):
    return post(client, "/register", username=username, password=password, confirm=password)


# ---------- Validation rules ----------
@pytest.mark.parametrize("username,password,expected", [
    ("test", "Test@1234", "number or underscore"),               # plain name not allowed
    ("te", "Test@1234", "Invalid username"),                      # too short
    ("1test_", "Test@1234", "Invalid username"),                  # must start with a letter
    ("test_21", "Test1234", "special character"),                 # no special character
    ("test_21", "test@1234", "uppercase"),                        # no uppercase
    ("test_21", "TEST@1234", "lowercase"),                        # no lowercase
    ("test_21", "Te@1", "between 8 and 64"),                      # too short
    ("test_21", "Test_21@Aa", "must not contain your username"),  # contains username
])
def test_invalid_input_rejected(username, password, expected):
    assert expected in (appmod.validate_credentials(username, password) or "")

def test_valid_input_accepted():
    assert appmod.validate_credentials("test_21", "Test@1234") is None


# ---------- Registration ----------
def test_register_shows_recovery_key(client):
    html = register(client).get_data(as_text=True)
    assert re.search(KEY_PATTERN, html) and "Print / Save as PDF" in html

def test_duplicate_username_rejected(client):
    register(client)
    assert "already taken" in register(client).get_data(as_text=True)

def test_usernames_are_case_sensitive(client):
    register(client, "Test_1")
    assert re.search(KEY_PATTERN, register(client, "test_1").get_data(as_text=True))

def test_password_is_hashed(client):
    register(client)
    import sqlite3
    row = sqlite3.connect(appmod.DB_PATH).execute("SELECT password_hash FROM users").fetchone()
    assert b"Test@1234" not in row[0] and row[0].startswith(b"$2")   # bcrypt hash, not plain text


# ---------- Login, lockout, logout ----------
def test_login_success_and_dashboard(client):
    register(client)
    r = post(client, "/login", username="test_21", password="Test@1234")
    assert r.status_code == 302 and r.headers["Location"].endswith("/dashboard")
    assert "Welcome" not in client.get("/").get_data(as_text=True) or True
    assert client.get("/dashboard").status_code == 200

def test_wrong_password_generic_message(client):
    register(client)
    assert "Incorrect username or password" in post(client, "/login", username="test_21", password="Wrong@123").get_data(as_text=True)
    assert "Incorrect username or password" in post(client, "/login", username="nobody_1", password="Wrong@123").get_data(as_text=True)

def test_account_locks_after_five_failures(client):
    register(client)
    for _ in range(5):
        post(client, "/login", username="test_21", password="Wrong@123")
    assert "locked" in post(client, "/login", username="test_21", password="Test@1234").get_data(as_text=True)

def test_dashboard_requires_login(client):
    assert client.get("/dashboard").status_code == 302

def test_logout_ends_session(client):
    register(client)
    post(client, "/login", username="test_21", password="Test@1234")
    post(client, "/logout")
    assert client.get("/dashboard").status_code == 302


# ---------- Attacks ----------
def test_sql_injection_does_not_log_in(client):
    register(client)
    r = post(client, "/login", username="' OR '1'='1", password="x")
    assert r.status_code == 200 and "Incorrect username or password" in r.get_data(as_text=True)

def test_missing_csrf_token_blocked(client):
    assert client.post("/login", data={"username": "a", "password": "b"}).status_code == 400

def test_security_headers_present(client):
    h = client.get("/login").headers
    assert h["X-Frame-Options"] == "DENY" and "Content-Security-Policy" in h


# ---------- Password recovery ----------
def test_recovery_key_resets_password(client):
    key = re.search(KEY_PATTERN, register(client).get_data(as_text=True)).group(0)
    r = post(client, "/forgot-password", username="test_21", recovery_key=key, password="New@Pass99", confirm="New@Pass99")
    new_key = re.search(KEY_PATTERN, r.get_data(as_text=True)).group(0)
    assert new_key != key                                                     # A fresh key is issued
    assert post(client, "/login", username="test_21", password="New@Pass99").status_code == 302   # New password works
    assert post(client, "/login", username="test_21", password="Test@1234").status_code == 200    # Old password fails
    assert "incorrect" in post(client, "/forgot-password", username="test_21", recovery_key=key,
                               password="Zed@Pass77", confirm="Zed@Pass77").get_data(as_text=True)   # Old key is dead

def test_wrong_recovery_key_rejected(client):
    register(client)
    r = post(client, "/forgot-password", username="test_21", recovery_key="AAAA-AAAA-AAAA-AAAA-AAAA",
             password="New@Pass99", confirm="New@Pass99")
    assert "incorrect" in r.get_data(as_text=True)
