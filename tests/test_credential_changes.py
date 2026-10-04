"""Tests for credential-change handlers (#30 password reset, #32 payment PIN).

#30: resetting an application account's password left its refresh tokens alone.
    They live in their own table with a 30-day lifetime, so an operator resetting
    a compromised account's password left the attacker's session working — the
    reset appeared to succeed and had no effect on access.
#32: the PIN validator used str.isdigit(), which is true for Arabic-Indic and
    other Unicode digits. bcrypt stored them, but the server compares the
    submitted PIN as an ASCII string, so the account ended up with a payment PIN
    that could never be verified.
"""

import os
import re
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


def _has_db():
    try:
        import db

        return bool(db.fetch_one("SELECT to_regclass('public.users') AS t"))
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _has_db(), reason="database not reachable")


# ---------- #32: the PIN format rule (no database needed) ----------

def test_pin_regex_rejects_non_ascii_digits():
    import app

    assert app.PIN_RE.match("123456")
    assert app.PIN_RE.match("000000")

    for bad in ("١٢٣٤٥٦", "१२३४५६", "12345", "1234567", "12a456", "", " 123456"):
        assert app.PIN_RE.match(bad) is None, f"{bad!r} accepted as a payment PIN"


def test_isdigit_would_have_accepted_unicode_digits():
    """Documents why PIN_RE exists: the old check let these through."""
    assert "١٢٣٤٥٦".isdigit() is True
    assert len("١٢٣٤٥٦") == 6
    # ...but they are not ASCII, so the server can never match them.
    assert not "١٢٣٤٥٦".isascii()


# ---------- authenticated client ----------

@pytest.fixture()
def admin_client():
    import bcrypt
    import db
    import app as app_module

    username = "pytest_cred_admin"
    password = "pytest-password-1"
    db.execute("DELETE FROM admin_accounts WHERE username = %s", (username,))
    db.execute(
        "INSERT INTO admin_accounts (username, password_hash, capabilities, can_verify) "
        "VALUES (%s, %s, '*', TRUE)",
        (username, bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()),
    )
    app_module.app.config.update(TESTING=True)
    client = app_module.app.test_client()
    page = client.get("/login")
    tok = re.search(r'name="csrf_token"\s+value="([^"]+)"', page.get_data(as_text=True))
    client.post(
        "/login",
        data={
            "username": username,
            "password": password,
            "csrf_token": tok.group(1) if tok else "",
        },
    )
    yield client
    db.execute("DELETE FROM admin_accounts WHERE username = %s", (username,))


def _csrf(client):
    page = client.get("/users")
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', page.get_data(as_text=True))
    return m.group(1) if m else ""


def _victim():
    import db

    username = "pytest_cred_victim"
    db.execute("DELETE FROM refresh_tokens WHERE user_id IN "
               "(SELECT id FROM users WHERE username = %s)", (username,))
    db.execute("DELETE FROM users WHERE username = %s", (username,))
    return db.fetch_one(
        "INSERT INTO users (username, nickname, email, role, password_hash, "
        "needs_registration, oauth2_provider, status) "
        "VALUES (%s, %s, '', 'user', 'old-hash', FALSE, '', 'active') RETURNING id",
        (username, username),
    )


def _drop(user_id):
    import db

    db.execute("DELETE FROM refresh_tokens WHERE user_id = %s", (user_id,))
    db.execute("DELETE FROM users WHERE id = %s", (user_id,))


def _add_token(user_id, tag):
    import db

    db.execute(
        "INSERT INTO refresh_tokens (user_id, token, expires_at, device_label) "
        "VALUES (%s, %s, NOW() + interval '30 days', 'pytest')",
        (user_id, f"pytest-token-{tag}-{user_id}"),
    )


def _token_count(user_id):
    import db

    return db.fetch_one(
        "SELECT COUNT(*) AS n FROM refresh_tokens WHERE user_id = %s", (user_id,)
    )["n"]


# ---------- #30: password reset revokes sessions ----------

def test_password_reset_revokes_refresh_tokens(admin_client):
    user = _victim()
    try:
        _add_token(user["id"], "before")
        assert _token_count(user["id"]) == 1

        token = _csrf(admin_client)
        admin_client.post(
            f"/users/{user['id']}/reset-password",
            data={"password": "brand-new-password-1", "csrf_token": token},
        )

        assert _token_count(user["id"]) == 0, (
            "a password reset left the old sessions valid for up to 30 days"
        )
    finally:
        _drop(user["id"])


def test_password_reset_still_updates_the_hash(admin_client):
    import bcrypt
    import db

    user = _victim()
    try:
        token = _csrf(admin_client)
        admin_client.post(
            f"/users/{user['id']}/reset-password",
            data={"password": "brand-new-password-1", "csrf_token": token},
        )
        row = db.fetch_one("SELECT password_hash FROM users WHERE id = %s", (user["id"],))
        assert bcrypt.checkpw(b"brand-new-password-1", row["password_hash"].encode())
    finally:
        _drop(user["id"])


# ---------- #32: PIN reset ----------

def test_unicode_pin_is_rejected(admin_client):
    import db

    user = _victim()
    try:
        token = _csrf(admin_client)
        admin_client.post(
            f"/users/{user['id']}/reset-pin",
            data={"pin": "١٢٣٤٥٦", "csrf_token": token},
        )
        row = db.fetch_one("SELECT pin_hash FROM users WHERE id = %s", (user["id"],))
        assert not row["pin_hash"], (
            "a non-ASCII PIN was stored; the server could never verify it"
        )
    finally:
        _drop(user["id"])


def test_ascii_pin_is_accepted(admin_client):
    import bcrypt
    import db

    user = _victim()
    try:
        token = _csrf(admin_client)
        admin_client.post(
            f"/users/{user['id']}/reset-pin",
            data={"pin": "246810", "csrf_token": token},
        )
        row = db.fetch_one("SELECT pin_hash FROM users WHERE id = %s", (user["id"],))
        assert row["pin_hash"], "a valid ASCII PIN was not stored"
        assert bcrypt.checkpw(b"246810", row["pin_hash"].encode())
    finally:
        _drop(user["id"])
