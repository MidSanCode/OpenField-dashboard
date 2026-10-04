"""Tests for OAuth unbinding (#21) and the credential-availability check.

Unbinding an account's last OAuth identity used to be unconditional, which left
an account with neither a password nor an identity — permanently unable to log
in, since the server authenticates by bcrypt-comparing password_hash or by an
OAuth identity and both were now gone.
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


# ---------- the helper itself (no database needed) ----------

def test_password_hash_detection():
    import app

    real = "$2b$12$" + "x" * 53
    assert app._is_usable_password_hash(real) is True
    assert app._is_usable_password_hash("$2a$10$" + "y" * 53) is True

    for bad in ("", None, "   ", "placeholder", "not-a-hash", "$2b$12$tooshort"):
        assert app._is_usable_password_hash(bad) is False, f"{bad!r} treated as usable"


# ---------- the route ----------

@pytest.fixture()
def admin_client():
    import bcrypt
    import db
    import app as app_module

    username = "pytest_oauth_admin"
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


def _oauth_user(password_hash):
    import db

    username = "pytest_oauth_victim"
    db.execute("DELETE FROM users WHERE username = %s", (username,))
    return db.fetch_one(
        "INSERT INTO users (username, nickname, email, role, password_hash, "
        "needs_registration, oauth2_provider, oauth2_id, status) "
        "VALUES (%s, %s, '', 'user', %s, FALSE, 'oidc', 'ext-1', 'active') RETURNING id",
        (username, username, password_hash),
    )


def _binding(user_id):
    import db

    return db.fetch_one(
        "SELECT oauth2_provider, oauth2_id FROM users WHERE id = %s", (user_id,)
    )


def _drop(user_id):
    import db

    db.execute("DELETE FROM users WHERE id = %s", (user_id,))


def test_unbinding_is_refused_when_it_is_the_last_credential(admin_client):
    """An OAuth-only account must keep its identity."""
    import db

    user = _oauth_user("")  # no password at all
    try:
        token = _csrf(admin_client)
        admin_client.post(
            f"/users/{user['id']}/unbind-oauth", data={"csrf_token": token}
        )
        binding = _binding(user["id"])
        assert binding["oauth2_provider"] == "oidc", (
            "the last credential was removed, locking the account out"
        )
    finally:
        _drop(user["id"])


def test_unbinding_is_refused_for_a_placeholder_hash(admin_client):
    """A non-empty but non-bcrypt hash cannot authenticate, so it is not a credential."""
    import db

    user = _oauth_user("placeholder")
    try:
        token = _csrf(admin_client)
        admin_client.post(
            f"/users/{user['id']}/unbind-oauth", data={"csrf_token": token}
        )
        assert _binding(user["id"])["oauth2_provider"] == "oidc"
    finally:
        _drop(user["id"])


def test_unbinding_succeeds_when_a_real_password_exists(admin_client):
    import bcrypt
    import db

    real = bcrypt.hashpw(b"user-password-1", bcrypt.gensalt()).decode()
    user = _oauth_user(real)
    try:
        token = _csrf(admin_client)
        admin_client.post(
            f"/users/{user['id']}/unbind-oauth", data={"csrf_token": token}
        )
        binding = _binding(user["id"])
        assert binding["oauth2_provider"] == "", "a legitimate unbind was refused"
        assert binding["oauth2_id"] == ""
    finally:
        _drop(user["id"])
