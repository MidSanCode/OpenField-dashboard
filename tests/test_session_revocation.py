"""Tests for panel session revocation (dashboard issue #26).

Flask's client-side session carried all authorization state, and login_required
asserted only that the cookie held an admin_id. Nothing reconciled that cookie
with admin_accounts, so deleting an administrator or rotating their password
left every session they already held fully usable. These tests pin the
revalidation: a session must die when the account is removed, disabled, or has
its credential generation bumped.
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

        return bool(db.fetch_one("SELECT to_regclass('public.admin_accounts') AS t"))
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _has_db(), reason="the admin_accounts table is not reachable"
)


@pytest.fixture()
def admin_row():
    """Create a disposable panel account with a known password."""
    import bcrypt
    import db

    username = "pytest_session_revoke"
    db.execute("DELETE FROM admin_accounts WHERE username = %s", (username,))
    password_hash = bcrypt.hashpw(b"pytest-password-1", bcrypt.gensalt()).decode()
    row = db.fetch_one(
        "INSERT INTO admin_accounts (username, password_hash, capabilities, can_verify) "
        "VALUES (%s, %s, '*', TRUE) RETURNING id, session_version",
        (username, password_hash),
    )
    yield row
    db.execute("DELETE FROM admin_accounts WHERE username = %s", (username,))


def _login(client, username="pytest_session_revoke", password="pytest-password-1"):
    """Log in through the real form, including the CSRF token.

    The panel validates a CSRF token on POSTs, so a test that skips it is
    rejected with 400 before authentication is even considered.
    """
    page = client.get("/login")
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', page.get_data(as_text=True))
    data = {"username": username, "password": password}
    if match:
        data["csrf_token"] = match.group(1)
    return client.post("/login", data=data, follow_redirects=False)


def _authed_client():
    import app as app_module

    app_module.app.config.update(TESTING=True)
    return app_module.app.test_client()


def test_valid_session_reaches_the_dashboard(admin_row):
    client = _authed_client()
    _login(client)
    resp = client.get("/")
    assert resp.status_code == 200, "a freshly logged-in session should work"


def test_bumping_session_version_logs_the_session_out(admin_row):
    """This is the revocation mechanism: a password rotation must end sessions."""
    import db

    client = _authed_client()
    _login(client)
    assert client.get("/").status_code == 200

    db.execute(
        "UPDATE admin_accounts SET session_version = session_version + 1 WHERE id = %s",
        (admin_row["id"],),
    )

    resp = client.get("/")
    assert resp.status_code == 302, "the revoked session must be redirected to login"
    assert "/login" in resp.headers.get("Location", "")


def test_deleting_the_account_logs_the_session_out(admin_row):
    import db

    client = _authed_client()
    _login(client)
    assert client.get("/").status_code == 200

    db.execute("DELETE FROM admin_accounts WHERE id = %s", (admin_row["id"],))

    resp = client.get("/")
    assert resp.status_code == 302
    assert "/login" in resp.headers.get("Location", "")


def test_disabling_the_account_logs_the_session_out(admin_row):
    import db

    client = _authed_client()
    _login(client)
    assert client.get("/").status_code == 200

    db.execute("UPDATE admin_accounts SET disabled = TRUE WHERE id = %s", (admin_row["id"],))

    resp = client.get("/")
    assert resp.status_code == 302
    assert "/login" in resp.headers.get("Location", "")


def test_a_disabled_account_cannot_log_in(admin_row):
    import db

    db.execute("UPDATE admin_accounts SET disabled = TRUE WHERE id = %s", (admin_row["id"],))

    client = _authed_client()
    resp = _login(client)
    # The login page is re-rendered with an error rather than redirecting on.
    assert resp.status_code != 302 or "/login" in resp.headers.get("Location", "")
    assert client.get("/").status_code == 302


def test_session_without_a_version_is_rejected(admin_row):
    """A cookie minted before this check (or forged without it) must not pass."""
    client = _authed_client()
    with client.session_transaction() as sess:
        sess["admin_id"] = admin_row["id"]
        sess["admin_username"] = "pytest_session_revoke"

    assert client.get("/").status_code == 302
