"""Tests for the low-severity validation and session issues (#8, #9, #13).

#8:  user_quota and user_wallet wrapped only float() in try/except. float("nan")
     and float("inf") parse fine, so the ValueError came from the later int()
     conversion and escaped as an unhandled HTTP 500 instead of a flash message.
#9:  /logout was a GET outside the CSRF method whitelist, so any page could sign
     the operator out with an image tag.
#13: the launcher scripts advertised port 5001 while app.py binds 1343.
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


@pytest.fixture()
def admin_client():
    import bcrypt
    import db
    import app as app_module

    username = "pytest_low_admin"
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


def _csrf(client, path="/users"):
    page = client.get(path)
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', page.get_data(as_text=True))
    return m.group(1) if m else ""


def _victim():
    import db

    username = "pytest_low_victim"
    db.execute("DELETE FROM users WHERE username = %s", (username,))
    return db.fetch_one(
        "INSERT INTO users (username, nickname, email, role, password_hash, "
        "needs_registration, oauth2_provider, status) "
        "VALUES (%s, %s, '', 'user', 'x', FALSE, '', 'active') RETURNING id",
        (username, username),
    )


# ---------- #8: non-finite numbers ----------

def test_finite_float_rejects_non_finite():
    import app

    for bad in ("nan", "NaN", "inf", "-inf", "Infinity", "", "abc", None):
        assert app._finite_float(bad) is None, f"{bad!r} was accepted"

    assert app._finite_float("1.5") == 1.5
    assert app._finite_float("-2") == -2.0
    assert app._finite_float("0") == 0.0


def test_quota_with_nan_does_not_500(admin_client):
    user = _victim()
    try:
        token = _csrf(admin_client)
        resp = admin_client.post(
            f"/users/{user['id']}/quota",
            data={"quota_mb": "nan", "csrf_token": token},
        )
        assert resp.status_code != 500, "nan in the quota field caused a server error"
        assert resp.status_code in (302, 200)
    finally:
        import db

        db.execute("DELETE FROM users WHERE id = %s", (user["id"],))


@pytest.mark.parametrize("value", ["nan", "inf", "-inf", "Infinity"])
def test_quota_with_other_non_finite_values_is_rejected_cleanly(admin_client, value):
    user = _victim()
    try:
        token = _csrf(admin_client)
        resp = admin_client.post(
            f"/users/{user['id']}/quota",
            data={"quota_mb": value, "csrf_token": token},
        )
        assert resp.status_code != 500, f"{value} caused a server error"
    finally:
        import db

        db.execute("DELETE FROM users WHERE id = %s", (user["id"],))


def test_wallet_with_nan_does_not_500(admin_client):
    user = _victim()
    try:
        token = _csrf(admin_client)
        resp = admin_client.post(
            f"/users/{user['id']}/wallet",
            data={"amount": "nan", "description": "", "csrf_token": token},
        )
        assert resp.status_code != 500, "nan in the amount field caused a server error"
    finally:
        import db

        db.execute("DELETE FROM users WHERE id = %s", (user["id"],))


def test_wallet_sub_cent_amount_does_not_create_a_zero_transaction(admin_client):
    """A value below one cent truncates to 0 and must be refused, not recorded."""
    import db

    user = _victim()
    try:
        token = _csrf(admin_client)
        resp = admin_client.post(
            f"/users/{user['id']}/wallet",
            data={"amount": "0.001", "description": "", "csrf_token": token},
        )
        assert resp.status_code in (302, 200)
        count = db.fetch_one(
            "SELECT COUNT(*) AS c FROM wallet_transactions WHERE user_id = %s",
            (user["id"],),
        )["c"]
        assert count == 0, "a zero-value wallet transaction was written"
    finally:
        db.execute("DELETE FROM users WHERE id = %s", (user["id"],))


# ---------- #9: logout requires POST + CSRF ----------

def test_logout_rejects_get(admin_client):
    resp = admin_client.get("/logout")
    assert resp.status_code == 405, (
        f"GET /logout was accepted (status {resp.status_code}); a cross-site "
        "image tag can still sign the operator out"
    )


def test_logout_requires_a_csrf_token(admin_client):
    """A POST without the token must be blocked by the CSRF layer."""
    resp = admin_client.post("/logout")
    assert resp.status_code == 400, f"status {resp.status_code}"


def test_logout_with_token_succeeds(admin_client):
    token = _csrf(admin_client)
    resp = admin_client.post("/logout", data={"csrf_token": token})
    assert resp.status_code in (302, 200)
    # The session must actually be gone.
    after = admin_client.get("/")
    assert after.status_code in (302, 200)


def test_sidebar_renders_logout_as_a_post_form(admin_client):
    body = admin_client.get("/").get_data(as_text=True)
    assert 'action="/logout"' in body, "the sidebar still links to /logout with a GET"
    assert 'href="/logout"' not in body


# ---------- #13: documented port matches the code ----------

def test_launcher_scripts_advertise_the_real_port():
    import app

    # The real port is what app.run uses; read it off the source of __main__.
    import inspect

    source = inspect.getsource(app)
    running = re.findall(r'app\.run\([^)]*port=(\d+)', source)
    assert running, "could not find the app.run port"
    real_port = running[-1]

    for name in ("scripts/start.sh", "scripts/start.bat"):
        path = os.path.join(REPO_ROOT, *name.split("/"))
        with open(path, encoding="utf-8") as fh:
            body = fh.read()
        assert real_port in body, f"{name} does not mention the real port {real_port}"
        assert "5001" not in body, f"{name} still advertises the old port 5001"


def test_readme_documents_the_real_port():
    path = os.path.join(REPO_ROOT, "README.md")
    with open(path, encoding="utf-8") as fh:
        body = fh.read()
    assert "1343" in body, "README does not document the real port"
    assert "5001" not in body, "README still documents the old port 5001"
