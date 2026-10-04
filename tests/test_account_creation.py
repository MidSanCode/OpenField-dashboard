"""Tests for account creation rules, the role/group distinction, and DB errors.

#10: user_new wrote the role column unvalidated and skipped password policy,
     unlike user_rename and the password-change route.
#11: the panel marked administrators via users.role, but the server's
     authorization comes from user_groups ⋈ group_permissions; nothing on the
     server reads users.role, so the label implied access it never granted.
#12: the global psycopg2 handler rendered the raw exception into the page and
     returned HTTP 200.
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

    username = "pytest_create_admin"
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


def _csrf(client, path="/users/new"):
    page = client.get(path)
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', page.get_data(as_text=True))
    return m.group(1) if m else ""


def _cleanup(username):
    import db

    db.execute("DELETE FROM users WHERE username = %s", (username,))


# ---------- #10: creation validates username, role and password ----------

def test_valid_creation_succeeds(admin_client):
    import db

    name = "pytest_created_ok"
    _cleanup(name)
    try:
        token = _csrf(admin_client)
        admin_client.post(
            "/users/new",
            data={
                "username": name,
                "nickname": "Ok",
                "email": "",
                "password": "goodpassword12",
                "role": "user",
                "csrf_token": token,
            },
        )
        assert db.fetch_one("SELECT id FROM users WHERE username = %s", (name,)), (
            "a valid user was not created"
        )
    finally:
        _cleanup(name)


def test_bad_username_is_rejected(admin_client):
    import db

    name = "BadName"
    _cleanup(name)
    token = _csrf(admin_client)
    admin_client.post(
        "/users/new",
        data={
            "username": name,
            "nickname": "N",
            "email": "",
            "password": "goodpassword12",
            "role": "user",
            "csrf_token": token,
        },
    )
    assert not db.fetch_one("SELECT id FROM users WHERE username = %s", (name,)), (
        "an uppercase username was accepted"
    )


def test_invalid_role_is_rejected(admin_client):
    """An arbitrary role produced an account the panel's own filters miss."""
    import db

    name = "pytest_created_badrole"
    _cleanup(name)
    try:
        token = _csrf(admin_client)
        admin_client.post(
            "/users/new",
            data={
                "username": name,
                "nickname": "N",
                "email": "",
                "password": "goodpassword12",
                "role": "superuser",
                "csrf_token": token,
            },
        )
        assert not db.fetch_one("SELECT id FROM users WHERE username = %s", (name,)), (
            "an out-of-vocabulary role was written into users.role"
        )
    finally:
        _cleanup(name)


def test_weak_password_is_rejected(admin_client):
    """The panel's own password-change route refuses short passwords."""
    import db

    name = "pytest_created_weakpw"
    _cleanup(name)
    try:
        token = _csrf(admin_client)
        admin_client.post(
            "/users/new",
            data={
                "username": name,
                "nickname": "N",
                "email": "",
                "password": "short1",
                "role": "user",
                "csrf_token": token,
            },
        )
        assert not db.fetch_one("SELECT id FROM users WHERE username = %s", (name,)), (
            "a password below the panel's own policy was accepted"
        )
    finally:
        _cleanup(name)


def test_password_with_outer_whitespace_is_rejected(admin_client):
    import db

    name = "pytest_created_wspw"
    _cleanup(name)
    try:
        token = _csrf(admin_client)
        admin_client.post(
            "/users/new",
            data={
                "username": name,
                "nickname": "N",
                "email": "",
                "password": " goodpassword12 ",
                "role": "user",
                "csrf_token": token,
            },
        )
        assert not db.fetch_one("SELECT id FROM users WHERE username = %s", (name,)), (
            "a password with surrounding whitespace was accepted"
        )
    finally:
        _cleanup(name)


def test_letters_only_password_is_rejected(admin_client):
    import db

    name = "pytest_created_alpha"
    _cleanup(name)
    try:
        token = _csrf(admin_client)
        admin_client.post(
            "/users/new",
            data={
                "username": name,
                "nickname": "N",
                "email": "",
                "password": "onlylettershere",
                "role": "user",
                "csrf_token": token,
            },
        )
        assert not db.fetch_one("SELECT id FROM users WHERE username = %s", (name,))
    finally:
        _cleanup(name)


# ---------- #11: the role column is a label, not a grant ----------

def test_role_templates_do_not_claim_administrative_access():
    """The UI must not describe users.role as granting admin rights."""
    for name, forbidden in [
        ("users.html", ">管理员<"),
        ("dashboard.html", ">管理员<"),
    ]:
        path = os.path.join(REPO_ROOT, "templates", name)
        with open(path, encoding="utf-8") as fh:
            body = fh.read()
        assert forbidden not in body, (
            f"{name} still labels users.role as plain 管理员, which implies the "
            "server grants admin access from that column"
        )


def test_role_route_still_rejects_unknown_values(admin_client):
    import db

    name = "pytest_role_victim"
    _cleanup(name)
    user = db.fetch_one(
        "INSERT INTO users (username, nickname, email, role, password_hash, "
        "needs_registration, oauth2_provider, status) "
        "VALUES (%s, %s, '', 'user', 'x', FALSE, '', 'active') RETURNING id",
        (name, name),
    )
    try:
        token = _csrf(admin_client)
        resp = admin_client.post(
            f"/users/{user['id']}/role",
            data={"role": "superuser", "csrf_token": token},
        )
        assert resp.status_code == 400, f"status {resp.status_code}"
        row = db.fetch_one("SELECT role FROM users WHERE id = %s", (user["id"],))
        assert row["role"] == "user", "an invalid role was written"
    finally:
        _cleanup(name)


# ---------- #12: database errors do not leak and do not report success ----------

def test_database_error_handler_hides_detail_and_sets_real_status(monkeypatch):
    """A raised psycopg2 error must not render its text, nor return 200."""
    import bcrypt
    import psycopg2
    import db
    import app as app_module

    secret = "SECRET-DB-DETAIL-9f3a"
    username = "pytest_dbadmin"

    db.execute("DELETE FROM admin_accounts WHERE username = %s", (username,))
    db.execute(
        "INSERT INTO admin_accounts (username, password_hash, capabilities, can_verify) "
        "VALUES (%s, %s, '*', TRUE)",
        (username, bcrypt.hashpw(b"pytest-password-1", bcrypt.gensalt()).decode()),
    )
    app_module.app.config.update(TESTING=True)
    client = app_module.app.test_client()
    page = client.get("/login")
    tok = re.search(r'name="csrf_token"\s+value="([^"]+)"', page.get_data(as_text=True))
    client.post(
        "/login",
        data={
            "username": username,
            "password": "pytest-password-1",
            "csrf_token": tok.group(1) if tok else "",
        },
    )

    def boom(*args, **kwargs):
        raise psycopg2.OperationalError(secret)

    # /users definitely queries the database, so the handler is reached.
    real_fetch_one = app_module.db.fetch_one
    real_fetch_all = app_module.db.fetch_all
    app_module.db.fetch_one = boom
    app_module.db.fetch_all = boom
    try:
        resp = client.get("/users")
    finally:
        app_module.db.fetch_one = real_fetch_one
        app_module.db.fetch_all = real_fetch_all
        db.execute("DELETE FROM admin_accounts WHERE username = %s", (username,))

    assert resp.status_code != 200, (
        "a database error was reported as HTTP 200, so monitoring sees success"
    )
    body = resp.get_data(as_text=True)
    assert secret not in body, "the raw database error was rendered to the client"


def test_db_unavailable_template_has_no_error_block():
    path = os.path.join(REPO_ROOT, "templates", "db_unavailable.html")
    with open(path, encoding="utf-8") as fh:
        body = fh.read()
    assert "{{ error }}" not in body, "the template still renders an error string"
