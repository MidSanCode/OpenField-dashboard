"""Tests for the inverted boolean form handlers (#15 and #37).

Both bugs are the same shape: a handler compared a checkbox submission against
the literal "1". A browser submits a ticked checkbox's *value* attribute
(conventionally "on") and omits the field entirely when unticked, so the
comparison read a checked box as False — and #37 additionally forced the flag
back to True whenever two backfilled text fields were non-empty, which they
always were.
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

    username = "pytest_bool_admin"
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


def _fresh_user(verified=False):
    import db

    username = "pytest_bool_victim"
    db.execute("DELETE FROM users WHERE username = %s", (username,))
    return db.fetch_one(
        "INSERT INTO users (username, nickname, email, role, password_hash, "
        "needs_registration, oauth2_provider, status, is_verified) "
        "VALUES (%s, %s, '', 'user', 'x', FALSE, '', 'active', %s) RETURNING id",
        (username, username, verified),
    )


def _drop(user_id):
    import db

    db.execute("DELETE FROM users WHERE id = %s", (user_id,))


# ---------- #15: the verification capability toggle ----------

def _verify_admin_row():
    import db

    return db.fetch_one(
        "SELECT id, can_verify, capabilities FROM admin_accounts WHERE username = %s",
        ("pytest_bool_target",),
    )


@pytest.fixture()
def target_admin():
    import bcrypt
    import db

    db.execute("DELETE FROM admin_accounts WHERE username = %s", ("pytest_bool_target",))
    db.execute(
        "INSERT INTO admin_accounts (username, password_hash, capabilities, can_verify) "
        "VALUES (%s, %s, 'users.verify', TRUE)",
        ("pytest_bool_target", bcrypt.hashpw(b"x", bcrypt.gensalt()).decode()),
    )
    yield _verify_admin_row()
    db.execute("DELETE FROM admin_accounts WHERE username = %s", ("pytest_bool_target",))


def test_ticking_the_toggle_grants_verification(admin_client, target_admin):
    """Submitting the checkbox as a browser does ("on") must GRANT, not revoke."""
    token = _csrf(admin_client, "/admins")
    admin_client.post(
        f"/admins/{target_admin['id']}/can-verify",
        data={"can_verify": "on", "csrf_token": token},
    )
    row = _verify_admin_row()
    assert row["can_verify"] is True, "a ticked box revoked the permission"
    assert "users.verify" in (row["capabilities"] or "")


def test_ticking_with_value_one_also_grants(admin_client, target_admin):
    token = _csrf(admin_client, "/admins")
    admin_client.post(
        f"/admins/{target_admin['id']}/can-verify",
        data={"can_verify": "1", "csrf_token": token},
    )
    assert _verify_admin_row()["can_verify"] is True


def test_unticking_the_toggle_revokes_verification(admin_client, target_admin):
    token = _csrf(admin_client, "/admins")
    admin_client.post(
        f"/admins/{target_admin['id']}/can-verify",
        data={"csrf_token": token},  # field absent == unchecked
    )
    row = _verify_admin_row()
    assert row["can_verify"] is False
    assert "users.verify" not in (row["capabilities"] or "")


# ---------- #37: the verified badge toggle ----------

def test_unchecking_verified_actually_revokes_the_badge(admin_client):
    """This is the #37 regression.

    The user already has verified_by/verified_note set, so the modal backfills
    both fields. The handler used to treat a non-empty value as proof of intent
    to verify, which made unticking the box impossible.
    """
    import db

    user = _fresh_user(verified=True)
    db.execute(
        "UPDATE users SET verified_by = 'someone', verified_note = 'note text' "
        "WHERE id = %s",
        (user["id"],),
    )
    try:
        token = _csrf(admin_client, "/users")
        admin_client.post(
            f"/users/{user['id']}/verified",
            data={
                # checkbox deliberately absent
                "verified_by": "someone",
                "verified_note": "note text",
                "csrf_token": token,
            },
        )
        row = db.fetch_one(
            "SELECT is_verified, verified_by, verified_note FROM users WHERE id = %s",
            (user["id"],),
        )
        assert row["is_verified"] is False, "unchecking did not revoke the badge"
        assert row["verified_by"] == "", "stale verification detail was left behind"
        assert row["verified_note"] == ""
    finally:
        _drop(user["id"])


def test_checking_verified_grants_the_badge(admin_client):
    import db

    user = _fresh_user(verified=False)
    try:
        token = _csrf(admin_client, "/users")
        admin_client.post(
            f"/users/{user['id']}/verified",
            data={
                "verified": "on",
                "verified_by": "official",
                "verified_note": "confirmed",
                "csrf_token": token,
            },
        )
        row = db.fetch_one(
            "SELECT is_verified, verified_by FROM users WHERE id = %s", (user["id"],)
        )
        assert row["is_verified"] is True
        assert row["verified_by"] == "official"
    finally:
        _drop(user["id"])


def test_verified_without_a_subject_gets_a_default(admin_client):
    import db

    user = _fresh_user(verified=False)
    try:
        token = _csrf(admin_client, "/users")
        admin_client.post(
            f"/users/{user['id']}/verified",
            data={"verified": "on", "csrf_token": token},
        )
        row = db.fetch_one(
            "SELECT is_verified, verified_by FROM users WHERE id = %s", (user["id"],)
        )
        assert row["is_verified"] is True
        assert row["verified_by"] == "admin"
    finally:
        _drop(user["id"])
