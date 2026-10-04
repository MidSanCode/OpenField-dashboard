"""Tests for timezone-correct expiry handling (#29).

Temp bans and membership expiry were computed from naive local time and written
into TIMESTAMPTZ columns. PostgreSQL interprets a naive value in the server's
timezone, so on a host whose local time is ahead of the database's a short ban
was stored already expired and had no effect — the panel reported success while
the user stayed active.
"""

import os
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


def test_utcnow_is_timezone_aware():
    import app

    now = app._utcnow()
    assert now.tzinfo is not None, "_utcnow returned a naive datetime"
    assert now.utcoffset() is not None


def test_utcnow_is_close_to_database_now():
    """The panel's clock and the database's must agree, in absolute terms."""
    import app
    import db

    db_now = db.fetch_one("SELECT NOW() AS n")["n"]
    delta = abs((app._utcnow() - db_now).total_seconds())
    assert delta < 60, (
        f"panel clock differs from the database by {delta:.0f}s; naive local time "
        "was likely reintroduced"
    )


def test_member_status_handles_aware_and_naive_expiry():
    """The comparison must not raise on either kind of value from the driver."""
    import datetime

    import app

    aware_future = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
    naive_future = datetime.datetime.now() + datetime.timedelta(days=1)

    active, name = app.member_status(3, aware_future)
    assert active is True and name

    active, name = app.member_status(3, naive_future)
    assert active is True and name

    aware_past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
    active, _ = app.member_status(3, aware_past)
    assert active is False


def test_member_status_without_expiry_is_inactive():
    import app

    assert app.member_status(3, None) == (False, app.MEMBER_TIER_NAMES.get(3))


# ---------- end to end: the stored value is in the future ----------

@pytest.fixture()
def admin_client():
    import bcrypt
    import re

    import db
    import app as app_module

    username = "pytest_tz_admin"
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


def _victim():
    import db

    username = "pytest_tz_victim"
    db.execute("DELETE FROM users WHERE username = %s", (username,))
    return db.fetch_one(
        "INSERT INTO users (username, nickname, email, role, password_hash, "
        "needs_registration, oauth2_provider, status) "
        "VALUES (%s, %s, '', 'user', 'x', FALSE, '', 'active') RETURNING id",
        (username, username),
    )


def test_membership_expiry_is_stored_in_the_future(admin_client):
    import re

    import db

    user = _victim()
    try:
        page = admin_client.get("/users")
        tok = re.search(r'name="csrf_token"\s+value="([^"]+)"', page.get_data(as_text=True))
        resp = admin_client.post(
            f"/users/{user['id']}/membership",
            data={"level": "1", "days": "1", "csrf_token": tok.group(1) if tok else ""},
        )
        assert resp.status_code in (302, 200)

        row = db.fetch_one(
            "SELECT member_level, member_expires_at, "
            "       member_expires_at > NOW() AS future "
            "FROM users WHERE id = %s",
            (user["id"],),
        )
        assert row["member_level"] == 1
        assert row["member_expires_at"] is not None
        assert row["future"] is True, "a 1-day membership was stored already expired"
    finally:
        db.execute("DELETE FROM users WHERE id = %s", (user["id"],))
