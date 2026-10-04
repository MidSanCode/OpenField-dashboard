"""Tests for the destructive-route fixes in dashboard issues #4, #5 and #7.

#4: /users/:id/punish claimed to apply its side effects in the same transaction
    as the history row, but every db.execute() opened its own autocommit
    connection, so the record and its effect could diverge.
#5: /groups/:id/permissions ran DELETE then a loop of INSERTs with no
    transaction, and had none of the default-group protection the neighbouring
    routes have.
#7: /users/:id/delete hard-deleted the row, bypassing the server's soft-delete
    lifecycle, behind a guard whose body was literally `pass`.
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
    """An authenticated panel client with full capabilities."""
    import bcrypt
    import db
    import app as app_module

    username = "pytest_txn_admin"
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
    token = re.search(
        r'name="csrf_token"\s+value="([^"]+)"', page.get_data(as_text=True)
    )
    client.post(
        "/login",
        data={
            "username": username,
            "password": password,
            "csrf_token": token.group(1) if token else "",
        },
    )

    yield client

    db.execute("DELETE FROM admin_accounts WHERE username = %s", (username,))


def _csrf(client, path):
    page = client.get(path)
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', page.get_data(as_text=True))
    return m.group(1) if m else ""


@pytest.fixture()
def victim_user():
    import db

    username = "pytest_txn_victim"
    db.execute("DELETE FROM user_punishments WHERE user_id IN "
               "(SELECT id FROM users WHERE username = %s)", (username,))
    db.execute("DELETE FROM users WHERE username = %s", (username,))
    row = db.fetch_one(
        "INSERT INTO users (username, nickname, email, role, password_hash, "
        "needs_registration, oauth2_provider, status) "
        "VALUES (%s, %s, '', 'user', 'x', FALSE, '', 'active') RETURNING id",
        (username, username),
    )
    yield row
    db.execute("DELETE FROM user_punishments WHERE user_id = %s", (row["id"],))
    db.execute("DELETE FROM refresh_tokens WHERE user_id = %s", (row["id"],))
    db.execute("DELETE FROM users WHERE id = %s", (row["id"],))


# ---------- #4: punishment atomicity ----------

def test_temp_ban_is_recorded_and_applied(admin_client, victim_user):
    """Both halves of a temp_ban must be visible after the request."""
    import db

    token = _csrf(admin_client, "/users")
    resp = admin_client.post(
        f"/users/{victim_user['id']}/punish",
        data={
            "type": "temp_ban",
            "reason": "pytest",
            "hours": "2",
            "csrf_token": token,
        },
    )
    assert resp.status_code in (302, 200)

    record = db.fetch_one(
        "SELECT type, expires_at FROM user_punishments WHERE user_id = %s "
        "ORDER BY id DESC LIMIT 1",
        (victim_user["id"],),
    )
    assert record is not None, "the punishment history row was not written"
    assert record["type"] == "temp_ban"

    user = db.fetch_one(
        "SELECT status, banned_until FROM users WHERE id = %s", (victim_user["id"],)
    )
    assert user["status"] == "banned", "the ban side effect was not applied"
    assert user["banned_until"] is not None


def test_ban_records_the_acting_administrator(admin_client, victim_user):
    """Punishments used to be recorded with a NULL operator and no name.

    operator_id is a FK to users(id) so it cannot hold an admin account id; the
    acting administrator is recorded in operator_username instead.
    """
    import db

    token = _csrf(admin_client, "/users")
    admin_client.post(
        f"/users/{victim_user['id']}/punish",
        data={"type": "warning", "reason": "pytest", "csrf_token": token},
    )
    record = db.fetch_one(
        "SELECT operator_username FROM user_punishments WHERE user_id = %s "
        "ORDER BY id DESC LIMIT 1",
        (victim_user["id"],),
    )
    assert record is not None
    assert record["operator_username"] == "pytest_txn_admin", (
        "the punishment is not attributed to the acting administrator"
    )


# ---------- #29: timezone-correct expiry ----------

def test_short_temp_ban_is_not_already_expired(admin_client, victim_user):
    """A one-hour ban must be in the FUTURE, not offset by the host timezone.

    This is the #29 regression: a naive local datetime written into a
    timestamptz column was reinterpreted in the database's timezone, so on a host
    ahead of the database a short ban was stored already expired and had no
    effect.
    """
    import db

    token = _csrf(admin_client, "/users")
    admin_client.post(
        f"/users/{victim_user['id']}/punish",
        data={"type": "temp_ban", "reason": "pytest", "hours": "1", "csrf_token": token},
    )
    row = db.fetch_one(
        "SELECT banned_until > NOW() AS future, "
        "       banned_until < NOW() + interval '2 hours' AS roughly_one_hour "
        "FROM users WHERE id = %s",
        (victim_user["id"],),
    )
    assert row["future"], "a 1-hour ban was stored already expired"
    assert row["roughly_one_hour"], "the ban expiry is not in the expected window"


# ---------- #7: soft delete ----------

def test_delete_soft_deletes_instead_of_removing_the_row(admin_client, victim_user):
    import db

    token = _csrf(admin_client, "/users")
    resp = admin_client.post(
        f"/users/{victim_user['id']}/delete", data={"csrf_token": token}
    )
    assert resp.status_code in (302, 200)

    row = db.fetch_one(
        "SELECT deleted_at FROM users WHERE id = %s", (victim_user["id"],)
    )
    assert row is not None, "the user row was hard-deleted instead of soft-deleted"
    assert row["deleted_at"] is not None, "deleted_at was not set"


def test_delete_revokes_refresh_tokens(admin_client, victim_user):
    import db

    db.execute(
        "INSERT INTO refresh_tokens (user_id, token, expires_at, device_label) "
        "VALUES (%s, %s, NOW() + interval '30 days', 'pytest')",
        (victim_user["id"], f"pytest-token-{victim_user['id']}"),
    )

    token = _csrf(admin_client, "/users")
    admin_client.post(f"/users/{victim_user['id']}/delete", data={"csrf_token": token})

    remaining = db.fetch_one(
        "SELECT COUNT(*) AS n FROM refresh_tokens WHERE user_id = %s",
        (victim_user["id"],),
    )
    assert remaining["n"] == 0, "refresh tokens survived the account deletion"


def test_second_delete_is_a_no_op(admin_client, victim_user):
    """Deleting twice must not move the grace-period clock."""
    import db

    token = _csrf(admin_client, "/users")
    admin_client.post(f"/users/{victim_user['id']}/delete", data={"csrf_token": token})
    first = db.fetch_one(
        "SELECT deleted_at FROM users WHERE id = %s", (victim_user["id"],)
    )["deleted_at"]

    token = _csrf(admin_client, "/users")
    admin_client.post(f"/users/{victim_user['id']}/delete", data={"csrf_token": token})
    second = db.fetch_one(
        "SELECT deleted_at FROM users WHERE id = %s", (victim_user["id"],)
    )["deleted_at"]

    assert first == second, "a repeat delete reset the deletion timestamp"


# ---------- #5: default group protection ----------

def test_default_group_permissions_cannot_be_emptied(admin_client):
    """The default group applies to everyone; clearing it is global revocation."""
    import db

    group = db.fetch_one("SELECT id, name FROM groups WHERE is_default = TRUE LIMIT 1")
    if group is None:
        pytest.skip("no default group in this database")

    before = db.fetch_all(
        "SELECT permission_key FROM group_permissions WHERE group_id = %s",
        (group["id"],),
    )

    token = _csrf(admin_client, "/groups")
    resp = admin_client.post(
        f"/groups/{group['id']}/permissions",
        data={"csrf_token": token},  # deliberately no permission_keys
    )
    assert resp.status_code in (302, 200)

    after = db.fetch_all(
        "SELECT permission_key FROM group_permissions WHERE group_id = %s",
        (group["id"],),
    )
    assert len(after) == len(before), "the default group's permissions were emptied"
