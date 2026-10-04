"""Tests for the login timing side channel and operator attribution (#33, #36).

#33: `admin and ... and bcrypt.checkpw(...)` short-circuited for a nonexistent
     username, so the expensive hash never ran. A failed login for a real account
     took ~100ms and one for an unknown account ~1ms, which is measurable over the
     network and turns the login form into a username oracle.
#36: wallet transactions attributed the operator by matching the panel account's
     username against the application users table, so a panel account whose name
     collides with (or is renamed to) an application user's name recorded the
     action against that unrelated person.
"""

import os
import re
import sys
import time

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


pytestmark = pytest.mark.skipif(not _has_db(), reason="database not reachable")


# ---------- #33: the dummy hash ----------

def test_dummy_hash_is_a_valid_bcrypt_hash():
    import app

    assert re.match(
        r"^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$", app._DUMMY_PASSWORD_HASH
    ), f"not a bcrypt hash: {app._DUMMY_PASSWORD_HASH!r}"


def test_dummy_hash_never_matches():
    """It must reject every password, so it cannot become a login bypass."""
    import bcrypt

    import app

    digest = app._DUMMY_PASSWORD_HASH.encode()
    for candidate in (b"", b"password", b"admin", b"1", b"\x00" * 32):
        assert not bcrypt.checkpw(candidate, digest), (
            f"{candidate!r} matched the dummy hash"
        )


def test_unknown_login_runs_a_real_hash():
    """The work factor for a nonexistent account must match a real one.

    Compares the time to reject an unknown username against the cost of one
    bcrypt comparison. If the handler short-circuits, the former is orders of
    magnitude smaller.
    """
    import bcrypt

    import app

    digest = app._DUMMY_PASSWORD_HASH.encode()

    start = time.perf_counter()
    bcrypt.checkpw(b"wrongpassword", digest)
    baseline = time.perf_counter() - start

    app.app.config.update(TESTING=True)
    client = app.app.test_client()
    page = client.get("/login")
    token = re.search(r'name="csrf_token"\s+value="([^"]+)"', page.get_data(as_text=True))

    start = time.perf_counter()
    client.post(
        "/login",
        data={
            "username": "definitely_no_such_admin_zzz",
            "password": "wrongpassword",
            "csrf_token": token.group(1) if token else "",
        },
    )
    unknown_cost = time.perf_counter() - start

    assert unknown_cost > baseline / 2, (
        f"an unknown username was rejected in {unknown_cost*1000:.1f}ms while a "
        f"single bcrypt check costs {baseline*1000:.1f}ms, so the username is "
        "leaked through response timing"
    )


def test_login_failure_message_is_identical_for_both_cases():
    """No response may distinguish 'no such user' from 'wrong password'."""
    import bcrypt
    import db

    import app as app_module

    username = "pytest_timing_admin"
    db.execute("DELETE FROM admin_accounts WHERE username = %s", (username,))
    db.execute(
        "INSERT INTO admin_accounts (username, password_hash) VALUES (%s, %s)",
        (username, bcrypt.hashpw(b"realpassword12", bcrypt.gensalt()).decode()),
    )
    app_module.app.config.update(TESTING=True)
    client = app_module.app.test_client()
    try:
        def attempt(name, password):
            page = client.get("/login")
            tok = re.search(
                r'name="csrf_token"\s+value="([^"]+)"', page.get_data(as_text=True)
            )
            resp = client.post(
                "/login",
                data={
                    "username": name,
                    "password": password,
                    "csrf_token": tok.group(1) if tok else "",
                },
                follow_redirects=True,
            )
            return resp.get_data(as_text=True)

        real_wrong = attempt(username, "wrongpassword")
        no_such = attempt("no_such_admin_zzz", "wrongpassword")
        assert "Invalid username or password" in real_wrong
        assert "Invalid username or password" in no_such
    finally:
        db.execute("DELETE FROM admin_accounts WHERE username = %s", (username,))


def test_login_source_always_hashes():
    """Guard against a future edit reintroducing the short circuit."""
    import inspect

    import app

    source = inspect.getsource(app.login)
    assert "_DUMMY_PASSWORD_HASH" in source, (
        "the login handler no longer uses the constant-cost dummy hash"
    )


# ---------- #36: operator attribution ----------

def _victim(name="pytest_attr_victim"):
    import db

    db.execute("DELETE FROM users WHERE username = %s", (name,))
    return db.fetch_one(
        "INSERT INTO users (username, nickname, email, role, password_hash, "
        "needs_registration, oauth2_provider, status) "
        "VALUES (%s, %s, '', 'user', 'x', FALSE, '', 'active') RETURNING id",
        (name, name),
    )


def test_wallet_operator_is_recorded_by_name_not_by_user_id_lookup():
    """A panel account name must never resolve to an application user id.

    An admin panel account named the same as an application user previously had
    its actions attributed to that user, because the code looked the operator up
    in the users table by username. The recorded operator must be the panel
    account's own name, with no user id claimed on its behalf.
    """
    import bcrypt
    import db

    import app as app_module

    # A panel account whose username collides with a real application user.
    collide = "pytest_attr_collide"
    victim = _victim(collide)
    db.execute("DELETE FROM admin_accounts WHERE username = %s", (collide,))
    db.execute(
        "INSERT INTO admin_accounts (username, password_hash, capabilities, can_verify) "
        "VALUES (%s, %s, '*', TRUE)",
        (collide, bcrypt.hashpw(b"pytest-password-1", bcrypt.gensalt()).decode()),
    )

    app_module.app.config.update(TESTING=True)
    client = app_module.app.test_client()
    try:
        page = client.get("/login")
        tok = re.search(
            r'name="csrf_token"\s+value="([^"]+)"', page.get_data(as_text=True)
        )
        client.post(
            "/login",
            data={
                "username": collide,
                "password": "pytest-password-1",
                "csrf_token": tok.group(1) if tok else "",
            },
        )

        target = _victim("pytest_attr_target")
        try:
            page = client.get("/users")
            tok = re.search(
                r'name="csrf_token"\s+value="([^"]+)"', page.get_data(as_text=True)
            )
            client.post(
                f"/users/{target['id']}/wallet",
                data={
                    "amount": "1",
                    "description": "attribution test",
                    "csrf_token": tok.group(1) if tok else "",
                },
            )
            row = db.fetch_one(
                "SELECT operator_id, operator_username FROM wallet_transactions "
                "WHERE user_id = %s ORDER BY id DESC LIMIT 1",
                (target["id"],),
            )
            assert row is not None, "no wallet transaction was written"
            # The operator is the PANEL account, so it must not be recorded as
            # the application user who happens to share the name.
            assert row["operator_id"] is None or row["operator_id"] != victim["id"], (
                "the panel operator was attributed to an unrelated application user"
            )
            assert row["operator_username"] == collide
        finally:
            db.execute("DELETE FROM wallet_transactions WHERE user_id = %s", (target["id"],))
            db.execute("DELETE FROM users WHERE id = %s", (target["id"],))
    finally:
        db.execute("DELETE FROM admin_accounts WHERE username = %s", (collide,))
        db.execute("DELETE FROM users WHERE id = %s", (victim["id"],))
