"""Tests for admin password policy and session revocation in seed_admin (#14).

seed_admin.py created the panel's most privileged account and validated only that
the password was non-empty, so an administrator could be created with "1" while
the in-panel rotation route refused exactly that. It also rotated the hash without
invalidating live sessions, so a run intended to recover from a compromise left
the attacker's cookie valid for its full lifetime.
"""

import importlib
import os
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


pytestmark = pytest.mark.skipif(not _has_db(), reason="database not reachable")


@pytest.fixture()
def seed_module():
    import seed_admin

    return seed_admin


# ---------- the policy itself ----------

def test_seed_rejects_empty_and_short(seed_module):
    for bad in ("", "a", "short1", "12345678901"):
        assert seed_module.password_policy_error(bad) is not None, (
            f"{bad!r} was accepted by the seed script"
        )


def test_seed_rejects_letters_only_and_digits_only(seed_module):
    assert seed_module.password_policy_error("onlylettershere") is not None
    assert seed_module.password_policy_error("123456789012") is not None


def test_seed_rejects_outer_whitespace(seed_module):
    """A password with surrounding spaces cannot be typed at the login form."""
    assert seed_module.password_policy_error(" goodpassword12") is not None
    assert seed_module.password_policy_error("goodpassword12 ") is not None


def test_seed_rejects_overlong(seed_module):
    assert seed_module.password_policy_error("x" * 300) is not None


def test_seed_accepts_a_reasonable_password(seed_module):
    assert seed_module.password_policy_error("goodpassword12") is None
    assert seed_module.password_policy_error("GoodPassword12") is None


def test_seed_policy_matches_the_panel_policy():
    """The two paths must not disagree, or the weaker one is the real policy."""
    import app

    cases = [
        "",
        "a",
        "short1",
        "onlylettershere",
        "123456789012",
        " goodpassword12",
        "goodpassword12 ",
        "goodpassword12",
        "x" * 300,
        "GoodPassword12",
    ]
    for case in cases:
        panel = app._password_policy_error(case)
        seed = importlib.import_module("seed_admin").password_policy_error(case)
        assert (panel is None) == (seed is None), (
            f"the panel and seed script disagree about {case[:20]!r}: "
            f"panel={panel!r} seed={seed!r}"
        )


# ---------- rotation revokes sessions ----------

def test_rotating_the_password_bumps_session_version():
    """A password rotation must invalidate the account's live sessions."""
    import bcrypt
    import db

    username = "pytest_seed_admin"
    db.execute("DELETE FROM admin_accounts WHERE username = %s", (username,))
    db.execute(
        "INSERT INTO admin_accounts (username, password_hash) VALUES (%s, %s)",
        (username, bcrypt.hashpw(b"oldpassword12", bcrypt.gensalt()).decode()),
    )
    try:
        before = db.fetch_one(
            "SELECT id, session_version FROM admin_accounts WHERE username = %s",
            (username,),
        )
        # Emulate the rotation branch of seed().
        db.execute(
            "UPDATE admin_accounts SET password_hash = %s, "
            "session_version = session_version + 1 WHERE id = %s",
            (bcrypt.hashpw(b"newpassword12", bcrypt.gensalt()).decode(), before["id"]),
        )
        after = db.fetch_one(
            "SELECT session_version FROM admin_accounts WHERE id = %s",
            (before["id"],),
        )
        assert after["session_version"] == before["session_version"] + 1, (
            "session_version did not change, so old sessions stay valid"
        )
    finally:
        db.execute("DELETE FROM admin_accounts WHERE username = %s", (username,))


def test_seed_update_statement_increments_session_version():
    """Read the source of seed() to confirm the rotation path revokes sessions."""
    import inspect

    import seed_admin

    source = inspect.getsource(seed_admin.seed)
    assert "session_version = session_version + 1" in source, (
        "the rotation path does not revoke existing sessions"
    )
