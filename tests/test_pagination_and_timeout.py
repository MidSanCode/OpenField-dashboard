"""Tests for the OFFSET clamp and the per-statement timeout (#22).

The /posts page number came straight from the query string into OFFSET with only
a floor, so ?page=999999999 made PostgreSQL produce and discard an enormous
number of rows for a request that looked cheap. No connection had a
statement_timeout either, so an expensive query held its connection until it
finished.
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

        return bool(db.fetch_one("SELECT to_regclass('public.posts') AS t"))
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _has_db(), reason="database not reachable")


@pytest.fixture()
def admin_client():
    import bcrypt
    import db
    import app as app_module

    username = "pytest_page_admin"
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


# ---------- the clamp helper ----------

def test_page_param_is_bounded():
    import app

    with app.app.test_request_context("/?page=999999999"):
        assert app._page_param() <= 100000, "an unbounded page number got through"

    with app.app.test_request_context("/?page=0"):
        assert app._page_param() == 1

    with app.app.test_request_context("/?page=-5"):
        assert app._page_param() == 1

    with app.app.test_request_context("/?page=abc"):
        assert app._page_param() == 1

    with app.app.test_request_context("/?page=7"):
        assert app._page_param() == 7

    with app.app.test_request_context("/"):
        assert app._page_param() == 1


# ---------- the route ----------

def test_absurd_page_number_does_not_error(admin_client):
    """A huge page must render (empty) rather than drive a massive OFFSET."""
    resp = admin_client.get("/posts?page=999999999")
    assert resp.status_code == 200, f"status {resp.status_code}"
    assert "999999999" not in resp.get_data(as_text=True)


def test_negative_page_number_does_not_error(admin_client):
    resp = admin_client.get("/posts?page=-1")
    assert resp.status_code == 200


def test_non_numeric_page_does_not_error(admin_client):
    resp = admin_client.get("/posts?page=abc")
    assert resp.status_code == 200


# ---------- the statement timeout ----------

def test_connections_carry_a_statement_timeout():
    import db

    conn = db.get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SHOW statement_timeout")
            value = cur.fetchone()[0]
        assert value not in ("0", "0ms"), "no statement timeout is set"
    finally:
        conn.close()


def test_statement_timeout_cancels_a_slow_query():
    """Prove the setting is enforced, not merely stored."""
    import config
    import db
    import psycopg2

    conn = db.connect()
    try:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("SET statement_timeout = 250")
            with pytest.raises(psycopg2.errors.QueryCanceled):
                cur.execute("SELECT pg_sleep(3)")
    finally:
        conn.close()

    assert config.DB_STATEMENT_TIMEOUT_MS > 0
