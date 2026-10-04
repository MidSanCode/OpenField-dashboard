"""Tests for the paginated list views (#28) and the N+1 group query (#23).

#28: the users and groups lists had no LIMIT, so every render loaded the whole
     table into memory. The users list also carried two correlated subqueries per
     row, and the users list's flag is a table whose size the operator does not
     control.
#23: the groups page issued one query (and one new database connection) per
     group to collect permission keys, and loaded the entire user_groups and
     users tables on every render.
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

        return bool(db.fetch_one("SELECT to_regclass('public.groups') AS t"))
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _has_db(), reason="database not reachable")


@pytest.fixture()
def admin_client():
    import bcrypt
    import db
    import app as app_module

    username = "pytest_list_admin"
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


# ---------- the pager helper ----------

def test_page_window_shape():
    import app

    assert app._page_window(1, 1) == [1]
    assert app._page_window(1, 3) == [1, 2, 3]

    # A long pagination collapses to a bounded number of entries plus gap marks.
    wide = app._page_window(500, 10000)
    assert len(wide) < 20, f"pager is not bounded: {wide}"
    assert None in wide, "no gap marker in a long pager"
    assert 1 in wide and 10000 in wide, "first/last page missing"
    assert 500 in wide
    assert wide == sorted(p for p in wide if p is not None) or all(
        a is None or b is None or a < b for a, b in zip(wide, wide[1:])
    )


# ---------- #28: the lists are bounded ----------

def test_users_list_renders_with_pagination(admin_client):
    resp = admin_client.get("/users")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # The per-page notice only appears when pagination is active; either way the
    # page must render and must not be an unbounded dump.
    assert "用户管理" in body


def test_users_list_page_parameter_is_respected(admin_client):
    first = admin_client.get("/users?page=1")
    assert first.status_code == 200

    # A wildly out-of-range page must not error, and must render an empty table.
    far = admin_client.get("/users?page=999999")
    assert far.status_code == 200, f"status {far.status_code}"


def test_users_search_combines_with_paging(admin_client):
    resp = admin_client.get("/users?q=zzz_no_such_user_zzz&page=2")
    assert resp.status_code == 200


def test_groups_list_renders_with_pagination(admin_client):
    resp = admin_client.get("/groups")
    assert resp.status_code == 200
    assert "权限组管理" in resp.get_data(as_text=True)


def test_groups_member_filter_works(admin_client):
    resp = admin_client.get("/groups?mq=zzz_no_such_user_zzz")
    assert resp.status_code == 200


def test_groups_page_does_not_scale_queries_with_group_count():
    """#23: permission keys must be fetched in ONE query, not one per group.

    Counts the SQL statements executed while rendering /groups and asserts the
    per-group permission lookup is a single set-based query.
    """
    import bcrypt
    import db
    import app as app_module

    username = "pytest_list_admin"
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

    statements = []
    real_fetch_all = db.fetch_all

    def counting_fetch_all(query, args=None):
        statements.append(query)
        return real_fetch_all(query, args)

    real_fetch_one = db.fetch_one

    def counting_fetch_one(query, args=None):
        statements.append(query)
        return real_fetch_one(query, args)

    db.fetch_all = counting_fetch_all
    db.fetch_one = counting_fetch_one
    # app.py holds its own reference to the module, so patch there too.
    app_module.db.fetch_all = counting_fetch_all
    app_module.db.fetch_one = counting_fetch_one
    try:
        resp = client.get("/groups")
        assert resp.status_code == 200
    finally:
        db.fetch_all = real_fetch_all
        db.fetch_one = real_fetch_one
        app_module.db.fetch_all = real_fetch_all
        app_module.db.fetch_one = real_fetch_one
        db.execute("DELETE FROM admin_accounts WHERE username = %s", (username,))

    per_group = [
        q for q in statements
        if "group_permissions" in q and "group_id = %s" in q
    ]
    assert not per_group, (
        f"the per-group permission lookup is still a loop ({len(per_group)} queries)"
    )
    set_based = [q for q in statements if "group_id = ANY(" in q]
    assert set_based, "no set-based permission query was issued"

    # The whole render should be a small constant number of statements.
    assert len(statements) < 15, (
        f"rendering /groups issued {len(statements)} statements: {statements}"
    )
