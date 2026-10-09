"""Tests for the moderation report queue (举报管理).

Covers the new /reports page, its filter handling, the resolve/reopen
workflow (including the interaction with the one-pending-report-per-target
unique index), the capability gate, and the N+1 guard on the polymorphic
target lookup.
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

        # to_regclass returns NULL (not an error) for a missing table, so the
        # value itself must be checked — a bare bool(row) would be True for any
        # row, including {"t": None}.
        row = db.fetch_one("SELECT to_regclass('public.reports') AS t")
        return bool(row and row["t"])
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _has_db(), reason="database not reachable or schema not migrated")


def _login(username, password="pytest-password-1", capabilities="*"):
    """Create a panel account with the given capabilities and sign in."""
    import bcrypt
    import db
    import app as app_module

    db.execute("DELETE FROM admin_accounts WHERE username = %s", (username,))
    db.execute(
        "INSERT INTO admin_accounts (username, password_hash, capabilities, can_verify) "
        "VALUES (%s, %s, %s, TRUE)",
        (username, bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode(), capabilities),
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
    return client


@pytest.fixture()
def admin_client():
    client = _login("pytest_reports_admin")
    yield client
    import db

    db.execute("DELETE FROM admin_accounts WHERE username = %s", ("pytest_reports_admin",))


@pytest.fixture()
def limited_client():
    """A signed-in panel account without reports.manage."""
    client = _login("pytest_reports_limited", capabilities="users.write")
    yield client
    import db

    db.execute("DELETE FROM admin_accounts WHERE username = %s", ("pytest_reports_limited",))


def _csrf(client, path="/reports"):
    page = client.get(path)
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', page.get_data(as_text=True))
    return m.group(1) if m else ""


def _make_user(prefix):
    import db

    name = f"pytest_rep_{prefix}"
    db.execute("DELETE FROM users WHERE username = %s", (name,))
    return db.fetch_one(
        "INSERT INTO users (username, nickname, email, role, password_hash, "
        "needs_registration, oauth2_provider, status, is_verified) "
        "VALUES (%s, %s, '', 'user', 'x', FALSE, '', 'active', FALSE) RETURNING id",
        (name, name),
    )["id"]


def _drop_user(user_id):
    import db

    db.execute("DELETE FROM users WHERE id = %s", (user_id,))


def _make_report(reporter_id, target_type="user", target_id=1, reason="pytest reason", status="pending"):
    import db

    return db.fetch_one(
        "INSERT INTO reports (reporter_id, target_type, target_id, reason, status) "
        "VALUES (%s, %s, %s, %s, %s) RETURNING id",
        (reporter_id, target_type, target_id, reason, status),
    )["id"]


def _drop_report(report_id):
    import db

    db.execute("DELETE FROM reports WHERE id = %s", (report_id,))


def _report_row(report_id):
    import db

    return db.fetch_one("SELECT * FROM reports WHERE id = %s", (report_id,))


# ---------- the page and its filters ----------

def test_reports_page_renders(admin_client):
    resp = admin_client.get("/reports")
    assert resp.status_code == 200, f"status {resp.status_code}"
    assert "举报管理" in resp.get_data(as_text=True)


def test_reports_unknown_filters_degrade_instead_of_erroring(admin_client):
    # A hand-edited URL must not 500 and must not silently drop the filter into
    # an unfiltered ("all") scan.
    resp = admin_client.get("/reports?status=nonsense&target_type=nonsense")
    assert resp.status_code == 200, f"status {resp.status_code}"


def test_reports_filter_helper_defaults_and_validation():
    import app as app_module

    with app_module.app.test_request_context("/reports"):
        where, params, status, target_type = app_module._reports_filter()
        assert status == "pending"
        assert target_type == "all"
        assert params == [app_module.REPORT_STATUSES[0]]
        assert "r.status = %s" in where
        assert "r.target_type" not in where

    with app_module.app.test_request_context("/reports?status=bogus&target_type=bogus"):
        where, params, status, target_type = app_module._reports_filter()
        assert status == "pending", "an unknown status must fall back to the default"
        assert target_type == "all"

    with app_module.app.test_request_context("/reports?status=all&target_type=message"):
        where, params, status, target_type = app_module._reports_filter()
        assert status == "all"
        assert target_type == "message"
        assert params == ["message"]
        assert "r.status" not in where
        assert "r.target_type = %s" in where


def test_reports_page_shows_a_pending_report(admin_client):
    reporter = _make_user("vis")
    report_id = _make_report(reporter, target_type="user", target_id=999999, reason="pytest visible reason")
    try:
        body = admin_client.get("/reports?status=pending").get_data(as_text=True)
        assert "pytest visible reason" in body, "the pending report is missing from the queue"
    finally:
        _drop_report(report_id)
        _drop_user(reporter)


# ---------- the resolve / reopen workflow ----------

def test_report_resolve_records_reviewer_note_and_audit(admin_client):
    import db

    reporter = _make_user("resolve")
    report_id = _make_report(reporter)
    try:
        resp = admin_client.post(
            f"/reports/{report_id}/resolve",
            data={
                "status": "reviewed",
                "review_note": "handled by pytest",
                "csrf_token": _csrf(admin_client),
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200, f"status {resp.status_code}"
        row = _report_row(report_id)
        assert row["status"] == "reviewed"
        assert row["reviewer_username"] == "pytest_reports_admin"
        assert row["review_note"] == "handled by pytest"
        assert row["reviewed_at"] is not None

        audit = db.fetch_one(
            "SELECT action, target_type, target_id FROM admin_audit_log "
            "WHERE action = 'report.resolve' AND target_id = %s ORDER BY id DESC LIMIT 1",
            (str(report_id),),
        )
        assert audit is not None, "resolving a report wrote no audit entry"
        assert audit["target_type"] == "report"
    finally:
        _drop_report(report_id)
        _drop_user(reporter)


def test_report_resolve_rejects_an_unknown_outcome(admin_client):
    reporter = _make_user("badoutcome")
    report_id = _make_report(reporter)
    try:
        resp = admin_client.post(
            f"/reports/{report_id}/resolve",
            data={"status": "whatever", "csrf_token": _csrf(admin_client)},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert _report_row(report_id)["status"] == "pending", "an invalid outcome changed the row"
    finally:
        _drop_report(report_id)
        _drop_user(reporter)


def test_report_reopen_returns_to_pending_then_refuses_on_clash(admin_client):
    reporter = _make_user("reopen")
    first = _make_report(reporter, reason="first")
    second = None
    try:
        token = _csrf(admin_client)
        # Resolve, then reopen: the report returns to the queue with its review
        # fields cleared.
        admin_client.post(
            f"/reports/{first}/resolve",
            data={"status": "dismissed", "csrf_token": token},
            follow_redirects=True,
        )
        assert _report_row(first)["status"] == "dismissed"

        admin_client.post(f"/reports/{first}/reopen", data={"csrf_token": token}, follow_redirects=True)
        row = _report_row(first)
        assert row["status"] == "pending", "reopen did not return the report to the queue"
        assert row["reviewed_at"] is None
        assert row["reviewer_username"] == ""

        # Free the slot again, then file a NEWER report on the same target. The
        # partial unique index now makes reopening the old one impossible, so it
        # must be refused cleanly instead of surfacing a 500.
        admin_client.post(
            f"/reports/{first}/resolve",
            data={"status": "reviewed", "csrf_token": token},
            follow_redirects=True,
        )
        second = _make_report(reporter, reason="second")
        resp = admin_client.post(
            f"/reports/{first}/reopen", data={"csrf_token": token}, follow_redirects=True
        )
        assert resp.status_code == 200
        assert _report_row(first)["status"] == "reviewed", "a clashing reopen was applied anyway"
        assert f"#{second}" in resp.get_data(as_text=True), "the clash was not explained to the operator"
    finally:
        _drop_report(first)
        if second is not None:
            _drop_report(second)
        _drop_user(reporter)


def test_report_resolve_unknown_id_is_404(admin_client):
    resp = admin_client.post(
        "/reports/999999999/resolve",
        data={"status": "reviewed", "csrf_token": _csrf(admin_client)},
    )
    assert resp.status_code == 404


# ---------- capability gate ----------

def test_reports_requires_the_reports_manage_capability(limited_client):
    assert limited_client.get("/reports").status_code == 403


def test_resolve_requires_the_reports_manage_capability(limited_client):
    reporter = _make_user("capgate")
    report_id = _make_report(reporter)
    try:
        # The CSRF token must come from a page this account may actually load:
        # /reports is itself denied, so its 403 page carries no form and the
        # request would be rejected as a CSRF failure before the capability
        # check ran, testing the wrong guard.
        resp = limited_client.post(
            f"/reports/{report_id}/resolve",
            data={"status": "reviewed", "csrf_token": _csrf(limited_client, "/")},
        )
        assert resp.status_code == 403
        assert _report_row(report_id)["status"] == "pending", "a denied caller changed the row"
    finally:
        _drop_report(report_id)
        _drop_user(reporter)


# ---------- the polymorphic target lookup is set-based ----------

def test_reports_page_does_not_scale_queries_per_row(admin_client):
    """The reported content is fetched in bulk, not one query per report."""
    import db
    import app as app_module

    reporter = _make_user("nplus1")
    target = _make_user("nplus1_target")
    post_id = db.fetch_one(
        "INSERT INTO posts (user_id, content) VALUES (%s, %s) RETURNING id",
        (target, "pytest reportable post"),
    )["id"]
    conv_id = db.fetch_one(
        "INSERT INTO conversations (type, title, owner_id) VALUES ('group', 'pytest report conv', %s) RETURNING id",
        (target,),
    )["id"]
    msg_id = db.fetch_one(
        "INSERT INTO messages (conversation_id, sender_id, content) VALUES (%s, %s, %s) RETURNING id",
        (conv_id, target, "pytest reportable message"),
    )["id"]
    report_ids = [
        _make_report(reporter, "user", target),
        _make_report(reporter, "post", post_id),
        _make_report(reporter, "message", msg_id),
    ]

    statements = []
    real_fetch_all = db.fetch_all
    real_fetch_one = db.fetch_one

    def counting_fetch_all(query, args=None):
        statements.append(query)
        return real_fetch_all(query, args)

    def counting_fetch_one(query, args=None):
        statements.append(query)
        return real_fetch_one(query, args)

    db.fetch_all = counting_fetch_all
    db.fetch_one = counting_fetch_one
    app_module.db.fetch_all = counting_fetch_all
    app_module.db.fetch_one = counting_fetch_one
    try:
        resp = admin_client.get("/reports?status=all")
        assert resp.status_code == 200
    finally:
        db.fetch_all = real_fetch_all
        db.fetch_one = real_fetch_one
        app_module.db.fetch_all = real_fetch_all
        app_module.db.fetch_one = real_fetch_one
        for rid in report_ids:
            _drop_report(rid)
        db.execute("DELETE FROM posts WHERE id = %s", (post_id,))
        db.execute("DELETE FROM conversations WHERE id = %s", (conv_id,))
        _drop_user(target)
        _drop_user(reporter)

    set_based = [q for q in statements if "id = ANY(" in q]
    assert set_based, "the target lookup is not set-based"
    per_row = [
        q for q in statements
        if re.search(r"FROM (posts|messages|users) WHERE id = %s", q)
    ]
    assert not per_row, f"a per-row target lookup is still issued ({len(per_row)} queries)"
    assert len(statements) < 12, f"rendering /reports issued {len(statements)} statements: {statements}"
