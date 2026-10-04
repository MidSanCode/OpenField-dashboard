"""Tests for the response-hardening headers and body limit (#25 and #24).

#25: the panel sent no CSP, X-Frame-Options or frame-ancestors, so any escaping
    gap in a page that renders user-controlled values became script execution in
    an origin holding a CSRF token, and the panel could be framed and
    clickjacked.
#24: Flask buffered the whole request body before any handler ran, and no global
    ceiling was configured, so a single POST could be arbitrarily large.
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

        return bool(db.fetch_one("SELECT to_regclass('public.admin_accounts') AS t"))
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _has_db(), reason="database not reachable")


@pytest.fixture()
def client():
    import app as app_module

    app_module.app.config.update(TESTING=True)
    return app_module.app.test_client()


def _authenticated():
    import bcrypt
    import db
    import app as app_module

    username = "pytest_headers_admin"
    password = "pytest-password-1"
    db.execute("DELETE FROM admin_accounts WHERE username = %s", (username,))
    db.execute(
        "INSERT INTO admin_accounts (username, password_hash, capabilities, can_verify) "
        "VALUES (%s, %s, '*', TRUE)",
        (username, bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()),
    )
    app_module.app.config.update(TESTING=True)
    c = app_module.app.test_client()
    page = c.get("/login")
    tok = re.search(r'name="csrf_token"\s+value="([^"]+)"', page.get_data(as_text=True))
    c.post(
        "/login",
        data={
            "username": username,
            "password": password,
            "csrf_token": tok.group(1) if tok else "",
        },
    )
    return c, username


# ---------- #25: security headers ----------

def test_login_page_carries_security_headers(client):
    resp = client.get("/login")
    assert resp.status_code == 200

    csp = resp.headers.get("Content-Security-Policy")
    assert csp, "no Content-Security-Policy header"
    assert "frame-ancestors 'none'" in csp, "the panel can be framed"
    assert "object-src 'none'" in csp
    assert "base-uri 'self'" in csp
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("Referrer-Policy") == "no-referrer"


def test_csp_does_not_allow_inline_script(client):
    """Allowing inline script would defeat the point of the policy."""
    csp = client.get("/login").headers.get("Content-Security-Policy", "")
    script_src = next(
        (d for d in csp.split(";") if d.strip().startswith("script-src")), ""
    )
    assert "'unsafe-inline'" not in script_src, script_src
    assert "'unsafe-eval'" not in script_src, script_src
    assert script_src.strip() == "script-src 'self'", script_src


def test_hsts_only_over_a_secure_connection(client):
    """Advertising HSTS over plain HTTP is meaningless; 127.0.0.1 is cleartext."""
    plain = client.get("/login", base_url="http://127.0.0.1:1343")
    assert "Strict-Transport-Security" not in plain.headers

    proxied = client.get(
        "/login",
        base_url="https://127.0.0.1:1343",
    )
    assert "Strict-Transport-Security" in proxied.headers


def test_headers_present_on_authenticated_pages():
    client, username = _authenticated()
    import db

    try:
        resp = client.get("/")
        assert resp.status_code == 200
        assert resp.headers.get("Content-Security-Policy")
        assert resp.headers.get("X-Frame-Options") == "DENY"
    finally:
        db.execute("DELETE FROM admin_accounts WHERE username = %s", (username,))


def test_templates_contain_no_inline_script():
    """A CSP without 'unsafe-inline' only works if no template needs it."""
    templates_dir = os.path.join(REPO_ROOT, "templates")
    offenders = []
    for name in sorted(os.listdir(templates_dir)):
        if not name.endswith(".html"):
            continue
        with open(os.path.join(templates_dir, name), encoding="utf-8") as fh:
            body = fh.read()
        # An opening <script> tag with no src attribute is an inline block.
        for m in re.finditer(r"<script(?![^>]*\bsrc=)[^>]*>", body):
            offenders.append(f"{name}: {m.group(0)}")
    assert not offenders, "inline script blocks remain: " + "; ".join(offenders)


def test_templates_contain_no_inline_event_handlers():
    templates_dir = os.path.join(REPO_ROOT, "templates")
    offenders = []
    for name in sorted(os.listdir(templates_dir)):
        if not name.endswith(".html"):
            continue
        with open(os.path.join(templates_dir, name), encoding="utf-8") as fh:
            body = fh.read()
        for m in re.finditer(
            r"<[^>]*\son(click|submit|change|load|error|input|focus|blur)\s*=", body
        ):
            offenders.append(f"{name}: {m.group(0)[:60]}")
    assert not offenders, "inline event handlers remain: " + "; ".join(offenders)


# ---------- #24: request body limit ----------

def test_max_content_length_is_configured():
    import app
    import config

    assert app.app.config["MAX_CONTENT_LENGTH"] == config.MAX_CONTENT_LENGTH
    assert config.MAX_CONTENT_LENGTH > 0, "no ceiling on buffered request bodies"


def test_oversized_body_is_rejected_with_413(client):
    import app

    original = app.app.config["MAX_CONTENT_LENGTH"]
    app.app.config["MAX_CONTENT_LENGTH"] = 1024  # 1 KB, for the test
    try:
        resp = client.post(
            "/login",
            data={"username": "x" * 5000, "password": "y" * 5000},
        )
        assert resp.status_code == 413, (
            f"an oversized body was accepted (status {resp.status_code})"
        )
        body = resp.get_data(as_text=True)
        assert "过大" in body or "413" in body
    finally:
        app.app.config["MAX_CONTENT_LENGTH"] = original
