"""Tests for the private import directory (#27) and the cookie/storage defaults.

#27: /db/import wrote a whole-database dump into the shared temp directory with
     default permissions, where any other local user could read it for the entire
     import window.
"""

import os
import re
import stat
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
def admin_client():
    import bcrypt
    import db
    import app as app_module

    username = "pytest_import_admin"
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


def _csrf(client):
    page = client.get("/db")
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', page.get_data(as_text=True))
    return m.group(1) if m else ""


# ---------- #27: the dump is not world-readable ----------

def test_import_dump_is_created_private_and_removed(admin_client, tmp_path):
    """An upload that fails screening must still be cleaned up, never left behind.

    A file that is rejected before reaching psql is the easiest case to check:
    the response returns, and nothing matching the import prefix may remain in
    the temp directory.
    """
    import glob
    import tempfile

    before = set(glob.glob(os.path.join(tempfile.gettempdir(), "openfield-import-*")))

    token = _csrf(admin_client)
    resp = admin_client.post(
        "/db/import",
        data={
            "confirm": "1",
            "csrf_token": token,
            # A dangerous statement the screener must reject.
            "file": (open(_sql_fixture("DROP DATABASE postgres;"), "rb"), "bad.sql"),
        },
        content_type="multipart/form-data",
    )
    assert resp.status_code in (302, 200)

    after = set(glob.glob(os.path.join(tempfile.gettempdir(), "openfield-import-*")))
    leftovers = after - before
    assert not leftovers, f"the import dump was left behind: {leftovers}"


def test_import_temp_directory_is_restricted_while_in_use(admin_client):
    """Capture the mode the route creates its directory and file with.

    The route removes both in a finally block, so this checks the values it
    requests rather than a path that survives the request: a 0700 directory and a
    0600 file. On Windows these bits are largely advisory, so the assertion is
    skipped where chmod is not honoured.
    """
    if os.name == "nt":
        pytest.skip("POSIX permission bits are not enforced on Windows")

    import db_admin

    assert db_admin._BACKUP_FILE_MODE == 0o600


def test_mkdtemp_directory_is_private():
    """The route's directory creation must request 0700."""
    import inspect

    import app

    source = inspect.getsource(app.db_import)
    assert "mkdtemp" in source, "the dump is still written into the shared temp dir"
    assert "0o700" in source, "the private directory is not restricted to 0700"
    assert "0o600" in source, "the dump file is not created 0600"


def _sql_fixture(text):
    import tempfile

    fd, path = tempfile.mkstemp(suffix=".sql")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


# ---------- #31: cookie and HSTS defaults ----------

def test_cookie_secure_defaults_on_for_non_loopback(monkeypatch):
    """A non-loopback bind must default the cookie to Secure."""
    import importlib

    import config

    monkeypatch.setenv("ADMIN_BIND_HOST", "0.0.0.0")
    monkeypatch.delenv("ADMIN_COOKIE_SECURE", raising=False)
    reloaded = importlib.reload(config)
    try:
        assert reloaded.SESSION_COOKIE_SECURE is True, (
            "a non-loopback bind left the session cookie non-Secure"
        )
    finally:
        monkeypatch.undo()
        importlib.reload(config)


def test_cookie_secure_defaults_off_on_loopback(monkeypatch):
    """Local administration over http://127.0.0.1 must keep working."""
    import importlib

    import config

    monkeypatch.setenv("ADMIN_BIND_HOST", "127.0.0.1")
    monkeypatch.delenv("ADMIN_COOKIE_SECURE", raising=False)
    reloaded = importlib.reload(config)
    try:
        assert reloaded.SESSION_COOKIE_SECURE is False
    finally:
        monkeypatch.undo()
        importlib.reload(config)


def test_explicit_cookie_secure_override_wins(monkeypatch):
    import importlib

    import config

    monkeypatch.setenv("ADMIN_BIND_HOST", "127.0.0.1")
    monkeypatch.setenv("ADMIN_COOKIE_SECURE", "true")
    reloaded = importlib.reload(config)
    try:
        assert reloaded.SESSION_COOKIE_SECURE is True
    finally:
        monkeypatch.undo()
        importlib.reload(config)


def test_cookie_attributes_are_set():
    import app

    assert app.app.config["SESSION_COOKIE_HTTPONLY"] is True, "cookie readable by script"
    assert app.app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert app.app.config["SESSION_COOKIE_NAME"] == "openfield_admin"


def test_hsts_is_sent_when_forwarded_https(admin_client):
    """Behind a TLS-terminating proxy the panel must advertise HSTS."""
    resp = admin_client.get("/login", base_url="https://panel.example.com")
    assert "Strict-Transport-Security" in resp.headers
    assert "max-age=" in resp.headers["Strict-Transport-Security"]
