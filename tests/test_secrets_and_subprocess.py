"""Tests for secret-key handling, subprocess hygiene and dependency pinning.

#38: _load_or_create_secret_key caught FileExistsError around os.open, which
     never raises it there; the real failure (PermissionError, an OSError) escaped
     and the panel could not start. The handler was dead code.
#39: backup/import stderr was rendered into the browser, exposing filesystem
     layout, host, port, role and the SQL with its literal values.
#40: subprocesses inherited the panel's full environment, including the key that
     signs the session cookie and the database password.
#41: requirements were lower-bound only and reinstalled from the network on every
     start.
#42: the connection error banner rendered the raw driver message on the login
     page, to unauthenticated visitors.
#43: ADMIN_SECRET_KEY was accepted without any validation.

Secret-key behaviour is exercised in a SUBPROCESS. Reading it requires importing
config, and importing config has side effects (it may create .secret_key and it
validates ADMIN_SECRET_KEY at import time), so reloading it inside the test
process leaves other modules holding a stale reference to the old module object.
A subprocess gets a clean import and cannot leak state into the suite.
"""

import json
import os
import re
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


def _run_in_subprocess(code, env_extra=None):
    """Run a snippet with the panel importable, returning its parsed stdout."""
    env = dict(os.environ)
    env.pop("ADMIN_SECRET_KEY", None)
    env["PYTHONIOENCODING"] = "utf-8"
    if env_extra:
        env.update(env_extra)
    # PYTHONPATH so the child can import the panel modules without a chdir.
    env["PYTHONPATH"] = REPO_ROOT + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        timeout=120,
    )
    if proc.returncode != 0:
        raise AssertionError(
            f"subprocess failed ({proc.returncode})\n"
            f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
        )
    return proc.stdout.strip()


# ---------- #43: secret key validation ----------

def test_weak_secret_keys_are_rejected():
    import config

    weak = [
        "abc",
        "short",
        "changeme",
        "change-me",
        "admin-panel-secret-key-change-me",
        "x" * 40,                      # too few distinct characters
        "a" * 64,                      # same
        " " + "Kf9xQ2mZ7pL4wR8tY1uI6oP3aS0dF5gH",  # outer whitespace
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ]
    for value in weak:
        assert config.secret_key_problem(value) is not None, (
            f"{value[:40]!r} was accepted as a session signing key"
        )


def test_strong_secret_key_is_accepted():
    import config

    assert config.secret_key_problem("Kf9xQ2mZ7pL4wR8tY1uI6oP3aS0dF5gH") is None


def test_rejected_env_secret_key_stops_startup():
    """An explicitly set but weak key must be a startup error, not a warning.

    Checked in a subprocess so the import-time SystemExit cannot disturb the
    running test suite.
    """
    code = "import config; print('STARTED')"
    with pytest.raises(AssertionError) as excinfo:
        _run_in_subprocess(code, {"ADMIN_SECRET_KEY": "weak"})
    assert "SystemExit" in str(excinfo.value) or "1" in str(excinfo.value)

    # And a strong key must be accepted.
    out = _run_in_subprocess(
        code, {"ADMIN_SECRET_KEY": "Kf9xQ2mZ7pL4wR8tY1uI6oP3aS0dF5gH"}
    )
    assert out == "STARTED"


def test_valid_env_key_is_used_verbatim():
    code = (
        "import config; print(config.SECRET_KEY)"
    )
    key = "Kf9xQ2mZ7pL4wR8tY1uI6oP3aS0dF5gH"
    assert _run_in_subprocess(code, {"ADMIN_SECRET_KEY": key}) == key


# ---------- #38: unwritable key file ----------

def test_key_file_handler_catches_oserror_not_just_fileexists():
    import inspect

    import config

    source = inspect.getsource(config._load_or_create_secret_key)
    assert "except OSError" in source, (
        "a PermissionError from os.open still escapes and the panel cannot start"
    )
    assert "except FileExistsError" in source, "the create race is no longer handled"


def test_panel_starts_when_the_key_file_cannot_be_written(tmp_path):
    """A read-only key location must fall back to an ephemeral key, not crash.

    Reproduces the real failure: no ADMIN_SECRET_KEY, and os.open on the key path
    raising PermissionError. The import must still succeed and the key must be
    usable.
    """
    code = """
import os, sys
_real_open = os.open
def deny(path, flags, *a, **kw):
    if str(path).endswith('.secret_key'):
        raise PermissionError(13, 'Permission denied')
    return _real_open(path, flags, *a, **kw)
os.open = deny
_real_io = open
def deny_read(path, *a, **kw):
    if str(path).endswith('.secret_key'):
        raise FileNotFoundError(path)
    return _real_io(path, *a, **kw)
import builtins
builtins.open = deny_read
import warnings
with warnings.catch_warnings(record=True) as caught:
    warnings.simplefilter('always')
    import config
    print(json.dumps({'len': len(config.SECRET_KEY), 'warned': len(caught) > 0}))
""".replace("print(json.dumps", "import json; print(json.dumps")
    out = _run_in_subprocess(code)
    result = json.loads(out.splitlines()[-1])
    assert result["len"] >= 32, "no usable key was produced"
    assert result["warned"] is True, "the fallback was silent"


# ---------- #39: stderr sanitising ----------

@pytest.mark.parametrize(
    "raw, leaks",
    [
        (
            'psql: error: connection to server at "10.0.0.5", port 5432 failed: '
            'FATAL: password authentication failed',
            ["10.0.0.5", "5432"],
        ),
        (
            'pg_dump: error: could not open output file '
            '"C:\\Users\\Administrator\\secret\\dump.sql"',
            ["Administrator", "dump.sql"],
        ),
        (
            "/var/lib/postgresql/backups/some.sql: Permission denied",
            ["var/lib/postgresql"],
        ),
        (
            "postgresql://of-user:supersecret@db.internal:5432/openfield",
            ["supersecret", "db.internal"],
        ),
        (
            "ERROR: INSERT INTO users (username, password_hash) "
            "VALUES ('alice', '$2b$12$topsecret')",
            ["$2b$12$topsecret", "alice"],
        ),
    ],
)
def test_sanitize_error_removes_infrastructure_detail(raw, leaks):
    import db_admin

    cleaned = db_admin._sanitize_error(raw)
    for leak in leaks:
        assert leak not in cleaned, f"{leak!r} survived sanitising: {cleaned!r}"


def test_sanitize_error_keeps_a_useful_message():
    import db_admin

    cleaned = db_admin._sanitize_error(
        'pg_dump: error: could not open output file "C:\\tmp\\x.sql": Permission denied'
    )
    assert "Permission denied" in cleaned, "the sanitizer removed the reason too"


def test_sanitize_error_handles_empty_input():
    import db_admin

    assert db_admin._sanitize_error("") == ""


# ---------- #40: subprocess environment ----------

def test_pg_env_excludes_panel_secrets():
    """psql must not be handed the session signing key or the panel's DB password.

    Runs in a subprocess because the environment must be set before config is
    imported, and re-importing config inside the test process would leave every
    other module holding a stale reference.
    """
    code = """
import json, db_admin
env = db_admin._pg_env()
print(json.dumps({
    'keys': sorted(env.keys()),
    'pgpassword': env.get('PGPASSWORD'),
    'encoding': env.get('PGCLIENTENCODING'),
    'has_path': 'PATH' in env,
}))
"""
    out = _run_in_subprocess(
        code,
        {
            "ADMIN_SECRET_KEY": "Kf9xQ2mZ7pL4wR8tY1uI6oP3aS0dF5gH",
            "ADMIN_DB_PASSWORD": "db-password-value",
            "SOME_OTHER_SECRET": "another-secret-value",
            "ADMIN_DB_USER": "of-user",
        },
    )
    result = json.loads(out.splitlines()[-1])

    assert "ADMIN_SECRET_KEY" not in result["keys"], (
        "the session signing key leaked to psql"
    )
    assert "SOME_OTHER_SECRET" not in result["keys"], (
        "the whole panel environment was passed through"
    )
    assert "ADMIN_DB_PASSWORD" not in result["keys"], (
        "the panel's DB password variable leaked"
    )
    # The child must still be able to reach the database.
    assert result["pgpassword"] == "db-password-value"
    assert result["encoding"] == "UTF8"
    assert result["has_path"] is True, "psql can no longer be found"


def test_pg_env_source_does_not_copy_the_whole_environment():
    import inspect

    import db_admin

    source = inspect.getsource(db_admin._pg_env)
    # Strip comments: the function explains in a comment what it used to do, and
    # that explanation mentions the very pattern being searched for.
    code_lines = [
        line for line in source.splitlines() if not line.strip().startswith("#")
    ]
    code = "\n".join(code_lines)
    assert "dict(os.environ)" not in code, (
        "the subprocess still inherits the panel's entire environment"
    )
    assert "os.environ[key]" in code or "os.environ.get(key)" in code, (
        "the environment is no longer sourced from a filtered allow-list"
    )


# ---------- #41: dependency pinning ----------

def test_requirements_are_exactly_pinned():
    path = os.path.join(REPO_ROOT, "requirements.txt")
    with open(path, encoding="utf-8") as fh:
        lines = [
            line.strip()
            for line in fh
            if line.strip() and not line.strip().startswith("#")
        ]
    assert lines, "no dependencies declared"
    for line in lines:
        assert re.match(r"^[A-Za-z0-9._-]+==[0-9][^\s]*$", line), (
            f"{line!r} is not pinned to an exact version"
        )


def test_start_scripts_do_not_reinstall_unconditionally():
    for name in ("scripts/start.sh", "scripts/start.bat"):
        path = os.path.join(REPO_ROOT, *name.split("/"))
        with open(path, encoding="utf-8") as fh:
            body = fh.read()
        assert "--install" in body, f"{name} has no way to skip the install"
        assert "import flask" in body, (
            f"{name} does not check whether dependencies are already present"
        )


# ---------- #42: no raw DB error on the login page ----------

def test_base_template_does_not_render_the_raw_db_error():
    path = os.path.join(REPO_ROOT, "templates", "base.html")
    with open(path, encoding="utf-8") as fh:
        body = fh.read()
    assert "{{ db_status.error }}" not in body, (
        "the login page still renders the raw database error to anonymous visitors"
    )


def test_login_page_shows_no_connection_detail():
    """End to end: make the schema check fail and read the login page.

    Note this also exercises the path where the failure is NOT a psycopg2.Error:
    db._check_schema must degrade to a generic notice rather than letting an
    unexpected exception escape during template rendering.
    """
    code = """
import json
import db
db.get_conn = lambda *a, **kw: (_ for _ in ()).throw(
    RuntimeError('connection to db.internal:5432 as of-user failed')
)
db.invalidate_schema_status()
import app
app.app.config.update(TESTING=True)
body = app.app.test_client().get('/login').get_data(as_text=True)
print(json.dumps({'status': 'ok', 'body': body}))
"""
    try:
        out = _run_in_subprocess(code)
    except AssertionError as exc:
        pytest.fail(
            "an unexpected database exception escaped while rendering the login "
            f"page instead of degrading gracefully: {exc}"
        )
    result = json.loads(out.splitlines()[-1])
    body = result["body"]
    assert "db.internal" not in body, "the database host is visible to anyone"
    assert "of-user" not in body, "the database role is visible to anyone"
    assert "5432" not in body, "the database port is visible to anyone"
