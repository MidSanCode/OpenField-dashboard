"""Tests for the credential defaults removed in dashboard issue #6.

The panel used to fall back to ADMIN_DB_USER=of-user /
ADMIN_DB_PASSWORD=of-user-1207, RUSTFS_ACCESS_KEY=RUSTFS_SECRET_KEY=rustfsadmin
and sslmode=disable. Those values are committed in this public repository (the
database password also appears in the Go server's tests), so a deployment that
forgot to set the variables connected to PostgreSQL in cleartext with published
credentials. These tests pin the fix: no credential has a usable default, a
missing one is reported by name, and sslmode is no longer forced to disable.
"""

import importlib
import os
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Environment variable names that must never carry a built-in default.
CREDENTIAL_VARS = (
    "ADMIN_DB_USER",
    "ADMIN_DB_PASSWORD",
    "RUSTFS_ACCESS_KEY",
    "RUSTFS_SECRET_KEY",
)

# The specific weak values that used to be hardcoded here.
FORBIDDEN_DEFAULTS = ("of-user", "of-user-1207", "rustfsadmin")

CLEAN_ENV = {
    k: v
    for k, v in os.environ.items()
    if k not in CREDENTIAL_VARS and k != "ADMIN_DB_SSLMODE"
}


def _fresh_config(**env):
    """Import config.py in a subprocess with a controlled environment."""
    child = dict(CLEAN_ENV)
    child.update(env)
    code = (
        "import json, config;"
        "print(json.dumps({"
        "'user': config.DB_USER,"
        "'password': config.DB_PASSWORD,"
        "'sslmode': config.DB_SSLMODE,"
        "'ak': config.RUSTFS_ACCESS_KEY,"
        "'sk': config.RUSTFS_SECRET_KEY,"
        "'missing': config.missing_credentials(),"
        "'dsn': config.dsn(),"
        "}))"
    )
    out = subprocess.run(
        [sys.executable, "-c", code],
        cwd=REPO_ROOT,
        env=child,
        capture_output=True,
        text=True,
        check=True,
    )
    import json

    return json.loads(out.stdout.strip().splitlines()[-1])


def test_no_weak_credential_defaults():
    """Unset variables must resolve to empty, never to a published password."""
    cfg = _fresh_config()
    for key in ("user", "password", "ak", "sk"):
        assert cfg[key] == "", f"{key} still has a built-in default: {cfg[key]!r}"
    assert cfg["sslmode"] == "", "sslmode still defaults to a value"


def test_forbidden_values_are_not_reachable_as_defaults():
    cfg = _fresh_config()
    blob = " ".join(str(v) for v in cfg.values())
    for weak in FORBIDDEN_DEFAULTS:
        assert weak not in blob, f"weak credential {weak!r} is still reachable"


def test_missing_credentials_names_every_unset_variable():
    cfg = _fresh_config()
    # RUSTFS_ENDPOINT has a default, so storage credentials are required too.
    for expected in (
        "ADMIN_DB_USER",
        "ADMIN_DB_PASSWORD",
        "RUSTFS_ACCESS_KEY",
        "RUSTFS_SECRET_KEY",
    ):
        assert expected in cfg["missing"], f"{expected} not reported as missing"


def test_missing_credentials_empty_when_configured():
    cfg = _fresh_config(
        ADMIN_DB_USER="panel",
        ADMIN_DB_PASSWORD="s3cret",
        RUSTFS_ACCESS_KEY="ak",
        RUSTFS_SECRET_KEY="sk",
    )
    assert cfg["missing"] == []


def test_sslmode_omitted_when_unset_so_libpq_default_applies():
    """"disable" must not be forced, and an empty sslmode= is a syntax error."""
    cfg = _fresh_config()
    assert "sslmode=" not in cfg["dsn"], cfg["dsn"]


def test_explicit_sslmode_is_honoured():
    cfg = _fresh_config(ADMIN_DB_SSLMODE="require")
    assert "sslmode=require" in cfg["dsn"]


def test_startup_refuses_to_run_without_credentials():
    """app.py must exit with a message naming the variable, not connect anyway."""
    env = dict(CLEAN_ENV)
    # A port nothing listens on: if the guard works we never try to connect.
    env["ADMIN_DB_HOST"] = "127.0.0.1"
    env["ADMIN_DB_PORT"] = "1"
    result = subprocess.run(
        [sys.executable, "app.py"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode != 0, "app.py started without credentials"
    combined = result.stdout + result.stderr
    assert "ADMIN_DB_USER" in combined or "ADMIN_DB_PASSWORD" in combined, combined
