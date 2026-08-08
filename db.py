import contextlib

import psycopg2
import psycopg2.extras

import config


def connect():
    return psycopg2.connect(config.dsn())


def get_conn():
    conn = connect()
    conn.autocommit = True
    return conn


@contextlib.contextmanager
def advisory_lock(lock_id):
    """Hold a PostgreSQL session-level advisory lock for the duration of a block.

    Used to serialize destructive operations (e.g. database initialization)
    across concurrent processes/threads.
    """
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT pg_advisory_lock(%s)", (lock_id,))
    try:
        yield
    finally:
        try:
            cur.execute("SELECT pg_advisory_unlock(%s)", (lock_id,))
        except Exception:
            pass
        cur.close()
        conn.close()


def fetch_all(query, args=None):
    conn = get_conn()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(query, args or ())
        rows = cur.fetchall()
        cur.close()
        return rows
    finally:
        conn.close()


def fetch_one(query, args=None):
    rows = fetch_all(query, args)
    return rows[0] if rows else None


def execute(query, args=None):
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(query, args or ())
        cur.close()
    finally:
        conn.close()


def init_admin_table():
    execute(
        """
        CREATE TABLE IF NOT EXISTS admin_accounts (
            id BIGSERIAL PRIMARY KEY,
            username VARCHAR(255) NOT NULL UNIQUE,
            password_hash VARCHAR(255) NOT NULL,
            can_verify BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """
    )
    execute(
        """
        ALTER TABLE admin_accounts ADD COLUMN IF NOT EXISTS can_verify BOOLEAN NOT NULL DEFAULT TRUE
        """
    )
    # User-verification columns only make sense once the OpenField schema (and
    # the users table) exists; on a brand-new database this runs after the Go
    # server migrations have initialized the schema.
    if not is_initialized():
        return
    execute(
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS verified_note TEXT NOT NULL DEFAULT ''"
    )
    execute(
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS verified_by VARCHAR(255) NOT NULL DEFAULT ''"
    )
    # Audit trail for admin wallet adjustments: keep the acting admin account
    # name even when the operator has no matching users row (operator_id stays
    # NULL in that case so the FK to users(id) is never violated).
    if fetch_one("SELECT to_regclass('public.wallet_transactions') AS t")["t"]:
        execute(
            "ALTER TABLE wallet_transactions ADD COLUMN IF NOT EXISTS "
            "operator_username VARCHAR(255) NOT NULL DEFAULT ''"
        )


def is_initialized():
    """True when the OpenField schema exists (the users table is present)."""
    row = fetch_one("SELECT to_regclass('public.users') AS t")
    return bool(row and row["t"])
