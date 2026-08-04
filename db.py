import psycopg2
import psycopg2.extras

import config


def connect():
    return psycopg2.connect(config.dsn())


def get_conn():
    conn = connect()
    conn.autocommit = True
    return conn


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


def is_initialized():
    """True when the OpenField schema exists (the users table is present)."""
    row = fetch_one("SELECT to_regclass('public.users') AS t")
    return bool(row and row["t"])
