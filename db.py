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
