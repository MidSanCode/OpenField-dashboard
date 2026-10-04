import contextlib
import time

import psycopg2
import psycopg2.extras

import config

# Tables the admin panel reads. When any of them is missing the panel stays
# usable (you can still log in and navigate) but data pages report "unreadable"
# instead of crashing; repair/initialization happens only via the DB panel.
CORE_TABLES = [
    "users",
    "posts",
    "messages",
    "attachments",
    "post_attachments",
    "wallets",
    "wallet_transactions",
    "groups",
    "group_permissions",
    "permissions",
    "user_groups",
]

# Short-TTL cache for schema_status() so it is not queried on every request.
_SCHEMA_CACHE = {"ts": 0.0, "ok": False, "missing": [], "error": None}
_SCHEMA_TTL = 5.0


def connect():
    return psycopg2.connect(config.dsn())


def get_conn():
    conn = connect()
    conn.autocommit = True
    # Bound how long any single statement may run.
    #
    # Without a server-side timeout a slow query holds its connection until it
    # finishes, and the panel's list pages issue several queries per request, so
    # a client could pin the small pool by repeatedly asking for expensive pages.
    # This is a per-session setting: it applies to every statement on this
    # connection and disappears with it.
    try:
        with conn.cursor() as cur:
            cur.execute("SET statement_timeout = %s", (config.DB_STATEMENT_TIMEOUT_MS,))
    except psycopg2.Error:
        # A server that rejects the setting must not stop the panel from working.
        pass
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


@contextlib.contextmanager
def transaction():
    """Run several statements atomically.

    Every other helper here opens its own autocommit connection, so a handler
    that ran two statements — a punishment row plus its side effects, a DELETE
    plus the replacement INSERTs — left a window where a failure between them
    committed half the change. Code inside this block must use the yielded
    cursor, not the module-level execute(), to stay in the transaction.
    """
    conn = get_conn()
    conn.autocommit = False
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
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
    try:
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
        # Explicit capability model. can_verify only ever gated the two
        # verification routes, so every other privileged action (resetting an
        # application user's password or payment PIN, granting permission
        # keys, restoring a database dump) was reachable by any authenticated
        # panel account. capabilities is a comma-separated list of the
        # capability names checked by app.require_capability.
        execute(
            """
            ALTER TABLE admin_accounts ADD COLUMN IF NOT EXISTS capabilities TEXT NOT NULL DEFAULT ''
            """
        )
        # Existing accounts predate the model and were able to do all of this,
        # so they keep full capabilities rather than being silently stripped.
        # can_verify=FALSE accounts were intended to be restricted, so they get
        # verification only.
        execute(
            """
            UPDATE admin_accounts
               SET capabilities = '*'
             WHERE COALESCE(capabilities, '') = '' AND can_verify = TRUE
            """
        )
        execute(
            """
            UPDATE admin_accounts
               SET capabilities = 'users.verify'
             WHERE COALESCE(capabilities, '') = '' AND can_verify = FALSE
            """
        )
        # Session revocation counter.
        #
        # Flask's client-side sessions carry all authorization state, so an
        # administrator whose password was rotated (or whose row was deleted)
        # kept full panel access with the cookie already in hand — there was no
        # way to invalidate a live session at all. Every login stamps the
        # account's current session_version into the cookie, and login_required
        # re-reads this column, so bumping it logs that account out everywhere.
        execute(
            """
            ALTER TABLE admin_accounts ADD COLUMN IF NOT EXISTS session_version BIGINT NOT NULL DEFAULT 0
            """
        )
        execute(
            """
            ALTER TABLE admin_accounts ADD COLUMN IF NOT EXISTS disabled BOOLEAN NOT NULL DEFAULT FALSE
            """
        )
        # Panel operation audit log.
        #
        # The panel performed privileged, irreversible actions — resetting an
        # application user's password or payment PIN, adjusting a wallet,
        # restoring a database dump, managing panel accounts — without recording
        # who did what. The only trace was the wallet_transactions columns, which
        # cover just one of those actions. This is the general trail.
        execute(
            """
            CREATE TABLE IF NOT EXISTS admin_audit_log (
                id BIGSERIAL PRIMARY KEY,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                actor_id BIGINT,
                actor_username VARCHAR(255) NOT NULL DEFAULT '',
                action VARCHAR(100) NOT NULL,
                target_type VARCHAR(50) NOT NULL DEFAULT '',
                target_id VARCHAR(255) NOT NULL DEFAULT '',
                detail TEXT NOT NULL DEFAULT '',
                client_ip VARCHAR(64) NOT NULL DEFAULT ''
            )
            """
        )
        execute(
            """
            CREATE INDEX IF NOT EXISTS admin_audit_log_created_at_idx
                ON admin_audit_log (created_at DESC)
            """
        )
        # Panel attribution for punishments.
        #
        # user_punishments.operator_id is a foreign key to users(id) — the
        # *application* user table — so it cannot hold an admin_accounts id, and
        # the panel used to hardcode NULL, leaving every punishment it recorded
        # unattributed. Record the acting administrator's name separately, the
        # same way wallet_transactions.operator_username already works.
        if fetch_one("SELECT to_regclass('public.user_punishments') AS t")["t"]:
            execute(
                "ALTER TABLE user_punishments ADD COLUMN IF NOT EXISTS "
                "operator_username VARCHAR(255) NOT NULL DEFAULT ''"
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
        execute(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS member_level BIGINT NOT NULL DEFAULT 0"
        )
        execute(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS member_expires_at TIMESTAMPTZ"
        )
        # Audit trail for admin wallet adjustments: keep the acting admin account
        # name even when the operator has no matching users row (operator_id stays
        # NULL in that case so the FK to users(id) is never violated).
        if fetch_one("SELECT to_regclass('public.wallet_transactions') AS t")["t"]:
            execute(
                "ALTER TABLE wallet_transactions ADD COLUMN IF NOT EXISTS "
                "operator_username VARCHAR(255) NOT NULL DEFAULT ''"
            )
    except psycopg2.Error:
        # A database outage must never prevent the admin panel from booting.
        # The table is (re)created again after database initialization.
        pass


def is_initialized():
    """True when the OpenField schema exists (the users table is present)."""
    try:
        row = fetch_one("SELECT to_regclass('public.users') AS t")
        return bool(row and row["t"])
    except psycopg2.Error:
        return False


def _check_schema():
    """Connect and report which core tables are missing.

    Returns a dict: {"ok", "missing", "error"}. "error" is set when the
    database itself is unreachable; "missing" lists absent core tables.
    """
    try:
        conn = get_conn()
    except psycopg2.Error as e:
        return {"ok": False, "missing": [], "error": str(e)}
    except Exception as e:
        # Anything else — a driver-level failure that is not a psycopg2.Error, a
        # missing configuration value, a bug in get_conn — must not escape.
        # schema_status runs from a template context processor, so an exception
        # here breaks rendering for EVERY page of the panel, including the login
        # form, turning a database problem into a completely unusable UI.
        return {"ok": False, "missing": [], "error": str(e)}
    try:
        missing = []
        with conn.cursor() as cur:
            for table in CORE_TABLES:
                cur.execute("SELECT to_regclass(%s) AS t", (f"public.{table}",))
                row = cur.fetchone()
                if not row or not row[0]:
                    missing.append(table)
        return {"ok": not missing, "missing": missing, "error": None}
    except psycopg2.Error as e:
        return {"ok": False, "missing": [], "error": str(e)}
    except Exception as e:
        return {"ok": False, "missing": [], "error": str(e)}
    finally:
        try:
            conn.close()
        except Exception:
            pass


def schema_status():
    """Cached database readiness: {"ok", "missing", "error"}."""
    now = time.monotonic()
    if now - _SCHEMA_CACHE["ts"] > _SCHEMA_TTL:
        _SCHEMA_CACHE.update({"ts": now, **_check_schema()})
    return dict(_SCHEMA_CACHE)


def invalidate_schema_status():
    """Force the next schema_status() call to re-query the database."""
    _SCHEMA_CACHE["ts"] = 0.0
