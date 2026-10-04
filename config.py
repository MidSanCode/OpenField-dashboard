import os

DB_HOST = os.getenv("ADMIN_DB_HOST", "localhost")
DB_PORT = int(os.getenv("ADMIN_DB_PORT", "5432"))
DB_USER = os.getenv("ADMIN_DB_USER", "")
DB_PASSWORD = os.getenv("ADMIN_DB_PASSWORD", "")
DB_NAME = os.getenv("ADMIN_DB_NAME", "openfield")
DB_SSLMODE = os.getenv("ADMIN_DB_SSLMODE", "")

RUSTFS_ENDPOINT = os.getenv("RUSTFS_ENDPOINT", "localhost:9000")
RUSTFS_ACCESS_KEY = os.getenv("RUSTFS_ACCESS_KEY", "")
RUSTFS_SECRET_KEY = os.getenv("RUSTFS_SECRET_KEY", "")
RUSTFS_BUCKET = os.getenv("RUSTFS_BUCKET", "openfield")

# Credentials deliberately have no built-in defaults.
#
# The panel used to fall back to ADMIN_DB_USER=of-user /
# ADMIN_DB_PASSWORD=of-user-1207 and RUSTFS_ACCESS_KEY=RUSTFS_SECRET_KEY=
# rustfsadmin, and to sslmode=disable. Those values were committed here and the
# database password also appears in the Go server's tests, so any deployment
# that simply forgot to set the variables connected to PostgreSQL in cleartext
# with credentials published in a public repository. A missing credential is now
# a startup error that names the variable, which is far better than silently
# using a known password.
#
# sslmode is left unset by default so libpq's own default applies ("prefer"),
# which attempts TLS and only falls back to cleartext when the server refuses —
# unlike the old hardcoded "disable", which never tried TLS at all.


def missing_credentials():
    """Return the names of required credential variables that are unset.

    An empty list means the configuration is complete. Callers report the list
    rather than crashing deep inside a connection attempt, so the operator sees
    exactly which variable to set.
    """
    required = {
        "ADMIN_DB_USER": DB_USER,
        "ADMIN_DB_PASSWORD": DB_PASSWORD,
    }
    # Object storage is optional: the panel works without it, so its credentials
    # are only required when an endpoint is configured.
    if RUSTFS_ENDPOINT:
        required["RUSTFS_ACCESS_KEY"] = RUSTFS_ACCESS_KEY
        required["RUSTFS_SECRET_KEY"] = RUSTFS_SECRET_KEY
    return sorted(name for name, value in required.items() if not str(value).strip())

# Flask session signing key.
#
# A predictable key lets anyone forge the "openfield_admin" session cookie and
# walk straight past the login form, so there is deliberately no insecure
# default. Resolution order:
#   1. ADMIN_SECRET_KEY environment variable;
#   2. a random key persisted to .secret_key next to this file on first run
#      (kept out of version control via .gitignore).
def secret_key_problem(value):
    """Return a message when a session-signing key is too weak, else None.

    Mirrors the strength requirements the Go services apply, so the panel does
    not become the weakest component by accepting a key they would reject.
    """
    if len(value) < 32:
        return f"长度至少 32 个字符（当前 {len(value)}）。"
    if len(value) > 512:
        return "长度最多 512 个字符。"
    if value.strip() != value:
        return "首尾不能有空白字符。"
    if len(set(value)) < 8:
        return "字符种类过少，随机性不足。"
    lowered = value.lower()
    for weak in ("changeme", "change-me", "secret", "password", "example", "default", "admin"):
        if weak in lowered:
            return f"包含常见弱口令片段 '{weak}'。"
    return None


def _load_or_create_secret_key():
    env = os.getenv("ADMIN_SECRET_KEY", "").strip()
    if env:
        # Validate the supplied key rather than trusting it.
        #
        # This value signs the session cookie, so a short or predictable key lets
        # anyone forge an administrator cookie and skip the login form entirely.
        # The Go services in this project enforce a strong key and refuse weak
        # ones, so accepting "abc" here was the asymmetric weak link. An operator
        # who sets the variable at all has opted into managing this secret, so a
        # rejected value is a startup error they can act on — unlike the
        # unset case, where generating a key is the helpful behaviour.
        problem = secret_key_problem(env)
        if problem is not None:
            raise SystemExit(
                f"ADMIN_SECRET_KEY 无效：{problem}\n"
                "该密钥用于签名管理员会话 cookie，强度不足时任何人都可伪造登录态。"
            )
        return env

    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".secret_key")
    try:
        with open(path, "r", encoding="utf-8") as f:
            existing = f.read().strip()
        if len(existing) >= 32:
            return existing
    except OSError:
        pass

    import secrets

    generated = secrets.token_urlsafe(48)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        # Another process won the race between the read above and this create;
        # read its key back rather than failing to start.
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        # The directory is read-only, or the key file is not writable by this
        # user, and no environment variable supplied a key.
        #
        # This used to be unreachable: the handler caught FileExistsError, which
        # os.open with O_CREAT|O_EXCL never raises here, while the real failure —
        # a PermissionError — propagated and the panel could not start at all,
        # with a traceback that did not mention ADMIN_SECRET_KEY. Generating an
        # ephemeral key keeps the panel usable; every login session simply ends
        # when the process restarts, and we say so loudly.
        import warnings

        warnings.warn(
            "无法写入 .secret_key，且未设置 ADMIN_SECRET_KEY。本次运行使用临时会话密钥："
            "重启面板后所有登录会话都会失效。请设置 ADMIN_SECRET_KEY 或使该目录可写。",
            RuntimeWarning,
            stacklevel=2,
        )
        return generated

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(generated)
    except OSError:
        pass
    return generated


SECRET_KEY = _load_or_create_secret_key()

# OpenField Go server repository root used by the server manager.
# Override with ADMIN_SERVER_ROOT; defaults to the sibling "server" folder
# next to this admin repository.
SERVER_ROOT = os.getenv("ADMIN_SERVER_ROOT", "").strip()
if not SERVER_ROOT:
    SERVER_ROOT = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "server"
    )

SESSION_COOKIE_NAME = "openfield_admin"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
# SameSite=Lax stops cross-site POSTs from carrying the cookie (the classic
# CSRF vector); Secure keeps the cookie off plain HTTP.
#
# The panel's only credential is this cookie, so on any link where an on-path
# attacker can read traffic, a non-Secure cookie hands over the session. It
# cannot simply default to True, because the panel is normally reached over
# plain HTTP on loopback for local administration (app.run binds 127.0.0.1) and
# a Secure cookie would never be sent there, making the panel unusable.
#
# The compromise: default to False only on loopback, and to True otherwise. An
# operator who exposes the panel beyond the local machine gets the safe value
# without having to know about this setting, while local use keeps working.
# ADMIN_COOKIE_SECURE overrides either way.
_COOKIE_SECURE_ENV = os.getenv("ADMIN_COOKIE_SECURE", "").strip().lower()


def _cookie_secure_default():
    if _COOKIE_SECURE_ENV:
        return _COOKIE_SECURE_ENV in ("1", "true", "yes", "on")
    return not _is_loopback_host(os.getenv("ADMIN_BIND_HOST", "127.0.0.1"))


def _is_loopback_host(host):
    host = (host or "").strip().lower().strip("[]")
    return host in ("127.0.0.1", "localhost", "::1") or host.startswith("127.")


SESSION_COOKIE_SECURE = _cookie_secure_default()

# Advisory lock id used to serialize database initialization.
DB_INIT_LOCK_ID = int(os.getenv("ADMIN_DB_INIT_LOCK_ID", "1207"))

# Upper bound on any request body Flask buffers for form/file parsing.
#
# Flask reads the whole body into memory before a handler runs, so without a
# ceiling a single POST could exhaust the process. The panel's own routes are all
# small; the only legitimately large upload is a database dump, which is why the
# default is generous. Raise ADMIN_MAX_CONTENT_LENGTH if an import needs more.
MAX_CONTENT_LENGTH = int(os.getenv("ADMIN_MAX_CONTENT_LENGTH", str(512 * 1024 * 1024)))

# Per-statement ceiling for every panel database connection, in milliseconds.
#
# A query that exceeds it is cancelled by PostgreSQL instead of holding its
# connection until it completes, so one expensive page request cannot pin the
# pool. Applied per connection in db.get_conn().
DB_STATEMENT_TIMEOUT_MS = int(os.getenv("ADMIN_DB_STATEMENT_TIMEOUT_MS", "30000"))


def dsn():
    """Build the libpq connection string.

    sslmode is omitted entirely when unset, so libpq's own default ("prefer",
    which tries TLS first) applies. Emitting an empty sslmode= would be a syntax
    error rather than a default.
    """
    parts = [
        f"host={DB_HOST}",
        f"port={DB_PORT}",
        f"dbname={DB_NAME}",
        f"user={DB_USER}",
        f"password={DB_PASSWORD}",
    ]
    if str(DB_SSLMODE).strip():
        parts.append(f"sslmode={DB_SSLMODE}")
    return " ".join(parts)
