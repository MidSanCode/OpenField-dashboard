import os

DB_HOST = os.getenv("ADMIN_DB_HOST", "localhost")
DB_PORT = int(os.getenv("ADMIN_DB_PORT", "5432"))
DB_USER = os.getenv("ADMIN_DB_USER", "of-user")
DB_PASSWORD = os.getenv("ADMIN_DB_PASSWORD", "of-user-1207")
DB_NAME = os.getenv("ADMIN_DB_NAME", "openfield")
DB_SSLMODE = os.getenv("ADMIN_DB_SSLMODE", "disable")

RUSTFS_ENDPOINT = os.getenv("RUSTFS_ENDPOINT", "localhost:9000")
RUSTFS_ACCESS_KEY = os.getenv("RUSTFS_ACCESS_KEY", "rustfsadmin")
RUSTFS_SECRET_KEY = os.getenv("RUSTFS_SECRET_KEY", "rustfsadmin")
RUSTFS_BUCKET = os.getenv("RUSTFS_BUCKET", "openfield")

# Flask session signing key.
#
# A predictable key lets anyone forge the "openfield_admin" session cookie and
# walk straight past the login form, so there is deliberately no insecure
# default. Resolution order:
#   1. ADMIN_SECRET_KEY environment variable;
#   2. a random key persisted to .secret_key next to this file on first run
#      (kept out of version control via .gitignore).
def _load_or_create_secret_key():
    env = os.getenv("ADMIN_SECRET_KEY", "").strip()
    if env:
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
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(generated)
    except FileExistsError:
        # Another process won the race; read its key back.
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
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
# SameSite=Lax stops cross-site POSTs from carrying the cookie (the classic
# CSRF vector); Secure keeps the cookie off plain HTTP when the panel is
# served over TLS (enable via ADMIN_COOKIE_SECURE=true).
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_SECURE = os.getenv("ADMIN_COOKIE_SECURE", "").lower() in ("1", "true", "yes")

# Advisory lock id used to serialize database initialization.
DB_INIT_LOCK_ID = int(os.getenv("ADMIN_DB_INIT_LOCK_ID", "1207"))


def dsn():
    return (
        f"host={DB_HOST} port={DB_PORT} dbname={DB_NAME} "
        f"user={DB_USER} password={DB_PASSWORD} sslmode={DB_SSLMODE}"
    )
