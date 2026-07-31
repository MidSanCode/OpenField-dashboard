import os

DB_HOST = os.getenv("ADMIN_DB_HOST", "localhost")
DB_PORT = int(os.getenv("ADMIN_DB_PORT", "5432"))
DB_USER = os.getenv("ADMIN_DB_USER", "of-user")
DB_PASSWORD = os.getenv("ADMIN_DB_PASSWORD", "of-user-1207")
DB_NAME = os.getenv("ADMIN_DB_NAME", "openfield")
DB_SSLMODE = os.getenv("ADMIN_DB_SSLMODE", "disable")

RUSTFS_ENDPOINT = os.getenv("RUSTFS_ENDPOINT", "localhost:9000")
RUSTFS_ACCESS_KEY = os.getenv("RUSTFS_ACCESS_KEY", "minioadmin")
RUSTFS_SECRET_KEY = os.getenv("RUSTFS_SECRET_KEY", "minioadmin")
RUSTFS_BUCKET = os.getenv("RUSTFS_BUCKET", "openfield")

SECRET_KEY = os.getenv("ADMIN_SECRET_KEY", "admin-panel-secret-key-change-me")

SESSION_COOKIE_NAME = "openfield_admin"
SESSION_COOKIE_HTTPONLY = True


def dsn():
    return (
        f"host={DB_HOST} port={DB_PORT} dbname={DB_NAME} "
        f"user={DB_USER} password={DB_PASSWORD} sslmode={DB_SSLMODE}"
    )
