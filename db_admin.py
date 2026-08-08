"""Database backup/restore helpers for the admin panel.

Uses the PostgreSQL client tools (pg_dump / psql) with credentials from
config.py. Backups are written as plain SQL with --clean/--if-exists so they
can be restored over the current schema, and are stored under admin/backups/.
"""

import os
import shutil
import subprocess
import time

import config

BACKUP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backups")

# Cap the size of error output surfaced in flash messages.
_MAX_ERROR_LEN = 3000


def _pg_env():
    env = dict(os.environ)
    env["PGPASSWORD"] = config.DB_PASSWORD
    env["PGCLIENTENCODING"] = "UTF8"
    return env


def _common_args():
    return [
        "-h", config.DB_HOST,
        "-p", str(config.DB_PORT),
        "-U", config.DB_USER,
        "-d", config.DB_NAME,
    ]


def _require_tool(name):
    if shutil.which(name) is None:
        raise RuntimeError(
            f"未找到 {name} 命令，请确认 PostgreSQL 客户端已安装并加入 PATH"
        )


def _truncate(text):
    if len(text) <= _MAX_ERROR_LEN:
        return text
    return "..." + text[-(_MAX_ERROR_LEN - 3):]


def backup_dir():
    os.makedirs(BACKUP_DIR, exist_ok=True)
    return BACKUP_DIR


def list_backups():
    """Return metadata for stored backup files, newest first."""
    if not os.path.isdir(BACKUP_DIR):
        return []
    files = []
    for name in os.listdir(BACKUP_DIR):
        path = os.path.join(BACKUP_DIR, name)
        if os.path.isfile(path):
            st = os.stat(path)
            files.append(
                {
                    "name": name,
                    "size": st.st_size,
                    "mtime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime)),
                }
            )
    files.sort(key=lambda f: f["name"], reverse=True)
    return files


def backup_path(filename):
    """Resolve a backup filename inside the backup dir, guarding against traversal."""
    base = os.path.basename(filename)
    path = os.path.join(BACKUP_DIR, base)
    if not os.path.isfile(path):
        raise FileNotFoundError(f"备份不存在: {filename}")
    return path


def delete_backup(filename):
    path = backup_path(filename)
    os.remove(path)


def export_backup():
    """Run pg_dump --clean --if-exists and write a timestamped .sql backup.

    Returns (path, message); path is None on failure.
    """
    try:
        _require_tool("pg_dump")
    except RuntimeError as e:
        return None, str(e)

    bdir = backup_dir()
    ts = time.strftime("%Y%m%d-%H%M%S")
    out_path = os.path.join(bdir, f"openfield-{ts}.sql")

    cmd = [
        "pg_dump",
        "--clean",
        "--if-exists",
        "--no-owner",
        "--no-privileges",
        *_common_args(),
    ]
    try:
        with open(out_path, "w", encoding="utf-8", newline="") as f:
            result = subprocess.run(
                cmd, stdout=f, stderr=subprocess.PIPE, env=_pg_env(), timeout=1800
            )
    except FileNotFoundError:
        return None, "未找到 pg_dump 命令，请确认 PostgreSQL 客户端已安装并加入 PATH"
    except subprocess.TimeoutExpired:
        try:
            os.remove(out_path)
        except OSError:
            pass
        return None, "备份超时（30 分钟）"

    if result.returncode != 0:
        try:
            os.remove(out_path)
        except OSError:
            pass
        stderr = result.stderr.decode("utf-8", "replace")
        return None, f"备份失败:\n{_truncate(stderr)}"

    size = os.path.getsize(out_path)
    return out_path, f"备份完成: {os.path.basename(out_path)}（{size / 1024:.1f} KB）"


def import_backup(sql_path):
    """Restore a plain-SQL backup via psql inside a single transaction.

    Any failing statement rolls back the whole import, leaving the database
    unchanged. Returns (ok, message).
    """
    try:
        _require_tool("psql")
    except RuntimeError as e:
        return False, str(e)

    cmd = [
        "psql",
        "--set", "ON_ERROR_STOP=1",
        "--single-transaction",
        *_common_args(),
        "-f", sql_path,
    ]
    try:
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=_pg_env(), timeout=1800
        )
    except FileNotFoundError:
        return False, "未找到 psql 命令，请确认 PostgreSQL 客户端已安装并加入 PATH"
    except subprocess.TimeoutExpired:
        return False, "导入超时（30 分钟）"

    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", "replace")
        return False, f"导入失败（已回滚）:\n{_truncate(stderr)}"

    return True, "导入完成（数据已恢复）"
