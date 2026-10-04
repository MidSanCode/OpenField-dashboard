"""Database backup/restore helpers for the admin panel.

Uses the PostgreSQL client tools (pg_dump / psql) with credentials from
config.py. Backups are written as plain SQL with --clean/--if-exists so they
can be restored over the current schema, and are stored under admin/backups/.
"""

import os
import re
import shutil
import subprocess
import time

import config

BACKUP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backups")

# Cap the size of error output surfaced in flash messages.
_MAX_ERROR_LEN = 3000

# Backup files are a complete copy of every row in the database, including
# users.password_hash, users.payment_pin_hash, session refresh-token hashes and
# the panel's own admin_accounts rows. They must not be world-readable on disk
# and must not be servable without an explicit capability check.
_BACKUP_FILE_MODE = 0o600


def _restrict_file(path):
    """Best-effort tighten permissions on a file we just created."""
    try:
        os.chmod(path, _BACKUP_FILE_MODE)
    except OSError:
        # Windows / exotic filesystems: not fatal, the capability gate and
        # directory location still protect the file.
        pass

# Largest backup file we will read or import.
MAX_IMPORT_BYTES = 512 * 1024 * 1024

# psql reads its input the same way it reads an interactive session, so a file
# containing backslash meta-commands executes them: `\!` runs a shell command,
# `\i` includes and runs another file, `\o` writes files, `\copy ... PROGRAM`
# runs a program. Passing a user-uploaded file to `psql -f` therefore handed an
# authenticated admin full command execution on the panel host, with output
# echoed back through the flash message. Only the harmless meta-commands a
# pg_dump-produced script actually emits are allowed through.
_ALLOWED_META = {
    "restrict", "unrestrict", "connect", "encoding", "set", "echo",
    "if", "endif", "on_error_stop", "timing", "charset", "qecho",
}

# Lines starting with a backslash followed by a command word.
_META_RE = re.compile(r"^\\([A-Za-z_][A-Za-z0-9_]*)?")

# `\copy ... PROGRAM '...'` and `COPY ... TO/FROM PROGRAM '...'` execute a
# shell command even though the verb is otherwise legitimate, so they are
# screened separately.
_PROGRAM_RE = re.compile(r"\bPROGRAM\b", re.IGNORECASE)


def contains_meta_command(sql_text):
    """Return a description of the first dangerous construct in sql_text.

    Returns None when the text is safe to feed to psql. Two constructs are
    intentionally tolerated because ordinary pg_dump output depends on them:
    the `\\.` COPY-data terminator and a trailing lone backslash. Everything
    else that begins with a backslash must be an allowlisted client command.
    """
    for raw_line in sql_text.splitlines():
        line = raw_line.strip()
        if not line.startswith("\\"):
            continue
        # The COPY data terminator is data, not a meta-command, and every
        # pg_dump script that copies rows contains it.
        if line == "\\.":
            continue
        match = _META_RE.match(line)
        cmd = (match.group(1) if match and match.group(1) else "").lower()
        if not cmd:
            # A bare backslash splices the following line onto this one, so
            # psql would interpret the next line's text in this context.
            # Rather than guess at the result, reject it.
            return "\\ (line continuation)"
        if cmd not in _ALLOWED_META:
            return "\\" + cmd

    # Shelling out via COPY, which has an otherwise benign verb.
    for raw_line in sql_text.splitlines():
        if _PROGRAM_RE.search(raw_line) and (
            "\\copy" in raw_line.lower() or raw_line.strip().lower().startswith("copy ")
        ):
            return "COPY ... PROGRAM"

    return None


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


def _sanitize_error(text):
    """Strip host paths from a tool's error output before showing it."""
    text = re.sub(r"(/[\w./-]+|[A-Za-z]:\\\\[\w.\\\\ -]+)", "<path>", text)
    return _truncate(text)


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
    """Resolve a backup filename inside the backup dir, guarding against traversal.

    Only regular files directly inside BACKUP_DIR are accepted: symlinks are
    rejected rather than resolved, so a link planted in the directory cannot
    turn a download into an arbitrary file read of, say, a private key or the
    panel's own config.py.
    """
    base = os.path.basename(filename)
    if not base or base != filename or base in (".", ".."):
        raise FileNotFoundError(f"备份不存在: {filename}")
    if os.path.islink(os.path.join(BACKUP_DIR, base)):
        raise FileNotFoundError(f"备份不存在: {filename}")
    path = os.path.join(BACKUP_DIR, base)
    if not os.path.isfile(path):
        raise FileNotFoundError(f"备份不存在: {filename}")
    # Confirm it really lives inside the backup dir after resolution.
    real = os.path.realpath(path)
    if real != path and not real.startswith(os.path.realpath(BACKUP_DIR) + os.sep):
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
    _restrict_file(out_path)
    return out_path, f"备份完成: {os.path.basename(out_path)}（{size / 1024:.1f} KB）"


def read_import_file(sql_path):
    """Read a candidate import file for screening.

    Returns the decoded text, or None when the file is missing, unreadable or
    larger than MAX_IMPORT_BYTES.
    """
    try:
        if os.path.getsize(sql_path) > MAX_IMPORT_BYTES:
            return None
        with open(sql_path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def import_backup(sql_path):
    """Restore a plain-SQL backup via psql inside a single transaction.

    Any failing statement rolls back the whole import, leaving the database
    unchanged. Returns (ok, message).
    """
    try:
        _require_tool("psql")
    except RuntimeError as e:
        return False, str(e)

    # Inspect the script before handing it to psql. This is the last line of
    # defense against the meta-command RCE (see contains_meta_command); the
    # caller screens it too, so a future call site cannot skip the check.
    try:
        size = os.path.getsize(sql_path)
    except OSError as e:
        return False, f"无法读取备份文件: {e}"
    if size > MAX_IMPORT_BYTES:
        return False, f"备份文件过大（{size / 1024 / 1024:.1f} MB），上限 {MAX_IMPORT_BYTES // 1024 // 1024} MB"
    try:
        with open(sql_path, "r", encoding="utf-8", errors="replace") as f:
            sql_text = f.read()
    except OSError as e:
        return False, f"无法读取备份文件: {e}"

    bad = contains_meta_command(sql_text)
    if bad is not None:
        return False, (
            f"备份文件包含不允许的 psql 元命令 {bad}，已拒绝导入。"
            "请仅导入本面板导出的备份文件。"
        )

    cmd = [
        "psql",
        # Do not read ~/.psqlrc: a startup file there would otherwise be
        # executed with the panel's database credentials.
        "-X",
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
        # psql echoes the offending statement and any location it resolved, and
        # a failed import previously surfaced all of it verbatim in the
        # browser. Keep the diagnostic value (the error class and message) but
        # drop absolute paths and DSN-style host/port fragments.
        return False, f"导入失败（已回滚）:\n{_sanitize_error(stderr)}"

    return True, "导入完成（数据已恢复）"
