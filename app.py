import functools
import hashlib
import io
import json
import math
import os
import re
import secrets
import tempfile
import threading
import time
import urllib.parse
import uuid
import datetime
import zipfile

import bcrypt
import psycopg2
from markupsafe import Markup
from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

import config
import db
import db_admin
import server_manager

app = Flask(__name__)
app.config["SECRET_KEY"] = config.SECRET_KEY
app.config["SESSION_COOKIE_NAME"] = config.SESSION_COOKIE_NAME
app.config["SESSION_COOKIE_HTTPONLY"] = config.SESSION_COOKIE_HTTPONLY
app.config["SESSION_COOKIE_SAMESITE"] = config.SESSION_COOKIE_SAMESITE
app.config["SESSION_COOKIE_SECURE"] = config.SESSION_COOKIE_SECURE
# Cap anything that arrives through request.form / request.files.
#
# Flask buffers the entire body before any handler runs, so without this a
# single POST of arbitrary size was read into memory before a route could look
# at it, and the panel had no global ceiling at all. Importing a database dump
# is the one legitimately large upload, so the limit is configurable and large
# by default; the streaming chunk-upload routes in db_admin.py are unaffected
# because they read the request stream directly rather than through Flask's
# form parsing.
app.config["MAX_CONTENT_LENGTH"] = config.MAX_CONTENT_LENGTH

# Ensure the admin account table exists, but never let a database outage stop
# the panel from booting.
try:
    db.init_admin_table()
except Exception as e:
    app.logger.error("failed to initialize admin table at startup: %s", e)


# ---------- response hardening ----------

# Content-Security-Policy for the panel.
#
# Every panel page carries a CSRF token and every destructive action is one
# click, so HTML escaping is the only thing standing between a stored value and
# script running with the ability to post arbitrary privileged requests. Escaping
# is not a guarantee — it was already bypassed once in this codebase by an inline
# onsubmit that decoded entities before compiling as JavaScript — so a policy
# that refuses inline script provides the defence in depth the escaping cannot.
#
# Scripts and styles were moved to external files under static/ precisely so no
# 'unsafe-inline' exemption is needed. 'unsafe-inline' for style-src is a
# deliberate, narrow concession: the templates use style="width: auto" and
# friends for layout, and style injection is a far weaker primitive than script
# injection. img-src allows data: and https: because avatars and banners are
# hosted elsewhere. frame-ancestors 'none' (with X-Frame-Options for old
# browsers) stops the panel being framed and clickjacked.
CSP_POLICY = "; ".join(
    [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: https:",
        "font-src 'self' data:",
        "connect-src 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "object-src 'none'",
    ]
)


@app.after_request
def _apply_security_headers(response):
    """Attach transport and browser-hardening headers to every response."""
    response.headers.setdefault("Content-Security-Policy", CSP_POLICY)
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    # HSTS only over a connection that was actually secure: it is meaningless on
    # cleartext, and the panel is routinely reached on http://127.0.0.1.
    if _request_is_secure():
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=63072000; includeSubDomains"
        )
    return response


def _request_is_secure():
    """True when the client's connection to the edge used TLS."""
    if request.is_secure:
        return True
    # A TLS-terminating proxy forwards plain HTTP and signals the original
    # scheme in this header. It is only consulted because the operator must
    # declare trusted proxies for the panel's own address handling anyway; see
    # _client_ip for the same reasoning.
    return (
        _TRUSTED_PROXY_COUNT > 0
        and request.headers.get("X-Forwarded-Proto", "").strip().lower() == "https"
    )


def _page_window(current, total, span=2):
    """Page numbers to show around the current one, with None marking a gap.

    Keeps the pager a fixed width so a table with thousands of pages renders a
    short control instead of thousands of links.
    """
    current = max(1, int(current))
    total = max(1, int(total))
    pages = []
    last = 0
    for p in range(1, total + 1):
        if p <= span or p > total - span or abs(p - current) <= span:
            if last and p - last > 1:
                pages.append(None)
            pages.append(p)
            last = p
    return pages


app.jinja_env.globals["page_window"] = _page_window


@app.errorhandler(413)
def _request_too_large(error):
    """Explain an oversized upload instead of showing Flask's bare 413."""
    limit_mb = config.MAX_CONTENT_LENGTH / (1024 * 1024)
    return (
        render_template(
            "too_large.html",
            limit_mb=f"{limit_mb:.0f}",
        ),
        413,
    )


# ---------- capabilities ----------

# Named capabilities gating whole classes of privileged action. Granted per
# panel account via admin_accounts.capabilities (comma-separated). The special
# value "*" means every capability.
CAP_USERS_CREDENTIALS = "users.credentials"  # reset an application password/PIN
CAP_USERS_WRITE = "users.write"              # create/rename/delete application users
CAP_USERS_PUNISH = "users.punish"            # punish, ban, adjust wallet/membership
CAP_USERS_VERIFY = "users.verify"            # grant/revoke the verification badge
CAP_USERS_GROUPS = "users.groups"            # attach permission keys to groups
CAP_DB_RESTORE = "db.restore"                # import a database dump
CAP_DB_BACKUP = "db.backup"                  # export/download/delete dumps
CAP_SERVER_MANAGE = "server.manage"          # start/stop/build server processes
CAP_PLUGINS_WRITE = "plugins.write"          # publish/unpublish plugins
CAP_ADMINS_MANAGE = "admins.manage"          # manage panel accounts

# Account names are written by several paths (this panel, the Go service's
# password registration, and OIDC provisioning) into one shared column. The
# panel previously validated only presence and uniqueness here, while
# user_rename enforced a format rule, so an unrestricted name could reach the
# listing. Enforce the application's own rule at every panel writer so a name
# with quotes, angle brackets or spaces can no longer be stored from here.
USERNAME_RE = re.compile(r"^[a-z0-9_]{3,32}$")
# Payment PINs must be ASCII digits. str.isdigit() accepts Arabic-Indic and other
# Unicode digits, which bcrypt would store into pin_hash even though the server
# compares the submitted PIN as an ASCII string — leaving the account with a PIN
# that can never verify. Defined once, here, rather than re-declared mid-module.
PIN_RE = re.compile(r"^[0-9]{6}$")

ALL_CAPABILITIES = (
    CAP_USERS_CREDENTIALS,
    CAP_USERS_WRITE,
    CAP_USERS_PUNISH,
    CAP_USERS_VERIFY,
    CAP_USERS_GROUPS,
    CAP_DB_RESTORE,
    CAP_DB_BACKUP,
    CAP_SERVER_MANAGE,
    CAP_PLUGINS_WRITE,
    CAP_ADMINS_MANAGE,
)

# Human-readable labels for the account-management UI.
CAPABILITY_LABELS = {
    CAP_USERS_CREDENTIALS: "重置应用账号口令/PIN",
    CAP_USERS_WRITE: "创建/重命名/删除用户",
    CAP_USERS_PUNISH: "处罚、封禁、钱包与会员调整",
    CAP_USERS_VERIFY: "发放/撤销认证标记",
    CAP_USERS_GROUPS: "配置用户组权限",
    CAP_DB_RESTORE: "导入数据库备份",
    CAP_DB_BACKUP: "导出/下载/删除备份",
    CAP_SERVER_MANAGE: "启停与构建服务进程",
    CAP_PLUGINS_WRITE: "发布/下架插件",
    CAP_ADMINS_MANAGE: "管理面板账号",
}


def _current_admin_capabilities():
    """Return the capability set for the signed-in panel account.

    Returns None when the account cannot be read, which the callers treat as
    denial so a database problem never widens access.
    """
    admin_id = session.get("admin_id")
    if admin_id is None:
        return None
    row = db.fetch_one(
        "SELECT capabilities FROM admin_accounts WHERE id = %s", (admin_id,)
    )
    if not row:
        return None
    raw = row.get("capabilities") or ""
    caps = {c.strip() for c in raw.split(",") if c.strip()}
    if "*" in caps:
        return set(ALL_CAPABILITIES)
    return caps


def has_capability(cap):
    caps = _current_admin_capabilities()
    return caps is not None and cap in caps


def require_capability(cap):
    """Gate a view behind a named capability.

    can_verify was the panel's only secondary permission and was enforced on
    just two of its routes, so a "restricted" account could still reset any
    application account's password. This decorator is the explicit model that
    replaces guessing from a single boolean.
    """

    def decorator(view):
        @functools.wraps(view)
        def wrapped(*args, **kwargs):
            if session.get("admin_id") is None:
                return redirect(url_for("login"))
            if not has_capability(cap):
                app.logger.warning(
                    "capability denied: admin_id=%s capability=%s path=%s",
                    session.get("admin_id"),
                    cap,
                    request.path,
                )
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    return decorator


# ---------- CSRF protection ----------

def _ensure_csrf_token():
    """Return the per-session CSRF token, minting one on first use."""
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


@app.context_processor
def inject_csrf():
    # csrf_input expands to the hidden field every POST form must include.
    # Templates reference it as {{ csrf_input }} without call parentheses, so
    # it must be a pre-rendered Markup string: a bare callable renders as its
    # repr, the hidden field never appears and every POST fails CSRF checks.
    csrf_field = Markup(
        f'<input type="hidden" name="csrf_token" value="{_ensure_csrf_token()}">'
    )
    return {"csrf_input": csrf_field, "csrf_token": _ensure_csrf_token()}


@app.template_filter("from_json")
def from_json(value):
    """Parses a JSON string column (e.g. plugins.permissions) into a list."""
    if not value:
        return []
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, list) else []
    except (json.JSONDecodeError, TypeError):
        return []


@app.before_request
def csrf_protect():
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return None

    # Defense in depth 1: same-origin enforcement. A browser always sends
    # Origin (fetch/XHR and cross-site form posts) or at least Referer; a
    # mismatch proves the request was forged elsewhere.
    origin = request.headers.get("Origin", "")
    referer = request.headers.get("Referer", "")
    host = request.host
    for header_value in (origin, referer):
        if not header_value:
            continue
        parsed_host = urllib.parse.urlsplit(header_value).netloc
        if parsed_host and parsed_host != host:
            app.logger.warning(
                "blocked cross-origin %s from %s (host %s)",
                request.path, parsed_host, host,
            )
            abort(400)

    # Defense in depth 2: explicit per-session token. Blocks forged requests
    # even from clients that strip Origin/Referer.
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    expected = session.get("_csrf_token")
    if not expected or not sent or not secrets.compare_digest(sent, expected):
        app.logger.warning("blocked missing/invalid CSRF token for %s", request.path)
        abort(400)
    return None


# ---------- initialization ----------

def initialize_database():
    """Ensure the OpenField schema exists by running the Go server migrations.

    Only ever invoked from the database management panel. Re-running is safe
    (the server migrations use CREATE TABLE IF NOT EXISTS), so this can also
    repair a partially-initialized schema. Returns (ok, message).
    """
    status = db.schema_status()
    if status["ok"]:
        return True, "数据库已初始化"
    cfg = server_manager.load_config()
    try:
        with db.advisory_lock(config.DB_INIT_LOCK_ID):
            # Re-check inside the lock: another process may have finished first.
            if db.schema_status()["ok"]:
                return True, "数据库已初始化"
            ok, msg = server_manager.run_migrations(cfg)
            if ok:
                db.init_admin_table()
                db.invalidate_schema_status()
                app.logger.info("database initialized: %s", msg)
            else:
                app.logger.error("database initialization failed: %s", msg)
            return ok, msg
    except psycopg2.Error as e:
        return False, f"数据库连接失败: {e}"


@app.context_processor
def inject_db_status():
    return {"db_status": db.schema_status()}


@app.errorhandler(psycopg2.Error)
def handle_db_error(exc):
    """Any database error renders a friendly page instead of a crash."""
    app.logger.error("database error: %s", exc)
    return render_template("db_unavailable.html", error=str(exc)), 200


# ---------- auth ----------

def _session_admin():
    """Resolve the cookie's admin_id to a live, enabled account.

    Returns the admin row, or None when the session must be discarded. This is
    the revalidation that flask_login_required previously skipped entirely: the
    cookie asserted an admin_id and nothing ever checked that the account still
    exists, is still enabled, or still carries the session version it was issued
    with, so deleting or rotating an administrator's credentials left every
    session they held fully usable for as long as the cookie survived.
    """
    admin_id = session.get("admin_id")
    if admin_id is None:
        return None
    row = db.fetch_one(
        "SELECT id, username, capabilities, session_version, disabled "
        "FROM admin_accounts WHERE id = %s",
        (admin_id,),
    )
    if row is None or row.get("disabled"):
        return None
    # A cookie without a version predates this check (or was forged without
    # one); treat it as stale so such sessions are retired by the next login.
    if session.get("session_version") != row["session_version"]:
        return None
    return row


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("admin_id") is None:
            return redirect(url_for("login"))
        admin = _session_admin()
        if admin is None:
            # The account was deleted, disabled, or had its password rotated.
            session.clear()
            return redirect(url_for("login"))
        # Keep the display name in step with the row: it was frozen at login, so
        # audit entries written later could attribute an action to a stale name.
        if admin["username"] != session.get("admin_username"):
            session["admin_username"] = admin["username"]
        return view(*args, **kwargs)

    return wrapped


# ---------- login rate limiting ----------

_login_attempts_lock = threading.Lock()
_login_attempts = {}  # key -> list of failed-attempt timestamps
_LOGIN_WINDOW_SECONDS = 15 * 60
_LOGIN_MAX_FAILURES = 5

# A separate, looser per-source-address budget. Throttling only per
# (address, username) would let an attacker stay under the limit by rotating
# usernames, and throttling only per address is what made a proxy deployment
# lockable by anyone. Keeping both budgets independent means neither dimension
# can be used to deny service to everyone.
_LOGIN_MAX_FAILURES_PER_IP = 20

# Number of trusted reverse proxies in front of the panel. Only used to pick
# the real client address out of X-Forwarded-For; 0 means the panel is exposed
# directly and the header is ignored entirely.
_TRUSTED_PROXY_COUNT = int(os.environ.get("ADMIN_TRUSTED_PROXY_COUNT", "0") or 0)


def _client_ip():
    """Return the client address for rate limiting and audit logs.

    X-Forwarded-For is client-controlled unless a proxy actually overwrites
    it, so it is only consulted when the operator declares how many proxies to
    trust (ADMIN_TRUSTED_PROXY_COUNT). Counting from the right skips the hops
    our own proxies appended, which an attacker cannot forge.
    """
    if _TRUSTED_PROXY_COUNT > 0:
        xff = request.headers.get("X-Forwarded-For", "")
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if len(parts) >= _TRUSTED_PROXY_COUNT:
            return parts[-_TRUSTED_PROXY_COUNT]
    return request.remote_addr


def _page_param(name="page", default=1, maximum=100000):
    """Read a page number from the query string, clamped to a sane range.

    Client-supplied page numbers feed straight into OFFSET, and PostgreSQL
    produces and discards the skipped rows before returning any, so an unbounded
    value such as ?page=999999999 makes the server walk an enormous number of
    rows for a request that looks cheap. The floor keeps the arithmetic valid and
    the ceiling keeps the cost finite.
    """
    try:
        value = int(request.args.get(name, default))
    except (TypeError, ValueError):
        return default
    return max(1, min(value, maximum))


def _utcnow():
    """Current time as a timezone-aware UTC datetime.

    Always use this (or NOW() in SQL) when writing to a TIMESTAMPTZ column.
    A naive local datetime makes PostgreSQL apply the server's timezone offset,
    which shifted expiry timestamps by hours — enough for a short ban or
    membership to be stored already expired. The Go server works in UTC, so the
    panel matches it.
    """
    return datetime.datetime.now(datetime.timezone.utc)


def _is_usable_password_hash(value):
    """Report whether a users.password_hash can actually authenticate.

    The Go server verifies passwords with bcrypt.CompareHashAndPassword, so a
    value that is not a bcrypt hash fails every login regardless of what the
    user types. Treating any non-empty string as "has a password" would let an
    operator unbind the last OAuth identity from an account whose hash is a
    placeholder, locking it out permanently.
    """
    if not value:
        return False
    text = str(value).strip()
    # bcrypt hashes look like $2a$/$2b$/$2y$ + cost + 53 salt/hash characters.
    return bool(re.match(r"^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$", text))


def _finite_float(value, default=None):
    """Parse a form number, rejecting NaN, infinity and malformed input.

    float() accepts "nan" and "inf", so a try/except around it is not enough:
    the parse succeeds and the failure moves to the later int() conversion, which
    raises ValueError and surfaced as an unhandled HTTP 500 rather than a
    validation message. Return None for anything not finite so callers can flash
    a normal error.
    """
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    if not math.isfinite(parsed):
        return default
    return parsed


def _audit(action, target_type="", target_id="", detail=""):
    """Record a privileged panel action in admin_audit_log.

    Best-effort by design: a failure to write the trail must not abort the
    action the operator just performed, but it is logged loudly so a silently
    broken audit path is visible.
    """
    try:
        db.execute(
            """
            INSERT INTO admin_audit_log
                (actor_id, actor_username, action, target_type, target_id, detail, client_ip)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (
                session.get("admin_id"),
                session.get("admin_username", "") or "",
                action,
                target_type or "",
                str(target_id or ""),
                detail or "",
                (_client_ip() or "")[:64],
            ),
        )
    except Exception as exc:  # noqa: BLE001 - auditing must never break the action
        app.logger.error("failed to write audit entry for %s: %s", action, exc)


def _login_blocked(key):
    now = time.monotonic()
    with _login_attempts_lock:
        stamps = [t for t in _login_attempts.get(key, []) if now - t < _LOGIN_WINDOW_SECONDS]
        _login_attempts[key] = stamps
        return len(stamps) >= _LOGIN_MAX_FAILURES


def _login_blocked_ip(ip):
    now = time.monotonic()
    with _login_attempts_lock:
        key = f"ip:{ip}"
        stamps = [t for t in _login_attempts.get(key, []) if now - t < _LOGIN_WINDOW_SECONDS]
        _login_attempts[key] = stamps
        return len(stamps) >= _LOGIN_MAX_FAILURES_PER_IP


def _login_record_failure(key):
    now = time.monotonic()
    with _login_attempts_lock:
        stamps = [t for t in _login_attempts.get(key, []) if now - t < _LOGIN_WINDOW_SECONDS]
        stamps.append(now)
        _login_attempts[key] = stamps
        if key.startswith("ip:"):
            return
        ip_key = "ip:" + key.split("|", 1)[0]
        ip_stamps = [
            t for t in _login_attempts.get(ip_key, []) if now - t < _LOGIN_WINDOW_SECONDS
        ]
        ip_stamps.append(now)
        _login_attempts[ip_key] = ip_stamps


def _login_reset(key):
    with _login_attempts_lock:
        _login_attempts.pop(key, None)


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("admin_id") is not None:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        # Throttle online password guessing. The key must combine BOTH the
        # source address and the submitted username: `request.remote_addr or
        # "?" + "|" + username.lower()` was parsed as
        # `remote_addr or (("?" + "|") + username.lower())` because `+` binds
        # tighter than `or`, so whenever remote_addr was set the username was
        # dropped and the bucket became IP-only. Behind a reverse proxy every
        # client shares one address, so five failed logins from anyone locked
        # out every administrator for 15 minutes.
        ip = _client_ip() or "?"
        attempt_key = f"{ip}|{username.lower()}"
        if _login_blocked(attempt_key) or _login_blocked_ip(ip):
            flash("尝试次数过多，请稍后再试。", "error")
            return render_template("login.html"), 429
        admin = db.fetch_one(
            "SELECT id, username, password_hash, session_version, disabled "
            "FROM admin_accounts WHERE username = %s",
            (username,),
        )
        if admin and not admin.get("disabled") and bcrypt.checkpw(
            password.encode("utf-8"), admin["password_hash"].encode("utf-8")
        ):
            _login_reset(attempt_key)
            session.clear()  # rotate the session id on login (fixation defense)
            session["admin_id"] = admin["id"]
            session["admin_username"] = admin["username"]
            # Bind the cookie to this account's current credential generation so
            # a later password rotation can invalidate it.
            session["session_version"] = admin["session_version"]
            return redirect(url_for("dashboard"))
        _login_record_failure(attempt_key)
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    """End the session.

    This was a GET, which meant any page on the internet could sign the operator
    out with a single <img src="http://127.0.0.1:1343/logout"> while they were
    working — and because GET is outside the CSRF method whitelist, nothing
    checked where the request came from. Requiring POST brings it under the same
    CSRF protection as every other state change. The nav now submits a form
    carrying the token.
    """
    session.clear()
    return redirect(url_for("login"))


# ---------- dashboard ----------

@app.route("/")
@login_required
def dashboard():
    counts = {
        "users": db.fetch_one("SELECT COUNT(*) AS c FROM users")["c"],
        "posts": db.fetch_one("SELECT COUNT(*) AS c FROM posts")["c"],
        "messages": db.fetch_one("SELECT COUNT(*) AS c FROM messages")["c"],
        "attachments": db.fetch_one("SELECT COUNT(*) AS c FROM attachments")["c"],
        "admins": db.fetch_one("SELECT COUNT(*) AS c FROM users WHERE role = 'admin'")["c"],
        "pending": db.fetch_one(
            "SELECT COUNT(*) AS c FROM users WHERE needs_registration = TRUE"
        )["c"],
    }
    recent_users = db.fetch_all(
        "SELECT id, username, nickname, email, role, needs_registration, created_at "
        "FROM users ORDER BY created_at DESC LIMIT 8"
    )
    recent_posts = db.fetch_all(
        "SELECT p.id, p.content, p.created_at, u.username "
        "FROM posts p JOIN users u ON u.id = p.user_id ORDER BY p.created_at DESC LIMIT 8"
    )
    return render_template(
        "dashboard.html",
        counts=counts,
        recent_users=recent_users,
        recent_posts=recent_posts,
    )


# ---------- server management ----------

@app.route("/server")
@login_required
def server_page():
    cfg = server_manager.load_config()
    services = server_manager.refresh_status(cfg, server_manager.discover(cfg.get("server_root", "")))
    return render_template(
        "server.html",
        config=cfg,
        services=services,
        server_root=cfg.get("server_root", ""),
    )


# ---------- database management ----------

@app.route("/db")
@login_required
def db_page():
    return render_template(
        "db.html",
        db_status=db.schema_status(),
        backups=db_admin.list_backups(),
    )


@app.route("/db/init", methods=["POST"])
@login_required
@require_capability(CAP_DB_RESTORE)
def db_init():
    status = db.schema_status()
    if status["ok"]:
        flash("数据库已完整初始化，禁止重复初始化。如需恢复数据请使用「导入备份」。", "error")
        return redirect(url_for("db_page"))
    ok, msg = initialize_database()
    flash(msg, "success" if ok else "error")
    return redirect(url_for("db_page"))


@app.route("/db/export", methods=["POST"])
@login_required
@require_capability(CAP_DB_BACKUP)
def db_export():
    path, msg = db_admin.export_backup()
    flash(msg, "success" if path else "error")
    return redirect(url_for("db_page"))


@app.route("/db/import", methods=["POST"])
@login_required
@require_capability(CAP_DB_RESTORE)
def db_import():
    if request.form.get("confirm") != "1":
        flash("请勾选「我理解导入会覆盖当前数据」后再执行导入。", "error")
        return redirect(url_for("db_page"))
    file = request.files.get("file")
    if not file or not file.filename:
        flash("请选择要导入的备份文件（.sql）。", "error")
        return redirect(url_for("db_page"))
    if not file.filename.lower().endswith(".sql"):
        flash("仅支持从本面板导出的 .sql 备份文件。", "error")
        return redirect(url_for("db_page"))
    # The dump holds the entire database — every password hash, every private
    # message — and it used to be written straight into the shared temp
    # directory with default permissions via file.save(), where any other local
    # user could read it for the whole import window. Restrict the directory
    # rather than just the file: a world-readable directory lets a local attacker
    # merely LIST what is there and race the filename, while 0700 removes both.
    tmp_dir = tempfile.mkdtemp(prefix="openfield-import-")
    try:
        os.chmod(tmp_dir, 0o700)
    except OSError:
        pass
    tmp_path = os.path.join(tmp_dir, f"openfield-import-{uuid.uuid4().hex}.sql")
    try:
        # Create the file 0600 BEFORE writing content into it, so there is no
        # window in which it exists with wider permissions.
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            file.save(fh)
        db_admin._restrict_file(tmp_path)
        # Screen the upload before it can reach psql. The check is repeated
        # inside import_backup so no call path can skip it.
        sql_text = db_admin.read_import_file(tmp_path)
        if sql_text is None:
            flash("无法读取备份文件。", "error")
            return redirect(url_for("db_page"))
        reason = db_admin.screen_import_text(sql_text)
        if reason is not None:
            app.logger.warning("rejected db import: %s", reason)
            flash(reason, "error")
            return redirect(url_for("db_page"))
        ok, msg = db_admin.import_backup(tmp_path)
        if ok:
            db.invalidate_schema_status()
        flash(msg, "success" if ok else "error")
    except Exception as e:
        app.logger.error("failed to import backup: %s", e)
        flash(f"导入失败: {e}", "error")
    finally:
        # Remove the dump and its private directory even on the failure and
        # early-return paths above, so nothing is left behind after the import
        # window closes.
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        try:
            os.rmdir(tmp_dir)
        except OSError:
            pass
    return redirect(url_for("db_page"))


@app.route("/db/backups/<path:filename>/download", methods=["POST"])
@login_required
@require_capability(CAP_DB_BACKUP)
def db_backup_download(filename):
    # Downloading a dump hands over every credential hash in the database, so
    # it is a deliberate POST behind the CSRF token and an explicit
    # confirmation rather than a GET link that any injected image or
    # prefetching client could trigger silently.
    if request.form.get("confirm") != "1":
        flash("请确认后再下载备份：备份包含全部账号口令与令牌哈希。", "error")
        return redirect(url_for("db_page"))
    try:
        path = db_admin.backup_path(filename)
    except FileNotFoundError:
        abort(404)
    app.logger.warning(
        "database backup downloaded: admin_id=%s file=%s",
        session.get("admin_id"),
        os.path.basename(path),
    )
    return send_file(path, as_attachment=True, download_name=os.path.basename(path))


@app.route("/db/backups/<path:filename>/delete", methods=["POST"])
@login_required
@require_capability(CAP_DB_BACKUP)
def db_backup_delete(filename):
    try:
        db_admin.delete_backup(filename)
        flash(f"备份已删除: {os.path.basename(filename)}", "success")
    except FileNotFoundError:
        abort(404)
    return redirect(url_for("db_page"))


@app.route("/server/config", methods=["POST"])
@login_required
@require_capability(CAP_SERVER_MANAGE)
def server_config():
    cfg = server_manager.load_config()
    new_root = request.form.get("server_root", "").strip()
    if not new_root:
        flash("服务器根目录不能为空。", "error")
        return redirect(url_for("server_page"))

    # server_root decides which binaries the panel later executes
    # (<root>/bin/openfield-*) and where `go build` runs, so an unchecked
    # value is a direct path from a panel account to running an arbitrary
    # program: point it at any directory containing bin/openfield-gateway and
    # press start. Confine it to the configured base directory instead.
    ok, result = server_manager.validate_server_root(new_root)
    if not ok:
        flash(f"服务器根目录无效: {result}", "error")
        return redirect(url_for("server_page"))
    cfg["server_root"] = result
    server_manager.save_config(cfg)
    flash(f"服务器根目录已设置为: {result}", "success")
    return redirect(url_for("server_page"))


@app.route("/server/<service_name>/build", methods=["POST"])
@login_required
@require_capability(CAP_SERVER_MANAGE)
def server_build(service_name):
    cfg = server_manager.load_config()
    ok, msg = server_manager.build_service(cfg, service_name)
    flash(msg, "success" if ok else "error")
    return redirect(url_for("server_page"))


@app.route("/server/<service_name>/start", methods=["POST"])
@login_required
@require_capability(CAP_SERVER_MANAGE)
def server_start(service_name):
    cfg = server_manager.load_config()
    ok, msg = server_manager.start_service(cfg, service_name)
    flash(msg, "success" if ok else "error")
    return redirect(url_for("server_page"))


@app.route("/server/<service_name>/stop", methods=["POST"])
@login_required
@require_capability(CAP_SERVER_MANAGE)
def server_stop(service_name):
    cfg = server_manager.load_config()
    ok, msg = server_manager.stop_service(cfg, service_name)
    flash(msg, "success" if ok else "error")
    return redirect(url_for("server_page"))


@app.route("/server/start-all", methods=["POST"])
@login_required
@require_capability(CAP_SERVER_MANAGE)
def server_start_all():
    cfg = server_manager.load_config()
    errors = []
    started = 0
    for name in server_manager.SERVICES:
        ok, msg = server_manager.start_service(cfg, name)
        if ok:
            started += 1
        elif "已在运行" not in msg:
            errors.append(msg)
    if started:
        flash(f"已启动 {started} 个服务。", "success")
    for e in errors:
        flash(e, "error")
    return redirect(url_for("server_page"))


@app.route("/server/stop-all", methods=["POST"])
@login_required
@require_capability(CAP_SERVER_MANAGE)
def server_stop_all():
    cfg = server_manager.load_config()
    stopped = 0
    for name in list(cfg.get("pids", {}).keys()):
        ok, _ = server_manager.stop_service(cfg, name)
        if ok:
            stopped += 1
    flash(f"已停止 {stopped} 个服务。", "success")
    return redirect(url_for("server_page"))


# ---------- users ----------


def _level_costs():
    """Exp required to advance from level i+1 to i+2; each level costs 5% more
    than the previous, rounded to the nearest integer (matching the server)."""
    costs = []
    cost = 100
    for _ in range(200):
        costs.append(cost)
        cost = int(cost * 1.05 + 0.5)
    return costs


_LEVEL_COSTS = _level_costs()


def _cum_thresholds():
    """Total exp required to *reach* level i+1 (level 1 costs 0)."""
    thresholds = [0]
    for c in _LEVEL_COSTS:
        thresholds.append(thresholds[-1] + c)
    return thresholds


_CUM_THRESHOLDS = _cum_thresholds()


def level_for_exp(exp):
    """Derives a user level from lifetime exp, matching the server formula."""
    if not exp or exp <= 0:
        return 1
    lo, hi = 1, 200
    while lo <= hi:
        mid = (lo + hi) // 2
        if _CUM_THRESHOLDS[mid - 1] <= exp:
            lo = mid + 1
        else:
            hi = mid - 1
    return hi


TIERS = [
    (10, "出发", "#9E9E9E"), (20, "徒步", "#7CB342"), (30, "听风", "#42A5F5"),
    (40, "赤足", "#B7611A"), (50, "燃火", "#E64A19"), (60, "共行", "#FFB300"),
    (70, "迷途", "#9575CD"), (80, "自鸣", "#EC6B8F"), (90, "越岭", "#757575"),
    (100, "高原", "#2C3E70"), (110, "观星", "#5B2C8E"), (120, "入画", "#A1672C"),
    (130, "风蚀", "#D4B86A"), (140, "绿洲", "#2E8B57"), (150, "如石", "#37474F"),
    (160, "俯瞰", "#4A90D9"), (170, "合一", "#00C48C"), (180, "回响", "#D9A13E"),
    (190, "无名", "#1F1F1F"), (200, "源起", "#4A90D9"),
]


def tier_for_level(level):
    """Returns the (name, color) tier for a level, matching the client table."""
    for top, name, color in TIERS:
        if level <= top:
            return name, color
    return TIERS[-1][1], TIERS[-1][2]


MEMBER_TIER_NAMES = {
    1: "薄雾（Lv.1）",
    2: "篝火（Lv.2）",
    3: "明月（Lv.3）",
    4: "孤星（Lv.4）",
}


def member_status(member_level, member_expires_at, now=None):
    """Returns (active, tier_name) for a member level and expiry, or (False, None) if not a member."""
    level = member_level or 0
    if level <= 0:
        return False, None
    name = MEMBER_TIER_NAMES.get(level, f"Lv.{level}")
    if member_expires_at is None:
        return False, name
    now = now or datetime.datetime.now(datetime.timezone.utc)
    if member_expires_at.tzinfo is None:
        now = now.replace(tzinfo=None)
    return member_expires_at > now, name


@app.route("/users")
@login_required
def users():
    query = request.args.get("q", "").strip()
    per_page = 50
    page = _page_param()
    base_select = (
        "SELECT u.id, u.username, u.nickname, u.email, u.avatar_url, u.role, "
        "u.needs_registration, u.oauth2_provider, u.storage_quota, u.is_verified, "
        "u.verified_note, u.verified_by, u.exp, u.member_level, u.member_expires_at, "
        "u.status, u.banned_until, "
        "u.created_at, "
        "COALESCE((SELECT SUM(a.size_bytes) FROM attachments a WHERE a.user_id = u.id), 0) AS storage_used, "
        "COALESCE((SELECT w.balance FROM wallets w WHERE w.user_id = u.id), 0) AS wallet_balance "
        "FROM users u "
    )
    where = ""
    args = ()
    if query:
        like = f"%{query}%"
        where = (
            "WHERE u.username ILIKE %s OR u.nickname ILIKE %s OR u.email ILIKE %s "
        )
        args = (like, like, like)

    # The list used to be unbounded: every render loaded the whole users table
    # into memory, and each row carried two correlated subqueries (attachment
    # storage and wallet balance), so the cost grew with the table and a single
    # page view could exhaust the process on a large instance.
    total = db.fetch_one(
        f"SELECT COUNT(*) AS c FROM users u {where}", args
    )["c"]
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = min(page, total_pages)
    offset = (page - 1) * per_page

    rows = db.fetch_all(
        base_select + where + "ORDER BY u.created_at DESC LIMIT %s OFFSET %s",
        args + (per_page, offset),
    )
    _row_levels(rows)
    return render_template(
        "users.html",
        users=rows,
        query=query,
        page=page,
        per_page=per_page,
        total=total,
        total_pages=total_pages,
    )


def _row_levels(rows):
    """Attach the derived level/tier/membership fields the list templates show."""
    for row in rows:
        row["level"] = level_for_exp(row.get("exp"))
        row["tier_name"], row["tier_color"] = tier_for_level(row["level"])
        row["member_active"], row["member_tier_name"] = member_status(
            row.get("member_level"), row.get("member_expires_at")
        )


@app.route("/users/<int:user_id>/quota", methods=["POST"])
@login_required
@require_capability(CAP_USERS_PUNISH)
def user_quota(user_id):
    user = db.fetch_one("SELECT id FROM users WHERE id = %s", (user_id,))
    if not user:
        abort(404)
    raw = request.form.get("quota_mb", "")
    quota_mb = _finite_float(raw)
    if quota_mb is None:
        flash("配额必须是有效的数字。", "error")
        return redirect(url_for("users"))
    if quota_mb <= 0:
        flash("Quota must be greater than 0.", "error")
        return redirect(url_for("users"))
    quota_bytes = int(quota_mb * 1024 * 1024)
    db.execute(
        "UPDATE users SET storage_quota = %s, updated_at = NOW() WHERE id = %s",
        (quota_bytes, user_id),
    )
    flash("Storage quota updated.", "success")
    return redirect(url_for("users"))


@app.route("/users/new", methods=["GET", "POST"])
@login_required
@require_capability(CAP_USERS_WRITE)
def user_new():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        nickname = request.form.get("nickname", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "user")
        if not username or not nickname or not password:
            flash("Username, nickname and password are required.", "error")
        elif not USERNAME_RE.match(username):
            flash(
                "Username must be 3-32 characters of lowercase letters, digits "
                "or underscores.",
                "error",
            )
        elif db.fetch_one("SELECT id FROM users WHERE username = %s", (username,)):
            flash("Username already taken.", "error")
        else:
            password_hash = bcrypt.hashpw(
                password.encode("utf-8"), bcrypt.gensalt()
            ).decode("utf-8")
            try:
                db.execute(
                    "INSERT INTO users (username, nickname, email, role, password_hash, "
                    "needs_registration, oauth2_provider) "
                    "VALUES (%s, %s, %s, %s, %s, FALSE, '')",
                    (username, nickname, email, role, password_hash),
                )
                flash(f"User '{username}' created.", "success")
                return redirect(url_for("users"))
            except Exception as e:
                app.logger.error("failed to create user: %s", e)
                flash("Failed to create user.", "error")
    return render_template("user_new.html")


@app.route("/users/<int:user_id>/wallet", methods=["POST"])
@login_required
@require_capability(CAP_USERS_PUNISH)
def user_wallet(user_id):
    user = db.fetch_one("SELECT id, username FROM users WHERE id = %s", (user_id,))
    if not user:
        abort(404)
    amount = _finite_float(request.form.get("amount", ""))
    if amount is None:
        flash("金额必须是有效的数字。", "error")
        return redirect(url_for("users"))
    if amount == 0:
        flash("Amount must not be zero.", "error")
        return redirect(url_for("users"))
    amount_cents = int(amount * 100)
    if amount_cents == 0:
        # A value smaller than one cent (for example 0.001) truncates to zero.
        # Writing that produced a wallet transaction that moved nothing while the
        # panel reported a successful adjustment.
        flash("金额过小（最小 0.01）。", "error")
        return redirect(url_for("users"))
    description = request.form.get("description", "").strip() or (
        "管理员充值" if amount_cents > 0 else "管理员扣款"
    )
    tx_type = "recharge" if amount_cents > 0 else "deduct"
    admin_name = session.get("admin_username", "")
    try:
        # mirror the server-side wallet adjustment in a transaction
        conn = db.connect()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO wallets (user_id, balance) VALUES (%s, 0) "
                    "ON CONFLICT (user_id) DO NOTHING",
                    (user_id,),
                )
                cur.execute(
                    "SELECT balance FROM wallets WHERE user_id = %s FOR UPDATE",
                    (user_id,),
                )
                balance = cur.fetchone()[0]
                new_balance = balance + amount_cents
                if new_balance < 0:
                    flash("Insufficient balance for deduction.", "error")
                    return redirect(url_for("users"))
                cur.execute(
                    "UPDATE wallets SET balance = %s, updated_at = NOW() WHERE user_id = %s",
                    (new_balance, user_id),
                )
                # Link the operator to a users row when the admin account shares
                # a username; otherwise leave operator_id NULL (the FK points to
                # users(id)) and record the admin account name for the audit log.
                cur.execute(
                    "SELECT id FROM users WHERE username = %s LIMIT 1",
                    (admin_name,),
                )
                op_row = cur.fetchone()
                operator_id = op_row[0] if op_row else None
                cur.execute(
                    "INSERT INTO wallet_transactions "
                    "(user_id, amount, balance_after, type, description, operator_id, operator_username) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (user_id, amount_cents, new_balance, tx_type, description, operator_id, admin_name),
                )
                conn.commit()
        finally:
            conn.close()
        flash(f"Wallet updated for '{user['username']}' ({amount_cents / 100:+.2f}).", "success")
    except Exception as e:
        app.logger.error("failed to adjust wallet: %s", e)
        flash("Failed to adjust wallet.", "error")
    return redirect(url_for("users"))


@app.route("/users/<int:user_id>/wallet/history")
@login_required
def user_wallet_history(user_id):
    user = db.fetch_one(
        "SELECT u.id, u.username, u.nickname, "
        "COALESCE((SELECT w.balance FROM wallets w WHERE w.user_id = u.id), 0) AS balance "
        "FROM users u WHERE u.id = %s",
        (user_id,),
    )
    if not user:
        abort(404)
    per_page = 20
    total = db.fetch_one(
        "SELECT COUNT(*) AS c FROM wallet_transactions WHERE user_id = %s",
        (user_id,),
    )["c"]
    total_pages = max(1, (total + per_page - 1) // per_page)
    # Bounded by the real page count, and by _page_param's own ceiling so the
    # floor is applied consistently before the two are combined.
    page = min(_page_param(), total_pages)
    offset = (page - 1) * per_page
    txns = db.fetch_all(
        "SELECT id, amount, balance_after, type, description, operator_id, "
        "operator_username, created_at "
        "FROM wallet_transactions WHERE user_id = %s "
        "ORDER BY id DESC LIMIT %s OFFSET %s",
        (user_id, per_page, offset),
    )
    return render_template(
        "wallet_history.html",
        user=user,
        txns=txns,
        page=page,
        total_pages=total_pages,
        total=total,
    )


@app.route("/users/<int:user_id>/membership", methods=["POST"])
@login_required
@require_capability(CAP_USERS_PUNISH)
def user_membership(user_id):
    user = db.fetch_one("SELECT id, username FROM users WHERE id = %s", (user_id,))
    if not user:
        abort(404)
    try:
        level = int(request.form.get("level", "0"))
    except ValueError:
        flash("Invalid membership level.", "error")
        return redirect(url_for("users"))
    if level < 0 or level > 4:
        flash("Membership level must be between 0 and 4.", "error")
        return redirect(url_for("users"))
    if level == 0:
        db.execute(
            "UPDATE users SET member_level = 0, member_expires_at = NULL, "
            "updated_at = NOW() WHERE id = %s",
            (user_id,),
        )
        flash(f"已清除 {user['username']} 的会员。", "success")
        return redirect(url_for("users"))
    days_text = request.form.get("days", "").strip()
    try:
        days = int(days_text) if days_text else 30
    except ValueError:
        flash("Invalid days value.", "error")
        return redirect(url_for("users"))
    if days <= 0:
        flash("Days must be greater than 0.", "error")
        return redirect(url_for("users"))
    # member_expires_at is TIMESTAMPTZ; a naive local value would be read in the
    # database's timezone and land hours off — for a 1-day grant that can mean
    # the membership is already expired. Use aware UTC like the Go server.
    expires_at = _utcnow() + datetime.timedelta(days=days)
    db.execute(
        "UPDATE users SET member_level = %s, member_expires_at = %s, "
        "updated_at = NOW() WHERE id = %s",
        (level, expires_at, user_id),
    )
    flash(f"已授予 {user['username']} {MEMBER_TIER_NAMES.get(level, f'Lv.{level}')} 会员 ({days} 天)。", "success")
    return redirect(url_for("users"))


@app.route("/users/<int:user_id>/role", methods=["POST"])
@login_required
@require_capability(CAP_USERS_WRITE)
def user_role(user_id):
    role = request.form.get("role", "user")
    if role not in ("user", "admin"):
        abort(400)
    user = db.fetch_one("SELECT id FROM users WHERE id = %s", (user_id,))
    if not user:
        abort(404)
    db.execute("UPDATE users SET role = %s, updated_at = NOW() WHERE id = %s", (role, user_id))
    flash("Role updated.", "success")
    return redirect(url_for("users"))


@app.route("/users/<int:user_id>/punish", methods=["POST"])
@login_required
@require_capability(CAP_USERS_PUNISH)
def user_punish(user_id):
    """Record a moderation action and apply its side effects.

    Types mirror the server's model.PunishmentType:
      warning    - 警告：仅记录
      demerit    - 记过：仅记录（可多次累加）
      revoke     - 剥夺权限：需指定 permission_key
      temp_ban   - 暂时封禁：需指定 hours 时长
      ban        - 永久封禁
      unban      - 解除封禁（并清除所有权限封禁）
      restore    - 恢复权限：需指定 permission_key
    """
    user = db.fetch_one("SELECT id, username FROM users WHERE id = %s", (user_id,))
    if not user:
        abort(404)
    ptype = request.form.get("type", "").strip()
    reason = request.form.get("reason", "").strip()
    if ptype not in ("warning", "demerit", "revoke", "temp_ban", "ban", "unban", "restore"):
        flash("Unknown punishment type.", "error")
        return redirect(url_for("users"))

    if ptype in ("revoke", "restore"):
        perm_key = request.form.get("permission_key", "").strip()
        if not perm_key:
            flash("请选择要剥夺 / 恢复的权限。", "error")
            return redirect(url_for("users"))
    else:
        perm_key = ""

    expires_at = None
    if ptype == "temp_ban":
        try:
            hours = float(request.form.get("hours", "").strip())
        except ValueError:
            flash("请输入有效的封禁时长。", "error")
            return redirect(url_for("users"))
        if hours <= 0:
            flash("封禁时长必须大于 0。", "error")
            return redirect(url_for("users"))
        # banned_until is a TIMESTAMPTZ column. datetime.now() returns a NAIVE
        # local time; writing one into a timestamptz column makes PostgreSQL
        # interpret it in the server's timezone, so on a host whose local time
        # is ahead of the database's a short ban was stored already expired and
        # silently had no effect. Use an aware UTC value, matching the Go
        # server's convention ("NOW()" / time.Now().UTC()).
        expires_at = _utcnow() + datetime.timedelta(hours=hours)

    # The history row and its side effects must land together: previously each
    # statement ran on its own autocommit connection, so a failure partway
    # through committed a punishment record whose side effect never applied
    # (or, worse for unban, cleared the ban without recording it).
    with db.transaction() as cur:
        cur.execute(
            "INSERT INTO user_punishments "
            "(user_id, operator_id, operator_username, type, permission_key, reason, expires_at) "
            "VALUES (%s, NULL, %s, %s, %s, %s, %s)",
            (
                user_id,
                session.get("admin_username") or "",
                ptype,
                perm_key,
                reason,
                expires_at,
            ),
        )
        if ptype == "revoke":
            cur.execute(
                "INSERT INTO user_permission_bans (user_id, permission_key, reason) "
                "VALUES (%s, %s, %s) ON CONFLICT (user_id, permission_key) "
                "DO UPDATE SET reason = EXCLUDED.reason",
                (user_id, perm_key, reason),
            )
        elif ptype == "temp_ban":
            cur.execute(
                "UPDATE users SET status = 'banned', banned_until = %s, updated_at = NOW() WHERE id = %s",
                (expires_at, user_id),
            )
        elif ptype == "ban":
            cur.execute(
                "UPDATE users SET status = 'banned', banned_until = NULL, updated_at = NOW() WHERE id = %s",
                (user_id,),
            )
        elif ptype == "unban":
            cur.execute(
                "UPDATE users SET status = 'active', banned_until = NULL, updated_at = NOW() WHERE id = %s",
                (user_id,),
            )
            cur.execute("DELETE FROM user_permission_bans WHERE user_id = %s", (user_id,))
        elif ptype == "restore":
            cur.execute(
                "DELETE FROM user_permission_bans WHERE user_id = %s AND permission_key = %s",
                (user_id, perm_key),
            )

    _audit(
        f"user.punish.{ptype}",
        target_type="user",
        target_id=user_id,
        detail=f"{ptype} on {user['username']}"
        + (f" ({reason})" if reason else "")
        + (f" until {expires_at.isoformat()}" if expires_at else "")
        + (f" perm={perm_key}" if perm_key else ""),
    )

    if ptype == "temp_ban":
        flash(f"已暂时封禁 {user['username']} {hours:g} 小时。", "success")
    elif ptype == "ban":
        flash(f"已永久封禁 {user['username']}。", "success")
    elif ptype == "unban":
        flash(f"已解除封禁 {user['username']}。", "success")
    else:
        flash(f"已对 {user['username']} 执行「{ptype}」。", "success")
    return redirect(url_for("user_punishment_history", user_id=user_id))


@app.route("/users/<int:user_id>/punishments")
@login_required
def user_punishment_history(user_id):
    user = db.fetch_one(
        "SELECT id, username, nickname, status, banned_until FROM users WHERE id = %s",
        (user_id,),
    )
    if not user:
        abort(404)
    rows = db.fetch_all(
        "SELECT p.id, p.type, p.permission_key, p.reason, p.expires_at, p.created_at, "
        "       COALESCE(op.username, '系统') AS operator "
        "FROM user_punishments p "
        "LEFT JOIN users op ON op.id = p.operator_id "
        "WHERE p.user_id = %s ORDER BY p.id DESC",
        (user_id,),
    )
    perm_rows = db.fetch_all(
        "SELECT permission_key, reason, created_at FROM user_permission_bans "
        "WHERE user_id = %s ORDER BY created_at DESC",
        (user_id,),
    )
    for r in rows:
        r["type_label"] = {
            "warning": "警告",
            "demerit": "记过",
            "revoke": "剥夺权限",
            "temp_ban": "暂时封禁",
            "ban": "永久封禁",
            "unban": "解除封禁",
            "restore": "恢复权限",
        }.get(r["type"], r["type"])
    return render_template(
        "user_punishments.html",
        user=user,
        punishments=rows,
        permission_bans=perm_rows,
        permission_keys=_all_permission_keys(),
    )


@app.route("/admins")
@login_required
def admins():
    admins = db.fetch_all(
        "SELECT id, username, can_verify, capabilities, created_at, disabled, session_version "
        "FROM admin_accounts ORDER BY id ASC"
    )
    for a in admins:
        raw = a.get("capabilities") or ""
        caps = {c.strip() for c in raw.split(",") if c.strip()}
        a["cap_list"] = sorted(caps)
        a["is_super"] = "*" in caps
    return render_template(
        "admins.html",
        admins=admins,
        all_capabilities=ALL_CAPABILITIES,
        capability_labels=CAPABILITY_LABELS,
        password_policy_hint="至少 12 位，需同时包含字母与数字。",
    )


@app.route("/audit")
@login_required
@require_capability(CAP_ADMINS_MANAGE)
def audit_log():
    """Recent privileged panel actions, newest first."""
    try:
        limit = max(1, min(int(request.args.get("limit", 200)), 1000))
    except (TypeError, ValueError):
        limit = 200
    rows = db.fetch_all(
        "SELECT created_at, actor_username, action, target_type, target_id, detail, client_ip "
        "FROM admin_audit_log ORDER BY created_at DESC LIMIT %s",
        (limit,),
    )
    return render_template("audit.html", entries=rows, limit=limit)


@app.route("/admins/<int:admin_id>/capabilities", methods=["POST"])
@login_required
@require_capability(CAP_ADMINS_MANAGE)
def admin_capabilities(admin_id):
    admin = db.fetch_one("SELECT id FROM admin_accounts WHERE id = %s", (admin_id,))
    if not admin:
        abort(404)

    selected = [c for c in request.form.getlist("capabilities") if c in ALL_CAPABILITIES]
    # Same checkbox convention as the verification toggle: a ticked box sends its
    # value attribute ("on"), not necessarily "1".
    if _form_checkbox(request.form.get("is_super")):
        caps = "*"
    else:
        caps = ",".join(sorted(selected))

    # An account holding admins.manage could otherwise strip its own access and
    # permanently lock every operator out of the panel, so refuse the change
    # when it would leave nobody able to manage accounts.
    if admin_id == session.get("admin_id") and not _cap_string_has(caps, CAP_ADMINS_MANAGE):
        if not _other_admin_can_manage(session.get("admin_id")):
            flash("不能移除自己最后一个「管理面板账号」权限。", "error")
            return redirect(url_for("admins"))

    db.execute(
        "UPDATE admin_accounts SET capabilities = %s WHERE id = %s", (caps, admin_id)
    )
    # Keep can_verify in step with the capability so the older verification
    # UI and the new model cannot disagree.
    db.execute(
        "UPDATE admin_accounts SET can_verify = %s WHERE id = %s",
        (_cap_string_has(caps, CAP_USERS_VERIFY), admin_id),
    )
    flash("账号权限已更新。", "success")
    return redirect(url_for("admins"))


def _cap_string_has(caps, cap):
    if caps == "*":
        return True
    return cap in {c.strip() for c in (caps or "").split(",") if c.strip()}


def _other_admin_can_manage(exclude_admin_id):
    """Report whether another account can still manage panel accounts."""
    rows = db.fetch_all(
        "SELECT id, capabilities FROM admin_accounts WHERE id <> %s", (exclude_admin_id,)
    )
    return any(_cap_string_has(r.get("capabilities") or "", CAP_ADMINS_MANAGE) for r in rows)


@app.route("/admins/<int:admin_id>/can-verify", methods=["POST"])
@login_required
@require_capability(CAP_ADMINS_MANAGE)
def admin_can_verify(admin_id):
    """Grant or revoke the verification capability for a panel account.

    This read `request.form.get("can_verify") == "1"`, but an HTML checkbox
    submits its `value` attribute — conventionally "on" — and omits the field
    entirely when unchecked. So a checked box compared against "1" produced
    False: ticking it revoked the permission it was meant to grant, and
    unticking it revoked it too. The toggle was inverted, and the result was
    written straight to can_verify, so the column silently disagreed with what
    the operator asked for.

    Accept the checkbox convention (any of the truthy values a browser can send)
    and treat an absent field as False, which is what "unchecked" means.
    """
    admin = db.fetch_one(
        "SELECT id, username, capabilities FROM admin_accounts WHERE id = %s",
        (admin_id,),
    )
    if not admin:
        abort(404)

    raw = request.form.get("can_verify")
    can_verify = _form_checkbox(raw)

    caps = {c.strip() for c in (admin.get("capabilities") or "").split(",") if c.strip()}
    # Super accounts hold '*' which already implies every capability; adding a
    # key would be meaningless and removing one would not restrict them.
    if "*" in caps:
        new_caps = "*"
    else:
        if can_verify:
            caps.add(CAP_USERS_VERIFY)
        else:
            caps.discard(CAP_USERS_VERIFY)
        new_caps = ",".join(sorted(caps))

    # can_verify and the capability list are two views of one fact, so write
    # them together rather than in two autocommitted statements that could
    # disagree if the second failed.
    with db.transaction() as cur:
        cur.execute(
            "UPDATE admin_accounts SET can_verify = %s, capabilities = %s WHERE id = %s",
            (can_verify, new_caps, admin_id),
        )

    _audit(
        "admin.can_verify",
        target_type="admin",
        target_id=admin_id,
        detail=f"{admin['username']}: can_verify={can_verify}",
    )
    flash(
        f"已{'授予' if can_verify else '撤销'} {admin['username']} 的认证权限。",
        "success",
    )
    return redirect(url_for("admins"))


def _form_checkbox(value):
    """Interpret a form value as a checkbox state.

    Returns True for the values a browser actually submits for a ticked box and
    False for anything else, including a missing field. Centralised because
    comparing against a single literal is how the verification toggle came to
    invert its meaning.
    """
    if value is None:
        return False
    return str(value).strip().lower() in ("1", "on", "true", "yes")


def _revoke_sessions(admin_id):
    """Invalidate every live session for an account.

    Bumping session_version makes each existing cookie fail the check in
    login_required on its next request. This is what makes a credential change
    actually terminate access rather than leaving the old cookie usable.
    """
    db.execute(
        "UPDATE admin_accounts SET session_version = session_version + 1 WHERE id = %s",
        (admin_id,),
    )


@app.route("/admins/<int:admin_id>/password", methods=["POST"])
@login_required
@require_capability(CAP_ADMINS_MANAGE)
def admin_set_password(admin_id):
    """Rotate a panel account's password and end its live sessions."""
    admin = db.fetch_one("SELECT id, username FROM admin_accounts WHERE id = %s", (admin_id,))
    if not admin:
        abort(404)

    password = request.form.get("password", "")
    confirm = request.form.get("password_confirm", "")
    if password != confirm:
        flash("两次输入的口令不一致。", "error")
        return redirect(url_for("admins"))
    problem = _password_policy_error(password)
    if problem:
        flash(problem, "error")
        return redirect(url_for("admins"))

    db.execute(
        "UPDATE admin_accounts SET password_hash = %s WHERE id = %s",
        (bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8"), admin_id),
    )
    _revoke_sessions(admin_id)
    _audit(
        "admin.password_rotate",
        target_type="admin",
        target_id=str(admin_id),
        detail=f"rotated password for panel account {admin['username']}",
    )
    if admin_id == session.get("admin_id"):
        # Our own session was just revoked; ask the operator to log in again
        # rather than leaving them on a page that will redirect on next click.
        session.clear()
        flash("口令已更新，请重新登录。", "success")
        return redirect(url_for("login"))
    flash(f"已重置 {admin['username']} 的口令，其所有会话已失效。", "success")
    return redirect(url_for("admins"))


@app.route("/admins/<int:admin_id>/disabled", methods=["POST"])
@login_required
@require_capability(CAP_ADMINS_MANAGE)
def admin_set_disabled(admin_id):
    """Enable or disable a panel account, ending its sessions when disabled."""
    admin = db.fetch_one("SELECT id, username FROM admin_accounts WHERE id = %s", (admin_id,))
    if not admin:
        abort(404)

    disabled = request.form.get("disabled") == "1"
    if disabled and admin_id == session.get("admin_id"):
        flash("不能停用当前登录的账号。", "error")
        return redirect(url_for("admins"))
    # Disabling the last account that can manage panel accounts would lock every
    # operator out permanently, the same hazard the capability check guards.
    if disabled and not _other_admin_can_manage(admin_id):
        flash("不能停用最后一个可管理面板账号的账号。", "error")
        return redirect(url_for("admins"))

    db.execute(
        "UPDATE admin_accounts SET disabled = %s WHERE id = %s", (disabled, admin_id)
    )
    if disabled:
        _revoke_sessions(admin_id)
    _audit(
        "admin.disable" if disabled else "admin.enable",
        target_type="admin",
        target_id=str(admin_id),
        detail=f"{'disabled' if disabled else 'enabled'} panel account {admin['username']}",
    )
    flash("账号状态已更新。" + ("其所有会话已失效。" if disabled else ""), "success")
    return redirect(url_for("admins"))


def _password_policy_error(password):
    """Return a message when a password is unacceptable, else None.

    The seed script enforced nothing, so an administrator account could be
    created with a one-character password; applying the same rule to rotation
    keeps the two paths consistent.
    """
    if len(password) < 12:
        return "口令至少需要 12 个字符。"
    if len(password) > 256:
        return "口令过长（最多 256 个字符）。"
    if password.strip() != password:
        return "口令首尾不能有空白字符。"
    if not any(c.isalpha() for c in password) or not any(c.isdigit() for c in password):
        return "口令需同时包含字母与数字。"
    return None


@app.route("/users/<int:user_id>/verified", methods=["POST"])
@login_required
@require_capability(CAP_USERS_VERIFY)
def user_verified(user_id):
    user = db.fetch_one(
        "SELECT id, username, is_verified, verified_by, verified_note FROM users WHERE id = %s",
        (user_id,),
    )
    if not user:
        abort(404)

    # The checkbox is the authority on the badge. This used to force verified
    # back to True whenever the verified_by/verified_note fields were non-empty
    # — but the modal backfills both from the current row, so they were ALWAYS
    # non-empty for a user who had ever been verified. Unticking the box could
    # therefore never revoke the mark: the operator unchecked it, submitted, and
    # the badge stayed.
    verified = _form_checkbox(request.form.get("verified"))
    verified_by = request.form.get("verified_by", "").strip()
    verified_note = request.form.get("verified_note", "").strip()

    if verified:
        # A verified account with no stated subject still needs one so the badge
        # has something to show.
        if not verified_by:
            verified_by = "admin"
    else:
        # Revoking clears the supporting detail too, so a later re-verification
        # cannot silently resurrect stale text that was never re-confirmed.
        verified_by = ""
        verified_note = ""

    db.execute(
        "UPDATE users SET is_verified = %s, verified_by = %s, verified_note = %s, "
        "updated_at = NOW() WHERE id = %s",
        (verified, verified_by, verified_note, user_id),
    )
    _audit(
        "user.verify" if verified else "user.unverify",
        target_type="user",
        target_id=user_id,
        detail=f"{user['username']}: is_verified={verified}"
        + (f" by={verified_by}" if verified_by else ""),
    )
    flash(
        f"已{'授予' if verified else '撤销'} {user['username']} 的认证标记。",
        "success",
    )
    return redirect(url_for("users"))


@app.route("/users/<int:user_id>/reset-password", methods=["POST"])
@login_required
@require_capability(CAP_USERS_CREDENTIALS)
def user_reset_password(user_id):
    user = db.fetch_one("SELECT id, username FROM users WHERE id = %s", (user_id,))
    if not user:
        abort(404)
    password = request.form.get("password", "")
    if not password:
        flash("Password is required.", "error")
    else:
        password_hash = bcrypt.hashpw(
            password.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")
        # Rotating a password must end the sessions that were opened with the
        # old one. Refresh tokens are valid for 30 days and are stored
        # independently of the password (refresh_tokens, pkg/repository/
        # session.go), so without this an operator resetting a compromised
        # account's password left the attacker's session working for another
        # month — the reset looked like it worked and had no effect on access.
        with db.transaction() as cur:
            cur.execute(
                "UPDATE users SET password_hash = %s, updated_at = NOW() WHERE id = %s",
                (password_hash, user_id),
            )
            cur.execute("DELETE FROM refresh_tokens WHERE user_id = %s", (user_id,))
        _audit(
            "user.password_reset",
            target_type="user",
            target_id=user_id,
            detail=f"reset password for {user['username']}; sessions revoked",
        )
        flash(
            f"Password for '{user['username']}' updated; existing sessions revoked.",
            "success",
        )
    return redirect(url_for("users"))


@app.route("/users/<int:user_id>/rename", methods=["POST"])
@login_required
@require_capability(CAP_USERS_WRITE)
def user_rename(user_id):
    """Change a user's username (the only rename path: registration sets it
    once and clients cannot rename themselves). Enforces the same rule as
    registration: 3-32 lowercase letters, digits or underscores."""
    user = db.fetch_one("SELECT id, username FROM users WHERE id = %s", (user_id,))
    if not user:
        abort(404)
    username = (request.form.get("username") or "").strip()
    if not USERNAME_RE.match(username):
        flash("用户名只能包含 3-32 个小写字母、数字或下划线。", "error")
        return redirect(url_for("users"))
    existing = db.fetch_one("SELECT id FROM users WHERE username = %s AND id <> %s", (username, user_id))
    if existing:
        flash(f"用户名 '{username}' 已被占用。", "error")
        return redirect(url_for("users"))
    db.execute(
        "UPDATE users SET username = %s, updated_at = NOW() WHERE id = %s",
        (username, user_id),
    )
    flash(f"已将 '{user['username']}' 的用户名改为 '{username}'。", "success")
    return redirect(url_for("users"))


@app.route("/users/<int:user_id>/reset-pin", methods=["POST"])
@login_required
@require_capability(CAP_USERS_CREDENTIALS)
def user_reset_pin(user_id):
    user = db.fetch_one("SELECT id, username FROM users WHERE id = %s", (user_id,))
    if not user:
        abort(404)
    pin = (request.form.get("pin") or "").strip()
    # str.isdigit() is true for non-ASCII digits — Arabic-Indic '٣', Devanagari
    # '३', superscripts like '²' — which bcrypt happily hashes into pin_hash.
    # The client posts PIN digits from an ASCII keypad and the server compares
    # them as an ASCII string, so a PIN stored from those codepoints can never be
    # verified: the account is left with a payment PIN that always fails, with no
    # way to tell from the panel that anything went wrong. Require ASCII digits.
    if not PIN_RE.match(pin):
        flash("支付PIN必须是6位ASCII数字（0-9）。", "error")
        return redirect(url_for("users"))

    # Replacing someone's payment PIN is a credential change on their account,
    # so it is recorded: the panel had no audit log at all before this round,
    # which meant an administrator could reset a PIN and leave no trace.
    pin_hash = bcrypt.hashpw(pin.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    db.execute(
        "UPDATE users SET pin_hash = %s, updated_at = NOW() WHERE id = %s",
        (pin_hash, user_id),
    )
    _audit(
        "user.reset_pin",
        target_type="user",
        target_id=user_id,
        detail=f"reset payment PIN for {user['username']}",
    )
    flash(f"已重置 '{user['username']}' 的支付PIN。", "success")
    return redirect(url_for("users"))


@app.route("/users/<int:user_id>/delete", methods=["POST"])
@login_required
@require_capability(CAP_USERS_WRITE)
def user_delete(user_id):
    """Soft-delete a user, matching the server's account-deletion lifecycle.

    This route used to run a plain DELETE FROM users. The server models account
    deletion as a soft delete (users.deleted_at) with a grace period, after which
    a background purge removes the data — RequestAccountDeletion and
    ListPurgeableUsers in pkg/repository/session.go. Hard-deleting from the panel
    bypassed that lifecycle entirely: the row vanished immediately with no grace
    period and no recovery, and any plain DELETE of the row left the dependent
    rows (sessions, posts, attachments, ...) dangling.

    The self-deletion guard was also a no-op — `if user_id ==
    session.get("admin_id"): pass` compared a users.id against an
    admin_accounts.id, which are unrelated sequences, and then did nothing in
    either case. The panel session holds an admin account, not an application
    user, so there is no legitimate "current user" to compare against here; the
    operation is simply recorded against the acting administrator instead.
    """
    user = db.fetch_one(
        "SELECT id, username, deleted_at FROM users WHERE id = %s", (user_id,)
    )
    if not user:
        abort(404)

    if user["deleted_at"] is not None:
        flash("该账号已处于删除宽限期，无需重复删除。", "info")
        return redirect(url_for("users"))

    # Soft delete: mark it, and drop the refresh tokens so access ends
    # immediately rather than at natural token expiry.
    with db.transaction() as cur:
        cur.execute(
            "UPDATE users SET deleted_at = NOW(), updated_at = NOW() "
            "WHERE id = %s AND deleted_at IS NULL",
            (user_id,),
        )
        cur.execute("DELETE FROM refresh_tokens WHERE user_id = %s", (user_id,))

    _audit(
        "user.delete",
        target_type="user",
        target_id=user_id,
        detail=f"soft-deleted {user['username']} (grace period before purge)",
    )
    flash(
        f"已标记删除 '{user['username']}'（软删除，宽限期结束后由服务端清理数据）。",
        "success",
    )
    return redirect(url_for("users"))


@app.route("/users/<int:user_id>/unbind-oauth", methods=["POST"])
@login_required
@require_capability(CAP_USERS_CREDENTIALS)
def user_unbind_oauth(user_id):
    user = db.fetch_one(
        "SELECT id, username, password_hash, needs_registration, oauth2_provider "
        "FROM users WHERE id = %s",
        (user_id,),
    )
    if not user:
        abort(404)

    # An account needs at least one usable credential. Unbinding the last OAuth
    # identity from an account with no password left it permanently unable to
    # log in: the server authenticates by bcrypt-comparing password_hash
    # (services/account/internal/handler/auth.go) or by an OAuth identity, and
    # with both gone there is no route back in short of direct database surgery.
    # Check that the stored hash is actually a bcrypt hash rather than merely
    # non-empty — a placeholder would satisfy a truthiness test while still
    # failing every login attempt.
    has_password = _is_usable_password_hash(user.get("password_hash"))
    provider = (user.get("oauth2_provider") or "").strip()
    if not provider:
        flash("该账号没有 OAuth 绑定。", "info")
        return redirect(url_for("users"))
    if not has_password:
        flash(
            "不能解绑最后一个登录凭据：该账号没有可用的密码，解绑后将永久无法登录。"
            "请先为该账号设置密码。",
            "error",
        )
        return redirect(url_for("users"))

    db.execute(
        "UPDATE users SET oauth2_provider = '', oauth2_id = '', oauth2_username = '', "
        "updated_at = NOW() WHERE id = %s",
        (user_id,),
    )
    _audit(
        "user.unbind_oauth",
        target_type="user",
        target_id=user_id,
        detail=f"{user['username']}: removed provider {user.get('oauth2_provider') or '(none)'}",
    )
    flash("OAuth binding removed.", "success")
    return redirect(url_for("users"))


# ---------- posts ----------

@app.route("/posts")
@login_required
def posts():
    page = _page_param()
    per_page = 20
    offset = (page - 1) * per_page
    rows = db.fetch_all(
        "SELECT p.id, p.user_id, p.content, p.created_at, u.username, "
        "(SELECT COUNT(*) FROM post_attachments pa WHERE pa.post_id = p.id) AS attachment_count "
        "FROM posts p JOIN users u ON u.id = p.user_id "
        "ORDER BY p.created_at DESC LIMIT %s OFFSET %s",
        (per_page, offset),
    )
    total = db.fetch_one("SELECT COUNT(*) AS c FROM posts")["c"]
    return render_template("posts.html", posts=rows, page=page, per_page=per_page, total=total)


@app.route("/posts/<int:post_id>/delete", methods=["POST"])
@login_required
def post_delete(post_id):
    post = db.fetch_one("SELECT id FROM posts WHERE id = %s", (post_id,))
    if not post:
        abort(404)
    db.execute("DELETE FROM posts WHERE id = %s", (post_id,))
    flash("Post deleted.", "success")
    return redirect(url_for("posts"))


# ---------- attachments ----------

@app.route("/attachments")
@login_required
def attachments():
    rows = db.fetch_all(
        "SELECT a.id, a.user_id, a.original_name, a.mime_type, a.size_bytes, a.url, "
        "a.created_at, u.username, "
        "(SELECT COUNT(*) FROM post_attachments pa WHERE pa.attachment_id = a.id) AS post_count "
        "FROM attachments a JOIN users u ON u.id = a.user_id "
        "ORDER BY a.created_at DESC LIMIT 200"
    )
    return render_template("attachments.html", attachments=rows)


@app.route("/attachments/<int:attachment_id>/delete", methods=["POST"])
@login_required
def attachment_delete(attachment_id):
    att = db.fetch_one("SELECT id, object_key FROM attachments WHERE id = %s", (attachment_id,))
    if not att:
        abort(404)
    db.execute("DELETE FROM attachments WHERE id = %s", (attachment_id,))
    flash("Attachment deleted from database. Note: run rustfs cleanup for the object.", "success")
    return redirect(url_for("attachments"))


# ---------- permission groups ----------

def _all_permission_keys():
    rows = db.fetch_all("SELECT key FROM permissions ORDER BY key ASC")
    return [r["key"] for r in rows]


@app.route("/groups")
@login_required
def groups():
    per_page = 25
    page = _page_param()

    total = db.fetch_one("SELECT COUNT(*) AS c FROM groups")["c"]
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = min(page, total_pages)
    offset = (page - 1) * per_page

    group_rows = db.fetch_all(
        "SELECT g.id, g.name, g.description, g.is_default, g.created_at, "
        "COALESCE(COUNT(ug.user_id), 0) AS member_count "
        "FROM groups g LEFT JOIN user_groups ug ON ug.group_id = g.id "
        "GROUP BY g.id ORDER BY g.is_default DESC, g.id ASC LIMIT %s OFFSET %s",
        (per_page, offset),
    )
    group_ids = [g["id"] for g in group_rows]

    perms = db.fetch_all("SELECT key, name FROM permissions ORDER BY key ASC")

    # One query for all the visible groups' permission keys, instead of one
    # round trip per group. The previous loop opened a fresh connection for each
    # group on every render, so the page cost grew with the number of groups.
    perm_keys_by_group = {gid: set() for gid in group_ids}
    if group_ids:
        perm_rows = db.fetch_all(
            "SELECT group_id, permission_key FROM group_permissions "
            "WHERE group_id = ANY(%s)",
            (group_ids,),
        )
        for r in perm_rows:
            perm_keys_by_group.setdefault(r["group_id"], set()).add(r["permission_key"])

    # Membership is limited to the visible groups too. Loading the whole
    # user_groups table every render was unbounded, and the flat (group_id,
    # user_id) rows carry no ordering the view depends on.
    members_by_group = {gid: [] for gid in group_ids}
    if group_ids:
        member_rows = db.fetch_all(
            "SELECT group_id, user_id FROM user_groups WHERE group_id = ANY(%s) "
            "ORDER BY group_id",
            (group_ids,),
        )
        for m in member_rows:
            members_by_group.setdefault(m["group_id"], []).append(m["user_id"])

    # The add-member picker needs a searchable user list, not the entire table.
    # Cap it and let the operator narrow it by name rather than loading every
    # account in the database on each render.
    member_query = request.args.get("mq", "").strip()
    if member_query:
        like = f"%{member_query}%"
        all_users = db.fetch_all(
            "SELECT id, username, nickname FROM users "
            "WHERE username ILIKE %s OR nickname ILIKE %s "
            "ORDER BY username ASC LIMIT 200",
            (like, like),
        )
    else:
        all_users = db.fetch_all(
            "SELECT id, username, nickname FROM users ORDER BY username ASC LIMIT 200"
        )
    user_lookup = {u["id"]: (u["nickname"] or u["username"]) for u in all_users}

    return render_template(
        "groups.html",
        groups=group_rows,
        perms=perms,
        all_keys=[p["key"] for p in perms],
        perm_keys_by_group=perm_keys_by_group,
        members_by_group=members_by_group,
        all_users=all_users,
        user_lookup=user_lookup,
        page=page,
        per_page=per_page,
        total=total,
        total_pages=total_pages,
        member_query=member_query,
    )


@app.route("/groups", methods=["POST"])
@login_required
@require_capability(CAP_USERS_GROUPS)
def group_create():
    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    if not name:
        flash("Group name is required.", "error")
        return redirect(url_for("groups"))
    if db.fetch_one("SELECT id FROM groups WHERE name = %s", (name,)):
        flash("Group name already exists.", "error")
        return redirect(url_for("groups"))
    try:
        db.execute(
            "INSERT INTO groups (name, description) VALUES (%s, %s)",
            (name, description),
        )
        flash(f"Group '{name}' created.", "success")
    except Exception as e:
        app.logger.error("failed to create group: %s", e)
        flash("Failed to create group.", "error")
    return redirect(url_for("groups"))


@app.route("/groups/<int:group_id>/permissions", methods=["POST"])
@login_required
@require_capability(CAP_USERS_GROUPS)
def group_permissions(group_id):
    group = db.fetch_one(
        "SELECT id, name, is_default FROM groups WHERE id = %s", (group_id,)
    )
    if not group:
        abort(404)
    keys = request.form.getlist("permission_keys")
    # only keep keys that actually exist
    valid = {r["key"] for r in db.fetch_all("SELECT key FROM permissions")}
    keys = [k for k in keys if k in valid]

    # The default group ("所有人") is granted to every user implicitly, so its
    # permission set is the floor that applies to everyone. Clearing it is
    # equivalent to revoking a permission globally, and an empty submission is
    # far more likely to be a mistake or a replayed request than an intent to
    # strip all baseline access. The member-removal and group-deletion routes
    # already refuse to touch the default group; this one did not.
    if group["is_default"] and not keys:
        flash(
            "默认组「所有人」的权限不能清空。请至少保留一项权限。",
            "error",
        )
        return redirect(url_for("groups"))

    # Replace the set atomically. Previously the DELETE committed on its own
    # connection and each INSERT on another, so any failure in the loop left the
    # group with a partial (or empty) permission set and no way to tell.
    with db.transaction() as cur:
        cur.execute("DELETE FROM group_permissions WHERE group_id = %s", (group_id,))
        for k in keys:
            cur.execute(
                "INSERT INTO group_permissions (group_id, permission_key) VALUES (%s, %s)",
                (group_id, k),
            )

    _audit(
        "group.permissions",
        target_type="group",
        target_id=group_id,
        detail=f"{group['name']}: {len(keys)} permission(s): {','.join(sorted(keys)) or '(none)'}",
    )
    flash(f"Permissions for '{group['name']}' updated.", "success")
    return redirect(url_for("groups"))


@app.route("/groups/<int:group_id>/members/add", methods=["POST"])
@login_required
@require_capability(CAP_USERS_GROUPS)
def group_member_add(group_id):
    group = db.fetch_one("SELECT id, name FROM groups WHERE id = %s", (group_id,))
    if not group:
        abort(404)
    user_id = request.form.get("user_id", type=int)
    user = db.fetch_one("SELECT id, username FROM users WHERE id = %s", (user_id,))
    if not user:
        flash("User not found.", "error")
        return redirect(url_for("groups"))
    db.execute(
        "INSERT INTO user_groups (user_id, group_id) VALUES (%s, %s) ON CONFLICT DO NOTHING",
        (user_id, group_id),
    )
    flash(f"User '{user['username']}' added to '{group['name']}'.", "success")
    return redirect(url_for("groups"))


@app.route("/groups/<int:group_id>/members/remove", methods=["POST"])
@login_required
@require_capability(CAP_USERS_GROUPS)
def group_member_remove(group_id):
    group = db.fetch_one("SELECT id, name, is_default FROM groups WHERE id = %s", (group_id,))
    if not group:
        abort(404)
    user_id = request.form.get("user_id", type=int)
    if group["is_default"]:
        flash("Users in the default group cannot be removed.", "error")
        return redirect(url_for("groups"))
    db.execute(
        "DELETE FROM user_groups WHERE user_id = %s AND group_id = %s",
        (user_id, group_id),
    )
    flash("User removed from group.", "success")
    return redirect(url_for("groups"))


@app.route("/groups/<int:group_id>/delete", methods=["POST"])
@login_required
@require_capability(CAP_USERS_GROUPS)
def group_delete(group_id):
    group = db.fetch_one("SELECT id, name, is_default FROM groups WHERE id = %s", (group_id,))
    if not group:
        abort(404)
    if group["is_default"]:
        flash("The default group cannot be deleted.", "error")
        return redirect(url_for("groups"))
    db.execute("DELETE FROM groups WHERE id = %s", (group_id,))
    flash(f"Group '{group['name']}' deleted.", "success")
    return redirect(url_for("groups"))


# ---------- plugin store ----------

PLUGIN_MAX_BYTES = 5 * 1024 * 1024  # must match the Go service cap
# Upper bound on the decompressed manifest. The 5MB upload cap bounds only the
# COMPRESSED size, and deflate reaches roughly 1000:1, so a legal-looking
# package expanded to gigabytes and json.loads copied it several more times —
# enough to OOM the shared panel process. A real manifest is a few KB.
PLUGIN_MAX_MANIFEST_BYTES = 256 * 1024
_PLUGIN_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
_PLUGIN_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$")
_PLUGIN_PERM_RE = re.compile(r"^[a-z0-9]+(?:\.[a-z0-9_]+){0,3}$")


def _read_member_bounded(zf, info, limit):
    """Decompress a zip member, refusing to produce more than limit bytes.

    Reads through the zip stream in bounded steps rather than calling
    zf.read(), which materialises the whole member: the size recorded in the
    central directory is attacker-controlled and must not be trusted. Returns
    the bytes, or raises ValueError when the limit is exceeded or the member
    is corrupt.
    """
    if info.file_size and info.file_size > limit:
        raise ValueError(
            f"插件包的 manifest.json 解压后过大（超过 {limit // 1024} KB）"
        )
    out = bytearray()
    try:
        with zf.open(info) as src:
            while True:
                chunk = src.read(64 * 1024)
                if not chunk:
                    break
                out.extend(chunk)
                if len(out) > limit:
                    raise ValueError(
                        f"插件包的 manifest.json 解压后过大（超过 {limit // 1024} KB）"
                    )
    except zipfile.BadZipFile:
        # Corrupt member or a checksum mismatch: reject as a bad package
        # rather than letting it surface as a 500.
        raise ValueError("插件包已损坏或校验失败")
    return bytes(out)


def _plugin_data_dir():
    """Directory the plugin service serves bundles from."""
    root = server_manager.load_config().get("server_root") or config.SERVER_ROOT
    return os.path.join(root, "data", "plugins")


def _read_bundle_manifest(file_storage):
    """Pars manifest.json out of an uploaded zip. Returns (manifest, raw_bytes)."""
    raw = file_storage.read()
    if len(raw) > PLUGIN_MAX_BYTES:
        raise ValueError(f"插件包过大（最大 {PLUGIN_MAX_BYTES // (1024*1024)} MB）")
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile:
        raise ValueError("不是有效的 zip 插件包")
    names = zf.namelist()
    target = None
    for n in names:
        if n.strip("./").lower() == "manifest.json" or n.lower() == "manifest.json":
            target = n
            break
    if not target:
        raise ValueError("插件包缺少根目录 manifest.json")
    try:
        raw_manifest = _read_member_bounded(
            zf, zf.getinfo(target), PLUGIN_MAX_MANIFEST_BYTES
        )
        mf = json.loads(raw_manifest.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("manifest.json 不是有效的 UTF-8 JSON")
    if not isinstance(mf, dict):
        raise ValueError("manifest.json 必须是 JSON 对象")

    pid = str(mf.get("id", ""))
    version = str(mf.get("version", ""))
    entry = str(mf.get("entry") or "main.js")
    perms = mf.get("permissions", [])
    if not _PLUGIN_ID_RE.match(pid):
        raise ValueError(f"无效插件 id: {pid!r}（小写字母/数字/点/横线，3-64 位）")
    if not str(mf.get("name", "")).strip():
        raise ValueError("manifest.name 不能为空")
    if not _PLUGIN_VERSION_RE.match(version):
        raise ValueError(f"无效版本号: {version!r}（应为 1.0.0 形式）")
    if "/" in entry or "\\" in entry or ".." in entry or not entry.endswith(".js"):
        raise ValueError("manifest.entry 必须是纯 .js 文件名")
    if not isinstance(perms, list) or any(
        not isinstance(p, str) or not _PLUGIN_PERM_RE.match(p) for p in perms
    ):
        raise ValueError("manifest.permissions 必须是权限字符串数组")
    # Entry script must exist inside the bundle.
    entry_names = {n.strip("./").lower() for n in names}
    if entry.lower() not in entry_names:
        raise ValueError(f"入口脚本 {entry} 不在插件包中")
    return {
        "id": pid,
        "name": str(mf.get("name")).strip(),
        "version": version,
        "author": str(mf.get("author", "")),
        "description": str(mf.get("description", "")),
        "entry": entry,
        "permissions": [str(p) for p in perms],
        "min_app_version": str(mf.get("min_app_version", "")),
    }, raw


@app.route("/plugins")
@login_required
def plugins():
    rows = db.fetch_all("SELECT * FROM plugins ORDER BY updated_at DESC LIMIT 500")
    return render_template("plugins.html", plugins=rows)


@app.route("/plugins/upload", methods=["POST"])
@login_required
@require_capability(CAP_PLUGINS_WRITE)
def plugin_upload():
    file = request.files.get("file")
    if not file or not file.filename:
        flash("请选择要上传的插件 zip 包。", "error")
        return redirect(url_for("plugins"))
    publish = request.form.get("publish") == "on"
    try:
        mf, raw = _read_bundle_manifest(file)
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("plugins"))

    sha = hashlib.sha256(raw).hexdigest()
    data_dir = _plugin_data_dir()
    os.makedirs(data_dir, exist_ok=True)
    dst = os.path.join(data_dir, f"{mf['id']}-{mf['version']}.zip")
    with open(dst, "wb") as f:
        f.write(raw)

    db.execute(
        """
        INSERT INTO plugins (id, name, version, author, description, permissions,
            min_app_version, entry, file_path, file_size, sha256, verified, published)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,TRUE,%s)
        ON CONFLICT (id) DO UPDATE SET
            name=EXCLUDED.name, version=EXCLUDED.version, author=EXCLUDED.author,
            description=EXCLUDED.description, permissions=EXCLUDED.permissions,
            min_app_version=EXCLUDED.min_app_version, entry=EXCLUDED.entry,
            file_path=EXCLUDED.file_path, file_size=EXCLUDED.file_size,
            sha256=EXCLUDED.sha256, verified=TRUE, published=EXCLUDED.published,
            updated_at=NOW()
        """,
        (
            mf["id"], mf["name"], mf["version"], mf["author"], mf["description"],
            json.dumps(mf["permissions"]), mf["min_app_version"], mf["entry"],
            dst, len(raw), sha, publish,
        ),
    )
    flash(f"插件 {mf['name']} v{mf['version']} 已上传。", "success")
    return redirect(url_for("plugins"))


@app.route("/plugins/<plugin_id>/publish", methods=["POST"])
@login_required
@require_capability(CAP_PLUGINS_WRITE)
def plugin_publish(plugin_id):
    row = db.fetch_one("SELECT id FROM plugins WHERE id = %s", (plugin_id,))
    if not row:
        abort(404)
    db.execute(
        "UPDATE plugins SET published = TRUE, updated_at = NOW() WHERE id = %s",
        (plugin_id,),
    )
    flash("插件已上架。", "success")
    return redirect(url_for("plugins"))


@app.route("/plugins/<plugin_id>/unpublish", methods=["POST"])
@login_required
@require_capability(CAP_PLUGINS_WRITE)
def plugin_unpublish(plugin_id):
    row = db.fetch_one("SELECT id FROM plugins WHERE id = %s", (plugin_id,))
    if not row:
        abort(404)
    db.execute(
        "UPDATE plugins SET published = FALSE, updated_at = NOW() WHERE id = %s",
        (plugin_id,),
    )
    flash("插件已下架，客户端商店不再展示。", "success")
    return redirect(url_for("plugins"))


@app.route("/plugins/<plugin_id>/delete", methods=["POST"])
@login_required
@require_capability(CAP_PLUGINS_WRITE)
def plugin_delete(plugin_id):
    row = db.fetch_one("SELECT id, file_path FROM plugins WHERE id = %s", (plugin_id,))
    if not row:
        abort(404)
    db.execute("DELETE FROM plugins WHERE id = %s", (plugin_id,))
    if row.get("file_path") and os.path.isfile(row["file_path"]):
        try:
            os.remove(row["file_path"])
        except OSError:
            pass
    flash("插件已删除。", "success")
    return redirect(url_for("plugins"))


if __name__ == "__main__":
    # Fail fast and loudly when credentials are missing, rather than falling
    # back to the weak published defaults this panel used to ship.
    _missing = config.missing_credentials()
    if _missing:
        raise SystemExit(
            "管理员面板缺少必需的凭据环境变量 / missing required credentials: "
            + ", ".join(_missing)
            + "\n请在启动前设置这些变量（见 README）。"
        )

    # The session cookie is the panel's only credential. Warn loudly when it is
    # not Secure, since that is only acceptable for local administration.
    if not config.SESSION_COOKIE_SECURE:
        app.logger.warning(
            "会话 cookie 未设置 Secure：仅适用于本机管理。若面板可被其它主机访问，"
            "请设置 ADMIN_COOKIE_SECURE=true（并通过 HTTPS 提供服务）。"
        )

    # Loopback by default. Binding elsewhere exposes an administrative panel
    # whose cookie is only sent over TLS when ADMIN_COOKIE_SECURE is set, so the
    # choice of bind address is a security decision, not just a networking one.
    bind_host = os.getenv("ADMIN_BIND_HOST", "127.0.0.1").strip() or "127.0.0.1"
    app.run(host=bind_host, port=1343, debug=False)
