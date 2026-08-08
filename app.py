import functools
import io
import os
import tempfile
import uuid

import bcrypt
import psycopg2
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

# Ensure the admin account table exists, but never let a database outage stop
# the panel from booting.
try:
    db.init_admin_table()
except Exception as e:
    app.logger.error("failed to initialize admin table at startup: %s", e)


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

def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("admin_id") is None:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("admin_id") is not None:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        admin = db.fetch_one(
            "SELECT id, username, password_hash FROM admin_accounts WHERE username = %s",
            (username,),
        )
        if admin and bcrypt.checkpw(
            password.encode("utf-8"), admin["password_hash"].encode("utf-8")
        ):
            session["admin_id"] = admin["id"]
            session["admin_username"] = admin["username"]
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
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
def db_export():
    path, msg = db_admin.export_backup()
    flash(msg, "success" if path else "error")
    return redirect(url_for("db_page"))


@app.route("/db/import", methods=["POST"])
@login_required
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
    tmp_path = os.path.join(
        tempfile.gettempdir(), f"openfield-import-{uuid.uuid4().hex}.sql"
    )
    try:
        file.save(tmp_path)
        ok, msg = db_admin.import_backup(tmp_path)
        if ok:
            db.invalidate_schema_status()
        flash(msg, "success" if ok else "error")
    except Exception as e:
        app.logger.error("failed to import backup: %s", e)
        flash(f"导入失败: {e}", "error")
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
    return redirect(url_for("db_page"))


@app.route("/db/backups/<path:filename>/download")
@login_required
def db_backup_download(filename):
    try:
        path = db_admin.backup_path(filename)
    except FileNotFoundError:
        abort(404)
    return send_file(path, as_attachment=True, download_name=os.path.basename(path))


@app.route("/db/backups/<path:filename>/delete", methods=["POST"])
@login_required
def db_backup_delete(filename):
    try:
        db_admin.delete_backup(filename)
        flash(f"备份已删除: {os.path.basename(filename)}", "success")
    except FileNotFoundError:
        abort(404)
    return redirect(url_for("db_page"))


@app.route("/server/config", methods=["POST"])
@login_required
def server_config():
    cfg = server_manager.load_config()
    new_root = request.form.get("server_root", "").strip()
    if new_root:
        cfg["server_root"] = new_root.rstrip("\\/")
        server_manager.save_config(cfg)
        flash(f"服务器根目录已设置为: {cfg['server_root']}", "success")
    else:
        flash("服务器根目录不能为空。", "error")
    return redirect(url_for("server_page"))


@app.route("/server/<service_name>/build", methods=["POST"])
@login_required
def server_build(service_name):
    cfg = server_manager.load_config()
    ok, msg = server_manager.build_service(cfg, service_name)
    flash(msg, "success" if ok else "error")
    return redirect(url_for("server_page"))


@app.route("/server/<service_name>/start", methods=["POST"])
@login_required
def server_start(service_name):
    cfg = server_manager.load_config()
    ok, msg = server_manager.start_service(cfg, service_name)
    flash(msg, "success" if ok else "error")
    return redirect(url_for("server_page"))


@app.route("/server/<service_name>/stop", methods=["POST"])
@login_required
def server_stop(service_name):
    cfg = server_manager.load_config()
    ok, msg = server_manager.stop_service(cfg, service_name)
    flash(msg, "success" if ok else "error")
    return redirect(url_for("server_page"))


@app.route("/server/start-all", methods=["POST"])
@login_required
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

@app.route("/users")
@login_required
def users():
    query = request.args.get("q", "").strip()
    base_select = (
        "SELECT u.id, u.username, u.nickname, u.email, u.avatar_url, u.role, "
        "u.needs_registration, u.oauth2_provider, u.storage_quota, u.is_verified, "
        "u.verified_note, u.verified_by, u.created_at, "
        "COALESCE((SELECT SUM(a.size_bytes) FROM attachments a WHERE a.user_id = u.id), 0) AS storage_used, "
        "COALESCE((SELECT w.balance FROM wallets w WHERE w.user_id = u.id), 0) AS wallet_balance "
        "FROM users u "
    )
    if query:
        like = f"%{query}%"
        rows = db.fetch_all(
            base_select
            + "WHERE u.username ILIKE %s OR u.nickname ILIKE %s OR u.email ILIKE %s "
            "ORDER BY u.created_at DESC",
            (like, like, like),
        )
    else:
        rows = db.fetch_all(base_select + "ORDER BY u.created_at DESC")
    return render_template("users.html", users=rows, query=query)


@app.route("/users/<int:user_id>/quota", methods=["POST"])
@login_required
def user_quota(user_id):
    user = db.fetch_one("SELECT id FROM users WHERE id = %s", (user_id,))
    if not user:
        abort(404)
    try:
        quota_mb = float(request.form.get("quota_mb", ""))
    except ValueError:
        flash("Invalid quota value.", "error")
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
def user_new():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        nickname = request.form.get("nickname", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "user")
        if not username or not nickname or not password:
            flash("Username, nickname and password are required.", "error")
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
def user_wallet(user_id):
    user = db.fetch_one("SELECT id, username FROM users WHERE id = %s", (user_id,))
    if not user:
        abort(404)
    try:
        amount = float(request.form.get("amount", ""))
    except ValueError:
        flash("Invalid amount value.", "error")
        return redirect(url_for("users"))
    if amount == 0:
        flash("Amount must not be zero.", "error")
        return redirect(url_for("users"))
    amount_cents = int(amount * 100)
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
    page = min(max(1, request.args.get("page", 1, type=int)), total_pages)
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


@app.route("/users/<int:user_id>/role", methods=["POST"])
@login_required
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


@app.route("/admins")
@login_required
def admins():
    admins = db.fetch_all(
        "SELECT id, username, can_verify, created_at FROM admin_accounts ORDER BY id ASC"
    )
    return render_template("admins.html", admins=admins)


@app.route("/admins/<int:admin_id>/can-verify", methods=["POST"])
@login_required
def admin_can_verify(admin_id):
    current = db.fetch_one(
        "SELECT can_verify FROM admin_accounts WHERE id = %s",
        (session.get("admin_id"),),
    )
    if not current or not current.get("can_verify"):
        flash("You do not have permission to manage verifiers.", "error")
        return redirect(url_for("admins"))
    admin = db.fetch_one("SELECT id FROM admin_accounts WHERE id = %s", (admin_id,))
    if not admin:
        abort(404)
    can_verify = request.form.get("can_verify") == "1"
    db.execute(
        "UPDATE admin_accounts SET can_verify = %s WHERE id = %s",
        (can_verify, admin_id),
    )
    flash("Verifier permission updated.", "success")
    return redirect(url_for("admins"))


@app.route("/users/<int:user_id>/verified", methods=["POST"])
@login_required
def user_verified(user_id):
    admin = db.fetch_one(
        "SELECT can_verify FROM admin_accounts WHERE id = %s",
        (session.get("admin_id"),),
    )
    if not admin or not admin.get("can_verify"):
        flash("You do not have permission to verify users.", "error")
        return redirect(url_for("users"))
    user = db.fetch_one("SELECT id FROM users WHERE id = %s", (user_id,))
    if not user:
        abort(404)
    verified = request.form.get("verified") == "1"
    verified_by = request.form.get("verified_by", "").strip()
    verified_note = request.form.get("verified_note", "").strip()
    db.execute(
        "UPDATE users SET is_verified = %s, verified_by = %s, verified_note = %s, updated_at = NOW() WHERE id = %s",
        (verified, verified_by, verified_note, user_id),
    )
    flash("Verified status updated.", "success")
    return redirect(url_for("users"))


@app.route("/users/<int:user_id>/reset-password", methods=["POST"])
@login_required
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
        db.execute(
            "UPDATE users SET password_hash = %s, updated_at = NOW() WHERE id = %s",
            (password_hash, user_id),
        )
        flash(f"Password for '{user['username']}' updated.", "success")
    return redirect(url_for("users"))


@app.route("/users/<int:user_id>/delete", methods=["POST"])
@login_required
def user_delete(user_id):
    if user_id == session.get("admin_id"):
        # admin_id is the admin_accounts id, not the users table id
        pass
    user = db.fetch_one("SELECT id FROM users WHERE id = %s", (user_id,))
    if not user:
        abort(404)
    db.execute("DELETE FROM users WHERE id = %s", (user_id,))
    flash("User deleted.", "success")
    return redirect(url_for("users"))


@app.route("/users/<int:user_id>/unbind-oauth", methods=["POST"])
@login_required
def user_unbind_oauth(user_id):
    user = db.fetch_one("SELECT id FROM users WHERE id = %s", (user_id,))
    if not user:
        abort(404)
    db.execute(
        "UPDATE users SET oauth2_provider = '', oauth2_id = '', updated_at = NOW() "
        "WHERE id = %s",
        (user_id,),
    )
    flash("OAuth binding removed.", "success")
    return redirect(url_for("users"))


# ---------- posts ----------

@app.route("/posts")
@login_required
def posts():
    page = max(1, request.args.get("page", 1, type=int))
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
    group_rows = db.fetch_all(
        "SELECT g.id, g.name, g.description, g.is_default, g.created_at, "
        "COALESCE(COUNT(ug.user_id), 0) AS member_count "
        "FROM groups g LEFT JOIN user_groups ug ON ug.group_id = g.id "
        "GROUP BY g.id ORDER BY g.is_default DESC, g.id ASC"
    )
    perms = db.fetch_all(
        "SELECT key, name FROM permissions ORDER BY key ASC"
    )
    memberships = db.fetch_all(
        "SELECT group_id, user_id FROM user_groups ORDER BY group_id"
    )
    members_by_group = {}
    for m in memberships:
        members_by_group.setdefault(m["group_id"], []).append(m["user_id"])

    perm_keys_by_group = {}
    for g in group_rows:
        rows = db.fetch_all(
            "SELECT permission_key FROM group_permissions WHERE group_id = %s", (g["id"],)
        )
        perm_keys_by_group[g["id"]] = {r["permission_key"] for r in rows}

    all_users = db.fetch_all("SELECT id, username, nickname FROM users ORDER BY username ASC")
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
    )


@app.route("/groups", methods=["POST"])
@login_required
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
def group_permissions(group_id):
    group = db.fetch_one("SELECT id, name FROM groups WHERE id = %s", (group_id,))
    if not group:
        abort(404)
    keys = request.form.getlist("permission_keys")
    # only keep keys that actually exist
    valid = {r["key"] for r in db.fetch_all("SELECT key FROM permissions")}
    keys = [k for k in keys if k in valid]
    db.execute("DELETE FROM group_permissions WHERE group_id = %s", (group_id,))
    for k in keys:
        db.execute(
            "INSERT INTO group_permissions (group_id, permission_key) VALUES (%s, %s)",
            (group_id, k),
        )
    flash(f"Permissions for '{group['name']}' updated.", "success")
    return redirect(url_for("groups"))


@app.route("/groups/<int:group_id>/members/add", methods=["POST"])
@login_required
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


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
