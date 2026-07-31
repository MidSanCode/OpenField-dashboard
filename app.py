import functools
import io

import bcrypt
from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

import config
import db

app = Flask(__name__)
app.config["SECRET_KEY"] = config.SECRET_KEY
app.config["SESSION_COOKIE_NAME"] = config.SESSION_COOKIE_NAME
app.config["SESSION_COOKIE_HTTPONLY"] = config.SESSION_COOKIE_HTTPONLY

db.init_admin_table()


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


# ---------- users ----------

@app.route("/users")
@login_required
def users():
    query = request.args.get("q", "").strip()
    if query:
        like = f"%{query}%"
        rows = db.fetch_all(
            "SELECT id, username, nickname, email, avatar_url, role, needs_registration, "
            "oauth2_provider, created_at FROM users "
            "WHERE username ILIKE %s OR nickname ILIKE %s OR email ILIKE %s "
            "ORDER BY created_at DESC",
            (like, like, like),
        )
    else:
        rows = db.fetch_all(
            "SELECT id, username, nickname, email, avatar_url, role, needs_registration, "
            "oauth2_provider, created_at FROM users ORDER BY created_at DESC"
        )
    return render_template("users.html", users=rows, query=query)


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


@app.route("/users/<int:user_id>/reset-password", methods=["POST"])
@login_required
def user_reset_password(user_id):
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
        flash("Password updated.", "success")
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


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
