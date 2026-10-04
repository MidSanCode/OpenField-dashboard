import getpass
import sys

import bcrypt
import db


def password_policy_error(password):
    """Return a message when a password is unacceptable, else None.

    Mirrors app._password_policy_error. This script creates the panel's most
    privileged account and previously accepted any non-empty string, so an
    administrator could be created with "1" — while the in-panel rotation route
    refused exactly that. The two paths must agree or the weaker one is the real
    policy.
    """
    if len(password) < 12:
        return "口令至少需要 12 个字符。"
    if len(password) > 256:
        return "口令过长（最多 256 个字符）。"
    if password.strip() != password:
        return "口令首尾不能有空白字符。"
    if not any(c.isalpha() for c in password):
        return "口令需包含字母。"
    if not any(c.isdigit() for c in password):
        return "口令需包含数字。"
    return None


def seed():
    username = input("Admin username: ").strip()
    if not username:
        print("Username required.")
        sys.exit(1)
    password = getpass.getpass("Admin password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("Passwords do not match.")
        sys.exit(1)
    if not password:
        print("Password required.")
        sys.exit(1)
    policy_error = password_policy_error(password)
    if policy_error is not None:
        print(f"Password rejected: {policy_error}")
        sys.exit(1)

    db.init_admin_table()
    existing = db.fetch_one(
        "SELECT id FROM admin_accounts WHERE username = %s", (username,)
    )
    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    if existing:
        # Rotating an admin password must also invalidate that account's live
        # sessions; otherwise a run intended to recover from a suspected
        # compromise leaves the attacker's cookie working for its full lifetime.
        # session_version is what app._session_admin revalidates against.
        db.execute(
            "UPDATE admin_accounts SET password_hash = %s, "
            "session_version = session_version + 1 WHERE id = %s",
            (password_hash, existing["id"]),
        )
        print(f"Updated admin account '{username}' (existing sessions revoked).")
    else:
        db.execute(
            "INSERT INTO admin_accounts (username, password_hash) VALUES (%s, %s)",
            (username, password_hash),
        )
        print(f"Created admin account '{username}'.")


if __name__ == "__main__":
    seed()
