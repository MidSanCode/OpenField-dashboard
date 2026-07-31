import getpass
import sys

import bcrypt
import db


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

    db.init_admin_table()
    existing = db.fetch_one(
        "SELECT id FROM admin_accounts WHERE username = %s", (username,)
    )
    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    if existing:
        db.execute(
            "UPDATE admin_accounts SET password_hash = %s WHERE id = %s",
            (password_hash, existing["id"]),
        )
        print(f"Updated admin account '{username}'.")
    else:
        db.execute(
            "INSERT INTO admin_accounts (username, password_hash) VALUES (%s, %s)",
            (username, password_hash),
        )
        print(f"Created admin account '{username}'.")


if __name__ == "__main__":
    seed()
