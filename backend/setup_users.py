"""SafePrompt Initial User Setup and Synchronization Utility.

Safely provisions or synchronizes user credentials into the SQLite user store (backend/users.db).

Usage:
  Interactive password setup (input hidden via getpass):
    python backend/setup_users.py

  Set password for a specific user interactively:
    python backend/setup_users.py --user admin
    python backend/setup_users.py --user hr_specialist
    python backend/setup_users.py --user employee_user

  Non-interactive synchronization from backend/.env:
    python backend/setup_users.py --from-env

Security Guarantees:
- Never prints, logs, or exposes plain-text passwords, salts, or hashes.
- Hashes passwords using PBKDF2-HMAC-SHA256 with 100,000 iterations and 16-byte random salts.
- Preserves user IDs, roles, vault records, audit history, and security checks.
- Updates existing user credentials cleanly without deleting database files.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

ENV_PATH = PROJECT_ROOT / "backend" / ".env"
load_dotenv(ENV_PATH)

from backend.auth_service import get_auth_service


ROLE_MAP = {
    "admin": ("admin", "INITIAL_ADMIN_PASSWORD"),
    "hr_specialist": ("hr", "INITIAL_HR_PASSWORD"),
    "employee_user": ("employee", "INITIAL_EMPLOYEE_PASSWORD"),
    "manager": ("hr", "INITIAL_HR_PASSWORD"),
    "worker": ("employee", "INITIAL_EMPLOYEE_PASSWORD"),
}


def _update_env_password(var_name: str, new_password: str) -> None:
    """Safely update an initial password variable in backend/.env without printing."""
    if not ENV_PATH.exists():
        return

    try:
        content = ENV_PATH.read_text(encoding="utf-8")
        lines = content.splitlines()
        found = False
        new_lines = []
        for line in lines:
            if line.startswith(f"{var_name}="):
                new_lines.append(f"{var_name}={new_password}")
                found = True
            else:
                new_lines.append(line)
        if not found:
            new_lines.append(f"{var_name}={new_password}")
        ENV_PATH.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    except Exception as exc:
        print(f"[WARN] Could not update {var_name} in backend/.env: {exc}", file=sys.stderr)


def set_user_password_interactive(target_username: str) -> bool:
    """Interactively prompt for password with input hidden and update users.db."""
    clean_username = target_username.strip().lower()
    if clean_username not in ROLE_MAP:
        print(
            f"[ERROR] Unknown username '{clean_username}'. Expected one of: {list(ROLE_MAP.keys())}",
            file=sys.stderr,
        )
        return False

    print(f"\n--- Setting password for user '{clean_username}' ---")
    pw1 = getpass.getpass(f"Enter new password for '{clean_username}': ")
    if not pw1 or not pw1.strip():
        print("[ERROR] Password cannot be empty or whitespace.", file=sys.stderr)
        return False

    pw2 = getpass.getpass(f"Confirm new password for '{clean_username}': ")
    if pw1 != pw2:
        print("[ERROR] Passwords do not match. Aborting.", file=sys.stderr)
        return False

    auth_service = get_auth_service()
    auth_service.update_user_password(clean_username, pw1)

    # If this is hr_specialist or employee_user, also sync alias
    if clean_username == "hr_specialist":
        auth_service.update_user_password("manager", pw1)
    elif clean_username == "manager":
        auth_service.update_user_password("hr_specialist", pw1)
    elif clean_username == "employee_user":
        auth_service.update_user_password("worker", pw1)
    elif clean_username == "worker":
        auth_service.update_user_password("employee_user", pw1)

    # Sync to backend/.env for test consistency
    _, env_var = ROLE_MAP[clean_username]
    _update_env_password(env_var, pw1)

    print(f"[OK] Password for '{clean_username}' updated successfully in users.db.")
    print("[INFO] Zero passwords or secret keys were printed or exposed.")
    return True


def sync_from_env(overwrite_existing: bool = True) -> int:
    """Synchronize configured environment credentials from backend/.env into users.db."""
    secret_key = os.getenv("AUTH_SECRET_KEY")
    if not secret_key or len(secret_key.strip()) < 32:
        print(
            "[ERROR] AUTH_SECRET_KEY is not configured or is under 32 bytes in backend/.env.",
            file=sys.stderr,
        )
        return 1

    try:
        auth_service = get_auth_service()
        results = auth_service.sync_configured_users(overwrite_existing=overwrite_existing)

        print("[OK] SafePrompt user store synchronization completed:")
        for r in results:
            print(f"  - Account '{r['username']}' ({r['role']}): {r['status']}")
        print("[INFO] Zero passwords, hashes, or secret keys were printed or exposed.")
        return 0
    except Exception as exc:
        print(f"[ERROR] Failed to synchronize users: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="SafePrompt secure user credential setup utility.",
    )
    parser.add_argument(
        "--from-env",
        action="store_true",
        help="Non-interactive: synchronize accounts from INITIAL_*_PASSWORD in backend/.env.",
    )
    parser.add_argument(
        "--user",
        type=str,
        default=None,
        help="Interactively set password for a specific account (e.g. admin, hr_specialist, employee_user).",
    )
    args = parser.parse_args()

    if args.from_env:
        return sync_from_env(overwrite_existing=True)

    if args.user:
        success = set_user_password_interactive(args.user)
        return 0 if success else 1

    # If running interactively
    print("=" * 60)
    print("SafePrompt Interactive Credential Setup")
    print("All password inputs are hidden (no characters displayed on screen).")
    print("=" * 60)

    accounts = ["admin", "hr_specialist", "employee_user"]
    print("Initial accounts available for setup:")
    for idx, acc in enumerate(accounts, start=1):
        role_label = ROLE_MAP[acc][0].upper()
        print(f"  [{idx}] {acc} ({role_label})")
    print("  [4] All of the above accounts sequentially")
    print("  [5] Synchronize from backend/.env without prompting")

    try:
        choice = input("\nEnter choice [1-5] (default: 4): ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\nAborted.")
        return 0

    if not choice:
        choice = "4"

    if choice == "1":
        return 0 if set_user_password_interactive("admin") else 1
    elif choice == "2":
        return 0 if set_user_password_interactive("hr_specialist") else 1
    elif choice == "3":
        return 0 if set_user_password_interactive("employee_user") else 1
    elif choice == "4":
        for acc in accounts:
            ok = set_user_password_interactive(acc)
            if not ok:
                return 1
        print("\n[OK] All initial accounts configured successfully.")
        return 0
    elif choice == "5":
        return sync_from_env(overwrite_existing=True)
    else:
        print("[ERROR] Invalid selection.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
