from __future__ import annotations

import argparse
import sys

from backend.app.firebase_init import init_firebase_app


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Assign a Firebase custom role claim to a user."
    )
    identity = parser.add_mutually_exclusive_group(required=True)
    identity.add_argument("--uid", help="Firebase Auth UID of the user")
    identity.add_argument("--email", help="Firebase Auth email of the user")
    parser.add_argument(
        "--role",
        default="admin",
        choices=("admin", "analyst", "user"),
        help="Role claim to set. Defaults to admin.",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()

    init_firebase_app()

    from firebase_admin import auth

    if args.email:
        user = auth.get_user_by_email(args.email)
    else:
        user = auth.get_user(args.uid)

    auth.set_custom_user_claims(user.uid, {"role": args.role})

    print(f"Updated Firebase custom claim for {user.email or user.uid}")
    print(f"Set claim: role={args.role!r}")
    print("Sign out and sign back in so Firebase mints a fresh ID token.")
    print("If the browser keeps an old session, call getIdToken(true) after sign-in.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
