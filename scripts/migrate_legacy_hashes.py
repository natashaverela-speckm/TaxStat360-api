#!/usr/bin/env python3
"""One-time migration: force a password reset for every account still sitting
on a legacy, unsalted SHA-256 password hash (fresh-pass audit, Aug 2026,
finding M-5).

Background: this app used to store SHA-256(password) with no salt for some
older accounts, before bcrypt became the standard (see _hash_password /
_verify_password / _upgrade_password_hash in app/main.py). Any account that
hasn't logged in since that migration is still sitting on a crackable
unsalted hash -- it only upgrades to bcrypt automatically the next time that
specific user logs in with their correct password (_upgrade_password_hash).
This script finds every account still in that state and forces the upgrade
proactively, without waiting on the user to log in on their own schedule, by
sending them the exact same "reset your password" email /auth/forgot-password
already sends -- setting a fresh reset_tok/reset_exp on each account so the
existing, already-tested /auth/reset-password endpoint completes the upgrade
to bcrypt the moment they click the link (reset_password always calls
_hash_password, which is always bcrypt).

Usage:
    # Safe by default: lists every affected account, sends nothing.
    python scripts/migrate_legacy_hashes.py

    # Actually sends the reset email to every affected account found.
    python scripts/migrate_legacy_hashes.py --execute

    # Re-run any time to confirm progress; exits 0 with "0 accounts remaining"
    # once every account has upgraded (either via this script or a normal login).

IMPORTANT -- this script identifies and emails affected accounts. It does NOT
remove the SHA-256 fallback from _verify_password/_resolve_stored_password in
app/main.py. That removal is a deliberate follow-up step, not part of this
commit: doing it now, before every legacy account has actually completed a
reset, would lock those users out entirely (their stored hash would no longer
verify against anything). Run this script, confirm via a re-run that it
reports zero remaining legacy-hash accounts (give the reset-link TTL, 1 hour,
plus a reasonable grace period for users to act on the email), and only then
remove the fallback branch in _verify_password as a separate, later commit.
"""
import argparse
import os
import sys
import time
from urllib.parse import quote

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import main as app_main  # noqa: E402


def _is_legacy_sha256(stored):
    s = str(stored or "")
    return len(s) == 64 and all(c in "0123456789abcdef" for c in s)


def find_legacy_accounts():
    """Returns {email: record} for every account whose resolved stored
    password is a legacy unsalted SHA-256 hash rather than bcrypt."""
    all_users = app_main.ddb_all_users()
    legacy = {}
    for email, rec in all_users.items():
        stored = app_main._resolve_stored_password(rec)
        if _is_legacy_sha256(stored):
            legacy[email] = rec
    return legacy


def send_forced_reset(email, rec):
    """Same reset_tok/reset_exp/email as /auth/forgot-password -- this is a
    scripted trigger of that exact, already-tested flow, not a new one."""
    reset_tok = app_main.secrets.token_hex(32)
    rec["reset_tok"] = reset_tok
    rec["reset_exp"] = int(time.time()) + app_main.RESET_TTL
    app_main.ddb_put_user(email, rec)
    reset_url = f"{app_main.FRONTEND_URL}/reset-password?token={reset_tok}&email={quote(email)}"
    ses = app_main._mailer()
    ses.send_email(
        Source=app_main.RESET_FROM,
        Destination={"ToAddresses": [email]},
        Message={
            "Subject": {"Data": "Action required: reset your TaxStat360 password"},
            "Body": {
                "Html": {
                    "Data": (
                        '<div style="font-family:-apple-system,sans-serif;max-width:520px;'
                        'margin:0 auto;padding:40px 24px">'
                        '<h2 style="color:#0D1B3E">Please reset your password</h2>'
                        "<p>As part of a routine security upgrade, we're asking all "
                        "accounts on an older password format to set a new password. "
                        "This link expires in 1 hour.</p>"
                        f'<p><a href="{reset_url}" style="background:#2563EB;color:#fff;'
                        'padding:12px 20px;border-radius:8px;text-decoration:none;'
                        'display:inline-block">Reset Password</a></p>'
                        '<p style="color:#475569;font-size:13px">If you have questions, '
                        "reply to this email or contact support@taxstat360.com.</p>"
                        "</div>"
                    )
                }
            },
        },
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Actually send reset emails. Without this flag, only lists affected accounts.",
    )
    args = parser.parse_args()

    legacy = find_legacy_accounts()
    if not legacy:
        print("0 accounts remaining on legacy SHA-256 hashes. Safe to remove the fallback.")
        return

    print(f"{len(legacy)} account(s) still on legacy SHA-256 password hashes:")
    for email in sorted(legacy):
        print(f"  - {email}")

    if not args.execute:
        print("\nDry run only -- no emails sent. Re-run with --execute to send reset emails.")
        return

    print("\nSending forced password-reset emails ...")
    sent, failed = 0, 0
    for email, rec in legacy.items():
        try:
            send_forced_reset(email, rec)
            sent += 1
            print(f"  sent: {email}")
        except Exception as e:
            failed += 1
            print(f"  FAILED: {email} ({e})")
    print(f"\nDone. {sent} sent, {failed} failed.")
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
