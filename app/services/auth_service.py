"""Local accounts with a one-time, administrator-approved signup gate.

Prospective users submit the configured external access-request form. An
administrator then approves the same email address here, optionally sending an
invitation through Gmail SMTP. Accounts are stored in a small SQLite database
that is independent of the crawler/log databases, and passwords are stored only
as bcrypt hashes.
"""

from __future__ import annotations

import re
import smtplib
import sqlite3
import threading
import time
from collections import defaultdict, deque
from email.mime.text import MIMEText

from passlib.context import CryptContext

from .. import config
from . import totp_service


class AuthError(ValueError):
    """An authentication/approval failure safe to show to a user."""


_pwd_context = CryptContext(
    schemes=["bcrypt"], deprecated="auto", bcrypt__truncate_error=True
)
# Verified against instead of returning early when the identifier doesn't exist,
# so a login attempt costs one bcrypt either way — response timing no longer
# reveals whether a username or email is registered.
_DUMMY_HASH = _pwd_context.hash("timing-equalizer-not-a-real-password")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,49}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_INVALID_LOGIN = "Invalid username, email, or password."

_signup_attempts: dict[str, deque[float]] = defaultdict(deque)
_login_attempts: dict[tuple[str, str], deque[float]] = defaultdict(deque)
_totp_attempts: dict[tuple[str, str], deque[float]] = defaultdict(deque)
_admin_attempts: dict[str, deque[float]] = defaultdict(deque)
_rate_lock = threading.Lock()

SIGNUP_LIMIT, SIGNUP_WINDOW = 5, 60
LOGIN_LIMIT, LOGIN_WINDOW = 10, 60
# 6-digit codes have a 1-in-10^6 guess chance; 10 tries/min makes online
# brute force hopeless within a code's 90s validity window.
TOTP_LIMIT, TOTP_WINDOW = 10, 60
# The admin console guards deploy/approval powers with one shared secret, so
# its brute-force budget is the strictest: 5 attempts per 5 minutes per IP.
ADMIN_LIMIT, ADMIN_WINDOW = 5, 300


def _get_conn() -> sqlite3.Connection:
    """Open the auth DB and idempotently install its tiny schema."""
    config.USERS_DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(config.USERS_DB, timeout=10)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            institution TEXT NOT NULL,
            created_at REAL NOT NULL
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS approved_emails (
            email TEXT PRIMARY KEY,
            institution TEXT NOT NULL,
            approved_at REAL NOT NULL,
            used INTEGER NOT NULL DEFAULT 0 CHECK (used IN (0, 1))
        )"""
    )
    # The original branch's table used case-sensitive SQLite uniqueness for
    # usernames. This index both fixes new databases and upgrades any database
    # already created while testing that branch.
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS users_username_nocase "
        "ON users(username COLLATE NOCASE)"
    )
    # Additive migration for databases created before TOTP support (mirrors the
    # collector's ADD COLUMN IF NOT EXISTS pattern; SQLite needs the pragma check).
    columns = {row[1] for row in conn.execute("PRAGMA table_info(users)")}
    if "totp_secret" not in columns:
        conn.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT")
    return conn


def _normalize_email(email: str) -> str:
    value = (email or "").strip().lower()
    if len(value) > 254 or not _EMAIL_RE.fullmatch(value):
        raise AuthError("Enter a valid email address.")
    return value


def _normalize_username(username: str) -> str:
    value = (username or "").strip()
    if not _USERNAME_RE.fullmatch(value):
        raise AuthError(
            "Username must be 1–50 characters and use only letters, numbers, dots, "
            "hyphens, or underscores."
        )
    return value


def _normalize_login_identifier(identifier: str) -> tuple[str, str]:
    """Return (kind, normalized value) for a username-or-email login field.

    Login validation is intentionally generic: format errors must not help an
    attacker distinguish an account lookup from a bad credential attempt.
    """
    value = (identifier or "").strip()
    try:
        if "@" in value:
            return "email", _normalize_email(value)
        return "username", _normalize_username(value)
    except AuthError:
        raise AuthError(_INVALID_LOGIN) from None


def _check_rate_limit(bucket, key, limit: int, window: int) -> bool:
    now = time.monotonic()
    with _rate_lock:
        attempts = bucket[key]
        while attempts and now - attempts[0] > window:
            attempts.popleft()
        if len(attempts) >= limit:
            return False
        attempts.append(now)
        return True


def _reset_rate_limits() -> None:
    """Clear process-local counters (used by the isolated test suite)."""
    with _rate_lock:
        _signup_attempts.clear()
        _login_attempts.clear()
        _totp_attempts.clear()
        _admin_attempts.clear()


def admin_login_allowed(ip: str) -> bool:
    """Rate-gate attempts at the shared administrator secret (per source IP)."""
    return _check_rate_limit(_admin_attempts, ip or "unknown", ADMIN_LIMIT, ADMIN_WINDOW)


def get_totp_secret(username: str) -> str | None:
    """Return the user's enrolled TOTP secret, or None when not enrolled."""
    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT totp_secret FROM users WHERE username = ? COLLATE NOCASE",
            (username,),
        ).fetchone()
    finally:
        conn.close()
    return row[0] if row and row[0] else None


def set_totp_secret(username: str, secret: str) -> None:
    """Persist a verified enrollment (called only after the user proves a code)."""
    conn = _get_conn()
    try:
        updated = conn.execute(
            "UPDATE users SET totp_secret = ? WHERE username = ? COLLATE NOCASE",
            (secret, username),
        )
        if updated.rowcount != 1:
            raise AuthError("Unknown account.")
        conn.commit()
    finally:
        conn.close()


def clear_totp_secret(username: str) -> None:
    """Remove a user's TOTP enrollment after their current code is verified."""
    conn = _get_conn()
    try:
        updated = conn.execute(
            "UPDATE users SET totp_secret = NULL "
            "WHERE username = ? COLLATE NOCASE",
            (username,),
        )
        if updated.rowcount != 1:
            raise AuthError("Unknown account.")
        conn.commit()
    finally:
        conn.close()


def verify_totp_login(username: str, code: str, ip: str) -> None:
    """Check a login-time TOTP code, with its own per-(user, IP) rate limit."""
    key = (username.casefold(), ip or "unknown")
    if not _check_rate_limit(_totp_attempts, key, TOTP_LIMIT, TOTP_WINDOW):
        raise AuthError("Too many code attempts -- try again in a minute.")
    secret = get_totp_secret(username)
    if not secret or not totp_service.verify_code(secret, code):
        raise AuthError("That code isn't valid. Enter the current 6-digit code.")


def _send_email(to_email: str, subject: str, body: str) -> bool:
    """Send one notification, or return False in unconfigured local dev."""
    if not config.SMTP_EMAIL or not config.SMTP_APP_PASSWORD:
        return False

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = config.SMTP_EMAIL
    msg["To"] = to_email
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=15) as server:
            server.login(config.SMTP_EMAIL, config.SMTP_APP_PASSWORD)
            server.sendmail(config.SMTP_EMAIL, [to_email], msg.as_string())
    except (OSError, smtplib.SMTPException) as exc:
        raise AuthError("the notification email could not be sent.") from exc
    return True


def approve_email(email: str, institution: str) -> bool:
    """Approve an address and send its signup invitation when SMTP is set.

    Returns whether an email was delivered. The approval is intentionally saved
    before delivery, so a temporary SMTP outage never discards an administrator's
    decision; the admin page reports that the link must be shared manually.
    """
    normalized_email = _normalize_email(email)
    if institution not in config.INSTITUTIONS:
        raise AuthError("Pick an institution from the list.")

    conn = _get_conn()
    try:
        existing = conn.execute(
            "SELECT used FROM approved_emails WHERE email = ?", (normalized_email,)
        ).fetchone()
        if existing and existing[0]:
            raise AuthError("An account has already been created for this email.")
        conn.execute(
            """INSERT INTO approved_emails (email, institution, approved_at, used)
               VALUES (?, ?, ?, 0)
               ON CONFLICT(email) DO UPDATE SET
                   institution = excluded.institution,
                   approved_at = excluded.approved_at""",
            (normalized_email, institution, time.time()),
        )
        conn.commit()
    finally:
        conn.close()

    try:
        return _send_email(
            normalized_email,
            "Your AI Bot Defender access request was approved",
            "Good news -- your access request for AI Bot Defender was approved.\n\n"
            f"Create your account here: {config.APP_BASE_URL}/signup\n\n"
            f"Use this same email address ({normalized_email}) when you sign up.\n\n"
            "-- Argus Lab",
        )
    except AuthError as exc:
        raise AuthError(f"Approval was saved, but {exc}") from exc


def decline_email(email: str) -> bool:
    """Revoke any unused approval and optionally notify the applicant."""
    normalized_email = _normalize_email(email)
    conn = _get_conn()
    try:
        existing = conn.execute(
            "SELECT used FROM approved_emails WHERE email = ?", (normalized_email,)
        ).fetchone()
        if existing and existing[0]:
            raise AuthError("This email already belongs to an active account.")
        conn.execute(
            "DELETE FROM approved_emails WHERE email = ? AND used = 0",
            (normalized_email,),
        )
        conn.commit()
    finally:
        conn.close()

    try:
        return _send_email(
            normalized_email,
            "AI Bot Defender access request",
            "Thank you for your interest in AI Bot Defender.\n\n"
            "After reviewing your request, we're unable to grant access at this time.\n\n"
            "If you have questions, please reach out to the Argus Lab team directly.\n\n"
            "-- Argus Lab",
        )
    except AuthError as exc:
        raise AuthError(f"The request was declined, but {exc}") from exc


def is_approved(email: str) -> tuple[str, int] | None:
    normalized_email = _normalize_email(email)
    conn = _get_conn()
    try:
        return conn.execute(
            "SELECT institution, used FROM approved_emails WHERE email = ?",
            (normalized_email,),
        ).fetchone()
    finally:
        conn.close()


def create_account(
    username: str, email: str, password: str, institution: str, ip: str
) -> str:
    """Consume an approval and create an account; return canonical username."""
    normalized_username = _normalize_username(username)
    normalized_email = _normalize_email(email)
    if institution not in config.INSTITUTIONS:
        raise AuthError("Pick an institution from the list.")
    if len(password or "") < 8:
        raise AuthError("Password must be at least 8 characters.")
    if len(password) > 128 or len(password.encode("utf-8")) > 72:
        raise AuthError("Password must be no more than 72 encoded characters.")
    if not _check_rate_limit(
        _signup_attempts, ip or "unknown", SIGNUP_LIMIT, SIGNUP_WINDOW
    ):
        raise AuthError("Too many signup attempts from this network -- try again in a minute.")

    # Reject unapproved submissions before doing deliberately expensive bcrypt
    # work. The same checks run again under SQLite's write lock below so two
    # concurrent requests still cannot consume one approval twice.
    approved = is_approved(normalized_email)
    if approved is None:
        raise AuthError(
            "This email hasn't been approved yet. Submit the access request form first."
        )
    approved_institution, used = approved
    if used:
        raise AuthError("An account has already been created for this email.")
    if institution != approved_institution:
        raise AuthError("Institution doesn't match your approved request.")

    # Hash before taking SQLite's write lock.
    password_hash = _pwd_context.hash(password)
    conn = _get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        approved = conn.execute(
            "SELECT institution, used FROM approved_emails WHERE email = ?",
            (normalized_email,),
        ).fetchone()
        if approved is None:
            raise AuthError(
                "This email hasn't been approved yet. Submit the access request form first."
            )
        approved_institution, used = approved
        if used:
            raise AuthError("An account has already been created for this email.")
        if institution != approved_institution:
            raise AuthError("Institution doesn't match your approved request.")

        conn.execute(
            """INSERT INTO users
                   (username, email, password_hash, institution, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (
                normalized_username,
                normalized_email,
                password_hash,
                institution,
                time.time(),
            ),
        )
        updated = conn.execute(
            "UPDATE approved_emails SET used = 1 WHERE email = ? AND used = 0",
            (normalized_email,),
        )
        if updated.rowcount != 1:
            raise AuthError("This approval has already been used.")
        conn.commit()
    except sqlite3.IntegrityError as exc:
        conn.rollback()
        raise AuthError("That username or email is already registered.") from exc
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return normalized_username


def verify_login(identifier: str, password: str, ip: str) -> str:
    """Verify a username or approved account email; return canonical username."""
    identifier_kind, normalized_identifier = _normalize_login_identifier(identifier)
    conn = _get_conn()
    try:
        if identifier_kind == "email":
            # Account emails are normalized before storage and can enter this
            # table only by consuming an administrator-approved email record.
            row = conn.execute(
                "SELECT username, password_hash FROM users WHERE email = ?",
                (normalized_identifier,),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT username, password_hash FROM users "
                "WHERE username = ? COLLATE NOCASE",
                (normalized_identifier,),
            ).fetchone()
    finally:
        conn.close()

    # Both aliases for a known account share one rate-limit bucket, preventing
    # username+email login support from doubling an attacker's guess budget.
    rate_identifier = row[0].casefold() if row else normalized_identifier.casefold()
    key = (rate_identifier, ip or "unknown")
    if not _check_rate_limit(_login_attempts, key, LOGIN_LIMIT, LOGIN_WINDOW):
        raise AuthError("Too many login attempts -- try again in a minute.")

    valid = False
    if row is not None:
        try:
            valid = _pwd_context.verify(password or "", row[1])
        except (TypeError, ValueError):
            valid = False
    else:
        # Burn the same bcrypt cost for unknown identifiers (see _DUMMY_HASH).
        try:
            _pwd_context.verify(password or "", _DUMMY_HASH)
        except (TypeError, ValueError):
            pass
    if not valid:
        raise AuthError(_INVALID_LOGIN)
    return row[0]
