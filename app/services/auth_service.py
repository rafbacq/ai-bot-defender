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


class AuthError(ValueError):
    """An authentication/approval failure safe to show to a user."""


_pwd_context = CryptContext(
    schemes=["bcrypt"], deprecated="auto", bcrypt__truncate_error=True
)
_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,49}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

_signup_attempts: dict[str, deque[float]] = defaultdict(deque)
_login_attempts: dict[tuple[str, str], deque[float]] = defaultdict(deque)
_rate_lock = threading.Lock()

SIGNUP_LIMIT, SIGNUP_WINDOW = 5, 60
LOGIN_LIMIT, LOGIN_WINDOW = 10, 60


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


def verify_login(username: str, password: str, ip: str) -> str:
    """Verify credentials and return the username exactly as it was registered."""
    normalized_username = _normalize_username(username)
    key = (normalized_username.casefold(), ip or "unknown")
    if not _check_rate_limit(_login_attempts, key, LOGIN_LIMIT, LOGIN_WINDOW):
        raise AuthError("Too many login attempts -- try again in a minute.")

    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT username, password_hash FROM users "
            "WHERE username = ? COLLATE NOCASE",
            (normalized_username,),
        ).fetchone()
    finally:
        conn.close()

    valid = False
    if row is not None:
        try:
            valid = _pwd_context.verify(password or "", row[1])
        except (TypeError, ValueError):
            valid = False
    if not valid:
        raise AuthError("Invalid username or password.")
    return row[0]
