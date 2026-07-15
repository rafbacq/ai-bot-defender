"""Stdlib-only TOTP (RFC 6238) — the optional second login factor.

Implemented with hmac/struct/base64 rather than a third-party package on
purpose: the app image bakes multi-gigabyte ML layers, and the project rule is
to keep `app/requirements.txt` byte-stable and dependency growth deliberate.
TOTP is small enough that the standard library is the safer dependency.

Compatible with Google Authenticator / Authy / 1Password etc.: 160-bit base32
secret, SHA-1, 6 digits, 30-second period (the de-facto defaults every
authenticator app assumes).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
import urllib.parse

ISSUER = "AI Bot Defender"
PERIOD = 30
DIGITS = 6


def generate_secret() -> str:
    """Return a fresh 160-bit secret, base32 without padding (RFC 4648)."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _hotp(secret: str, counter: int) -> str:
    padding = "=" * (-len(secret) % 8)
    key = base64.b32decode((secret + padding).upper())
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{code % 10 ** DIGITS:0{DIGITS}d}"


def verify_code(secret: str, code: str, window: int = 1, at: float | None = None) -> bool:
    """Check a submitted code against the current time step ± `window` steps.

    The ±1-step window (30s each way) absorbs clock skew between the server
    and the phone; every comparison is constant-time.
    """
    normalized = (code or "").strip().replace(" ", "")
    if len(normalized) != DIGITS or not normalized.isdigit():
        return False
    step = int((time.time() if at is None else at) // PERIOD)
    return any(
        hmac.compare_digest(_hotp(secret, step + skew), normalized)
        for skew in range(-window, window + 1)
    )


def provisioning_uri(secret: str, username: str) -> str:
    """The otpauth:// URI that authenticator apps import (via QR or paste)."""
    label = urllib.parse.quote(f"{ISSUER}:{username}")
    params = urllib.parse.urlencode(
        {
            "secret": secret,
            "issuer": ISSUER,
            "algorithm": "SHA1",
            "digits": str(DIGITS),
            "period": str(PERIOD),
        }
    )
    return f"otpauth://totp/{label}?{params}"
