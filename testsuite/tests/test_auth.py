"""Account approval, password storage, sessions, and route protection."""

from __future__ import annotations

import sqlite3
from email import message_from_string
from urllib.parse import parse_qs, urlsplit

import pytest


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def isolated_auth(tmp_path, monkeypatch):
    from app import config
    from app.services import auth_service

    users_db = tmp_path / "auth" / "users.db"
    monkeypatch.setattr(config, "USERS_DB", users_db)
    monkeypatch.setattr(config, "APP_BASE_URL", "https://defender.example")
    monkeypatch.setattr(config, "SMTP_EMAIL", "")
    monkeypatch.setattr(config, "SMTP_APP_PASSWORD", "")
    monkeypatch.setattr(config, "ADMIN_SECRET", "test-admin-secret")
    # config loads the machine-local .env (a public deployment sets
    # REQUIRE_2FA=true there); pin the flag so these flow assertions are
    # deterministic. The TOTP layer has its own dedicated test below.
    monkeypatch.setattr(config, "REQUIRE_2FA", False)
    auth_service._reset_rate_limits()
    yield auth_service, users_db
    auth_service._reset_rate_limits()


def test_approval_signup_and_login_round_trip(isolated_auth):
    auth, users_db = isolated_auth
    institution = "Duke University"

    # Local development is usable without Gmail credentials; the return value
    # tells the admin route to display the manual signup URL.
    assert auth.approve_email(" Researcher@Duke.edu ", institution) is False
    assert auth.is_approved("researcher@duke.edu") == (institution, 0)

    username = auth.create_account(
        "Researcher_1", "RESEARCHER@DUKE.EDU", "correct horse", institution, "127.0.0.1"
    )
    assert username == "Researcher_1"
    assert auth.verify_login("researcher_1", "correct horse", "127.0.0.2") == username
    assert (
        auth.verify_login(" RESEARCHER@DUKE.EDU ", "correct horse", "127.0.0.2")
        == username
    )

    with sqlite3.connect(users_db) as conn:
        password_hash, stored_email = conn.execute(
            "SELECT password_hash, email FROM users WHERE username = ?", (username,)
        ).fetchone()
        used = conn.execute(
            "SELECT used FROM approved_emails WHERE email = ?", (stored_email,)
        ).fetchone()[0]
    assert stored_email == "researcher@duke.edu"
    assert password_hash != "correct horse"
    assert password_hash.startswith("$2")
    assert used == 1

    with pytest.raises(auth.AuthError, match="Invalid username, email, or password"):
        auth.verify_login(username, "wrong password", "127.0.0.3")
    with pytest.raises(auth.AuthError, match="Invalid username, email, or password"):
        auth.verify_login(stored_email, "wrong password", "127.0.0.3")
    with pytest.raises(auth.AuthError, match="already been created"):
        auth.create_account(
            "someone_else", stored_email, "another pass", institution, "127.0.0.4"
        )


def test_approval_email_uses_configured_public_url(isolated_auth, monkeypatch):
    auth, _ = isolated_auth
    from app import config

    sent = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            sent.update(host=host, port=port, timeout=timeout)

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def login(self, username, password):
            sent["login"] = (username, password)

        def sendmail(self, sender, recipients, raw):
            sent.update(sender=sender, recipients=recipients, raw=raw)

    monkeypatch.setattr(config, "SMTP_EMAIL", "notifier@example.edu")
    monkeypatch.setattr(config, "SMTP_APP_PASSWORD", "app-password")
    monkeypatch.setattr(auth.smtplib, "SMTP_SSL", FakeSMTP)

    assert auth.approve_email("person@example.edu", "Duke University") is True
    message = message_from_string(sent["raw"])
    assert sent["host"] == "smtp.gmail.com" and sent["port"] == 465
    assert sent["recipients"] == ["person@example.edu"]
    assert "https://defender.example/signup" in message.get_payload()


def test_decline_revokes_an_unused_approval(isolated_auth):
    auth, _ = isolated_auth
    auth.approve_email("declined@example.edu", "Duke University")
    assert auth.decline_email("declined@example.edu") is False
    assert auth.is_approved("declined@example.edu") is None


def test_approved_email_cannot_log_in_until_its_account_exists(isolated_auth):
    """An unused approval is an invitation, not an account or login credential."""
    auth, _ = isolated_auth
    auth.approve_email("invited@example.edu", "Duke University")

    with pytest.raises(auth.AuthError, match="Invalid username, email, or password"):
        auth.verify_login("INVITED@EXAMPLE.EDU", "any password", "192.0.2.20")


def test_username_and_email_share_login_rate_limit(isolated_auth, monkeypatch):
    auth, _ = isolated_auth
    auth.approve_email("limited@example.edu", "Duke University")
    auth.create_account(
        "limited_user",
        "limited@example.edu",
        "correct horse",
        "Duke University",
        "127.0.0.1",
    )
    monkeypatch.setattr(auth, "LOGIN_LIMIT", 1)

    with pytest.raises(auth.AuthError, match="Invalid username, email, or password"):
        auth.verify_login("limited_user", "wrong password", "198.51.100.8")
    with pytest.raises(auth.AuthError, match="Too many login attempts"):
        auth.verify_login("LIMITED@EXAMPLE.EDU", "correct horse", "198.51.100.8")


def test_totp_second_factor_enrolls_and_gates_login(isolated_auth):
    """The stdlib TOTP layer: RFC 6238 correctness, enrollment, login gating."""
    import base64

    from app.services import totp_service

    auth, _ = isolated_auth

    # RFC 6238 Appendix B vector (SHA-1): T=59s -> 94287082, last six 287082.
    rfc_secret = base64.b32encode(b"12345678901234567890").decode().rstrip("=")
    assert totp_service.verify_code(rfc_secret, "287082", window=0, at=59)
    assert not totp_service.verify_code(rfc_secret, "000000", window=0, at=59)

    auth.approve_email("totp@example.edu", "Duke University")
    auth.create_account("totp_user", "totp@example.edu", "long enough", "Duke University", "127.0.0.1")
    assert auth.get_totp_secret("totp_user") is None
    # Email login must resolve to the canonical username before the unchanged
    # TOTP/session flow looks up this account's second-factor enrollment.
    assert (
        auth.verify_login("TOTP@EXAMPLE.EDU", "long enough", "127.0.0.2")
        == "totp_user"
    )

    secret = totp_service.generate_secret()
    auth.set_totp_secret("totp_user", secret)
    assert auth.get_totp_secret("TOTP_USER") == secret  # case-insensitive lookup

    current = totp_service._hotp(secret, int(__import__("time").time() // 30))
    auth.verify_totp_login("totp_user", current, "127.0.0.1")  # must not raise
    with pytest.raises(auth.AuthError, match="isn't valid"):
        auth.verify_totp_login("totp_user", "000000", "127.0.0.1")
    # Guess budget: TOTP_LIMIT attempts/min per (user, IP), then a hard stop.
    with pytest.raises(auth.AuthError, match="Too many code attempts"):
        for _ in range(auth.TOTP_LIMIT + 1):
            try:
                auth.verify_totp_login("totp_user", "000000", "10.0.0.9")
            except auth.AuthError as exc:
                if "Too many" in str(exc):
                    raise
    uri = totp_service.provisioning_uri(secret, "totp_user")
    assert uri.startswith("otpauth://totp/") and secret in uri

    auth.clear_totp_secret("TOTP_USER")
    assert auth.get_totp_secret("totp_user") is None
    with pytest.raises(auth.AuthError, match="Unknown account"):
        auth.clear_totp_secret("missing-user")


@pytest.mark.parametrize(
    ("username", "email", "password", "message"),
    [
        ("bad name", "person@example.edu", "long enough", "Username must"),
        ("valid", "not-an-email", "long enough", "valid email"),
        ("valid", "person@example.edu", "short", "at least 8"),
    ],
)
def test_signup_validation_is_server_side(
    isolated_auth, username, email, password, message
):
    auth, _ = isolated_auth
    with pytest.raises(auth.AuthError, match=message):
        auth.create_account(username, email, password, "Duke University", "127.0.0.1")


@pytest.mark.anyio
async def test_auth_routes_and_guard_protect_existing_features(isolated_auth):
    pytest.importorskip("fastapi")
    from starlette.middleware.sessions import SessionMiddleware
    from starlette.requests import Request
    from starlette.responses import PlainTextResponse
    from app import main

    auth, _ = isolated_auth

    def request(path="/", *, query="", method="GET", session=None):
        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": path,
            "raw_path": path.encode(),
            "query_string": query.encode(),
            "root_path": "",
            "headers": [],
            "client": ("127.0.0.1", 12345),
            "server": ("testserver", 80),
            "session": session if session is not None else {},
            "app": main.app,
            "router": main.app.router,
        }
        return Request(scope)

    async def reached(_request):
        return PlainTextResponse("reached")

    session_middleware = [
        item for item in main.app.user_middleware if item.cls is SessionMiddleware
    ]
    assert len(session_middleware) == 1
    assert session_middleware[0].kwargs["same_site"] == "lax"

    blocked = await main.auth_guard(request("/"), reached)
    assert blocked.status_code == 303
    assert blocked.headers["location"] == "/login"

    blocked_query = await main.auth_guard(
        request("/logs", query="site=site-001&search=bot%20agent"), reached
    )
    parsed = urlsplit(blocked_query.headers["location"])
    assert parsed.path == "/login"
    assert parse_qs(parsed.query)["next"] == [
        "/logs?site=site-001&search=bot%20agent"
    ]
    assert (await main.auth_guard(request("/login"), reached)).body == b"reached"
    assert (await main.auth_guard(request("/account"), reached)).status_code == 303

    login_page = main.login_page(request("/login"))
    login_html = login_page.body.decode()
    assert "Username or approved email" in login_html
    assert 'name="username"' in login_html
    assert 'maxlength="254"' in login_html
    for href, label in (
        ("/login", "Log in"),
        ("/request-access", "Request access"),
        ("/signup", "Create account"),
        ("/admin/approve", "Admin panel"),
    ):
        assert f'href="{href}" class="main-nav__link">{label}</a>' in login_html

    admin_session = {}
    admin_request = request("/admin/login", method="POST", session=admin_session)
    assert main.admin_login(admin_request, "wrong").status_code == 403
    unlocked = main.admin_login(admin_request, "test-admin-secret")
    assert unlocked.status_code == 303
    assert admin_session["is_admin"] is True
    # The admin console is least-privilege and does not substitute for user login.
    assert (await main.auth_guard(request("/", session=admin_session), reached)).status_code == 303

    approved = main.admin_approve_submit(
        request("/admin/approve", method="POST", session=admin_session),
        "person@example.edu",
        "Duke University",
    )
    assert approved.status_code == 303
    assert "Approved person@example.edu" in admin_session["admin_flash"]["message"]

    signup_session = dict(admin_session)
    signup = main.signup_submit(
        request("/signup", method="POST", session=signup_session),
        "person@example.edu",
        "person",
        "strong password",
        "Duke University",
    )
    assert signup.status_code == 303 and signup.headers["location"] == "/"
    assert signup_session == {"username": "person"}
    assert (await main.auth_guard(request("/logs", session=signup_session), reached)).body == b"reached"

    logout = main.logout(request("/logout", method="POST", session=signup_session))
    assert logout.status_code == 303 and logout.headers["location"] == "/login"
    assert signup_session == {}

    auth._reset_rate_limits()
    login_session = {}
    login = main.login_submit(
        request("/login", method="POST", session=login_session),
        "PERSON",
        "strong password",
        "//evil.test",
    )
    assert login.status_code == 303
    assert login.headers["location"] == "/"
    assert login_session == {"username": "person"}

    auth._reset_rate_limits()
    email_login_session = {}
    email_login = main.login_submit(
        request("/login", method="POST", session=email_login_session),
        "PERSON@EXAMPLE.EDU",
        "strong password",
        "/logs",
    )
    assert email_login.status_code == 303
    assert email_login.headers["location"] == "/logs"
    assert email_login_session == {"username": "person"}


@pytest.mark.anyio
async def test_account_totp_opt_in_challenge_and_verified_disable(isolated_auth):
    """An account opts into TOTP, is challenged next login, then proves a code
    before disabling; a never-enrolled account is not forced through setup."""
    pytest.importorskip("fastapi")
    from starlette.requests import Request
    from app import main
    from app.services import totp_service

    auth, _ = isolated_auth

    def request(path="/", *, method="GET", session=None):
        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": method,
            "scheme": "https",
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "root_path": "",
            "headers": [],
            "client": ("127.0.0.1", 12345),
            "server": ("testserver", 443),
            "session": session if session is not None else {},
            "app": main.app,
            "router": main.app.router,
        }
        return Request(scope)

    def current_code(secret):
        return totp_service._hotp(secret, int(__import__("time").time() // 30))

    def invalid_code(secret, code):
        candidate = (int(code) + 1) % 1_000_000
        while totp_service.verify_code(secret, f"{candidate:06d}"):
            candidate = (candidate + 1) % 1_000_000
        return f"{candidate:06d}"

    auth.approve_email("opt-in@example.edu", "Duke University")
    auth.create_account(
        "opt_in_user",
        "opt-in@example.edu",
        "strong password",
        "Duke University",
        "127.0.0.1",
    )

    # REQUIRE_2FA is false in the fixture: a fresh account logs straight in.
    session = {}
    login = main.login_submit(
        request("/login", method="POST", session=session),
        "opt_in_user",
        "strong password",
        "/account",
    )
    assert login.status_code == 303 and login.headers["location"] == "/account"
    assert session == {"username": "opt_in_user"}
    assert b">Off<" in main.account_page(request("/account", session=session)).body

    setup = main.account_twofactor_setup_page(
        request("/account/2fa/setup", session=session)
    )
    assert setup.status_code == 200
    secret = session["account_setup_secret"]
    assert "pending_setup_secret" not in session
    code = current_code(secret)

    rejected_enable = main.account_twofactor_enable(
        request("/account/2fa/enable", method="POST", session=session),
        invalid_code(secret, code),
    )
    assert rejected_enable.status_code == 400
    assert auth.get_totp_secret("opt_in_user") is None

    enabled = main.account_twofactor_enable(
        request("/account/2fa/enable", method="POST", session=session), code
    )
    assert enabled.status_code == 303
    assert enabled.headers["location"] == "/account?ok=enabled"
    assert auth.get_totp_secret("opt_in_user") == secret
    assert session == {"username": "opt_in_user"}

    # Enrollment changes the next password login into the existing challenge.
    main.logout(request("/logout", method="POST", session=session))
    challenged = main.login_submit(
        request("/login", method="POST", session=session),
        "opt-in@example.edu",
        "strong password",
        "/account",
    )
    assert challenged.status_code == 303
    assert challenged.headers["location"] == "/login/2fa"
    assert session == {"pending_2fa_user": "opt_in_user", "pending_next": "/account"}

    challenge_code = current_code(secret)
    completed = main.twofactor_submit(
        request("/login/2fa", method="POST", session=session), challenge_code
    )
    assert completed.status_code == 303
    assert session == {"username": "opt_in_user"}
    assert b">On<" in main.account_page(request("/account", session=session)).body

    rejected_disable = main.account_twofactor_disable(
        request("/account/2fa/disable", method="POST", session=session),
        invalid_code(secret, challenge_code),
    )
    assert rejected_disable.status_code == 400
    assert auth.get_totp_secret("opt_in_user") == secret

    disabled = main.account_twofactor_disable(
        request("/account/2fa/disable", method="POST", session=session),
        current_code(secret),
    )
    assert disabled.status_code == 303
    assert disabled.headers["location"] == "/account?ok=disabled"
    assert auth.get_totp_secret("opt_in_user") is None

    # Once disabled, subsequent password login again completes directly.
    main.logout(request("/logout", method="POST", session=session))
    direct = main.login_submit(
        request("/login", method="POST", session=session),
        "opt_in_user",
        "strong password",
        "/",
    )
    assert direct.status_code == 303 and direct.headers["location"] == "/"
    assert session == {"username": "opt_in_user"}
