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

    with pytest.raises(auth.AuthError, match="Invalid username or password"):
        auth.verify_login(username, "wrong password", "127.0.0.3")
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
