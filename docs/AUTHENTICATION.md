# Sign-in setup and user registration

The control-center web app is account-protected. There are two roles in the
registration process:

- **Administrator:** configures the app and approves an email address.
- **User:** creates an account with that approved email, then logs in with the
  chosen username and password.

An access-request form by itself does **not** create or approve an account. The
administrator must approve the email before the user can register at `/signup`.

All commands below run from the repository root.

## First-time setup: register yourself

Use these steps when running the app locally and you are both the administrator
and the first user.

### 1. Create the private `.env` file

```bash
if [ ! -f .env ]; then cp .env.example .env; fi
```

The app reads private settings from the project-root `.env`, which is
git-ignored because it contains secrets. Do not put real values in
`.env.example`, and do not commit `.env`.

### 2. Generate and save the two required secrets

Generate a session-signing key and an administrator password:

```bash
python -c "import secrets; print(secrets.token_hex(32))"      # SECRET_KEY
python -c "import secrets; print(secrets.token_urlsafe(24))"  # ADMIN_SECRET
```

Edit `.env` and set (no spaces around `=`):

```dotenv
SECRET_KEY=the-first-generated-value
ADMIN_SECRET=the-second-generated-value
APP_BASE_URL=http://localhost:8000
SESSION_HTTPS_ONLY=false
```

For local use, leave `SMTP_EMAIL=` and `SMTP_APP_PASSWORD=` blank — email is
optional. When they are blank, approval still works and you open the signup
page manually.

You do **not** need to edit `docker-compose.app.yml` or `app/config.py`;
Compose reads the values from `.env` automatically.

### 3. Start the application

```bash
make proxy
make app
```

The first `make app` builds the image and can take several minutes; later
starts reuse it. A successful start prints `http://localhost:8000`. If the app
does not open, check `make app-logs`.

### 4. Approve the email that will own the account

Open `http://localhost:8000/admin/approve`:

1. Enter the value after `ADMIN_SECRET=` in `.env`.
2. Select **Open approval console**.
3. Under **Approve request**, enter the email address you will register with
   and select the institution.
4. Select **Approve request**.

With SMTP disabled, the confirmation also tells you to share or open
`http://localhost:8000/signup` manually.

### 5. Create the user account

Open `http://localhost:8000/signup` and fill in:

1. **Approved email** — the email approved in step 4.
2. **Username** — what you will type on the login page. Must start with a
   letter or number; may contain letters, numbers, dots, hyphens, underscores.
3. **Password** — at least 8 characters.
4. **Institution** — the same institution chosen during approval.

Both the email and institution must match the unused approval, and each
approval creates exactly one account. After registration the app signs the new
user in automatically.

### 6. Verify normal login

Log out, then sign in at `http://localhost:8000/login` with the **username**
(not the email) and password.

## Registering another user

1. The prospective user submits the form at
   `http://localhost:8000/request-access`.
2. An administrator reviews the response outside the app.
3. The administrator approves the same email + institution at
   `/admin/approve`.
4. If SMTP is configured, the app emails an invitation; otherwise send the user
   the `/signup` URL manually.
5. The user registers, then signs in with their username.

## Two-factor authentication (TOTP)

2FA is self-service: any signed-in user can enroll an authenticator app from
`/account` (QR code + manual secret). Once enrolled, every password login also
requires a current code, and disabling 2FA requires a current code too. Setting
`REQUIRE_2FA=true` in `.env` forces enrollment organization-wide. The
implementation is self-hosted RFC 6238 (`app/services/totp_service.py`) and
works with Google Authenticator, Authy, 1Password, and similar apps.

## Where account data is stored

Local users and one-time approvals live in `configs/users.db` (SQLite,
git-ignored, separate from all research databases). Back this file up before
moving the app if the registered accounts must be preserved.

## Applying changes / stopping

- After changing `.env`: `make app` (re-reads the file; no rebuild needed).
- Stop just the web app: `make app-down`. Stop everything: `make down-all`.
- Rebuild the image only after changing the Dockerfile or a requirements file:
  `make app-build`.

## Optional email invitations

Set both values in `.env` to enable Gmail invitations/decline notices:

```dotenv
SMTP_EMAIL=the-sender-address
SMTP_APP_PASSWORD=the-sender-app-password
```

Then `make app`. If either is blank, the app stays in manual-invitation mode.

## Non-local deployments

Before exposing the app beyond localhost, set:

```dotenv
APP_BASE_URL=https://the-real-public-hostname
SESSION_HTTPS_ONLY=true
```

and use fresh, strong `SECRET_KEY` / `ADMIN_SECRET` values. `APP_BASE_URL`
controls the signup link placed in invitation emails;
`SESSION_HTTPS_ONLY=true` marks the session cookie Secure. See
[DEPLOYMENT.md](DEPLOYMENT.md) for the rest of the public hardening (rate
limits, HTTPS-only vhost, no-mirror rule).

## Common problems

- **"Invalid administrator password"** — use the exact value after
  `ADMIN_SECRET=` in `.env`, then `make app` to apply recent changes.
- **"This email hasn't been approved yet"** — approve it at `/admin/approve`
  before opening `/signup`.
- **"Institution doesn't match"** — choose the same institution in the
  approval console and the signup form.
- **"This approval has already been used"** — one approval creates one
  account; log in with the existing username instead.
- **Login fails after registration** — the login form expects the username,
  not the email.
- **No invitation email arrives** — email is not sent when `SMTP_EMAIL` or
  `SMTP_APP_PASSWORD` is blank; share `/signup` manually.

## Verifying

```bash
python testsuite/run_tests.py auth   # authentication tests only
python testsuite/run_tests.py       # the complete offline suite
```
