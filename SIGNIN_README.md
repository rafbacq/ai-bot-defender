# Sign-in setup and user registration

This guide uses the exact repository location on this machine:

```text
/mnt/c/Users/trist/ai-bot-defender
```

All commands below are for a WSL/Linux Bash terminal. Before running any of
them, move into the repository root:

```bash
cd /mnt/c/Users/trist/ai-bot-defender
```

There are two different roles in the registration process:

- **Administrator:** configures the app and approves an email address.
- **User:** creates an account with that approved email, then logs in with the
  chosen username and password.

An access-request form by itself does **not** create or approve an account. The
administrator must approve the email before the user can register at `/signup`.

## Fastest local setup: register yourself

Use these steps when running the app locally and you are both the administrator
and the first user.

### 1. Create the private `.env` configuration file

The tracked template is:

```text
/mnt/c/Users/trist/ai-bot-defender/.env.example
```

The app reads private settings from:

```text
/mnt/c/Users/trist/ai-bot-defender/.env
```

The same `.env` file appears in Windows Explorer as:

```text
C:\Users\trist\ai-bot-defender\.env
```

Run this command once. It creates `.env` only if one does not already exist, so
it will not overwrite existing API keys or settings:

```bash
cd /mnt/c/Users/trist/ai-bot-defender
if [ ! -f .env ]; then
    cp .env.example .env
else
    echo ".env already exists; leaving it unchanged"
fi
```

The `.env` file is intentionally ignored by Git because it contains secrets.
Do not edit `.env.example` with real passwords, and do not commit `.env`.

### 2. Generate and save the two required secrets

Generate a session-signing key:

```bash
cd /mnt/c/Users/trist/ai-bot-defender
python -c "import secrets; print(secrets.token_hex(32))"
```

Copy the printed value. Then generate an administrator password:

```bash
python -c "import secrets; print(secrets.token_urlsafe(24))"
```

Copy that second value too. Open the private configuration file with one of
these editors:

```bash
nano /mnt/c/Users/trist/ai-bot-defender/.env
```

Or, if the VS Code `code` command is installed:

```bash
code /mnt/c/Users/trist/ai-bot-defender/.env
```

Find these lines and replace only the values after `=`:

```dotenv
SECRET_KEY=paste-the-first-generated-value-here
ADMIN_SECRET=paste-the-second-generated-value-here
APP_BASE_URL=http://localhost:8000
SESSION_HTTPS_ONLY=false
```

Do not include the instructional words shown above. For example, a completed
line has the form `SECRET_KEY=a3f1...`, with no spaces around `=`.

For local use, leave these lines blank:

```dotenv
SMTP_EMAIL=
SMTP_APP_PASSWORD=
```

Email is optional. When those two settings are blank, approval still works and
you can open the signup page manually.

If using `nano`, save with `Ctrl+O`, press `Enter`, and exit with `Ctrl+X`.

You do **not** need to edit either of these files for normal setup:

```text
/mnt/c/Users/trist/ai-bot-defender/docker-compose.app.yml
/mnt/c/Users/trist/ai-bot-defender/app/config.py
```

Docker Compose reads the values from the project-root `.env` file automatically.

### 3. Start the application

Make sure Docker Desktop (or the Docker daemon) is running. Check it with:

```bash
docker version
docker compose version
```

Then start the reverse proxy and web app:

```bash
cd /mnt/c/Users/trist/ai-bot-defender
make proxy
make app
```

The first `make app` can take several minutes because it builds the application
image. Later starts reuse that image. A successful start prints:

```text
AI Bot Defender:  http://localhost:8000
```

Check the app container:

```bash
docker compose -f /mnt/c/Users/trist/ai-bot-defender/docker-compose.app.yml ps
```

If the app does not open, view its logs:

```bash
cd /mnt/c/Users/trist/ai-bot-defender
make app-logs
```

Press `Ctrl+C` to stop watching the logs. This does not stop the running app.

### 4. Approve the email that will own the account

Open this exact address in a browser:

```text
http://localhost:8000/admin/approve
```

1. Enter the value saved after `ADMIN_SECRET=` in `.env`.
2. Select **Open approval console**.
3. Under **Approve request**, enter the email address you will use to register.
4. Select the user's institution.
5. Select **Approve request**.

The page should confirm that the email was approved. With SMTP disabled, the
message also tells you to share or open this manual signup address:

```text
http://localhost:8000/signup
```

For a local test account, no external Google Form or email invitation is needed;
manual administrator approval is enough.

### 5. Create the user account

Open:

```text
http://localhost:8000/signup
```

Fill in the form as follows:

1. **Approved email:** use the email approved in step 4.
2. **Username:** choose the name you will later enter on the login page. It must
   start with a letter or number and may then contain letters, numbers, dots,
   hyphens, and underscores.
3. **Password:** choose a password with at least 8 characters.
4. **Institution:** select the same institution chosen during approval.
5. Select **Create account**.

Both the email and institution must match the unused approval. Each approval can
create only one account. After successful registration, the app signs the new
user in automatically.

### 6. Log out and verify normal login

Select **Log out** in the top navigation, or open the app and use its logout
button. The login page is:

```text
http://localhost:8000/login
```

Log in with the **username** chosen during registration, not the email address,
plus the user's password.

## Register another user

Use this workflow for every additional user:

1. The prospective user opens `http://localhost:8000/request-access` and submits
   the external form.
2. An administrator reviews that response outside the app.
3. The administrator opens `http://localhost:8000/admin/approve`, enters
   `ADMIN_SECRET` if prompted, and approves the same email and institution.
4. If SMTP is configured, the app emails an invitation. If it is not configured,
   send the user `http://localhost:8000/signup` manually.
5. The user creates an account with the approved email and institution.
6. The user later signs in at `http://localhost:8000/login` with their username
   and password.

## Where account data is stored

Local users and one-time approvals are stored in:

```text
/mnt/c/Users/trist/ai-bot-defender/configs/users.db
```

That SQLite database and its journal/WAL files are ignored by Git. It is separate
from the crawler-log PostgreSQL database and all honeypot databases. Back up this
file before moving the app if the registered accounts must be preserved.

## Restarting, stopping, and rebuilding

After changing `.env`, apply the new values with:

```bash
cd /mnt/c/Users/trist/ai-bot-defender
make app
```

Stop only the web app with:

```bash
make app-down
```

Stop the complete application stack with:

```bash
make down-all
```

Normal `.env` or Python/HTML edits do not require an image rebuild. Force a
rebuild only after changing the Dockerfile or a requirements file:

```bash
make app-build
```

## Optional email invitations

Local registration works without email. To enable the app's Gmail invitation
and decline messages, edit this exact file:

```text
/mnt/c/Users/trist/ai-bot-defender/.env
```

Set both values:

```dotenv
SMTP_EMAIL=the-sender-address
SMTP_APP_PASSWORD=the-sender-app-password
```

Then run `make app` again. If either value is blank, the app stays in manual
invitation mode.

## Non-local deployment settings

Before exposing the app outside this machine, edit
`/mnt/c/Users/trist/ai-bot-defender/.env` and set:

```dotenv
APP_BASE_URL=https://the-real-public-hostname
SESSION_HTTPS_ONLY=true
```

Use new, strong values for `SECRET_KEY` and `ADMIN_SECRET`. Do not use the local
placeholder values. `APP_BASE_URL` controls the signup link placed in invitation
emails, and `SESSION_HTTPS_ONLY=true` marks the browser session cookie Secure.

## Common registration problems

- **"Invalid administrator password":** use the exact value after
  `ADMIN_SECRET=` in `/mnt/c/Users/trist/ai-bot-defender/.env`, then run
  `make app` to apply recent changes.
- **"This email hasn't been approved yet":** approve that email at
  `http://localhost:8000/admin/approve` before opening `/signup`.
- **"Institution doesn't match":** choose the same institution in the approval
  console and signup form.
- **"This approval has already been used":** one approval creates one account;
  log in with the existing username instead of registering again.
- **Login fails after registration:** the login form expects the username, not
  the approved email address.
- **No invitation email arrives:** email is not sent when `SMTP_EMAIL` or
  `SMTP_APP_PASSWORD` is blank. Use `http://localhost:8000/signup` manually.

## Verification commands

If test dependencies are not installed on the host yet, create an ignored
virtual environment and install them once:

```bash
cd /mnt/c/Users/trist/ai-bot-defender
python -m venv .venv
source .venv/bin/activate
python -m pip install -r /mnt/c/Users/trist/ai-bot-defender/testsuite/requirements.txt
```

With that virtual environment still active, run the authentication tests only:

```bash
cd /mnt/c/Users/trist/ai-bot-defender
python testsuite/run_tests.py auth
```

Run the complete offline test suite:

```bash
python testsuite/run_tests.py
```

When finished, leave the virtual environment with:

```bash
deactivate
```

Validate the Docker Compose configuration:

```bash
docker compose -f /mnt/c/Users/trist/ai-bot-defender/docker-compose.app.yml config --quiet
```
