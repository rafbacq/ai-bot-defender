"""Shared paths and constants for the web application.

``PROJECT_ROOT`` defaults to the repository root (the parent of ``app/``) but is
overridable via the ``PROJECT_ROOT`` env var so the app works the same whether it
runs directly with uvicorn on the host or inside the path-mirrored container.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

APP_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = Path(os.environ.get("PROJECT_ROOT", APP_DIR.parent))

# Docker Compose loads the project-root .env file before it starts a container.
# Loading it here as well keeps `make app-dev` and direct Python/test runs
# consistent with the container without overriding variables supplied by the
# process environment.
load_dotenv(PROJECT_ROOT / ".env", override=False)

ANSIBLE_DIR = PROJECT_ROOT / "ansible"
ALL_YML = ANSIBLE_DIR / "group_vars" / "all.yml"
WEBSITE_DIR = PROJECT_ROOT / "website"
TEMPLATES_DIR = WEBSITE_DIR / "templates"
TEMPLATE_GENERATOR_DIR = PROJECT_ROOT / "template_generator"
PROXY_COMPOSE = PROJECT_ROOT / "docker-compose.proxy.yml"
PROXY_CONF_D = PROJECT_ROOT / "proxy" / "conf.d"
CONFIGS_DIR = PROJECT_ROOT / "configs"
SITES_CONFIG_DIR = CONFIGS_DIR / "sites"
HISTORY_DIR = CONFIGS_DIR / "history"

TEMPLATE_DIR = APP_DIR / "templates"
STATIC_DIR = APP_DIR / "static"


# --- Authentication and access-request workflow ---------------------------
# The Google Form remains the off-platform review queue. Once a request has
# been reviewed, an administrator approves the same email address in the app;
# that approval can be consumed exactly once to create a local account.
GOOGLE_FORM_URL = (
    os.environ.get("GOOGLE_FORM_URL") or "https://forms.gle/FJV94zCQwi29z36f9"
)
APP_BASE_URL = (
    os.environ.get("APP_BASE_URL") or "http://localhost:8000"
).rstrip("/")

SECRET_KEY = os.environ.get("SECRET_KEY") or "dev-only-change-me"
ADMIN_SECRET = os.environ.get("ADMIN_SECRET") or "change-me-admin-password"
SMTP_EMAIL = os.environ.get("SMTP_EMAIL", "")
SMTP_APP_PASSWORD = os.environ.get("SMTP_APP_PASSWORD", "")

# Set true when the app is served exclusively over HTTPS. Starlette then marks
# the signed session cookie Secure; localhost's default HTTP setup leaves it off.
SESSION_HTTPS_ONLY = os.environ.get("SESSION_HTTPS_ONLY", "false").strip().lower() in {
    "1", "true", "yes", "on",
}
SESSION_MAX_AGE = 14 * 24 * 60 * 60

USERS_DB = Path(os.environ.get("USERS_DB", str(CONFIGS_DIR / "users.db")))

INSTITUTIONS = (
    "Princeton University",
    "Massachusetts Institute of Technology (MIT)",
    "Harvard University",
    "Stanford University",
    "Yale University",
    "University of Pennsylvania",
    "California Institute of Technology (Caltech)",
    "Duke University",
    "Brown University",
    "Johns Hopkins University",
    "Northwestern University",
    "Columbia University",
    "Cornell University",
    "University of Chicago",
    "University of California, Berkeley",
    "University of California, Los Angeles (UCLA)",
    "Dartmouth College",
    "University of Michigan",
    "Rice University",
    "Vanderbilt University",
    "University of Notre Dame",
    "University of California, San Diego",
    "Carnegie Mellon University",
    "University of North Carolina at Chapel Hill",
    "University of Virginia",
    "Emory University",
    "Georgetown University",
    "University of Southern California (USC)",
    "New York University (NYU)",
    "University of Texas at Austin",
)
