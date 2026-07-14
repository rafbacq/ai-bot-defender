from flask import Flask, render_template, request
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker
import os
import sys
import hashlib
import logging
from datetime import datetime

from dotenv import load_dotenv
from faker import Faker

# All slots use standard en_US faker only -- no plugins required.
fake = Faker("en_US")

from ipwhois import IPWhois
from user_agents import parse as parse_ua_string

load_dotenv()

app = Flask(__name__, static_folder='static', static_url_path='')

DB_USER = os.environ.get("DB_USER", "null")
DB_PASS = os.environ.get("DB_PASS", "null")

# Set this to the category whose template + varList you want to serve, e.g.
# "towns", "movies", "biography", etc. -- matches templates/scraper_<CATEGORY>.html
# and varLists/scraper_<CATEGORY>.txt as written by generate_templates.py.
CATEGORY = os.environ.get("CATEGORY", "towns")

# SITE_ID identifies THIS deployed instance and determines its database files.
# Each deployed website gets its OWN canary-token database, so canary
# uniqueness is automatically scoped per site with no cross-site filtering
# needed. Defaults to CATEGORY, but set explicitly if multiple institutions
# might deploy the same category (e.g. "mit-towns", "stanford-towns") so they
# don't share a database file.
SITE_ID = os.environ.get("SITE_ID", CATEGORY)

# Use SQLite locally, PostgreSQL on Cloud Run.
# CLOUD_RUN is set explicitly (not inferred from PORT, since PORT is also used
# for local multi-category testing).
#
# TWO DATABASES, with different scopes:
#   1. canary DB  -- ONE PER SITE (canary_<SITE_ID>.db). One row per unique
#      visitor TO THIS SITE: their 10 assigned canary tokens plus lightweight
#      identifying info (user-agent, ASN, hashed IP, view count). This is
#      what set_vars() queries to avoid handing out a duplicate combination;
#      uniqueness is automatically scoped per site since each site has its
#      own file/database.
#   2. visits DB  -- SHARED ACROSS ALL SITES (one "visits.db" / "visits-db").
#      An append-only log of every single request across every deployed
#      site, tagged with site_id so you can see which site each visit hit.
#      Never queried for canary uniqueness.
if os.environ.get("CLOUD_RUN"):
    CANARY_DATABASE_URI = (
        f"postgresql+psycopg2://{DB_USER}:{DB_PASS}@/"
        f"canary-{SITE_ID}-db"
        f"?host=/cloudsql/scraper1-proj:us-central1:template-db"
    )
    VISITS_DATABASE_URI = (
        f"postgresql+psycopg2://{DB_USER}:{DB_PASS}@/"
        f"visits-db"
        f"?host=/cloudsql/scraper1-proj:us-central1:template-db"
    )
elif os.environ.get("DB_USER") and os.environ.get("DB_USER") != "null":  # local Postgres
    CANARY_DATABASE_URI = (
        f"postgresql+psycopg2://{DB_USER}:{DB_PASS}"
        f"@localhost:5432/canary-{SITE_ID}-db"
    )
    VISITS_DATABASE_URI = (
        f"postgresql+psycopg2://{DB_USER}:{DB_PASS}"
        f"@localhost:5432/visits-db"
    )
else:  # local SQLite fallback
    CANARY_DATABASE_URI = f"sqlite:///canary_{SITE_ID}.db"   # one file per site
    VISITS_DATABASE_URI = "sqlite:///visits.db"               # one shared file
    print(f"No DB credentials found -- using local SQLite "
          f"(canary_{SITE_ID}.db, visits.db)")

canary_engine = create_engine(CANARY_DATABASE_URI)
visits_engine = create_engine(VISITS_DATABASE_URI)

CanarySession = sessionmaker(bind=canary_engine)
VisitsSession = sessionmaker(bind=visits_engine)

CanaryBase = declarative_base()
Visits
class CanaryToken(CanaryBase):
    """One row per unique visitor to THIS site.

    This single table combines the visitor fingerprint/info with that visitor's
    assigned 10 canary tokens. Because this table lives in a per-site database,
    there is no site_id column here and no cross-site uniqueness check.
    """
    __tablename__ = 'canary_tokens'

    id = Column(Integer, primary_key=True)
    browser_family = Column(String, unique=False)
    user_agent = Column(String, unique=False)
    view_count = Column(Integer, unique=False)
    var1 = Column(String, unique=False)
    var2 = Column(String, unique=False)
    var3 = Column(String, unique=False)
    var4 = Column(String, unique=False)
    var5 = Column(String, unique=False)
    var6 = Column(String, unique=False)
    var7 = Column(String, unique=False)
    var8 = Column(String, unique=False)
    var9 = Column(String, unique=False)
    var10 = Column(String, unique=False)
    asn = Column(String, unique=False)
    hashed_ip = Column(String, unique=False)
    last_visited = Column(DateTime, unique=False)
    ip_netaddr = Column(String, unique=False)


class Visits(VisitsBase):
    """Append-only shared log of every request across ALL sites.

    This table lives in the one shared visits database and includes site_id so
    requests can be grouped back to the website that received them. It is never
    queried for canary-token uniqueness.
    """
    __tablename__ = 'visits'

    id = Column(Integer, primary_key=True)
    site_id = Column(String, unique=False, index=True)
    browser_family = Column(String, unique=False)
    user_agent = Column(String, unique=False)
    browser_version = Column(String, unique=False)
    os_family = Column(String, unique=False)
    os_version = Column(String, unique=False)
    device_family = Column(String, unique=False)
    is_mobile = Column(String, unique=False)
    is_tablet = Column(String, unique=False)
    is_pc = Column(String, unique=False)
    asn = Column(String, unique=False)
    ip_netaddr = Column(String, unique=False)
    hashed_ip = Column(String, unique=False)
    timestamp = Column(DateTime, default=datetime.utcnow, unique=False)


CanaryBase.metadata.create_all(canary_engine)
VisitsBase.metadata.create_all(visits_engine)


# ---------------------------------------------------------------------------
# Variable generation.
#
# The varList file (varLists/scraper_<CATEGORY>.txt) is written by
# generate_templates.py and contains exactly 10 lines, one faker expression
# per var slot, e.g.:
#
#   fake.city()
#   fake.city()
#   fake.state()
#   fake.first_name() + ' ' + fake.last_name()
#   fake.company()
#   ...
#
# These expressions are CATEGORY-AGNOSTIC (same 10 lines for every category --
# towns, movies, biography, etc.) since the slots are generic place/person/org
# nouns that read naturally across all 20 templates.
#
# Each expression is evaluated with `fake` in scope, which is the Faker
# instance created above. The expressions use only standard en_US providers.
# ---------------------------------------------------------------------------

# Known categories from generate_templates.py -- used only for a friendly
# startup warning if CATEGORY doesn't match an expected template.
KNOWN_CATEGORIES = {
    "tourist_locations", "biography", "towns", "artists", "movies", "books",
    "historical_figures", "animals", "political_figures", "universities",
    "companies", "languages", "cuisine", "scientists_inventors", "clothing",
    "medicine", "sports_teams", "folklore", "video_games", "religion",
}
if CATEGORY not in KNOWN_CATEGORIES:
    print(f"Warning: CATEGORY={CATEGORY!r} is not one of the 20 known categories. "
          f"Make sure templates/scraper_{CATEGORY}.html and "
          f"varLists/scraper_{CATEGORY}.txt exist.")

def load_var_list() -> list[str]:
    """Read the 10 faker expressions for the current category."""
    path = f"varLists/scraper_{CATEGORY}.txt"
    with open(path, 'r') as f:
        expressions = [line.strip() for line in f.readlines() if line.strip()]
    if len(expressions) != 10:
        raise ValueError(
            f"{path} must contain exactly 10 expressions, found {len(expressions)}"
        )
    return expressions


def eval_expression(expr: str) -> str:
    """Evaluate a single faker expression string with `fake` in scope."""
    return str(eval(expr))  # `fake` is in module scope, so eval can see it.


def gen_vars(expressions: list[str]) -> list[str]:
    """Generate one set of 10 canary values from the given faker expressions."""
    return [eval_expression(e) for e in expressions]


def set_vars(session, expressions: list[str], max_attempts: int = 10000) -> list[str]:
    """Generate a unique combination of canary values not already in this
    site's canary DB. On each attempt the full set is regenerated. If a
    collision is found, individual vars are re-rolled one at a time until the
    combination is unique. After max_attempts the loop gives up with a warning.

    Uniqueness is automatically scoped to this site -- each deployed site has
    its own canary DB (see CANARY_DATABASE_URI), so no category/site filter
    is needed in the query.
    """
    for _ in range(max_attempts):
        vars = gen_vars(expressions)
        exists = session.query(CanaryToken).filter_by(
            var1=vars[0], var2=vars[1], var3=vars[2], var4=vars[3], var5=vars[4],
            var6=vars[5], var7=vars[6], var8=vars[7], var9=vars[8], var10=vars[9]
        ).first()
        if not exists:
            return vars

        # Try re-rolling individual slots to break the collision.
        for idx in range(10):
            vars[idx] = eval_expression(expressions[idx])
            exists = session.query(CanaryToken).filter_by(
                var1=vars[0], var2=vars[1], var3=vars[2], var4=vars[3], var5=vars[4],
                var6=vars[5], var7=vars[6], var8=vars[7], var9=vars[8], var10=vars[9]
            ).first()
            if not exists:
                return vars

    logging.warning("set_vars: could not find a unique combination after %d attempts.", max_attempts)
    return gen_vars(expressions)


# ---------------------------------------------------------------------------
# Request helpers.
# ---------------------------------------------------------------------------

def get_client_ip() -> str:
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
    return request.remote_addr


def lookup_asn(ip: str):
    try:
        res = IPWhois(ip).lookup_rdap()
        asn = res.get('asn')
        print(f"ASN: {asn}")
        return asn
    except Exception as e:
        print(f"ASN Error: {e}")
        return None


def parse_ua(user_agent: str) -> dict:
    """Parse the User-Agent string using the user-agents library."""
    try:
        ua = parse_ua_string(user_agent or "")
        return {
            'browser_family': ua.browser.family or user_agent,
            'browser_version': '.'.join(str(v) for v in ua.browser.version if v),
            'os_family': ua.os.family,
            'os_version': '.'.join(str(v) for v in ua.os.version if v),
            'device_family': ua.device.family,
            'is_mobile': str(ua.is_mobile),
            'is_tablet': str(ua.is_tablet),
            'is_pc': str(ua.is_pc),
        }
    except Exception as e:
        logging.warning("UA parse error: %s", e)
        return {
            'browser_family': user_agent,
            'browser_version': None, 'os_family': None, 'os_version': None,
            'device_family': None, 'is_mobile': None, 'is_tablet': None, 'is_pc': None,
        }


# ---------------------------------------------------------------------------
# Core page handler.
# ---------------------------------------------------------------------------

def update_page(canary_session, visits_session, genmode: bool):
    user_agent = request.headers.get('User-Agent')
    client_ip = get_client_ip()

    hashed_ip = hashlib.sha256(client_ip.encode()).hexdigest() if client_ip else None

    # Trim the last IP segment for coarse bucketing (IPv4 and IPv6).
    ip_netaddr = None
    if client_ip:
        if ':' in client_ip:
            ip_netaddr = ':'.join(client_ip.split(':')[:-1])
        else:
            ip_netaddr = '.'.join(client_ip.split('.')[:-1])

    asn = lookup_asn(client_ip) if client_ip else None
    ua_info = parse_ua(user_agent)

    # Record every visit regardless of whether we've seen this agent before.
    # Goes to the VISITS DB -- a separate, append-only log.
    visit_entry = Visits(
        site_id=SITE_ID,
        browser_family=ua_info['browser_family'],
        user_agent=user_agent,
        browser_version=ua_info['browser_version'],
        os_family=ua_info['os_family'],
        os_version=ua_info['os_version'],
        device_family=ua_info['device_family'],
        is_mobile=ua_info['is_mobile'],
        is_tablet=ua_info['is_tablet'],
        is_pc=ua_info['is_pc'],
        asn=asn,
        ip_netaddr=ip_netaddr,
        hashed_ip=hashed_ip,
    )
    visits_session.add(visit_entry)
    visits_session.commit()

    # Check whether this user-agent + ASN combination has been seen before on
    # THIS SITE. Uniqueness is automatically per-site since the canary DB is
    # per-site -- no category/site filter needed.
    exact_entry = canary_session.query(CanaryToken).filter_by(
        user_agent=user_agent, asn=asn
    ).first()

    if exact_entry:
        # Returning visitor -- serve the same canary values as before.
        seen_before = True
        var1, var2, var3, var4, var5 = (
            exact_entry.var1, exact_entry.var2, exact_entry.var3,
            exact_entry.var4, exact_entry.var5,
        )
        var6, var7, var8, var9, var10 = (
            exact_entry.var6, exact_entry.var7, exact_entry.var8,
            exact_entry.var9, exact_entry.var10,
        )
        exact_entry.view_count += 1
        exact_entry.asn = asn or exact_entry.asn
        exact_entry.hashed_ip = hashed_ip or exact_entry.hashed_ip
        exact_entry.ip_netaddr = ip_netaddr or exact_entry.ip_netaddr
        exact_entry.last_visited = datetime.utcnow()
        canary_session.commit()

    else:
        seen_before = False
        if genmode:
            # New visitor in generation mode -- assign a unique canary set.
            expressions = load_var_list()
            vars = set_vars(canary_session, expressions)
            var1, var2, var3, var4, var5 = vars[0], vars[1], vars[2], vars[3], vars[4]
            var6, var7, var8, var9, var10 = vars[5], vars[6], vars[7], vars[8], vars[9]

            new_entry = CanaryToken(
                browser_family=ua_info['browser_family'],
                user_agent=user_agent,
                view_count=1,
                var1=var1, var2=var2, var3=var3, var4=var4, var5=var5,
                var6=var6, var7=var7, var8=var8, var9=var9, var10=var10,
                asn=asn,
                hashed_ip=hashed_ip,
                ip_netaddr=ip_netaddr,
                last_visited=datetime.utcnow(),
            )
            canary_session.add(new_entry)
            canary_session.commit()
        else:
            # Not in genmode -- serve null values (page still renders, just untracked).
            var1 = var2 = var3 = var4 = var5 = "Null"
            var6 = var7 = var8 = var9 = var10 = "Null"

    canary_session.close()
    visits_session.close()

    return render_template(
        f"scraper_{CATEGORY}.html",
        user_agent=user_agent,
        seen_before=seen_before,
        var1=var1, var2=var2, var3=var3, var4=var4, var5=var5,
        var6=var6, var7=var7, var8=var8, var9=var9, var10=var10,
    )


@app.route('/', methods=['GET'])
def index():
    genmode = not (len(sys.argv) >= 2 and sys.argv[1] == "nogen")
    print(f"Genmode: {genmode}")
    canary_session = CanarySession()
    visits_session = VisitsSession()
    return update_page(canary_session, visits_session, genmode)


if __name__ == '__main__':
    port = int(os.environ.get("PORT", "8080"))
    app.run(host="0.0.0.0", port=port, debug=False)
