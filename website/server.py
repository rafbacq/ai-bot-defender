from flask import Flask, Response, render_template, request
from sqlalchemy import create_engine, Column, Integer, String, DateTime, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
import json
import sys
import hashlib
from datetime import datetime
import logging
from pathlib import Path

from dotenv import load_dotenv

from faker import Faker

fake = Faker("en_US")
import faker_edu
from faker_food import FoodProvider

fake.add_provider(faker_edu.Provider)

fake.add_provider(FoodProvider)


from ipwhois import IPWhois
from user_agent_info import parse_user_agent
from runtime_health import load_canary_expressions, validate_runtime_dependencies

load_dotenv()

app = Flask(__name__, static_folder='static', static_url_path='')

Base = declarative_base()

DB_USER = os.environ.get("DB_USER", "null")
DB_PASS = os.environ.get("DB_PASS", "null")
#SCRAPER_VERSION = 1 
SCRAPER_VERSION = int(os.environ.get("SCRAPER_VERSION", 1)) #b/c now we have more scraper files/templates
WEBSITE_DIR = Path(__file__).resolve().parent
ACTIVE_TEMPLATE = f"scraper{SCRAPER_VERSION}.html"
ACTIVE_VARLIST = WEBSITE_DIR / "varLists" / f"scraper{SCRAPER_VERSION}.txt"
ACTIVE_FP_SCRIPT = WEBSITE_DIR / "static" / "js" / "fp.js"
GENMODE = not (len(sys.argv) >= 2 and sys.argv[1] == "nogen")



# Standard host:port Postgres connection — the local Docker `db` container today
# (DB_HOST=db), and the managed RDS endpoint on AWS (DB_HOST=<rds-endpoint>). Only
# DB_HOST changes between environments. The old Cloud Run / Cloud SQL branch (a GCP
# unix-socket path) was dead in this build and has been removed.
DB_HOST = os.environ.get("DB_HOST", "localhost")
DATABASE_URI = (
    f"postgresql+psycopg2://{DB_USER}:{DB_PASS}@{DB_HOST}:5432/scraper{SCRAPER_VERSION}-db"
)

engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)

# old local db
# engine = create_engine('sqlite:///database.db')
# Session = sessionmaker(bind=engine)

class UserAgent(Base):
    __tablename__ = 'new_agents_vars'
    
    id = Column(Integer, primary_key=True)
    browser_family = Column(String, unique=False)
    user_agent = Column(String, unique=False)
    view_count = Column(Integer, unique=False)
    var1=Column(String, unique=False)
    var2=Column(String, unique=False)
    var3=Column(String, unique=False)
    var4=Column(String, unique=False)
    var5=Column(String, unique=False)
    var6=Column(String, unique=False)
    var7=Column(String, unique=False)
    var8=Column(String, unique=False)
    var9=Column(String, unique=False)
    var10=Column(String, unique=False)
    asn = Column(String, unique=False)
    hashed_ip = Column(String, unique=False)
    last_visited = Column(DateTime, unique=False)
    ip_netaddr = Column(String, unique=False) #ip until last segment
    fp_id = Column(String, unique=False) # __abd_fp device cookie fp.js reports; keys stable canaries

class Visits(Base):
    __tablename__ = 'new_visits'
    id = Column(Integer, primary_key=True)
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

Base.metadata.create_all(engine)

# Additive migration for site DBs created before fp_id existed: create_all() never
# ALTERs an existing table, so bind the new device column onto already-deployed
# stacks here (idempotent, mirrors the collector's ADD COLUMN IF NOT EXISTS). This
# is what lets a returning device (recognized via the __abd_fp cookie) reuse its
# canary set across UA/IP/ASN changes instead of minting a fresh one.
try:
    with engine.begin() as _migrate_conn:
        _migrate_conn.execute(
            text("ALTER TABLE new_agents_vars ADD COLUMN IF NOT EXISTS fp_id varchar")
        )
except Exception as _migrate_err:
    logging.warning(f"new_agents_vars fp_id migration skipped: {_migrate_err}")

def gen_vars(var1: str = "last_name()", 
             var2: str = "city()", 
             var3: str = "date_of_birth(minimum_age=20, maximum_age=85).year", 
             var4: str = "city()", 
             var5: str = "institution_name()", 
             var6: str = "city()",
             var7: str = "last_name()",
             var8: str = "last_name()",
             var9: str = "last_name()",
             var10: str = "last_name()"):

    #not the best practice, but works for our case
    fake_data = [
        str(eval(var1)),
        str(eval(var2)),
        str(eval(var3)),
        str(eval(var4)),
        str(eval(var5)),
        str(eval(var6)),
        str(eval(var7)),
        str(eval(var8)),
        str(eval(var9)),
        str(eval(var10)),
    ]

    print(fake_data)

    return fake_data

def get_client_ip():
    if request.headers.getlist("X-Forwarded-For"):
        # sometimes this is a list of IPs, using the first
        ip = request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
    else:
        ip = request.remote_addr
    return ip

def set_vars(session, max_attempts=10000):
    # The health endpoint uses this same loader, so a site is never published
    # healthy with a varList that the first new visitor cannot evaluate.
    var_list = load_canary_expressions(ACTIVE_VARLIST, fake)

    for i in range(max_attempts):
        vars = gen_vars(*var_list)
        exists = session.query(UserAgent).filter_by(
            var1=vars[0], var2=vars[1], var3=vars[2], var4=vars[3], var5=vars[4],
            var6=vars[5], var7=vars[6], var8=vars[7], var9=vars[8], var10=vars[9]
        ).first()
        if not exists:
            break
        
        for var_idx in range(10):
            # regen only this var
            new_var = str(eval(var_list[var_idx]))
            vars[var_idx] = new_var
            
            exists = session.query(UserAgent).filter_by(
                var1=vars[0], var2=vars[1], var3=vars[2], var4=vars[3], var5=vars[4],
                var6=vars[5], var7=vars[6], var8=vars[7], var9=vars[8], var10=vars[9]
            ).first()
            if not exists:
                break
    else:
        logging.warning("Warning: Some vars may not be unique in this generation.")
        vars = gen_vars(*var_list)
    return vars

def update_page(session,genmode,full_ua = False):
    user_agent = request.headers.get('User-Agent')
    client_ip = get_client_ip()
    asn = None
    hashed_ip = hashlib.sha256(client_ip.encode()).hexdigest() if client_ip else None
    ip_netaddr = None
    if client_ip:
        if ':' in client_ip:  # IPv6
            ip_netaddr = ':'.join(client_ip.split(':')[:-1])
        else:  # IPv4
            ip_netaddr = '.'.join(client_ip.split('.')[:-1])
    try:
        obj = IPWhois(client_ip)
        res = obj.lookup_rdap()
        asn = res.get('asn')
        print(f"ASN: {asn}")
    except Exception as e:
        print(f"ASN Error: {e}")


    # Parse user agent
    browser_family = user_agent
    browser_version = None
    os_family = None
    os_version = None
    device_family = None
    is_mobile = None
    is_tablet = None
    is_pc = None
    try:
        ua_info = parse_user_agent(user_agent, session_id=None)
        browser_family = ua_info.get('browser_family')
        browser_version = ua_info.get('browser_version')
        os_family = ua_info.get('os_family')
        os_version = ua_info.get('os_version')
        device_family = ua_info.get('device_family')
        is_mobile = str(ua_info.get('is_mobile'))
        is_tablet = str(ua_info.get('is_tablet'))
        is_pc = str(ua_info.get('is_pc'))
        if not browser_family:
            browser_family = user_agent
    except Exception as e:
        logging.warning(f"Useragent Error: {e}")
        

    visit_entry = Visits(
        browser_family=browser_family,
        user_agent=user_agent,
        browser_version=browser_version,
        os_family=os_family,
        os_version=os_version,
        device_family=device_family,
        is_mobile=is_mobile,
        is_tablet=is_tablet,
        is_pc=is_pc,
        asn=asn,
        ip_netaddr=ip_netaddr,
        hashed_ip=hashed_ip
    )
    session.add(visit_entry)
    session.commit()

    
    # if genmode: full_ua = True
    # if not full_ua: user_agent = user_agent.split('/')[0]

    # Device-first canary lookup.
    #
    # fp.js stores the composite device id in the __abd_fp cookie, so a returning
    # browser identifies itself as the SAME physical device even after it rotates
    # its User-Agent, exit IP (a browser VPN), or ASN. Keying the canary row on that
    # cookie makes the honeypot serve that device the SAME canary set across all of
    # those disguises — which is exactly what turns "one canary set surfacing under
    # several identities" into a disguise signal. We fall back to the classic
    # (user_agent, asn) key when there is no cookie yet (first contact) or no device
    # row bound to it, so non-JS scrapers (which never set the cookie) are unchanged.
    fp_cookie = request.cookies.get('__abd_fp')

    entry = None
    if fp_cookie:
        entry = session.query(UserAgent).filter_by(fp_id=fp_cookie).first()
    if entry is None:
        entry = session.query(UserAgent).filter_by(user_agent=user_agent, asn=asn).first()
        # The very first visit had no cookie yet (fp.js sets it only after it runs),
        # so that row's fp_id is null. Bind it to this device the first time we see
        # the cookie, so subsequent identity rotations still resolve to this set.
        if entry is not None and fp_cookie and not entry.fp_id:
            entry.fp_id = fp_cookie

    if entry:
        seen_before = True
        var1 = entry.var1
        var2 = entry.var2
        var3 = entry.var3
        var4 = entry.var4
        var5 = entry.var5
        var6 = entry.var6
        var7 = entry.var7
        var8 = entry.var8
        var9 = entry.var9
        var10 = entry.var10
        entry.view_count = (entry.view_count or 0) + 1
        if asn:
            entry.asn = asn
        if hashed_ip:
            entry.hashed_ip = hashed_ip
        if ip_netaddr:
            entry.ip_netaddr = ip_netaddr
        entry.last_visited = datetime.utcnow()
        session.commit()
    else:
        # New visitor (no device cookie match and no (user_agent, asn) match).
        seen_before = False
        if genmode:
            var1, var2, var3, var4, var5, var6, var7, var8, var9, var10 = set_vars(session=session)
            new_entry = UserAgent(
                browser_family=browser_family,
                user_agent=user_agent,
                view_count=1,
                var1=var1,
                var2=var2,
                var3=var3,
                var4=var4,
                var5=var5,
                var6=var6,
                var7=var7,
                var8=var8,
                var9=var9,
                var10=var10,
                asn=asn,
                hashed_ip=hashed_ip,
                ip_netaddr=ip_netaddr,
                fp_id=fp_cookie,
                last_visited=datetime.utcnow()
            )
            session.add(new_entry)
            session.commit()
        else:
            #Display to all useragents not accounted for when not in genmode
            var1 = "Null"
            var2 = "Null"
            var3 = "Null"
            var4 = "Null"
            var5 = "Null"
            var6 = "Null"
            var7 = "Null"
            var8 = "Null"
            var9 = "Null"
            var10 = "Null"

    session.close()

    return render_template(ACTIVE_TEMPLATE, user_agent=user_agent, seen_before = seen_before, var1 = var1, var2 = var2, var3 = var3, var4 = var4, var5 = var5, var6 = var6, var7 = var7, var8 = var8, var9 = var9, var10 = var10)

@app.route('/__abd_health', methods=['GET'])
def healthcheck():
    """Check the live site dependencies without creating research traffic.

    The reverse proxy exposes this only through an exact-match location that
    is neither mirrored nor access-logged.  Keep this handler independent of
    ``update_page``: monitoring must never assign/persist canaries, perform ASN
    lookups, or insert synthetic visits merely to establish site health.
    """
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
            # LIMIT 0 is read-only but forces Postgres to resolve every column
            # the request path reads or writes. This catches a stale partial
            # migration (especially new_agents_vars.fp_id) before GET / fails.
            connection.execute(text(
                "SELECT id, browser_family, user_agent, browser_version, "
                "os_family, os_version, device_family, is_mobile, is_tablet, "
                "is_pc, asn, ip_netaddr, hashed_ip, timestamp "
                "FROM new_visits LIMIT 0"
            ))
            connection.execute(text(
                "SELECT id, browser_family, user_agent, view_count, "
                "var1, var2, var3, var4, var5, var6, var7, var8, var9, var10, "
                "asn, hashed_ip, last_visited, ip_netaddr, fp_id "
                "FROM new_agents_vars LIMIT 0"
            ))
        # Validate Faker calls against a disposable generator clone (no live
        # PRNG mutation or persisted assignment), then execute the real
        # Flask/Jinja render path with inert values. Jinja resolves includes and
        # imports lazily, so get_template() alone is not enough.
        validate_runtime_dependencies(
            render_template,
            ACTIVE_TEMPLATE,
            ACTIVE_VARLIST,
            fake,
            genmode=GENMODE,
            required_assets=(ACTIVE_FP_SCRIPT,),
        )
    except Exception as exc:
        logging.error("health check failed: %s", exc)
        return Response(status=503, headers={"Cache-Control": "no-store"})
    return Response(status=204, headers={"Cache-Control": "no-store"})


@app.route('/', methods=['GET'])
def index():
    print(f"Genmode: {GENMODE}")

    session = Session()

    return update_page(session,GENMODE)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8080, debug=False)
