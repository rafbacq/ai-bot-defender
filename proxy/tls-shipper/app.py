"""Stream Zeek's JSON logs into logdb (AI Bot Defender — Layer 2 fingerprints).

The tls-capture sidecar (Zeek) writes one JSON object per line to a shared volume.
This shipper tails those logs and inserts each record into logdb, keyed by the TCP
4-tuple (src_ip, src_port) + timestamp so ``crawler_graph`` can join each
fingerprint to the HTTP requests in ``all_visits`` that the connection carried.

Two independent streams, each on its own thread with its own DB connection (a
psycopg2 connection is not safe to share across threads):

  * ``ssl.log``     -> ``tls_handshakes``  (JA3/JA4 TLS fingerprints) — UNCHANGED.
  * ``tcp_syn.log`` -> ``tcp_fingerprints`` (client SYN: TTL/window/MSS/scale ->
    p0f-style OS inference + a JA4T-style signature). This is the "kernel betrays
    the spoofed OS" signal: it survives proxies/VPNs that only rewrite source IP.

Design rules (mirrors the request collector):
  - Never crash. logdb hiccups, log rotation, and malformed lines are tolerated.
  - Tail from the end on first start (only new records), and follow rotation
    (Zeek renames the log on rotate) by reopening when the inode/size changes.

The capture sidecar runs ONE ZEEK PER INTERFACE when nginx's netns has several
(Docker can move the inbound published-port hop between networks across stack
recreations), each writing to a per-interface subdirectory of the shared volume.
So besides the two fixed paths (SSL_LOG / TCP_LOG — the single-interface layout,
unchanged), the main loop *discovers* every ``<logdir>/*/ssl.log`` and
``<logdir>/*/tcp_syn.log`` as it appears and spawns a tailing thread for it.
"""

import glob
import json
import os
import threading
import time

import psycopg2

DB_HOST = os.environ.get("DB_HOST", "logdb")
DB_USER = os.environ.get("DB_USER", "logger")
DB_PASS = os.environ.get("DB_PASS", "logger")
DB_NAME = os.environ.get("DB_NAME", "site_logs")
SSL_LOG = os.environ.get("SSL_LOG", "/zeek/logs/ssl.log")
TCP_LOG = os.environ.get("TCP_LOG", "/zeek/logs/tcp_syn.log")
POLL_SECONDS = float(os.environ.get("POLL_SECONDS", "1.0"))
# Where the per-interface Zeek subdirectories live (multi-interface capture).
ZEEK_LOGDIR = os.environ.get("ZEEK_LOGDIR", "/zeek/logs")
# How often to look for newly-appeared per-interface logs.
DISCOVER_SECONDS = float(os.environ.get("DISCOVER_SECONDS", "5.0"))

# --- TLS handshakes (ssl.log) — unchanged schema/insert --------------------
TLS_CREATE = """
CREATE TABLE IF NOT EXISTS tls_handshakes (
    id          serial primary key,
    ts          timestamptz,
    uid         text,
    src_ip      text,
    src_port    int,
    dst_ip      text,
    dst_port    int,
    version     text,
    cipher      text,
    server_name text,
    sni         text,
    ja3         text,
    ja3s        text,
    ja4         text,
    ja4s        text
);
CREATE INDEX IF NOT EXISTS tls_handshakes_tuple
    ON tls_handshakes (src_ip, src_port, ts);
"""

TLS_INSERT = """
INSERT INTO tls_handshakes
    (ts, uid, src_ip, src_port, dst_ip, dst_port, version, cipher,
     server_name, sni, ja3, ja3s, ja4, ja4s)
VALUES (to_timestamp(%s), %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
"""

# --- TCP/IP stack fingerprints (tcp_syn.log) -------------------------------
TCP_CREATE = """
CREATE TABLE IF NOT EXISTS tcp_fingerprints (
    id        serial primary key,
    ts        timestamptz,
    uid       text,
    src_ip    text,
    src_port  int,
    dst_ip    text,
    dst_port  int,
    ttl       int,
    win_size  int,
    win_scale int,
    mss       int,
    sack_ok   boolean,
    df        boolean,
    os_guess  text,
    ja4t      text
);
CREATE INDEX IF NOT EXISTS tcp_fingerprints_tuple
    ON tcp_fingerprints (src_ip, src_port, ts);
"""

TCP_INSERT = """
INSERT INTO tcp_fingerprints
    (ts, uid, src_ip, src_port, dst_ip, dst_port, ttl, win_size, win_scale,
     mss, sack_ok, df, os_guess, ja4t)
VALUES (to_timestamp(%s), %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
"""


def tls_row_from(entry):
    """Map one Zeek ssl.log JSON object to TLS_INSERT params, or None to skip."""
    src_ip = entry.get("id.orig_h")
    if not src_ip:
        return None
    return (
        entry.get("ts"),
        entry.get("uid"),
        src_ip,
        entry.get("id.orig_p"),
        entry.get("id.resp_h"),
        entry.get("id.resp_p"),
        entry.get("version"),
        entry.get("cipher"),
        entry.get("server_name"),
        entry.get("server_name"),
        entry.get("ja3"),
        entry.get("ja3s"),
        entry.get("ja4"),
        entry.get("ja4s"),
    )


def _port(value):
    """Coerce a Zeek port (number, or "443/tcp") to an int, or None."""
    if value is None:
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value).split("/")[0])
    except (TypeError, ValueError):
        return None


def infer_os(ttl, win, wscale, mss):
    """p0f-style OS family inference from the client SYN's TCP/IP fields.

    The initial TTL (normalized up from the observed value: 64->unix-like,
    128->Windows, 255->network gear) is the strong family discriminator; for the
    crowded 64 bucket (Linux/Android/macOS/iOS all start at 64) the SYN window
    size + window scale separate Apple (window 65535, scale 6) from Linux/Android
    (larger windows, scale 7-10). Returns a clean token the consistency engine
    matches against the User-Agent-claimed OS: Windows / Apple / Linux /
    Network/BSD / unknown.
    """
    if ttl is None:
        return "unknown"
    try:
        ttl = int(ttl)
    except (TypeError, ValueError):
        return "unknown"
    initial = 255
    for cand in (32, 64, 128, 255):
        if ttl <= cand:
            initial = cand
            break
    if initial in (32, 128):
        return "Windows"
    if initial == 255:
        return "Network/BSD"
    # initial == 64: unix-like. Separate Apple from Linux/Android by SYN shape.
    try:
        ws = int(wscale) if wscale is not None else None
    except (TypeError, ValueError):
        ws = None
    if win == 65535 and ws in (5, 6):
        return "Apple"
    if ws is not None and ws >= 7:
        return "Linux"
    if win in (29200, 64240, 5840, 14600, 26883, 28960):
        return "Linux"
    return "Linux"


def build_ja4t(win, mss, wscale, sack_ok, df):
    """A JA4T-style signature from the SYN fields Zeek exposes.

    True JA4T also hashes the TCP *options ordering*, which Zeek's SYN_packet
    record does not surface; we encode the kernel-set values it does give —
    window size, MSS, window scale, and the SACK/DF flags — which already form a
    spoof-resistant per-stack signature.
    """
    def s(v):
        return str(v) if v is not None else "0"
    flags = f"{1 if sack_ok else 0}{1 if df else 0}"
    return f"{s(win)}_{s(mss)}_{s(wscale)}_{flags}"


def tcp_row_from(entry):
    """Map one Zeek tcp_syn.log JSON object to TCP_INSERT params, or None."""
    src_ip = entry.get("orig_h")
    if not src_ip:
        return None
    ttl = entry.get("ttl")
    win = entry.get("win_size")
    wscale = entry.get("win_scale")
    mss = entry.get("mss")
    sack_ok = entry.get("sack_ok")
    df = entry.get("df")
    return (
        entry.get("ts"),
        entry.get("uid"),
        src_ip,
        _port(entry.get("orig_p")),
        entry.get("resp_h"),
        _port(entry.get("resp_p")),
        ttl,
        win,
        wscale,
        mss,
        sack_ok,
        df,
        infer_os(ttl, win, wscale, mss),
        build_ja4t(win, mss, wscale, sack_ok, df),
    )


class Shipper:
    """Tail one Zeek JSON log into one logdb table on its own thread/connection."""

    def __init__(self, name, path, create_sql, insert_sql, mapper):
        self.name = name
        self.path = path
        self.create_sql = create_sql
        self.insert_sql = insert_sql
        self.mapper = mapper
        self._conn = None

    def get_conn(self):
        if self._conn is None or self._conn.closed:
            self._conn = psycopg2.connect(
                host=DB_HOST, user=DB_USER, password=DB_PASS, dbname=DB_NAME
            )
            self._conn.autocommit = True
        return self._conn

    def reset_conn(self):
        try:
            if self._conn is not None:
                self._conn.close()
        finally:
            self._conn = None

    def init_db(self):
        with self.get_conn().cursor() as cur:
            cur.execute(self.create_sql)

    def wait_for_db(self):
        for attempt in range(60):
            try:
                self.init_db()
                print(f"{self.name}: connected to logdb, table ready", flush=True)
                return
            except Exception as exc:
                print(f"{self.name}: waiting for logdb ({attempt}): {exc}", flush=True)
                self.reset_conn()
                time.sleep(2)

    def insert_entry(self, entry):
        row = self.mapper(entry)
        if row is None:
            return
        try:
            with self.get_conn().cursor() as cur:
                cur.execute(self.insert_sql, row)
        except Exception as exc:  # pragma: no cover - keep shipping
            print(f"{self.name}: insert failed: {exc}", flush=True)
            self.reset_conn()

    def tail(self):
        """Follow the log, inserting each new JSON line; handle rotation/truncation."""
        handle = None
        inode = None
        while True:
            try:
                if handle is None:
                    if not os.path.exists(self.path):
                        time.sleep(POLL_SECONDS)
                        continue
                    handle = open(self.path, "r", encoding="utf-8", errors="replace")
                    handle.seek(0, os.SEEK_END)
                    inode = os.fstat(handle.fileno()).st_ino
                    print(f"{self.name}: tailing {self.path}", flush=True)

                line = handle.readline()
                if line:
                    line = line.strip()
                    if line:
                        try:
                            self.insert_entry(json.loads(line))
                        except json.JSONDecodeError:
                            pass  # not a JSON record (header / partial line)
                    continue

                # EOF: check for rotation (new inode) or truncation (file shrank).
                time.sleep(POLL_SECONDS)
                try:
                    stat = os.stat(self.path)
                except FileNotFoundError:
                    handle.close()
                    handle = None
                    continue
                if stat.st_ino != inode or stat.st_size < handle.tell():
                    handle.close()
                    handle = open(self.path, "r", encoding="utf-8", errors="replace")
                    inode = os.fstat(handle.fileno()).st_ino
                    print(f"{self.name}: {self.path} rotated, reopened", flush=True)
            except Exception as exc:  # pragma: no cover - never die
                print(f"{self.name}: loop error: {exc}", flush=True)
                try:
                    if handle:
                        handle.close()
                finally:
                    handle = None
                time.sleep(POLL_SECONDS)

    def run(self):
        self.wait_for_db()
        self.tail()


# The two log kinds we ship: (thread-name prefix, fixed env path, per-interface
# basename, table DDL, insert, row mapper).
_STREAMS = [
    ("tls-shipper", SSL_LOG, "ssl.log", TLS_CREATE, TLS_INSERT, tls_row_from),
    ("tcp-shipper", TCP_LOG, "tcp_syn.log", TCP_CREATE, TCP_INSERT, tcp_row_from),
]


def _spawn(name, path, create_sql, insert_sql, mapper):
    shipper = Shipper(name, path, create_sql, insert_sql, mapper)
    thread = threading.Thread(target=shipper.run, name=name, daemon=True)
    thread.start()
    return thread


def main():
    # The fixed single-interface paths (waits for the file if absent — unchanged).
    started = set()
    for name, path, _base, create_sql, insert_sql, mapper in _STREAMS:
        _spawn(name, path, create_sql, insert_sql, mapper)
        started.add(path)

    # Discover per-interface logs (multi-interface capture) as they appear and
    # tail each on its own thread. Runs forever; threads are daemons, so the
    # process lives as long as this loop.
    while True:
        for name, _path, base, create_sql, insert_sql, mapper in _STREAMS:
            for found in glob.glob(os.path.join(ZEEK_LOGDIR, "*", base)):
                if found in started:
                    continue
                _spawn(f"{name}[{os.path.basename(os.path.dirname(found))}]",
                       found, create_sql, insert_sql, mapper)
                started.add(found)
        time.sleep(DISCOVER_SECONDS)


if __name__ == "__main__":
    main()
