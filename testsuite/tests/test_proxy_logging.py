"""Reverse-proxy logging path: request mirror + fingerprint beacon + TLS/TCP shipper.

The proxy is the single entry point that records all traffic. These tests drive
the three collector apps directly (DB connection stubbed) and assert the exact
rows they would write:

  * ``proxy/collector`` — one ``all_visits`` row per mirrored request, tagged with
    the canonical site and the (client_ip, client_port) join key.
  * ``proxy/fp-collector`` — one ``browser_fingerprints`` row per fp.js beacon,
    with normalized numeric fields, ignoring oversized / non-JSON bodies.
  * ``proxy/tls-shipper`` — Zeek ssl.log/tcp_syn.log rows mapped to
    ``tls_handshakes`` / ``tcp_fingerprints`` with a p0f-style OS inference + JA4T.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from .conftest import DummyConn, FakeRequest, load_module_from_path


def test_request_collector_writes_one_all_visits_row(repo_root, monkeypatch):
    """The mirror collector records site, IP, source port, method, URI+query, and UA."""
    pytest.importorskip("fastapi")
    pytest.importorskip("psycopg2")

    module = load_module_from_path("proxy_collector_app", repo_root / "proxy" / "collector" / "app.py")
    calls = []
    monkeypatch.setattr(module, "get_conn", lambda: DummyConn(calls))

    response = asyncio.run(module.collect("deep/path", FakeRequest(
        method="PATCH", path="/deep/path", query="x=1",
        headers={"x-site": "site-001", "x-real-ip": "203.0.113.10",
                 "x-client-port": "55001", "user-agent": "SyntheticBot/1.0"},
    )))

    assert response.status_code == 204
    insert = [c for c in calls if "INSERT INTO all_visits" in c[0]][0]
    assert insert[1][:6] == ("site-001", "203.0.113.10", 55001, "SyntheticBot/1.0", "PATCH", "/deep/path?x=1")


def test_request_collector_never_propagates_db_errors(repo_root, monkeypatch):
    """A DB failure is swallowed (fire-and-forget) and still returns 204."""
    pytest.importorskip("fastapi")
    pytest.importorskip("psycopg2")

    module = load_module_from_path("proxy_collector_app_err", repo_root / "proxy" / "collector" / "app.py")

    def boom():
        raise RuntimeError("logdb down")

    monkeypatch.setattr(module, "get_conn", boom)
    monkeypatch.setattr(module, "reset_conn", lambda: None)
    response = asyncio.run(module.collect("/", FakeRequest(headers={"x-site": "s"})))
    assert response.status_code == 204  # never blocks/fails the real client


def test_fingerprint_collector_normalizes_and_rejects_bad_payloads(repo_root, monkeypatch):
    """fp-collector stores normalized fields for a valid beacon and ignores junk/oversize."""
    pytest.importorskip("fastapi")
    pytest.importorskip("psycopg2")

    module = load_module_from_path("proxy_fp_collector_app", repo_root / "proxy" / "fp-collector" / "app.py")
    calls = []
    monkeypatch.setattr(module, "get_conn", lambda: DummyConn(calls))
    monkeypatch.setattr(module, "MAX_BODY", 2000)

    payload = {
        "phase": "load", "fp_id": "fp-123", "canvas_hash": "canvas", "canvas_winding": True,
        "webgl_hash": "webgl", "webgl_vendor": "Google", "webgl_renderer": "Google SwiftShader",
        "webgl_shader_ms": "12.5", "audio_hash": "audio", "audio_sample": "0.2",
        "font_hash": "font", "fonts": ["Arial"], "screen": {"w": 1440},
        "navigator": {"platform": "Win32"}, "automation": {"score": 2, "webdriver": True},
        "behavior": {"synthetic": True}, "webgpu": {"vendor": "none"},
    }
    ok = asyncio.run(module.collect("__fpbeacon", FakeRequest(
        method="POST", path="/__fpbeacon",
        headers={"x-site": "site-001", "x-real-ip": "203.0.113.10", "x-client-port": "55002",
                 "user-agent": "Chrome", "content-type": "application/json"},
        body=json.dumps(payload).encode("utf-8"),
    )))
    oversize = asyncio.run(module.collect("__fpbeacon", FakeRequest(method="POST", body=b"x" * 2001)))
    nonjson = asyncio.run(module.collect("__fpbeacon", FakeRequest(method="POST", body=b"not json")))

    assert ok.status_code == oversize.status_code == nonjson.status_code == 204
    inserts = [c for c in calls if "INSERT INTO browser_fingerprints" in c[0]]
    assert len(inserts) == 1, "only the valid beacon should be inserted"
    params = inserts[0][1]
    assert params[:7] == ("site-001", "203.0.113.10", 55002, "Chrome", "load", "fp-123", "canvas")
    assert params[11] == 12.5   # webgl_shader_ms coerced to float
    assert params[13] == 0.2    # audio_sample coerced to float


def test_tls_shipper_maps_handshakes_and_infers_tcp_os(repo_root):
    """The shipper maps Zeek rows and infers TCP/IP OS families + a JA4T signature."""
    pytest.importorskip("psycopg2")
    module = load_module_from_path("proxy_tls_shipper_app", repo_root / "proxy" / "tls-shipper" / "app.py")

    # Port coercion ("443/tcp" -> 443).
    assert module._port("443/tcp") == 443 and module._port(8443) == 8443 and module._port("bad") is None

    # p0f-style OS inference from the SYN (TTL bucket + window/scale).
    assert module.infer_os(127, 64240, 8, 1460) == "Windows"   # TTL ~128
    assert module.infer_os(64, 65535, 6, 1460) == "Apple"      # 64 + win 65535 + scale 6
    assert module.infer_os(63, 29200, 7, 1460) == "Linux"      # 64 + scale 7
    assert module.build_ja4t(64240, 1460, 8, True, True) == "64240_1460_8_11"

    tls = module.tls_row_from({
        "ts": 1.5, "uid": "C1", "id.orig_h": "203.0.113.10", "id.orig_p": 55001,
        "id.resp_h": "198.51.100.1", "id.resp_p": 443, "version": "TLSv13",
        "cipher": "TLS_AES_128_GCM_SHA256", "server_name": "site.example",
        "ja3": "ja3", "ja3s": "ja3s", "ja4": "ja4", "ja4s": "ja4s",
    })
    assert tls[2:5] == ("203.0.113.10", 55001, "198.51.100.1")
    assert tls[-2:] == ("ja4", "ja4s")
    assert module.tls_row_from({"id.orig_h": None}) is None  # no source -> skipped

    tcp = module.tcp_row_from({
        "ts": 2.0, "uid": "C2", "orig_h": "203.0.113.10", "orig_p": "55001/tcp",
        "resp_h": "198.51.100.1", "resp_p": "443/tcp", "ttl": 64, "win_size": 65535,
        "win_scale": 6, "mss": 1460, "sack_ok": True, "df": True,
    })
    assert tcp[2:6] == ("203.0.113.10", 55001, "198.51.100.1", 443)
    assert tcp[-2:] == ("Apple", "65535_1460_6_11")
