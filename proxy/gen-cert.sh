#!/bin/sh
# Generate a self-signed wildcard TLS certificate for the reverse proxy if one
# does not already exist. Runs as a one-shot init container (service `certgen`
# in docker-compose.proxy.yml) BEFORE nginx starts, and is idempotent: if a cert
# is already present in the mounted dir it leaves it untouched, so restarts of
# the proxy stack keep the same cert (and the same browser trust decision).
#
# A SINGLE wildcard cert serves every site, because all site hostnames are
# subdomains of the base domains:
#   *.<BASE_DOMAIN>        -> site-001.dukecodeplus.example, site-002..., ...
#   *.<LOCAL_BASE_DOMAIN>  -> site-001.dukecodeplus.localhost, ...
# nginx presents this one cert for any SNI (it is the global/default cert) and
# then routes by Host header -- exactly how name-based virtual hosting works on
# a normal HTTPS site.
#
# If you change proxy.base_domain / proxy.local_base_domain in
# ansible/group_vars/all.yml, update BASE_DOMAIN / LOCAL_BASE_DOMAIN below (set
# in the certgen service env) -- or just delete proxy/certs/* and re-run the
# proxy stack -- so the wildcard keeps covering every site's hostname.
#
# This is a LOCAL self-signed cert: browsers show a one-time warning, but the
# TLS handshake, SNI cert selection, and Host routing are real. For a
# zero-warning local experience use mkcert; for a public deployment use real
# ACME/Let's Encrypt certs (see CLAUDE.md).
set -eu

CERT_DIR="${CERT_DIR:-/certs}"
BASE_DOMAIN="${BASE_DOMAIN:-dukecodeplus.example}"
LOCAL_BASE_DOMAIN="${LOCAL_BASE_DOMAIN:-dukecodeplus.localhost}"
# Optional extra subjectAltName entries, comma-separated, in openssl syntax
# (e.g. "IP:18.206.209.106" so https://<raw public IP>/ matches the cert too).
EXTRA_SAN="${EXTRA_SAN:-}"
CRT="$CERT_DIR/wildcard.crt"
KEY="$CERT_DIR/wildcard.key"

if [ -s "$CRT" ] && [ -s "$KEY" ]; then
  echo "[certgen] $CRT already present; leaving it in place."
  exit 0
fi

# alpine ships without the openssl CLI; install it on demand (cached after first run).
command -v openssl >/dev/null 2>&1 || apk add --no-cache openssl >/dev/null

SAN="DNS:*.$BASE_DOMAIN,DNS:$BASE_DOMAIN,DNS:*.$LOCAL_BASE_DOMAIN,DNS:$LOCAL_BASE_DOMAIN"
[ -n "$EXTRA_SAN" ] && SAN="$SAN,$EXTRA_SAN"
echo "[certgen] generating self-signed wildcard cert for *.$BASE_DOMAIN and *.$LOCAL_BASE_DOMAIN (SAN: $SAN)"
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$KEY" -out "$CRT" -days 3650 \
  -subj "/O=AI Bot Defender/CN=*.$BASE_DOMAIN" \
  -addext "subjectAltName=$SAN"

# nginx master reads these as root at startup; lock the key down regardless.
chmod 644 "$CRT"
chmod 600 "$KEY"
echo "[certgen] wrote $CRT and $KEY"
