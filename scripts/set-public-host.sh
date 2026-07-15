#!/usr/bin/env bash
# Point every hostname-bearing config at this machine's public address, in one
# command. This is the ONLY supported way to change the deployment's public
# identity — the value lives in several places (Ansible vars, the certgen env,
# the TLS cert itself, each rendered nginx server block) and drift between
# them breaks routing or presents a mismatched cert.
#
# Usage:
#   scripts/set-public-host.sh                # auto-detect EC2 public IP (IMDSv2)
#   scripts/set-public-host.sh 3.85.1.2       # explicit IP  -> base domain 3.85.1.2.sslip.io
#   scripts/set-public-host.sh honeypots.example.org   # real domain -> used as base domain
#                                             (wildcard DNS for it must already
#                                              point at this instance)
#
# What it does, in order:
#   1. ansible/group_vars/all.yml: proxy.base_domain + proxy.server_aliases
#   2. .env: PROXY_BASE_DOMAIN / PROXY_EXTRA_SAN (read by docker-compose.proxy.yml)
#   3. Regenerates the self-signed wildcard cert iff it doesn't already cover
#      the new base domain, and hot-reloads nginx
#   4. Re-runs the Ansible playbook for every site in configs/sites/ so each
#      nginx server block carries the new names
#   5. Verifies: cert SAN + an HTTP and HTTPS request per site through nginx
#
# Idempotent: re-running with an unchanged address is a no-op apart from the
# playbook re-render.
set -euo pipefail
cd "$(dirname "$0")/.."

ALL_YML="ansible/group_vars/all.yml"
ENV_FILE=".env"
CRT="proxy/certs/wildcard.crt"

log() { printf '[set-public-host] %s\n' "$*"; }
die() { printf '[set-public-host] ERROR: %s\n' "$*" >&2; exit 1; }

imds_public_ip() {
    local token
    token=$(curl -s -m 5 -X PUT http://169.254.169.254/latest/api/token \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null) || return 0
    curl -s -m 5 -H "X-aws-ec2-metadata-token: $token" \
        http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || true
}

TARGET="${1:-}"
if [ -z "$TARGET" ]; then
    TARGET=$(imds_public_ip)
    [ -n "$TARGET" ] || die "no address given and EC2 metadata auto-detect failed; run: $0 <public-ip-or-domain>"
    log "auto-detected public IP: $TARGET"
fi

if [[ "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    PUBIP="$TARGET"
    BASE_DOMAIN="${TARGET}.sslip.io"   # public wildcard DNS: *.<ip>.sslip.io -> <ip>
else
    BASE_DOMAIN="$TARGET"
    PUBIP=$(imds_public_ip)            # keep the raw IP as alias/SAN when known
fi

EXTRA_SAN=""
ALIASES=""
if [ -n "$PUBIP" ]; then
    EXTRA_SAN="IP:$PUBIP"
    ALIASES="\"$PUBIP\""
fi

log "base domain     : $BASE_DOMAIN  (sites answer at <site-id>.$BASE_DOMAIN)"
log "raw-IP alias/SAN: ${PUBIP:-<none>}"

# --- 1. ansible/group_vars/all.yml -----------------------------------------
grep -q '^  base_domain: "' "$ALL_YML" || die "cannot find '  base_domain: \"...\"' in $ALL_YML"
grep -q '^  server_aliases: \[' "$ALL_YML" || die "cannot find '  server_aliases: [...]' in $ALL_YML"
sed -E -i "s|^(  base_domain: )\"[^\"]*\"|\\1\"$BASE_DOMAIN\"|" "$ALL_YML"
sed -E -i "s|^(  server_aliases: )\[[^]]*\]|\\1[$ALIASES]|" "$ALL_YML"
log "updated $ALL_YML"

# Keep the admin vhost's canonical name on the same base domain.
if [ -f proxy/admin.d/admin.conf ]; then
    sed -E -i "s|server_name admin\.[^;]*;|server_name admin.$BASE_DOMAIN;|g" proxy/admin.d/admin.conf
    log "updated proxy/admin.d/admin.conf server_name -> admin.$BASE_DOMAIN"
fi

# Warn about per-site canonical overrides this script deliberately never touches.
for f in configs/sites/*.yaml; do
    [ -e "$f" ] || continue
    if grep -q 'server_name:' "$f"; then
        log "WARNING: $f pins its own proxy.server_name — left as-is; edit it manually if it should follow the new base domain"
    fi
done

# --- 2. .env (read by docker-compose.proxy.yml's certgen service) -----------
touch "$ENV_FILE"
upsert() {
    local key="$1" val="$2"
    if grep -q "^${key}=" "$ENV_FILE"; then
        sed -i "s|^${key}=.*|${key}=${val}|" "$ENV_FILE"
    else
        [ -s "$ENV_FILE" ] && [ -n "$(tail -c1 "$ENV_FILE")" ] && echo >> "$ENV_FILE"
        echo "${key}=${val}" >> "$ENV_FILE"
    fi
}
upsert PROXY_BASE_DOMAIN "$BASE_DOMAIN"
upsert PROXY_EXTRA_SAN "$EXTRA_SAN"
# The control center's canonical public URL follows the base domain (used in
# invitation emails and shown on the admin console).
upsert APP_BASE_URL "https://admin.$BASE_DOMAIN"
log "updated $ENV_FILE (PROXY_BASE_DOMAIN, PROXY_EXTRA_SAN, APP_BASE_URL)"

# --- 3. TLS cert -------------------------------------------------------------
if [ -s "$CRT" ] && openssl x509 -in "$CRT" -noout -ext subjectAltName 2>/dev/null \
        | grep -q "DNS:\*\.$BASE_DOMAIN"; then
    log "cert already covers *.$BASE_DOMAIN — keeping it"
else
    log "regenerating wildcard cert for *.$BASE_DOMAIN"
    rm -f proxy/certs/wildcard.crt proxy/certs/wildcard.key
    docker compose -f docker-compose.proxy.yml run --rm certgen
    if docker ps --format '{{.Names}}' | grep -q '^proxy-nginx$'; then
        docker exec proxy-nginx nginx -t
        docker exec proxy-nginx nginx -s reload
        log "nginx reloaded with the new cert"
    else
        log "proxy-nginx not running — cert will be picked up on next 'make proxy'"
    fi
fi

# --- 4. re-render every site's nginx block + compose stack ------------------
shopt -s nullglob
site_files=(configs/sites/*.yaml)
if [ ${#site_files[@]} -eq 0 ]; then
    log "no sites in configs/sites/ — nothing to re-render"
else
    for f in "${site_files[@]}"; do
        sid=$(basename "$f" .yaml)
        log "re-rendering site $sid via the playbook"
        make playbook site_id="$sid"
    done
fi

# --- 5. verify ---------------------------------------------------------------
log "cert SAN: $(openssl x509 -in "$CRT" -noout -ext subjectAltName | tail -1 | sed 's/^ *//')"
fail=0
for f in "${site_files[@]}"; do
    sid=$(basename "$f" .yaml)
    host="$sid.$BASE_DOMAIN"
    if grep -q 'server_name:' "$f"; then
        host=$(sed -nE 's/^ *server_name: *"?([^"]*)"?.*/\1/p' "$f" | head -1)
    fi
    # The playbook just recreated the site's web container; give it up to 30s
    # to boot before calling the site broken (a fresh Flask + DB connect takes
    # a few seconds, and nginx 502s until then).
    code_http=000; code_https=000
    for _ in 1 2 3 4 5 6; do
        code_http=$(curl -s -m 10 -o /dev/null -w '%{http_code}' -H "Host: $host" http://localhost/ || true)
        code_https=$(curl -sk -m 10 -o /dev/null -w '%{http_code}' --resolve "$host:443:127.0.0.1" "https://$host/" || true)
        [ "$code_http" = "200" ] && [ "$code_https" = "200" ] && break
        sleep 5
    done
    if [ "$code_http" = "200" ] && [ "$code_https" = "200" ]; then
        log "OK  $host  (http $code_http, https $code_https)"
    else
        log "FAIL $host  (http $code_http, https $code_https)"
        fail=1
    fi
done
[ "$fail" = "0" ] || die "one or more sites failed verification — check 'make proxy-logs'"

log "done. Public URLs (once the security group allows 80/443):"
for f in "${site_files[@]}"; do
    sid=$(basename "$f" .yaml)
    log "  http://$sid.$BASE_DOMAIN/   https://$sid.$BASE_DOMAIN/"
done
log "  control center: https://admin.$BASE_DOMAIN/"

if grep -q '^  tls_fullchain:' "$ALL_YML"; then
    log "NOTE: a Let's Encrypt cert is wired in but was issued for the PREVIOUS"
    log "hostnames — run scripts/setup-letsencrypt.sh now to reissue for the new"
    log "ones (until then browsers see a name mismatch on the trusted cert)."
fi
