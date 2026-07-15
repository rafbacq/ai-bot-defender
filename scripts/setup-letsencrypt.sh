#!/usr/bin/env bash
# Obtain (or expand) ONE publicly-trusted Let's Encrypt certificate covering
# every public hostname this deployment serves — each honeypot site plus the
# admin control center — then wire nginx to present it.
#
# Usage:
#   scripts/setup-letsencrypt.sh              # issue/expand + wire + verify
#   LE_DRY_RUN=1 scripts/setup-letsencrypt.sh # staging dry-run (no cert saved,
#                                             #   nothing wired; validates the
#                                             #   ACME challenge plumbing)
#   LE_EMAIL=you@example.org scripts/...      # override the ACME account email
#
# Requirements: the proxy stack must be up (nginx serves the HTTP-01 challenge
# files from the shared certbot_webroot volume) and port 80 must be reachable
# from the internet (Let's Encrypt's validators fetch the challenge).
#
# Re-run whenever the set of public hostnames changes (new site deployed, base
# domain changed via set-public-host): --expand + --keep-until-expiring make
# re-runs cheap and idempotent. Renewals afterwards are automatic (the
# certbot-renew sidecar + nginx's 6-hourly reload loop).
#
# Rate-limit note: sslip.io is NOT on the Public Suffix List, so every sslip.io
# user worldwide shares Let's Encrypt's per-registered-domain limit. If
# issuance fails with "too many certificates", the deployment keeps working on
# the self-signed wildcard — retry later, or move to a real domain
# (make set-public-host HOST=<domain>) and re-run this script.
set -euo pipefail
cd "$(dirname "$0")/.."

ALL_YML="ansible/group_vars/all.yml"
ADMIN_CONF="proxy/admin.d/admin.conf"
CERT_NAME="abd"
EMAIL="${LE_EMAIL:-shirley.carter66@gmail.com}"

log() { printf '[setup-letsencrypt] %s\n' "$*"; }
die() { printf '[setup-letsencrypt] ERROR: %s\n' "$*" >&2; exit 1; }

BASE_DOMAIN=$(sed -nE 's/^  base_domain: "([^"]*)".*/\1/p' "$ALL_YML")
[ -n "$BASE_DOMAIN" ] || die "cannot read proxy.base_domain from $ALL_YML"

# --- assemble the SAN list ---------------------------------------------------
DOMAINS=("admin.$BASE_DOMAIN")
shopt -s nullglob
site_files=(configs/sites/*.yaml)
for f in "${site_files[@]}"; do
    sid=$(basename "$f" .yaml)
    host="$sid.$BASE_DOMAIN"
    if grep -q 'server_name:' "$f"; then
        host=$(sed -nE 's/^ *server_name: *"?([^"]*)"?.*/\1/p' "$f" | head -1)
    fi
    DOMAINS+=("$host")
done
log "requesting one cert for: ${DOMAINS[*]}"

DOMAIN_ARGS=()
for d in "${DOMAINS[@]}"; do DOMAIN_ARGS+=(-d "$d"); done

EXTRA_ARGS=()
if [ "${LE_DRY_RUN:-}" = "1" ]; then
    EXTRA_ARGS+=(--dry-run)
    log "DRY RUN (staging): validates challenges, saves nothing, wires nothing"
fi

# --- issue / expand ----------------------------------------------------------
docker ps --format '{{.Names}}' | grep -q '^proxy-nginx$' \
    || die "proxy-nginx is not running — start the proxy stack first (make proxy)"

set +e
OUTPUT=$(docker compose -f docker-compose.proxy.yml run --rm --entrypoint certbot certbot-renew \
    certonly --webroot -w /var/www/certbot \
    --cert-name "$CERT_NAME" --expand --keep-until-expiring \
    --agree-tos --no-eff-email -m "$EMAIL" --non-interactive \
    "${DOMAIN_ARGS[@]}" "${EXTRA_ARGS[@]}" 2>&1)
STATUS=$?
set -e
printf '%s\n' "$OUTPUT"
if [ $STATUS -ne 0 ]; then
    if printf '%s' "$OUTPUT" | grep -qi 'too many certificates'; then
        die "Let's Encrypt rate limit hit for the shared sslip.io domain — the \
self-signed cert stays in place; retry later or switch to a real domain first."
    fi
    die "certbot failed (exit $STATUS) — nginx is untouched and keeps serving the current cert"
fi
if [ "${LE_DRY_RUN:-}" = "1" ]; then
    log "dry run OK — challenge plumbing works end to end"
    exit 0
fi

# --- wire nginx to the trusted cert -----------------------------------------
LIVE="/etc/letsencrypt/live/$CERT_NAME"

# 1. admin vhost: uncomment the managed #LE# lines (idempotent).
sed -i 's|^\([[:space:]]*\)#LE# |\1|' "$ADMIN_CONF"

# 2. honeypot sites: set proxy.tls_fullchain/tls_key in all.yml (idempotent),
#    then re-render every site so its server block carries the override.
if ! grep -q '^  tls_fullchain:' "$ALL_YML"; then
    sed -i "/^  server_aliases: /a\\
  # Publicly-trusted cert (Let's Encrypt; managed by scripts/setup-letsencrypt.sh\\
  # — re-run it after adding a site or changing the base domain). When these two\\
  # keys are present every site's server block presents this cert instead of the\\
  # self-signed wildcard. Remove both keys + re-run the playbook to roll back.\\
  tls_fullchain: \"$LIVE/fullchain.pem\"\\
  tls_key: \"$LIVE/privkey.pem\"" "$ALL_YML"
    log "added proxy.tls_fullchain/tls_key to $ALL_YML"
fi

for f in "${site_files[@]}"; do
    sid=$(basename "$f" .yaml)
    log "re-rendering site $sid"
    make playbook site_id="$sid" >/dev/null
done

docker exec proxy-nginx nginx -t
docker exec proxy-nginx nginx -s reload
log "nginx reloaded with the trusted certificate"

# --- verify: full TLS validation (no -k!) against the live proxy -------------
fail=0
for d in "${DOMAINS[@]}"; do
    code=$(curl -s -m 15 -o /dev/null -w '%{http_code}' --resolve "$d:443:127.0.0.1" "https://$d/" || true)
    # Admin vhost answers with the app's login redirect/page (200 or 303) --
    # any code proves the TLS handshake validated against the system CA store.
    if [ "$code" = "000" ]; then
        log "FAIL https://$d/ (TLS validation or connection failed)"
        fail=1
    else
        log "OK  https://$d/ (status $code, certificate trusted)"
    fi
done
[ "$fail" = "0" ] || die "a hostname failed trusted-TLS verification"

issuer=$(echo | openssl s_client -connect 127.0.0.1:443 -servername "${DOMAINS[0]}" 2>/dev/null \
    | openssl x509 -noout -issuer)
log "presented issuer: $issuer"
log "done — browsers now get a clean padlock on: ${DOMAINS[*]}"
