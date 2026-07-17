#!/usr/bin/env bash
# Obtain or reconcile ONE publicly-trusted certificate for the admin vhost and
# every *published* honeypot route.  YAML files are desired configuration, not
# deployment inventory: a config-only or cancelled site must never enter ACME.
#
# Usage:
#   scripts/setup-letsencrypt.sh
#   LE_DRY_RUN=1 scripts/setup-letsencrypt.sh
#   LE_EMAIL=you@example.org scripts/setup-letsencrypt.sh
#
# The script is safe to call after every successful site deployment.  It first
# compares the requested names with the current certificate and does not contact
# ACME when every published name is already covered.  Normal `certbot renew`
# later preserves this lineage; adding a hostname requires this reconciliation.
set -euo pipefail
cd "$(dirname "$0")/.."

ALL_YML="ansible/group_vars/all.yml"
ADMIN_CONF="proxy/admin.d/admin.conf"
CERT_NAME="abd"
LIVE="/etc/letsencrypt/live/$CERT_NAME"
EMAIL="${LE_EMAIL:-shirley.carter66@gmail.com}"
CERTBOT_CONTAINER="${TLS_CERTBOT_CONTAINER:-abd-certbot-reconcile}"
PUBLICATION_LOCK_DIR="configs/.publication.lock"
# Match the 14-day certificate-expiry alert. This is safely inside Certbot's
# normal renewal window, so an operator responding to the alert never gets a
# misleading final-day-only no-op.
CERT_MIN_VALID_SECONDS="${TLS_CERT_MIN_VALID_SECONDS:-1209600}"

log() { printf '[setup-letsencrypt] %s\n' "$*"; }
die() { printf '[setup-letsencrypt] ERROR: %s\n' "$*" >&2; exit 1; }

valid_dns_name() {
    local hostname="$1" label
    local -a labels
    [ -n "$hostname" ] && [ "${#hostname}" -le 253 ] || return 1
    [[ "$hostname" =~ ^[a-z0-9.-]+$ ]] || return 1
    [[ "$hostname" != .* && "$hostname" != *. && "$hostname" != *..* ]] || return 1
    IFS=. read -r -a labels <<< "$hostname"
    for label in "${labels[@]}"; do
        [ "${#label}" -le 63 ] || return 1
        [[ "$label" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || return 1
    done
}

resolve_project_path() {
    local raw="$1" resolved mounted
    raw=$(printf '%s' "$raw" | sed "s|{{ project_root }}|$PWD|g")
    case "$raw" in
        /*) ;;
        *) raw="$PWD/$raw" ;;
    esac
    [ -d "$raw" ] || die "configured proxy.conf_dir does not exist: $raw"
    resolved=$(cd "$raw" && pwd -P)
    mounted=$(cd "$PWD/proxy/conf.d" && pwd -P)
    [ "$resolved" = "$mounted" ] || die \
        "proxy.conf_dir must resolve to the nginx-mounted directory $mounted (got $resolved)"
    printf '%s\n' "$resolved"
}

[[ "$CERTBOT_CONTAINER" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$ ]] \
    || die "TLS_CERTBOT_CONTAINER is not a safe Docker container name"
[[ "$CERT_MIN_VALID_SECONDS" =~ ^[0-9]+$ ]] \
    || die "TLS_CERT_MIN_VALID_SECONDS must be a non-negative integer"

SETUP_LOCK_ACQUIRED=0
CERTBOT_ACTIVE=0
if [ "${ABD_PUBLICATION_LOCK_HELD:-}" != "1" ]; then
    if ! mkdir "$PUBLICATION_LOCK_DIR" 2>/dev/null; then
        die "another deployment/TLS/public-host transaction owns $PUBLICATION_LOCK_DIR"
    fi
    printf 'operation=setup-letsencrypt\n' > "$PUBLICATION_LOCK_DIR/owner"
    SETUP_LOCK_ACQUIRED=1
    export ABD_PUBLICATION_LOCK_HELD=1
fi

cleanup() {
    local status="$?" stop_output
    local cleanup_failed=0
    trap - EXIT INT TERM
    set +e
    if [ "$CERTBOT_ACTIVE" = "1" ]; then
        stop_output=$(docker rm -f "$CERTBOT_CONTAINER" 2>&1)
        if [ "$?" -ne 0 ] && [[ "$stop_output" != *"No such container"* ]]; then
            printf '[setup-letsencrypt] ERROR: could not confirm %s stopped; publication lock retained\n' \
                "$CERTBOT_CONTAINER" >&2
            cleanup_failed=1
        fi
    fi
    if [ "$SETUP_LOCK_ACQUIRED" = "1" ]; then
        if [ "$cleanup_failed" = "1" ]; then
            printf 'operation=setup-letsencrypt\naction=confirm-certbot-stopped\ncontainer=%s\n' \
                "$CERTBOT_CONTAINER" > "$PUBLICATION_LOCK_DIR/owner"
        else
            rm -rf "$PUBLICATION_LOCK_DIR"
        fi
    fi
    if [ "$cleanup_failed" = "1" ] && [ "$status" -eq 0 ]; then
        status=1
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

BASE_DOMAIN=$(sed -nE 's/^  base_domain: "([^"]*)".*/\1/p' "$ALL_YML")
[ -n "$BASE_DOMAIN" ] || die "cannot read proxy.base_domain from $ALL_YML"
valid_dns_name "$BASE_DOMAIN" || die "proxy.base_domain is not a valid DNS name: $BASE_DOMAIN"
valid_dns_name "admin.$BASE_DOMAIN" \
    || die "admin hostname is too long or invalid: admin.$BASE_DOMAIN"
RAW_PROXY_CONF_DIR=$(sed -nE 's/^  conf_dir: "?([^"]+)"?.*/\1/p' "$ALL_YML")
[ -n "$RAW_PROXY_CONF_DIR" ] || RAW_PROXY_CONF_DIR="proxy/conf.d"
PROXY_CONF_DIR=$(resolve_project_path "$RAW_PROXY_CONF_DIR")

docker ps --format '{{.Names}}' | grep -q '^proxy-nginx$' \
    || die "proxy-nginx is not running — start the proxy stack first (make proxy)"

# The final route file is the publication marker.  It is written only after a
# site's web container starts successfully; stale/config-only YAML is excluded.
DOMAINS=("admin.$BASE_DOMAIN")
ROUTE_SITE_IDS=()
ROUTES_TLS_WIRED=1
TRANSITION_DOMAINS=()
declare -A SEEN_DOMAINS=(["admin.$BASE_DOMAIN"]=1)
shopt -s nullglob
route_files=("$PROXY_CONF_DIR"/*.conf)
for f in "${route_files[@]}"; do
    sid=$(basename "$f" .conf)
    [[ "$sid" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] \
        || die "unsafe site id derived from published route: $f"
    host=$(sed -nE 's/^[[:space:]]*set[[:space:]]+\$site_name[[:space:]]+([^;]+);.*/\1/p' "$f" | head -1)
    [ -n "$host" ] || die "cannot read canonical \$site_name from published route $f"
    valid_dns_name "$host" \
        || die "published route $f has an invalid canonical hostname: $host"
    if ! grep -Eq "^[[:space:]]*ssl_certificate[[:space:]]+$LIVE/fullchain\.pem;" "$f" \
            || ! grep -Eq "^[[:space:]]*ssl_certificate_key[[:space:]]+$LIVE/privkey\.pem;" "$f"; then
        ROUTES_TLS_WIRED=0
    fi
    ROUTE_SITE_IDS+=("$sid")
    while IFS= read -r transition_domain; do
        [ -n "$transition_domain" ] || continue
        valid_dns_name "$transition_domain" \
            || die "published route $f has an invalid TLS transition name: $transition_domain"
        TRANSITION_DOMAINS+=("$transition_domain")
    done < <(sed -nE \
        's/^[[:space:]]*#[[:space:]]*abd_tls_transition_name[[:space:]]+([^[:space:]]+).*/\1/p' \
        "$f")
    if [ -z "${SEEN_DOMAINS[$host]:-}" ]; then
        DOMAINS+=("$host")
        SEEN_DOMAINS[$host]=1
    fi
done
while IFS= read -r transition_domain; do
    [ -n "$transition_domain" ] || continue
    valid_dns_name "$transition_domain" \
        || die "$ADMIN_CONF has an invalid TLS transition name: $transition_domain"
    TRANSITION_DOMAINS+=("$transition_domain")
done < <(sed -nE \
    's/^[[:space:]]*#[[:space:]]*abd_tls_transition_name[[:space:]]+([^[:space:]]+).*/\1/p' \
    "$ADMIN_CONF")
VERIFY_DOMAINS=("${DOMAINS[@]}")

CURRENT_DNS=$(docker exec proxy-nginx openssl x509 \
    -in "$LIVE/fullchain.pem" -noout -ext subjectAltName 2>/dev/null \
    | grep -oE 'DNS:[^,[:space:]]+' | sed 's/^DNS://' || true)
CERT_VALID=0
docker exec proxy-nginx openssl x509 -in "$LIVE/fullchain.pem" \
    -noout -checkend "$CERT_MIN_VALID_SECONDS" >/dev/null 2>&1 && CERT_VALID=1
declare -A CURRENT_DOMAIN_SET=()
CURRENT_DOMAIN_COUNT=0
while IFS= read -r current_domain; do
    [ -n "$current_domain" ] || continue
    if [ -z "${CURRENT_DOMAIN_SET[$current_domain]:-}" ]; then
        CURRENT_DOMAIN_SET[$current_domain]=1
        CURRENT_DOMAIN_COUNT=$((CURRENT_DOMAIN_COUNT + 1))
    fi
done <<< "$CURRENT_DNS"

# Automatic publication retains only explicitly marked transition names until
# route/rule/target commit. Their temporary nginx aliases keep HTTP-01
# reachable. Blindly retaining every stale SAN would make later issuance depend
# on hostnames that may no longer resolve here. A normal invocation still
# reconciles to the exact published canonical inventory.
if [ "${TLS_RETAIN_EXISTING:-}" = "1" ]; then
    for transition_domain in "${TRANSITION_DOMAINS[@]}"; do
        if [ -z "${SEEN_DOMAINS[$transition_domain]:-}" ]; then
            DOMAINS+=("$transition_domain")
            SEEN_DOMAINS[$transition_domain]=1
        fi
    done
fi
log "requested certificate inventory: ${DOMAINS[*]}"

DOMAIN_ARGS=()
for d in "${DOMAINS[@]}"; do DOMAIN_ARGS+=(-d "$d"); done

CERT_MATCHES_PUBLICATION=1
if [ "$CURRENT_DOMAIN_COUNT" -ne "${#DOMAINS[@]}" ]; then
    CERT_MATCHES_PUBLICATION=0
fi
for d in "${DOMAINS[@]}"; do
    if [ -z "${CURRENT_DOMAIN_SET[$d]:-}" ]; then
        CERT_MATCHES_PUBLICATION=0
        break
    fi
done

TLS_FULLCHAIN_SET=0
TLS_KEY_SET=0
grep -q '^  tls_fullchain:' "$ALL_YML" && TLS_FULLCHAIN_SET=1
grep -q '^  tls_key:' "$ALL_YML" && TLS_KEY_SET=1
[ "$TLS_FULLCHAIN_SET" = "$TLS_KEY_SET" ] \
    || die "$ALL_YML has only one of proxy.tls_fullchain/proxy.tls_key; repair the pair first"
if [ "$TLS_FULLCHAIN_SET" = "1" ]; then
    TLS_FULLCHAIN_VALUE=$(sed -nE 's/^  tls_fullchain: "?([^"]+)"?.*/\1/p' "$ALL_YML")
    TLS_KEY_VALUE=$(sed -nE 's/^  tls_key: "?([^"]+)"?.*/\1/p' "$ALL_YML")
    [ "$TLS_FULLCHAIN_VALUE" = "$LIVE/fullchain.pem" ] \
        && [ "$TLS_KEY_VALUE" = "$LIVE/privkey.pem" ] \
        || die "$ALL_YML trusted TLS paths do not match the managed $CERT_NAME lineage"
fi

ADMIN_CERT_SET=0
ADMIN_KEY_SET=0
grep -Eq "^[[:space:]]*ssl_certificate[[:space:]]+$LIVE/fullchain\.pem;" "$ADMIN_CONF" \
    && ADMIN_CERT_SET=1
grep -Eq "^[[:space:]]*ssl_certificate_key[[:space:]]+$LIVE/privkey\.pem;" "$ADMIN_CONF" \
    && ADMIN_KEY_SET=1
[ "$ADMIN_CERT_SET" = "$ADMIN_KEY_SET" ] \
    || die "$ADMIN_CONF has only one active trusted-certificate directive; repair the pair first"
ADMIN_TLS_WIRED=$ADMIN_CERT_SET

# Fast, rate-limit-safe no-op for the automatic post-deploy path.
if [ "${LE_DRY_RUN:-}" != "1" ] && [ "$CERT_MATCHES_PUBLICATION" = "1" ] \
        && [ "$CERT_VALID" = "1" ] \
        && [ "$TLS_FULLCHAIN_SET" = "1" ] && [ "$ADMIN_TLS_WIRED" = "1" ] \
        && [ "$ROUTES_TLS_WIRED" = "1" ]; then
    log "certificate already covers every published hostname"
    exit 0
fi

EXTRA_ARGS=()
if [ "${LE_DRY_RUN:-}" = "1" ]; then
    EXTRA_ARGS+=(--dry-run)
    log "DRY RUN (staging): validates changed-domain challenges, saves and wires nothing"
fi

# --renew-with-new-domains handles both a strict expansion and a changed set
# after a site is retired.  --expand alone rejects the latter because the old
# certificate is no longer a strict subset of the desired names. If the exact
# lineage already exists but has not been wired into Ansible yet, reuse it and
# avoid an unnecessary issuance attempt.
if [ "${LE_DRY_RUN:-}" = "1" ] || [ "$CERT_MATCHES_PUBLICATION" = "0" ] \
        || [ "$CERT_VALID" = "0" ]; then
    set +e
    CERTBOT_ACTIVE=1
    OUTPUT=$(docker compose -f docker-compose.proxy.yml run --rm \
        --name "$CERTBOT_CONTAINER" --entrypoint certbot certbot-renew \
        certonly --webroot -w /var/www/certbot \
        --cert-name "$CERT_NAME" --renew-with-new-domains \
        --agree-tos --no-eff-email -m "$EMAIL" --non-interactive \
        "${DOMAIN_ARGS[@]}" "${EXTRA_ARGS[@]}" 2>&1)
    STATUS=$?
    STOP_OUTPUT=$(docker rm -f "$CERTBOT_CONTAINER" 2>&1)
    STOP_STATUS=$?
    if [ "$STOP_STATUS" -eq 0 ] || [[ "$STOP_OUTPUT" == *"No such container"* ]]; then
        CERTBOT_ACTIVE=0
    else
        printf '%s\n' "$OUTPUT"
        die "could not confirm $CERTBOT_CONTAINER stopped after Certbot returned; cleanup will retain the publication lock unless a final stop succeeds"
    fi
    set -e
    printf '%s\n' "$OUTPUT"
    if [ "$STATUS" -ne 0 ]; then
        if printf '%s' "$OUTPUT" | grep -qi 'too many certificates'; then
            die "Let's Encrypt rate limit hit for sslip.io; the existing certificate remains active"
        fi
        die "certbot failed (exit $STATUS); nginx still serves the existing certificate"
    fi
else
    log "existing certificate exactly matches the published hostname inventory; wiring it without contacting ACME"
fi
if [ "${LE_DRY_RUN:-}" = "1" ]; then
    log "dry run OK — changed-domain challenge plumbing works end to end"
    exit 0
fi

# First-time wiring only.  Later reconciliations update the same Certbot
# lineage/symlinks, so published vhosts already point at the new certificate.
sed -i 's|^\([[:space:]]*\)#LE# |\1|' "$ADMIN_CONF"
grep -Eq "^[[:space:]]*ssl_certificate[[:space:]]+$LIVE/fullchain\.pem;" "$ADMIN_CONF" \
    && grep -Eq "^[[:space:]]*ssl_certificate_key[[:space:]]+$LIVE/privkey\.pem;" "$ADMIN_CONF" \
    || die "$ADMIN_CONF does not contain the managed trusted-certificate pair"
ADDED_TLS_KEYS=0
if [ "$TLS_FULLCHAIN_SET" = "0" ]; then
    sed -i "/^  server_aliases: /a\\
  # Publicly-trusted cert (Let's Encrypt; managed by scripts/setup-letsencrypt.sh).\\
  tls_fullchain: \"$LIVE/fullchain.pem\"\\
  tls_key: \"$LIVE/privkey.pem\"" "$ALL_YML"
    log "added proxy.tls_fullchain/tls_key to $ALL_YML"
    ADDED_TLS_KEYS=1
fi

# Re-render only routes that were already public when trusted TLS was newly
# configured or a stale route still inherited the self-signed certificate.
# render_only prevents certificate maintenance from starting YAML-only sites;
# skip_tls_sync prevents recursive invocation through the publish role.
if [ "$ADDED_TLS_KEYS" = "1" ] || [ "$ROUTES_TLS_WIRED" = "0" ]; then
    for sid in "${ROUTE_SITE_IDS[@]}"; do
        log "re-rendering published route $sid with trusted TLS"
        make playbook site_id="$sid" \
            PLAYBOOK_EXTRA="-e render_only=true -e skip_tls_sync=true" >/dev/null
    done
fi

docker exec proxy-nginx nginx -t
docker exec proxy-nginx nginx -s reload
log "nginx reloaded with the reconciled trusted certificate"

# Full hostname validation runs inside proxy-nginx's network namespace. This is
# correct whether the script is launched on the host or by Ansible inside the
# app container, and the site-only health endpoint avoids synthetic visits and
# canary assignments. Trusted TLS is intentional here: never add -k.
#
# `nginx -s reload` returns as soon as the master accepts the signal, but worker
# replacement is asynchronous: for a short window the outgoing worker still owns
# the listening socket, accepts a new connection, then closes it as it shuts
# down. With `http2 on` the client sees that as a framing error (curl exit 16,
# http_code 000) — a dead connection, not an untrusted certificate. Verification
# runs immediately after that reload, so without this retry the FIRST hostname
# in the list absorbed the race and condemned a certificate that was fine.
#
# That made every hostname-set change flaky, which is precisely when this
# reconciliation runs at all: an unchanged inventory takes the no-op fast path
# above and never reaches here. So the bug only ever hit deploying a NEW site.
#
# Only a connection-level failure (000) is retried. A real HTTP answer — an
# unexpected status, an untrusted chain — is a definitive verdict and still
# fails immediately, so this cannot paper over a genuinely broken certificate.
verify_hostname() {
    docker exec proxy-nginx curl --noproxy '*' -s -m 15 \
        -o /dev/null -w '%{http_code}' --resolve "$1:443:127.0.0.1" \
        "https://$1$2" || true
}

fail=0
for d in "${VERIFY_DOMAINS[@]}"; do
    verify_path="/"
    expected_code="303"
    if [ "$d" != "admin.$BASE_DOMAIN" ]; then
        verify_path="/__abd_health"
        expected_code="204"
    fi
    code=""
    for attempt in 1 2 3 4 5; do
        code=$(verify_hostname "$d" "$verify_path")
        [ "$code" = "000" ] || break
        [ "$attempt" = "5" ] || sleep 1
    done
    if [ "$code" = "000" ]; then
        log "FAIL https://$d/ (TLS validation or connection failed)"
        fail=1
    elif [ "$code" != "$expected_code" ]; then
        log "FAIL https://$d$verify_path (expected $expected_code, got $code)"
        fail=1
    else
        log "OK  https://$d$verify_path (status $code, certificate trusted)"
    fi
done
[ "$fail" = "0" ] || die "a published hostname failed trusted-TLS verification"

issuer=$(docker exec proxy-nginx openssl x509 \
    -in "$LIVE/fullchain.pem" -noout -issuer)
log "presented issuer: $issuer"
log "done — trusted TLS covers: ${DOMAINS[*]}"
