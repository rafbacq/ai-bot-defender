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
#   1. Capture the currently published route inventory, then update
#      ansible/group_vars/all.yml: proxy.base_domain (shared aliases stay empty)
#   2. .env: PROXY_BASE_DOMAIN / PROXY_EXTRA_SAN (read by docker-compose.proxy.yml)
#      and refreshes a running Grafana so its /grafana/ root follows the host
#   3. Regenerates the self-signed wildcard cert iff it doesn't already cover
#      the new base domain, and hot-reloads nginx
#   4. Re-renders only the routes that were already published; config-only
#      sites remain config-only and no containers are created/restarted
#   5. Verifies: cert SAN + HTTP/HTTPS for each published route through nginx
#
# Idempotent: re-running with an unchanged address is a no-op apart from the
# playbook re-render.
set -euo pipefail
cd "$(dirname "$0")/.."

ALL_YML="ansible/group_vars/all.yml"
ENV_FILE=".env"
CRT="proxy/certs/wildcard.crt"
KEY="proxy/certs/wildcard.key"
ADMIN_CONF="proxy/admin.d/admin.conf"
RULES_DIR="monitoring/alerts.d"
TARGETS_DIR="monitoring/targets.d"
CERTBOT_CONTAINER="abd-certbot-reconcile-public-host"
CERT_SNAPSHOT_CONTAINER="abd-cert-snapshot-public-host"
CERTGEN_CONTAINER="abd-certgen-public-host"
PLAYBOOK_CONTAINER="abd-public-host-playbook"
CERT_SNAPSHOT_ID="public-host-$$"
CERT_SNAPSHOT_CREATED=0
PUBLICATION_LOCK_DIR="configs/.publication.lock"

log() { printf '[set-public-host] %s\n' "$*"; }
die() { printf '[set-public-host] ERROR: %s\n' "$*" >&2; exit 1; }

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

if ! mkdir "$PUBLICATION_LOCK_DIR" 2>/dev/null; then
    die "another deployment/TLS/public-host transaction owns $PUBLICATION_LOCK_DIR"
fi
printf 'operation=set-public-host\n' > "$PUBLICATION_LOCK_DIR/owner"
export ABD_PUBLICATION_LOCK_HELD=1
# Protect validation failures before the full transactional EXIT handler exists.
trap 'rm -rf "$PUBLICATION_LOCK_DIR"' EXIT

RAW_PROXY_CONF_DIR=$(sed -nE 's/^  conf_dir: "?([^"]+)"?.*/\1/p' "$ALL_YML")
[ -n "$RAW_PROXY_CONF_DIR" ] || RAW_PROXY_CONF_DIR="proxy/conf.d"
PROXY_CONF_DIR=$(resolve_project_path "$RAW_PROXY_CONF_DIR")

# Final nginx route files are the public deployment inventory. Capture them
# before changing the base domain, because their canonical names will change
# when render_only refreshes them later in this script.
shopt -s nullglob
route_files=("$PROXY_CONF_DIR"/*.conf)
PUBLISHED_SITE_IDS=()
for f in "${route_files[@]}"; do
    sid=$(basename "$f" .conf)
    [[ "$sid" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] \
        || die "unsafe site id derived from published route: $f"
    [ -f "configs/sites/$sid.yaml" ] \
        || die "published route $f has no configs/sites/$sid.yaml"
    PUBLISHED_SITE_IDS+=("$sid")
done
if [ ${#PUBLISHED_SITE_IDS[@]} -gt 0 ] \
        && ! docker ps --format '{{.Names}}' | grep -q '^proxy-nginx$'; then
    die "proxy-nginx must be running to validate published route updates; start it with make proxy"
fi

imds_public_ip() {
    local token
    token=$(curl -s -m 5 -X PUT http://169.254.169.254/latest/api/token \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null) || return 0
    curl -s -m 5 -H "X-aws-ec2-metadata-token: $token" \
        http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || true
}

valid_ipv4() {
    local address="$1" octet
    local -a octets
    IFS=. read -r -a octets <<< "$address"
    [ "${#octets[@]}" -eq 4 ] || return 1
    for octet in "${octets[@]}"; do
        [[ "$octet" =~ ^[0-9]{1,3}$ ]] || return 1
        (( 10#$octet <= 255 )) || return 1
    done
}

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

TARGET="${1:-}"
if [ -z "$TARGET" ]; then
    TARGET=$(imds_public_ip)
    [ -n "$TARGET" ] || die "no address given and EC2 metadata auto-detect failed; run: $0 <public-ip-or-domain>"
    log "auto-detected public IP: $TARGET"
fi
TARGET=${TARGET,,}

if [[ "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    valid_ipv4 "$TARGET" || die "invalid IPv4 address: $TARGET"
    PUBIP="$TARGET"
    BASE_DOMAIN="${TARGET}.sslip.io"   # public wildcard DNS: *.<ip>.sslip.io -> <ip>
else
    valid_dns_name "$TARGET" || die "invalid DNS base domain: $TARGET"
    BASE_DOMAIN="$TARGET"
    PUBIP=$(imds_public_ip)            # retain only as a self-signed cert SAN
    if [ -n "$PUBIP" ] && ! valid_ipv4 "$PUBIP"; then
        die "EC2 metadata returned an invalid public IPv4 address"
    fi
fi

EXTRA_SAN=""
if [ -n "$PUBIP" ]; then
    EXTRA_SAN="IP:$PUBIP"
fi

# Snapshot every publication/identity file before the first mutation. The EXIT
# trap restores the exact prior state after any mid-migration failure (route
# conflict, cert generation, trusted-TLS reconciliation, or health check).
BACKUP_DIR=$(mktemp -d /tmp/abd-public-host.XXXXXX)
MUTATION_STARTED=0
COMMITTED=0
GRAFANA_WAS_RUNNING=0
docker ps --format '{{.Names}}' | grep -q '^mon-grafana$' \
    && GRAFANA_WAS_RUNNING=1
APP_WAS_RUNNING=0
docker ps --format '{{.Names}}' | grep -q '^ai-bot-defender-app$' \
    && APP_WAS_RUNNING=1
TRUSTED_TLS_WAS_CONFIGURED=0
if grep -q '^  tls_fullchain:' "$ALL_YML" \
        && grep -q '^  tls_key:' "$ALL_YML"; then
    TRUSTED_TLS_WAS_CONFIGURED=1
fi
OLD_ADMIN_HOST=$(sed -nE \
    's/^[[:space:]]*server_name[[:space:]]+([^[:space:];]+).*/\1/p' \
    "$ADMIN_CONF" | head -1)
if [ "$TRUSTED_TLS_WAS_CONFIGURED" = "1" ]; then
    [ -n "$OLD_ADMIN_HOST" ] \
        || die "cannot read the prior admin hostname from $ADMIN_CONF"
    valid_dns_name "$OLD_ADMIN_HOST" \
        || die "prior admin hostname is invalid: $OLD_ADMIN_HOST"
fi

snapshot_file() {
    local source="$1" key="$2"
    if [ -e "$source" ]; then
        cp -p "$source" "$BACKUP_DIR/$key"
        : > "$BACKUP_DIR/$key.present"
    fi
}

restore_file() {
    local destination="$1" key="$2" temporary
    if [ -f "$BACKUP_DIR/$key.present" ]; then
        mkdir -p "$(dirname "$destination")"
        temporary="$destination.rollback.$$"
        cp -p "$BACKUP_DIR/$key" "$temporary"
        mv -f "$temporary" "$destination"
    else
        rm -f "$destination"
    fi
}

snapshot_trusted_lineage() {
    docker compose -f docker-compose.proxy.yml run --rm \
        --name "$CERT_SNAPSHOT_CONTAINER" --entrypoint sh certbot-renew -ec "
set -eu
root=/etc/letsencrypt/.abd-rollback/$CERT_SNAPSHOT_ID
tmp=\${root}.tmp
rm -rf \"\$tmp\" \"\$root\"
mkdir -p \"\$tmp\"
cp -a /etc/letsencrypt/live/abd \"\$tmp/live\"
if [ -f /etc/letsencrypt/renewal/abd.conf ]; then
    cp -a /etc/letsencrypt/renewal/abd.conf \"\$tmp/abd.conf\"
fi
mv \"\$tmp\" \"\$root\"
"
    CERT_SNAPSHOT_CREATED=1
}

restore_trusted_lineage() {
    docker compose -f docker-compose.proxy.yml run --rm \
        --name "$CERT_SNAPSHOT_CONTAINER" --entrypoint sh certbot-renew -ec "
set -eu
root=/etc/letsencrypt/.abd-rollback/$CERT_SNAPSHOT_ID
test -d \"\$root/live\"
rm -rf /etc/letsencrypt/live/abd.restore
cp -a \"\$root/live\" /etc/letsencrypt/live/abd.restore
rm -rf /etc/letsencrypt/live/abd
mv /etc/letsencrypt/live/abd.restore /etc/letsencrypt/live/abd
if [ -f \"\$root/abd.conf\" ]; then
    cp -a \"\$root/abd.conf\" /etc/letsencrypt/renewal/abd.conf.restore
    mv /etc/letsencrypt/renewal/abd.conf.restore /etc/letsencrypt/renewal/abd.conf
fi
rm -rf \"\$root\"
"
}

discard_trusted_lineage_snapshot() {
    docker compose -f docker-compose.proxy.yml run --rm \
        --name "$CERT_SNAPSHOT_CONTAINER" --entrypoint sh certbot-renew \
        -ec "rm -rf /etc/letsencrypt/.abd-rollback/$CERT_SNAPSHOT_ID"
}

run_site_playbook() {
    local sid="$1" preserve_transition="${2:-0}"
    local -a extra=(
        -e render_only=true
        -e skip_tls_sync=true
    )
    if [ "$preserve_transition" = "1" ]; then
        extra+=( -e preserve_tls_transition_alias=true )
    fi
    docker compose -f docker-compose.app.yml run --rm --no-deps \
        --name "$PLAYBOOK_CONTAINER" \
        -e ABD_PUBLICATION_LOCK_HELD=1 \
        -w "$PWD/ansible" app \
        ansible-playbook site.yml -e "site_id=$sid" "${extra[@]}"
}

snapshot_file "$ALL_YML" all-yml
snapshot_file "$ENV_FILE" env
snapshot_file "$ADMIN_CONF" admin-conf
snapshot_file "$CRT" wildcard-crt
snapshot_file "$KEY" wildcard-key
for sid in "${PUBLISHED_SITE_IDS[@]}"; do
    snapshot_file "$PROXY_CONF_DIR/$sid.conf" "route-$sid"
    snapshot_file "$RULES_DIR/$sid.yml" "rule-$sid"
    snapshot_file "$TARGETS_DIR/$sid.yml" "target-$sid"
done

rollback_on_exit() {
    local status="$?" sid cleanup_output
    local rollback_failed=0 safe_to_restore=1
    trap - EXIT INT TERM
    if [ "$COMMITTED" != "1" ] && [ "$MUTATION_STARTED" = "1" ]; then
        set +e
        log "migration failed; restoring the previous public identity"
        cleanup_output=$(docker rm -f "$CERTBOT_CONTAINER" 2>&1)
        if [ "$?" -ne 0 ] && [[ "$cleanup_output" != *"No such container"* ]]; then
            log "ERROR: could not stop $CERTBOT_CONTAINER before rollback"
            rollback_failed=1
            safe_to_restore=0
        fi
        cleanup_output=$(docker rm -f "$CERTGEN_CONTAINER" 2>&1)
        if [ "$?" -ne 0 ] && [[ "$cleanup_output" != *"No such container"* ]]; then
            log "ERROR: could not stop $CERTGEN_CONTAINER before rollback"
            rollback_failed=1
            safe_to_restore=0
        fi
        cleanup_output=$(docker rm -f "$PLAYBOOK_CONTAINER" 2>&1)
        if [ "$?" -ne 0 ] && [[ "$cleanup_output" != *"No such container"* ]]; then
            log "ERROR: could not stop $PLAYBOOK_CONTAINER before rollback"
            rollback_failed=1
            safe_to_restore=0
        fi
        cleanup_output=$(docker rm -f "$CERT_SNAPSHOT_CONTAINER" 2>&1)
        if [ "$?" -ne 0 ] && [[ "$cleanup_output" != *"No such container"* ]]; then
            log "ERROR: could not stop $CERT_SNAPSHOT_CONTAINER before rollback"
            rollback_failed=1
            safe_to_restore=0
        fi
        if [ "$safe_to_restore" = "1" ]; then
            restore_file "$ALL_YML" all-yml \
                || { log "ERROR: could not restore $ALL_YML"; rollback_failed=1; }
            restore_file "$ENV_FILE" env \
                || { log "ERROR: could not restore $ENV_FILE"; rollback_failed=1; }
            restore_file "$ADMIN_CONF" admin-conf \
                || { log "ERROR: could not restore $ADMIN_CONF"; rollback_failed=1; }
            restore_file "$CRT" wildcard-crt \
                || { log "ERROR: could not restore $CRT"; rollback_failed=1; }
            restore_file "$KEY" wildcard-key \
                || { log "ERROR: could not restore $KEY"; rollback_failed=1; }
            for sid in "${PUBLISHED_SITE_IDS[@]}"; do
                restore_file "$PROXY_CONF_DIR/$sid.conf" "route-$sid" \
                    || { log "ERROR: could not restore route $sid"; rollback_failed=1; }
                restore_file "$RULES_DIR/$sid.yml" "rule-$sid" \
                    || { log "ERROR: could not restore rule $sid"; rollback_failed=1; }
                restore_file "$TARGETS_DIR/$sid.yml" "target-$sid" \
                    || { log "ERROR: could not restore target $sid"; rollback_failed=1; }
                rm -f "$PROXY_CONF_DIR/.$sid.candidate" \
                    || { log "ERROR: could not remove candidate $sid"; rollback_failed=1; }
            done
            if [ "$CERT_SNAPSHOT_CREATED" = "1" ]; then
                restore_trusted_lineage \
                    || { log "ERROR: could not restore the prior trusted-certificate lineage"; rollback_failed=1; }
            fi
            if docker ps --format '{{.Names}}' | grep -q '^proxy-nginx$'; then
                docker exec proxy-nginx nginx -t \
                    && docker exec proxy-nginx nginx -s reload \
                    || { log "ERROR: restored nginx files need manual validation/reload"; rollback_failed=1; }
            fi
            if docker ps --format '{{.Names}}' | grep -q '^mon-prometheus$'; then
                docker kill --signal=HUP mon-prometheus >/dev/null 2>&1 \
                    || { log "ERROR: Prometheus needs a manual restored-rule reload"; rollback_failed=1; }
            fi
            if [ "$GRAFANA_WAS_RUNNING" = "1" ]; then
                docker compose -f docker-compose.monitoring.yml up -d grafana \
                    || { log "ERROR: Grafana needs a manual refresh with the restored .env"; rollback_failed=1; }
            fi
            if [ "$APP_WAS_RUNNING" = "1" ]; then
                docker compose -f docker-compose.app.yml up -d app \
                    || { log "ERROR: the app needs a manual refresh with the restored .env"; rollback_failed=1; }
            fi
        else
            log "ERROR: no route, certificate, monitoring, or app state was restored because a daemon-side certificate mutation may still be active"
        fi
    fi
    if [ "$rollback_failed" = "1" ]; then
        log "ERROR: rollback was incomplete; preserving recovery files at $BACKUP_DIR"
        log "ERROR: safety lock retained at $PUBLICATION_LOCK_DIR"
    else
        rm -rf "$BACKUP_DIR"
        rm -rf "$PUBLICATION_LOCK_DIR"
    fi
    exit "$status"
}

trap rollback_on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

log "base domain     : $BASE_DOMAIN  (sites answer at <site-id>.$BASE_DOMAIN)"
log "raw-IP cert SAN : ${PUBIP:-<none>}  (raw Host traffic stays in the unmatched 444 vhost)"

MUTATION_STARTED=1
if [ "$TRUSTED_TLS_WAS_CONFIGURED" = "1" ]; then
    log "snapshotting the current trusted-certificate lineage for rollback"
    snapshot_trusted_lineage
fi

# --- 1. ansible/group_vars/all.yml -----------------------------------------
grep -q '^  base_domain: "' "$ALL_YML" || die "cannot find '  base_domain: \"...\"' in $ALL_YML"
grep -q '^  server_aliases: \[' "$ALL_YML" || die "cannot find '  server_aliases: [...]' in $ALL_YML"
sed -E -i "s|^(  base_domain: )\"[^\"]*\"|\\1\"$BASE_DOMAIN\"|" "$ALL_YML"
sed -E -i "s|^(  server_aliases: )\[[^]]*\]|\\1[]|" "$ALL_YML"
log "updated $ALL_YML"

# Keep the admin vhost's canonical name on the same base domain.
if [ -f "$ADMIN_CONF" ]; then
    if [ "$TRUSTED_TLS_WAS_CONFIGURED" = "1" ] \
            && [ "$OLD_ADMIN_HOST" != "admin.$BASE_DOMAIN" ]; then
        sed -E -i "s|server_name admin\.[^;]*;|server_name admin.$BASE_DOMAIN $OLD_ADMIN_HOST;|g" "$ADMIN_CONF"
        sed -i "/server_name admin\.$BASE_DOMAIN /i\\    # abd_tls_transition_name $OLD_ADMIN_HOST" "$ADMIN_CONF"
    else
        sed -E -i "s|server_name admin\.[^;]*;|server_name admin.$BASE_DOMAIN;|g" "$ADMIN_CONF"
    fi
    log "updated $ADMIN_CONF server_name -> admin.$BASE_DOMAIN"
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

# Grafana's public root URL embeds PROXY_BASE_DOMAIN. If the monitoring stack
# is live, recreate only Grafana so links/cookies immediately follow the new
# admin hostname; otherwise the next `make monitoring` picks it up naturally.
if docker ps --format '{{.Names}}' | grep -q '^mon-grafana$'; then
    log "refreshing mon-grafana root URL -> https://admin.$BASE_DOMAIN/grafana/"
    docker network create monitoring_bridge >/dev/null 2>&1 || true
    docker compose -f docker-compose.monitoring.yml up -d grafana
fi

# --- 3. TLS cert -------------------------------------------------------------
if [ -s "$CRT" ] && openssl x509 -in "$CRT" -noout -ext subjectAltName 2>/dev/null \
        | grep -q "DNS:\*\.$BASE_DOMAIN"; then
    log "cert already covers *.$BASE_DOMAIN — keeping it"
else
    log "regenerating wildcard cert for *.$BASE_DOMAIN"
    rm -f proxy/certs/wildcard.crt proxy/certs/wildcard.key
    docker compose -f docker-compose.proxy.yml run --rm \
        --name "$CERTGEN_CONTAINER" certgen
    if docker ps --format '{{.Names}}' | grep -q '^proxy-nginx$'; then
        docker exec proxy-nginx nginx -t
        docker exec proxy-nginx nginx -s reload
        log "nginx reloaded with the new cert"
    else
        log "proxy-nginx not running — cert will be picked up on next 'make proxy'"
    fi
fi

# --- 4. re-render only the routes that were already published ---------------
if [ ${#PUBLISHED_SITE_IDS[@]} -eq 0 ]; then
    log "no published site routes — nothing to re-render"
else
    for sid in "${PUBLISHED_SITE_IDS[@]}"; do
        log "re-rendering published route $sid (containers untouched)"
        run_site_playbook "$sid" 1
    done
fi

# When trusted TLS is already managed, migrate it in the same transaction. The
# saved Certbot lineage—not old-name reauthorization—makes rollback safe when
# an old sslip.io address no longer resolves to this instance.
TRUSTED_TLS=$TRUSTED_TLS_WAS_CONFIGURED
if [ "$TRUSTED_TLS" = "1" ]; then
    log "reconciling trusted TLS for the new published hostnames"
    TLS_CERTBOT_CONTAINER="$CERTBOT_CONTAINER" \
        scripts/setup-letsencrypt.sh

    # The prior lineage snapshot makes rollback certificate-safe even when old
    # sslip.io DNS no longer points here, so this issuance is exact-new rather
    # than depending on old-name HTTP-01 authorization.
    sed -i '/abd_tls_transition_name /d' "$ADMIN_CONF"
    sed -E -i "s|server_name admin\.[^;]*;|server_name admin.$BASE_DOMAIN;|g" "$ADMIN_CONF"
    for sid in "${PUBLISHED_SITE_IDS[@]}"; do
        log "finalizing published route $sid without TLS transition aliases"
        run_site_playbook "$sid"
    done
fi

# --- 5. verify ---------------------------------------------------------------
log "cert SAN: $(openssl x509 -in "$CRT" -noout -ext subjectAltName | tail -1 | sed 's/^ *//')"
fail=0
for sid in "${PUBLISHED_SITE_IDS[@]}"; do
    route="$PROXY_CONF_DIR/$sid.conf"
    host=$(sed -nE 's/^[[:space:]]*set[[:space:]]+\$site_name[[:space:]]+([^;]+);.*/\1/p' "$route" | head -1)
    [ -n "$host" ] || die "cannot read canonical hostname from $route"
    code_http=000; code_https=000
    for _ in 1 2 3 4 5 6; do
        # Run from nginx's own loopback namespace so this works from either the
        # host or app container. The private health route verifies Flask, DB,
        # and Jinja without minting canaries or entering research request logs.
        code_http=$(docker exec proxy-nginx curl --noproxy '*' -s -m 10 \
            -o /dev/null -w '%{http_code}' -H "Host: $host" \
            http://127.0.0.1/__abd_health || true)
        if [ "$TRUSTED_TLS" = "1" ]; then
            code_https=$(docker exec proxy-nginx curl --noproxy '*' -s -m 10 \
                -o /dev/null -w '%{http_code}' --resolve "$host:443:127.0.0.1" \
                "https://$host/__abd_health" || true)
        else
            code_https=$(docker exec proxy-nginx curl --noproxy '*' -sk -m 10 \
                -o /dev/null -w '%{http_code}' --resolve "$host:443:127.0.0.1" \
                "https://$host/__abd_health" || true)
        fi
        [ "$code_http" = "204" ] && [ "$code_https" = "204" ] && break
        sleep 5
    done
    if [ "$code_http" = "204" ] && [ "$code_https" = "204" ]; then
        log "OK  $host  (http $code_http, https $code_https)"
    else
        log "FAIL $host  (http $code_http, https $code_https)"
        fail=1
    fi
done
[ "$fail" = "0" ] || die "one or more sites failed verification — check 'make proxy-logs'"

# Direct script invocation is a supported path, so a running control center
# must consume the newly committed APP_BASE_URL here rather than relying on a
# surrounding Make target. Failure remains inside the rollback transaction.
if [ "$APP_WAS_RUNNING" = "1" ]; then
    log "refreshing ai-bot-defender-app with APP_BASE_URL=https://admin.$BASE_DOMAIN"
    docker compose -f docker-compose.app.yml up -d app
fi

# No fallible migration work remains after this point.
COMMITTED=1
if [ "$CERT_SNAPSHOT_CREATED" = "1" ]; then
    log "discarding committed trusted-certificate rollback snapshot"
    if discard_trusted_lineage_snapshot; then
        CERT_SNAPSHOT_CREATED=0
    else
        log "WARNING: migration committed, but stale rollback snapshot $CERT_SNAPSHOT_ID remains in the letsencrypt volume"
    fi
fi
trap - EXIT INT TERM
rm -rf "$BACKUP_DIR"
rm -rf "$PUBLICATION_LOCK_DIR"

log "done. Public URLs (once the security group allows 80/443):"
for sid in "${PUBLISHED_SITE_IDS[@]}"; do
    route="$PROXY_CONF_DIR/$sid.conf"
    host=$(sed -nE 's/^[[:space:]]*set[[:space:]]+\$site_name[[:space:]]+([^;]+);.*/\1/p' "$route" | head -1)
    log "  http://$host/   https://$host/"
done
log "  control center: https://admin.$BASE_DOMAIN/"
