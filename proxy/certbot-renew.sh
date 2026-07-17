#!/bin/sh
# Scheduled Certbot renewal under the same host-visible publication lock used
# by site deployment, public-host migration, and one-shot TLS reconciliation.
# This prevents renewal from replacing the shared lineage while another
# transaction snapshots, changes, or restores its route/certificate state.

set -u

LOCK_DIR=/project/configs/.publication.lock
RENEW_INTERVAL_SECONDS=${CERTBOT_RENEW_INTERVAL_SECONDS:-43200}
LOCK_RETRY_SECONDS=${CERTBOT_LOCK_RETRY_SECONDS:-300}
lock_owned=0
child_pid=

log() {
    printf '[certbot-renew] %s\n' "$*"
}

cleanup() {
    status=$?
    trap - EXIT INT TERM
    if [ -n "$child_pid" ]; then
        kill -TERM "$child_pid" 2>/dev/null || true
        wait "$child_pid" 2>/dev/null || true
        child_pid=
    fi
    if [ "$lock_owned" = "1" ]; then
        if rm -rf "$LOCK_DIR"; then
            lock_owned=0
        else
            log "ERROR: publication lock could not be released; it remains for operator recovery"
        fi
    fi
    exit "$status"
}

trap cleanup EXIT INT TERM

while :; do
    delay=$LOCK_RETRY_SECONDS
    if mkdir "$LOCK_DIR" 2>/dev/null; then
        lock_owned=1
        printf 'operation=scheduled-certbot-renew\n' > "$LOCK_DIR/owner"
        log "publication lock acquired; checking certificate renewal"

        certbot renew --webroot -w /var/www/certbot --quiet &
        child_pid=$!
        if wait "$child_pid"; then
            log "renewal check complete"
        else
            log "renewal check failed; it will be retried on the next interval"
        fi
        child_pid=

        if rm -rf "$LOCK_DIR"; then
            lock_owned=0
        else
            log "ERROR: publication lock release failed; stopping after one cleanup retry"
            exit 1
        fi
        delay=$RENEW_INTERVAL_SECONDS
    else
        log "publication transaction busy; retrying in ${LOCK_RETRY_SECONDS}s"
    fi

    sleep "$delay" &
    child_pid=$!
    wait "$child_pid" || true
    child_pid=
done
