#!/usr/bin/env bash
# Keep the passive TLS/TCP capture sidecar attached to the CURRENT nginx
# network namespace. Docker stores network_mode: service:nginx as the concrete
# nginx container ID when tls-capture is created. If Compose later replaces
# nginx but leaves tls-capture running, Zeek silently sniffs the retired
# namespace and the disguise-analysis inputs stop updating even though both
# containers still report "Up".

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

nginx_id=$(docker inspect --format '{{.Id}}' proxy-nginx 2>/dev/null || true)
if [[ -z "$nginx_id" ]]; then
    echo "tls-capture sync: proxy-nginx is not running" >&2
    exit 1
fi

capture_mode=$(
    docker inspect --format '{{.HostConfig.NetworkMode}}' proxy-tls-capture \
        2>/dev/null || true
)
expected_mode="container:$nginx_id"

if [[ "$capture_mode" == "$expected_mode" ]]; then
    echo "tls-capture sync: already attached to current nginx"
    exit 0
fi

echo "tls-capture sync: nginx was replaced; rebinding capture sidecar"
docker compose -f docker-compose.proxy.yml up -d --no-deps --force-recreate tls-capture

capture_mode=$(
    docker inspect --format '{{.HostConfig.NetworkMode}}' proxy-tls-capture \
        2>/dev/null || true
)
if [[ "$capture_mode" != "$expected_mode" ]]; then
    echo "tls-capture sync: rebind failed (capture=$capture_mode)" >&2
    exit 1
fi

echo "tls-capture sync: attached to current nginx"
