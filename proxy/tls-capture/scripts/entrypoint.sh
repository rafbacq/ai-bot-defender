#!/bin/sh
# Launch Zeek on the proxy's interface(s), writing JSON logs to the shared volume.
#
# Because this container shares the nginx container's network namespace, its
# interfaces ARE nginx's. nginx sits on MORE THAN ONE Docker network (the proxy
# stack's own default network + the shared proxy_net), and which of them carries
# the inbound published-port (:80/:443) traffic is a Docker implementation detail
# that can CHANGE when the stacks/networks are recreated (observed live: entry via
# proxy_default's gateway one week, proxy_net's the next). Sniffing a single
# interface — the old behaviour, which picked the default-route interface —
# therefore silently captured NOTHING once the entry hop moved.
#
# Zeek cannot capture several interfaces from one process (repeated -i is an
# error, and the libpcap "any" pseudo-device fails Zeek's promiscuous open), so
# we run ONE ZEEK PER non-loopback INTERFACE, each writing its JSON logs to a
# per-interface subdirectory ($LOGDIR/<iface>/ssl.log, .../tcp_syn.log). The
# tls-shipper discovers and tails every such file. With exactly one interface the
# logs stay at the volume root, exactly as before. The SYN filter in
# tcp-fingerprint.zeek (resp_p 80/443 only) keeps nginx's own egress connections
# out of the capture, whichever interface they leave on. Verify once that the src
# IP Zeek records matches nginx's $remote_addr (the all_visits.client_ip) — on
# Docker bridge with iptables DNAT it does; with the userland docker-proxy it may
# not, in which case capture on the host instead.
#
# CAPTURE_IFACE overrides auto-detection (a space-separated interface list).
set -e

LOGDIR="${ZEEK_LOGDIR:-/zeek/logs}"
mkdir -p "$LOGDIR"

IFACES="${CAPTURE_IFACE:-}"
if [ -z "$IFACES" ]; then
    for cand in $(ls /sys/class/net 2>/dev/null); do
        [ "$cand" = "lo" ] && continue
        IFACES="$IFACES $cand"
    done
    IFACES="${IFACES# }"
fi
IFACES="${IFACES:-eth0}"

set --
for iface in $IFACES; do
    set -- "$@" "$iface"
done

if [ "$#" -eq 1 ]; then
    echo "tls-capture: Zeek sniffing $1, JSON logs -> $LOGDIR"
    cd "$LOGDIR"
    exec zeek -i "$1" /opt/zeek-local/local.zeek
fi

echo "tls-capture: Zeek sniffing ${IFACES} (one process per interface), JSON logs -> $LOGDIR/<iface>"
PIDS=""
for iface in "$@"; do
    dir="$LOGDIR/$iface"
    mkdir -p "$dir"
    ( cd "$dir" && exec zeek -i "$iface" /opt/zeek-local/local.zeek ) &
    PIDS="$PIDS $!"
done

# If any Zeek dies, exit so Docker's restart policy relaunches the whole sidecar
# (dash has no `wait -n`, so poll the pids).
while :; do
    for pid in $PIDS; do
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "tls-capture: a zeek process exited; restarting the sidecar" >&2
            exit 1
        fi
    done
    sleep 5
done
