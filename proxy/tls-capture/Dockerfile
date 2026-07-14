# Passive TLS-fingerprint capture sidecar (AI Bot Defender — Direction 6a).
#
# Runs Zeek in the reverse proxy's network namespace (see docker-compose.proxy.yml:
# `network_mode: "service:nginx"`) so it sees the raw TLS ClientHello of every
# connection BEFORE nginx terminates it — which is the only way to get a true
# JA3/JA4 fingerprint without rebuilding nginx. It writes JSON ssl.log to a shared
# volume; the tls-shipper streams that into logdb.tls_handshakes.
#
# The JA3/JA4 packages are installed best-effort: if a package source/name has
# changed the image still builds, Zeek still logs version/cipher/SNI, and the
# shipper tolerates missing fingerprint fields. JA3 is well-established; JA4 is
# FoxIO's newer scheme.
FROM zeek/zeek:lts

# Install fingerprint packages via the Zeek package manager, non-interactively.
# `yes |` answers zkg's confirmation prompts (there is no stdin in a build, which
# otherwise EOFErrors); the trailing `true` keeps the layer green if a package
# source/name has changed — base Zeek still logs version/cipher/SNI and the
# shipper tolerates missing JA3/JA4 fields. local.zeek `@load packages` then loads
# whatever actually installed.
RUN yes | zkg autoconfig 2>/dev/null || true; \
    yes | zkg refresh   2>/dev/null || true; \
    (yes | zkg install zeek/ja3 2>/dev/null) || (yes | zkg install zeek/salesforce/ja3 2>/dev/null) || (yes | zkg install ja3 2>/dev/null) || true; \
    (yes | zkg install zeek/foxio/ja4 2>/dev/null) || (yes | zkg install FoxIO-LLC/ja4 2>/dev/null) || (yes | zkg install ja4 2>/dev/null) || true; \
    zkg list 2>/dev/null || true

COPY scripts/local.zeek /opt/zeek-local/local.zeek
COPY scripts/tcp-fingerprint.zeek /opt/zeek-local/tcp-fingerprint.zeek
COPY scripts/entrypoint.sh /opt/zeek-local/entrypoint.sh
RUN chmod +x /opt/zeek-local/entrypoint.sh

ENTRYPOINT ["/opt/zeek-local/entrypoint.sh"]
