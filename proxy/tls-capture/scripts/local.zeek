##! AI Bot Defender — passive TLS fingerprint capture configuration.
##!
##! Loads the base SSL analyzer plus any zkg-installed fingerprint packages
##! (JA3 / JA4), and writes logs as JSON (one object per line) so the tls-shipper
##! can stream ssl.log into logdb.tls_handshakes. The JA3/JA4 packages add their
##! fields (ja3, ja3s, ja4, ...) to the SSL::Info record automatically when loaded.

@load base/protocols/ssl
# Loads every package installed by zkg (JA3 / JA4 if they were fetched at build).
@load packages

# Passive TCP/IP-stack fingerprint of each client SYN (Layer 2: OS inference that
# survives proxies/VPNs). Loaded after SSL and isolated in its own module, so it
# cannot disturb the ssl.log path. Writes tcp_syn.log (JSON), shipped to
# logdb.tcp_fingerprints by the tls-shipper.
@load ./tcp-fingerprint

# JSON logging: one JSON object per line, no #fields header — easy to tail/parse.
redef LogAscii::use_json = T;

# Keep one current ssl.log the shipper tails; rotate hourly into archives.
redef Log::default_rotation_interval = 1 hr;

# We only care about the TLS handshake metadata, never payload. Disabling
# checksum validation avoids dropping packets on interfaces with TX offload
# (common inside containers / on veth pairs).
redef ignore_checksums = T;
