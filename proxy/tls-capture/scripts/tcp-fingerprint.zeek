##! AI Bot Defender — passive TCP/IP stack fingerprint capture (Layer 2).
##!
##! Loaded by local.zeek AFTER the SSL analyzer, in its own module so a problem
##! here can never disturb the proven ssl.log path. We log the CLIENT's SYN
##! packet (is_orig) for every connection: its initial TTL, advertised window
##! size, window scale, MSS, SACK-OK and DF bit are set by the OS kernel's TCP/IP
##! stack and survive VPNs/proxies (which only rewrite the source IP). That is the
##! "the kernel betrays the real OS" signal from the reference doc: a bot on a
##! Linux cloud host can spoof an iPhone User-Agent and even mimic a Safari JA4,
##! but its SYN still carries Linux window sizes / a TTL based at 64.
##!
##! `connection_SYN_packet` fires ONLY on SYN packets, so this adds negligible
##! overhead (unlike a per-packet handler). The tls-shipper streams tcp_syn.log
##! into logdb.tcp_fingerprints, where it computes the OS inference + a JA4T-style
##! signature and crawler_graph joins it to requests by the (src_ip, src_port) tuple.

module TCPFP;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:        time   &log;
        uid:       string  &log;
        orig_h:    addr    &log;
        orig_p:    port    &log;
        resp_h:    addr    &log;
        resp_p:    port    &log;
        ttl:       count   &log &optional;
        win_size:  count   &log &optional;
        win_scale: int     &log &optional;
        mss:       count   &log &optional;
        sack_ok:   bool    &log &optional;
        df:        bool    &log &optional;
        syn_size:  count   &log &optional;
    };
}

event zeek_init()
    {
    # JSON (inherited from local.zeek's LogAscii::use_json=T) -> one object per
    # line in tcp_syn.log, which the shipper tails exactly like ssl.log.
    Log::create_stream(TCPFP::LOG, [$columns=Info, $path="tcp_syn"]);
    }

event connection_SYN_packet(c: connection, pkt: SYN_packet)
    {
    # Only the client's SYN (originator) carries the visitor's OS fingerprint;
    # the server's SYN-ACK is our own kernel and is uninteresting.
    if ( ! pkt$is_orig )
        return;

    # Only inbound connections to the ports nginx SERVES (the honeypot front
    # door). This drops nginx's OWN egress SYNs to the collector/fp-collector
    # (:8000) and the per-site backends (:8080) — those carry the proxy host's
    # kernel fingerprint, not a visitor's, and would pollute the OS inference.
    # NOTE (host topology): the captured SYN's source is only the real remote
    # client when the proxy receives connections directly (or via iptables DNAT
    # that preserves the source). Behind a userland docker-proxy / Docker Desktop
    # port-forwarder the inbound SYN may be the forwarder's, not the client's —
    # the same caveat documented for the TLS-capture IP match. The OS-inference
    # logic itself is validated by the offline selftest.
    if ( c$id$resp_p != 80/tcp && c$id$resp_p != 443/tcp )
        return;

    local rec: Info = [
        $ts        = network_time(),
        $uid       = c$uid,
        $orig_h    = c$id$orig_h,
        $orig_p    = c$id$orig_p,
        $resp_h    = c$id$resp_h,
        $resp_p    = c$id$resp_p,
        $ttl       = pkt$ttl,
        $win_size  = pkt$win_size,
        $win_scale = pkt$win_scale,
        $mss       = pkt$MSS,
        $sack_ok   = pkt$SACK_OK,
        $df        = pkt$DF,
        $syn_size  = pkt$size
    ];
    Log::write(TCPFP::LOG, rec);
    }
