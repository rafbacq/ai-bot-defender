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
##! into logdb.tcp_fingerprints, where it computes the OS inference + the canonical
##! FoxIO JA4T signature and crawler_graph joins it to requests by (src_ip, src_port).
##!
##! We also record the SYN's ORDERED TCP option kinds (`opt_kinds`). Two payoffs:
##!  1. The option ORDER is the strongest, most spoof-resistant OS discriminator in
##!     the crowded TTL-64 bucket (Linux `2-4-8-1-3` vs Apple `2-1-3-1-1-8-4`), which
##!     the shipper feeds into infer_os() to resolve the ambiguity that otherwise
##!     collapses Linux/Android/macOS/iOS to "unknown".
##!  2. It is exactly the field canonical JA4T needs (`win_opts_mss_wscale`).
##! The byte-walk mirrors the installed FoxIO ja4t package's `get_tcp_options`
##! (proven on this Zeek build) so our JA4T equals FoxIO's for the same connection;
##! it is standard RFC 793 option parsing, fully bounds-checked so it can never
##! runtime-abort and disturb the ssl.log path (this is a separate module).

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
        # Ordered TCP option kinds from the client SYN, e.g. [2,4,8,1,3]. Set ONLY
        # when the raw options were located and walked (an empty [] is a valid
        # no-option SYN); UNSET when parsing could not reach the TCP header, which
        # is the shipper's signal to fall back to the legacy JA4T string.
        opt_kinds: vector of count &log &optional;
    };

    # Result of the option walk: `ok` distinguishes "walked (kinds may be empty)"
    # from "could not locate the options" so the caller only logs a trustworthy list.
    type OptWalk: record {
        ok:    bool           &default=F;
        kinds: vector of count &default=vector();
    };
}

# Walk the current SYN packet's raw bytes and return its ordered TCP option kinds.
# Mirrors the FoxIO ja4t package's get_tcp_options (Ethernet + VLAN + IPv4/IPv6
# offsets, then RFC 793 option TLV walk). Every index is bounds-checked against
# caplen; any failure returns ok=F (caller omits the field -> legacy fallback).
function syn_option_kinds(): OptWalk
    {
    local res: OptWalk;
    local rph = get_current_packet_header();
    # No TCP header, or header <= 20 bytes means no options: a valid empty result.
    if ( ! rph?$tcp )
        return res;
    if ( rph$tcp$hl <= 20 )
        { res$ok = T; return res; }
    if ( ! rph?$l2 || rph$l2$encap != LINK_ETHERNET )
        return res;

    local pkt = get_current_packet();
    local offset = 12;  # start at the Ethernet EtherType field
    # Skip VLAN tags (802.1Q/802.1ad, incl. stacked) to reach the L3 header.
    while ( offset + 2 < pkt$caplen )
        {
        local etype = bytestring_to_count(pkt$data[offset:offset+2]);
        if ( etype == 0x8100 || etype == 0x88A8 )
            { offset += 4; next; }
        else if ( etype == 0x0800 )  # IPv4
            { if ( ! rph?$ip ) return res; offset += 2 + rph$ip$hl; break; }
        else if ( etype == 0x86DD )  # IPv6 (SYN packets carry no ext headers here)
            { offset += 2 + 40; break; }
        else
            return res;  # unknown L3: cannot locate the TCP header
        }

    local header_end = offset + rph$tcp$hl;
    if ( header_end > pkt$caplen )
        return res;
    offset += 20;  # skip the base TCP header to the options region

    # We reached the options region; an empty walk from here is a real no-option SYN.
    res$ok = T;
    while ( offset < header_end )
        {
        local kind = bytestring_to_count(pkt$data[offset]);
        if ( kind == 0 )  # End-of-Options: not part of the JA4T kind list (matches FoxIO)
            break;
        res$kinds += kind;
        if ( kind == 1 || offset + 1 >= header_end )  # NOP, or no room for a length byte
            { offset += 1; next; }
        local optlen = bytestring_to_count(pkt$data[offset + 1]);
        if ( optlen < 2 )
            return res;  # corrupt option length: stop (kinds so far, matches FoxIO)
        offset += optlen;
        }
    return res;
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

    # Record the ordered TCP option kinds for the canonical JA4T + OS disambiguation.
    # Only set the field when the walk actually reached the options (ok), so an
    # unparseable packet omits it and the shipper keeps the legacy signature.
    local opts = syn_option_kinds();
    if ( opts$ok )
        rec$opt_kinds = opts$kinds;

    Log::write(TCPFP::LOG, rec);
    }
