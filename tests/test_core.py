import socket
import struct

import pytest
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

from spoofshifter.core import (
    DnsSpoofEngine,
    SpoofError,
    SpoofRule,
    _is_ip_fragment,
    _tcp_segment_has_single_complete_dns,
    build_spoofed_response,
    decode_qname,
    match_rule,
    normalize_qname,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_query(qname="www.google.com", qtype=1, src="192.168.1.100", dst="8.8.8.8",
               sport=5353, dport=53, tid=0x1234):
    pkt = IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / DNS(
        id=tid, rd=1, qd=DNSQR(qname=qname, qtype=qtype))
    return bytes(pkt)


def make_response(qname="www.google.com", qtype=1, rdata=None,
                  src="8.8.8.8", dst="192.168.1.100", sport=53, dport=5353, tid=0x1234,
                  extra=False):
    if rdata is None:
        rdata = "2001:db8::1" if qtype == 28 else "142.250.72.100"
    dns = DNS(id=tid, qr=1, rd=1, ra=1, qdcount=1, ancount=1,
              qd=DNSQR(qname=qname, qtype=qtype),
              an=DNSRR(rrname=qname, type=qtype, rclass=1, ttl=60, rdata=rdata))
    if extra:
        dns.arcount = 1
        dns.ar = DNSRR(rrname=qname, type=qtype, rclass=1, ttl=60, rdata="8.8.4.4")
    pkt = IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / dns
    return bytes(pkt)


def make_tcp_response(qname="www.google.com", qtype=1, rdata=None,
                      src="8.8.8.8", dst="192.168.1.100", sport=53, dport=5353,
                      tid=0x1234, seq=1000, ack=2000, extra=False,
                      truncate=None, coalesce=1):
    """A DNS-over-TCP response: 2-byte length prefix + DNS message."""
    if rdata is None:
        rdata = "2001:db8::1" if qtype == 28 else "142.250.72.100"
    dns = DNS(id=tid, qr=1, rd=1, ra=1, qdcount=1, ancount=1,
              qd=DNSQR(qname=qname, qtype=qtype),
              an=DNSRR(rrname=qname, type=qtype, rclass=1, ttl=60, rdata=rdata))
    if extra:
        dns.arcount = 1
        dns.ar = DNSRR(rrname=qname, type=qtype, rclass=1, ttl=60, rdata="8.8.4.4")
    framed = struct.pack("!H", len(bytes(dns))) + bytes(dns)
    if coalesce > 1:
        framed = framed * coalesce
    if truncate is not None:
        framed = framed[:truncate]
    pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags="PA") / Raw(framed)
    return bytes(pkt)


def tcp_checksum_valid(payload, src, dst):
    """True if the TCP checksum on the wire matches the pseudo-header sum."""
    pkt = IP(payload)
    stored = pkt[TCP].chksum
    tcp_raw = bytes(pkt[TCP])
    zeroed = tcp_raw[:16] + b"\x00\x00" + tcp_raw[18:]  # checksum field at offset 16
    if len(zeroed) % 2:
        zeroed += b"\x00"
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(tcp_raw))
    total = sum(struct.unpack("!%dH" % (len(pseudo) // 2), pseudo))
    total += sum(struct.unpack("!%dH" % (len(zeroed) // 2), zeroed))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ((~total) & 0xFFFF) == stored


def ip_checksum_valid(payload):
    """True if the IPv4 header checksum stored on the wire is correct."""
    pkt = IP(payload)
    raw = bytes(pkt)
    hdr = raw[:pkt.ihl * 4]
    stored = struct.unpack("!H", hdr[10:12])[0]
    zeroed = hdr[:10] + b"\x00\x00" + hdr[12:]
    words = struct.unpack("!%dH" % (len(zeroed) // 2), zeroed)
    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ((~total) & 0xFFFF) == stored


def rule(domain, ipv4=None, ipv6=None, ttl=300):
    return SpoofRule(domain=domain, ipv4=ipv4, ipv6=ipv6, ttl=ttl)


# ---------------------------------------------------------------------------
# qname decoding / normalization
# ---------------------------------------------------------------------------

def test_normalize_qname():
    assert normalize_qname("WWW.Google.COM.") == "www.google.com"
    assert normalize_qname("  example.com  ") == "example.com"
    assert normalize_qname("example.com") == "example.com"


def test_decode_qname_wire_format():
    wire = b"\x03www\x06google\x03com\x00"
    assert decode_qname(wire) == "www.google.com"


def test_decode_qname_wire_format_empty_root():
    assert decode_qname(b"\x00") == ""


def test_decode_qname_wire_format_with_compression_pointer():
    # labels up to the pointer are decoded; the pointer itself stops parsing
    assert decode_qname(b"\x03www\xc0\x0c") == "www"


def test_decode_qname_plain_ascii_bytes():
    assert decode_qname(b"www.google.com.") == "www.google.com"


def test_decode_qname_string():
    assert decode_qname("www.google.com.") == "www.google.com"


# ---------------------------------------------------------------------------
# Rule matching
# ---------------------------------------------------------------------------

def test_match_rule_exact():
    rules = [rule("www.google.com", ipv4="10.0.2.4")]
    assert match_rule("www.google.com", rules) == rules[0]
    assert match_rule("WWW.GOOGLE.COM.", rules) == rules[0]
    assert match_rule("mail.google.com", rules) is None
    assert match_rule("www.google.co.uk", rules) is None


def test_match_rule_wildcard():
    rules = [rule("*.example.com", ipv4="10.0.2.4")]
    assert match_rule("example.com", rules) == rules[0]
    assert match_rule("foo.example.com", rules) == rules[0]
    assert match_rule("a.b.example.com", rules) == rules[0]
    assert match_rule("example.org", rules) is None
    assert match_rule("badexample.com", rules) is None


def test_match_rule_exact_beats_wildcard():
    rules = [
        rule("*.google.com", ipv4="1.1.1.1"),
        rule("www.google.com", ipv4="2.2.2.2"),
    ]
    assert match_rule("www.google.com", rules).ipv4 == "2.2.2.2"
    assert match_rule("mail.google.com", rules).ipv4 == "1.1.1.1"


def test_match_rule_longest_wildcard_wins():
    rules = [
        rule("*.example.com", ipv4="1.1.1.1"),
        rule("*.b.example.com", ipv4="2.2.2.2"),
    ]
    assert match_rule("a.b.example.com", rules).ipv4 == "2.2.2.2"
    assert match_rule("c.example.com", rules).ipv4 == "1.1.1.1"


def test_match_rule_empty_rules():
    assert match_rule("example.com", []) is None


# ---------------------------------------------------------------------------
# SpoofRule validation
# ---------------------------------------------------------------------------

def test_rule_requires_address():
    with pytest.raises(SpoofError):
        SpoofRule(domain="example.com")


def test_rule_rejects_bad_ipv4():
    with pytest.raises(SpoofError):
        rule("example.com", ipv4="not-an-ip")


def test_rule_rejects_ipv6_in_ipv4_field():
    with pytest.raises(SpoofError):
        rule("example.com", ipv4="fd00::1")


def test_rule_rejects_ipv4_in_ipv6_field():
    with pytest.raises(SpoofError):
        rule("example.com", ipv6="10.0.2.4")


def test_rule_rejects_negative_ttl():
    with pytest.raises(SpoofError):
        rule("example.com", ipv4="10.0.2.4", ttl=-1)


def test_engine_rejects_unknown_mode():
    with pytest.raises(SpoofError):
        DnsSpoofEngine([rule("example.com", ipv4="10.0.2.4")], mode="bogus")


def test_engine_accepts_listen_mode():
    DnsSpoofEngine([], mode="listen")  # must not raise; rules are optional


# ---------------------------------------------------------------------------
# Engine: listen mode (--list-domains)
# ---------------------------------------------------------------------------

def test_listen_mode_logs_query_and_passes_through(caplog):
    import logging
    caplog.set_level(logging.INFO, logger="spoofshifter")
    engine = DnsSpoofEngine([], mode="listen")
    payload = make_query()
    out = engine.process_payload(payload)
    assert out is payload  # passive: byte-for-byte untouched
    assert engine.stats.queries == 1
    assert engine.stats.spoofed == 0
    assert engine.stats.dropped == 0
    assert "www.google.com" in caplog.text
    assert "192.168.1.100" in caplog.text  # client IP


def test_listen_mode_never_drops_or_spoofs():
    # Even traffic a spoofing rule would answer/drop is forwarded untouched.
    engine = DnsSpoofEngine([rule("www.google.com", ipv4="10.0.2.4")], mode="listen")
    for payload in (make_query(), make_query(qtype=28), make_response()):
        assert engine.process_payload(payload) is payload
    assert engine.stats.spoofed == 0
    assert engine.stats.dropped == 0


def test_listen_mode_ignores_responses(caplog):
    import logging
    caplog.set_level(logging.INFO, logger="spoofshifter")
    engine = DnsSpoofEngine([], mode="listen")
    out = engine.process_payload(make_response())
    assert out is not None
    assert engine.stats.queries == 0  # only queries are counted/logged
    assert "www.google.com" not in caplog.text


def test_listen_mode_logs_aaaa_and_unknown_qtypes(caplog):
    import logging
    caplog.set_level(logging.INFO, logger="spoofshifter")
    engine = DnsSpoofEngine([], mode="listen")
    engine.process_payload(make_query(qname="ipv6.example.com", qtype=28))
    engine.process_payload(make_query(qname="mx.example.com", qtype=15))
    assert "ipv6.example.com (AAAA)" in caplog.text
    assert "mx.example.com (MX)" in caplog.text


def test_listen_mode_tcp_queries_logged(caplog):
    import logging
    caplog.set_level(logging.INFO, logger="spoofshifter")
    engine = DnsSpoofEngine([], mode="listen")
    pkt = IP(src="192.168.1.100", dst="8.8.8.8") / TCP(sport=5353, dport=53) / DNS(
        id=1, rd=1, qd=DNSQR(qname="tcp.example.com", qtype=1))
    payload = bytes(pkt)
    assert engine.process_payload(payload) is payload
    assert "tcp.example.com" in caplog.text


# ---------------------------------------------------------------------------
# Engine: reply mode
# ---------------------------------------------------------------------------

def test_reply_mode_spoofs_query():
    engine = DnsSpoofEngine([rule("www.google.com", ipv4="10.0.2.4", ttl=120)])
    out = engine.process_payload(make_query())
    assert out is not None

    resp = IP(out)
    assert resp[IP].src == "8.8.8.8"        # answers from the queried server
    assert resp[IP].dst == "192.168.1.100"  # back to the victim
    assert ip_checksum_valid(out)

    dns = resp[DNS]
    assert dns.id == 0x1234                 # transaction id preserved
    assert dns.qr == 1
    assert dns.aa == 1
    assert dns.ra == 1
    assert dns.qdcount == 1
    assert dns.ancount == 1
    assert decode_qname(dns.qd[0].qname) == "www.google.com"
    assert dns.an[0].type == 1
    assert dns.an[0].rdata == "10.0.2.4"
    assert dns.an[0].ttl == 120

    stats = engine.stats
    assert stats.seen == 1
    assert stats.queries == 1
    assert stats.spoofed == 1


def test_reply_mode_spoofs_aaaa():
    engine = DnsSpoofEngine([rule("ipv6.example.com", ipv6="fd00::1")])
    out = engine.process_payload(make_query(qname="ipv6.example.com", qtype=28))
    assert out is not None
    dns = IP(out)[DNS]
    assert dns.an[0].type == 28
    assert dns.an[0].rdata == "fd00::1"


def test_reply_mode_drops_aaaa_query_without_ipv6_rule():
    engine = DnsSpoofEngine([rule("www.google.com", ipv4="10.0.2.4")])
    out = engine.process_payload(make_query(qtype=28))
    assert out is None  # dropped so the client falls back to A
    assert engine.stats.dropped == 1


def test_reply_mode_drops_a_query_without_ipv4_rule():
    engine = DnsSpoofEngine([rule("ipv6.example.com", ipv6="fd00::1")])
    out = engine.process_payload(make_query(qname="ipv6.example.com", qtype=1))
    assert out is None
    assert engine.stats.dropped == 1


def test_reply_mode_forwards_non_matching_query():
    engine = DnsSpoofEngine([rule("www.google.com", ipv4="10.0.2.4")])
    payload = make_query(qname="example.org")
    assert engine.process_payload(payload) is payload
    assert engine.stats.forwarded == 1
    assert engine.stats.spoofed == 0


def test_reply_mode_forwards_non_a_queries():
    engine = DnsSpoofEngine([rule("example.com", ipv4="10.0.2.4")])
    payload = make_query(qname="example.com", qtype=15)  # MX
    assert engine.process_payload(payload) is payload
    assert engine.stats.forwarded == 1


def test_reply_mode_forwards_tcp_queries():
    engine = DnsSpoofEngine([rule("www.google.com", ipv4="10.0.2.4")])
    pkt = IP(src="192.168.1.100", dst="8.8.8.8") / TCP(sport=5353, dport=53) / DNS(
        id=1, rd=1, qd=DNSQR(qname="www.google.com", qtype=1))
    payload = bytes(pkt)
    assert engine.process_payload(payload) is payload


def test_reply_mode_ignores_responses():
    engine = DnsSpoofEngine([rule("www.google.com", ipv4="10.0.2.4")])
    payload = make_response()
    assert engine.process_payload(payload) is payload


def test_reply_mode_non_dns_packet_passthrough():
    engine = DnsSpoofEngine([rule("www.google.com", ipv4="10.0.2.4")])
    payload = bytes(IP(src="1.2.3.4", dst="5.6.7.8") / UDP(sport=1, dport=2) / b"hi")
    assert engine.process_payload(payload) is payload


def test_malformed_payload_does_not_crash():
    engine = DnsSpoofEngine([rule("www.google.com", ipv4="10.0.2.4")])
    for garbage in (b"", b"\xff\xff\xff", b"not a packet at all"):
        assert engine.process_payload(garbage) == garbage  # passed through, no exception


def test_wildcard_rule_applies_to_engine():
    engine = DnsSpoofEngine([rule("*.google.com", ipv4="10.0.2.4")])
    out = engine.process_payload(make_query(qname="mail.google.com"))
    assert out is not None
    assert IP(out)[DNS].an[0].rdata == "10.0.2.4"


# ---------------------------------------------------------------------------
# Engine: mutate mode
# ---------------------------------------------------------------------------

def test_mutate_mode_rewrites_response():
    engine = DnsSpoofEngine([rule("www.google.com", ipv4="10.0.2.4")], mode="mutate")
    out = engine.process_payload(make_response())
    assert out is not None
    resp = IP(out)
    assert ip_checksum_valid(out)
    dns = resp[DNS]
    assert dns.an[0].rdata == "10.0.2.4"
    assert dns.ancount == 1
    assert dns.nscount == 0
    assert dns.arcount == 0
    assert engine.stats.spoofed == 1


def test_mutate_mode_ignores_queries():
    engine = DnsSpoofEngine([rule("www.google.com", ipv4="10.0.2.4")], mode="mutate")
    payload = make_query()
    assert engine.process_payload(payload) is payload


def test_mutate_mode_forwards_non_matching_response():
    engine = DnsSpoofEngine([rule("www.google.com", ipv4="10.0.2.4")], mode="mutate")
    payload = make_response(qname="example.org")
    assert engine.process_payload(payload) is payload
    assert engine.stats.forwarded == 1


def test_mutate_mode_forwards_when_family_missing():
    engine = DnsSpoofEngine([rule("www.google.com", ipv6="fd00::1")], mode="mutate")
    payload = make_response()  # A record, rule has no ipv4
    assert engine.process_payload(payload) is payload
    assert engine.stats.forwarded == 1


def test_mutate_mode_spoofs_aaaa():
    engine = DnsSpoofEngine([rule("ipv6.example.com", ipv6="fd00::1")], mode="mutate")
    out = engine.process_payload(make_response(qname="ipv6.example.com", qtype=28))
    assert out is not None
    assert IP(out)[DNS].an[0].rdata == "fd00::1"


# ---------------------------------------------------------------------------
# Query counting / --top-domains
# ---------------------------------------------------------------------------

def test_record_query_and_top_domains_ranking():
    from spoofshifter.core import PacketStats
    stats = PacketStats()
    stats.record_query("www.google.com")
    stats.record_query("www.google.com")
    stats.record_query("mail.google.com")
    stats.record_query("WWW.GOOGLE.COM.")  # normalized: same as www.google.com
    stats.record_query("example.org")
    assert stats.query_counts["www.google.com"] == 3
    assert stats.query_counts["mail.google.com"] == 1
    assert stats.query_counts["example.org"] == 1
    # ranked by count desc, ties alphabetical
    assert stats.top_domains()[:2] == [("www.google.com", 3), ("example.org", 1)]


def test_top_domains_limit_and_empty():
    from spoofshifter.core import PacketStats
    stats = PacketStats()
    assert stats.top_domains(10) == []
    for i in range(5):
        stats.record_query(f"d{i}.example.com")
    assert len(stats.top_domains(3)) == 3
    assert len(stats.top_domains(10)) == 5


def test_listen_mode_tracks_query_counts():
    engine = DnsSpoofEngine([], mode="listen")
    engine.process_payload(make_query(qname="a.example.com"))
    engine.process_payload(make_query(qname="a.example.com"))
    engine.process_payload(make_query(qname="b.example.com"))
    engine.process_payload(make_response())  # responses are not queries
    assert engine.stats.query_counts == {"a.example.com": 2, "b.example.com": 1}


def test_reply_mode_tracks_all_queries_including_forwarded():
    engine = DnsSpoofEngine([rule("www.google.com", ipv4="10.0.2.4")])
    engine.process_payload(make_query())                    # matched
    engine.process_payload(make_query(qname="other.org"))  # forwarded
    tcp_pkt = IP(src="192.168.1.100", dst="8.8.8.8") / TCP(sport=5353, dport=53) / DNS(
        id=1, rd=1, qd=DNSQR(qname="tcp.org", qtype=1))
    engine.process_payload(bytes(tcp_pkt))                  # TCP query, forwarded
    assert engine.stats.query_counts["www.google.com"] == 1
    assert engine.stats.query_counts["other.org"] == 1
    assert engine.stats.query_counts["tcp.org"] == 1


def test_mutate_mode_tracks_no_queries():
    engine = DnsSpoofEngine([rule("www.google.com", ipv4="10.0.2.4")], mode="mutate")
    engine.process_payload(make_response())  # responses flow through mutate mode
    assert engine.stats.query_counts == {}


# ---------------------------------------------------------------------------
# Wire-level guards
# ---------------------------------------------------------------------------

def test_is_ip_fragment_detects_mf_and_offset():
    assert _is_ip_fragment(bytes(IP(src="1.1.1.1", dst="2.2.2.2", flags="MF") / UDP(sport=1, dport=2)))
    assert _is_ip_fragment(bytes(IP(src="1.1.1.1", dst="2.2.2.2", frag=5) / UDP(sport=1, dport=2)))
    assert not _is_ip_fragment(bytes(IP(src="1.1.1.1", dst="2.2.2.2", flags="DF") / UDP(sport=1, dport=2)))
    assert not _is_ip_fragment(bytes(IP(src="1.1.1.1", dst="2.2.2.2") / UDP(sport=1, dport=2)))
    assert not _is_ip_fragment(b"\x45\x00\x00\x14")  # too short to have a fragment field


def test_tcp_segment_completeness_check():
    full = make_tcp_response()
    assert _tcp_segment_has_single_complete_dns(full, IP(full))
    truncated = make_tcp_response(truncate=20)
    assert not _tcp_segment_has_single_complete_dns(truncated, IP(truncated))
    coalesced = make_tcp_response(coalesce=2)
    assert not _tcp_segment_has_single_complete_dns(coalesced, IP(coalesced))


# ---------------------------------------------------------------------------
# Engine: mutate mode over TCP
# ---------------------------------------------------------------------------

def test_mutate_tcp_rewrites_complete_response():
    engine = DnsSpoofEngine([rule("www.google.com", ipv4="10.0.2.4")], mode="mutate")
    payload = make_tcp_response()
    out = engine.process_payload(payload)
    assert out is not None and out is not payload

    pkt = IP(out)
    assert ip_checksum_valid(out)
    assert tcp_checksum_valid(out, "8.8.8.8", "192.168.1.100")
    assert pkt[TCP].seq == 1000 and pkt[TCP].ack == 2000  # stream positions untouched
    assert len(out) == len(payload)  # size preserved -> TCP accounting intact

    assert pkt[DNS].an[0].rdata == "10.0.2.4"
    assert pkt[DNS].ancount == 1
    # the 2-byte length prefix stays consistent with the rewritten message
    raw = bytes(pkt[TCP].payload)
    assert int.from_bytes(raw[:2], "big") == len(raw) - 2
    assert engine.stats.spoofed == 1


def test_mutate_tcp_rewrites_aaaa():
    engine = DnsSpoofEngine([rule("ipv6.example.com", ipv6="fd00::1")], mode="mutate")
    out = engine.process_payload(make_tcp_response(qname="ipv6.example.com", qtype=28))
    assert out is not None
    assert IP(out)[DNS].an[0].rdata == "fd00::1"
    assert tcp_checksum_valid(out, "8.8.8.8", "192.168.1.100")


def test_mutate_tcp_skips_truncated_message():
    engine = DnsSpoofEngine([rule("www.google.com", ipv4="10.0.2.4")], mode="mutate")
    payload = make_tcp_response(truncate=20)  # half a message in one segment
    assert engine.process_payload(payload) is payload
    assert engine.stats.spoofed == 0


def test_mutate_tcp_skips_coalesced_messages():
    engine = DnsSpoofEngine([rule("www.google.com", ipv4="10.0.2.4")], mode="mutate")
    payload = make_tcp_response(coalesce=2)  # two messages in one segment
    assert engine.process_payload(payload) is payload
    assert engine.stats.spoofed == 0
    assert engine.stats.forwarded == 1


def test_mutate_tcp_skips_size_changing_rewrite():
    # Response with an additional record: replacing it with a bare answer would
    # shrink the segment, breaking TCP sequence accounting, so it is forwarded.
    engine = DnsSpoofEngine([rule("www.google.com", ipv4="10.0.2.4")], mode="mutate")
    payload = make_tcp_response(extra=True)
    assert engine.process_payload(payload) is payload
    assert engine.stats.spoofed == 0
    assert engine.stats.forwarded == 1


def test_mutate_tcp_nonmatching_passthrough():
    engine = DnsSpoofEngine([rule("www.google.com", ipv4="10.0.2.4")], mode="mutate")
    payload = make_tcp_response(qname="example.org")
    assert engine.process_payload(payload) is payload
    assert engine.stats.forwarded == 1


def test_mutate_tcp_skips_when_family_missing():
    engine = DnsSpoofEngine([rule("www.google.com", ipv6="fd00::1")], mode="mutate")
    payload = make_tcp_response()  # A record, rule has no ipv4
    assert engine.process_payload(payload) is payload
    assert engine.stats.forwarded == 1


def test_mutate_drops_leftover_records_cleanly():
    # Zeroing counts must actually remove NS/additional records from the wire.
    engine = DnsSpoofEngine([rule("www.google.com", ipv4="10.0.2.4")], mode="mutate")
    out = engine.process_payload(make_response(extra=True))
    assert out is not None
    dns = IP(out)[DNS]
    assert dns.ancount == 1
    assert dns.nscount == 0
    assert dns.arcount == 0
    # re-parsed message must not contain stray records
    rebuilt = DNS(bytes(dns))
    assert rebuilt.ancount == 1
    assert rebuilt.nscount == 0
    assert rebuilt.arcount == 0


# ---------------------------------------------------------------------------
# Fragment guards
# ---------------------------------------------------------------------------

def test_mutate_mode_skips_fragmented_response():
    engine = DnsSpoofEngine([rule("www.google.com", ipv4="10.0.2.4")], mode="mutate")
    pkt = IP(make_response())
    pkt[IP].flags = "MF"
    fragmented = bytes(pkt)
    assert engine.process_payload(fragmented) is fragmented
    assert engine.stats.spoofed == 0
    assert engine.stats.forwarded == 1


def test_reply_mode_skips_fragmented_query():
    engine = DnsSpoofEngine([rule("www.google.com", ipv4="10.0.2.4")])
    pkt = IP(make_query())
    pkt[IP].frag = 3  # non-zero offset: a later fragment
    fragmented = bytes(pkt)
    assert engine.process_payload(fragmented) is fragmented
    assert engine.stats.spoofed == 0


# ---------------------------------------------------------------------------
# build_spoofed_response direct
# ---------------------------------------------------------------------------

def test_build_spoofed_response_unsupported_qtype():
    rule_ = rule("example.com", ipv4="10.0.2.4")
    query = IP(bytes(IP(src="1.1.1.1", dst="2.2.2.2") / UDP(sport=5353, dport=53) / DNS(
        id=1, qd=DNSQR(qname="example.com", qtype=15))))
    assert build_spoofed_response(query, rule_, 15) is None
