"""End-to-end transaction simulation.

These tests push realistic wire packets through the real code path
(runner -> engine) and then verify the result the way a resolver would:
transaction-id echo, response flags, valid IP/UDP/TCP checksums, and a
re-parseable DNS message containing the forged answer.  Everything except the
kernel iptables/NFQUEUE plumbing is exercised here (see tools/self_test.sh
for the live kernel-level test).
"""

import socket
import struct

import pytest
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

from spoofshifter.core import TYPE_NAMES, DnsSpoofEngine, SpoofRule
from spoofshifter.runner import DnsSpoofRunner


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class FakePacket:
    def __init__(self, payload):
        self.payload = payload
        self.accepted = 0
        self.dropped = 0
        self.out = None

    def get_payload(self):
        return self.payload

    def set_payload(self, payload):
        self.out = payload

    def accept(self):
        self.accepted += 1

    def drop(self):
        self.dropped += 1


def run_through_runner(engine, payload):
    """Feed a wire payload through the runner exactly like NFQUEUE would."""
    runner = DnsSpoofRunner(engine, queue_num=0)
    packet = FakePacket(payload)
    runner._on_packet(packet)
    return packet


def make_query(qname="www.google.com", qtype=1, tid=0x4A11,
               src="192.168.1.100", dst="192.0.2.1"):
    pkt = IP(src=src, dst=dst) / UDP(sport=5353, dport=53) / DNS(
        id=tid, rd=1, qd=DNSQR(qname=qname, qtype=qtype))
    return bytes(pkt)


def make_response(qname="www.google.com", qtype=1, rdata=None, tid=0x4A11):
    if rdata is None:
        rdata = "2001:db8::1" if qtype == 28 else "142.250.72.100"
    pkt = IP(src="192.0.2.1", dst="192.168.1.100") / UDP(sport=53, dport=5353) / DNS(
        id=tid, qr=1, rd=1, ra=1, qdcount=1, ancount=1,
        qd=DNSQR(qname=qname, qtype=qtype),
        an=DNSRR(rrname=qname, type=qtype, rclass=1, ttl=60, rdata=rdata))
    return bytes(pkt)


def _checksum_valid(raw, zero_offset):
    stored = struct.unpack("!H", raw[zero_offset:zero_offset + 2])[0]
    zeroed = raw[:zero_offset] + b"\x00\x00" + raw[zero_offset + 2:]
    if len(zeroed) % 2:
        zeroed += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(zeroed) // 2), zeroed))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ((~total) & 0xFFFF) == stored


def ip_checksum_valid(payload):
    pkt = IP(payload)
    return _checksum_valid(bytes(pkt)[:pkt.ihl * 4], 10)


def udp_checksum_valid(payload, src, dst):
    pkt = IP(payload)
    udp_raw = bytes(pkt[UDP])
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 17, len(udp_raw))
    stored = struct.unpack("!H", udp_raw[6:8])[0]
    zeroed = udp_raw[:6] + b"\x00\x00" + udp_raw[8:]
    if len(zeroed) % 2:
        zeroed += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(pseudo) // 2), pseudo))
    total += sum(struct.unpack("!%dH" % (len(zeroed) // 2), zeroed))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ((~total) & 0xFFFF) == stored


def tcp_checksum_valid(payload, src, dst):
    pkt = IP(payload)
    tcp_raw = bytes(pkt[TCP])
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(tcp_raw))
    stored = struct.unpack("!H", tcp_raw[16:18])[0]
    zeroed = tcp_raw[:16] + b"\x00\x00" + tcp_raw[18:]
    if len(zeroed) % 2:
        zeroed += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(pseudo) // 2), pseudo))
    total += sum(struct.unpack("!%dH" % (len(zeroed) // 2), zeroed))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ((~total) & 0xFFFF) == stored


def parse_answers(dns_wire):
    """Extract (type-name, rdata) pairs the way a resolver would."""
    dns = DNS(dns_wire)
    return [(TYPE_NAMES.get(record.type, record.type), record.rdata) for record in (dns.an or [])]


# ---------------------------------------------------------------------------
# Full transactions
# ---------------------------------------------------------------------------

def test_reply_mode_full_roundtrip():
    """Victim query -> tool -> forged response a resolver would accept."""
    engine = DnsSpoofEngine([SpoofRule("www.google.com", ipv4="10.9.9.9")], mode="reply")
    packet = run_through_runner(engine, make_query())

    assert packet.accepted == 1 and packet.dropped == 0
    assert packet.out is not None
    out = packet.out

    resp = IP(out)
    # checksums must be valid on the wire
    assert ip_checksum_valid(out)
    assert udp_checksum_valid(out, resp[IP].src, resp[IP].dst)
    # addresses and ports swapped: answers from the queried "server" back to us
    assert resp[IP].src == "192.0.2.1"
    assert resp[IP].dst == "192.168.1.100"
    assert resp[UDP].sport == 53
    assert resp[UDP].dport == 5353
    # the client would accept it: id echo, QR/AA/RA set, question preserved
    dns = resp[DNS]
    assert dns.id == 0x4A11
    assert dns.qr == 1 and dns.aa == 1 and dns.ra == 1
    assert dns.qdcount == 1 and dns.ancount == 1
    # re-parse the datagram payload and extract the answer (resolver-style)
    answers = parse_answers(bytes(resp[UDP].payload))
    assert ("A", "10.9.9.9") in answers
    assert engine.stats.spoofed == 1


def test_aaaa_query_dropped_so_client_falls_back_to_ipv4():
    engine = DnsSpoofEngine([SpoofRule("www.google.com", ipv4="10.9.9.9")], mode="reply")
    packet = run_through_runner(engine, make_query(qtype=28))
    assert packet.dropped == 1
    assert packet.out is None
    assert engine.stats.dropped == 1


def test_listen_mode_transaction_forwarded_untouched():
    engine = DnsSpoofEngine([], mode="listen")
    query = make_query(qname="recon.example.com")
    packet = run_through_runner(engine, query)
    assert packet.accepted == 1
    assert packet.dropped == 0
    assert packet.out is None  # never re-injected with a modified payload
    assert engine.stats.queries == 1


def test_mutate_mode_udp_roundtrip():
    engine = DnsSpoofEngine([SpoofRule("www.google.com", ipv4="10.9.9.9")], mode="mutate")
    packet = run_through_runner(engine, make_response())
    assert packet.accepted == 1
    assert packet.out is not None
    out = packet.out
    resp = IP(out)
    assert ip_checksum_valid(out)
    assert udp_checksum_valid(out, resp[IP].src, resp[IP].dst)
    assert parse_answers(bytes(resp[UDP].payload)) == [("A", "10.9.9.9")]
    assert engine.stats.spoofed == 1


def test_mutate_mode_tcp_roundtrip():
    engine = DnsSpoofEngine([SpoofRule("www.google.com", ipv4="10.9.9.9")], mode="mutate")
    dns = DNS(id=0x4A11, qr=1, rd=1, ra=1, qdcount=1, ancount=1,
              qd=DNSQR(qname="www.google.com", qtype=1),
              an=DNSRR(rrname="www.google.com", type=1, rclass=1, ttl=60, rdata="142.250.72.100"))
    framed = struct.pack("!H", len(bytes(dns))) + bytes(dns)
    payload = bytes(IP(src="192.0.2.1", dst="192.168.1.100") /
                    TCP(sport=53, dport=5353, seq=1000, ack=2000, flags="PA") / Raw(framed))
    packet = run_through_runner(engine, payload)
    assert packet.accepted == 1
    out = packet.out
    resp = IP(out)
    assert ip_checksum_valid(out)
    assert tcp_checksum_valid(out, resp[IP].src, resp[IP].dst)
    assert resp[TCP].seq == 1000 and resp[TCP].ack == 2000
    assert len(out) == len(payload)  # TCP stream length preserved
    answers = parse_answers(bytes(resp[TCP].payload)[2:])  # skip 2-byte length prefix
    assert answers == [("A", "10.9.9.9")]


def test_listen_mode_tracks_top_domains_across_transactions():
    engine = DnsSpoofEngine([], mode="listen")
    run_through_runner(engine, make_query(qname="a.example.com"))
    run_through_runner(engine, make_query(qname="a.example.com"))
    run_through_runner(engine, make_query(qname="b.example.com"))
    assert engine.stats.top_domains(2) == [("a.example.com", 2), ("b.example.com", 1)]
