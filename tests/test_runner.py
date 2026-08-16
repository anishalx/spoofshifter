import sys
import types

import pytest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP

from spoofshifter.core import DnsSpoofEngine, SpoofRule
from spoofshifter.runner import DnsSpoofRunner, RunnerError


def make_query(qname="www.google.com", qtype=1):
    pkt = IP(src="192.168.1.100", dst="8.8.8.8") / UDP(sport=5353, dport=53) / DNS(
        id=0x1234, rd=1, qd=DNSQR(qname=qname, qtype=qtype))
    return bytes(pkt)


class FakePacket:
    def __init__(self, payload):
        self.payload = payload
        self.accepted = 0
        self.dropped = 0
        self.set_payload_calls = []
        self.fail_get = False
        self.fail_set = False

    def get_payload(self):
        if self.fail_get:
            raise RuntimeError("read failed")
        return self.payload

    def set_payload(self, payload):
        if self.fail_set:
            raise RuntimeError("write failed")
        self.payload = payload
        self.set_payload_calls.append(payload)

    def accept(self):
        self.accepted += 1

    def drop(self):
        self.dropped += 1


class FakeQueue:
    def __init__(self):
        self.bound_num = None
        self.handler = None
        self.unbound = 0
        self.ran = 0

    def bind(self, num, handler):
        self.bound_num = num
        self.handler = handler

    def unbind(self):
        self.unbound += 1

    def run(self):
        self.ran += 1
        raise KeyboardInterrupt()


@pytest.fixture
def fake_queue(monkeypatch):
    module = types.ModuleType("netfilterqueue")
    module.NetfilterQueue = FakeQueue
    monkeypatch.setitem(sys.modules, "netfilterqueue", module)
    return FakeQueue


def make_engine():
    return DnsSpoofEngine([SpoofRule("www.google.com", ipv4="10.0.2.4")])


# ---------------------------------------------------------------------------
# Queue lifecycle
# ---------------------------------------------------------------------------

def test_start_binds_queue(fake_queue):
    runner = DnsSpoofRunner(make_engine(), queue_num=3)
    runner.start()
    assert isinstance(runner._queue, FakeQueue)
    assert runner._queue.bound_num == 3
    assert callable(runner._queue.handler)


def test_stop_unbinds_queue(fake_queue):
    runner = DnsSpoofRunner(make_engine(), queue_num=0)
    runner.start()
    queue = runner._queue
    runner.stop()
    assert runner._queue is None
    assert queue.unbound == 1


def test_run_forever_requires_start():
    with pytest.raises(RunnerError, match="start"):
        DnsSpoofRunner(make_engine()).run_forever()


def test_run_forever_handles_keyboard_interrupt(fake_queue):
    runner = DnsSpoofRunner(make_engine(), queue_num=0)
    runner.start()
    runner.run_forever()  # must not raise
    assert runner._queue.ran == 1


def test_start_without_netfilterqueue(monkeypatch):
    monkeypatch.setitem(sys.modules, "netfilterqueue", None)
    runner = DnsSpoofRunner(make_engine())
    with pytest.raises(RunnerError, match="netfilterqueue"):
        runner.start()


# ---------------------------------------------------------------------------
# Packet handling
# ---------------------------------------------------------------------------

def test_on_packet_spoofs_and_accepts(fake_queue):
    runner = DnsSpoofRunner(make_engine(), queue_num=0)
    runner.start()
    packet = FakePacket(make_query())
    runner._on_packet(packet)
    assert packet.accepted == 1
    assert packet.dropped == 0
    assert len(packet.set_payload_calls) == 1
    resp = IP(packet.set_payload_calls[0])
    assert resp[DNS].an[0].rdata == "10.0.2.4"
    assert runner.engine.stats.spoofed == 1


def test_on_packet_drops_aaaa_without_ipv6(fake_queue):
    runner = DnsSpoofRunner(make_engine(), queue_num=0)
    runner.start()
    packet = FakePacket(make_query(qtype=28))
    runner._on_packet(packet)
    assert packet.dropped == 1
    assert packet.accepted == 0
    assert runner.engine.stats.dropped == 1


def test_on_packet_passthrough_unchanged(fake_queue):
    runner = DnsSpoofRunner(make_engine(), queue_num=0)
    runner.start()
    packet = FakePacket(make_query(qname="example.org"))
    runner._on_packet(packet)
    assert packet.accepted == 1
    assert packet.set_payload_calls == []  # no rewrite
    assert runner.engine.stats.forwarded == 1


def test_on_packet_get_payload_error_still_accepts(fake_queue):
    runner = DnsSpoofRunner(make_engine(), queue_num=0)
    runner.start()
    packet = FakePacket(b"")
    packet.fail_get = True
    runner._on_packet(packet)
    assert packet.accepted == 1
    assert packet.dropped == 0
    assert runner.engine.stats.errors == 1


def test_on_packet_set_payload_error_still_accepts(fake_queue):
    runner = DnsSpoofRunner(make_engine(), queue_num=0)
    runner.start()
    packet = FakePacket(make_query())
    packet.fail_set = True
    runner._on_packet(packet)
    assert packet.accepted == 1
    assert packet.dropped == 0


def test_on_packet_does_not_reinject_unmodified_payload(fake_queue):
    runner = DnsSpoofRunner(make_engine(), queue_num=0)
    runner.start()
    packet = FakePacket(b"\x45\x00\x00\x14\x00\x00\x00\x00\x40\x11\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01")
    runner._on_packet(packet)
    # no DNS inside: passthrough without set_payload
    assert packet.accepted == 1
    assert packet.set_payload_calls == []
