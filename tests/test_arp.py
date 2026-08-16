import time

import pytest
from scapy.layers.l2 import ARP, Ether

from spoofshifter import arp
from spoofshifter.arp import (
    ArpError,
    ArpSpoofer,
    build_restore_packet,
    build_spoof_packet,
    get_own_mac,
    resolve_mac,
)


@pytest.fixture(autouse=True)
def reset_ip_forward_state():
    yield
    arp._IP_FORWARD_ORIGINAL = None


# ---------------------------------------------------------------------------
# Packet construction
# ---------------------------------------------------------------------------

def test_build_spoof_packet():
    pkt = build_spoof_packet("00:11:22:33:44:55", "192.168.1.100", "aa:bb:cc:dd:ee:ff", "192.168.1.1")
    assert pkt[Ether].src == "00:11:22:33:44:55"
    assert pkt[Ether].dst == "aa:bb:cc:dd:ee:ff"
    assert pkt[ARP].op == 2
    assert pkt[ARP].psrc == "192.168.1.1"          # pretending to be the gateway
    assert pkt[ARP].pdst == "192.168.1.100"        # aimed at the victim
    assert pkt[ARP].hwsrc == "00:11:22:33:44:55"
    assert pkt[ARP].hwdst == "aa:bb:cc:dd:ee:ff"


def test_build_restore_packet():
    pkt = build_restore_packet("aa:bb:cc:dd:ee:ff", "192.168.1.100", "aa:bb:cc:dd:ee:ff", "192.168.1.1")
    assert pkt[ARP].op == 2
    assert pkt[ARP].psrc == "192.168.1.1"          # true gateway IP
    assert pkt[ARP].hwsrc == "aa:bb:cc:dd:ee:ff"   # true gateway MAC


# ---------------------------------------------------------------------------
# MAC resolution
# ---------------------------------------------------------------------------

def _fake_srp1(reply=None):
    def fake(pkt, **kwargs):
        return reply
    return fake


def test_resolve_mac_from_reply(monkeypatch):
    reply = Ether(src="aa:bb:cc:dd:ee:ff") / ARP(op=2, hwsrc="aa:bb:cc:dd:ee:ff", psrc="192.168.1.1")
    monkeypatch.setattr(arp, "srp1", _fake_srp1(reply))
    assert resolve_mac("192.168.1.1", "eth0") == "aa:bb:cc:dd:ee:ff"


def test_resolve_mac_ignores_non_arp_reply(monkeypatch):
    reply = Ether() / ARP(op=1)  # a request, not a reply
    monkeypatch.setattr(arp, "srp1", _fake_srp1(reply))
    assert resolve_mac("192.168.1.1", "eth0", retries=1) is None


def test_resolve_mac_no_answer(monkeypatch):
    monkeypatch.setattr(arp, "srp1", _fake_srp1(None))
    assert resolve_mac("192.168.1.1", "eth0") is None


def test_resolve_mac_retries_until_answer(monkeypatch):
    calls = {"n": 0}
    reply = Ether(src="aa:bb:cc:dd:ee:ff") / ARP(op=2, hwsrc="aa:bb:cc:dd:ee:ff", psrc="192.168.1.1")

    def flaky(pkt, **kwargs):
        calls["n"] += 1
        return reply if calls["n"] >= 3 else None

    monkeypatch.setattr(arp, "srp1", flaky)
    assert resolve_mac("192.168.1.1", "eth0", retries=5) == "aa:bb:cc:dd:ee:ff"
    assert calls["n"] == 3


# ---------------------------------------------------------------------------
# Own MAC
# ---------------------------------------------------------------------------

def test_get_own_mac(monkeypatch):
    import scapy.arch
    monkeypatch.setattr(scapy.arch, "get_if_hwaddr", lambda iface: "00:11:22:33:44:55")
    assert get_own_mac("eth0") == "00:11:22:33:44:55"


def test_get_own_mac_error(monkeypatch):
    import scapy.arch

    def boom(iface):
        raise OSError("no such device")

    monkeypatch.setattr(scapy.arch, "get_if_hwaddr", boom)
    with pytest.raises(ArpError, match="eth0"):
        get_own_mac("eth0")


# ---------------------------------------------------------------------------
# IP forwarding
# ---------------------------------------------------------------------------

class FakeFile:
    def __init__(self, content=""):
        self.content = content

    def read(self):
        return self.content

    def write(self, value):
        self.content = value

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_enable_and_restore_ip_forwarding(monkeypatch):
    state = FakeFile("0")

    def fake_open(path, mode="r", encoding=None):
        assert path == "/proc/sys/net/ipv4/ip_forward"
        return state

    monkeypatch.setattr("builtins.open", fake_open)
    arp.enable_ip_forwarding()
    assert state.content == "1"
    arp.restore_ip_forwarding()
    assert state.content == "0"


def test_restore_ip_forwarding_noop_when_never_enabled(monkeypatch):
    def boom(path, mode="r", encoding=None):
        raise AssertionError("open() must not be called")

    monkeypatch.setattr("builtins.open", boom)
    arp.restore_ip_forwarding()  # must not raise


def test_enable_ip_forwarding_error(monkeypatch):
    def boom(path, mode="r", encoding=None):
        raise OSError("permission denied")

    monkeypatch.setattr("builtins.open", boom)
    with pytest.raises(ArpError, match="IP forwarding"):
        arp.enable_ip_forwarding()


# ---------------------------------------------------------------------------
# ArpSpoofer lifecycle
# ---------------------------------------------------------------------------

def test_spoofer_start_requires_setup():
    spoofer = ArpSpoofer("eth0", "192.168.1.100", "192.168.1.1")
    with pytest.raises(ArpError, match="setup"):
        spoofer.start()


def test_spoofer_start_requires_resolvable_macs(monkeypatch):
    monkeypatch.setattr(arp, "get_own_mac", lambda iface: "00:11:22:33:44:55")
    monkeypatch.setattr(arp, "resolve_mac", lambda ip, iface: None)
    monkeypatch.setattr(arp, "enable_ip_forwarding", lambda: (_ for _ in ()).throw(AssertionError("must not run")))
    spoofer = ArpSpoofer("eth0", "192.168.1.100", "192.168.1.1")
    spoofer.setup()
    with pytest.raises(ArpError, match="192.168.1.100"):
        spoofer.start()


def test_spoofer_poisons_and_restores(monkeypatch):
    sent = []
    forwarding = {"enabled": 0, "restored": 0}

    def fake_sendp(pkt, **kwargs):
        sent.append(pkt)

    monkeypatch.setattr(arp, "get_own_mac", lambda iface: "00:11:22:33:44:55")
    monkeypatch.setattr(
        arp, "resolve_mac",
        lambda ip, iface: "aa:bb:cc:dd:ee:ff" if ip == "192.168.1.100" else "11:22:33:44:55:66",
    )
    monkeypatch.setattr(arp, "sendp", fake_sendp)
    monkeypatch.setattr(arp, "enable_ip_forwarding", lambda: forwarding.__setitem__("enabled", 1))
    monkeypatch.setattr(arp, "restore_ip_forwarding", lambda: forwarding.__setitem__("restored", 1))

    spoofer = ArpSpoofer("eth0", "192.168.1.100", "192.168.1.1", interval=0.05)
    spoofer.setup()
    spoofer.start()
    time.sleep(0.12)  # let the poison thread fire a few times
    spoofer.restore()

    # Thread stopped
    assert spoofer._thread is None or not spoofer._thread.is_alive()

    poison = [p for p in sent if p[ARP].psrc == "192.168.1.1" and p[ARP].hwsrc == "00:11:22:33:44:55"]
    assert poison, "expected poison packets pretending to be the gateway"
    assert all(p[ARP].pdst == "192.168.1.100" for p in poison)

    reverse = [p for p in sent if p[ARP].psrc == "192.168.1.100"]
    assert reverse, "expected poison packets pretending to be the victim"
    assert all(p[ARP].pdst == "192.168.1.1" for p in reverse)

    restore = [p for p in sent if p[ARP].psrc == "192.168.1.1" and p[ARP].hwsrc == "11:22:33:44:55:66"]
    assert restore, "expected restore packets with the true gateway MAC"

    assert forwarding == {"enabled": 1, "restored": 1}


def test_restore_without_start_is_safe():
    spoofer = ArpSpoofer("eth0", "192.168.1.100", "192.168.1.1")
    spoofer.restore()  # must not raise
    spoofer.restore(restore_arp=False)  # must not raise either


def test_restore_skips_arp_packets_when_disabled(monkeypatch):
    sent = []
    forwarding = {"restored": 0}

    def fake_sendp(pkt, **kwargs):
        sent.append(pkt)

    monkeypatch.setattr(arp, "get_own_mac", lambda iface: "00:11:22:33:44:55")
    monkeypatch.setattr(
        arp, "resolve_mac",
        lambda ip, iface: "aa:bb:cc:dd:ee:ff" if ip == "192.168.1.100" else "11:22:33:44:55:66",
    )
    monkeypatch.setattr(arp, "sendp", fake_sendp)
    monkeypatch.setattr(arp, "enable_ip_forwarding", lambda: None)
    monkeypatch.setattr(arp, "restore_ip_forwarding", lambda: forwarding.__setitem__("restored", 1))

    spoofer = ArpSpoofer("eth0", "192.168.1.100", "192.168.1.1", interval=0.05)
    spoofer.setup()
    spoofer.start()
    time.sleep(0.08)  # let the poison thread fire
    spoofer.restore(restore_arp=False)

    # Poison packets were sent, but no correct-ARP restore packets.
    assert sent, "expected poison packets"
    assert not any(
        p[ARP].hwsrc == "11:22:33:44:55:66" and p[ARP].psrc == "192.168.1.1"
        for p in sent
    ), "no restore packet should have been sent"
    assert spoofer._thread is None or not spoofer._thread.is_alive()
    assert forwarding == {"restored": 1}  # IP forwarding still restored
