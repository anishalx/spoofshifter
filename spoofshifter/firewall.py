"""iptables / ip6tables helpers.

Manages the NFQUEUE redirection rules that send DNS traffic to the tool.
Rules added by SpoofShifter are tracked so they can be removed exactly on
shutdown (never a blanket ``iptables --flush``, which would wipe unrelated
rules the operator may have).  ``_run_cmd`` is the only subprocess touchpoint,
which keeps everything unit-testable.
"""

from __future__ import annotations

import logging
import os
import subprocess
from typing import List, Optional, Sequence, Tuple

log = logging.getLogger("spoofshifter")


class FirewallError(Exception):
    """Raised when the firewall cannot be managed (missing tools, no root)."""


def require_root() -> None:
    """Fail fast with a clear message when we cannot capture packets."""
    if os.name != "posix":
        raise FirewallError(
            "SpoofShifter requires Linux: NFQUEUE packet capture is not "
            "available on this platform"
        )
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise FirewallError("root privileges are required (run with sudo)")


def _run_cmd(cmd: Sequence[str]) -> subprocess.CompletedProcess:
    try:
        proc = subprocess.run(list(cmd), capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise FirewallError(f"required command not found: {cmd[0]}") from exc
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        message = (
            f"command failed with exit code {proc.returncode}: {' '.join(cmd)}"
            + (f"\n{stderr}" if stderr else "")
        )
        raise FirewallError(message)
    return proc


def build_redirect_rule(
    queue_num: int,
    chain: str,
    proto: str = "udp",
    table: str = "filter",
    ipv6: bool = False,
    bypass: bool = True,
) -> List[str]:
    """Build one iptables rule redirecting DNS traffic to an NFQUEUE."""
    binary = "ip6tables" if ipv6 else "iptables"
    cmd = [
        binary, "-t", table, "-I", chain,
        "-p", proto, "--dport", "53",
        "-j", "NFQUEUE", "--queue-num", str(queue_num),
    ]
    if bypass:
        # Keep forwarding DNS traffic if the queue program is not running.
        cmd.append("--queue-bypass")
    return cmd


def default_chains(table: str) -> Tuple[str, ...]:
    """Chains to hook, per table."""
    if table == "nat":
        # Router-mode: redirect before routing decisions.
        return ("PREROUTING", "OUTPUT")
    return ("FORWARD", "OUTPUT")


def add_redirect_rules(
    queue_num: int,
    table: str = "filter",
    chains: Optional[Sequence[str]] = None,
    ipv6: bool = False,
    bypass: bool = True,
) -> List[List[str]]:
    """Install NFQUEUE rules and return the exact commands that were run.

    The returned list is what ``remove_redirect_rules`` needs to clean up.
    """
    if chains is None:
        chains = default_chains(table)
    added: List[List[str]] = []
    for chain in chains:
        for proto in ("udp", "tcp"):
            cmd = build_redirect_rule(queue_num, chain, proto, table, ipv6, bypass)
            _run_cmd(cmd)
            added.append(cmd)
            log.debug("added rule: %s", " ".join(cmd))
    return added


def remove_redirect_rules(rules: Sequence[Sequence[str]]) -> None:
    """Delete exactly the rules that were added (``-I`` becomes ``-D``)."""
    for cmd in reversed(rules):
        delete = list(cmd)
        delete[2] = "-D"  # iptables -t <table> -D <chain> ...
        try:
            _run_cmd(delete)
            log.debug("removed rule: %s", " ".join(delete))
        except FirewallError:
            log.warning("could not remove rule (already gone?): %s", " ".join(delete))
