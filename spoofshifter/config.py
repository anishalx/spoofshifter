"""Configuration: CLI parsing, JSON config files, rule construction.

CLI flags always win over values from a config file.  Rules from the file and
from ``-d`` flags are merged (deduplicated by domain).
"""

from __future__ import annotations

import argparse
import ipaddress
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from . import __version__
from .core import SpoofError, SpoofRule


class ConfigError(Exception):
    """Raised for invalid command line or config file input."""


@dataclass
class ArpConfig:
    interface: str
    target: str
    gateway: str
    interval: float = 2.0


@dataclass
class Config:
    rules: List[SpoofRule]
    queue_num: int = 0
    mode: str = "reply"
    ttl: int = 300
    manage_iptables: bool = True
    table: str = "filter"
    ipv6_rules: bool = False
    bypass: bool = True
    arp: Optional[ArpConfig] = None
    verbose: int = 0
    top_domains: Optional[int] = None  # limit for the on-exit ranking, None = off


# ---------------------------------------------------------------------------
# Rule parsing
# ---------------------------------------------------------------------------

def parse_domain_spec(
    spec: str,
    default_ip: Optional[str] = None,
    ttl: int = 300,
) -> SpoofRule:
    """Parse one rule string into a SpoofRule.

    Accepts ``example.com``, ``example.com@10.0.2.4`` or
    ``*.example.com@[fd00::1]``.  A bare domain gets ``default_ip`` if given;
    otherwise the rule must carry its own address.
    """
    spec = spec.strip()
    if not spec:
        raise ConfigError("empty domain rule")
    domain, separator, address = spec.partition("@")
    domain = domain.strip()
    if not domain:
        raise ConfigError(f"invalid rule {spec!r}: missing domain")

    ipv4 = ipv6 = None
    if separator:
        address = address.strip().strip("[]")
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            raise ConfigError(f"invalid IP address in rule {spec!r}: {address!r}")
        if parsed.version == 4:
            ipv4 = str(parsed)
        else:
            ipv6 = str(parsed)
    elif default_ip:
        try:
            parsed = ipaddress.ip_address(default_ip.strip().strip("[]"))
        except ValueError:
            raise ConfigError(f"invalid --ip address: {default_ip!r}")
        if parsed.version == 4:
            ipv4 = str(parsed)
        else:
            ipv6 = str(parsed)

    try:
        return SpoofRule(domain=domain, ipv4=ipv4, ipv6=ipv6, ttl=ttl)
    except SpoofError as exc:
        raise ConfigError(f"invalid rule {spec!r}: {exc}") from exc


def rules_from_config_dict(data: Dict[str, Any], default_ttl: int) -> List[SpoofRule]:
    """Build rules from the ``rules`` key of a JSON config file."""
    rules: List[SpoofRule] = []
    entries = data.get("rules", [])
    if not isinstance(entries, list):
        raise ConfigError("config key 'rules' must be a list")
    for entry in entries:
        if isinstance(entry, str):
            rules.append(parse_domain_spec(entry, ttl=default_ttl))
            continue
        if not isinstance(entry, dict):
            raise ConfigError(f"invalid rule entry: {entry!r}")
        domain = entry.get("domain")
        if not isinstance(domain, str) or not domain.strip():
            raise ConfigError(f"rule entry is missing a 'domain': {entry!r}")
        ttl = entry.get("ttl", default_ttl)
        ipv4 = entry.get("ipv4")
        ipv6 = entry.get("ipv6")
        if ipv4 is not None and not isinstance(ipv4, str):
            raise ConfigError(f"rule {domain!r}: 'ipv4' must be a string")
        if ipv6 is not None and not isinstance(ipv6, str):
            raise ConfigError(f"rule {domain!r}: 'ipv6' must be a string")
        try:
            rules.append(SpoofRule(domain=domain, ipv4=ipv4, ipv6=ipv6, ttl=ttl))
        except SpoofError as exc:
            raise ConfigError(f"invalid rule for {domain!r}: {exc}") from exc
    return rules


def _dedupe_rules(rules: List[SpoofRule]) -> List[SpoofRule]:
    seen: Dict[str, SpoofRule] = {}
    for rule in rules:
        key = rule.domain.lower().rstrip(".")
        if key not in seen:
            seen[key] = rule
    return list(seen.values())


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="spoofshifter",
        description=(
            "Advanced DNS spoofing tool for authorized penetration testing. "
            "Run as root on Linux."
        ),
        epilog=(
            "examples:\n"
            "  sudo python3 spoofshifter.py -d www.google.com@10.0.2.4\n"
            "  sudo python3 spoofshifter.py -d '*.example.com@10.0.2.4' -d example.com@[fd00::1]\n"
            "  sudo python3 spoofshifter.py -c config.json\n"
            "  sudo python3 spoofshifter.py -d example.com@10.0.2.4 --arp-spoof \\\n"
            "      --target 192.168.1.100 --gateway 192.168.1.1 -i eth0"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-d", "--domain", action="append", metavar="DOMAIN[@IP]",
        help=(
            "domain to spoof; optionally 'example.com@10.0.2.4' or "
            "'*.example.com@[fd00::1]' (repeatable, wildcards allowed)"
        ),
    )
    parser.add_argument(
        "--ip", metavar="IP",
        help="default spoof address applied to bare domains",
    )
    parser.add_argument(
        "-c", "--config", metavar="FILE",
        help="JSON config file (CLI flags override it)",
    )
    parser.add_argument(
        "-q", "--queue", type=int, metavar="NUM",
        help="NFQUEUE number to bind (default 0)",
    )
    parser.add_argument(
        "--mode", choices=("reply", "mutate", "listen"),
        help=(
            "reply: forge answers to queries (default); mutate: rewrite "
            "in-flight responses; listen: passive DNS query logging"
        ),
    )
    parser.add_argument(
        "--list-domains", action="store_true", default=None,
        help="passive recon mode: log every DNS query and forward it untouched "
             "(no spoofing rules needed)",
    )
    parser.add_argument(
        "--top-domains", nargs="?", const=10, type=int, metavar="N",
        help="print the most-queried domains (ranked) on exit; default top 10, "
             "e.g. --top-domains 25 for the top 25",
    )
    parser.add_argument(
        "--ttl", type=int, metavar="SEC",
        help="TTL on spoofed DNS answers (default 300)",
    )
    parser.add_argument(
        "--no-iptables", action="store_true", default=None,
        help="do not add/remove iptables rules (assume rules are already set up)",
    )
    parser.add_argument(
        "--nat", action="store_true", default=None,
        help="hook the nat table (PREROUTING/OUTPUT) instead of FORWARD/OUTPUT, for router mode",
    )
    parser.add_argument(
        "--no-bypass", action="store_true", default=None,
        help="do not use --queue-bypass (DNS is dropped while the tool is stopped)",
    )
    parser.add_argument(
        "--arp-spoof", action="store_true", default=None,
        help="also run ARP spoofing between target and gateway",
    )
    parser.add_argument("--target", metavar="IP", help="victim IP for ARP spoofing")
    parser.add_argument("--gateway", metavar="IP", help="gateway/router IP for ARP spoofing")
    parser.add_argument("-i", "--iface", metavar="IFACE", help="network interface for ARP spoofing")
    parser.add_argument(
        "--arp-interval", type=float, metavar="SEC",
        help="seconds between ARP poison packets (default 2)",
    )
    parser.add_argument(
        "-v", "--verbose", action="count", default=0,
        help="verbose logging (-v debug)",
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="only log errors",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}",
    )
    return parser


def _pick(cli_value: Any, file_value: Any, default: Any) -> Any:
    """CLI flag wins, then config file, then built-in default."""
    if cli_value is not None:
        return cli_value
    if file_value is not None:
        return file_value
    return default


def load_config(args: argparse.Namespace) -> Config:
    """Merge a JSON config file (if any) with CLI flags into a Config."""
    file_cfg: Dict[str, Any] = {}
    if args.config:
        try:
            with open(args.config, "r", encoding="utf-8") as fh:
                file_cfg = json.load(fh)
        except OSError as exc:
            raise ConfigError(f"cannot read config file {args.config!r}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise ConfigError(f"invalid JSON in {args.config!r}: {exc}") from exc
        if not isinstance(file_cfg, dict):
            raise ConfigError("config file must contain a JSON object")

    ttl = _pick(args.ttl, file_cfg.get("ttl"), 300)
    if not isinstance(ttl, int) or ttl < 0:
        raise ConfigError(f"invalid ttl: {ttl!r}")

    mode = _pick(args.mode, file_cfg.get("mode"), "reply")
    if args.list_domains:
        mode = "listen"  # the flag wins over any mode in the config file
    if mode not in ("reply", "mutate", "listen"):
        raise ConfigError(f"invalid mode {mode!r} (expected 'reply', 'mutate' or 'listen')")

    queue_num = _pick(args.queue, file_cfg.get("queue"), 0)
    if not isinstance(queue_num, int) or queue_num < 0 or queue_num > 65535:
        raise ConfigError(f"invalid queue number: {queue_num!r}")

    table = "nat" if _pick(args.nat, file_cfg.get("nat"), False) else "filter"

    file_no_iptables = None
    if "manage_iptables" in file_cfg:
        file_no_iptables = not bool(file_cfg["manage_iptables"])
    manage_iptables = not bool(_pick(args.no_iptables, file_no_iptables, False))

    file_no_bypass = None
    if "bypass" in file_cfg:
        file_no_bypass = not bool(file_cfg["bypass"])
    bypass = not bool(_pick(args.no_bypass, file_no_bypass, False))

    default_ip = args.ip or file_cfg.get("default_ip")

    rules: List[SpoofRule] = []
    rules.extend(rules_from_config_dict(file_cfg, ttl))
    for spec in args.domain or []:
        rules.append(parse_domain_spec(spec, default_ip=default_ip, ttl=ttl))
    rules = _dedupe_rules(rules)

    arp: Optional[ArpConfig] = None
    file_arp = file_cfg.get("arp")
    arp_enabled_file = isinstance(file_arp, dict) and bool(file_arp.get("enabled", False))
    if _pick(args.arp_spoof, arp_enabled_file, False):
        arp_file = file_arp if isinstance(file_arp, dict) else {}
        iface = _pick(args.iface, arp_file.get("interface"), None)
        target = _pick(args.target, arp_file.get("target"), None)
        gateway = _pick(args.gateway, arp_file.get("gateway"), None)
        interval = _pick(args.arp_interval, arp_file.get("interval"), 2.0)
        missing = [name for name, value in (("interface", iface), ("target", target), ("gateway", gateway)) if not value]
        if missing:
            raise ConfigError(
                f"ARP spoofing enabled but missing: {', '.join(missing)} "
                "(use --iface/--target/--gateway or the config file)"
            )
        for label, value in (("target", target), ("gateway", gateway)):
            try:
                ipaddress.ip_address(value)
            except ValueError:
                raise ConfigError(f"invalid {label} IP for ARP spoofing: {value!r}")
        if not isinstance(interval, (int, float)) or interval <= 0:
            raise ConfigError(f"invalid ARP interval: {interval!r}")
        arp = ArpConfig(interface=iface, target=target, gateway=gateway, interval=float(interval))

    verbose = args.verbose
    if args.quiet:
        verbose = -1

    top_domains = args.top_domains
    if top_domains is None and "top_domains" in file_cfg:
        file_top = file_cfg["top_domains"]
        if file_top is True:
            top_domains = 10
        elif isinstance(file_top, int) and file_top > 0:
            top_domains = file_top
        elif file_top is False or file_top is None:
            top_domains = None
        else:
            raise ConfigError(f"invalid top_domains value: {file_top!r}")
    if top_domains is not None and top_domains < 1:
        raise ConfigError(f"invalid top_domains limit: {top_domains!r}")

    ipv6_rules = any(rule.ipv6 for rule in rules)

    return Config(
        rules=rules,
        queue_num=queue_num,
        mode=mode,
        ttl=ttl,
        manage_iptables=manage_iptables,
        table=table,
        ipv6_rules=ipv6_rules,
        bypass=bypass,
        arp=arp,
        verbose=verbose,
        top_domains=top_domains,
    )
