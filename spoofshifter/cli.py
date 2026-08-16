"""Command line entry point: wires everything together and cleans up."""

from __future__ import annotations

import logging
import signal
import sys
from typing import List, Optional

from . import __version__
from .arp import ArpError, ArpSpoofer
from .config import Config, ConfigError, build_parser, load_config
from .core import DnsSpoofEngine, PacketStats, SpoofError
from .firewall import (
    FirewallError,
    add_redirect_rules,
    remove_redirect_rules,
    require_root,
)
from .runner import DnsSpoofRunner, RunnerError

log = logging.getLogger("spoofshifter")


def setup_logging(verbose: int) -> None:
    if verbose >= 1:
        level = logging.DEBUG
        fmt = "%(levelname)s %(name)s: %(message)s"
    elif verbose == 0:
        level = logging.INFO
        fmt = "%(message)s"
    else:
        level = logging.ERROR
        fmt = "%(message)s"
    logging.basicConfig(level=level, format=fmt)


def print_banner(cfg: Config) -> None:
    if cfg.mode == "listen":
        print(f"SpoofShifter v{__version__}  (mode=listen - passive DNS query logging)")
        print("No spoofing is performed; every query is logged and forwarded.")
    else:
        print(f"SpoofShifter v{__version__}  (mode={cfg.mode}, queue={cfg.queue_num})")
        print("Rules:")
        for rule in cfg.rules:
            addresses = ", ".join(
                part for part in (
                    f"A:{rule.ipv4}" if rule.ipv4 else None,
                    f"AAAA:{rule.ipv6}" if rule.ipv6 else None,
                ) if part
            )
            print(f"  {rule.domain:<32} {addresses:<44} ttl={rule.ttl}")
    print("Waiting for DNS traffic (Ctrl-C to stop)...")
    print()


def print_top_domains(stats: PacketStats, limit: int) -> None:
    """Print the most-queried domains observed during the session."""
    top = stats.top_domains(limit)
    if not top:
        print("top domains: no queries observed")
        return
    print(f"top domains (top {len(top)} by query count):")
    for name, count in top:
        print(f"  {name:<40} {count}")


def cleanup(
    added_rules: List[List[str]],
    arp_spoofer: Optional[ArpSpoofer] = None,
    runner: Optional[DnsSpoofRunner] = None,
) -> None:
    """Best-effort teardown in dependency order; never raises."""
    if runner is not None:
        try:
            runner.stop()
        except Exception:
            log.exception("error stopping the packet queue")
    if arp_spoofer is not None:
        try:
            arp_spoofer.restore()
        except Exception:
            log.exception("error restoring ARP state")
    if added_rules:
        try:
            remove_redirect_rules(added_rules)
            log.info("[+] iptables rules removed (%d)", len(added_rules))
        except Exception:
            log.exception("error removing iptables rules")


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        cfg = load_config(args)
    except (ConfigError, SpoofError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    setup_logging(cfg.verbose)

    if not cfg.rules and cfg.mode != "listen":
        print("error: no spoofing rules configured (use -d DOMAIN[@IP] or --config)", file=sys.stderr)
        return 2

    added_rules: List[List[str]] = []
    arp_spoofer: Optional[ArpSpoofer] = None

    try:
        require_root()
        if cfg.manage_iptables:
            added_rules = add_redirect_rules(
                cfg.queue_num, table=cfg.table, ipv6=cfg.ipv6_rules, bypass=cfg.bypass,
            )
            log.info("[+] iptables rules installed (%d)", len(added_rules))
        if cfg.arp is not None:
            arp_spoofer = ArpSpoofer(
                cfg.arp.interface, cfg.arp.target, cfg.arp.gateway, cfg.arp.interval,
            )
            arp_spoofer.setup()
            arp_spoofer.start()
    except (FirewallError, ArpError) as exc:
        cleanup(added_rules, arp_spoofer)
        print(f"error: {exc}", file=sys.stderr)
        return 1

    engine = DnsSpoofEngine(cfg.rules, mode=cfg.mode, stats=PacketStats())
    runner = DnsSpoofRunner(engine, cfg.queue_num)

    def _on_sigterm(signum, frame):  # noqa: ARG001 - signal handler signature
        raise KeyboardInterrupt()

    previous_sigterm = signal.signal(signal.SIGTERM, _on_sigterm)
    print_banner(cfg)
    try:
        runner.start()
        runner.run_forever()
    except RunnerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        pass  # already logged by run_forever
    finally:
        signal.signal(signal.SIGTERM, previous_sigterm)
        cleanup(added_rules, arp_spoofer, runner)
        print(engine.stats.summary())
        if cfg.top_domains is not None:
            print()
            print_top_domains(engine.stats, cfg.top_domains)
    return 0


if __name__ == "__main__":
    sys.exit(main())
