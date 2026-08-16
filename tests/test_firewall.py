import pytest

from spoofshifter import firewall
from spoofshifter.firewall import (
    FirewallError,
    add_redirect_rules,
    build_redirect_rule,
    default_chains,
    remove_redirect_rules,
    require_root,
)


class FakeOS:
    name = "posix"

    def __init__(self, euid):
        self._euid = euid

    def geteuid(self):
        return self._euid


# ---------------------------------------------------------------------------
# Root check
# ---------------------------------------------------------------------------

def test_require_root_passes_as_root(monkeypatch):
    monkeypatch.setattr(firewall, "os", FakeOS(0))
    require_root()  # must not raise


def test_require_root_raises_for_non_root(monkeypatch):
    monkeypatch.setattr(firewall, "os", FakeOS(1000))
    with pytest.raises(FirewallError, match="root privileges"):
        require_root()


def test_require_root_raises_on_windows(monkeypatch):
    fake = FakeOS(0)
    fake.name = "nt"
    monkeypatch.setattr(firewall, "os", fake)
    with pytest.raises(FirewallError, match="Linux"):
        require_root()


# ---------------------------------------------------------------------------
# Rule construction
# ---------------------------------------------------------------------------

def test_build_redirect_rule_default():
    cmd = build_redirect_rule(0, "FORWARD")
    assert cmd == [
        "iptables", "-t", "filter", "-I", "FORWARD",
        "-p", "udp", "--dport", "53",
        "-j", "NFQUEUE", "--queue-num", "0", "--queue-bypass",
    ]


def test_build_redirect_rule_tcp():
    cmd = build_redirect_rule(7, "OUTPUT", proto="tcp")
    assert cmd[2:6] == ["filter", "-I", "OUTPUT", "-p"] and "tcp" in cmd


def test_build_redirect_rule_nat():
    cmd = build_redirect_rule(1, "PREROUTING", table="nat")
    assert cmd[2] == "nat"
    assert "PREROUTING" in cmd


def test_build_redirect_rule_ipv6():
    cmd = build_redirect_rule(0, "FORWARD", ipv6=True)
    assert cmd[0] == "ip6tables"


def test_build_redirect_rule_no_bypass():
    cmd = build_redirect_rule(0, "FORWARD", bypass=False)
    assert "--queue-bypass" not in cmd


def test_default_chains():
    assert default_chains("filter") == ("FORWARD", "OUTPUT")
    assert default_chains("nat") == ("PREROUTING", "OUTPUT")


# ---------------------------------------------------------------------------
# Add / remove with a captured command log
# ---------------------------------------------------------------------------

def test_add_rules_installs_and_tracks_commands(monkeypatch):
    calls = []

    def fake_run_cmd(cmd):
        calls.append(list(cmd))
        return None

    monkeypatch.setattr(firewall, "_run_cmd", fake_run_cmd)
    added = add_redirect_rules(3)
    assert len(added) == 4  # 2 chains x 2 protocols
    assert added == calls
    chains = [cmd[4] for cmd in added]
    assert chains == ["FORWARD", "FORWARD", "OUTPUT", "OUTPUT"]
    protos = [cmd[6] for cmd in added]
    assert protos == ["udp", "tcp", "udp", "tcp"]
    assert all("--queue-num" in cmd and "3" in cmd for cmd in added)


def test_add_rules_nat_table_uses_prerouting(monkeypatch):
    calls = []

    def fake_run_cmd(cmd):
        calls.append(list(cmd))
        return None

    monkeypatch.setattr(firewall, "_run_cmd", fake_run_cmd)
    added = add_redirect_rules(0, table="nat")
    chains = [cmd[4] for cmd in added]
    assert chains == ["PREROUTING", "PREROUTING", "OUTPUT", "OUTPUT"]
    assert all(cmd[2] == "nat" for cmd in added)


def test_add_rules_ipv6_uses_ip6tables(monkeypatch):
    calls = []

    def fake_run_cmd(cmd):
        calls.append(list(cmd))
        return None

    monkeypatch.setattr(firewall, "_run_cmd", fake_run_cmd)
    added = add_redirect_rules(0, ipv6=True)
    assert all(cmd[0] == "ip6tables" for cmd in added)


def test_remove_rules_turns_insert_into_delete(monkeypatch):
    calls = []

    def fake_run_cmd(cmd):
        calls.append(list(cmd))
        return None

    monkeypatch.setattr(firewall, "_run_cmd", fake_run_cmd)
    rules = [
        ["iptables", "-t", "filter", "-I", "FORWARD", "-p", "udp", "--dport", "53",
         "-j", "NFQUEUE", "--queue-num", "0", "--queue-bypass"],
        ["iptables", "-t", "filter", "-I", "OUTPUT", "-p", "udp", "--dport", "53",
         "-j", "NFQUEUE", "--queue-num", "0", "--queue-bypass"],
    ]
    remove_redirect_rules(rules)
    assert [cmd[2] for cmd in calls] == ["-D", "-D"]
    assert [cmd[4] for cmd in calls] == ["OUTPUT", "FORWARD"]  # reversed order
    assert calls[0][4] == "OUTPUT"


def test_remove_rules_tolerates_already_gone(monkeypatch):
    def failing(cmd):
        raise FirewallError("rule not found")

    monkeypatch.setattr(firewall, "_run_cmd", failing)
    remove_redirect_rules([["iptables", "-t", "filter", "-I", "FORWARD", "-p", "udp"]])  # no raise


# ---------------------------------------------------------------------------
# Command execution
# ---------------------------------------------------------------------------

def test_run_cmd_missing_binary(monkeypatch):
    def missing(cmd, **kwargs):
        raise FileNotFoundError(cmd[0])

    monkeypatch.setattr(firewall.subprocess, "run", missing)
    with pytest.raises(FirewallError, match="not found: iptables"):
        firewall._run_cmd(["iptables", "-L"])


def test_run_cmd_reports_failure(monkeypatch):
    def failing(cmd, **kwargs):
        return firewall.subprocess.CompletedProcess(cmd, 1, "", "iptables: Permission denied")

    monkeypatch.setattr(firewall.subprocess, "run", failing)
    with pytest.raises(FirewallError, match="Permission denied"):
        firewall._run_cmd(["iptables", "-L"])


def test_run_cmd_success(monkeypatch):
    def ok(cmd, **kwargs):
        return firewall.subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(firewall.subprocess, "run", ok)
    assert firewall._run_cmd(["iptables", "-L"]).returncode == 0
