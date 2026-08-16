import pytest

from spoofshifter import cli


def test_main_without_rules(capsys):
    code = cli.main(["--no-iptables"])
    assert code == 2
    assert "no spoofing rules" in capsys.readouterr().err


def test_main_usage_error_exits_2():
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--mode", "bogus", "-d", "example.com@10.0.2.4"])
    assert excinfo.value.code == 2


def test_main_invalid_rule_returns_2(capsys):
    code = cli.main(["-d", "example.com@not-an-ip", "--no-iptables"])
    assert code == 2
    assert "invalid IP" in capsys.readouterr().err


def test_main_requires_linux(capsys):
    # On this platform (Windows) the root/Linux check must fail cleanly.
    code = cli.main(["-d", "example.com@10.0.2.4", "--no-iptables"])
    assert code == 1
    assert "Linux" in capsys.readouterr().err


def test_main_list_domains_needs_no_rules(capsys):
    # Listen mode must reach the runtime (and fail only on the Linux check),
    # not the "no spoofing rules" usage error.
    code = cli.main(["--list-domains", "--no-iptables"])
    assert code == 1
    assert "Linux" in capsys.readouterr().err


def test_print_top_domains_ranked(capsys):
    from spoofshifter.core import PacketStats
    stats = PacketStats()
    stats.record_query("www.google.com")
    stats.record_query("www.google.com")
    stats.record_query("mail.google.com")
    cli.print_top_domains(stats, 10)
    out = capsys.readouterr().out
    lines = [line for line in out.splitlines() if line.startswith("  ")]
    assert lines[0].split() == ["www.google.com", "2"]
    assert lines[1].split() == ["mail.google.com", "1"]


def test_print_top_domains_empty(capsys):
    from spoofshifter.core import PacketStats
    cli.print_top_domains(PacketStats(), 10)
    assert "no queries observed" in capsys.readouterr().out


def test_listen_banner_printed():
    import contextlib
    import io

    from spoofshifter.config import Config

    cfg = Config(rules=[], mode="listen")
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        cli.print_banner(cfg)
    text = out.getvalue()
    assert "mode=listen" in text
    assert "No spoofing is performed" in text
    assert "Rules:" not in text  # no rules table in listen mode


def test_cleanup_passes_arp_restore_flag():
    calls = []

    class FakeArp:
        def restore(self, restore_arp=True):
            calls.append(restore_arp)

    cli.cleanup([], FakeArp(), None, arp_restore=False)
    cli.cleanup([], FakeArp(), None, arp_restore=True)
    assert calls == [False, True]


def _main_with_fake_runner(monkeypatch, *argv):
    """Run cli.main() past the platform checks with a runner that interrupts."""
    import spoofshifter.cli as cli_mod

    monkeypatch.setattr(cli_mod, "require_root", lambda: None)
    monkeypatch.setattr(cli_mod, "add_redirect_rules", lambda *a, **k: [])

    class InterruptRunner:
        def __init__(self, engine, queue_num=0):
            pass

        def start(self):
            raise KeyboardInterrupt()

        def run_forever(self):
            pass

        def stop(self):
            pass

    monkeypatch.setattr(cli_mod, "DnsSpoofRunner", InterruptRunner)
    return cli_mod.main(list(argv))


def test_quiet_mode_suppresses_banner_and_summary(capsys, monkeypatch):
    code = _main_with_fake_runner(monkeypatch, "-d", "example.com@10.0.2.4", "--quiet")
    out = capsys.readouterr().out
    assert code == 0
    assert "SpoofShifter" not in out      # no banner
    assert "summary:" not in out          # no on-exit report


def test_default_mode_prints_banner_and_summary(capsys, monkeypatch):
    code = _main_with_fake_runner(monkeypatch, "-d", "example.com@10.0.2.4")
    out = capsys.readouterr().out
    assert code == 0
    assert "SpoofShifter" in out          # banner shown
    assert "summary:" in out              # on-exit report shown


def test_quiet_listen_mode_suppresses_top_domains(capsys, monkeypatch):
    code = _main_with_fake_runner(monkeypatch, "--list-domains", "--top-domains", "--quiet")
    assert code == 0
    assert "top domains" not in capsys.readouterr().out


# ---------------------------------------------------------------------------
# --pidfile
# ---------------------------------------------------------------------------

def test_cleanup_removes_own_pidfile(tmp_path):
    from spoofshifter.pidfile import write_pidfile
    pid_path = tmp_path / "spoofshifter.pid"
    write_pidfile(str(pid_path))
    cli.cleanup([], pidfile=str(pid_path))
    assert not pid_path.exists()


def test_cleanup_leaves_foreign_pidfile(tmp_path):
    pid_path = tmp_path / "spoofshifter.pid"
    pid_path.write_text("98765", encoding="ascii")
    cli.cleanup([], pidfile=str(pid_path))
    assert pid_path.exists()


def test_main_writes_and_removes_pidfile(tmp_path, monkeypatch):
    pid_path = tmp_path / "spoofshifter.pid"
    code = _main_with_fake_runner(
        monkeypatch, "-d", "example.com@10.0.2.4", "--pidfile", str(pid_path),
    )
    assert code == 0
    assert not pid_path.exists()  # written at start, removed at shutdown


def test_main_rejects_live_instance(tmp_path, monkeypatch, capsys):
    import spoofshifter.pidfile as pidfile_mod
    pid_path = tmp_path / "spoofshifter.pid"
    pid_path.write_text("1234", encoding="ascii")
    monkeypatch.setattr(pidfile_mod, "pid_alive", lambda pid: True)
    code = _main_with_fake_runner(
        monkeypatch, "-d", "example.com@10.0.2.4", "--pidfile", str(pid_path),
    )
    assert code == 1
    assert "already running" in capsys.readouterr().err
    assert pid_path.exists()  # foreign pidfile untouched
    assert pid_path.read_text(encoding="ascii") == "1234"


# ---------------------------------------------------------------------------
# --log-file
# ---------------------------------------------------------------------------

def _main_with_event_runner(monkeypatch, *argv):
    """Like _main_with_fake_runner, but the runner feeds a real DNS query
    through the engine before interrupting, so spoofing events are logged."""
    import spoofshifter.cli as cli_mod
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import IP, UDP

    monkeypatch.setattr(cli_mod, "require_root", lambda: None)
    monkeypatch.setattr(cli_mod, "add_redirect_rules", lambda *a, **k: [])

    class EventRunner:
        def __init__(self, engine, queue_num=0):
            self.engine = engine

        def start(self):
            query = bytes(IP(src="192.168.1.100", dst="192.0.2.1") / UDP(sport=5353, dport=53) / DNS(
                id=1, rd=1, qd=DNSQR(qname="www.google.com", qtype=1)))
            self.engine.process_payload(query)
            raise KeyboardInterrupt()

        def run_forever(self):
            pass

        def stop(self):
            pass

    monkeypatch.setattr(cli_mod, "DnsSpoofRunner", EventRunner)
    return cli_mod.main(list(argv))


def test_log_file_created_in_quiet_mode(tmp_path, monkeypatch, capsys):
    log_path = tmp_path / "spoofshifter.log"
    code = _main_with_fake_runner(
        monkeypatch, "-d", "example.com@10.0.2.4", "--quiet", "--log-file", str(log_path),
    )
    assert code == 0
    assert log_path.exists()
    # quiet console stays clean even though a log file is configured
    assert "SpoofShifter" not in capsys.readouterr().out


def test_log_file_captures_events_while_quiet(tmp_path, monkeypatch):
    log_path = tmp_path / "spoofshifter.log"
    code = _main_with_event_runner(
        monkeypatch, "-d", "www.google.com@10.0.2.4", "--quiet", "--log-file", str(log_path),
    )
    assert code == 0
    content = log_path.read_text(encoding="utf-8")
    # the spoofing event reached the file even though the console is quiet
    assert "spoofing www.google.com A -> 10.0.2.4" in content
    assert "INFO" in content  # timestamped, level-tagged format


def test_log_file_also_records_in_default_mode(tmp_path, monkeypatch):
    log_path = tmp_path / "spoofshifter.log"
    code = _main_with_event_runner(
        monkeypatch, "-d", "www.google.com@10.0.2.4", "--log-file", str(log_path),
    )
    assert code == 0
    assert "spoofing www.google.com A -> 10.0.2.4" in log_path.read_text(encoding="utf-8")


def test_log_file_creation_failure_returns_1(tmp_path, monkeypatch, capsys):
    # a directory cannot be opened as a log file
    code = _main_with_fake_runner(
        monkeypatch, "-d", "example.com@10.0.2.4", "--log-file", str(tmp_path),
    )
    assert code == 1
    assert "cannot open log file" in capsys.readouterr().err


def test_version_exits_0():
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--version"])
    assert excinfo.value.code == 0
