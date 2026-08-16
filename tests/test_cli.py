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


def test_version_exits_0():
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--version"])
    assert excinfo.value.code == 0
