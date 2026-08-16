import json

import pytest

from spoofshifter.config import (
    ConfigError,
    build_parser,
    load_config,
    parse_domain_spec,
)


def parse_args(*argv):
    return build_parser().parse_args(list(argv))


# ---------------------------------------------------------------------------
# Domain spec parsing
# ---------------------------------------------------------------------------

def test_parse_domain_spec_with_ipv4():
    rule = parse_domain_spec("www.google.com@10.0.2.4")
    assert rule.domain == "www.google.com"
    assert rule.ipv4 == "10.0.2.4"
    assert rule.ipv6 is None


def test_parse_domain_spec_with_ipv6_brackets():
    rule = parse_domain_spec("example.com@[fd00::1]")
    assert rule.ipv6 == "fd00::1"
    assert rule.ipv4 is None


def test_parse_domain_spec_wildcard():
    rule = parse_domain_spec("*.example.com@10.0.2.4")
    assert rule.domain == "*.example.com"
    assert rule.ipv4 == "10.0.2.4"


def test_parse_domain_spec_bare_with_default_ip():
    rule = parse_domain_spec("example.com", default_ip="10.0.2.4")
    assert rule.ipv4 == "10.0.2.4"


def test_parse_domain_spec_bare_without_ip_raises():
    with pytest.raises(ConfigError, match="needs at least one spoof address"):
        parse_domain_spec("example.com")


def test_parse_domain_spec_invalid_ip():
    with pytest.raises(ConfigError, match="invalid IP"):
        parse_domain_spec("example.com@not-an-ip")


def test_parse_domain_spec_empty():
    with pytest.raises(ConfigError):
        parse_domain_spec("")


def test_parse_domain_spec_bad_default_ip():
    with pytest.raises(ConfigError, match="invalid --ip"):
        parse_domain_spec("example.com", default_ip="999.1.1.1")


def test_parse_domain_spec_respects_ttl():
    rule = parse_domain_spec("example.com@10.0.2.4", ttl=60)
    assert rule.ttl == 60


# ---------------------------------------------------------------------------
# CLI-only loading
# ---------------------------------------------------------------------------

def test_load_config_minimal_domain():
    cfg = load_config(parse_args("-d", "www.google.com@10.0.2.4"))
    assert len(cfg.rules) == 1
    assert cfg.rules[0].ipv4 == "10.0.2.4"
    assert cfg.queue_num == 0
    assert cfg.mode == "reply"
    assert cfg.manage_iptables is True
    assert cfg.table == "filter"
    assert cfg.bypass is True
    assert cfg.arp is None


def test_load_config_default_ip_applies_to_bare_domain():
    cfg = load_config(parse_args("-d", "example.com", "--ip", "10.0.2.4"))
    assert cfg.rules[0].ipv4 == "10.0.2.4"


def test_load_config_flags():
    cfg = load_config(parse_args(
        "-d", "example.com@10.0.2.4",
        "--queue", "5", "--mode", "mutate", "--ttl", "60",
        "--no-iptables", "--no-bypass", "--nat", "--verbose",
    ))
    assert cfg.queue_num == 5
    assert cfg.mode == "mutate"
    assert cfg.ttl == 60
    assert cfg.manage_iptables is False
    assert cfg.bypass is False
    assert cfg.table == "nat"
    assert cfg.verbose == 1


def test_load_config_quiet():
    cfg = load_config(parse_args("-d", "example.com@10.0.2.4", "--quiet"))
    assert cfg.verbose == -1


def test_load_config_list_domains_sets_listen_mode():
    cfg = load_config(parse_args("--list-domains"))
    assert cfg.mode == "listen"
    assert cfg.rules == []  # rules are optional in listen mode


def test_list_domains_overrides_config_file_mode(tmp_path):
    path = _write_config(tmp_path, {"mode": "mutate", "rules": ["example.com@10.0.2.4"]})
    cfg = load_config(parse_args("-c", path, "--list-domains"))
    assert cfg.mode == "listen"


def test_listen_mode_from_config_file(tmp_path):
    path = _write_config(tmp_path, {"mode": "listen", "rules": []})
    cfg = load_config(parse_args("-c", path))
    assert cfg.mode == "listen"


# ---------------------------------------------------------------------------
# --top-domains
# ---------------------------------------------------------------------------

def test_top_domains_flag_defaults_to_ten():
    cfg = load_config(parse_args("--list-domains", "--top-domains"))
    assert cfg.top_domains == 10


def test_top_domains_flag_with_custom_limit():
    cfg = load_config(parse_args("--list-domains", "--top-domains", "25"))
    assert cfg.top_domains == 25


def test_top_domains_disabled_by_default():
    cfg = load_config(parse_args("--list-domains"))
    assert cfg.top_domains is None


def test_top_domains_from_config_file_true(tmp_path):
    path = _write_config(tmp_path, {"mode": "listen", "rules": [], "top_domains": True})
    assert load_config(parse_args("-c", path)).top_domains == 10


def test_top_domains_from_config_file_int(tmp_path):
    path = _write_config(tmp_path, {"mode": "listen", "rules": [], "top_domains": 25})
    assert load_config(parse_args("-c", path)).top_domains == 25


def test_top_domains_from_config_file_false(tmp_path):
    path = _write_config(tmp_path, {"mode": "listen", "rules": [], "top_domains": False})
    assert load_config(parse_args("-c", path)).top_domains is None


def test_top_domains_cli_overrides_file(tmp_path):
    path = _write_config(tmp_path, {"mode": "listen", "rules": [], "top_domains": 5})
    cfg = load_config(parse_args("-c", path, "--top-domains", "50"))
    assert cfg.top_domains == 50


def test_top_domains_invalid_limit():
    with pytest.raises(ConfigError, match="invalid top_domains limit"):
        load_config(parse_args("--list-domains", "--top-domains", "0"))


# ---------------------------------------------------------------------------
# --no-arp-restore
# ---------------------------------------------------------------------------

def test_arp_restore_enabled_by_default():
    cfg = load_config(parse_args("-d", "example.com@10.0.2.4"))
    assert cfg.arp_restore is True


def test_no_arp_restore_flag():
    cfg = load_config(parse_args("-d", "example.com@10.0.2.4", "--no-arp-restore"))
    assert cfg.arp_restore is False


def test_arp_restore_from_file(tmp_path):
    path = _write_config(tmp_path, {"rules": ["example.com@10.0.2.4"], "arp_restore": False})
    assert load_config(parse_args("-c", path)).arp_restore is False
    path = _write_config(tmp_path, {"rules": ["example.com@10.0.2.4"], "arp_restore": True})
    assert load_config(parse_args("-c", path)).arp_restore is True


def test_no_arp_restore_cli_overrides_file(tmp_path):
    path = _write_config(tmp_path, {"rules": ["example.com@10.0.2.4"], "arp_restore": True})
    assert load_config(parse_args("-c", path, "--no-arp-restore")).arp_restore is False


# ---------------------------------------------------------------------------
# --pidfile
# ---------------------------------------------------------------------------

def test_pidfile_flag():
    cfg = load_config(parse_args("-d", "example.com@10.0.2.4", "--pidfile", "/run/spoofshifter.pid"))
    assert cfg.pidfile == "/run/spoofshifter.pid"


def test_pidfile_default_none():
    cfg = load_config(parse_args("-d", "example.com@10.0.2.4"))
    assert cfg.pidfile is None


def test_pidfile_from_file(tmp_path):
    path = _write_config(tmp_path, {"rules": ["example.com@10.0.2.4"], "pidfile": "/run/s.pid"})
    assert load_config(parse_args("-c", path)).pidfile == "/run/s.pid"


def test_pidfile_cli_overrides_file(tmp_path):
    path = _write_config(tmp_path, {"rules": ["example.com@10.0.2.4"], "pidfile": "/run/a.pid"})
    assert load_config(parse_args("-c", path, "--pidfile", "/run/b.pid")).pidfile == "/run/b.pid"


def test_pidfile_invalid_file_value(tmp_path):
    path = _write_config(tmp_path, {"rules": ["example.com@10.0.2.4"], "pidfile": 42})
    with pytest.raises(ConfigError, match="invalid pidfile"):
        load_config(parse_args("-c", path))


# ---------------------------------------------------------------------------
# --log-file
# ---------------------------------------------------------------------------

def test_log_file_flag():
    cfg = load_config(parse_args("-d", "example.com@10.0.2.4", "--log-file", "/var/log/s.log"))
    assert cfg.log_file == "/var/log/s.log"


def test_log_file_default_none():
    assert load_config(parse_args("-d", "example.com@10.0.2.4")).log_file is None


def test_log_file_from_file(tmp_path):
    path = _write_config(tmp_path, {"rules": ["example.com@10.0.2.4"], "log_file": "/var/log/s.log"})
    assert load_config(parse_args("-c", path)).log_file == "/var/log/s.log"


def test_log_file_cli_overrides_file(tmp_path):
    path = _write_config(tmp_path, {"rules": ["example.com@10.0.2.4"], "log_file": "/var/log/a.log"})
    assert load_config(parse_args("-c", path, "--log-file", "/var/log/b.log")).log_file == "/var/log/b.log"


def test_log_file_invalid_value(tmp_path):
    path = _write_config(tmp_path, {"rules": ["example.com@10.0.2.4"], "log_file": 42})
    with pytest.raises(ConfigError, match="invalid log_file"):
        load_config(parse_args("-c", path))


def test_top_domains_invalid_file_value(tmp_path):
    path = _write_config(tmp_path, {"mode": "listen", "rules": [], "top_domains": "many"})
    with pytest.raises(ConfigError, match="invalid top_domains value"):
        load_config(parse_args("-c", path))


def test_load_config_arp_spoof_cli():
    cfg = load_config(parse_args(
        "-d", "example.com@10.0.2.4",
        "--arp-spoof", "--target", "192.168.1.100",
        "--gateway", "192.168.1.1", "--iface", "eth0",
    ))
    assert cfg.arp is not None
    assert cfg.arp.target == "192.168.1.100"
    assert cfg.arp.gateway == "192.168.1.1"
    assert cfg.arp.interface == "eth0"
    assert cfg.arp.interval == 2.0


def test_load_config_arp_missing_fields():
    with pytest.raises(ConfigError, match="missing: target"):
        load_config(parse_args(
            "-d", "example.com@10.0.2.4",
            "--arp-spoof", "--gateway", "192.168.1.1", "--iface", "eth0",
        ))


def test_load_config_arp_bad_ip():
    with pytest.raises(ConfigError, match="invalid target IP"):
        load_config(parse_args(
            "-d", "example.com@10.0.2.4",
            "--arp-spoof", "--target", "999.1.1.1",
            "--gateway", "192.168.1.1", "--iface", "eth0",
        ))


def test_load_config_invalid_mode_from_file(tmp_path):
    path = _write_config(tmp_path, {"mode": "bogus", "rules": ["example.com@10.0.2.4"]})
    with pytest.raises(ConfigError, match="invalid mode"):
        load_config(parse_args("-c", path))


def test_load_config_invalid_queue():
    with pytest.raises(ConfigError, match="invalid queue"):
        load_config(parse_args("-d", "example.com@10.0.2.4", "--queue", "70000"))


def test_load_config_invalid_ttl():
    with pytest.raises(ConfigError, match="invalid ttl"):
        load_config(parse_args("-d", "example.com@10.0.2.4", "--ttl", "-5"))


# ---------------------------------------------------------------------------
# Config files
# ---------------------------------------------------------------------------

def _write_config(tmp_path, data):
    path = tmp_path / "config.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def test_load_config_from_file(tmp_path):
    path = _write_config(tmp_path, {
        "queue": 2,
        "mode": "mutate",
        "ttl": 60,
        "rules": [
            {"domain": "www.google.com", "ipv4": "10.0.2.4"},
            "example.com@10.0.2.5",
            {"domain": "ipv6.example.com", "ipv6": "fd00::1", "ttl": 10},
        ],
    })
    cfg = load_config(parse_args("-c", path))
    assert len(cfg.rules) == 3
    assert cfg.queue_num == 2
    assert cfg.mode == "mutate"
    assert cfg.ttl == 60
    assert cfg.rules[0].ipv4 == "10.0.2.4"
    assert cfg.rules[1].ipv4 == "10.0.2.5"
    assert cfg.rules[2].ipv6 == "fd00::1"
    assert cfg.rules[2].ttl == 10
    assert cfg.ipv6_rules is True  # auto-enabled because a rule has ipv6


def test_file_settings_can_disable_iptables(tmp_path):
    path = _write_config(tmp_path, {
        "manage_iptables": False,
        "rules": ["example.com@10.0.2.4"],
    })
    cfg = load_config(parse_args("-c", path))
    assert cfg.manage_iptables is False


def test_file_bypass_setting(tmp_path):
    path = _write_config(tmp_path, {
        "bypass": False,
        "rules": ["example.com@10.0.2.4"],
    })
    cfg = load_config(parse_args("-c", path))
    assert cfg.bypass is False


def test_cli_overrides_file(tmp_path):
    path = _write_config(tmp_path, {
        "queue": 2,
        "ttl": 100,
        "rules": ["example.com@10.0.2.4"],
    })
    cfg = load_config(parse_args("-c", path, "--queue", "9", "--ttl", "500"))
    assert cfg.queue_num == 9
    assert cfg.ttl == 500


def test_cli_domains_append_to_file_rules(tmp_path):
    path = _write_config(tmp_path, {"rules": ["one.com@10.0.2.4"]})
    cfg = load_config(parse_args("-c", path, "-d", "two.com@10.0.2.5"))
    domains = [r.domain for r in cfg.rules]
    assert domains == ["one.com", "two.com"]


def test_rules_deduplicated_by_domain(tmp_path):
    path = _write_config(tmp_path, {"rules": ["example.com@10.0.2.4"]})
    cfg = load_config(parse_args("-c", path, "-d", "EXAMPLE.COM@10.0.2.5"))
    assert len(cfg.rules) == 1
    assert cfg.rules[0].domain == "example.com"
    assert cfg.rules[0].ipv4 == "10.0.2.4"  # first rule wins


def test_arp_config_from_file(tmp_path):
    path = _write_config(tmp_path, {
        "rules": ["example.com@10.0.2.4"],
        "arp": {
            "enabled": True,
            "target": "192.168.1.100",
            "gateway": "192.168.1.1",
            "interface": "wlan0",
            "interval": 3,
        },
    })
    cfg = load_config(parse_args("-c", path))
    assert cfg.arp is not None
    assert cfg.arp.interface == "wlan0"
    assert cfg.arp.interval == 3.0


def test_config_file_missing(tmp_path):
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(parse_args("-c", str(tmp_path / "nope.json")))


def test_config_file_invalid_json(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ConfigError, match="invalid JSON"):
        load_config(parse_args("-c", str(path)))


def test_config_file_not_an_object(tmp_path):
    path = _write_config(tmp_path, [1, 2, 3])
    with pytest.raises(ConfigError, match="JSON object"):
        load_config(parse_args("-c", path))


def test_config_file_rule_without_address(tmp_path):
    path = _write_config(tmp_path, {"rules": [{"domain": "example.com"}]})
    with pytest.raises(ConfigError, match="needs at least one spoof address"):
        load_config(parse_args("-c", path))


def test_config_file_bad_rule_type(tmp_path):
    path = _write_config(tmp_path, {"rules": [42]})
    with pytest.raises(ConfigError, match="invalid rule entry"):
        load_config(parse_args("-c", path))
