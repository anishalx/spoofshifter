import configparser
from pathlib import Path

import pytest

SERVICE_FILE = Path(__file__).resolve().parent.parent / "systemd" / "spoofshifter.service"


@pytest.fixture(scope="module")
def service_config():
    assert SERVICE_FILE.exists(), f"missing {SERVICE_FILE}"
    parser = configparser.ConfigParser()
    parsed = parser.read(SERVICE_FILE, encoding="utf-8")
    assert parsed, f"could not parse {SERVICE_FILE}"
    return parser


def test_has_required_sections(service_config):
    assert set(service_config.sections()) >= {"Unit", "Service", "Install"}


def test_unit_waits_for_network(service_config):
    assert service_config["Unit"]["After"] == "network-online.target"
    assert service_config["Unit"]["Wants"] == "network-online.target"


def test_service_runs_foreground_with_config(service_config):
    exec_start = service_config["Service"]["ExecStart"]
    assert "spoofshifter.py" in exec_start
    assert "-c" in exec_start  # driven by a config file
    assert service_config["Service"]["Type"] == "simple"


def test_service_runs_as_root(service_config):
    # NFQUEUE capture, iptables and ARP spoofing all require root.
    assert service_config["Service"]["User"] == "root"
    assert service_config["Service"]["Group"] == "root"


def test_restart_policy_and_stop_timeout(service_config):
    assert service_config["Service"]["Restart"] == "on-failure"
    assert service_config["Service"]["RestartSec"] == "3"
    assert service_config["Service"]["TimeoutStopSec"] == "10"  # room for cleanup


def test_installed_for_multi_user_target(service_config):
    assert service_config["Install"]["WantedBy"] == "multi-user.target"
