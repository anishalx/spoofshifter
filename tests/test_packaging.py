try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"


@pytest.fixture(scope="module")
def pyproject():
    with open(PYPROJECT, "rb") as fh:
        return tomllib.load(fh)


def test_has_build_system(pyproject):
    assert pyproject["build-system"]["build-backend"] == "setuptools.build_meta"
    assert any(req.startswith("setuptools") for req in pyproject["build-system"]["requires"])


def test_console_script_entry_point(pyproject):
    scripts = pyproject["project"]["scripts"]
    assert scripts["spoofshifter"] == "spoofshifter.cli:main"


def test_entry_point_is_callable_and_returns_exit_code():
    from spoofshifter import cli
    assert callable(cli.main)
    # Console scripts wrap the entry point as sys.exit(main()); main() must
    # return an int exit code (2 here: usage error, no rules given).
    assert isinstance(cli.main([]), int)


def test_runtime_dependencies(pyproject):
    deps = pyproject["project"]["dependencies"]
    assert "scapy>=2.7" in deps
    # netfilterqueue is Linux-only and must carry the platform marker so the
    # package installs (and tests run) anywhere.
    assert any("netfilterqueue" in dep and "sys_platform == 'linux'" in dep for dep in deps)


def test_only_the_package_is_shipped(pyproject):
    setup_tools = pyproject["tool"]["setuptools"]
    assert setup_tools["packages"] == ["spoofshifter"]
    # The root spoofshifter.py wrapper must not be packaged as a module
    # (it would shadow the package on import).
    assert setup_tools["py-modules"] == []


def test_dev_extra_includes_pytest(pyproject):
    assert "pytest>=7" in pyproject["project"]["optional-dependencies"]["dev"]
