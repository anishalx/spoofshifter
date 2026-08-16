import os

import pytest

from spoofshifter import pidfile
from spoofshifter.pidfile import PidfileError, pid_alive, remove_pidfile, write_pidfile


# ---------------------------------------------------------------------------
# pid_alive
# ---------------------------------------------------------------------------

def test_pid_alive_detects_live_process():
    assert pid_alive(os.getpid())  # this test process is alive
    assert not pid_alive(99999999)  # no such pid in practice


def test_pid_alive_handles_os_errors(monkeypatch):
    def fake_kill(pid, sig):
        if pid == 1:
            raise ProcessLookupError()
        if pid == 2:
            raise PermissionError()
        if pid == 3:
            raise OSError("unexpected")
        return None

    monkeypatch.setattr(pidfile.os, "kill", fake_kill)
    assert not pid_alive(1)   # no such process
    assert pid_alive(2)       # exists but owned by another user
    assert not pid_alive(3)   # unexpected error -> assume gone
    assert not pid_alive(0)
    assert not pid_alive(-5)


# ---------------------------------------------------------------------------
# write_pidfile
# ---------------------------------------------------------------------------

def test_write_pidfile_creates_file(tmp_path):
    path = tmp_path / "spoofshifter.pid"
    write_pidfile(str(path))
    assert path.read_text(encoding="ascii").strip() == str(os.getpid())


def test_write_pidfile_overwrites_stale(tmp_path, monkeypatch):
    path = tmp_path / "spoofshifter.pid"
    path.write_text("99999999", encoding="ascii")
    monkeypatch.setattr(pidfile, "pid_alive", lambda pid: False)
    write_pidfile(str(path))
    assert path.read_text(encoding="ascii").strip() == str(os.getpid())


def test_write_pidfile_rejects_live_instance(tmp_path, monkeypatch):
    path = tmp_path / "spoofshifter.pid"
    path.write_text("1234", encoding="ascii")
    monkeypatch.setattr(pidfile, "pid_alive", lambda pid: True)
    with pytest.raises(PidfileError, match="already running"):
        write_pidfile(str(path))
    # the foreign pidfile must be left untouched
    assert path.read_text(encoding="ascii").strip() == "1234"


def test_write_pidfile_replaces_garbage(tmp_path):
    path = tmp_path / "spoofshifter.pid"
    path.write_text("not a pid", encoding="ascii")
    write_pidfile(str(path))
    assert path.read_text(encoding="ascii").strip() == str(os.getpid())


def test_write_pidfile_unwritable(tmp_path):
    with pytest.raises(PidfileError, match="cannot write pidfile"):
        write_pidfile(str(tmp_path))  # a directory is not writable as a file


# ---------------------------------------------------------------------------
# remove_pidfile
# ---------------------------------------------------------------------------

def test_remove_pidfile_removes_own(tmp_path):
    path = tmp_path / "spoofshifter.pid"
    write_pidfile(str(path))
    remove_pidfile(str(path))
    assert not path.exists()


def test_remove_pidfile_leaves_foreign_pidfile(tmp_path):
    path = tmp_path / "spoofshifter.pid"
    path.write_text("98765", encoding="ascii")
    remove_pidfile(str(path))
    assert path.exists()
    assert path.read_text(encoding="ascii").strip() == "98765"


def test_remove_pidfile_missing_is_noop(tmp_path):
    remove_pidfile(str(tmp_path / "nope.pid"))  # must not raise


def test_remove_pidfile_none_is_noop():
    remove_pidfile(None)  # must not raise
