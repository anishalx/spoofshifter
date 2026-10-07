"""PID file management for headless/service use.

The pidfile is claimed after startup checks pass and removed on shutdown, so
supervisors (systemd, cron wrappers, custom scripts) can tell whether an
instance is running and kill it by PID.

Safety rules:
* a live second instance is rejected, not silently overwritten;
* a stale pidfile (dead PID) is replaced;
* only the process that wrote the file removes it - a pidfile belonging to a
  different process is never touched.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

log = logging.getLogger("spoofshifter")


class PidfileError(Exception):
    """Raised when a pidfile cannot be claimed (e.g. another instance runs)"""


if os.name == "nt":  # pragma: no cover - exercised on Windows CI/dev boxes
    import ctypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    _kernel32.OpenProcess.restype = ctypes.c_void_p
    _kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    _PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

    def _probe(pid: int) -> None:
        """Check that a pid exists without signalling it.

        ``os.kill(pid, 0)`` must not be used on Windows: signal 0 is the
        value of ``CTRL_C_EVENT``, so it would inject a Ctrl+C into the
        caller's console (and still fail for processes without one).
        """
        handle = _kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if handle:
            _kernel32.CloseHandle(handle)
            return
        err = ctypes.get_last_error()
        if err == 5:  # ERROR_ACCESS_DENIED -> exists, owned by someone else
            raise PermissionError(f"process {pid} exists but is not ours")
        # ERROR_INVALID_PARAMETER (87) and friends -> no such process
        raise ProcessLookupError(f"no such process: {pid}")

else:

    def _probe(pid: int) -> None:
        os.kill(pid, 0)


def pid_alive(pid: int) -> bool:
    """Best-effort check whether a process with this pid exists."""
    if pid <= 0:
        return False
    try:
        _probe(pid)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists, owned by another user
    except OSError:
        return False
    return True


def write_pidfile(path: str) -> None:
    """Claim a pidfile, failing if another live instance holds it."""
    try:
        existing = _read_pid(path)
    except OSError:
        existing = None
    if existing is not None and pid_alive(existing):
        raise PidfileError(
            f"another instance is already running (pid {existing}, pidfile {path})"
        )
    if existing is not None:
        log.info("[+] removing stale pidfile %s (pid %d is gone)", path, existing)
        try:
            os.remove(path)
        except OSError:
            pass
    try:
        with open(path, "w", encoding="ascii") as fh:
            fh.write(str(os.getpid()))
    except OSError as exc:
        raise PidfileError(f"cannot write pidfile {path}: {exc}") from exc
    log.debug("wrote pidfile %s (pid %d)", path, os.getpid())


def remove_pidfile(path: Optional[str]) -> None:
    """Remove the pidfile, but only if it still holds our own pid."""
    if not path:
        return
    try:
        current = _read_pid(path)
    except OSError:
        return  # already gone - nothing to do
    if current != os.getpid():
        log.warning(
            "pidfile %s holds pid %r, not ours (%d); leaving it alone",
            path, current, os.getpid(),
        )
        return
    try:
        os.remove(path)
        log.debug("removed pidfile %s", path)
    except OSError:
        pass


def _read_pid(path: str) -> Optional[int]:
    with open(path, "r", encoding="ascii") as fh:
        content = fh.read().strip()
    try:
        return int(content)
    except ValueError:
        return None
