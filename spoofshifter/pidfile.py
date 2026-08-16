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
    """Raised when a pidfile cannot be claimed (e.g. another instance runs)."""


def pid_alive(pid: int) -> bool:
    """Best-effort check whether a process with this pid exists."""
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
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
