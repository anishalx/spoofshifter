"""Runtime glue: binds a DnsSpoofEngine to a NetfilterQueue.

``netfilterqueue`` is imported lazily (it is Linux-only) so the rest of the
package - and the entire test suite - works on any platform.  The runner never
raises out of the packet callback: a broken packet is accepted/dropped and the
loop keeps running.
"""

from __future__ import annotations

import logging
from typing import Optional

from .core import DnsSpoofEngine

log = logging.getLogger("spoofshifter")


class RunnerError(Exception):
    """Raised when the packet queue cannot be set up."""


def _safe(action) -> None:
    try:
        action()
    except Exception:
        log.debug("packet action failed", exc_info=True)


class DnsSpoofRunner:
    """Binds an engine to a NetfilterQueue and owns its lifecycle."""

    def __init__(self, engine: DnsSpoofEngine, queue_num: int = 0) -> None:
        self.engine = engine
        self.queue_num = queue_num
        self._queue = None

    # -- NetfilterQueue glue ------------------------------------------------
    def _new_queue(self):
        try:
            import netfilterqueue
        except ImportError as exc:
            raise RunnerError(
                "netfilterqueue is not installed (Linux only): "
                "pip install netfilterqueue"
            ) from exc
        return netfilterqueue.NetfilterQueue()

    def start(self) -> None:
        self._queue = self._new_queue()
        self._queue.bind(self.queue_num, self._on_packet)
        log.info("[+] bound to NFQUEUE %d", self.queue_num)

    def stop(self) -> None:
        if self._queue is not None:
            try:
                self._queue.unbind()
            except Exception:
                log.debug("queue unbind failed", exc_info=True)
            self._queue = None

    # -- packet callback ----------------------------------------------------
    def _on_packet(self, packet) -> None:
        try:
            payload = packet.get_payload()
        except Exception:
            self.engine.stats.errors += 1
            _safe(packet.accept)
            return
        out = self.engine.process_payload(payload)
        if out is None:
            _safe(packet.drop)
            return
        if out is not payload:
            try:
                packet.set_payload(out)
            except Exception:
                _safe(packet.accept)
                return
        _safe(packet.accept)

    def run_forever(self) -> None:
        if self._queue is None:
            raise RunnerError("call start() before run_forever()")
        try:
            self._queue.run()
        except KeyboardInterrupt:
            log.info("[+] interrupted, shutting down")
