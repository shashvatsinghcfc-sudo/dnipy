"""
load_balancer.py – Load Balancer (LB) thread.

Mirrors the C++ class declared in include/load_balancer.h and implemented in
src/dpi_mt.cpp.

Each LB thread:
  1. Pops a Packet from its own input TSQueue.
  2. Hashes the packet's 5-tuple to select a Fast Path.
  3. Pushes the packet to that Fast Path's input queue.

Consistent hashing ensures that all packets of the same 5-tuple always go
to the same Fast Path, preserving flow-state correctness.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import List, Optional

from dpi_types import Packet
from thread_safe_queue import TSQueue
from fast_path import FastPath


# ---------------------------------------------------------------------------
# Stats dataclass
# ---------------------------------------------------------------------------

@dataclass
class LoadBalancerStats:
    dispatched: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def increment(self) -> None:
        with self.lock:
            self.dispatched += 1


# ---------------------------------------------------------------------------
# LoadBalancer  (mirrors C++ class LoadBalancer)
# ---------------------------------------------------------------------------

class LoadBalancer:
    """
    Distribute packets across a pool of Fast Path threads.

    Parameters
    ----------
    lb_id      : integer identifier.
    fast_paths : list of FastPath instances this LB distributes work to.
    queue_size : capacity of this LB's input queue.
    """

    def __init__(
        self,
        lb_id:       int,
        fast_paths:  List[FastPath],
        queue_size:  int = 1000,
    ) -> None:
        self.lb_id       = lb_id
        self._fps        = fast_paths
        self._num_fps    = len(fast_paths)
        self._queue: TSQueue[Packet] = TSQueue(maxsize=queue_size)
        self._stats      = LoadBalancerStats()
        self._thread:    Optional[threading.Thread] = None
        self._running    = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def queue(self) -> TSQueue:
        return self._queue

    @property
    def stats(self) -> LoadBalancerStats:
        return self._stats

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(
            target=self._run,
            name=f"LoadBalancer-{self.lb_id}",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        self._queue.shutdown()

    def join(self) -> None:
        if self._thread:
            self._thread.join()

    # ------------------------------------------------------------------
    # Thread body  (mirrors C++ LoadBalancer::run())
    # ------------------------------------------------------------------

    def _run(self) -> None:
        """
        Main loop::

            while running:
                pkt = input_queue.pop()
                fp_idx = hash(pkt.tuple) % num_fps
                fps[fp_idx].queue.push(pkt)
                stats.dispatched++
        """
        while self._running:
            pkt = self._queue.pop()
            if pkt is None:
                continue

            fp_idx = self._select_fp(pkt)
            self._fps[fp_idx].queue.push(pkt)
            self._stats.increment()

        # Drain remaining packets after shutdown
        while not self._queue.empty():
            pkt = self._queue.try_pop()
            if pkt is None:
                break
            fp_idx = self._select_fp(pkt)
            self._fps[fp_idx].queue.push(pkt)
            self._stats.increment()

    # ------------------------------------------------------------------
    # Consistent hashing  (mirrors C++ hash(pkt.tuple) % num_fps_)
    # ------------------------------------------------------------------

    def _select_fp(self, pkt: Packet) -> int:
        """
        Hash the packet's 5-tuple to an FP index.

        Python's built-in hash() on a frozen dataclass is deterministic
        within a single process run, which is sufficient here.
        """
        if pkt.tuple is not None:
            return hash(pkt.tuple) % self._num_fps
        # No tuple (non-TCP/UDP) – round-robin using packet address
        return id(pkt) % self._num_fps
