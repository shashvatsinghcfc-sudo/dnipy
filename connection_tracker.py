"""
connection_tracker.py – Per-Fast-Path flow table (connection tracker).

Mirrors the C++ ConnectionTracker class declared in
include/connection_tracker.h.

Each Fast Path thread owns exactly one ConnectionTracker.  Because
consistent hashing guarantees that all packets of a given 5-tuple always
reach the same Fast Path, NO locking is needed here – only one thread
ever touches each flow table.  This mirrors the design decision described
in the README.
"""

from __future__ import annotations

from typing import Dict, Optional

from dpi_types import FiveTuple, Flow, AppType


class ConnectionTracker:
    """
    Stateful flow table: FiveTuple → Flow.

    The C++ equivalent uses ``std::unordered_map<FiveTuple, Flow>``.
    Python's built-in dict provides the same O(1) amortised lookup with
    FiveTuple as a frozen dataclass (hashable).
    """

    def __init__(self) -> None:
        self._flows: Dict[FiveTuple, Flow] = {}

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    def get_or_create(self, key: FiveTuple, timestamp: float = 0.0) -> Flow:
        """
        Return the existing Flow for *key*, or create a new one.

        Mirrors the C++ pattern::

            Flow& flow = flows_[pkt.tuple];

        which default-constructs a Flow if the key is absent.
        """
        if key not in self._flows:
            flow = Flow(tuple=key, first_seen=timestamp, last_seen=timestamp)
            self._flows[key] = flow
        else:
            self._flows[key].last_seen = timestamp
        return self._flows[key]

    def get(self, key: FiveTuple) -> Optional[Flow]:
        """Return the Flow for *key*, or None if not tracked."""
        return self._flows.get(key)

    def remove(self, key: FiveTuple) -> None:
        """Remove a flow (e.g., after FIN/RST)."""
        self._flows.pop(key, None)

    # ------------------------------------------------------------------
    # Iteration / stats
    # ------------------------------------------------------------------

    def all_flows(self):
        """Iterate over all (FiveTuple, Flow) pairs."""
        return self._flows.items()

    def flow_count(self) -> int:
        return len(self._flows)
