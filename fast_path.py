"""
fast_path.py – Fast Path (FP) processing thread.

Mirrors the C++ class declared in include/fast_path.h and implemented in
the multi-threaded version src/dpi_mt.cpp.

Each FP thread:
  1. Pops a Packet from its own input TSQueue.
  2. Looks up (or creates) the flow in its private ConnectionTracker.
  3. Classifies the flow: extracts SNI / HTTP Host, maps to AppType.
  4. Checks blocking rules.
  5. Forwards to the output queue, or increments the drop counter.

Consistent hashing (done by the LoadBalancer) guarantees that all packets
of a given 5-tuple always arrive at the same FP, so the ConnectionTracker
needs no locks.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Optional

from dpi_types import AppType, Packet, Flow, sni_to_app_type
from thread_safe_queue import TSQueue
from connection_tracker import ConnectionTracker
from rule_manager import RuleManager
from sni_extractor import SNIExtractor, HTTPHostExtractor


HTTPS_PORT = 443
HTTP_PORT  = 80
DNS_PORT   = 53

# Minimum payload bytes needed for a TLS Client Hello attempt
TLS_MIN_PAYLOAD = 6


# ---------------------------------------------------------------------------
# Stats dataclass (mirrors the C++ atomic counters on FastPath)
# ---------------------------------------------------------------------------

@dataclass
class FastPathStats:
    processed: int = 0
    forwarded: int = 0
    dropped:   int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def increment_processed(self) -> None:
        with self.lock:
            self.processed += 1

    def increment_forwarded(self) -> None:
        with self.lock:
            self.forwarded += 1

    def increment_dropped(self) -> None:
        with self.lock:
            self.dropped += 1


# ---------------------------------------------------------------------------
# FastPath  (mirrors C++ class FastPath)
# ---------------------------------------------------------------------------

class FastPath:
    """
    A single DPI processing thread.

    Parameters
    ----------
    fp_id      : integer identifier (for logging / stats).
    rules      : shared RuleManager (read-only from FP's perspective).
    output_q   : shared TSQueue where forwarded packets are pushed.
    queue_size : capacity of this FP's input queue.
    """

    def __init__(
        self,
        fp_id:      int,
        rules:      RuleManager,
        output_q:   TSQueue,
        queue_size: int = 1000,
    ) -> None:
        self.fp_id    = fp_id
        self._rules   = rules
        self._output  = output_q
        self._queue: TSQueue[Packet] = TSQueue(maxsize=queue_size)
        self._tracker = ConnectionTracker()
        self._stats   = FastPathStats()
        self._thread: Optional[threading.Thread] = None
        self._running = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def queue(self) -> TSQueue:
        return self._queue

    @property
    def stats(self) -> FastPathStats:
        return self._stats

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(
            target=self._run,
            name=f"FastPath-{self.fp_id}",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        self._queue.shutdown()

    def join(self) -> None:
        if self._thread:
            self._thread.join()

    def flow_count(self) -> int:
        return self._tracker.flow_count()

    def all_flows(self):
        return self._tracker.all_flows()

    # ------------------------------------------------------------------
    # Thread body  (mirrors C++ FastPath::run())
    # ------------------------------------------------------------------

    def _run(self) -> None:
        """
        Main loop:

          while running:
              pkt = input_queue.pop()          # block until packet arrives
              flow = flows[pkt.tuple]           # get/create flow
              classify_flow(pkt, flow)          # DPI: SNI / Host extraction
              if rules.is_blocked(...):
                  stats.dropped++
              else:
                  output_queue.push(pkt)
                  stats.forwarded++
        """
        while self._running:
            pkt = self._queue.pop()
            if pkt is None:
                continue

            self._stats.increment_processed()

            if pkt.tuple is None:
                # No transport-layer info – just forward
                self._forward(pkt)
                continue

            # --- Flow lookup / creation ------------------------------------
            flow = self._tracker.get_or_create(pkt.tuple, pkt.parsed.timestamp)
            flow.packet_count += 1
            flow.byte_count   += pkt.parsed.ip_length

            # --- Classification (DPI) --------------------------------------
            if not flow.blocked:
                self._classify(pkt, flow)

            # --- Blocking check --------------------------------------------
            if flow.blocked or self._rules.is_blocked(
                pkt.tuple.src_ip, flow.app_type, flow.sni
            ):
                flow.blocked = True
                self._stats.increment_dropped()
            else:
                self._forward(pkt)

        # Drain any remaining packets after shutdown signal
        while not self._queue.empty():
            pkt = self._queue.try_pop()
            if pkt is None:
                break
            self._stats.increment_processed()
            # (drop remaining packets on shutdown)

    # ------------------------------------------------------------------
    # Classification logic  (mirrors C++ FastPath::classifyFlow)
    # ------------------------------------------------------------------

    def _classify(self, pkt: Packet, flow: Flow) -> None:
        """
        Inspect the packet payload to identify the application.

        Priority:
          1. HTTPS (port 443) → try TLS SNI extraction
          2. HTTP  (port 80)  → try HTTP Host header extraction
          3. DNS   (port 53)  → mark as DNS
          4. Fallback: HTTPS label for port-443 flows with no SNI yet
        """
        payload = pkt.parsed.payload
        dst_port = pkt.parsed.dst_port

        # ---- TLS / HTTPS ---------------------------------------------------
        if dst_port == HTTPS_PORT and len(payload) >= TLS_MIN_PAYLOAD:
            if flow.sni == "":   # only parse until we have SNI
                sni = SNIExtractor.extract(payload)
                if sni:
                    flow.sni      = sni
                    flow.app_type = sni_to_app_type(sni)
                    return
            # Port 443 but no SNI yet (e.g. SYN packet) → mark as HTTPS
            if flow.app_type == AppType.UNKNOWN:
                flow.app_type = AppType.HTTPS
            return

        # ---- HTTP ----------------------------------------------------------
        if dst_port == HTTP_PORT and len(payload) > 0:
            if flow.host == "":
                host = HTTPHostExtractor.extract(payload)
                if host:
                    flow.host     = host
                    flow.sni      = host   # treat Host as the flow's "sni" for rule matching
                    flow.app_type = sni_to_app_type(host)
                    return
            if flow.app_type == AppType.UNKNOWN:
                flow.app_type = AppType.HTTP
            return

        # ---- DNS -----------------------------------------------------------
        if dst_port == DNS_PORT:
            if flow.app_type == AppType.UNKNOWN:
                flow.app_type = AppType.DNS
            return

    # ------------------------------------------------------------------
    # Forwarding
    # ------------------------------------------------------------------

    def _forward(self, pkt: Packet) -> None:
        self._output.push(pkt)
        self._stats.increment_forwarded()
