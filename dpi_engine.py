"""
dpi_engine.py – Multi-threaded DPI Engine orchestrator.

Mirrors the C++ multi-threaded version in src/dpi_mt.cpp.

Architecture (from README §6):

    Reader Thread
         │
         │  hash(5-tuple) % num_lbs
         ▼
    ┌─────────────────┐     ┌─────────────────┐
    │  LB-0 Thread    │     │  LB-1 Thread    │  ...
    └────────┬────────┘     └────────┬────────┘
             │ hash % num_fps          │
    ┌────────▼────┐ ┌────────▼────┐  ...
    │  FP-0 Thread│ │  FP-1 Thread│
    └─────┬───────┘ └─────┬───────┘
          │               │
          └───────┬───────┘
                  │ output_queue
                  ▼
          Output Writer Thread

Usage (command-line – see __main__ block at the bottom):

    python dpi_engine.py input.pcap output.pcap \
        [--block-app YouTube] \
        [--block-ip 192.168.1.50] \
        [--block-domain facebook] \
        [--lbs 2] [--fps 2]
"""

from __future__ import annotations

import sys
import threading
import time
from collections import defaultdict
from typing import Dict, List, Optional

from dpi_types import AppType, Flow, Packet, ParsedPacket, app_type_to_str
from pcap_reader import PcapReader, PcapWriter
from packet_parser import PacketParser
from rule_manager import RuleManager
from load_balancer import LoadBalancer
from fast_path import FastPath
from thread_safe_queue import TSQueue


# ---------------------------------------------------------------------------
# DPIEngine
# ---------------------------------------------------------------------------

class DPIEngine:
    """
    Orchestrates the multi-threaded DPI pipeline.

    Parameters
    ----------
    input_path  : path to input .pcap file
    output_path : path for the filtered output .pcap file
    num_lbs     : number of Load Balancer threads (default 2)
    num_fps     : number of Fast Path threads *per LB* (default 2)
    """

    def __init__(
        self,
        input_path:  str,
        output_path: str,
        num_lbs:     int = 2,
        num_fps:     int = 2,
    ) -> None:
        self.input_path  = input_path
        self.output_path = output_path
        self.num_lbs     = num_lbs
        self.num_fps_per_lb = num_fps

        self._rules      = RuleManager()
        self._output_q: TSQueue[Packet] = TSQueue(maxsize=5000)
        self._lbs:  List[LoadBalancer] = []
        self._fps:  List[FastPath]     = []

        # Global counters (updated by output writer)
        self._total_packets  = 0
        self._total_bytes    = 0
        self._forwarded      = 0
        self._dropped        = 0
        self._tcp_count      = 0
        self._udp_count      = 0

    # ------------------------------------------------------------------
    # Rule configuration  (pass-through to RuleManager)
    # ------------------------------------------------------------------

    def block_app(self, app_name: str) -> None:
        self._rules.add_blocked_app(app_name)

    def block_ip(self, ip_str: str) -> None:
        self._rules.add_blocked_ip(ip_str)

    def block_domain(self, domain: str) -> None:
        self._rules.add_blocked_domain(domain)

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def run(self) -> None:
        self._print_banner()
        self._start_workers()
        self._reader_thread()
        self._drain_and_stop()
        self._print_report()

    # ------------------------------------------------------------------
    # Banner
    # ------------------------------------------------------------------

    def _print_banner(self) -> None:
        total_fps = self.num_lbs * self.num_fps_per_lb
        print("╔" + "═" * 62 + "╗")
        print("║" + "    DPI ENGINE v2.0 (Multi-threaded / Python)".center(62) + "║")
        print("╠" + "═" * 62 + "╣")
        print(f"║  Load Balancers: {self.num_lbs:>2}   "
              f"FPs per LB: {self.num_fps_per_lb:>2}   "
              f"Total FPs: {total_fps:>3}".ljust(62) + "║")
        print("╚" + "═" * 62 + "╝")
        print()

    # ------------------------------------------------------------------
    # Worker thread lifecycle
    # ------------------------------------------------------------------

    def _start_workers(self) -> None:
        """
        Create and start all LB and FP threads.

        Layout mirrors the C++ constructor in dpi_mt.cpp:
          - Create num_fps Fast Path threads (shared across all LBs).
          - Create num_lbs Load Balancer threads, each pointing to all FPs.
        """
        # Create all Fast Path threads
        for i in range(self.num_lbs * self.num_fps_per_lb):
            fp = FastPath(
                fp_id    = i,
                rules    = self._rules,
                output_q = self._output_q,
                queue_size=1000,
            )
            self._fps.append(fp)
            fp.start()

        # Create Load Balancer threads; each LB owns a slice of the FP pool
        for i in range(self.num_lbs):
            fp_slice = self._fps[i * self.num_fps_per_lb : (i + 1) * self.num_fps_per_lb]
            lb = LoadBalancer(lb_id=i, fast_paths=fp_slice, queue_size=1000)
            self._lbs.append(lb)
            lb.start()

        # Start output writer thread
        self._writer_thread_obj = threading.Thread(
            target=self._output_writer,
            name="OutputWriter",
            daemon=True,
        )
        self._writer_done = threading.Event()
        self._writer_thread_obj.start()

    def _drain_and_stop(self) -> None:
        """Stop all threads in the correct order and wait for completion."""
        # Wait a tick to let LBs and FPs drain their queues
        time.sleep(0.2)

        # Stop LBs first
        for lb in self._lbs:
            lb.stop()
        for lb in self._lbs:
            lb.join()

        # Then stop FPs
        for fp in self._fps:
            fp.stop()
        for fp in self._fps:
            fp.join()

        # Signal output writer that all packets have been processed
        self._output_q.shutdown()
        self._writer_done.wait(timeout=10)

    # ------------------------------------------------------------------
    # Reader thread  (mirrors C++ main thread reading loop)
    # ------------------------------------------------------------------

    def _reader_thread(self) -> None:
        """
        Read all packets from the input PCAP, parse them, and dispatch
        each to the appropriate Load Balancer via consistent hashing.

        Mirrors::

            while (reader.readNextPacket(raw)):
                pkt = createPacket(raw)
                lb_idx = hash(pkt.tuple) % num_lbs
                lbs_[lb_idx]->queue().push(pkt)
        """
        print(f"[Reader] Processing packets from {self.input_path} …")
        with PcapReader(self.input_path) as reader:
            for raw in reader:
                parsed = ParsedPacket()
                if not PacketParser.parse(raw, parsed):
                    continue   # skip non-IPv4 / malformed packets

                pkt = Packet(
                    raw    = raw,
                    parsed = parsed,
                    tuple  = PacketParser.make_five_tuple(parsed),
                )

                # Counters
                self._total_packets += 1
                self._total_bytes   += parsed.ip_length
                if parsed.has_tcp:
                    self._tcp_count += 1
                elif parsed.has_udp:
                    self._udp_count += 1

                # Dispatch to a Load Balancer
                lb_idx = (hash(pkt.tuple) if pkt.tuple else id(pkt)) % self.num_lbs
                self._lbs[lb_idx].queue.push(pkt)

        print(f"[Reader] Done reading {self._total_packets} packets.")

    # ------------------------------------------------------------------
    # Output writer thread  (mirrors C++ output writer thread)
    # ------------------------------------------------------------------

    def _output_writer(self) -> None:
        """
        Pop forwarded packets from the shared output queue and write them
        to the output PCAP file.

        Mirrors the C++ output thread::

            while (running_ || output_queue.size() > 0):
                pkt = output_queue.pop()
                output_file.write(pkt)
        """
        with PcapWriter(self.output_path) as writer:
            while True:
                pkt = self._output_q.pop()
                if pkt is None:
                    if self._output_q.empty():
                        break
                    continue
                writer.write_packet(pkt.raw)
                self._forwarded += 1

        self._writer_done.set()

    # ------------------------------------------------------------------
    # Report  (mirrors C++ final report in dpi_mt.cpp)
    # ------------------------------------------------------------------

    def _print_report(self) -> None:
        """Collect stats from all FP threads and print the final report."""

        # Aggregate drop count from FP stats (forwarded already tracked by writer)
        total_dropped = sum(fp.stats.dropped for fp in self._fps)
        self._dropped = total_dropped

        # Collect all flows for app breakdown and SNI list
        app_counts: Dict[AppType, int] = defaultdict(int)
        sni_map:    Dict[str, AppType] = {}

        for fp in self._fps:
            for _key, flow in fp.all_flows():
                app_counts[flow.app_type] += flow.packet_count
                if flow.sni:
                    sni_map[flow.sni] = flow.app_type

        total_processed = self._forwarded + self._dropped

        w = 64
        sep = "═" * w

        print()
        print("╔" + sep + "╗")
        print("║" + "PROCESSING REPORT".center(w) + "║")
        print("╠" + sep + "╣")
        print(f"║  Total Packets:  {self._total_packets:>10}".ljust(w + 1) + "║")
        print(f"║  Total Bytes:    {self._total_bytes:>10}".ljust(w + 1) + "║")
        print(f"║  TCP Packets:    {self._tcp_count:>10}".ljust(w + 1) + "║")
        print(f"║  UDP Packets:    {self._udp_count:>10}".ljust(w + 1) + "║")
        print("╠" + sep + "╣")
        print(f"║  Forwarded:      {self._forwarded:>10}".ljust(w + 1) + "║")
        print(f"║  Dropped:        {self._dropped:>10}".ljust(w + 1) + "║")
        print("╠" + sep + "╣")
        print("║" + "THREAD STATISTICS".center(w) + "║")
        for i, lb in enumerate(self._lbs):
            print(f"║    LB{i} dispatched:   {lb.stats.dispatched:>8}".ljust(w + 1) + "║")
        for i, fp in enumerate(self._fps):
            print(f"║    FP{i} processed:    {fp.stats.processed:>8}".ljust(w + 1) + "║")
        print("╠" + sep + "╣")
        print("║" + "APPLICATION BREAKDOWN".center(w) + "║")
        print("╠" + sep + "╣")

        total_flow_pkts = sum(app_counts.values()) or 1
        sorted_apps = sorted(app_counts.items(), key=lambda x: x[1], reverse=True)
        for app, count in sorted_apps:
            pct  = count / total_flow_pkts * 100
            bar  = "#" * max(1, int(pct / 5))
            name = app_type_to_str(app)
            blocked_str = " (BLOCKED)" if app in self._get_blocked_apps() else ""
            line = f"  {name:<16} {count:>5}  {pct:5.1f}%  {bar}{blocked_str}"
            print(f"║{line}".ljust(w + 1) + "║")

        print("╠" + sep + "╣")
        print("║" + "DETECTED DOMAINS / SNIs".center(w) + "║")
        print("╠" + sep + "╣")
        for sni, app in sorted(sni_map.items()):
            line = f"  {sni}  →  {app_type_to_str(app)}"
            print(f"║{line}".ljust(w + 1) + "║")
        print("╚" + sep + "╝")

    def _get_blocked_apps(self):
        return self._rules._blocked_apps


# ---------------------------------------------------------------------------
# CLI entry point  (mirrors dpi_mt.cpp's main() argument parsing)
# ---------------------------------------------------------------------------

def _parse_args(argv: List[str]):
    """Minimal argument parser matching the C++ CLI."""
    import argparse
    p = argparse.ArgumentParser(
        description="Deep Packet Inspection Engine (Python port of dpi_mt.cpp)"
    )
    p.add_argument("input",  help="Input PCAP file")
    p.add_argument("output", help="Output PCAP file (forwarded packets)")
    p.add_argument("--block-app",    action="append", default=[], metavar="APP",
                   help="Block application (e.g. YouTube, TikTok)")
    p.add_argument("--block-ip",     action="append", default=[], metavar="IP",
                   help="Block source IP address")
    p.add_argument("--block-domain", action="append", default=[], metavar="DOMAIN",
                   help="Block domain substring (e.g. facebook)")
    p.add_argument("--lbs",  type=int, default=2, metavar="N",
                   help="Number of Load Balancer threads (default 2)")
    p.add_argument("--fps",  type=int, default=2, metavar="N",
                   help="Number of Fast Path threads per LB (default 2)")
    return p.parse_args(argv)


if __name__ == "__main__":
    args = _parse_args(sys.argv[1:])

    engine = DPIEngine(
        input_path  = args.input,
        output_path = args.output,
        num_lbs     = args.lbs,
        num_fps     = args.fps,
    )

    for app in args.block_app:
        engine.block_app(app)
    for ip in args.block_ip:
        engine.block_ip(ip)
    for dom in args.block_domain:
        engine.block_domain(dom)

    engine.run()
