"""
main_simple.py – Single-threaded DPI engine.

Mirrors the C++ simple version in src/main_working.cpp.

This file is the best starting point for understanding the code because
it follows the sequential "journey of a packet" described in README §5:

    Step 1:  Open PCAP file
    Step 2:  Read each packet
    Step 3:  Parse Ethernet / IP / TCP/UDP headers
    Step 4:  Create/look up 5-tuple flow
    Step 5:  Extract SNI (DPI)
    Step 6:  Check blocking rules
    Step 7:  Forward or drop
    Step 8:  Print report

Usage::

    python main_simple.py input.pcap output.pcap \
        [--block-app YouTube] \
        [--block-ip 192.168.1.50] \
        [--block-domain facebook]
"""

from __future__ import annotations

import sys
import argparse
from collections import defaultdict
from typing import Dict

from dpi_types import AppType, Flow, FiveTuple, ParsedPacket, app_type_to_str, sni_to_app_type
from pcap_reader import PcapReader, PcapWriter
from packet_parser import PacketParser
from rule_manager import RuleManager
from sni_extractor import SNIExtractor, HTTPHostExtractor


HTTPS_PORT = 443
HTTP_PORT  = 80
DNS_PORT   = 53


# ---------------------------------------------------------------------------
# Simple / single-threaded engine
# ---------------------------------------------------------------------------

def run(
    input_path:  str,
    output_path: str,
    rules:       RuleManager,
) -> None:
    """Process every packet in *input_path* and write forwarded ones to *output_path*."""

    # Flow table: FiveTuple → Flow
    flows: Dict[FiveTuple, Flow] = {}

    total_packets = 0
    total_bytes   = 0
    tcp_count     = 0
    udp_count     = 0
    forwarded     = 0
    dropped       = 0

    print(f"[Reader] Processing packets from {input_path} …")

    with PcapReader(input_path) as reader, PcapWriter(output_path) as writer:
        for raw in reader:

            # ---- Step 2: Read packet ---------------------------------------
            parsed = ParsedPacket()

            # ---- Step 3: Parse headers -------------------------------------
            if not PacketParser.parse(raw, parsed):
                continue   # skip non-IPv4 / malformed

            total_packets += 1
            total_bytes   += parsed.ip_length
            if parsed.has_tcp:
                tcp_count += 1
            elif parsed.has_udp:
                udp_count += 1

            # ---- Step 4: Create / look up five-tuple flow ------------------
            five_tuple = PacketParser.make_five_tuple(parsed)
            if five_tuple is None:
                # Non-TCP/UDP IPv4 packet – just forward it
                writer.write_packet(raw)
                forwarded += 1
                continue

            if five_tuple not in flows:
                flows[five_tuple] = Flow(
                    tuple      = five_tuple,
                    first_seen = parsed.timestamp,
                    last_seen  = parsed.timestamp,
                )
            flow = flows[five_tuple]
            flow.last_seen    = parsed.timestamp
            flow.packet_count += 1
            flow.byte_count   += parsed.ip_length

            # ---- Step 5: Extract SNI (Deep Packet Inspection) --------------
            if not flow.blocked:
                _classify(parsed, flow)

            # ---- Step 6: Check blocking rules ------------------------------
            if flow.blocked or rules.is_blocked(
                five_tuple.src_ip, flow.app_type, flow.sni
            ):
                flow.blocked = True
                dropped += 1
                continue   # drop

            # ---- Step 7: Forward -------------------------------------------
            writer.write_packet(raw)
            forwarded += 1

    print(f"[Reader] Done reading {total_packets} packets.")

    # ---- Step 8: Report ----------------------------------------------------
    _print_report(
        flows         = flows,
        total_packets = total_packets,
        total_bytes   = total_bytes,
        tcp_count     = tcp_count,
        udp_count     = udp_count,
        forwarded     = forwarded,
        dropped       = dropped,
        rules         = rules,
    )


# ---------------------------------------------------------------------------
# Classification helper  (same logic as FastPath._classify)
# ---------------------------------------------------------------------------

def _classify(parsed: ParsedPacket, flow: Flow) -> None:
    payload  = parsed.payload
    dst_port = parsed.dst_port

    if dst_port == HTTPS_PORT and len(payload) >= 6:
        if not flow.sni:
            sni = SNIExtractor.extract(payload)
            if sni:
                flow.sni      = sni
                flow.app_type = sni_to_app_type(sni)
                return
        if flow.app_type == AppType.UNKNOWN:
            flow.app_type = AppType.HTTPS
        return

    if dst_port == HTTP_PORT and payload:
        if not flow.host:
            host = HTTPHostExtractor.extract(payload)
            if host:
                flow.host     = host
                flow.sni      = host
                flow.app_type = sni_to_app_type(host)
                return
        if flow.app_type == AppType.UNKNOWN:
            flow.app_type = AppType.HTTP
        return

    if dst_port == DNS_PORT:
        if flow.app_type == AppType.UNKNOWN:
            flow.app_type = AppType.DNS
        return


# ---------------------------------------------------------------------------
# Report printer
# ---------------------------------------------------------------------------

def _print_report(
    flows, total_packets, total_bytes,
    tcp_count, udp_count, forwarded, dropped, rules,
) -> None:
    app_counts: Dict[AppType, int] = defaultdict(int)
    sni_map = {}

    for flow in flows.values():
        app_counts[flow.app_type] += flow.packet_count
        if flow.sni:
            sni_map[flow.sni] = flow.app_type

    w = 64
    sep = "═" * w

    print()
    print("╔" + sep + "╗")
    print("║" + "PROCESSING REPORT  (single-threaded)".center(w) + "║")
    print("╠" + sep + "╣")
    print(f"║  Total Packets:   {total_packets:>10}".ljust(w + 1) + "║")
    print(f"║  Total Bytes:     {total_bytes:>10}".ljust(w + 1) + "║")
    print(f"║  TCP Packets:     {tcp_count:>10}".ljust(w + 1) + "║")
    print(f"║  UDP Packets:     {udp_count:>10}".ljust(w + 1) + "║")
    print("╠" + sep + "╣")
    print(f"║  Forwarded:       {forwarded:>10}".ljust(w + 1) + "║")
    print(f"║  Dropped:         {dropped:>10}".ljust(w + 1) + "║")
    print("╠" + sep + "╣")
    print("║" + "APPLICATION BREAKDOWN".center(w) + "║")
    print("╠" + sep + "╣")

    total_flow_pkts = sum(app_counts.values()) or 1
    for app, count in sorted(app_counts.items(), key=lambda x: x[1], reverse=True):
        pct = count / total_flow_pkts * 100
        bar = "#" * max(1, int(pct / 5))
        name = app_type_to_str(app)
        blocked_str = " (BLOCKED)" if app in rules._blocked_apps else ""
        line = f"  {name:<16} {count:>5}  {pct:5.1f}%  {bar}{blocked_str}"
        print(f"║{line}".ljust(w + 1) + "║")

    print("╠" + sep + "╣")
    print("║" + "DETECTED DOMAINS / SNIs".center(w) + "║")
    print("╠" + sep + "╣")
    for sni, app in sorted(sni_map.items()):
        line = f"  {sni}  →  {app_type_to_str(app)}"
        print(f"║{line}".ljust(w + 1) + "║")
    print("╚" + sep + "╝")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args(argv):
    p = argparse.ArgumentParser(
        description="Deep Packet Inspection Engine – simple single-threaded version"
    )
    p.add_argument("input",  help="Input PCAP file")
    p.add_argument("output", help="Output PCAP file")
    p.add_argument("--block-app",    action="append", default=[], metavar="APP")
    p.add_argument("--block-ip",     action="append", default=[], metavar="IP")
    p.add_argument("--block-domain", action="append", default=[], metavar="DOMAIN")
    return p.parse_args(argv)


if __name__ == "__main__":
    args  = _parse_args(sys.argv[1:])
    rules = RuleManager()
    for app in args.block_app:
        rules.add_blocked_app(app)
    for ip in args.block_ip:
        rules.add_blocked_ip(ip)
    for dom in args.block_domain:
        rules.add_blocked_domain(dom)

    run(args.input, args.output, rules)
