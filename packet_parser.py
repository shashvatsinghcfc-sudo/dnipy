"""
packet_parser.py – Parse raw Ethernet / IPv4 / TCP / UDP packet bytes.

Mirrors the C++ code in include/packet_parser.h and src/packet_parser.cpp.

Network byte-order (big-endian) → host byte-order conversion is handled
by Python's struct module using the '>' (big-endian) format character,
equivalent to ntohs() / ntohl() in C.
"""

from __future__ import annotations

import struct
from typing import Optional

from dpi_types import FiveTuple, ParsedPacket, RawPacket


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ETHERNET_HEADER_SIZE = 14
IPV4_MIN_HEADER_SIZE = 20
TCP_MIN_HEADER_SIZE  = 20
UDP_HEADER_SIZE      = 8

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP  = 0x0806

PROTO_TCP = 6
PROTO_UDP = 17


# ---------------------------------------------------------------------------
# PacketParser
# ---------------------------------------------------------------------------

class PacketParser:
    """
    Stateless parser.  Call ``parse()`` for each RawPacket.

    The method returns ``True`` and populates *parsed* on success, or
    returns ``False`` if the packet is malformed / too short / not IPv4.
    """

    @staticmethod
    def parse(raw: RawPacket, parsed: ParsedPacket) -> bool:
        """
        Attempt to parse Ethernet → IP → TCP/UDP headers from *raw*.

        Returns True on success, False if the packet cannot be parsed.
        """
        data = raw.data
        parsed.timestamp = raw.header.ts_sec + raw.header.ts_usec / 1_000_000.0

        # ---- Ethernet -------------------------------------------------------
        if len(data) < ETHERNET_HEADER_SIZE:
            return False

        parsed.dst_mac = PacketParser._mac_to_str(data[0:6])
        parsed.src_mac = PacketParser._mac_to_str(data[6:12])
        parsed.eth_type = struct.unpack_from(">H", data, 12)[0]

        if parsed.eth_type != ETHERTYPE_IPV4:
            return False   # only IPv4 is supported

        # ---- IPv4 -----------------------------------------------------------
        ip_offset = ETHERNET_HEADER_SIZE
        if len(data) < ip_offset + IPV4_MIN_HEADER_SIZE:
            return False

        ip_ver_ihl = data[ip_offset]
        ip_version    = (ip_ver_ihl >> 4) & 0xF
        ip_header_len = (ip_ver_ihl & 0xF) * 4   # IHL field is in 32-bit words

        if ip_version != 4:
            return False
        if ip_header_len < IPV4_MIN_HEADER_SIZE:
            return False
        if len(data) < ip_offset + ip_header_len:
            return False

        # Total length (bytes 2-3 of IP header)
        parsed.ip_length = struct.unpack_from(">H", data, ip_offset + 2)[0]

        parsed.ttl      = data[ip_offset + 8]
        parsed.protocol = data[ip_offset + 9]

        src_ip_raw = struct.unpack_from(">I", data, ip_offset + 12)[0]
        dst_ip_raw = struct.unpack_from(">I", data, ip_offset + 16)[0]
        parsed.src_ip = PacketParser._ip_to_str(src_ip_raw)
        parsed.dst_ip = PacketParser._ip_to_str(dst_ip_raw)

        transport_offset = ip_offset + ip_header_len

        # ---- TCP ------------------------------------------------------------
        if parsed.protocol == PROTO_TCP:
            if len(data) < transport_offset + TCP_MIN_HEADER_SIZE:
                return False

            parsed.has_tcp  = True
            parsed.src_port = struct.unpack_from(">H", data, transport_offset)[0]
            parsed.dst_port = struct.unpack_from(">H", data, transport_offset + 2)[0]
            parsed.seq_num  = struct.unpack_from(">I", data, transport_offset + 4)[0]
            parsed.ack_num  = struct.unpack_from(">I", data, transport_offset + 8)[0]

            data_offset_nibble = (data[transport_offset + 12] >> 4) & 0xF
            parsed.tcp_header_len = data_offset_nibble * 4   # in bytes
            if parsed.tcp_header_len < TCP_MIN_HEADER_SIZE:
                parsed.tcp_header_len = TCP_MIN_HEADER_SIZE

            parsed.tcp_flags = data[transport_offset + 13]

            payload_offset = transport_offset + parsed.tcp_header_len
            parsed.payload = data[payload_offset:]
            parsed.payload_length = len(parsed.payload)

        # ---- UDP ------------------------------------------------------------
        elif parsed.protocol == PROTO_UDP:
            if len(data) < transport_offset + UDP_HEADER_SIZE:
                return False

            parsed.has_udp  = True
            parsed.src_port = struct.unpack_from(">H", data, transport_offset)[0]
            parsed.dst_port = struct.unpack_from(">H", data, transport_offset + 2)[0]

            payload_offset = transport_offset + UDP_HEADER_SIZE
            parsed.payload = data[payload_offset:]
            parsed.payload_length = len(parsed.payload)

        else:
            # Other protocol – still return True so caller knows it's IPv4
            parsed.payload = b""
            parsed.payload_length = 0

        return True

    # ------------------------------------------------------------------
    # Convenience factory: build a FiveTuple from a successfully parsed packet
    # ------------------------------------------------------------------

    @staticmethod
    def make_five_tuple(parsed: ParsedPacket) -> Optional[FiveTuple]:
        """
        Construct a FiveTuple from a parsed packet.

        Returns None if the packet has no transport-layer ports.
        """
        if not (parsed.has_tcp or parsed.has_udp):
            return None
        src_ip = PacketParser._str_to_ip(parsed.src_ip)
        dst_ip = PacketParser._str_to_ip(parsed.dst_ip)
        return FiveTuple(
            src_ip   = src_ip,
            dst_ip   = dst_ip,
            src_port = parsed.src_port,
            dst_port = parsed.dst_port,
            protocol = parsed.protocol,
        )

    # ------------------------------------------------------------------
    # TCP flag helpers
    # ------------------------------------------------------------------

    @staticmethod
    def is_syn(flags: int) -> bool:
        return bool(flags & 0x02)

    @staticmethod
    def is_ack(flags: int) -> bool:
        return bool(flags & 0x10)

    @staticmethod
    def is_fin(flags: int) -> bool:
        return bool(flags & 0x01)

    @staticmethod
    def is_rst(flags: int) -> bool:
        return bool(flags & 0x04)

    # ------------------------------------------------------------------
    # Internal format helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _mac_to_str(raw_bytes: bytes) -> str:
        return ":".join(f"{b:02x}" for b in raw_bytes)

    @staticmethod
    def _ip_to_str(ip_int: int) -> str:
        return ".".join([
            str((ip_int >> 24) & 0xFF),
            str((ip_int >> 16) & 0xFF),
            str((ip_int >>  8) & 0xFF),
            str( ip_int        & 0xFF),
        ])

    @staticmethod
    def _str_to_ip(ip_str: str) -> int:
        parts = ip_str.split(".")
        result = 0
        for part in parts:
            result = (result << 8) | int(part)
        return result
