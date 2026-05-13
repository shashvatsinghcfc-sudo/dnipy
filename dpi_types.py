"""
types.py – Core data structures for the DPI Engine.

Mirrors the C++ structs / enums defined in include/types.h and src/types.cpp.
"""

from __future__ import annotations

import struct
import socket
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional


# ---------------------------------------------------------------------------
# AppType  (mirrors C++ enum class AppType)
# ---------------------------------------------------------------------------

class AppType(Enum):
    UNKNOWN   = auto()
    HTTP      = auto()
    HTTPS     = auto()
    DNS       = auto()
    GOOGLE    = auto()
    YOUTUBE   = auto()
    FACEBOOK  = auto()
    TWITTER   = auto()
    INSTAGRAM = auto()
    TIKTOK    = auto()
    NETFLIX   = auto()
    AMAZON    = auto()
    GITHUB    = auto()
    REDDIT    = auto()
    WIKIPEDIA = auto()
    ZOOM      = auto()
    TEAMS     = auto()
    SLACK     = auto()
    DISCORD   = auto()
    TWITCH    = auto()
    SPOTIFY   = auto()
    APPLE     = auto()
    MICROSOFT = auto()


def sni_to_app_type(sni: str) -> AppType:
    """
    Map a Server Name Indication string to an AppType.

    Mirrors the sniToAppType() function in src/types.cpp.
    Uses substring matching (case-insensitive) – same approach as the C++ code.
    """
    s = sni.lower()
    mapping = [
        ("youtube",    AppType.YOUTUBE),
        ("googlevideo", AppType.YOUTUBE),  # YouTube CDN
        ("facebook",   AppType.FACEBOOK),
        ("fbcdn",      AppType.FACEBOOK),  # Facebook CDN
        ("instagram",  AppType.INSTAGRAM),
        ("twitter",    AppType.TWITTER),
        ("tiktok",     AppType.TIKTOK),
        ("netflix",    AppType.NETFLIX),
        ("nflxvideo",  AppType.NETFLIX),   # Netflix CDN
        ("amazon",     AppType.AMAZON),
        ("twitch",     AppType.TWITCH),
        ("spotify",    AppType.SPOTIFY),
        ("zoom",       AppType.ZOOM),
        ("teams",      AppType.TEAMS),
        ("slack",      AppType.SLACK),
        ("discord",    AppType.DISCORD),
        ("reddit",     AppType.REDDIT),
        ("wikipedia",  AppType.WIKIPEDIA),
        ("github",     AppType.GITHUB),
        ("apple",      AppType.APPLE),
        ("icloud",     AppType.APPLE),
        ("microsoft",  AppType.MICROSOFT),
        ("office365",  AppType.MICROSOFT),
        ("google",     AppType.GOOGLE),
    ]
    for keyword, app in mapping:
        if keyword in s:
            return app
    return AppType.UNKNOWN


def app_type_to_str(app: AppType) -> str:
    return app.name.capitalize()


# ---------------------------------------------------------------------------
# FiveTuple  (mirrors C++ struct FiveTuple)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FiveTuple:
    """
    Uniquely identifies a network flow / connection.

    Fields stored as native Python integers (host byte-order) for convenience;
    the parsers convert from network byte-order on intake.
    """
    src_ip:   int   # 32-bit IPv4 address
    dst_ip:   int   # 32-bit IPv4 address
    src_port: int   # 16-bit port
    dst_port: int   # 16-bit port
    protocol: int   # 8-bit: 6=TCP, 17=UDP

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def src_ip_str(self) -> str:
        return socket.inet_ntoa(struct.pack(">I", self.src_ip))

    def dst_ip_str(self) -> str:
        return socket.inet_ntoa(struct.pack(">I", self.dst_ip))

    def __str__(self) -> str:
        proto = "TCP" if self.protocol == 6 else ("UDP" if self.protocol == 17 else str(self.protocol))
        return (f"{self.src_ip_str()}:{self.src_port} → "
                f"{self.dst_ip_str()}:{self.dst_port} [{proto}]")


# ---------------------------------------------------------------------------
# PCAP file structures  (mirrors include/pcap_reader.h)
# ---------------------------------------------------------------------------

PCAP_MAGIC_BE   = 0xa1b2c3d4   # big-endian timestamps
PCAP_MAGIC_LE   = 0xd4c3b2a1   # little-endian timestamps (same values, swapped)
PCAP_GLOBAL_HDR_SIZE  = 24
PCAP_PKT_HDR_SIZE     = 16


@dataclass
class PcapGlobalHeader:
    magic_number:   int   # 0xa1b2c3d4
    version_major:  int
    version_minor:  int
    thiszone:       int   # GMT offset (usually 0)
    sigfigs:        int   # accuracy of timestamps (usually 0)
    snaplen:        int   # max captured packet size
    network:        int   # link-layer type (1 = Ethernet)


@dataclass
class PcapPacketHeader:
    ts_sec:   int   # capture timestamp (seconds since epoch)
    ts_usec:  int   # microseconds part
    incl_len: int   # bytes saved in the file
    orig_len: int   # original packet length on wire


# ---------------------------------------------------------------------------
# RawPacket / ParsedPacket  (mirrors C++ structs of the same name)
# ---------------------------------------------------------------------------

@dataclass
class RawPacket:
    header: PcapPacketHeader
    data:   bytes


@dataclass
class ParsedPacket:
    # Ethernet
    src_mac:  str = ""
    dst_mac:  str = ""
    eth_type: int = 0

    # IPv4
    src_ip:    str = ""
    dst_ip:    str = ""
    protocol:  int = 0
    ttl:       int = 0
    ip_length: int = 0

    # Transport
    src_port: int = 0
    dst_port: int = 0

    # TCP-specific
    has_tcp:    bool  = False
    tcp_flags:  int   = 0
    seq_num:    int   = 0
    ack_num:    int   = 0
    tcp_header_len: int = 0

    # UDP-specific
    has_udp: bool = False

    # Payload
    payload:        bytes = b""
    payload_length: int   = 0

    # PCAP timestamp
    timestamp: float = 0.0


# ---------------------------------------------------------------------------
# Flow  (state tracked per 5-tuple, mirrors the Flow struct in the C++ code)
# ---------------------------------------------------------------------------

@dataclass
class Flow:
    tuple:    Optional[FiveTuple] = None
    sni:      str      = ""
    host:     str      = ""          # HTTP Host header value
    app_type: AppType  = AppType.UNKNOWN
    blocked:  bool     = False
    packet_count: int  = 0
    byte_count:   int  = 0
    first_seen:   float = 0.0
    last_seen:    float = 0.0


# ---------------------------------------------------------------------------
# Packet  (enriched packet passed through the processing pipeline)
# ---------------------------------------------------------------------------

@dataclass
class Packet:
    raw:     RawPacket
    parsed:  ParsedPacket
    tuple:   Optional[FiveTuple] = None
