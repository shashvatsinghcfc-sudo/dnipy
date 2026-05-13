"""
pcap_reader.py – Read and write libpcap (.pcap) capture files.

Mirrors the C++ classes in include/pcap_reader.h and src/pcap_reader.cpp.
No external libraries are required – everything is done with the stdlib
`struct` module and plain file I/O, matching the approach in the C++ code.
"""

from __future__ import annotations

import struct
from typing import Iterator, Optional

from dpi_types import (
    PCAP_MAGIC_BE, PCAP_GLOBAL_HDR_SIZE, PCAP_PKT_HDR_SIZE,
    PcapGlobalHeader, PcapPacketHeader, RawPacket,
)


# ---------------------------------------------------------------------------
# PcapReader
# ---------------------------------------------------------------------------

class PcapReader:
    """
    Opens a libpcap file and iterates over its packets.

    Usage::

        reader = PcapReader("capture.pcap")
        reader.open()
        for raw in reader:
            process(raw)
        reader.close()
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self._file = None
        self._little_endian = True   # standard pcap is little-endian on most platforms
        self.global_header: Optional[PcapGlobalHeader] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def open(self) -> None:
        """Open the file and read the 24-byte global header."""
        self._file = open(self.path, "rb")
        self._read_global_header()

    def close(self) -> None:
        if self._file:
            self._file.close()
            self._file = None

    def __enter__(self) -> "PcapReader":
        self.open()
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def __iter__(self) -> Iterator[RawPacket]:
        return self._packet_generator()

    def read_next_packet(self) -> Optional[RawPacket]:
        """Read and return the next packet, or None at EOF."""
        if not self._file:
            raise RuntimeError("File not open. Call open() first.")
        return self._read_packet()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _read_global_header(self) -> None:
        """
        Read and validate the 24-byte PCAP global header.

        PCAP Global Header format:
          magic_number  : 4 bytes  (0xa1b2c3d4)
          version_major : 2 bytes
          version_minor : 2 bytes
          thiszone      : 4 bytes  (GMT offset, usually 0)
          sigfigs       : 4 bytes  (timestamp accuracy, usually 0)
          snaplen       : 4 bytes  (max packet snapshot length)
          network       : 4 bytes  (link-layer type; 1 = Ethernet)
        """
        raw = self._file.read(PCAP_GLOBAL_HDR_SIZE)
        if len(raw) < PCAP_GLOBAL_HDR_SIZE:
            raise ValueError("File too short to be a valid PCAP.")

        # Detect endianness from the magic number
        magic = struct.unpack_from("<I", raw, 0)[0]
        if magic == PCAP_MAGIC_BE:
            self._little_endian = True       # native little-endian file
            fmt = "<IHHiIII"
        elif magic == 0xa1b23c4d:            # nanosecond variant
            self._little_endian = True
            fmt = "<IHHiIII"
        else:
            # Try big-endian
            magic = struct.unpack_from(">I", raw, 0)[0]
            if magic == PCAP_MAGIC_BE:
                self._little_endian = False
                fmt = ">IHHiIII"
            else:
                raise ValueError(f"Not a valid PCAP file (bad magic: {magic:#010x})")

        fields = struct.unpack(fmt, raw)
        self.global_header = PcapGlobalHeader(
            magic_number  = fields[0],
            version_major = fields[1],
            version_minor = fields[2],
            thiszone      = fields[3],
            sigfigs       = fields[4],
            snaplen       = fields[5],
            network       = fields[6],
        )

    def _read_packet(self) -> Optional[RawPacket]:
        """
        Read the next 16-byte per-packet header and its data.

        PCAP Per-Packet Header:
          ts_sec   : 4 bytes  (Unix timestamp, seconds)
          ts_usec  : 4 bytes  (microseconds)
          incl_len : 4 bytes  (bytes in file)
          orig_len : 4 bytes  (original packet length on wire)
        """
        hdr_raw = self._file.read(PCAP_PKT_HDR_SIZE)
        if len(hdr_raw) == 0:
            return None   # EOF
        if len(hdr_raw) < PCAP_PKT_HDR_SIZE:
            raise ValueError("Truncated PCAP packet header.")

        fmt = "<IIII" if self._little_endian else ">IIII"
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(fmt, hdr_raw)
        pkt_header = PcapPacketHeader(ts_sec, ts_usec, incl_len, orig_len)

        data = self._file.read(incl_len)
        if len(data) < incl_len:
            raise ValueError(f"Truncated packet data: expected {incl_len}, got {len(data)}.")

        return RawPacket(header=pkt_header, data=data)

    def _packet_generator(self) -> Iterator[RawPacket]:
        while True:
            pkt = self._read_packet()
            if pkt is None:
                break
            yield pkt


# ---------------------------------------------------------------------------
# PcapWriter
# ---------------------------------------------------------------------------

class PcapWriter:
    """
    Write packets to a new libpcap file (Ethernet link type, 65535 snaplen).

    Usage::

        with PcapWriter("output.pcap") as w:
            w.write_packet(raw)
    """

    GLOBAL_HEADER_FMT = "<IHHiIII"
    PKT_HEADER_FMT    = "<IIII"

    def __init__(self, path: str) -> None:
        self.path = path
        self._file = None

    def open(self) -> None:
        self._file = open(self.path, "wb")
        self._write_global_header()

    def close(self) -> None:
        if self._file:
            self._file.close()
            self._file = None

    def __enter__(self) -> "PcapWriter":
        self.open()
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def write_packet(self, raw: RawPacket) -> None:
        """Write one packet (per-packet header + data) to the output file."""
        hdr = raw.header
        data = raw.data
        incl_len = len(data)
        packed_hdr = struct.pack(
            self.PKT_HEADER_FMT,
            hdr.ts_sec, hdr.ts_usec, incl_len, hdr.orig_len,
        )
        self._file.write(packed_hdr)
        self._file.write(data)

    def _write_global_header(self) -> None:
        hdr = struct.pack(
            self.GLOBAL_HEADER_FMT,
            0xa1b2c3d4,  # magic
            2, 4,        # version major, minor
            0,           # thiszone
            0,           # sigfigs
            65535,       # snaplen
            1,           # network (1 = Ethernet)
        )
        self._file.write(hdr)
