"""
sni_extractor.py – Extract domain names from TLS Client Hello and HTTP packets.

Mirrors the C++ code in include/sni_extractor.h and src/sni_extractor.cpp.

Key insight (from the README):
  Even though HTTPS traffic is encrypted, the very first packet of a TLS
  connection (the "Client Hello") contains the destination hostname in
  plaintext inside the SNI (Server Name Indication) extension.  We parse
  that extension here without needing to decrypt anything.
"""

from __future__ import annotations

import struct
from typing import Optional


# ---------------------------------------------------------------------------
# TLS constants
# ---------------------------------------------------------------------------

TLS_CONTENT_TYPE_HANDSHAKE   = 0x16
TLS_HANDSHAKE_TYPE_CLIENT_HELLO = 0x01
TLS_EXTENSION_SNI            = 0x0000
TLS_SNI_TYPE_HOSTNAME        = 0x00

# Minimum sizes for sanity checks
TLS_RECORD_HEADER_SIZE       = 5   # content_type(1) + version(2) + length(2)
TLS_HANDSHAKE_HEADER_SIZE    = 4   # type(1) + length(3)
TLS_CLIENT_HELLO_MIN_SIZE    = 34  # version(2) + random(32)


# ---------------------------------------------------------------------------
# SNIExtractor  (mirrors C++ class SNIExtractor)
# ---------------------------------------------------------------------------

class SNIExtractor:
    """
    Parse TLS Client Hello payloads and extract the SNI hostname.

    All logic is in the static method ``extract()``, matching the C++ design.

    TLS Client Hello layout (simplified):
    ┌──────────────────────────────────────────────────────────────┐
    │ TLS Record Header (5 bytes)                                   │
    │   content_type  = 0x16 (Handshake)                           │
    │   version       = 0x0301 (TLS 1.0 record layer)              │
    │   length        = <record length>                            │
    ├──────────────────────────────────────────────────────────────┤
    │ Handshake Header (4 bytes)                                    │
    │   type   = 0x01 (Client Hello)                               │
    │   length = <handshake length> (3 bytes, big-endian)          │
    ├──────────────────────────────────────────────────────────────┤
    │ Client Hello Body                                             │
    │   client_version    (2 bytes)                                │
    │   random            (32 bytes)                               │
    │   session_id_len    (1 byte)                                 │
    │   session_id        (session_id_len bytes)                   │
    │   cipher_suites_len (2 bytes)                                │
    │   cipher_suites     (cipher_suites_len bytes)                │
    │   comp_methods_len  (1 byte)                                 │
    │   comp_methods      (comp_methods_len bytes)                 │
    ├──────────────────────────────────────────────────────────────┤
    │ Extensions                                                    │
    │   extensions_len  (2 bytes)                                  │
    │   for each extension:                                        │
    │     ext_type   (2 bytes)                                     │
    │     ext_length (2 bytes)                                     │
    │     ext_data   (ext_length bytes)                            │
    │                                                              │
    │     SNI extension (ext_type == 0x0000):                     │
    │       sni_list_length (2 bytes)                              │
    │       sni_type        (1 byte, 0x00 = hostname)              │
    │       sni_name_length (2 bytes)                              │
    │       sni_name        (sni_name_length bytes, ASCII)         │
    └──────────────────────────────────────────────────────────────┘
    """

    @staticmethod
    def extract(payload: bytes) -> Optional[str]:
        """
        Attempt to extract the SNI hostname from a raw TCP payload.

        Returns the hostname string, or None if:
          - The payload is not a TLS Handshake record.
          - The record is not a Client Hello.
          - The SNI extension is absent or malformed.
        """
        offset = 0
        length = len(payload)

        # --- TLS Record Header (5 bytes) ------------------------------------
        if length < TLS_RECORD_HEADER_SIZE:
            return None

        content_type = payload[offset]
        if content_type != TLS_CONTENT_TYPE_HANDSHAKE:
            return None
        offset += 3   # skip content_type(1) + version(2)

        record_length = struct.unpack_from(">H", payload, offset)[0]
        offset += 2   # skip record_length(2)

        if length < offset + record_length:
            return None

        # --- Handshake Header (4 bytes) -------------------------------------
        if length < offset + TLS_HANDSHAKE_HEADER_SIZE:
            return None

        handshake_type = payload[offset]
        if handshake_type != TLS_HANDSHAKE_TYPE_CLIENT_HELLO:
            return None
        offset += 1

        # Handshake length is 3 bytes big-endian
        handshake_length = (
            (payload[offset]     << 16) |
            (payload[offset + 1] <<  8) |
             payload[offset + 2]
        )
        offset += 3

        if length < offset + handshake_length:
            return None

        # --- Client Hello Body ----------------------------------------------
        #  client_version (2) + random (32) = 34 bytes fixed
        if length < offset + TLS_CLIENT_HELLO_MIN_SIZE:
            return None

        offset += 2    # skip client_version
        offset += 32   # skip random bytes

        # Session ID
        if length < offset + 1:
            return None
        session_id_len = payload[offset]
        offset += 1 + session_id_len

        # Cipher Suites
        if length < offset + 2:
            return None
        cipher_suites_len = struct.unpack_from(">H", payload, offset)[0]
        offset += 2 + cipher_suites_len

        # Compression Methods
        if length < offset + 1:
            return None
        comp_methods_len = payload[offset]
        offset += 1 + comp_methods_len

        # --- Extensions -----------------------------------------------------
        if length < offset + 2:
            return None   # No extensions present

        extensions_len = struct.unpack_from(">H", payload, offset)[0]
        offset += 2

        ext_end = offset + extensions_len

        while offset + 4 <= ext_end and offset + 4 <= length:
            ext_type   = struct.unpack_from(">H", payload, offset)[0]
            ext_length = struct.unpack_from(">H", payload, offset + 2)[0]
            offset += 4

            if ext_type == TLS_EXTENSION_SNI:
                # SNI extension found
                return SNIExtractor._parse_sni_extension(payload, offset, ext_length)

            offset += ext_length

        return None   # SNI extension not found

    @staticmethod
    def _parse_sni_extension(payload: bytes, offset: int, ext_length: int) -> Optional[str]:
        """Parse the data portion of an SNI extension and return the hostname."""
        if len(payload) < offset + 2:
            return None

        sni_list_length = struct.unpack_from(">H", payload, offset)[0]
        offset += 2

        list_end = offset + sni_list_length

        while offset + 3 <= list_end and offset + 3 <= len(payload):
            sni_type       = payload[offset]
            sni_name_length = struct.unpack_from(">H", payload, offset + 1)[0]
            offset += 3

            if sni_type == TLS_SNI_TYPE_HOSTNAME:
                if len(payload) < offset + sni_name_length:
                    return None
                hostname = payload[offset: offset + sni_name_length].decode("ascii", errors="replace")
                return hostname

            offset += sni_name_length

        return None


# ---------------------------------------------------------------------------
# HTTPHostExtractor  (mirrors C++ class HTTPHostExtractor)
# ---------------------------------------------------------------------------

class HTTPHostExtractor:
    """
    Extract the ``Host:`` header value from a plaintext HTTP request.

    Mirrors the C++ HTTPHostExtractor in src/sni_extractor.cpp.

    HTTP request format (relevant part):
      GET /path HTTP/1.1\\r\\n
      Host: www.example.com\\r\\n
      ...
    """

    HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ",
                    b"DELETE ", b"CONNECT ", b"OPTIONS ", b"PATCH ")

    @staticmethod
    def extract(payload: bytes) -> Optional[str]:
        """
        Return the value of the ``Host:`` header, or None if not found.
        """
        if not payload:
            return None

        # Quick check: must look like an HTTP request
        if not any(payload.startswith(m) for m in HTTPHostExtractor.HTTP_METHODS):
            return None

        # Search for the Host header (case-insensitive)
        payload_lower = payload.lower()
        host_idx = payload_lower.find(b"host: ")
        if host_idx == -1:
            return None

        value_start = host_idx + 6   # len("host: ") == 6
        line_end    = payload.find(b"\r\n", value_start)
        if line_end == -1:
            line_end = payload.find(b"\n", value_start)
        if line_end == -1:
            line_end = len(payload)

        host = payload[value_start:line_end].decode("ascii", errors="replace").strip()
        # Remove port if present (e.g. "example.com:8080" → "example.com")
        host = host.split(":")[0]
        return host if host else None
