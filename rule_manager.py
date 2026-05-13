"""
rule_manager.py – Manage IP / application / domain blocking rules.

Mirrors the C++ class in include/rule_manager.h (used by the multi-threaded
version dpi_mt.cpp and also imported by the simple version).

Three rule types are supported (matching the C++ README description):

  IP     – block all traffic whose *source IP* appears in the blocked set.
  App    – block all flows classified as a specific AppType.
  Domain – block any flow whose SNI contains the given substring.
"""

from __future__ import annotations

import threading
from typing import Set

from dpi_types import AppType


class RuleManager:
    """
    Thread-safe store of blocking rules.

    All mutating methods acquire a lock so the multi-threaded Fast Path
    threads can query rules concurrently without data races.
    """

    def __init__(self) -> None:
        self._lock            = threading.RLock()
        self._blocked_ips:    Set[int] = set()   # 32-bit host-byte-order ints
        self._blocked_apps:   Set[AppType] = set()
        self._blocked_domains: Set[str] = set()  # lowercase substrings

    # ------------------------------------------------------------------
    # Rule addition
    # ------------------------------------------------------------------

    def add_blocked_ip(self, ip_str: str) -> None:
        """Block all traffic from the given source IP (dotted-decimal)."""
        ip_int = self._str_to_ip(ip_str)
        with self._lock:
            self._blocked_ips.add(ip_int)
        print(f"[Rules] Blocked IP: {ip_str}")

    def add_blocked_app(self, app_name: str) -> None:
        """Block all flows classified as the named application."""
        try:
            app = AppType[app_name.upper()]
        except KeyError:
            print(f"[Rules] Warning: unknown app '{app_name}' – ignoring.")
            return
        with self._lock:
            self._blocked_apps.add(app)
        print(f"[Rules] Blocked app: {app_name}")

    def add_blocked_domain(self, domain: str) -> None:
        """Block any flow whose SNI contains *domain* as a substring."""
        with self._lock:
            self._blocked_domains.add(domain.lower())
        print(f"[Rules] Blocked domain substring: {domain}")

    # ------------------------------------------------------------------
    # Rule query  (mirrors C++ RuleManager::isBlocked)
    # ------------------------------------------------------------------

    def is_blocked(self, src_ip: int, app: AppType, sni: str) -> bool:
        """
        Return True if the packet / flow should be dropped.

        Checks (in order, matching the C++ code):
          1. Is the source IP in the blocked IP set?
          2. Is the classified app in the blocked app set?
          3. Does the SNI contain any blocked domain substring?
        """
        with self._lock:
            # 1. IP check
            if src_ip in self._blocked_ips:
                return True

            # 2. App check
            if app in self._blocked_apps:
                return True

            # 3. Domain substring check
            sni_lower = sni.lower()
            for dom in self._blocked_domains:
                if dom in sni_lower:
                    return True

        return False

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _str_to_ip(ip_str: str) -> int:
        parts = ip_str.split(".")
        result = 0
        for part in parts:
            result = (result << 8) | int(part)
        return result
