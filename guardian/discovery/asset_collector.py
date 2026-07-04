"""Collect asset attributes from discovery data and (optionally) local host."""
from __future__ import annotations

import platform
import shutil
import socket
import uuid

from guardian.core.models import Asset, Criticality
from guardian.discovery.network_scanner import DiscoveredHost
from guardian.fingerprinting.os_fingerprint import fingerprint_os


class AssetCollector:
    """Turns a DiscoveredHost into an Asset, enriching with fingerprints."""

    def from_discovered_host(self, host: DiscoveredHost) -> Asset:
        os_fp = fingerprint_os(nmap_os_match=host.os_match)
        asset = Asset(
            hostname=host.hostname,
            ip_address=host.ip_address,
            mac_address=host.mac_address,
            os_name=os_fp.os_name or host.os_match,
            os_version=os_fp.os_version,
            manufacturer=os_fp.vendor,
            asset_type=self._guess_type(host, os_fp.os_name),
            criticality=Criticality.MEDIUM,
        )
        return asset

    @staticmethod
    def _guess_type(host: DiscoveredHost, os_name: str | None) -> str:
        ports = {p.port for p in host.ports}
        if os_name and "cisco" in os_name.lower():
            return "Router"
        if {80, 443} & ports and {22} & ports:
            return "Server"
        if 3389 in ports:
            return "PC"
        if os_name and "server" in os_name.lower():
            return "Server"
        return "PC"

    def collect_local(self) -> Asset:
        """Collect attributes about the machine Guardian is running on."""
        hostname = socket.gethostname()
        try:
            ip = socket.gethostbyname(hostname)
        except Exception:
            ip = "127.0.0.1"
        mac = ":".join(f"{(uuid.getnode() >> ele) & 0xFF:02x}" for ele in range(40, -8, -8))

        mem_gb = self._memory_gb()
        disk_gb = None
        try:
            total, _, _ = shutil.disk_usage("/")
            disk_gb = round(total / (1024 ** 3), 1)
        except Exception:
            pass

        return Asset(
            hostname=hostname,
            ip_address=ip,
            mac_address=mac,
            os_name=platform.system(),
            os_version=platform.release(),
            cpu=platform.processor() or platform.machine(),
            memory_gb=mem_gb,
            disk_gb=disk_gb,
            asset_type="Server",
            criticality=Criticality.HIGH,
        )

    @staticmethod
    def _memory_gb() -> float | None:
        try:
            with open("/proc/meminfo") as fh:
                for line in fh:
                    if line.startswith("MemTotal:"):
                        kb = int(line.split()[1])
                        return round(kb / (1024 ** 2), 1)
        except Exception:
            pass
        return None
