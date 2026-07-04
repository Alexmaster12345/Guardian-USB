"""nmap-based host discovery and port scanning."""
from __future__ import annotations

import shutil
import socket
import subprocess
from dataclasses import dataclass, field

from guardian.core.exceptions import DiscoveryError

try:  # optional dependency
    import nmap  # type: ignore
    _HAS_NMAP = True
except Exception:  # pragma: no cover
    nmap = None  # type: ignore
    _HAS_NMAP = False


@dataclass
class DiscoveredPort:
    port: int
    protocol: str
    state: str
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    banner: str | None = None


@dataclass
class DiscoveredHost:
    ip_address: str
    hostname: str | None = None
    mac_address: str | None = None
    os_match: str | None = None
    ports: list[DiscoveredPort] = field(default_factory=list)


class NetworkScanner:
    """Discovers hosts and open ports using nmap when available,
    falling back to a pure-Python TCP connect scan."""

    COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
                    1433, 3306, 3389, 5432, 6379, 8080, 8443]

    def __init__(self, arguments: str = "-sV -O -T4") -> None:
        self.arguments = arguments

    @property
    def nmap_available(self) -> bool:
        return _HAS_NMAP and shutil.which("nmap") is not None

    def scan(self, target_range: str, ports: str | None = None) -> list[DiscoveredHost]:
        if self.nmap_available:
            return self._scan_with_nmap(target_range, ports)
        return self._scan_fallback(target_range)

    def _scan_with_nmap(self, target_range: str, ports: str | None) -> list[DiscoveredHost]:
        scanner = nmap.PortScanner()
        args = self.arguments
        try:
            scanner.scan(hosts=target_range, ports=ports, arguments=args)
        except Exception as exc:  # pragma: no cover
            raise DiscoveryError(f"nmap scan failed: {exc}") from exc

        hosts: list[DiscoveredHost] = []
        for host in scanner.all_hosts():
            data = scanner[host]
            hostname = data.hostname() or None
            mac = data.get("addresses", {}).get("mac")
            os_match = None
            matches = data.get("osmatch") or []
            if matches:
                os_match = matches[0].get("name")
            dh = DiscoveredHost(ip_address=host, hostname=hostname, mac_address=mac, os_match=os_match)
            for proto in data.all_protocols():
                for port in sorted(data[proto].keys()):
                    p = data[proto][port]
                    dh.ports.append(
                        DiscoveredPort(
                            port=int(port),
                            protocol=proto,
                            state=p.get("state", "unknown"),
                            service_name=p.get("name") or None,
                            product=p.get("product") or None,
                            version=p.get("version") or None,
                            banner=(p.get("extrainfo") or p.get("product") or None),
                        )
                    )
            hosts.append(dh)
        return hosts

    def _scan_fallback(self, target_range: str) -> list[DiscoveredHost]:
        """Pure-Python fallback: expand simple CIDR/host and TCP-connect scan."""
        targets = self._expand_targets(target_range)
        hosts: list[DiscoveredHost] = []
        for ip in targets:
            open_ports: list[DiscoveredPort] = []
            for port in self.COMMON_PORTS:
                if self._tcp_probe(ip, port):
                    banner = self._grab_banner(ip, port)
                    open_ports.append(
                        DiscoveredPort(port=port, protocol="tcp", state="open", banner=banner)
                    )
            if open_ports:
                hostname = None
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except Exception:
                    pass
                hosts.append(DiscoveredHost(ip_address=ip, hostname=hostname, ports=open_ports))
        return hosts

    @staticmethod
    def _expand_targets(target_range: str) -> list[str]:
        import ipaddress

        target_range = target_range.strip()
        try:
            net = ipaddress.ip_network(target_range, strict=False)
            hosts = [str(h) for h in net.hosts()]
            return hosts[:256] if hosts else [str(net.network_address)]
        except ValueError:
            return [target_range]

    @staticmethod
    def _tcp_probe(ip: str, port: int, timeout: float = 0.5) -> bool:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        except Exception:
            return False

    @staticmethod
    def _grab_banner(ip: str, port: int, timeout: float = 1.0) -> str | None:
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                if port in (80, 8080):
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                data = sock.recv(256)
                return data.decode(errors="replace").strip() or None
        except Exception:
            return None

    def ping_host(self, ip: str) -> bool:
        """Lightweight liveness check via system ping."""
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False
