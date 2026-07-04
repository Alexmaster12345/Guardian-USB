"""Installed-software detection via SSH (remote) or local package managers."""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass

from guardian.core.models import Software

try:
    import paramiko  # type: ignore
    _HAS_PARAMIKO = True
except Exception:  # pragma: no cover
    paramiko = None  # type: ignore
    _HAS_PARAMIKO = False


@dataclass
class SSHCredentials:
    host: str
    username: str
    password: str | None = None
    key_filename: str | None = None
    port: int = 22


class SoftwareInventory:
    """Enumerates installed software locally or over SSH."""

    def collect_local(self) -> list[Software]:
        packages = self._run_local_package_manager()
        return [self._to_software(v, p, ver) for v, p, ver in packages]

    def collect_remote(self, creds: SSHCredentials) -> list[Software]:
        if not _HAS_PARAMIKO:
            raise RuntimeError("paramiko is required for remote software inventory")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                creds.host, port=creds.port, username=creds.username,
                password=creds.password, key_filename=creds.key_filename, timeout=10,
            )
            out = self._exec(client, "dpkg-query -W -f='${Package} ${Version}\\n' 2>/dev/null || "
                                     "rpm -qa --qf '%{NAME} %{VERSION}\\n' 2>/dev/null")
        finally:
            client.close()
        return self._parse_package_lines(out)

    @staticmethod
    def _exec(client, command: str) -> str:
        _stdin, stdout, _stderr = client.exec_command(command, timeout=30)
        return stdout.read().decode(errors="replace")

    def _run_local_package_manager(self) -> list[tuple[str | None, str, str | None]]:
        commands = [
            ["dpkg-query", "-W", "-f=${Package} ${Version}\n"],
            ["rpm", "-qa", "--qf", "%{NAME} %{VERSION}\n"],
        ]
        for cmd in commands:
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if res.returncode == 0 and res.stdout.strip():
                    parsed = self._parse_package_lines(res.stdout)
                    return [(s.vendor, s.product, s.version) for s in parsed]
            except Exception:
                continue
        return []

    def _parse_package_lines(self, text: str) -> list[Software]:
        result: list[Software] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 1)
            product = parts[0]
            version = None
            if len(parts) > 1:
                version = re.sub(r"^\d+:", "", parts[1]).split("-")[0].split("+")[0]
            result.append(self._to_software(None, product, version))
        return result

    @staticmethod
    def _to_software(vendor: str | None, product: str, version: str | None) -> Software:
        return Software(vendor=vendor, product=product, version=version, architecture=None)
