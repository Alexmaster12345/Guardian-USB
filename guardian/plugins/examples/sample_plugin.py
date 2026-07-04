"""A sample plugin that logs events and flags critical findings.

Demonstrates all hook methods of GuardianPlugin.
"""
from __future__ import annotations

import logging

from guardian.core.models import Severity
from guardian.plugins.base import GuardianPlugin

logger = logging.getLogger("guardian.plugin.sample")


class SampleAlertPlugin(GuardianPlugin):
    """Emits alerts for critical findings and keeps counters."""

    name = "sample-alert-plugin"
    version = "1.0.0"

    def __init__(self) -> None:
        self.assets_seen = 0
        self.findings_seen = 0
        self.critical_alerts: list[str] = []

    def on_load(self) -> None:
        logger.info("SampleAlertPlugin loaded (v%s)", self.version)

    def on_asset_discovered(self, asset) -> None:
        self.assets_seen += 1
        logger.info("Asset discovered: %s (%s)", getattr(asset, "hostname", "?"),
                    getattr(asset, "ip_address", "?"))

    def on_finding(self, finding) -> None:
        self.findings_seen += 1
        sev = getattr(finding, "severity", None)
        sev_val = sev.value if isinstance(sev, Severity) else sev
        if sev_val == Severity.CRITICAL.value:
            msg = f"CRITICAL finding: {getattr(finding, 'title', 'unknown')}"
            self.critical_alerts.append(msg)
            logger.warning(msg)

    def on_scan_complete(self, scan, findings: list) -> None:
        logger.info(
            "Scan '%s' complete: %d assets, %d findings, %d critical alerts",
            getattr(scan, "name", "?"),
            self.assets_seen,
            len(findings),
            len(self.critical_alerts),
        )

    def on_unload(self) -> None:
        logger.info("SampleAlertPlugin unloaded")
