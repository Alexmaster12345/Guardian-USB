"""Plugin abstract base class with lifecycle hooks."""
from __future__ import annotations

from abc import ABC


class GuardianPlugin(ABC):
    """Base class for Guardian plugins.

    Subclasses override any of the hook methods. All hooks have safe
    default no-op implementations so plugins only implement what they need.
    """

    name: str = "unnamed-plugin"
    version: str = "0.0.0"
    enabled: bool = True

    def on_load(self) -> None:
        """Called once when the plugin is loaded."""

    def on_asset_discovered(self, asset) -> None:
        """Called for each newly discovered asset."""

    def on_finding(self, finding) -> None:
        """Called for each finding generated."""

    def on_scan_complete(self, scan, findings: list) -> None:
        """Called when a scan finishes with all its findings."""

    def on_unload(self) -> None:
        """Called when the plugin is being unloaded."""

    def __repr__(self) -> str:  # pragma: no cover
        return f"<{self.__class__.__name__} name={self.name!r} v{self.version}>"
