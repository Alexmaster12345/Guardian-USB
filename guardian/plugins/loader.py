"""Dynamic plugin loading and dispatch."""
from __future__ import annotations

import importlib
import importlib.util
import inspect
import pkgutil
from pathlib import Path

from guardian.core.exceptions import PluginError
from guardian.plugins.base import GuardianPlugin


class PluginLoader:
    """Discovers GuardianPlugin subclasses from a package or directory."""

    def load_from_package(self, package_name: str = "guardian.plugins.examples") -> list[GuardianPlugin]:
        plugins: list[GuardianPlugin] = []
        try:
            package = importlib.import_module(package_name)
        except ImportError as exc:
            raise PluginError(f"Cannot import plugin package {package_name}: {exc}") from exc

        for _finder, mod_name, _ispkg in pkgutil.iter_modules(package.__path__):
            module = importlib.import_module(f"{package_name}.{mod_name}")
            plugins.extend(self._extract(module))
        return plugins

    def load_from_directory(self, directory: str | Path) -> list[GuardianPlugin]:
        directory = Path(directory)
        if not directory.is_dir():
            raise PluginError(f"Plugin directory not found: {directory}")
        plugins: list[GuardianPlugin] = []
        for py_file in directory.glob("*.py"):
            if py_file.name.startswith("_"):
                continue
            spec = importlib.util.spec_from_file_location(py_file.stem, py_file)
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            try:
                spec.loader.exec_module(module)
            except Exception as exc:
                raise PluginError(f"Failed to load plugin {py_file}: {exc}") from exc
            plugins.extend(self._extract(module))
        return plugins

    @staticmethod
    def _extract(module) -> list[GuardianPlugin]:
        found: list[GuardianPlugin] = []
        for _name, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, GuardianPlugin) and obj is not GuardianPlugin:
                if obj.__module__ == module.__name__:
                    found.append(obj())
        return found


class PluginManager:
    """Holds loaded plugins and dispatches hook events to them."""

    def __init__(self, plugins: list[GuardianPlugin] | None = None) -> None:
        self.plugins: list[GuardianPlugin] = plugins or []
        for plugin in self.plugins:
            self._safe(plugin, "on_load")

    def register(self, plugin: GuardianPlugin) -> None:
        self.plugins.append(plugin)
        self._safe(plugin, "on_load")

    def dispatch_asset_discovered(self, asset) -> None:
        for plugin in self._active():
            self._safe(plugin, "on_asset_discovered", asset)

    def dispatch_finding(self, finding) -> None:
        for plugin in self._active():
            self._safe(plugin, "on_finding", finding)

    def dispatch_scan_complete(self, scan, findings: list) -> None:
        for plugin in self._active():
            self._safe(plugin, "on_scan_complete", scan, findings)

    def _active(self):
        return [p for p in self.plugins if getattr(p, "enabled", True)]

    @staticmethod
    def _safe(plugin, method: str, *args) -> None:
        try:
            getattr(plugin, method)(*args)
        except Exception:
            # A failing plugin must never break the core pipeline.
            pass
