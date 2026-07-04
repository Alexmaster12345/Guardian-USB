"""Jinja2-based HTML report exporter."""
from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

_TEMPLATE_DIR = Path(__file__).resolve().parents[1] / "templates"


class HTMLExporter:
    def __init__(self, template_dir: str | Path | None = None) -> None:
        self.template_dir = Path(template_dir) if template_dir else _TEMPLATE_DIR
        self.env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=select_autoescape(["html", "xml", "j2"]),
        )
        self.env.filters["sev_color"] = self._sev_color

    @staticmethod
    def _sev_color(severity: str) -> str:
        return {
            "Critical": "#c0392b",
            "High": "#e67e22",
            "Medium": "#f1c40f",
            "Low": "#3498db",
        }.get(str(severity), "#7f8c8d")

    def export(self, report_data: dict, output_path: str | Path | None = None) -> str:
        template = self.env.get_template("report.html.j2")
        html = template.render(**report_data)
        if output_path:
            Path(output_path).write_text(html, encoding="utf-8")
        return html
