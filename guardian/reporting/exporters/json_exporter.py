"""JSON report exporter."""
from __future__ import annotations

import json
from pathlib import Path


class JSONExporter:
    def export(self, report_data: dict, output_path: str | Path | None = None) -> str:
        text = json.dumps(report_data, indent=2, default=str)
        if output_path:
            Path(output_path).write_text(text, encoding="utf-8")
        return text
