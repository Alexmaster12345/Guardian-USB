"""CSV report exporter (findings table)."""
from __future__ import annotations

import csv
import io
from pathlib import Path


class CSVExporter:
    FIELDS = ["id", "asset", "title", "severity", "risk_score", "status", "finding_type", "found_at"]

    def export(self, report_data: dict, output_path: str | Path | None = None) -> str:
        findings = report_data.get("findings", [])
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=self.FIELDS, extrasaction="ignore")
        writer.writeheader()
        for f in findings:
            writer.writerow({
                "id": f.get("id"),
                "asset": f.get("asset") or f.get("asset_id"),
                "title": f.get("title"),
                "severity": f.get("severity"),
                "risk_score": f.get("risk_score"),
                "status": f.get("status"),
                "finding_type": f.get("finding_type"),
                "found_at": f.get("found_at"),
            })
        text = buffer.getvalue()
        if output_path:
            Path(output_path).write_text(text, encoding="utf-8")
        return text
