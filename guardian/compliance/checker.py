"""Run compliance checks against an asset and produce ComplianceResults."""
from __future__ import annotations

from dataclasses import dataclass

from guardian.core.models import Asset, ComplianceResult
from guardian.compliance.rules import get_all_rule_modules


@dataclass
class RuleOutcome:
    framework: str
    rule_id: str
    rule_name: str
    passed: bool
    details: str


class ComplianceChecker:
    """Evaluates all registered compliance rules against an asset context."""

    def __init__(self, rule_modules=None) -> None:
        self.rule_modules = rule_modules or get_all_rule_modules()

    def build_context(self, asset: Asset, extra: dict | None = None) -> dict:
        context = {
            "asset": asset,
            "services": list(getattr(asset, "services", []) or []),
            "software": list(getattr(asset, "software", []) or []),
        }
        if extra:
            context.update(extra)
        return context

    def run(self, asset: Asset, extra: dict | None = None) -> list[RuleOutcome]:
        context = self.build_context(asset, extra)
        outcomes: list[RuleOutcome] = []
        for module in self.rule_modules:
            framework = getattr(module, "FRAMEWORK", module.__name__)
            for rule in getattr(module, "RULES", []):
                try:
                    passed, details = rule.evaluate(context)
                except Exception as exc:  # a broken rule should not abort the run
                    passed, details = False, f"Rule error: {exc}"
                outcomes.append(
                    RuleOutcome(
                        framework=framework,
                        rule_id=rule.id,
                        rule_name=rule.name,
                        passed=bool(passed),
                        details=str(details),
                    )
                )
        return outcomes

    def to_results(
        self, asset: Asset, outcomes: list[RuleOutcome], scan_id: int | None = None
    ) -> list[ComplianceResult]:
        return [
            ComplianceResult(
                asset_id=getattr(asset, "id", None),
                scan_id=scan_id,
                framework=o.framework,
                rule_id=o.rule_id,
                rule_name=o.rule_name,
                passed=o.passed,
                details=o.details,
            )
            for o in outcomes
        ]

    def summary(self, outcomes: list[RuleOutcome]) -> dict:
        total = len(outcomes)
        passed = sum(1 for o in outcomes if o.passed)
        return {
            "total": total,
            "passed": passed,
            "failed": total - passed,
            "pass_rate": round(passed / total * 100, 1) if total else 0.0,
        }
