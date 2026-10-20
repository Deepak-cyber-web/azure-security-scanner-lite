"""JSON and HTML report generation."""

import json
from pathlib import Path
from typing import Any, Iterable

from jinja2 import Environment, FileSystemLoader, select_autoescape

from models import Finding


class ReportGenerator:
    """Write assessment results to the local output directory."""

    def __init__(self, output_dir: str = "output") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def write_json(self, subscription_id: str, subscription_name: str, resource_group: str | None, findings: Iterable[Finding], score: dict[str, Any], resource_count: int) -> Path:
        findings = list(findings)
        payload = {"assessment": {"subscription_id": subscription_id, "subscription_name": subscription_name, "resource_group": resource_group or "subscription", "security_score": score["score"], "risk_level": score["risk_level"]}, "summary": {"resources_scanned": resource_count, "critical": score["critical"], "high": score["high"], "medium": score["medium"], "low": score["low"], "info": score["info"], "passed": score["passed"], "failed": score["failed"]}, "findings": [item.to_dict() for item in findings]}
        path = self.output_dir / "findings.json"
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return path

    def write_html(self, assessment: dict[str, Any], summary: dict[str, Any], findings: Iterable[Finding]) -> Path:
        environment = Environment(loader=FileSystemLoader(Path(__file__).parent / "templates"), autoescape=select_autoescape(["html", "xml"]))
        template = environment.get_template("report.html")
        path = self.output_dir / "report.html"
        path.write_text(template.render(assessment=assessment, summary=summary, findings=list(findings)), encoding="utf-8")
        return path
