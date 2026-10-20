"""Project-specific security scoring."""

from collections import Counter
from typing import Iterable

from models import Finding


class SecurityScoringEngine:
    """Calculate a simple score; this is not Microsoft's official Secure Score."""

    PENALTIES = {"CRITICAL": 15, "HIGH": 10, "MEDIUM": 5, "LOW": 2, "INFO": 0}

    def calculate(self, findings: Iterable[Finding]) -> dict[str, int | str]:
        findings = list(findings)
        score = 100 - sum(
            self.PENALTIES.get(item.severity.upper(), 0)
            for item in findings if item.status.upper() == "FAIL"
        )
        counts = Counter(item.severity.lower() for item in findings)
        passed = sum(item.status.upper() == "PASS" for item in findings)
        failed = sum(item.status.upper() == "FAIL" for item in findings)
        score = max(0, score)
        if score >= 90:
            risk = "EXCELLENT"
        elif score >= 75:
            risk = "LOW"
        elif score >= 50:
            risk = "MEDIUM"
        elif score >= 25:
            risk = "HIGH"
        else:
            risk = "CRITICAL"
        return {"score": score, "risk_level": risk, "critical": counts["critical"], "high": counts["high"], "medium": counts["medium"], "low": counts["low"], "info": counts["info"], "passed": passed, "failed": failed}
