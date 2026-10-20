"""Shared data models for Azure Security Scanner Lite."""

from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class Finding:
    """One read-only security assessment result."""

    check_id: str
    service: str
    resource_name: str
    resource_group: str
    severity: str
    title: str
    description: str
    current_value: str
    recommended_value: str
    recommendation: str
    status: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return asdict(self)
