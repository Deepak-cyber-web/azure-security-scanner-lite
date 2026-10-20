"""Security checks for Azure Key Vaults."""

from typing import Any, Iterable

from discovery import ResourceDiscovery
from models import Finding
from scanners.storage import value_text


class KeyVaultSecurityScanner:
    """Run read-only Key Vault configuration checks."""

    def __init__(self, resources: Iterable[Any]) -> None:
        self.resources = resources

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        for vault in self.resources:
            properties = getattr(vault, "properties", vault)
            name = getattr(vault, "name", "unknown")
            group = ResourceDiscovery.resource_group(vault)
            public_access = value_text(getattr(properties, "public_network_access", None))
            purge = getattr(properties, "enable_purge_protection", None)
            public_enabled = public_access.lower() in {"enabled", "true"}
            findings.append(Finding(
                "KV-001", "Key Vault", name, group, "MEDIUM",
                "Key Vault public network access is enabled" if public_enabled else "Key Vault public network access is restricted",
                "Public access should be considered carefully for sensitive vault workloads.", public_access,
                "Restricted access, firewall rules, or private endpoint",
                "Review whether public access is required and prefer firewall restrictions or private endpoints for sensitive workloads.",
                "FAIL" if public_enabled else "PASS"))
            findings.append(Finding(
                "KV-002", "Key Vault", name, group, "MEDIUM",
                "Purge protection is disabled" if purge is not True else "Purge protection is enabled",
                "Without purge protection, deleted important vault data may be harder to recover.", value_text(purge, "False"), "True",
                "Enable purge protection for important production vaults to reduce the risk of irreversible deletion.",
                "PASS" if purge is True else "FAIL"))
        return findings
