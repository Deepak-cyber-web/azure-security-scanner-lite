"""Security checks for Azure Storage Accounts."""

from typing import Any, Iterable

from discovery import ResourceDiscovery
from models import Finding


def value_text(value: Any, default: str = "unknown") -> str:
    """Normalize Azure enum objects and ordinary values for comparisons and reports."""
    if value is None:
        return default
    return str(getattr(value, "value", value)).split(".")[-1]


class StorageSecurityScanner:
    """Run read-only configuration checks against discovered storage accounts."""

    def __init__(self, resources: Iterable[Any]) -> None:
        self.resources = resources

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        for account in self.resources:
            properties = getattr(account, "properties", account)
            name = getattr(account, "name", "unknown")
            group = ResourceDiscovery.resource_group(account)
            blob_public = getattr(properties, "allow_blob_public_access", None)
            tls = value_text(getattr(properties, "minimum_tls_version", None))
            https_only = getattr(properties, "enable_https_traffic_only", None)
            public_network = value_text(getattr(properties, "public_network_access", None))

            findings.append(Finding(
                "STG-001", "Storage", name, group, "HIGH",
                "Blob public access is permitted" if blob_public is True else "Blob public access is disabled",
                "Account-level anonymous blob access can expose data publicly.", value_text(blob_public, "False"), "False",
                "Disable account-level blob public access unless anonymous access is explicitly required.",
                "FAIL" if blob_public is True else "PASS"))
            insecure_tls = tls.upper() in {"TLS1_0", "TLS1_1", "TLS10", "TLS11"}
            findings.append(Finding(
                "STG-002", "Storage", name, group, "HIGH",
                "Legacy TLS version permitted" if insecure_tls else "Modern TLS version enforced",
                "Legacy TLS versions provide weaker transport security.", tls, "TLS1_2 or newer",
                "Require TLS 1.2 or newer for storage traffic.", "FAIL" if insecure_tls else "PASS"))
            findings.append(Finding(
                "STG-003", "Storage", name, group, "HIGH",
                "Secure transfer is not enforced" if https_only is not True else "Secure transfer is enforced",
                "HTTP traffic should not be accepted for storage operations.", value_text(https_only, "False"), "True",
                "Require HTTPS-only traffic for the storage account.", "PASS" if https_only is True else "FAIL"))
            if public_network.lower() in {"enabled", "true"}:
                findings.append(Finding(
                    "STG-004", "Storage", name, group, "INFO",
                    "Storage account has public network access enabled",
                    "Public network access is not automatically a vulnerability and should match business needs.",
                    public_network, "Review according to business requirements",
                    "Review public network access according to business requirements.", "PASS"))
        return findings
