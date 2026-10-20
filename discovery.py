"""Discovery of the three supported Azure resource types."""

import re
from typing import Any, Optional

from azure.core.exceptions import AzureError
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.storage import StorageManagementClient


class ResourceDiscovery:
    """List storage accounts, Key Vaults, and NSGs without changing resources."""

    def __init__(self, credential: Any, subscription_id: str) -> None:
        self.credential = credential
        self.subscription_id = subscription_id
        self.storage_client = StorageManagementClient(credential, subscription_id)
        self.keyvault_client = KeyVaultManagementClient(credential, subscription_id)
        self.network_client = NetworkManagementClient(credential, subscription_id)

    @staticmethod
    def _resource_group(resource: Any) -> str:
        resource_id = getattr(resource, "id", "") or ""
        match = re.search(r"/resourceGroups/([^/]+)", resource_id, re.IGNORECASE)
        return match.group(1) if match else "unknown"

    def discover(self, resource_group: Optional[str] = None) -> dict[str, list[Any]]:
        """Return discovered SDK objects, optionally restricted to one resource group."""
        try:
            if resource_group:
                storage = list(self.storage_client.storage_accounts.list_by_resource_group(resource_group))
                vaults = list(self.keyvault_client.vaults.list_by_resource_group(resource_group))
                nsgs = list(self.network_client.network_security_groups.list(resource_group))
            else:
                storage = list(self.storage_client.storage_accounts.list())
                vaults = list(self.keyvault_client.vaults.list_by_subscription())
                nsgs = list(self.network_client.network_security_groups.list_all())
        except AzureError as exc:
            raise RuntimeError(
                "Azure resource discovery failed. Check Reader access and the subscription scope."
            ) from exc

        return {"storage": storage, "keyvault": vaults, "network": nsgs}

    @classmethod
    def resource_group(cls, resource: Any) -> str:
        """Expose consistent resource-group extraction to scanners."""
        return cls._resource_group(resource)
