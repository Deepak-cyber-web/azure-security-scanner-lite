"""Azure CLI authentication helpers."""

from typing import Optional

from azure.identity import AzureCliCredential
from azure.core.exceptions import AzureError
from azure.mgmt.subscription import SubscriptionClient


class AzureAuthenticator:
    """Authenticate with the user's existing Azure CLI session."""

    def __init__(self, subscription_id: Optional[str] = None) -> None:
        self.requested_subscription_id = subscription_id
        self.credential = None
        self.subscription_id: Optional[str] = None
        self.subscription_name: Optional[str] = None

    def get_credential(self):
        """Create and return an Azure CLI credential."""
        try:
            self.credential = AzureCliCredential()
            # Force a token request now so login and CLI installation errors are clear.
            self.credential.get_token("https://management.azure.com/.default")
            return self.credential
        except Exception as exc:
            raise RuntimeError(
                "Azure CLI authentication failed. Install Azure CLI, run 'az login', "
                "and try again."
            ) from exc

    def get_subscription(self):
        """Resolve the requested subscription or the first available subscription."""
        if self.credential is None:
            self.get_credential()
        try:
            client = SubscriptionClient(self.credential)
            subscriptions = list(client.subscriptions.list())
            if self.requested_subscription_id:
                subscriptions = [
                    item for item in subscriptions
                    if item.subscription_id == self.requested_subscription_id
                ]
            if not subscriptions:
                requested = self.requested_subscription_id or "the Azure CLI account"
                raise RuntimeError(f"No accessible subscription found for {requested}.")
            subscription = subscriptions[0]
            self.subscription_id = subscription.subscription_id
            self.subscription_name = subscription.display_name or self.subscription_id
            return self.subscription_id, self.subscription_name
        except RuntimeError:
            raise
        except AzureError as exc:
            raise RuntimeError(
                "Unable to list Azure subscriptions. Check the CLI login and Reader permissions."
            ) from exc
        except Exception as exc:
            raise RuntimeError("Unable to determine the active Azure subscription.") from exc
