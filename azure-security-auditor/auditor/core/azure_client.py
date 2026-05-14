"""Azure client wrapper for service interactions."""
import logging
from typing import Dict, Optional, Any
from azure.identity import DefaultAzureCredential, ClientSecretCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.security import SecurityCenter
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.core.exceptions import AzureError

logger = logging.getLogger(__name__)


class AzureClient:
    """Wrapper for Azure SDK clients."""
    
    def __init__(
        self,
        subscription_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        credential: Optional[Any] = None
    ):
        """
        Initialize Azure client.
        
        Args:
            subscription_id: Azure subscription ID
            tenant_id: Azure AD tenant ID
            client_id: Service principal client ID
            client_secret: Service principal secret
            credential: Pre-configured credential object
        """
        # Set up authentication
        if credential:
            self.credential = credential
        elif client_id and client_secret and tenant_id:
            # Service Principal authentication
            self.credential = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret
            )
        else:
            # Default credential chain (az login, managed identity, etc.)
            self.credential = DefaultAzureCredential()
        
        # Get subscription ID from environment if not provided
        if not subscription_id:
            subscription_id = self._get_default_subscription()
        
        self.subscription_id = subscription_id
        self.tenant_id = tenant_id
        
        # Cache for service clients
        self._clients: Dict[str, Any] = {}
        
        logger.info(f"Initialized Azure client for subscription: {subscription_id}")
    
    def _get_default_subscription(self) -> str:
        """Get default subscription from Azure CLI or environment."""
        import os
        import json
        import subprocess
        
        # Try environment variable first
        sub_id = os.getenv('AZURE_SUBSCRIPTION_ID')
        if sub_id:
            return sub_id
        
        # Try Azure CLI
        try:
            result = subprocess.run(
                ['az', 'account', 'show'],
                capture_output=True,
                text=True,
                check=True
            )
            account = json.loads(result.stdout)
            return account['id']
        except Exception as e:
            logger.error(f"Could not determine subscription ID: {e}")
            raise ValueError("Subscription ID must be provided or set in environment")
    
    def get_resource_client(self) -> ResourceManagementClient:
        """Get Resource Management client."""
        if 'resource' not in self._clients:
            self._clients['resource'] = ResourceManagementClient(
                credential=self.credential,
                subscription_id=self.subscription_id
            )
        return self._clients['resource']
    
    def get_storage_client(self) -> StorageManagementClient:
        """Get Storage Management client."""
        if 'storage' not in self._clients:
            self._clients['storage'] = StorageManagementClient(
                credential=self.credential,
                subscription_id=self.subscription_id
            )
        return self._clients['storage']
    
    def get_compute_client(self) -> ComputeManagementClient:
        """Get Compute Management client."""
        if 'compute' not in self._clients:
            self._clients['compute'] = ComputeManagementClient(
                credential=self.credential,
                subscription_id=self.subscription_id
            )
        return self._clients['compute']
    
    def get_network_client(self) -> NetworkManagementClient:
        """Get Network Management client."""
        if 'network' not in self._clients:
            self._clients['network'] = NetworkManagementClient(
                credential=self.credential,
                subscription_id=self.subscription_id
            )
        return self._clients['network']
    
    def get_monitor_client(self) -> MonitorManagementClient:
        """Get Monitor client."""
        if 'monitor' not in self._clients:
            self._clients['monitor'] = MonitorManagementClient(
                credential=self.credential,
                subscription_id=self.subscription_id
            )
        return self._clients['monitor']
    
    def get_keyvault_client(self) -> KeyVaultManagementClient:
        """Get Key Vault Management client."""
        if 'keyvault' not in self._clients:
            self._clients['keyvault'] = KeyVaultManagementClient(
                credential=self.credential,
                subscription_id=self.subscription_id
            )
        return self._clients['keyvault']
    
    def get_security_center_client(self) -> SecurityCenter:
        """Get Security Center client."""
        if 'security' not in self._clients:
            self._clients['security'] = SecurityCenter(
                credential=self.credential,
                subscription_id=self.subscription_id
            )
        return self._clients['security']
    
    def get_authorization_client(self) -> AuthorizationManagementClient:
        """Get Authorization Management client."""
        if 'authorization' not in self._clients:
            self._clients['authorization'] = AuthorizationManagementClient(
                credential=self.credential,
                subscription_id=self.subscription_id
            )
        return self._clients['authorization']
    
    def list_resource_groups(self):
        """List all resource groups in subscription."""
        try:
            resource_client = self.get_resource_client()
            return list(resource_client.resource_groups.list())
        except AzureError as e:
            logger.error(f"Error listing resource groups: {e}")
            return []
    
    def handle_api_error(self, error: Exception, operation: str) -> Optional[str]:
        """
        Handle Azure API errors gracefully.
        
        Args:
            error: Exception raised
            operation: Operation being performed
            
        Returns:
            Error message or None
        """
        if isinstance(error, AzureError):
            error_msg = str(error)
            
            # Handle specific error codes
            if "AuthorizationFailed" in error_msg or "Forbidden" in error_msg:
                logger.warning(f"Access denied for {operation}: {error_msg}")
                return f"Insufficient permissions for {operation}"
            elif "ResourceNotFound" in error_msg or "NotFound" in error_msg:
                logger.info(f"Resource not found for {operation}")
                return None
            else:
                logger.error(f"Azure API error during {operation}: {error_msg}")
                return f"API error: {error_msg}"
        else:
            logger.error(f"Unexpected error during {operation}: {error}")
            return f"Unexpected error: {str(error)}"
