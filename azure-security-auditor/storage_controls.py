"""CIS Azure Foundations Benchmark - Storage Account Controls."""
from typing import List
from auditor.core.control import Control
from auditor.core.finding import Finding, Status, Severity
import logging

logger = logging.getLogger(__name__)


class CIS_Azure_3_1_SecureTransferRequired(Control):
    """
    CIS Azure 3.1 - Ensure 'Secure transfer required' is set to 'Enabled'
    
    The secure transfer option enhances the security of a storage account by only 
    allowing requests to the storage account by a secure connection (HTTPS).
    """
    
    def __init__(self):
        super().__init__()
        self.control_id = "CIS-Azure-3.1"
        self.title = "Ensure 'Secure transfer required' is set to 'Enabled'"
        self.description = "Storage accounts should require secure transfer (HTTPS only)"
        self.rationale = "HTTPS encrypts data in transit and prevents man-in-the-middle attacks"
        self.remediation = """
        Enable secure transfer:
        1. Go to Azure Portal → Storage Accounts
        2. Select storage account
        3. Settings → Configuration
        4. Set 'Secure transfer required' to 'Enabled'
        
        Or use Azure CLI:
        az storage account update \\
          --name <storage-account-name> \\
          --resource-group <resource-group> \\
          --https-only true
        """
        self.framework = "CIS-Azure"
        self.severity = Severity.HIGH
        self.service = "storage"
        self.references = [
            "https://docs.microsoft.com/en-us/azure/storage/common/storage-require-secure-transfer",
            "CIS Azure Foundations Benchmark v1.5.0"
        ]
    
    async def audit(self, azure_client) -> List[Finding]:
        """Check if storage accounts require HTTPS."""
        findings = []
        
        try:
            storage_client = azure_client.get_storage_client()
            
            # List all storage accounts in subscription
            for account in storage_client.storage_accounts.list():
                account_name = account.name
                resource_group = account.id.split('/')[4]  # Extract from resource ID
                
                if not account.enable_https_traffic_only:
                    findings.append(self._create_finding(
                        Status.FAIL,
                        resource_type="Storage Account",
                        resource_id=account_name,
                        details={
                            'storage_account': account_name,
                            'resource_group': resource_group,
                            'https_only': False,
                            'location': account.location
                        },
                        evidence=[
                            f"Storage account '{account_name}' does not require secure transfer (HTTPS)"
                        ]
                    ))
                else:
                    findings.append(self._create_finding(
                        Status.PASS,
                        resource_type="Storage Account",
                        resource_id=account_name,
                        details={
                            'storage_account': account_name,
                            'resource_group': resource_group,
                            'https_only': True
                        }
                    ))
        
        except Exception as e:
            logger.error(f"Error checking storage accounts: {e}")
            findings.append(self._create_finding(
                Status.ERROR,
                resource_type="Storage Account",
                details={'error': str(e)}
            ))
        
        return findings


class CIS_Azure_3_2_StorageEncryptionEnabled(Control):
    """
    CIS Azure 3.2 - Ensure storage for critical data is encrypted with Customer Managed Keys
    """
    
    def __init__(self):
        super().__init__()
        self.control_id = "CIS-Azure-3.2"
        self.title = "Ensure storage encryption is enabled"
        self.description = "Storage service encryption protects data at rest"
        self.rationale = "Encryption at rest protects data from unauthorized access"
        self.remediation = """
        Storage encryption is enabled by default on all new storage accounts.
        For existing accounts without encryption, create a new account and migrate data.
        """
        self.framework = "CIS-Azure"
        self.severity = Severity.HIGH
        self.service = "storage"
        self.references = ["CIS Azure Foundations Benchmark v1.5.0"]
    
    async def audit(self, azure_client) -> List[Finding]:
        findings = []
        
        try:
            storage_client = azure_client.get_storage_client()
            
            for account in storage_client.storage_accounts.list():
                account_name = account.name
                
                # Check blob encryption
                blob_encryption = account.encryption.services.blob.enabled if account.encryption else False
                
                # Check file encryption
                file_encryption = account.encryption.services.file.enabled if account.encryption else False
                
                if not (blob_encryption and file_encryption):
                    findings.append(self._create_finding(
                        Status.FAIL,
                        resource_type="Storage Account",
                        resource_id=account_name,
                        details={
                            'storage_account': account_name,
                            'blob_encryption': blob_encryption,
                            'file_encryption': file_encryption
                        },
                        evidence=[f"Storage account '{account_name}' does not have full encryption enabled"]
                    ))
                else:
                    findings.append(self._create_finding(
                        Status.PASS,
                        resource_type="Storage Account",
                        resource_id=account_name,
                        details={
                            'storage_account': account_name,
                            'blob_encryption': True,
                            'file_encryption': True
                        }
                    ))
        
        except Exception as e:
            logger.error(f"Error checking storage encryption: {e}")
            findings.append(self._create_finding(
                Status.ERROR,
                resource_type="Storage Account",
                details={'error': str(e)}
            ))
        
        return findings


class CIS_Azure_3_3_PublicAccessDisabled(Control):
    """
    CIS Azure 3.3 - Ensure storage accounts disallow public access
    """
    
    def __init__(self):
        super().__init__()
        self.control_id = "CIS-Azure-3.3"
        self.title = "Ensure storage accounts disallow public access"
        self.description = "Anonymous public read access should be disabled"
        self.rationale = "Public access can expose sensitive data to unauthorized users"
        self.remediation = """
        Disable public access:
        1. Azure Portal → Storage Account → Configuration
        2. Set 'Allow Blob public access' to 'Disabled'
        
        Or use Azure CLI:
        az storage account update \\
          --name <storage-account-name> \\
          --resource-group <resource-group> \\
          --allow-blob-public-access false
        """
        self.framework = "CIS-Azure"
        self.severity = Severity.CRITICAL
        self.service = "storage"
        self.references = ["CIS Azure Foundations Benchmark v1.5.0"]
    
    async def audit(self, azure_client) -> List[Finding]:
        findings = []
        
        try:
            storage_client = azure_client.get_storage_client()
            
            for account in storage_client.storage_accounts.list():
                account_name = account.name
                
                # Check if public access is allowed
                public_access_allowed = account.allow_blob_public_access
                
                if public_access_allowed:
                    findings.append(self._create_finding(
                        Status.FAIL,
                        resource_type="Storage Account",
                        resource_id=account_name,
                        details={
                            'storage_account': account_name,
                            'public_access_allowed': True
                        },
                        evidence=[
                            f"Storage account '{account_name}' allows public blob access"
                        ]
                    ))
                else:
                    findings.append(self._create_finding(
                        Status.PASS,
                        resource_type="Storage Account",
                        resource_id=account_name,
                        details={
                            'storage_account': account_name,
                            'public_access_allowed': False
                        }
                    ))
        
        except Exception as e:
            logger.error(f"Error checking public access: {e}")
            findings.append(self._create_finding(
                Status.ERROR,
                resource_type="Storage Account",
                details={'error': str(e)}
            ))
        
        return findings


class CIS_Azure_3_7_SoftDeleteEnabled(Control):
    """
    CIS Azure 3.7 - Ensure soft delete is enabled for Azure Blob Storage
    """
    
    def __init__(self):
        super().__init__()
        self.control_id = "CIS-Azure-3.7"
        self.title = "Ensure soft delete is enabled for Azure Blob Storage"
        self.description = "Soft delete allows recovery of deleted blobs"
        self.rationale = "Protects against accidental or malicious deletion of data"
        self.remediation = """
        Enable soft delete:
        az storage blob service-properties delete-policy update \\
          --account-name <storage-account> \\
          --enable true \\
          --days-retained 7
        """
        self.framework = "CIS-Azure"
        self.severity = Severity.MEDIUM
        self.service = "storage"
        self.references = ["CIS Azure Foundations Benchmark v1.5.0"]
    
    async def audit(self, azure_client) -> List[Finding]:
        findings = []
        
        try:
            storage_client = azure_client.get_storage_client()
            
            for account in storage_client.storage_accounts.list():
                account_name = account.name
                resource_group = account.id.split('/')[4]
                
                # Get blob service properties
                try:
                    blob_properties = storage_client.blob_services.get_service_properties(
                        resource_group_name=resource_group,
                        account_name=account_name
                    )
                    
                    soft_delete_enabled = False
                    retention_days = 0
                    
                    if blob_properties.delete_retention_policy:
                        soft_delete_enabled = blob_properties.delete_retention_policy.enabled
                        retention_days = blob_properties.delete_retention_policy.days or 0
                    
                    if not soft_delete_enabled or retention_days < 7:
                        findings.append(self._create_finding(
                            Status.FAIL,
                            resource_type="Storage Account",
                            resource_id=account_name,
                            details={
                                'storage_account': account_name,
                                'soft_delete_enabled': soft_delete_enabled,
                                'retention_days': retention_days
                            },
                            evidence=[
                                f"Storage account '{account_name}' does not have adequate soft delete protection"
                            ]
                        ))
                    else:
                        findings.append(self._create_finding(
                            Status.PASS,
                            resource_type="Storage Account",
                            resource_id=account_name,
                            details={
                                'storage_account': account_name,
                                'soft_delete_enabled': True,
                                'retention_days': retention_days
                            }
                        ))
                
                except Exception as e:
                    logger.warning(f"Could not check soft delete for {account_name}: {e}")
        
        except Exception as e:
            logger.error(f"Error checking soft delete: {e}")
            findings.append(self._create_finding(
                Status.ERROR,
                resource_type="Storage Account",
                details={'error': str(e)}
            ))
        
        return findings
