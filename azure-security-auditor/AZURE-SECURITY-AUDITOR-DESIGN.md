# Azure Security Auditor - Complete Project Design

## 🏗️ Project Overview

**Name:** `azure-security-auditor`
**Purpose:** Automated Azure security compliance auditing tool for CIS Azure Foundations Benchmark, Azure Security Benchmark, SOC2, and ISO 27001.

**Key Differences from AWS Auditor:**
- **Authentication:** Azure AD (Entra ID) service principals vs AWS IAM credentials
- **Services:** Azure AD, Storage Accounts, Virtual Networks, Key Vault vs IAM, S3, VPC
- **SDK:** Azure SDK for Python (`azure-mgmt-*`) vs boto3
- **API Structure:** Resource Manager REST API vs AWS API Gateway
- **Compliance:** CIS Azure + Azure Security Benchmark vs CIS AWS

---

## 📦 Architecture

### **Project Structure**

```
azure-security-auditor/
├── auditor/
│   ├── __init__.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── azure_client.py        # Azure SDK wrapper
│   │   ├── engine.py               # Audit orchestration (same as AWS)
│   │   ├── control.py              # Control base class (reusable)
│   │   └── finding.py              # Finding data model (reusable)
│   ├── frameworks/
│   │   ├── __init__.py
│   │   ├── cis_azure/              # CIS Azure Foundations Benchmark
│   │   │   ├── __init__.py
│   │   │   ├── identity_controls.py
│   │   │   ├── logging_controls.py
│   │   │   ├── networking_controls.py
│   │   │   └── storage_controls.py
│   │   ├── azure_security_benchmark/  # Microsoft Azure Security Benchmark
│   │   │   ├── __init__.py
│   │   │   └── controls.py
│   │   ├── soc2/                   # SOC2 for Azure
│   │   │   ├── __init__.py
│   │   │   └── security.py
│   │   └── iso27001/               # ISO 27001 controls
│   │       ├── __init__.py
│   │       └── controls.py
│   ├── services/
│   │   ├── __init__.py
│   │   ├── azure_ad_service.py     # Azure AD (Entra ID)
│   │   ├── storage_service.py      # Storage Accounts
│   │   ├── compute_service.py      # Virtual Machines
│   │   ├── network_service.py      # Virtual Networks, NSGs
│   │   ├── keyvault_service.py     # Key Vault
│   │   ├── monitor_service.py      # Azure Monitor
│   │   └── security_center_service.py  # Security Center
│   └── reports/
│       ├── __init__.py
│       ├── json_report.py          # Same as AWS
│       ├── html_report.py          # Same as AWS
│       └── templates/
│           └── report.html
├── config/
│   ├── __init__.py
│   └── config.yaml
├── tests/
│   ├── test_controls.py
│   └── test_services.py
├── cli.py
├── requirements.txt
├── setup.py
├── README.md
└── AZURE_SETUP.md
```

---

## 🔑 Key Components

### 1. **Azure Client Wrapper** (`azure_client.py`)

Handles Azure authentication and service management:

```python
from azure.identity import DefaultAzureCredential, ClientSecretCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.security import SecurityCenter

class AzureClient:
    """Wrapper for Azure SDK clients."""
    
    def __init__(self, subscription_id=None, credential=None):
        # Support multiple auth methods
        self.credential = credential or DefaultAzureCredential()
        self.subscription_id = subscription_id
        self._clients = {}
    
    def get_resource_client(self):
        """Get Resource Management client."""
        
    def get_storage_client(self):
        """Get Storage Management client."""
        
    def get_compute_client(self):
        """Get Compute Management client."""
        
    def get_network_client(self):
        """Get Network Management client."""
        
    def get_monitor_client(self):
        """Get Monitor client."""
        
    def get_security_center_client(self):
        """Get Security Center client."""
```

### 2. **Azure Service Wrappers**

#### **Azure AD Service** (`azure_ad_service.py`)
```python
# Operations:
- list_users()
- get_user_mfa_status()
- list_service_principals()
- check_conditional_access_policies()
- get_password_policies()
- list_privileged_role_assignments()
```

#### **Storage Service** (`storage_service.py`)
```python
# Operations:
- list_storage_accounts()
- check_encryption_enabled()
- check_public_access()
- check_https_only()
- list_blob_containers()
- check_soft_delete_enabled()
```

#### **Network Service** (`network_service.py`)
```python
# Operations:
- list_virtual_networks()
- list_network_security_groups()
- check_nsg_rules()
- list_public_ips()
- check_network_watcher_enabled()
```

---

## 🎯 Compliance Frameworks

### **1. CIS Azure Foundations Benchmark v1.5.0**

**Section 1: Identity and Access Management (18 controls)**
- 1.1: Ensure security defaults are enabled
- 1.2: Ensure MFA is enabled for all privileged users
- 1.3: Ensure guest user permissions are limited
- 1.4: Ensure administrative accounts are separate
- 1.20: Ensure password hash sync is enabled
- ... (15 more)

**Section 2: Microsoft Defender for Cloud (9 controls)**
- 2.1: Ensure Defender for Cloud is enabled
- 2.2: Ensure Defender plans are enabled
- 2.3: Ensure automatic provisioning is enabled
- ... (6 more)

**Section 3: Storage Accounts (11 controls)**
- 3.1: Ensure secure transfer is required
- 3.2: Ensure storage encryption is enabled
- 3.3: Ensure storage accounts disallow public access
- 3.7: Ensure soft delete is enabled for blobs
- ... (7 more)

**Section 4: Database Services (8 controls)**
- 4.1: Ensure auditing is enabled for SQL servers
- 4.2: Ensure encryption is enabled
- ... (6 more)

**Section 5: Logging and Monitoring (13 controls)**
- 5.1: Ensure diagnostic settings are configured
- 5.2: Ensure Activity Log retention is 365+ days
- 5.3: Ensure storage logging is enabled
- ... (10 more)

**Section 6: Networking (7 controls)**
- 6.1: Ensure RDP is restricted from internet
- 6.2: Ensure SSH is restricted from internet
- 6.3: Ensure network security groups restrict access
- ... (4 more)

**Section 7: Virtual Machines (10 controls)**
- 7.1: Ensure VM disks are encrypted
- 7.2: Ensure approved extensions only
- 7.3: Ensure endpoint protection is installed
- ... (7 more)

**Section 8: Key Vault (9 controls)**
- 8.1: Ensure expiration date is set for keys
- 8.2: Ensure expiration date is set for secrets
- 8.3: Ensure Key Vault is recoverable
- ... (6 more)

**Total: 85 controls**

### **2. Azure Security Benchmark**

Microsoft's cloud-specific security baseline:
- Network Security
- Identity Management
- Privileged Access
- Data Protection
- Asset Management
- Logging and Threat Detection
- Incident Response
- Posture and Vulnerability Management
- Endpoint Security
- Backup and Recovery
- DevOps Security

### **3. SOC2 for Azure**

Trust Services Criteria mapped to Azure:
- CC6.1: Logical Access (Azure AD, MFA, RBAC)
- CC6.6: Logging (Azure Monitor, Log Analytics)
- CC6.7: Encryption (Storage, Key Vault, Disk Encryption)
- CC7.2: Availability (Backup, Disaster Recovery)

---

## 💻 Example Control Implementation

### **CIS Azure 1.2: MFA for Privileged Users**

```python
from typing import List
from auditor.core.control import Control
from auditor.core.finding import Finding, Status, Severity
from auditor.services.azure_ad_service import AzureADService

class CIS_Azure_1_2_MFAPrivilegedUsers(Control):
    """
    CIS Azure 1.2 - Ensure MFA is enabled for all privileged users
    
    Privileged accounts should have MFA enabled to prevent unauthorized access.
    """
    
    def __init__(self):
        super().__init__()
        self.control_id = "CIS-Azure-1.2"
        self.title = "Ensure MFA is enabled for all privileged users"
        self.description = "All privileged Azure AD users must have MFA enabled"
        self.rationale = "MFA provides additional security layer against credential theft"
        self.remediation = """
        Enable MFA for privileged users:
        1. Go to Azure AD → Users
        2. Select user → Authentication methods
        3. Enable MFA → Configure methods
        """
        self.framework = "CIS-Azure"
        self.severity = Severity.HIGH
        self.service = "azure-ad"
        self.references = [
            "https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-mfa",
            "CIS Azure Foundations Benchmark v1.5.0"
        ]
    
    async def audit(self, azure_client) -> List[Finding]:
        """Check MFA status for privileged users."""
        findings = []
        ad_service = AzureADService(azure_client)
        
        try:
            # Get privileged role assignments
            privileged_users = ad_service.get_privileged_users()
            
            for user in privileged_users:
                user_id = user['id']
                user_principal_name = user['userPrincipalName']
                roles = user['roles']
                
                # Check MFA status
                mfa_status = ad_service.get_user_mfa_status(user_id)
                
                if not mfa_status['enabled']:
                    findings.append(self._create_finding(
                        Status.FAIL,
                        resource_type="Azure AD User",
                        resource_id=user_principal_name,
                        details={
                            'user': user_principal_name,
                            'privileged_roles': roles,
                            'mfa_enabled': False
                        },
                        evidence=[
                            f"User {user_principal_name} with privileged roles {', '.join(roles)} does not have MFA enabled"
                        ]
                    ))
                else:
                    findings.append(self._create_finding(
                        Status.PASS,
                        resource_type="Azure AD User",
                        resource_id=user_principal_name,
                        details={
                            'user': user_principal_name,
                            'mfa_enabled': True,
                            'mfa_methods': mfa_status['methods']
                        }
                    ))
        
        except Exception as e:
            findings.append(self._create_finding(
                Status.ERROR,
                resource_type="Azure AD",
                details={'error': str(e)}
            ))
        
        return findings
```

---

## 🔐 Authentication Methods

### **1. Interactive Login** (Development)
```bash
az login
python cli.py
```

### **2. Service Principal** (Production)
```bash
export AZURE_CLIENT_ID="xxx"
export AZURE_CLIENT_SECRET="xxx"
export AZURE_TENANT_ID="xxx"
export AZURE_SUBSCRIPTION_ID="xxx"
python cli.py
```

### **3. Managed Identity** (Azure VMs)
```python
# Automatically uses VM's managed identity
client = AzureClient()
```

---

## 📋 Required Azure Permissions

### **Reader Role + Custom Permissions**

```json
{
  "Name": "Security Auditor",
  "Description": "Read-only access for security auditing",
  "Actions": [
    "*/read",
    "Microsoft.Authorization/roleAssignments/read",
    "Microsoft.Authorization/roleDefinitions/read",
    "Microsoft.Security/*/read",
    "Microsoft.Insights/diagnosticSettings/read",
    "Microsoft.Network/networkWatchers/read",
    "Microsoft.Storage/storageAccounts/listKeys/action"
  ],
  "NotActions": [],
  "DataActions": [],
  "NotDataActions": [],
  "AssignableScopes": ["/subscriptions/{subscription-id}"]
}
```

---

## 🚀 CLI Usage

```bash
# Basic audit
python cli.py

# Specific subscription
python cli.py --subscription-id xxx-xxx-xxx

# Specific framework
python cli.py --frameworks CIS-Azure

# Specific resource groups
python cli.py --resource-groups prod-rg staging-rg

# Specific services
python cli.py --services storage compute network

# Multi-subscription
python cli.py --all-subscriptions
```

---

## 📦 Dependencies

```txt
# Azure SDK packages
azure-identity>=1.12.0
azure-mgmt-resource>=23.0.0
azure-mgmt-storage>=21.0.0
azure-mgmt-compute>=30.0.0
azure-mgmt-network>=23.0.0
azure-mgmt-monitor>=6.0.0
azure-mgmt-keyvault>=10.0.0
azure-mgmt-security>=5.0.0
azure-mgmt-authorization>=3.0.0

# Microsoft Graph (for Azure AD)
msgraph-core>=0.2.2
azure-identity>=1.12.0

# Common
python-dateutil>=2.8.0
```

---

## 🎯 Key Differences from AWS Auditor

| Aspect | AWS Auditor | Azure Auditor |
|--------|-------------|---------------|
| **Authentication** | boto3 credentials | Azure SDK credential chain |
| **Identity Service** | IAM | Azure AD (Entra ID) |
| **Storage** | S3 | Storage Accounts (Blob, File, Queue) |
| **Compute** | EC2 | Virtual Machines |
| **Networking** | VPC, Security Groups | VNet, Network Security Groups |
| **Logging** | CloudTrail | Activity Log, Diagnostic Settings |
| **Monitoring** | CloudWatch | Azure Monitor |
| **Secrets** | Secrets Manager | Key Vault |
| **Security Service** | Security Hub | Defender for Cloud |
| **SDK Package** | boto3 | azure-mgmt-* (multiple packages) |
| **API Structure** | Service-specific APIs | ARM REST API |
| **Regions** | AWS Regions | Azure Regions + Resource Groups |

---

## 🎓 Implementation Priority

### **Phase 1: Foundation** (Week 1-2)
- ✅ Core Azure client wrapper
- ✅ Engine (reuse from AWS)
- ✅ Finding/Control models (reuse)
- ✅ CLI interface
- ✅ Basic reporting

### **Phase 2: Azure AD Controls** (Week 3)
- ✅ CIS 1.1-1.20 (Identity controls)
- ✅ MFA checks
- ✅ Password policies
- ✅ Privileged access

### **Phase 3: Storage Controls** (Week 4)
- ✅ CIS 3.1-3.11 (Storage controls)
- ✅ Encryption checks
- ✅ Public access
- ✅ Secure transfer

### **Phase 4: Networking & Compute** (Week 5)
- ✅ CIS 6.x (Network controls)
- ✅ CIS 7.x (VM controls)
- ✅ NSG rules
- ✅ Disk encryption

### **Phase 5: Logging & Monitoring** (Week 6)
- ✅ CIS 5.x (Logging controls)
- ✅ Activity Log
- ✅ Diagnostic settings
- ✅ Log retention

---

## 📊 Expected Output

```
============================================================
AZURE SECURITY AUDIT SUMMARY
============================================================
Subscription:      prod-subscription-123
Tenant:           contoso.onmicrosoft.com
Total Findings:   52
Passed:          35
Failed:          15
Warnings:        2
Compliance Rate:  67.31%
============================================================

FRAMEWORK BREAKDOWN:
  CIS-Azure  - Total: 40 | Passed: 28 | Failed: 10 | Rate: 70.0%
  SOC2       - Total: 12 | Passed:  7 | Failed:  5 | Rate: 58.3%
============================================================
```

---

## 🔄 Reusable Components from AWS Auditor

These can be reused with minimal changes:
- ✅ `engine.py` - Audit orchestration logic
- ✅ `control.py` - Base control class
- ✅ `finding.py` - Finding data model
- ✅ `json_report.py` - JSON report generator
- ✅ `html_report.py` - HTML report generator (with Azure branding)
- ✅ CLI argument structure

Only need Azure-specific:
- ❌ `azure_client.py` - New Azure SDK wrapper
- ❌ All framework controls (Azure services)
- ❌ All service wrappers (Azure APIs)

---

## 💡 Unique Azure Features

### **1. Resource Groups**
```bash
# Audit specific resource groups
python cli.py --resource-groups prod-rg dev-rg
```

### **2. Management Groups**
```bash
# Audit entire management group hierarchy
python cli.py --management-group root-mg
```

### **3. Azure Policy Integration**
```python
# Check Azure Policy compliance
check_policy_compliance()
compare_with_azure_policy()
```

### **4. Microsoft Graph Integration**
```python
# Deep Azure AD analysis
check_sign_in_logs()
analyze_risky_users()
check_app_permissions()
```

---

## 🎯 Success Metrics

- **85 CIS Azure controls** documented
- **15-20 controls** implemented initially
- **Sub-60 second** audit time for typical subscription
- **HTML + JSON** reports
- **Multi-subscription** support
- **CI/CD integration** ready

---

## 📚 Documentation to Create

1. **README.md** - Setup and usage
2. **AZURE_SETUP.md** - Azure-specific authentication setup
3. **CIS_AZURE_FRAMEWORK.md** - All 85 controls documented
4. **AZURE_PERMISSIONS.md** - Required RBAC roles
5. **COMPARISON.md** - AWS vs Azure differences

---

This design gives you a complete roadmap for building the Azure Security Auditor! 🚀
