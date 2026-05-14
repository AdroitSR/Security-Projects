# Azure Security Auditor 🔒☁️

Automated security compliance auditing for Microsoft Azure environments. Scan your Azure subscription against **CIS Azure Foundations Benchmark**, **Azure Security Benchmark**, **SOC2**, and **ISO 27001** in under 60 seconds.

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Azure](https://img.shields.io/badge/Azure-Security-0078D4)

```bash
# Quick Start - 3 commands to get running
cd azure-security-auditor
pip install -e .
python cli.py
```

---

## ⚡ Quick Start (5 Minutes)

### **Prerequisites**
- Python 3.8 or higher
- Azure subscription
- Azure CLI installed and configured
- Appropriate Azure RBAC permissions

### **Installation**

```bash
# 1. Navigate to project
cd azure-security-auditor

# 2. Install dependencies
pip install -r requirements.txt

# 3. Install as package
pip install -e .

# 4. Verify installation
python cli.py --help
```

### **Configure Azure Authentication**

```bash
# Option 1: Azure CLI (recommended for development)
az login
az account set --subscription "your-subscription-id"
python cli.py

# Option 2: Service Principal (recommended for production)
export AZURE_SUBSCRIPTION_ID="xxx-xxx-xxx"
export AZURE_TENANT_ID="xxx-xxx-xxx"
export AZURE_CLIENT_ID="xxx-xxx-xxx"
export AZURE_CLIENT_SECRET="xxx-xxx-xxx"
python cli.py

# Option 3: Managed Identity (for Azure VMs)
# Automatically detected when running on Azure resources
python cli.py
```

### **Run Your First Audit**

```bash
# Run full audit
python cli.py

# View results
open reports/audit_report.html  # macOS
xdg-open reports/audit_report.html  # Linux
start reports/audit_report.html  # Windows
```

**That's it!** You should see a compliance summary and HTML report. 🎉

---

## 🎯 Features

- ✅ **85+ Security Controls** across Azure services
- ✅ **4 Compliance Frameworks**: CIS Azure, Azure Security Benchmark, SOC2, ISO 27001
- ✅ **Fast Execution**: Parallel async scanning
- ✅ **Professional Reports**: HTML dashboards + JSON for automation
- ✅ **Multi-Subscription Support**: Audit multiple subscriptions
- ✅ **Resource Group Filtering**: Target specific resource groups
- ✅ **CI/CD Ready**: Exit codes for pipeline integration
- ✅ **Safe & Read-Only**: No modifications to your Azure environment

---

## 📖 Usage Examples

### **Basic Commands**

```bash
# Run all controls
python cli.py

# Run specific framework
python cli.py --frameworks CIS-Azure

# Run specific subscription
python cli.py --subscription-id xxx-xxx-xxx

# Audit specific resource groups
python cli.py --resource-groups prod-rg staging-rg

# Audit specific Azure services
python cli.py --services storage compute network

# Use service principal
python cli.py \
  --subscription-id xxx \
  --tenant-id xxx \
  --client-id xxx \
  --client-secret xxx
```

### **Multi-Subscription Auditing**

```bash
# Audit all accessible subscriptions
python cli.py --all-subscriptions

# Audit specific subscriptions
python cli.py --subscriptions sub-1 sub-2 sub-3
```

### **Output Options**

```bash
# Generate JSON only
python cli.py --format json

# Custom output directory
python cli.py --output ./azure-audit-results

# Verbose logging
python cli.py -v
```

### **CI/CD Integration**

```bash
# Exit with error code if findings detected
python cli.py --fail-on-findings

# Azure DevOps Pipeline example
az login --service-principal -u $servicePrincipalId -p $servicePrincipalKey --tenant $tenantId
python cli.py --fail-on-findings --format json
```

---

## 🔧 What Gets Checked

### **CIS Azure Foundations Benchmark v1.5.0** (85 controls)

**Section 1: Identity and Access Management (18 controls)**
- MFA for privileged users
- Security defaults enabled
- Guest user permissions
- Password policies
- Conditional Access policies

**Section 2: Microsoft Defender for Cloud (9 controls)**
- Defender plans enabled
- Automatic provisioning
- Security contacts configured

**Section 3: Storage Accounts (11 controls)**
- Secure transfer required
- Encryption enabled
- Public access blocked
- Soft delete enabled

**Section 4: Database Services (8 controls)**
- Auditing enabled
- Encryption at rest
- Firewall rules configured

**Section 5: Logging and Monitoring (13 controls)**
- Diagnostic settings configured
- Activity Log retention
- Storage logging enabled

**Section 6: Networking (7 controls)**
- RDP/SSH restricted
- Network Security Groups configured
- Network Watcher enabled

**Section 7: Virtual Machines (10 controls)**
- Disk encryption enabled
- Endpoint protection installed
- Approved extensions only

**Section 8: Key Vault (9 controls)**
- Expiration dates set
- Vault recoverable
- Soft delete enabled

### **Azure Services Covered**

- ✅ **Azure AD**: Users, groups, MFA, conditional access, password policies
- ✅ **Storage Accounts**: Encryption, public access, HTTPS, soft delete
- ✅ **Virtual Machines**: Disk encryption, extensions, endpoint protection
- ✅ **Virtual Networks**: NSGs, subnets, network watcher
- ✅ **Key Vault**: Secrets, keys, certificates, recovery settings
- ✅ **Azure Monitor**: Diagnostic settings, log analytics, activity logs
- ✅ **Security Center**: Defender plans, security policies, recommendations

---

## 📊 Understanding Results

### **Console Output**

```bash
$ python cli.py

============================================================
AZURE SECURITY AUDIT SUMMARY
============================================================
Subscription:      prod-subscription-123
Tenant:           contoso.onmicrosoft.com
Resource Groups:  15
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

### **HTML Report**

Professional HTML dashboard with:
- 📊 Executive summary with visual metrics
- 📋 Framework breakdown by Azure service
- ❌ Failed controls with Azure-specific remediation
- ✅ Complete findings list with severity colors
- 🔗 Direct links to Azure Portal for quick fixes

### **JSON Report**

Machine-readable format for automation:

```json
{
  "summary": {
    "subscription_id": "xxx-xxx-xxx",
    "tenant_id": "xxx-xxx-xxx",
    "total_findings": 52,
    "passed": 35,
    "failed": 15,
    "compliance_rate": 67.31
  },
  "findings": [
    {
      "control_id": "CIS-Azure-1.2",
      "status": "FAIL",
      "severity": "HIGH",
      "resource_type": "Azure AD User",
      "resource_id": "admin@contoso.com",
      "remediation": "Enable MFA for this user...",
      "azure_portal_link": "https://portal.azure.com/#blade/..."
    }
  ]
}
```

---

## 🔐 Required Azure Permissions

### **Option 1: Built-in Reader Role**

The simplest approach:

```bash
# Assign Reader role
az role assignment create \
  --assignee user@contoso.com \
  --role "Reader" \
  --scope "/subscriptions/{subscription-id}"
```

### **Option 2: Custom Role** (Recommended)

More restrictive custom role:

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
    "Microsoft.Network/networkWatchers/read"
  ],
  "NotActions": [],
  "AssignableScopes": [
    "/subscriptions/{subscription-id}"
  ]
}
```

Apply the custom role:

```bash
# Create custom role
az role definition create --role-definition security-auditor-role.json

# Assign to service principal
az role assignment create \
  --assignee <service-principal-id> \
  --role "Security Auditor" \
  --scope "/subscriptions/{subscription-id}"
```

---

## 🐛 Troubleshooting

### **Problem: Authentication Failed**

**Solution:**
```bash
# Check Azure CLI login
az account show

# Re-login if needed
az login

# Verify subscription
az account list --output table
```

### **Problem: Insufficient Permissions**

**Solution:**
```bash
# Check your role assignments
az role assignment list --assignee user@contoso.com

# You need at least "Reader" role
az role assignment create \
  --assignee user@contoso.com \
  --role "Reader" \
  --scope "/subscriptions/{subscription-id}"
```

### **Problem: ModuleNotFoundError**

**Solution:**
```bash
cd azure-security-auditor
pip install -e .
```

### **Problem: Subscription Not Found**

**Solution:**
```bash
# List accessible subscriptions
az account list --output table

# Set default subscription
az account set --subscription "your-subscription-name"

# Or specify in command
python cli.py --subscription-id xxx-xxx-xxx
```

---

## 🔄 Key Differences from AWS Auditor

| Aspect | AWS | Azure |
|--------|-----|-------|
| **Authentication** | AWS credentials/IAM | Azure AD / Service Principal |
| **Identity** | IAM | Azure AD (Entra ID) |
| **Storage** | S3 | Storage Accounts |
| **Compute** | EC2 | Virtual Machines |
| **Networking** | VPC | Virtual Networks |
| **Logging** | CloudTrail | Activity Log |
| **Monitoring** | CloudWatch | Azure Monitor |
| **Secrets** | Secrets Manager | Key Vault |
| **Security** | Security Hub | Defender for Cloud |
| **SDK** | boto3 | azure-mgmt-* |
| **Regions** | AWS Regions | Azure Regions + Resource Groups |

---

## 🚀 Advanced Usage

### **Service Principal Setup** (Production)

Create a service principal for automated auditing:

```bash
# Create service principal
az ad sp create-for-rbac --name "SecurityAuditor" --role "Reader" \
  --scopes /subscriptions/{subscription-id}

# Output will contain:
# {
#   "appId": "xxx",          # AZURE_CLIENT_ID
#   "password": "xxx",       # AZURE_CLIENT_SECRET
#   "tenant": "xxx"          # AZURE_TENANT_ID
# }

# Set environment variables
export AZURE_SUBSCRIPTION_ID="your-subscription-id"
export AZURE_TENANT_ID="tenant-from-output"
export AZURE_CLIENT_ID="appId-from-output"
export AZURE_CLIENT_SECRET="password-from-output"

# Run audit
python cli.py
```

### **Multi-Subscription Auditing**

```bash
#!/bin/bash
# Audit multiple subscriptions

subscriptions=(
    "prod-sub-id"
    "staging-sub-id"
    "dev-sub-id"
)

for sub in "${subscriptions[@]}"; do
    echo "Auditing subscription: $sub"
    python cli.py \
        --subscription-id $sub \
        --output reports/$sub \
        --format json html
done
```

### **Azure DevOps Pipeline**

```yaml
# azure-pipelines.yml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
- task: UsePythonVersion@0
  inputs:
    versionSpec: '3.9'

- script: |
    pip install -r requirements.txt
    pip install -e .
  displayName: 'Install dependencies'

- task: AzureCLI@2
  inputs:
    azureSubscription: 'prod-subscription'
    scriptType: 'bash'
    scriptLocation: 'inlineScript'
    inlineScript: |
      python cli.py --fail-on-findings --format json html
  displayName: 'Run Security Audit'

- task: PublishBuildArtifacts@1
  inputs:
    pathToPublish: 'reports'
    artifactName: 'security-audit-reports'
```

---

## 📁 Project Structure

```
azure-security-auditor/
├── auditor/
│   ├── core/
│   │   ├── azure_client.py        # Azure SDK wrapper
│   │   ├── engine.py               # Audit orchestration
│   │   ├── control.py              # Control base class
│   │   └── finding.py              # Finding data model
│   ├── frameworks/
│   │   ├── cis_azure/              # CIS Azure controls
│   │   ├── azure_security_benchmark/  # Azure Security Benchmark
│   │   ├── soc2/                   # SOC2 for Azure
│   │   └── iso27001/               # ISO 27001 controls
│   ├── services/
│   │   ├── azure_ad_service.py     # Azure AD operations
│   │   ├── storage_service.py      # Storage operations
│   │   ├── compute_service.py      # VM operations
│   │   ├── network_service.py      # Network operations
│   │   └── security_service.py     # Security Center
│   └── reports/
│       ├── json_report.py
│       └── html_report.py
├── cli.py                          # Command-line interface
├── requirements.txt                # Dependencies
└── README.md                       # This file
```

---

## 📚 Documentation

- **`README.md`** - Getting started and usage
- **`AZURE_SETUP.md`** - Detailed Azure authentication setup
- **`CIS_AZURE_FRAMEWORK.md`** - All 85 CIS controls documented
- **`AZURE_PERMISSIONS.md`** - Required RBAC roles
- **`COMPARISON.md`** - AWS vs Azure differences

---

## 🎓 Learning Resources

- [CIS Azure Foundations Benchmark](https://www.cisecurity.org/benchmark/azure)
- [Azure Security Benchmark](https://docs.microsoft.com/en-us/security/benchmark/azure/)
- [Azure Security Best Practices](https://docs.microsoft.com/en-us/azure/security/fundamentals/best-practices-and-patterns)
- [Azure Well-Architected Framework](https://docs.microsoft.com/en-us/azure/architecture/framework/)

---

## ⚠️ Important Notes

### **Read-Only Operations**

✅ This tool performs **read-only** checks  
✅ It does **NOT** make changes to your Azure environment  
✅ It does **NOT** create, modify, or delete resources

### **Security Considerations**

- ⚠️ Reports contain sensitive security information - protect them
- ⚠️ Use minimal RBAC permissions (principle of least privilege)
- ⚠️ Consider using managed identities for Azure VMs
- ⚠️ Rotate service principal secrets regularly

---

## 📝 License

MIT License - see LICENSE file for details

---

## ⭐ Quick Reference

```bash
# Installation
pip install -e .

# Basic usage
python cli.py

# Common options
python cli.py --subscription-id xxx    # Specific subscription
python cli.py --resource-groups rg1    # Specific resource group
python cli.py --frameworks CIS-Azure   # CIS only
python cli.py --services storage       # Storage only
python cli.py --all-subscriptions      # All subscriptions
python cli.py --fail-on-findings       # CI/CD mode
python cli.py -v                       # Verbose

# Get help
python cli.py --help
```

---

## 🎯 Next Steps

1. ✅ Run your first audit: `python cli.py`
2. ✅ Review the HTML report
3. ✅ Fix critical findings first (red items)
4. ✅ Set up service principal for automated audits
5. ✅ Schedule regular audits in Azure DevOps
6. ✅ Add custom controls for your needs

**Happy auditing!** 🚀☁️
