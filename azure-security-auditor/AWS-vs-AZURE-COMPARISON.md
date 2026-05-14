# AWS vs Azure Security Auditor - Complete Comparison

This document helps you understand the differences between auditing AWS and Azure environments.

---

## 🔄 Quick Comparison Table

| Feature | AWS Security Auditor | Azure Security Auditor |
|---------|---------------------|------------------------|
| **Language** | Python 3.8+ | Python 3.8+ |
| **Authentication** | AWS credentials, IAM roles | Azure AD, Service Principal, Managed Identity |
| **SDK** | boto3 (single package) | azure-mgmt-* (multiple packages) |
| **Identity Service** | AWS IAM | Azure AD (Entra ID) |
| **Storage** | Amazon S3 | Azure Storage Accounts |
| **Compute** | Amazon EC2 | Azure Virtual Machines |
| **Networking** | Amazon VPC, Security Groups | Azure VNet, Network Security Groups |
| **Secrets Management** | AWS Secrets Manager | Azure Key Vault |
| **Monitoring** | Amazon CloudWatch | Azure Monitor |
| **Logging** | AWS CloudTrail | Azure Activity Log |
| **Security Service** | AWS Security Hub | Microsoft Defender for Cloud |
| **Compliance Frameworks** | CIS AWS, SOC1/2 | CIS Azure, Azure Security Benchmark, SOC1/2, ISO 27001 |
| **Total Controls** | 63 CIS + SOC2 | 85 CIS + Azure Benchmark + SOC2 + ISO 27001 |

---

## 🔐 Authentication Differences

### **AWS Authentication**

```bash
# Option 1: AWS CLI
aws configure
# Enter: Access Key ID, Secret Access Key, Region

# Option 2: Environment Variables
export AWS_ACCESS_KEY_ID="xxx"
export AWS_SECRET_ACCESS_KEY="xxx"
export AWS_DEFAULT_REGION="us-east-1"

# Option 3: IAM Role (EC2)
# Automatic when running on EC2 with IAM role

# Run auditor
python cli.py
```

**Python Code:**
```python
import boto3

# Uses credential chain automatically
client = boto3.client('iam')
```

### **Azure Authentication**

```bash
# Option 1: Azure CLI (Development)
az login
az account set --subscription "xxx"

# Option 2: Service Principal (Production)
export AZURE_SUBSCRIPTION_ID="xxx"
export AZURE_TENANT_ID="xxx"
export AZURE_CLIENT_ID="xxx"
export AZURE_CLIENT_SECRET="xxx"

# Option 3: Managed Identity (Azure VM)
# Automatic when running on Azure VM

# Run auditor
python cli.py
```

**Python Code:**
```python
from azure.identity import DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient

# Uses credential chain
credential = DefaultAzureCredential()
client = StorageManagementClient(credential, subscription_id)
```

---

## 🛠️ Service Mappings

### **Identity & Access Management**

| AWS | Azure | Key Differences |
|-----|-------|-----------------|
| AWS IAM | Azure AD (Entra ID) | Azure AD is more focused on user identity; Azure RBAC for resource permissions |
| IAM Users | Azure AD Users | Similar concepts |
| IAM Roles | Azure AD Roles + Managed Identities | Azure has separate identity roles and resource roles |
| IAM Policies | Azure RBAC Role Assignments | Azure uses role-based access control |
| IAM Groups | Azure AD Groups | Similar |
| Access Keys | Service Principals | Azure uses App registrations/Service Principals |
| MFA | Azure MFA / Conditional Access | Azure has more granular conditional access policies |

**AWS Control Example:**
```python
# Check if root has access keys
users = iam.list_users()
for user in users:
    if user['UserName'] == 'root':
        access_keys = iam.list_access_keys(UserName='root')
```

**Azure Equivalent:**
```python
# Check if Global Admin has MFA
users = graph_client.users.list()
for user in users:
    if 'Global Administrator' in user.roles:
        mfa_status = graph_client.users.get_mfa(user.id)
```

### **Storage**

| AWS | Azure | Key Differences |
|-----|-------|-----------------|
| S3 Buckets | Storage Accounts | Azure has 4 types: Blob, File, Queue, Table |
| S3 Objects | Blobs | Similar concept |
| Bucket Policies | Storage Account Access Policies | Different policy structure |
| S3 Encryption | Storage Service Encryption | Both support encryption at rest |
| S3 Versioning | Blob Versioning | Similar functionality |
| S3 Public Access Block | Storage Account Public Access | Different configuration method |

**AWS Control Example:**
```python
# Check S3 encryption
buckets = s3.list_buckets()
for bucket in buckets['Buckets']:
    encryption = s3.get_bucket_encryption(Bucket=bucket['Name'])
```

**Azure Equivalent:**
```python
# Check Storage Account encryption
storage_client = azure_client.get_storage_client()
accounts = storage_client.storage_accounts.list()
for account in accounts:
    encryption = account.encryption.services.blob.enabled
```

### **Compute**

| AWS | Azure | Key Differences |
|-----|-------|-----------------|
| EC2 Instances | Virtual Machines | Similar |
| AMI | VM Images | Similar |
| EC2 Instance Types | VM Sizes | Different naming (t2.micro vs Standard_B1s) |
| EBS Volumes | Managed Disks | Similar |
| Security Groups | Network Security Groups | NSGs are subnet or NIC-level |
| Key Pairs | SSH Keys / Passwords | Azure supports both |

### **Networking**

| AWS | Azure | Key Differences |
|-----|-------|-----------------|
| VPC | Virtual Network (VNet) | Similar concepts |
| Subnets | Subnets | Same |
| Security Groups | Network Security Groups | NSGs attached to NIC or subnet |
| Network ACLs | NSG Rules | Similar |
| Internet Gateway | Virtual Network Gateway | Different setup |
| VPC Peering | VNet Peering | Similar |
| Route Tables | Route Tables | Same concept |

### **Logging & Monitoring**

| AWS | Azure | Key Differences |
|-----|-------|-----------------|
| CloudTrail | Activity Log | CloudTrail is more API-focused |
| CloudWatch Logs | Log Analytics | Azure uses workspaces |
| CloudWatch Metrics | Azure Monitor Metrics | Similar |
| CloudWatch Alarms | Azure Monitor Alerts | Similar |
| AWS Config | Azure Policy | Azure Policy is more preventive |

---

## 📊 Control Framework Comparison

### **CIS Benchmarks**

#### **CIS AWS Foundations (63 controls)**
- Section 1: IAM (21 controls)
- Section 2: Storage (10 controls)
- Section 3: Logging (11 controls)
- Section 4: Monitoring (15 controls)
- Section 5: Networking (6 controls)

#### **CIS Azure Foundations (85 controls)**
- Section 1: Identity & Access (18 controls)
- Section 2: Defender for Cloud (9 controls)
- Section 3: Storage (11 controls)
- Section 4: Database (8 controls)
- Section 5: Logging (13 controls)
- Section 6: Networking (7 controls)
- Section 7: Virtual Machines (10 controls)
- Section 8: Key Vault (9 controls)

**Key Difference:** Azure has more controls due to additional services like Key Vault, Defender for Cloud, and more granular Azure AD controls.

---

## 💻 Code Structure Comparison

### **Project Similarity: ~70% Reusable**

#### **Reusable Components (Copy-Paste):**
- ✅ `control.py` - Base control class
- ✅ `finding.py` - Finding data model
- ✅ `engine.py` - Audit orchestration
- ✅ `json_report.py` - JSON report generator
- ✅ `html_report.py` - HTML report generator (minor branding changes)
- ✅ CLI argument structure

#### **Cloud-Specific Components:**
- ❌ `aws_client.py` vs `azure_client.py` - Different SDKs
- ❌ All framework controls - Different services/APIs
- ❌ All service wrappers - Different API structures

### **AWS Auditor Structure:**
```
auditor/
├── core/
│   ├── aws_client.py      ← AWS-specific
│   ├── engine.py           ← Reusable ✅
│   ├── control.py          ← Reusable ✅
│   └── finding.py          ← Reusable ✅
├── frameworks/
│   ├── cis/                ← AWS-specific
│   └── soc2/               ← AWS-specific
├── services/
│   ├── iam_service.py      ← AWS-specific
│   └── s3_service.py       ← AWS-specific
└── reports/
    ├── json_report.py      ← Reusable ✅
    └── html_report.py      ← Reusable ✅
```

### **Azure Auditor Structure:**
```
auditor/
├── core/
│   ├── azure_client.py    ← Azure-specific
│   ├── engine.py           ← Copy from AWS ✅
│   ├── control.py          ← Copy from AWS ✅
│   └── finding.py          ← Copy from AWS ✅
├── frameworks/
│   ├── cis_azure/          ← Azure-specific
│   └── soc2/               ← Azure-specific
├── services/
│   ├── azure_ad_service.py ← Azure-specific
│   └── storage_service.py  ← Azure-specific
└── reports/
    ├── json_report.py      ← Copy from AWS ✅
    └── html_report.py      ← Copy from AWS ✅
```

---

## 🚀 Migration Effort

### **From AWS Auditor to Azure Auditor:**

#### **Time Estimates:**

| Task | Effort | Notes |
|------|--------|-------|
| Copy reusable components | 30 min | engine, control, finding, reports |
| Create Azure client wrapper | 2-3 hours | azure_client.py |
| Create Azure service wrappers | 4-6 hours | 5-7 services |
| Implement Azure AD controls | 1-2 days | 18 CIS controls |
| Implement Storage controls | 1 day | 11 CIS controls |
| Implement Network controls | 1 day | 7 CIS controls |
| Implement VM controls | 1 day | 10 CIS controls |
| Implement Key Vault controls | 1 day | 9 CIS controls |
| Testing & debugging | 2-3 days | End-to-end testing |
| Documentation | 1 day | README, setup guides |
| **Total** | **2-3 weeks** | For complete implementation |

#### **Quick Prototype (1 week):**
- Day 1: Copy reusable components + Azure client
- Day 2-3: 5-10 core Azure AD controls
- Day 4: 5 Storage controls
- Day 5: Testing + basic HTML report
- **Result:** Working prototype with 15-20 controls

---

## 🎯 Which One Should You Build First?

### **Build AWS Auditor First If:**
- ✅ Your organization primarily uses AWS
- ✅ You're more familiar with AWS services
- ✅ You need CIS AWS Foundations compliance
- ✅ You want simpler authentication (boto3)
- ✅ You want a single SDK package

### **Build Azure Auditor First If:**
- ✅ Your organization primarily uses Azure
- ✅ You need Azure Security Benchmark compliance
- ✅ You work with Azure AD (Entra ID) heavily
- ✅ You need ISO 27001 compliance
- ✅ You use Microsoft 365 / Azure integration

### **Build Both If:**
- ✅ Multi-cloud environment
- ✅ Want comprehensive cloud security
- ✅ Building a security product
- ✅ Have 3-4 weeks for development

**Recommendation:** Build AWS first (simpler), then port to Azure (70% reusable code).

---

## 📈 Complexity Comparison

### **AWS Auditor:**
- **Complexity:** Medium
- **SDK:** Single package (boto3)
- **Authentication:** Straightforward
- **API Structure:** Consistent across services
- **Documentation:** Excellent
- **Learning Curve:** Moderate

### **Azure Auditor:**
- **Complexity:** Medium-High
- **SDK:** Multiple packages (azure-mgmt-*)
- **Authentication:** More options but more complex
- **API Structure:** ARM REST API (more consistent than legacy APIs)
- **Documentation:** Good (improving)
- **Learning Curve:** Steeper

---

## 💡 Pro Tips

### **When Building Azure Auditor:**

1. **Start with Azure CLI**: Get `az login` working first
2. **Use DefaultAzureCredential**: It handles all auth methods
3. **Test on free tier**: Azure free tier is generous
4. **Use Azure Portal**: Side-by-side comparison helps
5. **Check Resource Graph**: Azure Resource Graph can query across subscriptions
6. **Watch for rate limits**: Azure APIs have different limits than AWS

### **Reusable Patterns:**

```python
# This pattern works for BOTH:

class ControlBase:
    async def audit(self, cloud_client):
        findings = []
        # Your logic here
        return findings

# AWS version:
async def audit(self, aws_client):
    s3 = aws_client.get_client('s3')
    
# Azure version:
async def audit(self, azure_client):
    storage = azure_client.get_storage_client()
```

---

## 🎓 Learning Path

### **If You Know AWS, Learning Azure:**

1. **Week 1**: Azure fundamentals, Resource Manager
2. **Week 2**: Azure AD, RBAC, subscriptions
3. **Week 3**: Storage Accounts, VMs, networking
4. **Week 4**: Azure Monitor, Security Center
5. **Week 5**: Implement auditor controls

### **Recommended Resources:**

- [Azure for AWS Professionals](https://docs.microsoft.com/en-us/azure/architecture/aws-professional/)
- [Azure Services Comparison](https://docs.microsoft.com/en-us/azure/architecture/aws-professional/services)
- [Azure Python SDK Docs](https://docs.microsoft.com/en-us/python/api/overview/azure/)

---

## ✅ Summary

| Aspect | Winner | Reason |
|--------|--------|--------|
| **Ease of Development** | AWS | Simpler SDK, single package |
| **Authentication** | AWS | More straightforward |
| **Control Coverage** | Azure | 85 vs 63 CIS controls |
| **Code Reusability** | Tie | 70% reusable between them |
| **Documentation** | AWS | More mature ecosystem |
| **Enterprise Features** | Azure | Better AD integration, compliance |

**Bottom Line:** Build AWS first for faster results, then leverage 70% of the code for Azure. Total time: 3-4 weeks for both. 🚀
