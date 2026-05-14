"""CIS Azure Foundations Benchmark - Network Security Controls."""
from typing import List
from auditor.core.control import Control
from auditor.core.finding import Finding, Status, Severity
import logging

logger = logging.getLogger(__name__)


class CIS_Azure_6_1_RDPRestrictedFromInternet(Control):
    """
    CIS Azure 6.1 - Ensure that RDP access is restricted from the internet
    
    Disable Remote Desktop Protocol (RDP) access from the Internet and require RDP 
    access to be from a specific IP address or range.
    """
    
    def __init__(self):
        super().__init__()
        self.control_id = "CIS-Azure-6.1"
        self.title = "Ensure that RDP access is restricted from the internet"
        self.description = "Network Security Groups should not allow RDP (port 3389) from 0.0.0.0/0"
        self.rationale = "Public RDP access increases attack surface and risk of brute force attacks"
        self.remediation = """
        Restrict RDP access:
        1. Azure Portal → Network Security Groups
        2. Select NSG → Inbound security rules
        3. Find rule allowing port 3389 from 0.0.0.0/0
        4. Modify rule to restrict source to specific IP ranges
        
        Or use Azure CLI:
        az network nsg rule update \\
          --resource-group <rg> \\
          --nsg-name <nsg-name> \\
          --name <rule-name> \\
          --source-address-prefixes <your-ip>/32
        """
        self.framework = "CIS-Azure"
        self.severity = Severity.HIGH
        self.service = "network"
        self.references = [
            "https://docs.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview",
            "CIS Azure Foundations Benchmark v1.5.0"
        ]
    
    async def audit(self, azure_client) -> List[Finding]:
        """Check NSGs for unrestricted RDP access."""
        findings = []
        
        try:
            network_client = azure_client.get_network_client()
            
            # List all Network Security Groups
            for nsg in network_client.network_security_groups.list_all():
                nsg_name = nsg.name
                resource_group = nsg.id.split('/')[4]
                
                # Check inbound security rules
                for rule in nsg.security_rules:
                    # Check if rule allows RDP (port 3389)
                    if (rule.direction == 'Inbound' and 
                        rule.access == 'Allow' and 
                        self._check_port_range(rule, 3389)):
                        
                        # Check if source is the internet (0.0.0.0/0, *, Internet)
                        if self._is_internet_source(rule.source_address_prefix):
                            findings.append(self._create_finding(
                                Status.FAIL,
                                resource_type="Network Security Group",
                                resource_id=nsg_name,
                                details={
                                    'nsg_name': nsg_name,
                                    'resource_group': resource_group,
                                    'rule_name': rule.name,
                                    'source': rule.source_address_prefix,
                                    'port': 3389,
                                    'protocol': rule.protocol
                                },
                                evidence=[
                                    f"NSG '{nsg_name}' allows RDP (port 3389) from the internet via rule '{rule.name}'"
                                ]
                            ))
            
            # If no violations found
            if not findings:
                findings.append(self._create_finding(
                    Status.PASS,
                    resource_type="Network Security Group",
                    details={'message': 'No NSGs allow unrestricted RDP access'}
                ))
        
        except Exception as e:
            logger.error(f"Error checking NSG rules: {e}")
            findings.append(self._create_finding(
                Status.ERROR,
                resource_type="Network Security Group",
                details={'error': str(e)}
            ))
        
        return findings
    
    def _check_port_range(self, rule, port):
        """Check if port is included in rule's port range."""
        if rule.destination_port_range == '*':
            return True
        
        if rule.destination_port_range:
            if '-' in rule.destination_port_range:
                start, end = map(int, rule.destination_port_range.split('-'))
                return start <= port <= end
            else:
                return int(rule.destination_port_range) == port
        
        # Check destination_port_ranges (list)
        if rule.destination_port_ranges:
            for port_range in rule.destination_port_ranges:
                if port_range == '*':
                    return True
                if str(port) == port_range:
                    return True
        
        return False
    
    def _is_internet_source(self, source):
        """Check if source represents the internet."""
        internet_sources = ['0.0.0.0/0', '*', 'Internet', 'Any']
        return source in internet_sources


class CIS_Azure_6_2_SSHRestrictedFromInternet(Control):
    """
    CIS Azure 6.2 - Ensure that SSH access is restricted from the internet
    """
    
    def __init__(self):
        super().__init__()
        self.control_id = "CIS-Azure-6.2"
        self.title = "Ensure that SSH access is restricted from the internet"
        self.description = "Network Security Groups should not allow SSH (port 22) from 0.0.0.0/0"
        self.rationale = "Public SSH access increases attack surface and risk of brute force attacks"
        self.remediation = """
        Restrict SSH access:
        1. Azure Portal → Network Security Groups
        2. Select NSG → Inbound security rules
        3. Find rule allowing port 22 from 0.0.0.0/0
        4. Modify rule to restrict source to specific IP ranges
        """
        self.framework = "CIS-Azure"
        self.severity = Severity.HIGH
        self.service = "network"
        self.references = ["CIS Azure Foundations Benchmark v1.5.0"]
    
    async def audit(self, azure_client) -> List[Finding]:
        """Check NSGs for unrestricted SSH access."""
        findings = []
        
        try:
            network_client = azure_client.get_network_client()
            
            for nsg in network_client.network_security_groups.list_all():
                nsg_name = nsg.name
                resource_group = nsg.id.split('/')[4]
                
                for rule in nsg.security_rules:
                    if (rule.direction == 'Inbound' and 
                        rule.access == 'Allow' and 
                        self._check_port_range(rule, 22)):
                        
                        if self._is_internet_source(rule.source_address_prefix):
                            findings.append(self._create_finding(
                                Status.FAIL,
                                resource_type="Network Security Group",
                                resource_id=nsg_name,
                                details={
                                    'nsg_name': nsg_name,
                                    'resource_group': resource_group,
                                    'rule_name': rule.name,
                                    'source': rule.source_address_prefix,
                                    'port': 22
                                },
                                evidence=[
                                    f"NSG '{nsg_name}' allows SSH (port 22) from the internet via rule '{rule.name}'"
                                ]
                            ))
            
            if not findings:
                findings.append(self._create_finding(
                    Status.PASS,
                    resource_type="Network Security Group",
                    details={'message': 'No NSGs allow unrestricted SSH access'}
                ))
        
        except Exception as e:
            logger.error(f"Error checking NSG rules: {e}")
            findings.append(self._create_finding(
                Status.ERROR,
                resource_type="Network Security Group",
                details={'error': str(e)}
            ))
        
        return findings
    
    def _check_port_range(self, rule, port):
        """Check if port is included in rule's port range."""
        if rule.destination_port_range == '*':
            return True
        
        if rule.destination_port_range:
            if '-' in rule.destination_port_range:
                start, end = map(int, rule.destination_port_range.split('-'))
                return start <= port <= end
            else:
                return int(rule.destination_port_range) == port
        
        if rule.destination_port_ranges:
            for port_range in rule.destination_port_ranges:
                if port_range == '*' or str(port) == port_range:
                    return True
        
        return False
    
    def _is_internet_source(self, source):
        """Check if source represents the internet."""
        return source in ['0.0.0.0/0', '*', 'Internet', 'Any']


class CIS_Azure_6_3_NetworkSecurityGroupsConfigured(Control):
    """
    CIS Azure 6.3 - Ensure no SQL Databases allow ingress from 0.0.0.0/0 (Any IP)
    """
    
    def __init__(self):
        super().__init__()
        self.control_id = "CIS-Azure-6.3"
        self.title = "Ensure no SQL Databases allow ingress from 0.0.0.0/0"
        self.description = "SQL firewall rules should not allow access from all IP addresses"
        self.rationale = "Public database access poses significant security risk"
        self.remediation = """
        Remove the firewall rule allowing 0.0.0.0 - 255.255.255.255:
        1. Azure Portal → SQL Server → Firewall and virtual networks
        2. Remove or modify the rule
        
        Or use Azure CLI:
        az sql server firewall-rule delete \\
          --resource-group <rg> \\
          --server <server-name> \\
          --name <rule-name>
        """
        self.framework = "CIS-Azure"
        self.severity = Severity.CRITICAL
        self.service = "network"
        self.references = ["CIS Azure Foundations Benchmark v1.5.0"]
    
    async def audit(self, azure_client) -> List[Finding]:
        """Check SQL firewall rules for unrestricted access."""
        findings = []
        
        try:
            # This would require azure-mgmt-sql client
            # Implementation depends on your architecture
            # For now, return a placeholder
            findings.append(self._create_finding(
                Status.ERROR,
                resource_type="SQL Server",
                details={'error': 'SQL firewall check not yet implemented'}
            ))
        
        except Exception as e:
            logger.error(f"Error checking SQL firewall: {e}")
            findings.append(self._create_finding(
                Status.ERROR,
                resource_type="SQL Server",
                details={'error': str(e)}
            ))
        
        return findings
