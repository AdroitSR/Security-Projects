"""Base control class for security controls."""
from abc import ABC, abstractmethod
from typing import List, Optional
from auditor.core.finding import Finding, Status, Severity


class Control(ABC):
    """Abstract base class for all security controls."""

    def __init__(self):
        """Initialize control with metadata."""
        self.control_id: str = ""
        self.title: str = ""
        self.description: str = ""
        self.rationale: str = ""
        self.remediation: str = ""
        self.framework: str = ""
        self.severity: Severity = Severity.MEDIUM
        self.service: str = ""
        self.references: List[str] = []

    @abstractmethod
    async def audit(self, cloud_client) -> List[Finding]:
        """
        Execute the audit check.

        Args:
            cloud_client: Azure or AWS client wrapper

        Returns:
            List of findings
        """
        pass

    def _create_finding(
        self,
        status: Status,
        resource_type: str,
        resource_id: Optional[str] = None,
        details: Optional[dict] = None,
        evidence: Optional[List[str]] = None
    ) -> Finding:
        """
        Helper method to create a finding.

        Args:
            status: Finding status (PASS, FAIL, etc.)
            resource_type: Type of resource being audited
            resource_id: Specific resource identifier
            details: Additional details dictionary
            evidence: List of evidence strings

        Returns:
            Finding object
        """
        return Finding(
            control_id=self.control_id,
            control_title=self.title,
            framework=self.framework,
            status=status,
            severity=self.severity,
            resource_type=resource_type,
            resource_id=resource_id,
            description=self.description,
            rationale=self.rationale,
            remediation=self.remediation,
            evidence=evidence or [],
            details=details or {},
            references=self.references,
            service=self.service
        )

    def __str__(self) -> str:
        """String representation of control."""
        return f"{self.control_id}: {self.title}"

    def __repr__(self) -> str:
        """Representation of control."""
        return f"Control({self.control_id})"
