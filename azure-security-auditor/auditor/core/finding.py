"""Finding data models for security audit results."""
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any, Optional
from datetime import datetime


class Status(Enum):
    """Finding status enumeration."""
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    ERROR = "ERROR"
    INFO = "INFO"


class Severity(Enum):
    """Finding severity enumeration."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """Represents a single audit finding."""

    # Control information
    control_id: str
    control_title: str
    framework: str

    # Finding details
    status: Status
    severity: Severity

    # Resource information
    resource_type: str
    resource_id: Optional[str] = None

    # Additional context
    description: Optional[str] = None
    rationale: Optional[str] = None
    remediation: Optional[str] = None
    evidence: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)
    references: List[str] = field(default_factory=list)

    # Metadata
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    service: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            'control_id': self.control_id,
            'control_title': self.control_title,
            'framework': self.framework,
            'status': self.status.value,
            'severity': self.severity.value,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'description': self.description,
            'rationale': self.rationale,
            'remediation': self.remediation,
            'evidence': self.evidence,
            'details': self.details,
            'references': self.references,
            'timestamp': self.timestamp,
            'service': self.service
        }
