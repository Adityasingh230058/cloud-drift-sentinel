"""
Data models and taxonomy for Cloud Drift Sentinel findings, resources, and drift records.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, Any, List, Optional
import datetime


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ResourceType(str, Enum):
    IAM_USER = "aws:iam:user"
    IAM_ROLE = "aws:iam:role"
    IAM_POLICY = "aws:iam:policy"
    IAM_ACCOUNT = "aws:iam:account"
    S3_BUCKET = "aws:s3:bucket"
    SECURITY_GROUP = "aws:ec2:security-group"
    EC2_INSTANCE = "aws:ec2:instance"
    RDS_INSTANCE = "aws:rds:db-instance"
    CLOUDTRAIL = "aws:cloudtrail:trail"
    KMS_KEY = "aws:kms:key"
    VPC = "aws:ec2:vpc"
    GENERIC = "cloud:generic"


class DriftType(str, Enum):
    ADDED = "ADDED"          # Resource exists in cloud but not in baseline
    REMOVED = "REMOVED"      # Resource in baseline missing from cloud
    MODIFIED = "MODIFIED"    # Resource attributes have drifted from baseline


@dataclass
class CloudResource:
    id: str
    name: str
    resource_type: ResourceType
    provider: str = "aws"
    region: str = "global"
    tags: Dict[str, str] = field(default_factory=dict)
    raw_config: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "resource_type": self.resource_type.value if isinstance(self.resource_type, ResourceType) else str(self.resource_type),
            "provider": self.provider,
            "region": self.region,
            "tags": self.tags,
            "raw_config": self.raw_config,
        }


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: Severity
    resource_id: str
    resource_type: ResourceType
    description: str
    impact: str
    remediation_guidance: str
    benchmark_reference: str
    region: str = "global"
    provider: str = "aws"
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value if isinstance(self.severity, Severity) else str(self.severity),
            "resource_id": self.resource_id,
            "resource_type": self.resource_type.value if isinstance(self.resource_type, ResourceType) else str(self.resource_type),
            "description": self.description,
            "impact": self.impact,
            "remediation_guidance": self.remediation_guidance,
            "benchmark_reference": self.benchmark_reference,
            "region": self.region,
            "provider": self.provider,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
        }


@dataclass
class DriftRecord:
    drift_type: DriftType
    resource_id: str
    resource_type: ResourceType
    resource_name: str
    differences: Dict[str, Any] = field(default_factory=dict)
    baseline_value: Optional[Any] = None
    current_value: Optional[Any] = None
    timestamp: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "drift_type": self.drift_type.value if isinstance(self.drift_type, DriftType) else str(self.drift_type),
            "resource_id": self.resource_id,
            "resource_type": self.resource_type.value if isinstance(self.resource_type, ResourceType) else str(self.resource_type),
            "resource_name": self.resource_name,
            "differences": self.differences,
            "baseline_value": self.baseline_value,
            "current_value": self.current_value,
            "timestamp": self.timestamp,
        }


@dataclass
class ScanSummary:
    total_resources: int = 0
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    compliance_score: float = 100.0
    passed_rules: int = 0
    failed_rules: int = 0

    def calculate_score(self):
        """
        Deducts points based on finding severities to compute an overall compliance score (0-100%).
        """
        deductions = (
            (self.critical_count * 25) +
            (self.high_count * 12) +
            (self.medium_count * 5) +
            (self.low_count * 2)
        )
        self.compliance_score = max(0.0, round(100.0 - deductions, 1))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    provider: str
    scan_time: str
    resources: List[CloudResource] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    drift_records: List[DriftRecord] = field(default_factory=list)
    summary: ScanSummary = field(default_factory=ScanSummary)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "scan_time": self.scan_time,
            "resources": [r.to_dict() for r in self.resources],
            "findings": [f.to_dict() for f in self.findings],
            "drift_records": [d.to_dict() for d in self.drift_records],
            "summary": self.summary.to_dict(),
        }
