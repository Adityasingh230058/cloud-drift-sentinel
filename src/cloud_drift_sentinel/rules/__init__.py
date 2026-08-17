"""
Rules package initialization: auto-registers all CIS benchmark rules.
"""

from .base import BaseRule, RuleRegistry
from .cis_iam import (
    RootAccessKeyRule,
    IAMConsoleMFARule,
    IAMWildcardAdminPolicyRule,
    IAMInactiveCredentialsRule,
    IAMTrustWildcardPrincipalRule,
)
from .cis_storage import (
    S3PublicAccessBlockRule,
    S3DefaultEncryptionRule,
    S3PublicPolicyOrACLRule,
    S3VersioningRule,
    RDSEncryptionAtRestRule,
)
from .cis_network import (
    SecurityGroupSSHExposureRule,
    SecurityGroupRDPExposureRule,
    SecurityGroupDatabaseExposureRule,
    DefaultVPCInUseRule,
)
from .cis_governance import (
    CloudTrailMultiRegionRule,
    CloudTrailLogValidationRule,
    KMSKeyRotationRule,
    VPCFlowLogsRule,
)

__all__ = [
    "BaseRule",
    "RuleRegistry",
    "RootAccessKeyRule",
    "IAMConsoleMFARule",
    "IAMWildcardAdminPolicyRule",
    "IAMInactiveCredentialsRule",
    "IAMTrustWildcardPrincipalRule",
    "S3PublicAccessBlockRule",
    "S3DefaultEncryptionRule",
    "S3PublicPolicyOrACLRule",
    "S3VersioningRule",
    "RDSEncryptionAtRestRule",
    "SecurityGroupSSHExposureRule",
    "SecurityGroupRDPExposureRule",
    "SecurityGroupDatabaseExposureRule",
    "DefaultVPCInUseRule",
    "CloudTrailMultiRegionRule",
    "CloudTrailLogValidationRule",
    "KMSKeyRotationRule",
    "VPCFlowLogsRule",
]
