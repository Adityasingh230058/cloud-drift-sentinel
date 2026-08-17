"""
CIS AWS Foundations Benchmark - Section 3: Logging, Monitoring & KMS Governance Rules.
"""

from typing import Optional
from .base import BaseRule, RuleRegistry
from ..core.models import CloudResource, Finding, Severity, ResourceType


@RuleRegistry.register
class CloudTrailMultiRegionRule(BaseRule):
    rule_id = "CIS-3.1"
    rule_name = "Ensure CloudTrail is enabled across all regions"
    severity = Severity.HIGH
    resource_type = ResourceType.CLOUDTRAIL
    description = "CloudTrail should record events across all AWS regions to capture unauthorized activity even in unused regions."
    impact = "Attackers frequently launch malicious compute or miners in obscure, unmonitored AWS regions."
    remediation_guidance = "Update CloudTrail trail to be multi-region: `aws cloudtrail update-trail --name <trail> --is-multi-region-trail`."
    benchmark_reference = "CIS AWS Foundations v2.0 - 3.1"

    def evaluate(self, resource: CloudResource) -> Optional[Finding]:
        if resource.resource_type != ResourceType.CLOUDTRAIL:
            return None
        is_multi_region = resource.raw_config.get("IsMultiRegionTrail", False)
        is_logging = resource.raw_config.get("IsLogging", True)

        if not is_multi_region or not is_logging:
            return self.create_finding(
                resource=resource,
                custom_description=f"CloudTrail '{resource.name}' is not configured as a multi-region trail or logging is paused.",
                metadata={"is_multi_region": is_multi_region, "is_logging": is_logging}
            )
        return None


@RuleRegistry.register
class CloudTrailLogValidationRule(BaseRule):
    rule_id = "CIS-3.2"
    rule_name = "Ensure CloudTrail log file validation is enabled"
    severity = Severity.MEDIUM
    resource_type = ResourceType.CLOUDTRAIL
    description = "Log file validation provides cryptographic SHA-256 signatures to verify that log files were not modified or deleted."
    impact = "Without log validation, tampered or altered forensic trails cannot be cryptographically proven in breach investigations."
    remediation_guidance = "Enable log file validation: `aws cloudtrail update-trail --name <trail> --enable-log-file-validation`."
    benchmark_reference = "CIS AWS Foundations v2.0 - 3.2"

    def evaluate(self, resource: CloudResource) -> Optional[Finding]:
        if resource.resource_type != ResourceType.CLOUDTRAIL:
            return None
        val_enabled = resource.raw_config.get("LogFileValidationEnabled", False)
        if not val_enabled:
            return self.create_finding(
                resource=resource,
                custom_description=f"CloudTrail '{resource.name}' does not have log file integrity validation enabled.",
                metadata={"validation_enabled": val_enabled}
            )
        return None


@RuleRegistry.register
class KMSKeyRotationRule(BaseRule):
    rule_id = "CIS-3.7"
    rule_name = "Ensure AWS KMS Customer Managed Keys have automatic annual rotation enabled"
    severity = Severity.MEDIUM
    resource_type = ResourceType.KMS_KEY
    description = "AWS KMS automatic key rotation generates new cryptographic material annually without altering key ARNs."
    impact = "Prevents long-term exposure of a single cryptographic key backing critical customer data."
    remediation_guidance = "Enable key rotation on the KMS key: `aws kms enable-key-rotation --key-id <key-id>`."
    benchmark_reference = "CIS AWS Foundations v2.0 - 3.7"

    def evaluate(self, resource: CloudResource) -> Optional[Finding]:
        if resource.resource_type != ResourceType.KMS_KEY:
            return None
        key_manager = resource.raw_config.get("KeyManager", "CUSTOMER")
        rotation_enabled = resource.raw_config.get("KeyRotationEnabled", False)

        # Only evaluate Customer Managed Keys (AWS managed keys rotate automatically)
        if key_manager == "CUSTOMER" and not rotation_enabled:
            return self.create_finding(
                resource=resource,
                custom_description=f"KMS Key '{resource.id}' (Alias: {resource.name}) does not have automatic annual rotation enabled.",
                metadata={"key_id": resource.id, "key_rotation": rotation_enabled}
            )
        return None


@RuleRegistry.register
class VPCFlowLogsRule(BaseRule):
    rule_id = "CIS-3.9"
    rule_name = "Ensure VPC Flow Logging is enabled for all VPCs"
    severity = Severity.MEDIUM
    resource_type = ResourceType.VPC
    description = "VPC Flow Logs capture IP traffic going to and from network interfaces in your VPCs."
    impact = "Without flow logs, network anomaly detection, data exfiltration tracking, and threat investigations are severely impaired."
    remediation_guidance = "Enable VPC Flow Logs to CloudWatch Logs or S3: `aws ec2 create-flow-logs`."
    benchmark_reference = "CIS AWS Foundations v2.0 - 3.9"

    def evaluate(self, resource: CloudResource) -> Optional[Finding]:
        if resource.resource_type != ResourceType.VPC:
            return None
        flow_logs_enabled = resource.raw_config.get("flow_logs_enabled", False)
        if not flow_logs_enabled:
            return self.create_finding(
                resource=resource,
                custom_description=f"VPC '{resource.id}' ({resource.name}) lacks active VPC Flow Logging.",
                metadata={"flow_logs": flow_logs_enabled}
            )
        return None
