"""
CIS AWS Foundations Benchmark - Section 2: Storage and Data Protection (S3, EBS, RDS) Rules.
"""

from typing import Optional
from .base import BaseRule, RuleRegistry
from ..core.models import CloudResource, Finding, Severity, ResourceType


@RuleRegistry.register
class S3PublicAccessBlockRule(BaseRule):
    rule_id = "CIS-2.1.1"
    rule_name = "Ensure S3 Buckets have Public Access Block configuration enabled"
    severity = Severity.HIGH
    resource_type = ResourceType.S3_BUCKET
    description = "S3 Public Access Block settings override permissive ACLs and policies to prevent public data exposure."
    impact = "Without Public Access Block, accidental ACL changes or bucket policy mistakes can expose private company data publicly."
    remediation_guidance = "Enable all 4 S3 Public Access Block flags: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets."
    benchmark_reference = "CIS AWS Foundations v2.0 - 2.1.1"

    def evaluate(self, resource: CloudResource) -> Optional[Finding]:
        if resource.resource_type != ResourceType.S3_BUCKET:
            return None
        pab = resource.raw_config.get("public_access_block", {})
        block_acls = pab.get("BlockPublicAcls", False)
        block_policy = pab.get("BlockPublicPolicy", False)
        ignore_acls = pab.get("IgnorePublicAcls", False)
        restrict_public = pab.get("RestrictPublicBuckets", False)

        if not (block_acls and block_policy and ignore_acls and restrict_public):
            return self.create_finding(
                resource=resource,
                custom_description=f"S3 Bucket '{resource.name}' does not have all 4 S3 Public Access Block settings enabled.",
                metadata={"public_access_block_config": pab}
            )
        return None


@RuleRegistry.register
class S3DefaultEncryptionRule(BaseRule):
    rule_id = "CIS-2.1.2"
    rule_name = "Ensure S3 Bucket default encryption is enabled"
    severity = Severity.HIGH
    resource_type = ResourceType.S3_BUCKET
    description = "S3 buckets should enforce server-side encryption (SSE-S3 or SSE-KMS) for all stored objects."
    impact = "Unencrypted objects are vulnerable to unauthorized access if raw storage media is inspected or compliance audits fail."
    remediation_guidance = "Configure default server-side encryption on the bucket using AES256 or AWS KMS: `aws s3api put-bucket-encryption`."
    benchmark_reference = "CIS AWS Foundations v2.0 - 2.1.2"

    def evaluate(self, resource: CloudResource) -> Optional[Finding]:
        if resource.resource_type != ResourceType.S3_BUCKET:
            return None
        encryption = resource.raw_config.get("encryption", {})
        rules = encryption.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        if not rules:
            return self.create_finding(
                resource=resource,
                custom_description=f"S3 Bucket '{resource.name}' lacks default server-side encryption configuration.",
                metadata={"encryption_config": encryption}
            )
        return None


@RuleRegistry.register
class S3PublicPolicyOrACLRule(BaseRule):
    rule_id = "CIS-2.1.3"
    rule_name = "Ensure S3 Bucket does not allow public Read or Write access"
    severity = Severity.CRITICAL
    resource_type = ResourceType.S3_BUCKET
    description = "S3 bucket policy or ACL explicitly allows public/anonymous Read, Write, or List permissions."
    impact = "Confidential data can be exfiltrated, downloaded, or overwritten by any unauthenticated Internet user."
    remediation_guidance = "Remove public grants from Bucket ACL and remove `Principal: '*'` statements with `Effect: 'Allow'`."
    benchmark_reference = "CIS AWS Foundations v2.0 - 2.1.3"

    def evaluate(self, resource: CloudResource) -> Optional[Finding]:
        if resource.resource_type != ResourceType.S3_BUCKET:
            return None
        
        # Check ACL
        acl_grants = resource.raw_config.get("acl", {}).get("Grants", [])
        for grant in acl_grants:
            grantee = grant.get("Grantee", {})
            uri = grantee.get("URI", "")
            if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                return self.create_finding(
                    resource=resource,
                    custom_description=f"S3 Bucket '{resource.name}' has public ACL grant ({grant.get('Permission')}) for {uri}.",
                    metadata={"violating_grant": grant}
                )

        # Check Bucket Policy
        policy = resource.raw_config.get("policy", {})
        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            if stmt.get("Effect") == "Allow":
                principal = stmt.get("Principal", "")
                if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                    # Check condition
                    condition = stmt.get("Condition", {})
                    if not condition:
                        return self.create_finding(
                            resource=resource,
                            custom_description=f"S3 Bucket '{resource.name}' policy contains public statement granting '{stmt.get('Action')}' to '*'.",
                            metadata={"violating_statement": stmt}
                        )

        return None


@RuleRegistry.register
class S3VersioningRule(BaseRule):
    rule_id = "CIS-2.1.4"
    rule_name = "Ensure S3 Bucket has Versioning enabled"
    severity = Severity.LOW
    resource_type = ResourceType.S3_BUCKET
    description = "Versioning keeps multiple versions of an object in the same bucket, protecting against accidental deletion or ransomware."
    impact = "Accidental object overwrites or malicious deletions cannot be restored without version history."
    remediation_guidance = "Enable versioning on the S3 bucket: `aws s3api put-bucket-versioning --status Enabled`."
    benchmark_reference = "CIS AWS Foundations v2.0 - 2.1.4"

    def evaluate(self, resource: CloudResource) -> Optional[Finding]:
        if resource.resource_type != ResourceType.S3_BUCKET:
            return None
        versioning_status = resource.raw_config.get("versioning", {}).get("Status", "Disabled")
        if versioning_status != "Enabled":
            return self.create_finding(
                resource=resource,
                custom_description=f"S3 Bucket '{resource.name}' does not have object versioning enabled (Status: {versioning_status}).",
                metadata={"versioning_status": versioning_status}
            )
        return None


@RuleRegistry.register
class RDSEncryptionAtRestRule(BaseRule):
    rule_id = "CIS-2.3.1"
    rule_name = "Ensure RDS Database instances have encryption at rest enabled"
    severity = Severity.HIGH
    resource_type = ResourceType.RDS_INSTANCE
    description = "RDS database instances must use AWS KMS keys to encrypt underlying storage, automated backups, and snapshots."
    impact = "Unencrypted database volumes pose significant compliance risks and risk data compromise upon physical storage decommission."
    remediation_guidance = "Create an encrypted snapshot of the database and restore it to a new encrypted DB instance."
    benchmark_reference = "CIS AWS Foundations v2.0 - 2.3.1"

    def evaluate(self, resource: CloudResource) -> Optional[Finding]:
        if resource.resource_type != ResourceType.RDS_INSTANCE:
            return None
        encrypted = resource.raw_config.get("storage_encrypted", False)
        if not encrypted:
            return self.create_finding(
                resource=resource,
                custom_description=f"RDS Instance '{resource.name}' ({resource.id}) is not encrypted at rest.",
                metadata={"engine": resource.raw_config.get("engine", "unknown")}
            )
        return None
