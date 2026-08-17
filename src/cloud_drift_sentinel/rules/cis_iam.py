"""
CIS AWS Foundations Benchmark - Section 1: Identity and Access Management (IAM) Rules.
"""

from typing import Optional
from .base import BaseRule, RuleRegistry
from ..core.models import CloudResource, Finding, Severity, ResourceType


@RuleRegistry.register
class RootAccessKeyRule(BaseRule):
    rule_id = "CIS-1.4"
    rule_name = "Ensure no root account access key exists"
    severity = Severity.CRITICAL
    resource_type = ResourceType.IAM_ACCOUNT
    description = "Root account should not possess active access keys as root possesses unrestricted administrative access."
    impact = "Compromise of root API keys allows an attacker complete control over the entire AWS cloud organization."
    remediation_guidance = "Delete all root user access keys immediately via AWS IAM console or CLI: `aws iam delete-access-key`."
    benchmark_reference = "CIS AWS Foundations v2.0 - 1.4"

    def evaluate(self, resource: CloudResource) -> Optional[Finding]:
        if resource.resource_type != ResourceType.IAM_ACCOUNT:
            return None
        has_root_key = resource.raw_config.get("root_account_has_active_key", False)
        if has_root_key:
            return self.create_finding(
                resource=resource,
                metadata={"root_keys": resource.raw_config.get("root_access_keys", [])}
            )
        return None


@RuleRegistry.register
class IAMConsoleMFARule(BaseRule):
    rule_id = "CIS-1.5"
    rule_name = "Ensure MFA is enabled for all IAM users with console passwords"
    severity = Severity.HIGH
    resource_type = ResourceType.IAM_USER
    description = "Multi-Factor Authentication (MFA) adds an extra layer of defense against compromised passwords."
    impact = "Without MFA, password compromise immediately leads to unauthorized cloud console takeover."
    remediation_guidance = "Enable hardware or virtual MFA device for user: `aws iam enable-mfa-device`."
    benchmark_reference = "CIS AWS Foundations v2.0 - 1.5"

    def evaluate(self, resource: CloudResource) -> Optional[Finding]:
        if resource.resource_type != ResourceType.IAM_USER:
            return None
        password_enabled = resource.raw_config.get("password_enabled", False)
        mfa_active = resource.raw_config.get("mfa_active", False)
        if password_enabled and not mfa_active:
            return self.create_finding(
                resource=resource,
                custom_description=f"IAM user '{resource.name}' has console password access without MFA enabled.",
                metadata={"username": resource.name}
            )
        return None


@RuleRegistry.register
class IAMWildcardAdminPolicyRule(BaseRule):
    rule_id = "CIS-1.16"
    rule_name = "Ensure IAM policies do not allow unrestricted wildcard administrative privileges"
    severity = Severity.CRITICAL
    resource_type = ResourceType.IAM_POLICY
    description = "IAM policy grants wildcard permissions ('*') across all resources ('*'), violating the principle of least privilege."
    impact = "Identities with this policy possess unrestricted superuser permissions and can modify all cloud infrastructure."
    remediation_guidance = "Scope down policy statements to specific actions and explicit ARNs instead of wildcards."
    benchmark_reference = "CIS AWS Foundations v2.0 - 1.16"

    def evaluate(self, resource: CloudResource) -> Optional[Finding]:
        if resource.resource_type not in (ResourceType.IAM_POLICY, ResourceType.IAM_ROLE):
            return None
        statements = resource.raw_config.get("policy_document", {}).get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            effect = stmt.get("Effect", "")
            action = stmt.get("Action", "")
            res = stmt.get("Resource", "")

            # Check if action contains '*' and resource is '*'
            is_wild_action = (action == "*") or (isinstance(action, list) and "*" in action)
            is_wild_res = (res == "*") or (isinstance(res, list) and "*" in res)

            if effect == "Allow" and is_wild_action and is_wild_res:
                return self.create_finding(
                    resource=resource,
                    custom_description=f"Policy '{resource.name}' contains unrestricted wildcard statement with Action: '*' and Resource: '*'.",
                    metadata={"violating_statement": stmt}
                )
        return None


@RuleRegistry.register
class IAMInactiveCredentialsRule(BaseRule):
    rule_id = "CIS-1.19"
    rule_name = "Ensure IAM credentials unused for 90 days or greater are disabled"
    severity = Severity.MEDIUM
    resource_type = ResourceType.IAM_USER
    description = "Stale credentials that have not been used in 90 days increase the attack surface if forgotten."
    impact = "Dormant credentials can be exploited without regular visibility or active monitoring."
    remediation_guidance = "Deactivate or remove unused access keys: `aws iam update-access-key --status Inactive`."
    benchmark_reference = "CIS AWS Foundations v2.0 - 1.19"

    def evaluate(self, resource: CloudResource) -> Optional[Finding]:
        if resource.resource_type != ResourceType.IAM_USER:
            return None
        keys = resource.raw_config.get("access_keys", [])
        for key in keys:
            days_unused = key.get("days_since_last_used", 0)
            status = key.get("status", "Active")
            if status == "Active" and days_unused >= 90:
                return self.create_finding(
                    resource=resource,
                    custom_description=f"IAM User '{resource.name}' has active access key '{key.get('access_key_id')}' unused for {days_unused} days.",
                    metadata={"access_key_id": key.get("access_key_id"), "days_unused": days_unused}
                )
        return None


@RuleRegistry.register
class IAMTrustWildcardPrincipalRule(BaseRule):
    rule_id = "CIS-1.22"
    rule_name = "Ensure IAM trust policies do not allow wildcard principals"
    severity = Severity.HIGH
    resource_type = ResourceType.IAM_ROLE
    description = "Role assume trust policy allows wildcard '*' principal, allowing any AWS account to assume this role."
    impact = "Allows arbitrary external AWS accounts or unauthenticated attackers to assume this IAM role."
    remediation_guidance = "Restrict the 'Principal' block in the role trust relationship to specific trusted AWS account IDs or IAM ARNs."
    benchmark_reference = "CIS AWS Foundations v2.0 - 1.22"

    def evaluate(self, resource: CloudResource) -> Optional[Finding]:
        if resource.resource_type != ResourceType.IAM_ROLE:
            return None
        assume_policy = resource.raw_config.get("assume_role_policy", {})
        statements = assume_policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            if stmt.get("Effect") == "Allow":
                principal = stmt.get("Principal", {})
                if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                    return self.create_finding(
                        resource=resource,
                        custom_description=f"Role '{resource.name}' trust policy allows wildcard principal '*', exposing the role externally.",
                        metadata={"trust_statement": stmt}
                    )
        return None
