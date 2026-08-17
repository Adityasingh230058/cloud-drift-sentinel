"""
CIS AWS Foundations Benchmark - Section 4 & 5: Networking and Security Group Perimeter Rules.
"""

from typing import Optional, List, Dict, Any
from .base import BaseRule, RuleRegistry
from ..core.models import CloudResource, Finding, Severity, ResourceType


def _check_open_ingress(ip_permissions: List[Dict[str, Any]], target_ports: List[int]) -> List[Dict[str, Any]]:
    """Checks if any IP permission rule allows 0.0.0.0/0 or ::/0 on target ports."""
    violating_rules = []
    for perm in ip_permissions:
        from_port = perm.get("FromPort")
        to_port = perm.get("ToPort")
        ip_protocol = perm.get("IpProtocol", "")

        # Check if target port falls in range
        is_port_match = False
        if ip_protocol == "-1":  # All traffic
            is_port_match = True
        elif from_port is not None and to_port is not None:
            for p in target_ports:
                if from_port <= p <= to_port:
                    is_port_match = True
                    break

        if not is_port_match:
            continue

        # Check IP ranges
        ip_ranges = [r.get("CidrIp") for r in perm.get("IpRanges", [])]
        ipv6_ranges = [r.get("CidrIpv6") for r in perm.get("Ipv6Ranges", [])]

        if "0.0.0.0/0" in ip_ranges or "::/0" in ipv6_ranges:
            violating_rules.append(perm)

    return violating_rules


@RuleRegistry.register
class SecurityGroupSSHExposureRule(BaseRule):
    rule_id = "CIS-4.1"
    rule_name = "Ensure no Security Group allows ingress from 0.0.0.0/0 to port 22 (SSH)"
    severity = Severity.CRITICAL
    resource_type = ResourceType.SECURITY_GROUP
    description = "Security group rules allow unrestricted global inbound traffic to SSH port 22."
    impact = "Exposes SSH services directly to internet-wide brute force attacks, credential spraying, and remote exploits."
    remediation_guidance = "Restrict port 22 access to specific corporate IP CIDRs or use AWS Systems Manager (SSM) Session Manager."
    benchmark_reference = "CIS AWS Foundations v2.0 - 4.1"

    def evaluate(self, resource: CloudResource) -> Optional[Finding]:
        if resource.resource_type != ResourceType.SECURITY_GROUP:
            return None
        ip_permissions = resource.raw_config.get("IpPermissions", [])
        violating = _check_open_ingress(ip_permissions, [22])
        if violating:
            return self.create_finding(
                resource=resource,
                custom_description=f"Security Group '{resource.name}' ({resource.id}) allows unrestricted SSH (port 22) ingress from 0.0.0.0/0.",
                metadata={"violating_rules": violating}
            )
        return None


@RuleRegistry.register
class SecurityGroupRDPExposureRule(BaseRule):
    rule_id = "CIS-4.2"
    rule_name = "Ensure no Security Group allows ingress from 0.0.0.0/0 to port 3389 (RDP)"
    severity = Severity.CRITICAL
    resource_type = ResourceType.SECURITY_GROUP
    description = "Security group rules allow unrestricted global inbound traffic to Remote Desktop Protocol (RDP) port 3389."
    impact = "Directly exposes Windows instances to BlueKeep, ransomware vectors, and automated credential stuffing."
    remediation_guidance = "Remove 0.0.0.0/0 ingress for port 3389 and mandate VPN / Bastion host access."
    benchmark_reference = "CIS AWS Foundations v2.0 - 4.2"

    def evaluate(self, resource: CloudResource) -> Optional[Finding]:
        if resource.resource_type != ResourceType.SECURITY_GROUP:
            return None
        ip_permissions = resource.raw_config.get("IpPermissions", [])
        violating = _check_open_ingress(ip_permissions, [3389])
        if violating:
            return self.create_finding(
                resource=resource,
                custom_description=f"Security Group '{resource.name}' ({resource.id}) allows unrestricted RDP (port 3389) ingress from 0.0.0.0/0.",
                metadata={"violating_rules": violating}
            )
        return None


@RuleRegistry.register
class SecurityGroupDatabaseExposureRule(BaseRule):
    rule_id = "CIS-4.3"
    rule_name = "Ensure no Security Group allows public ingress to Database ports"
    severity = Severity.HIGH
    resource_type = ResourceType.SECURITY_GROUP
    description = "Security group allows public 0.0.0.0/0 ingress to database ports (3306, 5432, 27017, 1433, 6379)."
    impact = "Exposes database listeners to external unauthorized connection attempts and potential data leaks."
    remediation_guidance = "Restrict database ports to application subnet CIDRs or application security group IDs."
    benchmark_reference = "CIS AWS Foundations v2.0 - 4.3"

    def evaluate(self, resource: CloudResource) -> Optional[Finding]:
        if resource.resource_type != ResourceType.SECURITY_GROUP:
            return None
        db_ports = [3306, 5432, 27017, 1433, 6379]  # MySQL, Postgres, MongoDB, MSSQL, Redis
        ip_permissions = resource.raw_config.get("IpPermissions", [])
        violating = _check_open_ingress(ip_permissions, db_ports)
        if violating:
            return self.create_finding(
                resource=resource,
                custom_description=f"Security Group '{resource.name}' ({resource.id}) allows public 0.0.0.0/0 ingress to sensitive database ports.",
                metadata={"violating_rules": violating}
            )
        return None


@RuleRegistry.register
class DefaultVPCInUseRule(BaseRule):
    rule_id = "CIS-4.4"
    rule_name = "Ensure Default VPC is not actively deployed for production workloads"
    severity = Severity.LOW
    resource_type = ResourceType.VPC
    description = "The default VPC contains public subnets with internet gateways attached by default, lacking isolated network tiers."
    impact = "Deploying workloads in the default VPC increases accidental public exposure risks."
    remediation_guidance = "Create custom multi-tier VPCs with dedicated private and public subnets, NAT gateways, and flow logs."
    benchmark_reference = "CIS AWS Foundations v2.0 - 4.4"

    def evaluate(self, resource: CloudResource) -> Optional[Finding]:
        if resource.resource_type != ResourceType.VPC:
            return None
        is_default = resource.raw_config.get("is_default", False)
        has_instances = resource.raw_config.get("active_instances_count", 0) > 0
        if is_default and has_instances:
            return self.create_finding(
                resource=resource,
                custom_description=f"Default VPC '{resource.id}' is actively hosting running production compute instances.",
                metadata={"active_instances": resource.raw_config.get("active_instances_count", 0)}
            )
        return None
