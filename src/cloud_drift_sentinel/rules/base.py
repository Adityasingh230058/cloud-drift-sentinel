"""
Base Rule class and registry for Cloud Drift Sentinel.
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Type, Dict
from ..core.models import CloudResource, Finding, Severity, ResourceType


class BaseRule(ABC):
    """
    Abstract Base Class for all compliance and posture rules.
    """
    rule_id: str = "CIS-0.0"
    rule_name: str = "Base Rule"
    severity: Severity = Severity.MEDIUM
    resource_type: ResourceType = ResourceType.GENERIC
    description: str = ""
    impact: str = ""
    remediation_guidance: str = ""
    benchmark_reference: str = "CIS Benchmark"

    @abstractmethod
    def evaluate(self, resource: CloudResource) -> Optional[Finding]:
        """
        Evaluates a cloud resource. Returns a Finding if non-compliant, or None if compliant.
        """
        pass

    def create_finding(
        self,
        resource: CloudResource,
        custom_description: Optional[str] = None,
        custom_impact: Optional[str] = None,
        custom_remediation: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> Finding:
        """Helper to generate a standardized Finding."""
        return Finding(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            resource_id=resource.id,
            resource_type=resource.resource_type,
            description=custom_description or self.description,
            impact=custom_impact or self.impact,
            remediation_guidance=custom_remediation or self.remediation_guidance,
            benchmark_reference=self.benchmark_reference,
            region=resource.region,
            provider=resource.provider,
            metadata=metadata or {},
        )


class RuleRegistry:
    """Registry maintaining active rules."""

    _rules: Dict[str, BaseRule] = {}

    @classmethod
    def register(cls, rule_cls: Type[BaseRule]) -> Type[BaseRule]:
        rule_instance = rule_cls()
        cls._rules[rule_instance.rule_id] = rule_instance
        return rule_cls

    @classmethod
    def get_all_rules(cls) -> List[BaseRule]:
        return list(cls._rules.values())

    @classmethod
    def get_rules_for_resource(cls, resource_type: ResourceType) -> List[BaseRule]:
        return [r for r in cls._rules.values() if r.resource_type == resource_type or r.resource_type == ResourceType.GENERIC]

    @classmethod
    def clear(cls):
        cls._rules.clear()
