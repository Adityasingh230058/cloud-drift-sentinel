"""
Orchestrator and Rule Execution Engine for Cloud Drift Sentinel.
"""

import datetime
from typing import List, Optional
from .models import CloudResource, Finding, ScanSummary, ScanResult, Severity, DriftRecord
from .baseline import BaselineManager
from ..providers.base import BaseCloudProvider
from ..rules.base import RuleRegistry
import cloud_drift_sentinel.rules  # Ensure all rules are loaded and registered


class SentinelEngine:
    """
    Core engine that coordinates inventory collection, rule execution,
    baseline drift comparison, and score aggregation.
    """

    def __init__(self, provider: BaseCloudProvider):
        self.provider = provider

    def run_scan(self, baseline_file: Optional[str] = None) -> ScanResult:
        """
        Executes a full posture scan across the configured provider.
        """
        scan_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
        resources: List[CloudResource] = self.provider.collect_resources()
        findings: List[Finding] = []
        rules = RuleRegistry.get_all_rules()

        passed_rules_count = 0
        failed_rules_count = 0

        # Evaluate rules
        for rule in rules:
            rule_failed = False
            relevant_resources = [
                r for r in resources
                if r.resource_type == rule.resource_type or rule.resource_type.value == "cloud:generic"
            ]

            for res in relevant_resources:
                finding = rule.evaluate(res)
                if finding:
                    findings.append(finding)
                    rule_failed = True

            if relevant_resources:
                if rule_failed:
                    failed_rules_count += 1
                else:
                    passed_rules_count += 1

        # Drift calculation
        drift_records: List[DriftRecord] = []
        if baseline_file:
            baseline_resources = BaselineManager.load_baseline(baseline_file)
            drift_records = BaselineManager.compare_drift(baseline_resources, resources)

        # Calculate summary metrics
        summary = ScanSummary(
            total_resources=len(resources),
            total_findings=len(findings),
            passed_rules=passed_rules_count,
            failed_rules=failed_rules_count,
        )

        for f in findings:
            if f.severity == Severity.CRITICAL:
                summary.critical_count += 1
            elif f.severity == Severity.HIGH:
                summary.high_count += 1
            elif f.severity == Severity.MEDIUM:
                summary.medium_count += 1
            elif f.severity == Severity.LOW:
                summary.low_count += 1
            elif f.severity == Severity.INFO:
                summary.info_count += 1

        summary.calculate_score()

        return ScanResult(
            provider=self.provider.provider_name,
            scan_time=scan_time,
            resources=resources,
            findings=findings,
            drift_records=drift_records,
            summary=summary,
        )
