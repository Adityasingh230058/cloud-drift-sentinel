"""
Unit tests for SentinelEngine, compliance score calculation, and report generators.
"""

import os
import pytest
from cloud_drift_sentinel.core.engine import SentinelEngine
from cloud_drift_sentinel.core.models import Severity
from cloud_drift_sentinel.providers.mock_provider import MockCloudProvider
from cloud_drift_sentinel.reports.html_report import HTMLReporter
from cloud_drift_sentinel.remediation.generator import RemediationGenerator


def test_engine_scan_with_mock_provider():
    provider = MockCloudProvider()
    engine = SentinelEngine(provider=provider)

    result = engine.run_scan()

    assert result.provider == "mock-aws"
    assert len(result.resources) > 0
    assert len(result.findings) > 0

    summary = result.summary
    assert summary.critical_count > 0
    assert summary.high_count > 0
    assert summary.compliance_score < 100.0
    assert summary.total_findings == len(result.findings)


def test_html_report_generation(tmp_path):
    provider = MockCloudProvider()
    engine = SentinelEngine(provider=provider)
    result = engine.run_scan()

    html_file = os.path.join(tmp_path, "report.html")
    generated_path = HTMLReporter.generate_html_report(result, html_file)

    assert os.path.exists(generated_path)
    with open(generated_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "Cloud Drift Sentinel" in content
    assert "chart.js" in content.lower()
    assert "findingsBody" in content


def test_remediation_generation(tmp_path):
    provider = MockCloudProvider()
    engine = SentinelEngine(provider=provider)
    result = engine.run_scan()

    out_dir = os.path.join(tmp_path, "remediation")
    scripts = RemediationGenerator.generate_remediation_suite(result.findings, out_dir)

    assert "remediate_aws_findings.sh" in scripts
    assert "remediate_aws_findings.py" in scripts
    assert os.path.exists(os.path.join(out_dir, "remediate_aws_findings.sh"))
    assert os.path.exists(os.path.join(out_dir, "remediate_aws_findings.py"))
