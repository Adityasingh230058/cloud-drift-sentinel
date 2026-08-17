"""
Unit tests for Typer CLI commands.
"""

import os
from typer.testing import CliRunner
from cloud_drift_sentinel.cli import app

runner = CliRunner()


def test_cli_rules_command():
    result = runner.invoke(app, ["rules"])
    assert result.exit_code == 0
    assert "CIS-1.4" in result.stdout
    assert "CIS-4.1" in result.stdout


def test_cli_scan_mock(tmp_path):
    html_out = os.path.join(tmp_path, "test_report.html")
    json_out = os.path.join(tmp_path, "test_report.json")
    remed_dir = os.path.join(tmp_path, "remediation_out")

    result = runner.invoke(app, [
        "scan",
        "--mock",
        "--html", html_out,
        "--json", json_out,
        "--remediate", remed_dir,
    ])

    assert result.exit_code == 0
    assert "CLOUD DRIFT SENTINEL" in result.stdout
    assert os.path.exists(html_out)
    assert os.path.exists(json_out)
    assert os.path.exists(remed_dir)


def test_cli_baseline_and_drift_mock(tmp_path):
    baseline_file = os.path.join(tmp_path, "baseline.json")

    # 1. Export Baseline
    b_result = runner.invoke(app, ["baseline", "--output", baseline_file, "--mock"])
    assert b_result.exit_code == 0
    assert os.path.exists(baseline_file)

    # 2. Check Drift against identical baseline (Zero drift expected)
    d_result = runner.invoke(app, ["drift", "--baseline", baseline_file, "--mock"])
    assert d_result.exit_code == 0
    assert "Zero drift detected" in d_result.stdout
