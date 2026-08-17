<div align="center">

# 🛡️ Cloud Drift Sentinel
### Automated Multi-Cloud Security Posture Management (CSPM) & Infrastructure Drift Detection Engine

[![CI Build](https://img.shields.io/badge/CI-GitHub%20Actions-blue.svg)](.github/workflows/ci.yml)
[![Python Version](https://img.shields.io/badge/Python-3.9%20|%203.10%20|%203.11%20|%203.12-brightgreen.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Benchmark](https://img.shields.io/badge/Benchmark-CIS%20AWS%20v2.0-orange.svg)](https://www.cisecurity.org/benchmark/amazon_web_services)
[![Code Style](https://img.shields.io/badge/Code%20Style-Black-000000.svg)](https://github.com/psf/black)

**`cloud-drift-sentinel`** is a production-grade Cloud Security Posture Management (CSPM) and Infrastructure Drift Auditing engine designed for DevOps and Cloud Security teams. It continuously evaluates live cloud assets (IAM, S3, Security Groups, RDS, KMS, CloudTrail) against **CIS Foundations Benchmarks**, isolates unauthorized manual drift from IaC Golden State baselines, and generates actionable automated remediation playbooks alongside interactive executive dashboards.

</div>

---

## 🌟 Key Highlights

- 🔍 **Multi-Service CIS Audit**: Scans IAM accounts, access keys, wildcard policies, public S3 buckets, open security groups (0.0.0.0/0), unencrypted databases, and logging pipelines.
- ⚡ **Deep Infrastructure Drift Engine**: Compares observed cloud state against Golden Baseline IaC definitions (`ADDED`, `REMOVED`, `MODIFIED` configurations).
- 🛠️ **Automated Remediation Generator**: Automatically creates executable **Python (Boto3)** and **Bash (AWS CLI)** remediation playbooks to instantly close security gaps.
- 📊 **Executive HTML Report & Live CLI Dashboard**: Generates responsive, glassmorphic HTML security reports with interactive Chart.js analytics, risk filters, and terminal gauges.
- 🧪 **Zero-Cost Simulation / Mock Engine**: Includes built-in simulated enterprise telemetry so developers can test rules and drift workflows without requiring cloud credentials or billing.
- 🚀 **CI/CD Ready**: Native GitHub Actions pipeline testing multi-Python versions (3.10, 3.11, 3.12).

---

## 🏛️ Architecture Overview

```
                      ┌─────────────────────────────────┐
                      │    Cloud Drift Sentinel CLI     │
                      └────────────────┬────────────────┘
                                       │
                ┌──────────────────────┴──────────────────────┐
                ▼                                             ▼
     ┌──────────────────────┐                      ┌──────────────────────┐
     │  AWS Live Provider   │                      │  Mock Cloud Provider │
     │ (IAM, S3, EC2, RDS)  │                      │ (Offline Simulation) │
     └──────────┬───────────┘                      └──────────┬───────────┘
                │                                             │
                └──────────────────────┬──────────────────────┘
                                       ▼
                       ┌───────────────────────────────┐
                       │    Sentinel Core Engine       │
                       └───────┬───────────────┬───────┘
                               │               │
        ┌──────────────────────▼───────┐       └──────────────────────┐
        │  CIS Benchmark Rule Registry │                              │
        │  (IAM, Storage, Network, Gov)│                              │
        └──────────────┬───────────────┘                              │
                       │                                              │
                       ▼                                              ▼
        ┌──────────────────────────────┐              ┌───────────────────────────────┐
        │    Security Findings &       │              │    Golden Baseline Drift      │
        │    Compliance Score (0-100%) │              │    Comparator (Added/Mod/Del) │
        └──────────────┬───────────────┘              └───────────────┬───────────────┘
                       │                                              │
                       └──────────────────────┬───────────────────────┘
                                              ▼
                     ┌─────────────────────────────────────────────────┐
                     │              Output Artifacts                   │
                     ├─────────────────────────┬───────────────────────┤
                     │ 📊 Interactive HTML UI  │ 🖥️ Rich Console Table │
                     │ 📜 Auto-Remediation     │ 📦 JSON Telemetry     │
                     └─────────────────────────┴───────────────────────┘
```

---

## 📋 Evaluated CIS Benchmark Rules

| Rule ID | Domain | Severity | Description |
| :--- | :--- | :---: | :--- |
| **CIS-1.4** | **IAM** | `CRITICAL` | Ensure no root account active access keys exist |
| **CIS-1.5** | **IAM** | `HIGH` | Ensure MFA is enabled for all IAM console users |
| **CIS-1.16**| **IAM** | `CRITICAL` | Ensure IAM policies do not allow unrestricted wildcard `*` admin privileges |
| **CIS-1.19**| **IAM** | `MEDIUM` | Ensure stale IAM credentials unused for ≥90 days are deactivated |
| **CIS-1.22**| **IAM** | `HIGH` | Ensure IAM trust policies do not allow wildcard `*` principals |
| **CIS-2.1.1**| **Storage** | `HIGH` | Ensure S3 buckets enforce S3 Public Access Block settings |
| **CIS-2.1.2**| **Storage** | `HIGH` | Ensure S3 bucket default server-side encryption is enabled |
| **CIS-2.1.3**| **Storage** | `CRITICAL` | Ensure S3 buckets do not have public Read/Write ACLs or bucket policies |
| **CIS-2.1.4**| **Storage** | `LOW` | Ensure S3 bucket object versioning is enabled |
| **CIS-2.3.1**| **Database**| `HIGH` | Ensure RDS DB instances have encryption at rest enabled |
| **CIS-4.1** | **Network** | `CRITICAL` | Ensure no security group allows `0.0.0.0/0` ingress to port 22 (SSH) |
| **CIS-4.2** | **Network** | `CRITICAL` | Ensure no security group allows `0.0.0.0/0` ingress to port 3389 (RDP) |
| **CIS-4.3** | **Network** | `HIGH` | Ensure no security group allows `0.0.0.0/0` ingress to database ports |
| **CIS-4.4** | **Network** | `LOW` | Ensure default VPC is not actively hosting production compute |
| **CIS-3.1** | **Governance**| `HIGH` | Ensure CloudTrail is enabled across all regions |
| **CIS-3.2** | **Governance**| `MEDIUM` | Ensure CloudTrail log file cryptographic validation is enabled |
| **CIS-3.7** | **Governance**| `MEDIUM` | Ensure AWS KMS Customer Managed Keys have automatic annual rotation |
| **CIS-3.9** | **Governance**| `MEDIUM` | Ensure VPC Flow Logging is active for all VPC networks |

---

## ⚡ Quickstart

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/Adityasingh230058/cloud-drift-sentinel.git
cd cloud-drift-sentinel

# Install dependencies in editable mode
pip install -e .
```

---

## 💻 CLI Usage & Examples

### 1. Run Offline Simulation Scan (Zero-Cost Mode)
Run a complete posture audit with interactive HTML report, JSON export, and automated remediation scripts:

```bash
cloud-drift-sentinel scan --mock \
  --html report.html \
  --json scan_result.json \
  --remediate ./remediation_scripts
```

### 2. Run Live AWS Cloud Scan
Scan a live AWS account using your configured AWS CLI profile or default credentials:

```bash
# Scan default region
cloud-drift-sentinel scan --region us-east-1 --html aws_audit.html

# Scan with named profile and generate remediation code
cloud-drift-sentinel scan --profile production --region eu-west-1 --remediate ./playbooks
```

### 3. Golden State Baseline & Drift Detection

```bash
# Step 1: Snapshot current healthy cloud state into a baseline
cloud-drift-sentinel baseline --output samples/baseline_config.json --mock

# Step 2: Periodically compare live cloud state against golden baseline to detect manual drift
cloud-drift-sentinel drift --baseline samples/baseline_config.json --mock
```

### 4. List Registered CIS Rules

```bash
cloud-drift-sentinel rules
```

---

## 🧪 Testing

Execute the comprehensive test suite:

```bash
# Run pytest with coverage report
pytest --cov=cloud_drift_sentinel --cov-report=term-missing tests/
```

---

## 📂 Repository Structure

```
cloud-drift-sentinel/
├── .github/
│   └── workflows/
│       └── ci.yml                 # Automated CI test matrix
├── src/
│   └── cloud_drift_sentinel/
│       ├── __init__.py
│       ├── cli.py                 # Rich interactive CLI entrypoint
│       ├── core/
│       │   ├── models.py          # Data models: Findings, Resources, DriftRecords
│       │   ├── engine.py          # Posture evaluation & scoring engine
│       │   └── baseline.py        # IaC baseline snapshot & drift diff logic
│       ├── providers/
│       │   ├── base.py            # Base provider interface
│       │   ├── aws.py             # Live AWS Boto3 scanner
│       │   └── mock_provider.py   # Offline enterprise simulation telemetry
│       ├── rules/
│       │   ├── base.py            # Rule registry & base class
│       │   ├── cis_iam.py         # CIS Section 1: IAM rules
│       │   ├── cis_storage.py     # CIS Section 2: S3 & RDS rules
│       │   ├── cis_network.py     # CIS Section 4: Security Groups & VPC rules
│       │   └── cis_governance.py  # CIS Section 3: CloudTrail & KMS rules
│       ├── remediation/
│       │   └── generator.py       # Automated Python & Bash remediation generator
│       └── reports/
│           ├── console.py         # Rich terminal output formatting
│           └── html_report.py     # Responsive glassmorphism HTML dashboard
├── tests/
│   ├── test_rules.py              # Rule evaluations
│   ├── test_drift.py              # Baseline comparison & drift isolation
│   ├── test_engine.py             # End-to-end scanning & scoring
│   └── test_cli.py                # CLI runner tests
├── samples/
│   ├── baseline_config.json       # Sample Golden State IaC baseline
│   └── drifted_cloud_state.json   # Sample drifted cloud configuration
├── pyproject.toml                 # Package configuration
├── requirements.txt               # Dependencies
└── README.md                      # Documentation
```

---

## 📜 License

Distributed under the **MIT License**. See `LICENSE` for more information.

---

<div align="center">
  <sub>Built with ❤️ by <strong>Aditya Singh</strong> as part of the 30-Day Cloud, Cyber Security & Data Engineering Challenge.</sub>
</div>
