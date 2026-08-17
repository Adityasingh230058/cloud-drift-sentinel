"""
Automated Remediation Generator: Produces production-ready AWS CLI and Python Boto3
scripts to quickly fix detected misconfigurations and security posture drifts.
"""

from typing import List, Dict, Any
import os
from ..core.models import Finding, Severity


class RemediationGenerator:
    """
    Generates actionable remediation code files tailored to discovered findings.
    """

    @classmethod
    def generate_remediation_suite(cls, findings: List[Finding], output_dir: str) -> Dict[str, str]:
        """
        Generates bash and python remediation scripts for critical and high severity findings.
        Returns a dictionary of filename -> content.
        """
        os.makedirs(output_dir, exist_ok=True)
        scripts = {}

        # 1. AWS CLI Bash Script
        bash_lines = [
            "#!/usr/bin/env bash",
            "# ==================================================================",
            "# Cloud Drift Sentinel - Automated AWS Security Remediation Script",
            "# Generated automatically based on active security posture audit",
            "# ==================================================================",
            "set -euo pipefail",
            "echo '[*] Starting Cloud Drift Sentinel automated remediation...'",
            "",
        ]

        # 2. Python Boto3 Script
        py_lines = [
            "#!/usr/bin/env python3",
            '"""',
            "Cloud Drift Sentinel - Python Boto3 Remediation Playbook",
            "Executes automated fixes for critical cloud security findings.",
            '"""',
            "import boto3",
            "from botocore.exceptions import ClientError",
            "",
            "def main():",
            '    print("[*] Initiating Boto3 Cloud Sentinel Remediation...")',
            '    session = boto3.Session()',
            "",
        ]

        for finding in findings:
            if finding.severity not in (Severity.CRITICAL, Severity.HIGH):
                continue

            rule_id = finding.rule_id
            res_id = finding.resource_id
            region = finding.region if finding.region != "global" else "us-east-1"

            if rule_id == "CIS-2.1.1" or rule_id == "CIS-2.1.3":
                # S3 Public Access Remediation
                bucket_name = res_id.replace("arn:aws:s3:::", "")
                bash_lines.append(f"# Remediation for {finding.rule_name} on bucket: {bucket_name}")
                bash_lines.append(f"echo '[+] Enabling Public Access Block on {bucket_name}...'")
                bash_lines.append(
                    f"aws s3control put-public-access-block --account-id $(aws sts get-caller-identity --query Account --output text) "
                    f"--public-access-block-configuration 'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true' 2>/dev/null || "
                    f"aws s3api put-public-access-block --bucket {bucket_name} "
                    f"--public-access-block-configuration 'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'"
                )
                bash_lines.append("")

                py_lines.append(f"    # Fix S3 Public Access: {bucket_name}")
                py_lines.append(f"    try:")
                py_lines.append(f"        s3 = session.client('s3', region_name='{region}')")
                py_lines.append(f"        s3.put_public_access_block(")
                py_lines.append(f"            Bucket='{bucket_name}',")
                py_lines.append(f"            PublicAccessBlockConfiguration={{")
                py_lines.append(f"                'BlockPublicAcls': True, 'IgnorePublicAcls': True,")
                py_lines.append(f"                'BlockPublicPolicy': True, 'RestrictPublicBuckets': True")
                py_lines.append(f"            }}")
                py_lines.append(f"        )")
                py_lines.append(f"        print('[✓] Enforced Public Access Block on {bucket_name}')")
                py_lines.append(f"    except ClientError as e:")
                py_lines.append(f"        print(f'[!] Failed to update {bucket_name}: {{e}}')")
                py_lines.append("")

            elif rule_id in ("CIS-4.1", "CIS-4.2", "CIS-4.3"):
                # Security Group Remediation
                sg_id = res_id
                violating_rules = finding.metadata.get("violating_rules", [])
                for v in violating_rules:
                    f_port = v.get("FromPort", 22)
                    t_port = v.get("ToPort", 22)
                    proto = v.get("IpProtocol", "tcp")
                    bash_lines.append(f"# Revoke open {proto} {f_port}-{t_port} on {sg_id}")
                    bash_lines.append(
                        f"aws ec2 revoke-security-group-ingress --group-id {sg_id} --region {region} "
                        f"--protocol {proto} --port {f_port} --cidr 0.0.0.0/0 || true"
                    )
                    bash_lines.append("")

                    py_lines.append(f"    # Revoke open ingress on {sg_id}")
                    py_lines.append(f"    try:")
                    py_lines.append(f"        ec2 = session.client('ec2', region_name='{region}')")
                    py_lines.append(f"        ec2.revoke_security_group_ingress(")
                    py_lines.append(f"            GroupId='{sg_id}',")
                    py_lines.append(f"            IpProtocol='{proto}',")
                    py_lines.append(f"            FromPort={f_port},")
                    py_lines.append(f"            ToPort={t_port},")
                    py_lines.append(f"            CidrIp='0.0.0.0/0'")
                    py_lines.append(f"        )")
                    py_lines.append(f"        print('[✓] Revoked 0.0.0.0/0 port {f_port} on {sg_id}')")
                    py_lines.append(f"    except ClientError as e:")
                    py_lines.append(f"        print(f'[!] Failed to revoke SG {sg_id}: {{e}}')")
                    py_lines.append("")

            elif rule_id == "CIS-3.7":
                # KMS Rotation
                key_id = finding.metadata.get("key_id", res_id)
                bash_lines.append(f"# Enable automatic KMS key rotation on {key_id}")
                bash_lines.append(f"aws kms enable-key-rotation --key-id {key_id} --region {region}")
                bash_lines.append("")

                py_lines.append(f"    # Enable KMS key rotation: {key_id}")
                py_lines.append(f"    try:")
                py_lines.append(f"        kms = session.client('kms', region_name='{region}')")
                py_lines.append(f"        kms.enable_key_rotation(KeyId='{key_id}')")
                py_lines.append(f"        print('[✓] Enabled key rotation on KMS key {key_id}')")
                py_lines.append(f"    except ClientError as e:")
                py_lines.append(f"        print(f'[!] Failed to enable KMS rotation for {key_id}: {{e}}')")
                py_lines.append("")

        bash_lines.append("echo '[✓] Remediation sequence finished.'")
        py_lines.append("    print('[✓] Remediation sequence finished.')")
        py_lines.append("")
        py_lines.append("if __name__ == '__main__':")
        py_lines.append("    main()")

        bash_script = "\n".join(bash_lines)
        py_script = "\n".join(py_lines)

        bash_path = os.path.join(output_dir, "remediate_aws_findings.sh")
        py_path = os.path.join(output_dir, "remediate_aws_findings.py")

        with open(bash_path, "w", encoding="utf-8") as f:
            f.write(bash_script)
        with open(py_path, "w", encoding="utf-8") as f:
            f.write(py_script)

        scripts["remediate_aws_findings.sh"] = bash_script
        scripts["remediate_aws_findings.py"] = py_script

        return scripts
