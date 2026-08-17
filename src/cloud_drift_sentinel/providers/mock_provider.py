"""
Mock Cloud Provider: Provides simulated enterprise cloud datasets for offline testing,
evaluations, CI/CD pipelines, and local compliance demonstrations.
"""

from typing import List
from .base import BaseCloudProvider
from ..core.models import CloudResource, ResourceType


class MockCloudProvider(BaseCloudProvider):
    """
    Simulates a realistic hybrid AWS cloud environment with both secure baseline
    resources and deliberate security posture misconfigurations for testing.
    """
    provider_name = "mock-aws"

    def __init__(self, scenario: str = "default"):
        self.scenario = scenario

    def collect_resources(self) -> List[CloudResource]:
        resources: List[CloudResource] = [
            # 1. Root Account with Active Key (CRITICAL)
            CloudResource(
                id="aws-account-112233445566-root",
                name="AWS Root Account (Production)",
                resource_type=ResourceType.IAM_ACCOUNT,
                region="global",
                tags={"Environment": "Production", "Owner": "SecOps"},
                raw_config={
                    "root_account_has_active_key": True,
                    "root_access_keys": ["AKIAIOSFODNN7EXAMPLE"],
                    "account_mfa_present": True,
                },
            ),

            # 2. IAM User: Admin user without MFA and with stale key (HIGH + MEDIUM)
            CloudResource(
                id="arn:aws:iam::112233445566:user/devops_lead",
                name="devops_lead",
                resource_type=ResourceType.IAM_USER,
                region="global",
                tags={"Team": "DevOps", "Tier": "1"},
                raw_config={
                    "password_enabled": True,
                    "mfa_active": False,
                    "access_keys": [
                        {
                            "access_key_id": "AKIAI44QH8DHBEXAMPLE",
                            "status": "Active",
                            "days_since_last_used": 124,
                        }
                    ],
                },
            ),

            # 3. IAM User: Compliant Engineer (PASS)
            CloudResource(
                id="arn:aws:iam::112233445566:user/sarah_security",
                name="sarah_security",
                resource_type=ResourceType.IAM_USER,
                region="global",
                tags={"Team": "SecOps"},
                raw_config={
                    "password_enabled": True,
                    "mfa_active": True,
                    "access_keys": [
                        {
                            "access_key_id": "AKIAJ66FF8DHBEXAMPLE",
                            "status": "Active",
                            "days_since_last_used": 5,
                        }
                    ],
                },
            ),

            # 4. Over-permissive Wildcard IAM Policy (CRITICAL)
            CloudResource(
                id="arn:aws:iam::112233445566:policy/ShadowAdminFullAccess",
                name="ShadowAdminFullAccess",
                resource_type=ResourceType.IAM_POLICY,
                region="global",
                tags={"CreatedBy": "LegacyCI"},
                raw_config={
                    "policy_document": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "*",
                                "Resource": "*",
                            }
                        ],
                    }
                },
            ),

            # 5. IAM Role with Wildcard Assume Trust (HIGH)
            CloudResource(
                id="arn:aws:iam::112233445566:role/PublicCrossAccountRole",
                name="PublicCrossAccountRole",
                resource_type=ResourceType.IAM_ROLE,
                region="global",
                tags={"Purpose": "CrossAccount"},
                raw_config={
                    "assume_role_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"AWS": "*"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    }
                },
            ),

            # 6. S3 Bucket: Public ACL and No Public Access Block (CRITICAL + HIGH)
            CloudResource(
                id="arn:aws:s3:::corp-customer-analytics-prod-data",
                name="corp-customer-analytics-prod-data",
                resource_type=ResourceType.S3_BUCKET,
                region="us-east-1",
                tags={"DataClassification": "Confidential", "Department": "Analytics"},
                raw_config={
                    "public_access_block": {
                        "BlockPublicAcls": False,
                        "IgnorePublicAcls": False,
                        "BlockPublicPolicy": False,
                        "RestrictPublicBuckets": False,
                    },
                    "encryption": {},
                    "versioning": {"Status": "Suspended"},
                    "acl": {
                        "Grants": [
                            {
                                "Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
                                "Permission": "READ",
                            }
                        ]
                    },
                },
            ),

            # 7. S3 Bucket: Secure & Fully Compliant (PASS)
            CloudResource(
                id="arn:aws:s3:::corp-audit-vault-compliant",
                name="corp-audit-vault-compliant",
                resource_type=ResourceType.S3_BUCKET,
                region="us-east-1",
                tags={"Environment": "Production", "Compliance": "CIS"},
                raw_config={
                    "public_access_block": {
                        "BlockPublicAcls": True,
                        "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True,
                        "RestrictPublicBuckets": True,
                    },
                    "encryption": {
                        "ServerSideEncryptionConfiguration": {
                            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]
                        }
                    },
                    "versioning": {"Status": "Enabled"},
                    "acl": {"Grants": []},
                },
            ),

            # 8. Security Group: Exposed SSH (22) and RDP (3389) to 0.0.0.0/0 (CRITICAL)
            CloudResource(
                id="sg-01a2b3c4d5e6f7001",
                name="launch-wizard-legacy-web",
                resource_type=ResourceType.SECURITY_GROUP,
                region="us-east-1",
                tags={"Environment": "Development"},
                raw_config={
                    "VpcId": "vpc-0987654321fedcba0",
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        },
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 3389,
                            "ToPort": 3389,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        },
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 80,
                            "ToPort": 80,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        },
                    ],
                },
            ),

            # 9. Security Group: Exposed PostgreSQL Database Port 5432 (HIGH)
            CloudResource(
                id="sg-01a2b3c4d5e6f7002",
                name="db-postgres-cluster-sg",
                resource_type=ResourceType.SECURITY_GROUP,
                region="us-east-1",
                tags={"Tier": "Database"},
                raw_config={
                    "VpcId": "vpc-0987654321fedcba0",
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 5432,
                            "ToPort": 5432,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        }
                    ],
                },
            ),

            # 10. Security Group: Fully Hardened Internal SG (PASS)
            CloudResource(
                id="sg-01a2b3c4d5e6f7003",
                name="internal-microservice-hardened-sg",
                resource_type=ResourceType.SECURITY_GROUP,
                region="us-east-1",
                tags={"Tier": "Backend", "Hardened": "True"},
                raw_config={
                    "VpcId": "vpc-0987654321fedcba0",
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 8080,
                            "ToPort": 8080,
                            "IpRanges": [{"CidrIp": "10.0.0.0/16"}],
                        }
                    ],
                },
            ),

            # 11. RDS Database: Unencrypted Storage (HIGH)
            CloudResource(
                id="arn:aws:rds:us-east-1:112233445566:db:corp-legacy-mysql-primary",
                name="corp-legacy-mysql-primary",
                resource_type=ResourceType.RDS_INSTANCE,
                region="us-east-1",
                tags={"Engine": "MySQL", "Environment": "Production"},
                raw_config={
                    "engine": "mysql",
                    "storage_encrypted": False,
                    "publicly_accessible": False,
                },
            ),

            # 12. CloudTrail: Single Region & Missing Log File Validation (HIGH + MEDIUM)
            CloudResource(
                id="arn:aws:cloudtrail:us-east-1:112233445566:trail/management-trail",
                name="management-trail",
                resource_type=ResourceType.CLOUDTRAIL,
                region="us-east-1",
                tags={"Compliance": "Legacy"},
                raw_config={
                    "IsMultiRegionTrail": False,
                    "LogFileValidationEnabled": False,
                    "IsLogging": True,
                },
            ),

            # 13. KMS Key: Missing Rotation (MEDIUM)
            CloudResource(
                id="arn:aws:kms:us-east-1:112233445566:key/c0987654-1234-abcd-ef01-234567890abc",
                name="alias/app-master-encryption-key",
                resource_type=ResourceType.KMS_KEY,
                region="us-east-1",
                tags={"ManagedBy": "Terraform"},
                raw_config={
                    "KeyManager": "CUSTOMER",
                    "KeyRotationEnabled": False,
                    "Enabled": True,
                },
            ),

            # 14. Default VPC with Active Compute (LOW)
            CloudResource(
                id="vpc-default-0123456789",
                name="vpc-default",
                resource_type=ResourceType.VPC,
                region="us-east-1",
                tags={"Name": "Default VPC"},
                raw_config={
                    "is_default": True,
                    "cidr_block": "172.31.0.0/16",
                    "flow_logs_enabled": False,
                    "active_instances_count": 4,
                },
            ),
        ]
        return resources
