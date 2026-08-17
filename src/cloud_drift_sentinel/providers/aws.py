"""
AWS Live Cloud Provider using Boto3 SDK.
"""

import datetime
from typing import List, Dict, Any, Optional
import boto3
from botocore.exceptions import ClientError, BotoCoreError

from .base import BaseCloudProvider
from ..core.models import CloudResource, ResourceType


class AWSCloudProvider(BaseCloudProvider):
    """
    Scans live AWS cloud environments across IAM, S3, EC2, RDS, KMS, and CloudTrail.
    """
    provider_name = "aws"

    def __init__(self, region_name: str = "us-east-1", profile_name: Optional[str] = None):
        self.region_name = region_name
        self.session = boto3.Session(profile_name=profile_name, region_name=region_name)

    def collect_resources(self) -> List[CloudResource]:
        resources: List[CloudResource] = []
        resources.extend(self._collect_iam_account_summary())
        resources.extend(self._collect_iam_users())
        resources.extend(self._collect_iam_roles())
        resources.extend(self._collect_s3_buckets())
        resources.extend(self._collect_security_groups())
        resources.extend(self._collect_vpcs())
        resources.extend(self._collect_rds_instances())
        resources.extend(self._collect_cloudtrail())
        resources.extend(self._collect_kms_keys())
        return resources

    def _collect_iam_account_summary(self) -> List[CloudResource]:
        try:
            iam = self.session.client("iam")
            summary = iam.get_account_summary().get("SummaryMap", {})
            has_root_key = summary.get("AccountAccessKeysPresent", 0) > 0
            return [
                CloudResource(
                    id="aws-account-root",
                    name="AWS Root Account",
                    resource_type=ResourceType.IAM_ACCOUNT,
                    region="global",
                    raw_config={
                        "root_account_has_active_key": has_root_key,
                        "account_mfa_present": summary.get("AccountMFAEnabled", 0) > 0,
                    },
                )
            ]
        except (ClientError, BotoCoreError):
            return []

    def _collect_iam_users(self) -> List[CloudResource]:
        resources = []
        try:
            iam = self.session.client("iam")
            paginator = iam.get_paginator("list_users")
            now = datetime.datetime.now(datetime.timezone.utc)

            for page in paginator.paginate():
                for user in page.get("Users", []):
                    username = user["UserName"]
                    # Check password & MFA
                    try:
                        iam.get_login_profile(UserName=username)
                        has_pwd = True
                    except ClientError:
                        has_pwd = False

                    mfa_devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
                    has_mfa = len(mfa_devices) > 0

                    # Access keys
                    access_keys = []
                    for key in iam.list_access_keys(UserName=username).get("AccessKeyMetadata", []):
                        create_date = key.get("CreateDate")
                        days_old = (now - create_date).days if create_date else 0
                        access_keys.append({
                            "access_key_id": key["AccessKeyId"],
                            "status": key["Status"],
                            "days_since_last_used": days_old,
                        })

                    resources.append(
                        CloudResource(
                            id=user["Arn"],
                            name=username,
                            resource_type=ResourceType.IAM_USER,
                            region="global",
                            raw_config={
                                "password_enabled": has_pwd,
                                "mfa_active": has_mfa,
                                "access_keys": access_keys,
                            },
                        )
                    )
        except (ClientError, BotoCoreError):
            pass
        return resources

    def _collect_iam_roles(self) -> List[CloudResource]:
        resources = []
        try:
            iam = self.session.client("iam")
            paginator = iam.get_paginator("list_roles")
            for page in paginator.paginate():
                for role in page.get("Roles", []):
                    # Skip AWS internal service-linked roles
                    if "/aws-service-role/" in role.get("Path", ""):
                        continue
                    resources.append(
                        CloudResource(
                            id=role["Arn"],
                            name=role["RoleName"],
                            resource_type=ResourceType.IAM_ROLE,
                            region="global",
                            raw_config={
                                "assume_role_policy": role.get("AssumeRolePolicyDocument", {}),
                            },
                        )
                    )
        except (ClientError, BotoCoreError):
            pass
        return resources

    def _collect_s3_buckets(self) -> List[CloudResource]:
        resources = []
        try:
            s3 = self.session.client("s3")
            buckets = s3.list_buckets().get("Buckets", [])
            for b in buckets:
                name = b["Name"]
                # Public Access Block
                pab_conf = {}
                try:
                    pab = s3.get_public_access_block(Bucket=name)
                    pab_conf = pab.get("PublicAccessBlockConfiguration", {})
                except ClientError:
                    pab_conf = {
                        "BlockPublicAcls": False,
                        "IgnorePublicAcls": False,
                        "BlockPublicPolicy": False,
                        "RestrictPublicBuckets": False,
                    }

                # Encryption
                enc_conf = {}
                try:
                    enc_conf = s3.get_bucket_encryption(Bucket=name)
                except ClientError:
                    enc_conf = {}

                # Versioning
                ver_conf = {}
                try:
                    ver_conf = s3.get_bucket_versioning(Bucket=name)
                except ClientError:
                    ver_conf = {}

                # ACL
                acl_conf = {}
                try:
                    acl_conf = s3.get_bucket_acl(Bucket=name)
                except ClientError:
                    acl_conf = {}

                resources.append(
                    CloudResource(
                        id=f"arn:aws:s3:::{name}",
                        name=name,
                        resource_type=ResourceType.S3_BUCKET,
                        region=self.region_name,
                        raw_config={
                            "public_access_block": pab_conf,
                            "encryption": enc_conf,
                            "versioning": ver_conf,
                            "acl": acl_conf,
                        },
                    )
                )
        except (ClientError, BotoCoreError):
            pass
        return resources

    def _collect_security_groups(self) -> List[CloudResource]:
        resources = []
        try:
            ec2 = self.session.client("ec2", region_name=self.region_name)
            sgs = ec2.describe_security_groups().get("SecurityGroups", [])
            for sg in sgs:
                tags = {t.get("Key"): t.get("Value") for t in sg.get("Tags", [])}
                resources.append(
                    CloudResource(
                        id=sg["GroupId"],
                        name=sg.get("GroupName", sg["GroupId"]),
                        resource_type=ResourceType.SECURITY_GROUP,
                        region=self.region_name,
                        tags=tags,
                        raw_config={
                            "IpPermissions": sg.get("IpPermissions", []),
                            "IpPermissionsEgress": sg.get("IpPermissionsEgress", []),
                            "VpcId": sg.get("VpcId"),
                        },
                    )
                )
        except (ClientError, BotoCoreError):
            pass
        return resources

    def _collect_vpcs(self) -> List[CloudResource]:
        resources = []
        try:
            ec2 = self.session.client("ec2", region_name=self.region_name)
            vpcs = ec2.describe_vpcs().get("Vpcs", [])
            for vpc in vpcs:
                vpc_id = vpc["VpcId"]
                # Check flow logs
                flow_logs = ec2.describe_flow_logs(
                    Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
                ).get("FlowLogs", [])

                resources.append(
                    CloudResource(
                        id=vpc_id,
                        name=vpc_id,
                        resource_type=ResourceType.VPC,
                        region=self.region_name,
                        raw_config={
                            "is_default": vpc.get("IsDefault", False),
                            "cidr_block": vpc.get("CidrBlock"),
                            "flow_logs_enabled": len(flow_logs) > 0,
                            "active_instances_count": 0,
                        },
                    )
                )
        except (ClientError, BotoCoreError):
            pass
        return resources

    def _collect_rds_instances(self) -> List[CloudResource]:
        resources = []
        try:
            rds = self.session.client("rds", region_name=self.region_name)
            instances = rds.describe_db_instances().get("DBInstances", [])
            for db in instances:
                resources.append(
                    CloudResource(
                        id=db.get("DBInstanceArn", db.get("DBInstanceIdentifier")),
                        name=db.get("DBInstanceIdentifier", "unnamed-db"),
                        resource_type=ResourceType.RDS_INSTANCE,
                        region=self.region_name,
                        raw_config={
                            "engine": db.get("Engine"),
                            "storage_encrypted": db.get("StorageEncrypted", False),
                            "publicly_accessible": db.get("PubliclyAccessible", False),
                        },
                    )
                )
        except (ClientError, BotoCoreError):
            pass
        return resources

    def _collect_cloudtrail(self) -> List[CloudResource]:
        resources = []
        try:
            ct = self.session.client("cloudtrail", region_name=self.region_name)
            trails = ct.describe_trails().get("trailList", [])
            for t in trails:
                arn = t.get("TrailARN", t.get("Name"))
                name = t.get("Name")
                status = ct.get_trail_status(Name=arn)
                resources.append(
                    CloudResource(
                        id=arn,
                        name=name,
                        resource_type=ResourceType.CLOUDTRAIL,
                        region=t.get("HomeRegion", self.region_name),
                        raw_config={
                            "IsMultiRegionTrail": t.get("IsMultiRegionTrail", False),
                            "LogFileValidationEnabled": t.get("LogFileValidationEnabled", False),
                            "IsLogging": status.get("IsLogging", False),
                        },
                    )
                )
        except (ClientError, BotoCoreError):
            pass
        return resources

    def _collect_kms_keys(self) -> List[CloudResource]:
        resources = []
        try:
            kms = self.session.client("kms", region_name=self.region_name)
            keys = kms.list_keys().get("Keys", [])
            for k in keys:
                key_id = k.get("KeyId")
                meta = kms.describe_key(KeyId=key_id).get("KeyMetadata", {})
                key_mgr = meta.get("KeyManager", "CUSTOMER")

                rotation = False
                if key_mgr == "CUSTOMER":
                    try:
                        rotation = kms.get_key_rotation_status(KeyId=key_id).get("KeyRotationEnabled", False)
                    except ClientError:
                        rotation = False

                resources.append(
                    CloudResource(
                        id=meta.get("Arn", key_id),
                        name=key_id,
                        resource_type=ResourceType.KMS_KEY,
                        region=self.region_name,
                        raw_config={
                            "KeyManager": key_mgr,
                            "KeyRotationEnabled": rotation,
                            "Enabled": meta.get("Enabled", True),
                        },
                    )
                )
        except (ClientError, BotoCoreError):
            pass
        return resources
