"""
Unit tests for CIS security posture rules across IAM, Storage, Network, and Governance.
"""

import pytest
from cloud_drift_sentinel.core.models import CloudResource, ResourceType, Severity
from cloud_drift_sentinel.rules.cis_iam import (
    RootAccessKeyRule,
    IAMConsoleMFARule,
    IAMWildcardAdminPolicyRule,
    IAMInactiveCredentialsRule,
    IAMTrustWildcardPrincipalRule,
)
from cloud_drift_sentinel.rules.cis_storage import (
    S3PublicAccessBlockRule,
    S3DefaultEncryptionRule,
    S3PublicPolicyOrACLRule,
    S3VersioningRule,
    RDSEncryptionAtRestRule,
)
from cloud_drift_sentinel.rules.cis_network import (
    SecurityGroupSSHExposureRule,
    SecurityGroupRDPExposureRule,
    SecurityGroupDatabaseExposureRule,
    DefaultVPCInUseRule,
)
from cloud_drift_sentinel.rules.cis_governance import (
    CloudTrailMultiRegionRule,
    CloudTrailLogValidationRule,
    KMSKeyRotationRule,
    VPCFlowLogsRule,
)


class TestIAMRules:
    def test_root_access_key_violation(self):
        rule = RootAccessKeyRule()
        res_bad = CloudResource(
            id="root", name="root", resource_type=ResourceType.IAM_ACCOUNT,
            raw_config={"root_account_has_active_key": True}
        )
        res_good = CloudResource(
            id="root", name="root", resource_type=ResourceType.IAM_ACCOUNT,
            raw_config={"root_account_has_active_key": False}
        )
        assert rule.evaluate(res_bad) is not None
        assert rule.evaluate(res_bad).severity == Severity.CRITICAL
        assert rule.evaluate(res_good) is None

    def test_iam_console_mfa(self):
        rule = IAMConsoleMFARule()
        res_no_mfa = CloudResource(
            id="user1", name="user1", resource_type=ResourceType.IAM_USER,
            raw_config={"password_enabled": True, "mfa_active": False}
        )
        res_with_mfa = CloudResource(
            id="user2", name="user2", resource_type=ResourceType.IAM_USER,
            raw_config={"password_enabled": True, "mfa_active": True}
        )
        assert rule.evaluate(res_no_mfa) is not None
        assert rule.evaluate(res_no_mfa).severity == Severity.HIGH
        assert rule.evaluate(res_with_mfa) is None

    def test_iam_wildcard_admin_policy(self):
        rule = IAMWildcardAdminPolicyRule()
        res_admin = CloudResource(
            id="pol1", name="AdminPol", resource_type=ResourceType.IAM_POLICY,
            raw_config={"policy_document": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}
        )
        res_scoped = CloudResource(
            id="pol2", name="ScopedPol", resource_type=ResourceType.IAM_POLICY,
            raw_config={"policy_document": {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::mybucket/*"}]}}
        )
        assert rule.evaluate(res_admin) is not None
        assert rule.evaluate(res_scoped) is None

    def test_iam_inactive_credentials(self):
        rule = IAMInactiveCredentialsRule()
        res_stale = CloudResource(
            id="user1", name="user1", resource_type=ResourceType.IAM_USER,
            raw_config={"access_keys": [{"access_key_id": "AKIA1", "status": "Active", "days_since_last_used": 120}]}
        )
        res_active = CloudResource(
            id="user2", name="user2", resource_type=ResourceType.IAM_USER,
            raw_config={"access_keys": [{"access_key_id": "AKIA2", "status": "Active", "days_since_last_used": 10}]}
        )
        assert rule.evaluate(res_stale) is not None
        assert rule.evaluate(res_active) is None

    def test_iam_role_wildcard_trust(self):
        rule = IAMTrustWildcardPrincipalRule()
        res_wildcard_role = CloudResource(
            id="role1", name="role1", resource_type=ResourceType.IAM_ROLE,
            raw_config={"assume_role_policy": {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]}}
        )
        res_safe_role = CloudResource(
            id="role2", name="role2", resource_type=ResourceType.IAM_ROLE,
            raw_config={"assume_role_policy": {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"}, "Action": "sts:AssumeRole"}]}}
        )
        assert rule.evaluate(res_wildcard_role) is not None
        assert rule.evaluate(res_safe_role) is None


class TestStorageRules:
    def test_s3_public_access_block(self):
        rule = S3PublicAccessBlockRule()
        res_bad = CloudResource(
            id="b1", name="b1", resource_type=ResourceType.S3_BUCKET,
            raw_config={"public_access_block": {"BlockPublicAcls": False, "BlockPublicPolicy": True, "IgnorePublicAcls": True, "RestrictPublicBuckets": True}}
        )
        res_good = CloudResource(
            id="b2", name="b2", resource_type=ResourceType.S3_BUCKET,
            raw_config={"public_access_block": {"BlockPublicAcls": True, "BlockPublicPolicy": True, "IgnorePublicAcls": True, "RestrictPublicBuckets": True}}
        )
        assert rule.evaluate(res_bad) is not None
        assert rule.evaluate(res_good) is None

    def test_s3_encryption(self):
        rule = S3DefaultEncryptionRule()
        res_no_enc = CloudResource(
            id="b1", name="b1", resource_type=ResourceType.S3_BUCKET,
            raw_config={"encryption": {}}
        )
        res_enc = CloudResource(
            id="b2", name="b2", resource_type=ResourceType.S3_BUCKET,
            raw_config={"encryption": {"ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}}}
        )
        assert rule.evaluate(res_no_enc) is not None
        assert rule.evaluate(res_enc) is None

    def test_s3_public_policy(self):
        rule = S3PublicPolicyOrACLRule()
        res_public = CloudResource(
            id="b1", name="b1", resource_type=ResourceType.S3_BUCKET,
            raw_config={"policy": {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]}}
        )
        assert rule.evaluate(res_public) is not None
        assert rule.evaluate(res_public).severity == Severity.CRITICAL

    def test_s3_versioning(self):
        rule = S3VersioningRule()
        res_unver = CloudResource(
            id="b1", name="b1", resource_type=ResourceType.S3_BUCKET,
            raw_config={"versioning": {"Status": "Suspended"}}
        )
        res_ver = CloudResource(
            id="b2", name="b2", resource_type=ResourceType.S3_BUCKET,
            raw_config={"versioning": {"Status": "Enabled"}}
        )
        assert rule.evaluate(res_unver) is not None
        assert rule.evaluate(res_ver) is None

    def test_rds_encryption(self):
        rule = RDSEncryptionAtRestRule()
        res_unenc = CloudResource(
            id="db1", name="db1", resource_type=ResourceType.RDS_INSTANCE,
            raw_config={"storage_encrypted": False}
        )
        res_enc = CloudResource(
            id="db2", name="db2", resource_type=ResourceType.RDS_INSTANCE,
            raw_config={"storage_encrypted": True}
        )
        assert rule.evaluate(res_unenc) is not None
        assert rule.evaluate(res_enc) is None


class TestNetworkRules:
    def test_sg_ssh_exposure(self):
        rule = SecurityGroupSSHExposureRule()
        res_open_ssh = CloudResource(
            id="sg-1", name="sg-1", resource_type=ResourceType.SECURITY_GROUP,
            raw_config={"IpPermissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}
        )
        res_safe_ssh = CloudResource(
            id="sg-2", name="sg-2", resource_type=ResourceType.SECURITY_GROUP,
            raw_config={"IpPermissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "192.168.1.0/24"}]}]}
        )
        assert rule.evaluate(res_open_ssh) is not None
        assert rule.evaluate(res_open_ssh).severity == Severity.CRITICAL
        assert rule.evaluate(res_safe_ssh) is None

    def test_sg_database_exposure(self):
        rule = SecurityGroupDatabaseExposureRule()
        res_open_mysql = CloudResource(
            id="sg-1", name="sg-1", resource_type=ResourceType.SECURITY_GROUP,
            raw_config={"IpPermissions": [{"IpProtocol": "tcp", "FromPort": 3306, "ToPort": 3306, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}
        )
        assert rule.evaluate(res_open_mysql) is not None


class TestGovernanceRules:
    def test_cloudtrail_multi_region(self):
        rule = CloudTrailMultiRegionRule()
        res_bad = CloudResource(
            id="ct-1", name="trail1", resource_type=ResourceType.CLOUDTRAIL,
            raw_config={"IsMultiRegionTrail": False, "IsLogging": True}
        )
        res_good = CloudResource(
            id="ct-2", name="trail2", resource_type=ResourceType.CLOUDTRAIL,
            raw_config={"IsMultiRegionTrail": True, "IsLogging": True}
        )
        assert rule.evaluate(res_bad) is not None
        assert rule.evaluate(res_good) is None

    def test_kms_key_rotation(self):
        rule = KMSKeyRotationRule()
        res_no_rot = CloudResource(
            id="key-1", name="key1", resource_type=ResourceType.KMS_KEY,
            raw_config={"KeyManager": "CUSTOMER", "KeyRotationEnabled": False}
        )
        res_rot = CloudResource(
            id="key-2", name="key2", resource_type=ResourceType.KMS_KEY,
            raw_config={"KeyManager": "CUSTOMER", "KeyRotationEnabled": True}
        )
        assert rule.evaluate(res_no_rot) is not None
        assert rule.evaluate(res_rot) is None
