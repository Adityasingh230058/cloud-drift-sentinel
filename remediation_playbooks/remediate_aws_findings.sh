#!/usr/bin/env bash
# ==================================================================
# Cloud Drift Sentinel - Automated AWS Security Remediation Script
# Generated automatically based on active security posture audit
# ==================================================================
set -euo pipefail
echo '[*] Starting Cloud Drift Sentinel automated remediation...'

# Remediation for Ensure S3 Buckets have Public Access Block configuration enabled on bucket: corp-customer-analytics-prod-data
echo '[+] Enabling Public Access Block on corp-customer-analytics-prod-data...'
aws s3control put-public-access-block --account-id $(aws sts get-caller-identity --query Account --output text) --public-access-block-configuration 'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true' 2>/dev/null || aws s3api put-public-access-block --bucket corp-customer-analytics-prod-data --public-access-block-configuration 'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'

# Remediation for Ensure S3 Bucket does not allow public Read or Write access on bucket: corp-customer-analytics-prod-data
echo '[+] Enabling Public Access Block on corp-customer-analytics-prod-data...'
aws s3control put-public-access-block --account-id $(aws sts get-caller-identity --query Account --output text) --public-access-block-configuration 'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true' 2>/dev/null || aws s3api put-public-access-block --bucket corp-customer-analytics-prod-data --public-access-block-configuration 'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'

# Revoke open tcp 22-22 on sg-01a2b3c4d5e6f7001
aws ec2 revoke-security-group-ingress --group-id sg-01a2b3c4d5e6f7001 --region us-east-1 --protocol tcp --port 22 --cidr 0.0.0.0/0 || true

# Revoke open tcp 3389-3389 on sg-01a2b3c4d5e6f7001
aws ec2 revoke-security-group-ingress --group-id sg-01a2b3c4d5e6f7001 --region us-east-1 --protocol tcp --port 3389 --cidr 0.0.0.0/0 || true

# Revoke open tcp 5432-5432 on sg-01a2b3c4d5e6f7002
aws ec2 revoke-security-group-ingress --group-id sg-01a2b3c4d5e6f7002 --region us-east-1 --protocol tcp --port 5432 --cidr 0.0.0.0/0 || true

echo '[✓] Remediation sequence finished.'