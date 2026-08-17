"""
Unit tests for baseline snapshot management and infrastructure drift calculation.
"""

import os
import json
import pytest
from cloud_drift_sentinel.core.models import CloudResource, ResourceType, DriftType
from cloud_drift_sentinel.core.baseline import BaselineManager


def test_baseline_export_and_load(tmp_path):
    filepath = os.path.join(tmp_path, "test_baseline.json")
    resources = [
        CloudResource(
            id="arn:aws:s3:::test-bucket",
            name="test-bucket",
            resource_type=ResourceType.S3_BUCKET,
            region="us-east-1",
            tags={"Env": "Test"},
            raw_config={"encryption": "AES256"},
        )
    ]

    BaselineManager.export_baseline(resources, filepath)
    assert os.path.exists(filepath)

    loaded = BaselineManager.load_baseline(filepath)
    assert len(loaded) == 1
    assert loaded[0].id == "arn:aws:s3:::test-bucket"
    assert loaded[0].tags == {"Env": "Test"}


def test_drift_detection_types():
    # 1. Baseline State
    b_s3 = CloudResource(
        id="s3-1", name="prod-data", resource_type=ResourceType.S3_BUCKET,
        raw_config={"encrypted": True, "versioning": True}, tags={"Team": "Data"}
    )
    b_sg = CloudResource(
        id="sg-1", name="web-sg", resource_type=ResourceType.SECURITY_GROUP,
        raw_config={"port": 443}
    )
    b_deleted = CloudResource(
        id="sg-old", name="old-sg", resource_type=ResourceType.SECURITY_GROUP,
        raw_config={"port": 80}
    )
    baseline = [b_s3, b_sg, b_deleted]

    # 2. Current State
    c_s3 = CloudResource(
        id="s3-1", name="prod-data", resource_type=ResourceType.S3_BUCKET,
        raw_config={"encrypted": False, "versioning": True}, tags={"Team": "Data", "ManualEdit": "true"}
    )
    c_sg = CloudResource(
        id="sg-1", name="web-sg", resource_type=ResourceType.SECURITY_GROUP,
        raw_config={"port": 443}
    )
    c_rogue = CloudResource(
        id="iam-rogue", name="RogueRole", resource_type=ResourceType.IAM_ROLE,
        raw_config={"admin": True}
    )
    current = [c_s3, c_sg, c_rogue]

    # 3. Calculate Drift
    drift_records = BaselineManager.compare_drift(baseline, current)

    drift_map = {d.resource_id: d for d in drift_records}
    assert len(drift_records) == 3

    # Modified S3 bucket
    assert "s3-1" in drift_map
    assert drift_map["s3-1"].drift_type == DriftType.MODIFIED
    assert "encrypted" in drift_map["s3-1"].differences

    # Removed old Security Group
    assert "sg-old" in drift_map
    assert drift_map["sg-old"].drift_type == DriftType.REMOVED

    # Added Rogue IAM Role
    assert "iam-rogue" in drift_map
    assert drift_map["iam-rogue"].drift_type == DriftType.ADDED
