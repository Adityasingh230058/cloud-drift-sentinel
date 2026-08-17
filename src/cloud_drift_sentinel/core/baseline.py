"""
Baseline configuration manager and infrastructure drift comparator.
"""

import json
import os
from typing import Dict, Any, List, Tuple
from .models import CloudResource, DriftRecord, DriftType, ResourceType


class BaselineManager:
    """
    Manages Golden State IaC baselines and computes deep drift between
    expected baseline configurations and observed cloud state.
    """

    @staticmethod
    def export_baseline(resources: List[CloudResource], filepath: str) -> None:
        """Saves current resource list as a JSON baseline snapshot."""
        data = {
            "version": "1.0",
            "provider": resources[0].provider if resources else "aws",
            "resource_count": len(resources),
            "resources": [r.to_dict() for r in resources],
        }
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    @staticmethod
    def load_baseline(filepath: str) -> List[CloudResource]:
        """Loads resources from a JSON baseline snapshot."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Baseline file not found: {filepath}")

        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        raw_resources = data.get("resources", [])
        loaded_resources: List[CloudResource] = []

        for item in raw_resources:
            r_type_str = item.get("resource_type", "cloud:generic")
            try:
                r_type = ResourceType(r_type_str)
            except ValueError:
                r_type = ResourceType.GENERIC

            res = CloudResource(
                id=item.get("id", ""),
                name=item.get("name", ""),
                resource_type=r_type,
                provider=item.get("provider", "aws"),
                region=item.get("region", "global"),
                tags=item.get("tags", {}),
                raw_config=item.get("raw_config", {}),
            )
            loaded_resources.append(res)

        return loaded_resources

    @classmethod
    def compare_drift(
        cls,
        baseline_resources: List[CloudResource],
        current_resources: List[CloudResource],
    ) -> List[DriftRecord]:
        """
        Compares baseline resources with current cloud state and generates
        a list of DriftRecords (ADDED, REMOVED, MODIFIED).
        """
        drift_records: List[DriftRecord] = []
        baseline_map: Dict[str, CloudResource] = {r.id: r for r in baseline_resources}
        current_map: Dict[str, CloudResource] = {r.id: r for r in current_resources}

        # Check for modified and removed resources
        for b_id, b_res in baseline_map.items():
            if b_id not in current_map:
                drift_records.append(
                    DriftRecord(
                        drift_type=DriftType.REMOVED,
                        resource_id=b_id,
                        resource_type=b_res.resource_type,
                        resource_name=b_res.name,
                        differences={"status": "Resource deleted or removed from cloud"},
                        baseline_value=b_res.raw_config,
                        current_value=None,
                    )
                )
            else:
                c_res = current_map[b_id]
                diffs = cls._diff_dicts(b_res.raw_config, c_res.raw_config)
                tag_diffs = cls._diff_dicts(b_res.tags, c_res.tags)

                if tag_diffs:
                    diffs["tags"] = tag_diffs

                if diffs:
                    drift_records.append(
                        DriftRecord(
                            drift_type=DriftType.MODIFIED,
                            resource_id=b_id,
                            resource_type=b_res.resource_type,
                            resource_name=b_res.name,
                            differences=diffs,
                            baseline_value=b_res.raw_config,
                            current_value=c_res.raw_config,
                        )
                    )

        # Check for newly added (unmanaged) resources in the cloud
        for c_id, c_res in current_map.items():
            if c_id not in baseline_map:
                drift_records.append(
                    DriftRecord(
                        drift_type=DriftType.ADDED,
                        resource_id=c_id,
                        resource_type=c_res.resource_type,
                        resource_name=c_res.name,
                        differences={"status": "Unmanaged / rogue resource created outside IaC baseline"},
                        baseline_value=None,
                        current_value=c_res.raw_config,
                    )
                )

        return drift_records

    @staticmethod
    def _diff_dicts(base: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
        """Calculates differences between two dictionaries recursively."""
        diffs = {}
        all_keys = set(base.keys()).union(set(current.keys()))

        for key in all_keys:
            if key not in base:
                diffs[key] = {"baseline": None, "current": current[key], "type": "ADDED_KEY"}
            elif key not in current:
                diffs[key] = {"baseline": base[key], "current": None, "type": "REMOVED_KEY"}
            else:
                val_base = base[key]
                val_curr = current[key]
                if isinstance(val_base, dict) and isinstance(val_curr, dict):
                    nested_diff = BaselineManager._diff_dicts(val_base, val_curr)
                    if nested_diff:
                        diffs[key] = nested_diff
                elif val_base != val_curr:
                    diffs[key] = {"baseline": val_base, "current": val_curr, "type": "CHANGED"}

        return diffs
