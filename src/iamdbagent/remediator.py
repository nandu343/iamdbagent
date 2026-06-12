"""Remediator: stages IaC outputs and summarizes remediation impact."""
import os
import json
from typing import Dict, Any
from .analyzer import generate_iac_from_policy


def _safe_name(name: str) -> str:
    return name.replace(" ", "_").lower()


def stage_consolidation(cluster: Dict[str, Any], recommendation: Dict[str, Any], output_dir: str) -> Dict[str, Any]:
    """Stage consolidation recommendation: write files and return summary."""
    os.makedirs(output_dir, exist_ok=True)

    role_count = len(cluster.get("roles", []))
    perms_before = set(cluster.get("permissions", []))

    std_name = recommendation.get("standard_role_name") or ("consolidated_" + _safe_name("_".join(cluster.get("roles", []))))
    suggested_policy = recommendation.get("suggested_policy") or {}

    suggested_perms = set()
    for stmt in suggested_policy.get("Statement", []) if isinstance(suggested_policy, dict) else []:
        actions = stmt.get("Action") or stmt.get("NotAction") or []
        resources = stmt.get("Resource") or stmt.get("NotResource") or []
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        for a in actions:
            for r in resources:
                suggested_perms.add(f"{a}|{r}")

    removed = perms_before - suggested_perms
    removed_count = len(removed)
    consolidated_into_one = 1 if role_count > 1 else role_count

    paths = generate_iac_from_policy(suggested_policy or {}, std_name, output_dir)

    return {
        "message": f"If applied, this will remove {removed_count} permissions from the cluster and consolidate {role_count} roles into {consolidated_into_one}.",
        "removed_permissions_count": removed_count,
        "roles_consolidated": role_count,
        "consolidated_into": consolidated_into_one,
        "files": paths,
        "removed_permissions_sample": list(removed)[:20],
    }


def stage_analysis_fix(analysis_result: Dict[str, Any], output_dir: str) -> Dict[str, Any]:
    """Stage fixes for a general analyze() result that may include suggested_policy(s)."""
    os.makedirs(output_dir, exist_ok=True)
    files = []
    summaries = []

    if isinstance(analysis_result, dict):
        if "suggested_policy" in analysis_result and "standard_role_name" in analysis_result:
            paths = generate_iac_from_policy(analysis_result["suggested_policy"], analysis_result["standard_role_name"], output_dir)
            files.append(paths)
            summaries.append({"type": "top-level", "files": paths})

        for f in analysis_result.get("findings", []) if isinstance(analysis_result.get("findings"), list) else []:
            if "suggested_policy" in f and "action" in f:
                name = f.get("action", "policy")
                paths = generate_iac_from_policy(f["suggested_policy"], name, output_dir)
                files.append(paths)
                summaries.append({"type": "finding", "files": paths})

    combined_tf_path = None
    if files:
        combined_tf_path = os.path.join(output_dir, "remediation.tf")
        with open(combined_tf_path, "w") as combined:
            for p in files:
                tfp = p.get("tf")
                if tfp and os.path.exists(tfp):
                    with open(tfp, "r") as tf_file:
                        combined.write(tf_file.read())
                        combined.write("\n\n")

    result = {"files": files, "summaries": summaries}
    if combined_tf_path:
        result["combined_tf"] = combined_tf_path
    return result


def preview_consolidation(cluster: Dict[str, Any], recommendation: Dict[str, Any]) -> Dict[str, Any]:
    """Return summary of what would happen if consolidation is applied, without writing files."""
    role_count = len(cluster.get("roles", []))
    perms_before = set(cluster.get("permissions", []))

    std_name = recommendation.get("standard_role_name") or ("consolidated_" + _safe_name("_".join(cluster.get("roles", []))))
    suggested_policy = recommendation.get("suggested_policy") or {}

    suggested_perms = set()
    for stmt in suggested_policy.get("Statement", []) if isinstance(suggested_policy, dict) else []:
        actions = stmt.get("Action") or stmt.get("NotAction") or []
        resources = stmt.get("Resource") or stmt.get("NotResource") or []
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        for a in actions:
            for r in resources:
                suggested_perms.add(f"{a}|{r}")

    removed = perms_before - suggested_perms
    removed_count = len(removed)
    consolidated_into_one = 1 if role_count > 1 else role_count

    return {
        "message": f"Would remove {removed_count} permissions and consolidate {role_count} roles into {consolidated_into_one}.",
        "removed_permissions_count": removed_count,
        "roles_consolidated": role_count,
        "consolidated_into": consolidated_into_one,
        "removed_permissions_sample": list(removed)[:20],
        "proposed_role_name": std_name,
    }


def preview_analysis_fix(analysis_result: Dict[str, Any]) -> Dict[str, Any]:
    """Preview fixes for analysis_result without writing files."""
    previews = []
    if isinstance(analysis_result, dict):
        if "suggested_policy" in analysis_result and "standard_role_name" in analysis_result:
            previews.append({
                "type": "top-level",
                "proposed_role_name": analysis_result.get("standard_role_name"),
                "policy_summary": analysis_result.get("suggested_policy", {}),
            })
        for f in analysis_result.get("findings", []) if isinstance(analysis_result.get("findings"), list) else []:
            if "suggested_policy" in f and "action" in f:
                previews.append({"type": "finding", "action": f.get("action"), "policy_summary": f.get("suggested_policy")})
    return {"previews": previews}
