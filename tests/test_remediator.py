import json
import pytest
from unittest.mock import patch, MagicMock


CLUSTER = {
    "roles": ["dev-read", "dev-write"],
    "permissions": ["s3:GetObject|*", "s3:PutObject|*", "iam:ListRoles|*"],
}

RECOMMENDATION = {
    "standard_role_name": "dev-unified",
    "suggested_policy": {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}
        ],
    },
    "remediation_steps": ["Detach s3:PutObject from dev-write", "Remove dev-read and dev-write, attach dev-unified"],
}


# ---------------------------------------------------------------------------
# preview_consolidation
# ---------------------------------------------------------------------------

def test_preview_consolidation_no_file_writes(tmp_path):
    from iamdbagent.remediator import preview_consolidation

    result = preview_consolidation(CLUSTER, RECOMMENDATION)
    assert "removed_permissions_count" in result
    assert result["roles_consolidated"] == 2
    assert result["consolidated_into"] == 1
    # No files should exist in tmp_path (preview writes nothing)
    assert list(tmp_path.iterdir()) == []


def test_preview_consolidation_correct_delta():
    from iamdbagent.remediator import preview_consolidation

    result = preview_consolidation(CLUSTER, RECOMMENDATION)
    # suggested_policy only has s3:GetObject|*, so s3:PutObject|* and iam:ListRoles|* are removed
    assert result["removed_permissions_count"] == 2


# ---------------------------------------------------------------------------
# stage_consolidation
# ---------------------------------------------------------------------------

def test_stage_consolidation_writes_files(tmp_path):
    from iamdbagent.remediator import stage_consolidation

    summary = stage_consolidation(CLUSTER, RECOMMENDATION, str(tmp_path))
    assert "files" in summary
    files = summary["files"]
    assert "json" in files and "tf" in files
    assert tmp_path.joinpath("dev-unified_policy.json").exists()
    assert tmp_path.joinpath("dev-unified.tf").exists()


def test_stage_consolidation_json_valid(tmp_path):
    from iamdbagent.remediator import stage_consolidation

    stage_consolidation(CLUSTER, RECOMMENDATION, str(tmp_path))
    data = json.loads(tmp_path.joinpath("dev-unified_policy.json").read_text())
    assert data["Version"] == "2012-10-17"


# ---------------------------------------------------------------------------
# stage_analysis_fix
# ---------------------------------------------------------------------------

def test_stage_analysis_fix_with_finding_policy(tmp_path):
    from iamdbagent.remediator import stage_analysis_fix

    analysis = {
        "findings": [
            {
                "action": "s3_cleanup",
                "resource": "*",
                "risk_score": 8,
                "suggested_policy": {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::mybucket/*"}],
                },
            }
        ]
    }
    result = stage_analysis_fix(analysis, str(tmp_path))
    assert len(result["files"]) == 1
    assert result.get("combined_tf") is not None
    assert tmp_path.joinpath("remediation.tf").exists()


def test_stage_analysis_fix_skips_finding_without_policy(tmp_path):
    from iamdbagent.remediator import stage_analysis_fix

    analysis = {
        "findings": [
            {"action": "iam:List*", "resource": "*", "risk_score": 3}
        ]
    }
    result = stage_analysis_fix(analysis, str(tmp_path))
    assert result["files"] == []
    assert result.get("combined_tf") is None


# ---------------------------------------------------------------------------
# preview_analysis_fix
# ---------------------------------------------------------------------------

def test_preview_analysis_fix_no_writes(tmp_path):
    from iamdbagent.remediator import preview_analysis_fix

    analysis = {
        "findings": [
            {
                "action": "ec2_cleanup",
                "suggested_policy": {"Version": "2012-10-17", "Statement": []},
            }
        ]
    }
    result = preview_analysis_fix(analysis)
    assert isinstance(result["previews"], list)
    assert len(result["previews"]) == 1
    assert list(tmp_path.iterdir()) == []
