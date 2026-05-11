"""Minimal AWS IAM read-only extractor.

Exports:
- `extract_aws_iam(session)` -> dict with `users`, `roles`, `policies`

This is intentionally conservative: it enumerates users, roles and attached policies and
parses policy documents to extract actions and resources.
"""
from typing import Dict, List, Any
import json
import logging
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


def _safe_get(client_fn, *args, **kwargs):
    try:
        return client_fn(*args, **kwargs)
    except ClientError as e:
        logger.error("AWS client error: %s", e)
        return {}


def _parse_policy_document(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    result = []
    for s in statements:
        actions = s.get("Action") or s.get("NotAction")
        resources = s.get("Resource") or s.get("NotResource")
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        result.append({
            "effect": s.get("Effect"),
            "actions": actions or [],
            "resources": resources or [],
            "condition": s.get("Condition"),
        })
    return result


def extract_aws_iam(boto3_session=None) -> Dict[str, Any]:
    """Extract IAM entities from AWS using boto3 session (or default session).

    Returns a dict with keys: `users`, `roles`, `policies`, `errors`.
    Raises RuntimeError if all three resource types fail entirely.
    """
    session = boto3_session or boto3.Session()
    iam = session.client("iam")

    out: Dict[str, Any] = {"users": [], "roles": [], "policies": [], "errors": []}

    # Users
    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for u in page.get("Users", []):
                username = u["UserName"]
                user_obj = {"UserName": username, "Arn": u.get("Arn"), "AttachedPolicies": [], "InlinePolicies": []}

                for ap in iam.list_attached_user_policies(UserName=username).get("AttachedPolicies", []):
                    user_obj["AttachedPolicies"].append(ap)

                for name in iam.list_user_policies(UserName=username).get("PolicyNames", []):
                    doc = iam.get_user_policy(UserName=username, PolicyName=name).get("PolicyDocument")
                    parsed = _parse_policy_document(doc or {})
                    user_obj["InlinePolicies"].append({"PolicyName": name, "Document": parsed})

                out["users"].append(user_obj)
    except ClientError as e:
        logger.error("Failed to list IAM users: %s", e)
        out["errors"].append({"resource": "users", "error": str(e)})

    # Roles
    try:
        rp = iam.get_paginator("list_roles")
        for page in rp.paginate():
            for r in page.get("Roles", []):
                name = r["RoleName"]
                role_obj = {"RoleName": name, "Arn": r.get("Arn"), "AssumeRolePolicy": r.get("AssumeRolePolicyDocument"), "AttachedPolicies": [], "InlinePolicies": []}

                for ap in iam.list_attached_role_policies(RoleName=name).get("AttachedPolicies", []):
                    role_obj["AttachedPolicies"].append(ap)

                for pname in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
                    doc = iam.get_role_policy(RoleName=name, PolicyName=pname).get("PolicyDocument")
                    parsed = _parse_policy_document(doc or {})
                    role_obj["InlinePolicies"].append({"PolicyName": pname, "Document": parsed})

                out["roles"].append(role_obj)
    except ClientError as e:
        logger.error("Failed to list IAM roles: %s", e)
        out["errors"].append({"resource": "roles", "error": str(e)})

    # Managed policies (summary)
    try:
        pp = iam.get_paginator("list_policies")
        for page in pp.paginate(Scope="All"):
            for p in page.get("Policies", []):
                try:
                    ver = iam.get_policy(PolicyArn=p["Arn"]).get("Policy", {}).get("DefaultVersionId")
                    doc = iam.get_policy_version(PolicyArn=p["Arn"], VersionId=ver).get("PolicyVersion", {}).get("Document")
                except Exception:
                    doc = {}
                parsed = _parse_policy_document(doc or {})
                out["policies"].append({"PolicyName": p.get("PolicyName"), "Arn": p.get("Arn"), "Document": parsed})
    except ClientError as e:
        logger.error("Failed to list IAM policies: %s", e)
        out["errors"].append({"resource": "policies", "error": str(e)})

    if not out["users"] and not out["roles"] and not out["policies"] and out["errors"]:
        raise RuntimeError(f"AWS IAM extraction failed entirely: {out['errors']}")

    return out


if __name__ == "__main__":
    import os
    s = boto3.Session()
    data = extract_aws_iam(s)
    print(json.dumps({"users": len(data["users"]), "roles": len(data["roles"]), "policies": len(data["policies"])}))
