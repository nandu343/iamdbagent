"""SailPoint IdentityNow read-only IAM extractor.

Exports:
- `extract_sailpoint_iam(tenant_url, client_id, client_secret)` -> dict with
  `users`, `roles`, `policies`, `entitlements`, `errors`

Mapping:
    SailPoint Identity      -> User node
    SailPoint Role          -> Role node
    SailPoint Access Profile -> Policy node
    SailPoint Entitlement   -> Permission node
"""
import logging
import time
from typing import Any, Dict, List, Optional
import requests

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

_PAGE_LIMIT = 250


class SailPointClient:
    """OAuth2 client-credentials client for SailPoint IdentityNow V3 API."""

    def __init__(self, tenant_url: str, client_id: str, client_secret: str):
        self.base_url = tenant_url.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self._token: Optional[str] = None
        self._token_expires: float = 0.0

    def _ensure_token(self) -> None:
        if self._token and time.time() < self._token_expires - 30:
            return
        resp = requests.post(
            f"{self.base_url}/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
            timeout=30,
        )
        resp.raise_for_status()
        payload = resp.json()
        self._token = payload["access_token"]
        self._token_expires = time.time() + int(payload.get("expires_in", 3600))

    def _headers(self) -> Dict[str, str]:
        self._ensure_token()
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
        }

    def paginate(self, path: str, params: Optional[Dict] = None) -> List[Dict]:
        """Fetch all pages from a V3 list endpoint using limit/offset pagination."""
        results: List[Dict] = []
        offset = 0
        base_params: Dict[str, Any] = dict(params or {})
        base_params["limit"] = _PAGE_LIMIT
        while True:
            base_params["offset"] = offset
            resp = requests.get(
                f"{self.base_url}/v3/{path.lstrip('/')}",
                headers=self._headers(),
                params=base_params,
                timeout=60,
            )
            resp.raise_for_status()
            page: List[Dict] = resp.json()
            if not page:
                break
            results.extend(page)
            if len(page) < _PAGE_LIMIT:
                break
            offset += _PAGE_LIMIT
        return results


def _safe_paginate(
    client: SailPointClient, path: str, errors: List[Dict], params: Optional[Dict] = None
) -> List[Dict]:
    try:
        return client.paginate(path, params=params)
    except requests.HTTPError as exc:
        logger.error("SailPoint API error [%s]: %s", path, exc)
        errors.append({"resource": path, "error": str(exc)})
        return []
    except requests.RequestException as exc:
        logger.error("SailPoint request failed [%s]: %s", path, exc)
        errors.append({"resource": path, "error": str(exc)})
        return []


def extract_sailpoint_iam(
    tenant_url: str, client_id: str, client_secret: str
) -> Dict[str, Any]:
    """Extract IAM entities from SailPoint IdentityNow (read-only).

    Returns dict with keys: `users`, `roles`, `policies`, `entitlements`, `errors`.
    Raises RuntimeError if all primary resource types fail entirely.
    """
    client = SailPointClient(tenant_url, client_id, client_secret)
    out: Dict[str, Any] = {
        "users": [],
        "roles": [],
        "policies": [],
        "entitlements": [],
        "errors": [],
    }

    # Entitlements → Permission nodes
    raw_entitlements = _safe_paginate(client, "entitlements", out["errors"])
    entitlement_map: Dict[str, Dict] = {}
    for ent in raw_entitlements:
        eid = ent.get("id", "")
        source = ent.get("source") or {}
        source_name = source.get("name") if isinstance(source, dict) else str(source)
        record = {
            "id": eid,
            "name": ent.get("name", eid),
            "attribute": ent.get("attribute") or ent.get("name") or eid,
            "value": ent.get("value") or "*",
            "sourceName": source_name or "*",
        }
        entitlement_map[eid] = record
        out["entitlements"].append(record)
    logger.info("SailPoint: fetched %d entitlements", len(out["entitlements"]))

    # Access Profiles → Policy nodes (each AP bundles entitlements)
    raw_aps = _safe_paginate(client, "access-profiles", out["errors"])
    ap_map: Dict[str, Dict] = {}
    for ap in raw_aps:
        apid = ap.get("id", "")
        ap_map[apid] = ap
        doc: List[Dict] = []
        for ae in ap.get("entitlements") or []:
            ae_id = ae.get("id") if isinstance(ae, dict) else ae
            ent_rec = entitlement_map.get(ae_id, {})
            attr = ent_rec.get("attribute") or ae_id or "unknown"
            val = ent_rec.get("value") or "*"
            doc.append({"effect": "Allow", "actions": [attr], "resources": [val], "condition": None})
        out["policies"].append({
            "PolicyName": ap.get("name", apid),
            "Arn": apid,
            "Document": doc,
            "Source": "sailpoint:access-profile",
        })
    logger.info("SailPoint: fetched %d access profiles", len(out["policies"]))

    # Roles → Role nodes (each role references access profiles as policies)
    raw_roles = _safe_paginate(client, "roles", out["errors"])
    for r in raw_roles:
        rid = r.get("id", "")
        attached: List[Dict] = []
        for ap_ref in r.get("accessProfiles") or []:
            ap_id = ap_ref.get("id") if isinstance(ap_ref, dict) else ap_ref
            ap_data = ap_map.get(ap_id, {})
            attached.append({"PolicyArn": ap_id, "PolicyName": ap_data.get("name", ap_id)})
        out["roles"].append({
            "RoleName": r.get("name", rid),
            "Arn": rid,
            "AttachedPolicies": attached,
            "InlinePolicies": [],
            "Source": "sailpoint:role",
        })
    logger.info("SailPoint: fetched %d roles", len(out["roles"]))

    # Identities → User nodes
    raw_identities = _safe_paginate(client, "identities", out["errors"])
    for ident in raw_identities:
        iid = ident.get("id", "")

        # Roles assigned to this identity
        identity_role_ids: List[str] = []
        for role_ref in ident.get("roleAssignments") or []:
            role_id = (
                role_ref.get("roleId") if isinstance(role_ref, dict) else role_ref
            )
            if role_id:
                identity_role_ids.append(role_id)

        # Access profiles assigned directly to this identity
        attached_aps: List[Dict] = []
        for ap_ref in ident.get("accessProfiles") or []:
            ap_id = ap_ref.get("id") if isinstance(ap_ref, dict) else ap_ref
            ap_data = ap_map.get(ap_id, {})
            attached_aps.append({"PolicyArn": ap_id, "PolicyName": ap_data.get("name", ap_id)})

        out["users"].append({
            "UserName": ident.get("name") or ident.get("alias") or iid,
            "Arn": iid,
            "AttachedPolicies": attached_aps,
            "InlinePolicies": [],
            "Roles": identity_role_ids,
            "IsServiceAccount": ident.get("type") not in (None, "HUMAN"),
            "Source": "sailpoint:identity",
        })
    logger.info("SailPoint: fetched %d identities", len(out["users"]))

    if (
        not out["users"]
        and not out["roles"]
        and not out["policies"]
        and out["errors"]
    ):
        raise RuntimeError(f"SailPoint IAM extraction failed entirely: {out['errors']}")

    return out


if __name__ == "__main__":
    import json, os, sys

    url = os.environ.get("SAILPOINT_TENANT_URL", "")
    cid = os.environ.get("SAILPOINT_CLIENT_ID", "")
    csec = os.environ.get("SAILPOINT_CLIENT_SECRET", "")
    if not (url and cid and csec):
        print("Set SAILPOINT_TENANT_URL, SAILPOINT_CLIENT_ID, SAILPOINT_CLIENT_SECRET")
        sys.exit(1)
    data = extract_sailpoint_iam(url, cid, csec)
    print(json.dumps({k: len(v) for k, v in data.items() if isinstance(v, list)}))
