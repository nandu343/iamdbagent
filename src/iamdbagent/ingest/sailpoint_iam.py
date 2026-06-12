"""SailPoint IdentityNow read-only IAM extractor.

Exports:
- `extract_sailpoint_iam(tenant_url, client_id, client_secret)` -> dict with
  `users`, `roles`, `policies`, `entitlements`, `errors`

Mapping:
    SailPoint Identity       -> User node
    SailPoint Role           -> Role node
    SailPoint Access Profile -> Policy node
    SailPoint Entitlement    -> Permission node

Activity / last_used:
    The extractor attempts to populate `last_used` on entitlement records by
    reading `attributes.lastLoginDate` from identities that hold those entitlements
    via access profile membership. If SailPoint does not surface this attribute,
    `last_used` is left null — those permissions will be flagged as zombie candidates.
"""
import logging
import time
from typing import Any, Dict, List, Optional
import requests

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

_PAGE_LIMIT = 250
_MAX_RETRIES = 3


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
    client: SailPointClient,
    path: str,
    errors: List[Dict],
    params: Optional[Dict] = None,
) -> List[Dict]:
    """Paginate with exponential back-off retry on transient errors and rate limits."""
    for attempt in range(_MAX_RETRIES):
        try:
            return client.paginate(path, params=params)
        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else 0
            if status == 429 or status >= 500:
                wait = 2 ** attempt
                logger.warning("SailPoint API %d on %s — retrying in %ds", status, path, wait)
                time.sleep(wait)
                continue
            logger.error("SailPoint API error [%s]: %s", path, exc)
            errors.append({"resource": path, "error": str(exc)})
            return []
        except requests.RequestException as exc:
            if attempt < _MAX_RETRIES - 1:
                wait = 2 ** attempt
                logger.warning("Request failed [%s], retrying in %ds: %s", path, wait, exc)
                time.sleep(wait)
                continue
            logger.error("SailPoint request failed [%s]: %s", path, exc)
            errors.append({"resource": path, "error": str(exc)})
            return []
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

    # ── 1. Entitlements ───────────────────────────────────────────────────────
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
            "last_used": None,  # populated below from identity activity
        }
        entitlement_map[eid] = record
    logger.info("SailPoint: fetched %d entitlements", len(entitlement_map))

    # ── 2. Access Profiles ────────────────────────────────────────────────────
    raw_aps = _safe_paginate(client, "access-profiles", out["errors"])
    ap_map: Dict[str, Dict] = {}
    # entitlement_id -> list of ap_ids that contain it
    entitlement_to_aps: Dict[str, List[str]] = {}
    for ap in raw_aps:
        apid = ap.get("id", "")
        ap_map[apid] = ap
        for ae in ap.get("entitlements") or []:
            ae_id = ae.get("id") if isinstance(ae, dict) else ae
            if ae_id:
                entitlement_to_aps.setdefault(ae_id, []).append(apid)
    logger.info("SailPoint: fetched %d access profiles", len(ap_map))

    # ── 3. Roles ──────────────────────────────────────────────────────────────
    raw_roles = _safe_paginate(client, "roles", out["errors"])
    logger.info("SailPoint: fetched %d roles", len(raw_roles))

    # ── 4. Identities + build ap_last_used map ────────────────────────────────
    raw_identities = _safe_paginate(client, "identities", out["errors"])
    logger.info("SailPoint: fetched %d identities", len(raw_identities))

    # ap_id -> most recent lastLoginDate seen across identities that hold it
    ap_last_used: Dict[str, str] = {}
    for ident in raw_identities:
        attrs = ident.get("attributes") or {}
        last_login = (
            attrs.get("lastLoginDate")
            or attrs.get("lastActivity")
            or ident.get("lastActivity")
        )
        if last_login:
            last_login_str = str(last_login)
            for ap_ref in ident.get("accessProfiles") or []:
                ap_id = ap_ref.get("id") if isinstance(ap_ref, dict) else ap_ref
                if ap_id:
                    existing = ap_last_used.get(ap_id)
                    if not existing or last_login_str > existing:
                        ap_last_used[ap_id] = last_login_str

    # ── 5. Populate last_used on entitlement records ──────────────────────────
    for eid, ent_rec in entitlement_map.items():
        last_used = None
        for ap_id in entitlement_to_aps.get(eid, []):
            ap_lu = ap_last_used.get(ap_id)
            if ap_lu and (not last_used or ap_lu > last_used):
                last_used = ap_lu
        ent_rec["last_used"] = last_used
        out["entitlements"].append(ent_rec)

    # ── 6. Build policy records from access profiles ──────────────────────────
    for ap in raw_aps:
        apid = ap.get("id", "")
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

    # ── 7. Build role records ─────────────────────────────────────────────────
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

    # ── 8. Build user (identity) records ──────────────────────────────────────
    for ident in raw_identities:
        iid = ident.get("id", "")

        identity_role_ids: List[str] = []
        for role_ref in ident.get("roleAssignments") or []:
            role_id = role_ref.get("roleId") if isinstance(role_ref, dict) else role_ref
            if role_id:
                identity_role_ids.append(role_id)

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
