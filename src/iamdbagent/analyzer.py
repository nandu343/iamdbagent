"""Analyzer module: runs Neo4j queries and forwards findings to an LLM for recommendations.

Features:
- `find_zombie_permissions(driver, days=90)` — permissions not used in `days` days.
- `find_shadow_admin_paths(driver)` — transitive privilege escalation paths.
- `analyze(uri, user, password, ...)` — orchestrates query -> LLM -> parsed JSON output.
- `consolidate_roles(uri, user, password, ...)` — clusters similar roles and proposes merges.
"""
from neo4j import GraphDatabase
import datetime
import json
import requests
import logging
import os
from typing import List, Dict, Any, Optional
from jsonschema import validate as jsonschema_validate
from jsonschema.exceptions import ValidationError

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


def _get_driver(uri: str, user: str, password: str):
    return GraphDatabase.driver(uri, auth=(user, password))


def find_zombie_permissions(driver, days: int = 90) -> List[Dict[str, Any]]:
    """Return list of permissions not used in the last `days` days.

    Each item contains: action, resource, last_used, roles (list of role names).
    Permissions with NULL last_used (never used) are included and flagged highest-risk.
    """
    cutoff_clause = f"datetime() - duration({{days: {days}}})"
    q = (
        "MATCH (r:Role)-[:HAS_PERMISSION]->(p:Permission)"
        " WHERE p.last_used IS NULL OR datetime(p.last_used) < "
        + cutoff_clause
        + "\nRETURN p.action AS action, p.resource AS resource, p.last_used AS last_used, collect(DISTINCT r.name) AS roles"
    )

    with driver.session() as session:
        res = session.run(q)
        out = []
        for record in res:
            out.append({
                "action": record["action"],
                "resource": record["resource"],
                "last_used": record["last_used"],
                "roles": record["roles"],
            })
    return out


def find_shadow_admin_paths(driver, max_hops: int = 6) -> List[Dict[str, Any]]:
    """Find transitive paths from non-admin Users to high-risk Permission nodes.

    Returns a list of dicts:
      { user, action, resource, path: [ {labels, props}, ... ] }
    """
    # Variable-length relationship bounds cannot use Cypher parameters — interpolate directly
    q = (
        f"MATCH (u:User) WHERE NOT u:Admin "
        f"MATCH path = (u)-[*1..{max_hops}]->(perm:Permission) "
        "WHERE toLower(perm.action) CONTAINS 'delete' OR toLower(perm.action) CONTAINS 'passrole' OR perm.action = '*' "
        "RETURN u.name AS user, perm.action AS action, perm.resource AS resource, path LIMIT 200"
    )

    with driver.session() as session:
        res = session.run(q)
        out = []
        for record in res:
            path = record["path"]
            nodes = []
            for n in path.nodes:
                nodes.append({"labels": list(n.labels), "props": dict(n)})
            out.append({
                "user": record["user"],
                "action": record["action"],
                "resource": record["resource"],
                "path": nodes,
            })
    return out


def _is_sailpoint_data(driver) -> bool:
    """Return True if Neo4j contains SailPoint-sourced Role or Permission nodes."""
    with driver.session() as session:
        result = session.run(
            "MATCH (r:Role) WHERE r.Source STARTS WITH 'sailpoint:' RETURN count(r) AS n LIMIT 1"
        )
        record = result.single()
        return (record["n"] if record else 0) > 0


def ollama_generate(system_prompt: str, user_prompt: str, model: Optional[str] = None, timeout: int = 30) -> str:
    """Send prompts to a local Ollama instance."""
    url = "http://localhost:11434/api/generate"
    model = model or "llama2"
    json_guard = "OUTPUT MUST BE VALID JSON ONLY. DO NOT OUTPUT ANY EXPLANATION OR MARKDOWN."
    combined = f"<SYSTEM>\n{system_prompt}\n{json_guard}\n</SYSTEM>\n<USER>\n{user_prompt}\n</USER>"
    try:
        resp = requests.post(url, json={"model": model, "prompt": combined}, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, dict) and "output" in data:
            return data["output"]
        if isinstance(data, dict) and "text" in data:
            return data["text"]
        return json.dumps(data)
    except Exception as e:
        raise RuntimeError(f"Ollama not reachable: {e}") from e


def openai_generate(system_prompt: str, user_prompt: str, model: Optional[str] = None, timeout: int = 30) -> str:
    """Use OpenAI ChatCompletion (if `openai` package and API key available)."""
    try:
        import openai
        key = os.getenv("OPENAI_API_KEY")
        if not key:
            raise RuntimeError("OPENAI_API_KEY not set")
        openai.api_key = key
        model = model or "gpt-4o-mini"
        json_guard = "OUTPUT MUST BE VALID JSON ONLY. DO NOT OUTPUT ANY EXPLANATION OR MARKDOWN."
        messages = [
            {"role": "system", "content": system_prompt + "\n" + json_guard},
            {"role": "user", "content": user_prompt},
        ]
        resp = openai.ChatCompletion.create(model=model, messages=messages, timeout=timeout)
        if resp and "choices" in resp and len(resp["choices"]) > 0:
            return resp["choices"][0]["message"]["content"]
        return json.dumps(resp)
    except Exception as e:
        logger.warning("OpenAI request failed: %s", e)
        return json.dumps({"summary": "OpenAI unavailable or failed", "error": str(e)})


def anthropic_generate(system_prompt: str, user_prompt: str, model: Optional[str] = None, timeout: int = 30) -> str:
    """Use Anthropic Messages API via `anthropic` package and ANTHROPIC_API_KEY."""
    try:
        from anthropic import Anthropic
        key = os.getenv("ANTHROPIC_API_KEY")
        if not key:
            raise RuntimeError("ANTHROPIC_API_KEY not set")
        client = Anthropic(api_key=key)
        model = model or "claude-sonnet-4-6"
        json_guard = "OUTPUT MUST BE VALID JSON ONLY. DO NOT OUTPUT ANY EXPLANATION OR MARKDOWN."
        resp = client.messages.create(
            model=model,
            max_tokens=1500,
            system=system_prompt + "\n" + json_guard,
            messages=[{"role": "user", "content": user_prompt}],
        )
        return resp.content[0].text
    except Exception as e:
        logger.warning("Anthropic request failed: %s", e)
        return json.dumps({"summary": "Anthropic unavailable or failed", "error": str(e)})


def generate_llm(system_prompt: str, user_prompt: str, model: Optional[str] = None, backend: str = "ollama", timeout: int = 30) -> str:
    """Dispatch to the selected LLM backend. Supported backends: ollama, openai, anthropic."""
    backend = (backend or "ollama").lower()
    if backend == "openai":
        return openai_generate(system_prompt, user_prompt, model=model, timeout=timeout)
    if backend == "anthropic":
        return anthropic_generate(system_prompt, user_prompt, model=model, timeout=timeout)
    return ollama_generate(system_prompt, user_prompt, model=model, timeout=timeout)


def _validate_llm_output(parsed: Dict[str, Any], schema_name: str) -> Optional[str]:
    """Validate parsed LLM JSON against a small schema. Returns None if valid, else error string."""
    try:
        if schema_name == "analyze":
            schema = {
                "type": "object",
                "properties": {
                    "findings": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "action": {"type": "string"},
                                "resource": {"type": "string"},
                                "last_used": {"type": "string"},
                                "roles": {"type": "array"},
                                "risk": {"type": "string"},
                                "risk_score": {"type": "integer", "minimum": 1, "maximum": 10},
                                "risk_score_after": {"type": ["integer", "null"]},
                                "mitre_technique": {"type": "string"},
                            },
                            "required": ["action", "resource", "risk_score", "mitre_technique"]
                        }
                    },
                    "shadow_admin_paths": {"type": "array"},
                    "overall_risk": {"type": "string"},
                    "executive_summary": {"type": "string"},
                },
                "required": ["findings"]
            }
        elif schema_name == "consolidation":
            schema = {
                "type": "object",
                "properties": {
                    "standard_role_name": {"type": "string"},
                    "suggested_policy": {"type": "object"},
                    "justification": {"type": "string"},
                    "remediation_steps": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["standard_role_name", "suggested_policy", "remediation_steps"]
            }
        else:
            return None
        jsonschema_validate(instance=parsed, schema=schema)
        return None
    except ValidationError as e:
        return str(e)


def _build_system_prompt(rag_context: str = "", sailpoint: bool = False) -> str:
    sailpoint_hint = ""
    if sailpoint:
        sailpoint_hint = (
            "\n\nData source: SailPoint IdentityNow. Findings represent SailPoint identities, roles, "
            "access profiles, and entitlements. Remediation steps should reference SailPoint-native "
            "actions (e.g. 'Revoke entitlement in IdentityNow', 'Remove access profile from identity', "
            "'Trigger access certification campaign for this role') rather than AWS-specific actions."
        )

    base = (
        "You are a Senior IAM Engineer. Given raw findings from an IAM graph and any transitive path contexts, produce a "
        "single JSON object with the following schema:\n{\n  \"findings\": [ {\n    \"action\": \"<action>\",\n    \"resource\": \"<resource>\",\n    \"last_used\": \"<iso>\",\n    \"roles\": [\"role1\"],\n    \"risk\": \"LOW|MEDIUM|HIGH\",\n    \"risk_score\": \"<1-10>\",\n    \"risk_score_after\": \"<1-10|null>\",\n    \"mitre_technique\": \"<TXXXX>\",\n    \"justification\": \"<text>\",\n    \"suggested_policy\": {\n      \"Version\": \"2012-10-17\",\n      \"Statement\": [ { \"Effect\": \"Allow\", \"Action\": [\"...\"], \"Resource\": [\"...\"] } ]\n    },\n    \"remediation_steps\": [\"Remove user from group X\", \"Detach policy Y from role Z\"]\n  } ],\n  \"shadow_admin_paths\": [ {\n    \"user\": \"<user>\",\n    \"action\": \"<action>\",\n    \"resource\": \"<resource>\",\n    \"path\": [ { \"labels\": [\"User\"], \"props\": {\"name\": \"Alice\"} }, ... ]\n  } ],\n  \"overall_risk\": \"LOW|MEDIUM|HIGH\",\n  \"summary\": \"<text>\",\n  \"executive_summary\": \"<one-paragraph CISO-friendly summary of risk reduction and business impact>\"\n}\n\n"
        "Be explicit: for each finding include a `mitre_technique` (e.g. TXXXX) and a numeric `risk_score` (1-10). If you propose a remediation, include an estimated `risk_score_after` (1-10) showing the expected risk after the change. For each shadow path, recommend the minimum change to break the transitive path (a single actionable remediation like 'Remove Alice from group X' or 'Detach policy ARN'). Also include an `executive_summary` that quantifies risk reduction (approximate percentage) and a short business rationale."
        + sailpoint_hint
    )
    if rag_context:
        base = (
            base
            + "\n\n--- RETRIEVED CONTEXT (use this to inform risk scoring and MITRE mapping) ---\n"
            + rag_context
            + "\n--- END RETRIEVED CONTEXT ---"
        )
    return base


def analyze(
    uri: str,
    user: str,
    password: str,
    days: int = 90,
    model: Optional[str] = None,
    backend: str = "ollama",
    embed_fn=None,
) -> Dict[str, Any]:
    """Run zombie-permission detection and send findings to the LLM, returning parsed JSON.

    If `embed_fn` is provided, runs RAG retrieval to augment the system prompt with
    semantically relevant IAM security knowledge before calling the LLM.

    Returns the parsed JSON if LLM returns valid JSON, else returns a dict with `raw` key.
    """
    driver = _get_driver(uri, user, password)
    try:
        findings = find_zombie_permissions(driver, days=days)
        shadow_paths = find_shadow_admin_paths(driver, max_hops=6)
        sailpoint = _is_sailpoint_data(driver)

        rag_context = ""
        if embed_fn is not None:
            try:
                from .rag.retriever import retrieve_iam_context, build_finding_queries
                queries = build_finding_queries(findings, shadow_paths)
                rag_context = retrieve_iam_context(driver, queries, embed_fn, top_k=5)
                if rag_context:
                    logger.info("RAG context retrieved (%d chars)", len(rag_context))
            except Exception as exc:
                logger.warning("RAG retrieval failed, continuing without context: %s", exc)
    finally:
        driver.close()

    system_prompt = _build_system_prompt(rag_context=rag_context, sailpoint=sailpoint)
    user_prompt = (
        f"Findings:\n{json.dumps(findings, indent=2)}\n\n"
        f"Shadow_Admin_Paths:\n{json.dumps(shadow_paths, indent=2)}\n\n"
        "Provide structured recommendations as JSON."
    )
    llm_out = generate_llm(system_prompt, user_prompt, model=model, backend=backend)

    try:
        parsed = json.loads(llm_out)
        v_err = _validate_llm_output(parsed, "analyze")
        if v_err:
            return {"raw": llm_out, "validation_error": v_err, "findings": findings, "shadow_paths": shadow_paths}
        parsed.setdefault("_context", {})
        parsed["_context"]["findings"] = findings
        parsed["_context"]["shadow_paths"] = shadow_paths
        parsed["_context"]["rag_used"] = bool(rag_context)
        parsed["_context"]["sailpoint"] = sailpoint
        return parsed
    except Exception:
        return {"raw": llm_out, "findings": findings, "shadow_paths": shadow_paths}


def _get_roles_permissions(driver) -> Dict[str, set]:
    """Return a mapping of role name -> set of permission strings (action|resource)."""
    q = (
        "MATCH (r:Role)-[:HAS_PERMISSION]->(p:Permission)"
        " RETURN r.name AS role, collect(distinct p.action + '|' + p.resource) AS perms"
    )
    with driver.session() as session:
        res = session.run(q)
        out = {}
        for rec in res:
            role = rec["role"]
            perms = rec["perms"] or []
            out[role] = set(perms)
    return out


def compute_role_similarities(role_perms: Dict[str, set]) -> List[Dict[str, Any]]:
    """Compute Jaccard similarity between all role pairs."""
    roles = list(role_perms.keys())
    results = []
    for i in range(len(roles)):
        for j in range(i + 1, len(roles)):
            a = roles[i]
            b = roles[j]
            pa = role_perms.get(a, set())
            pb = role_perms.get(b, set())
            inter = pa.intersection(pb)
            uni = pa.union(pb)
            jaccard = float(len(inter)) / float(len(uni)) if len(uni) > 0 else 0.0
            results.append({
                "role_a": a,
                "role_b": b,
                "intersection": len(inter),
                "union": len(uni),
                "jaccard": jaccard,
            })
    return results


def find_similar_role_clusters(driver, threshold: float = 0.8) -> List[Dict[str, Any]]:
    """Identify clusters of roles with pairwise similarity >= threshold."""
    role_perms = _get_roles_permissions(driver)
    sims = compute_role_similarities(role_perms)

    adj = {r: set() for r in role_perms.keys()}
    for s in sims:
        if s["jaccard"] >= threshold:
            adj[s["role_a"]].add(s["role_b"])
            adj[s["role_b"]].add(s["role_a"])

    visited = set()
    clusters = []
    for r in adj:
        if r in visited:
            continue
        stack = [r]
        comp = []
        while stack:
            node = stack.pop()
            if node in visited:
                continue
            visited.add(node)
            comp.append(node)
            for nbr in adj[node]:
                if nbr not in visited:
                    stack.append(nbr)
        if len(comp) > 1:
            perms_union = set()
            for role in comp:
                perms_union.update(role_perms.get(role, set()))
            clusters.append({"roles": comp, "permissions": sorted(list(perms_union))})
    return clusters


def _build_consolidation_prompt(cluster: Dict[str, Any]) -> str:
    roles = cluster.get("roles", [])
    perms = cluster.get("permissions", [])
    example_perm_lines = []
    for p in perms[:100]:
        if "|" in p:
            action, resource = p.split("|", 1)
        else:
            action, resource = p, "*"
        example_perm_lines.append(f"- Action: {action}, Resource: {resource}")

    prompt = (
        "You are a Senior IAM Engineer tasked with consolidating similar roles.\n"
        "Given the following cluster of roles and their combined permissions, propose a single standardized role name and a minimal policy (JSON) that covers required permissions while removing redundant or overly broad permissions.\n\n"
        f"Roles: {roles}\n\nPermissions (sample):\n{chr(10).join(example_perm_lines)}\n\n"
        "Output a JSON object with keys: `standard_role_name`, `suggested_policy` (IAM policy JSON), `justification`, and `remediation_steps` (list of actionable steps to consolidate)."
    )
    return prompt


def consolidate_roles(
    uri: str,
    user: str,
    password: str,
    threshold: float = 0.8,
    model: Optional[str] = None,
    backend: str = "ollama",
    embed_fn=None,
) -> Dict[str, Any]:
    """Find similar role clusters and ask the LLM to suggest consolidated roles."""
    driver = _get_driver(uri, user, password)
    clusters = find_similar_role_clusters(driver, threshold=threshold)
    results = []
    for c in clusters:
        rag_context = ""
        if embed_fn is not None:
            try:
                from .rag.retriever import retrieve_iam_context
                role_query = f"Role consolidation for roles: {', '.join(c.get('roles', []))}"
                perm_queries = [
                    f"IAM permission: {p.split('|')[0]} on {p.split('|')[1] if '|' in p else '*'}"
                    for p in c.get("permissions", [])[:10]
                ]
                rag_context = retrieve_iam_context(
                    driver, [role_query] + perm_queries, embed_fn, top_k=4
                )
            except Exception as exc:
                logger.warning("RAG retrieval failed for cluster consolidation: %s", exc)

        prompt = _build_consolidation_prompt(c)
        sys_prompt = _build_system_prompt(rag_context=rag_context)
        llm_out = generate_llm(sys_prompt, prompt, model=model, backend=backend)
        try:
            parsed = json.loads(llm_out)
            v_err = _validate_llm_output(parsed, "consolidation")
            if v_err:
                parsed = {"raw": llm_out, "validation_error": v_err}
        except Exception:
            parsed = {"raw": llm_out}
        results.append({"cluster": c, "recommendation": parsed})
    driver.close()
    return {"clusters": results}


def generate_iac_from_policy(
    suggested_policy: Dict[str, Any],
    standard_role_name: str,
    output_dir: str,
    principal_arn: Optional[str] = None,
) -> Dict[str, str]:
    """Generate IaC artifacts from a suggested IAM policy.

    Writes `<standard_role_name>_policy.json` and `<standard_role_name>.tf` to `output_dir`.
    Returns dict with paths: {"json": path, "tf": path}
    """
    if not principal_arn:
        logger.warning(
            "No principal_arn provided for role '%s' — Terraform assume_role_policy uses a placeholder.",
            standard_role_name,
        )

    os.makedirs(output_dir, exist_ok=True)
    safe_name = standard_role_name.replace(" ", "_").lower()
    json_path = os.path.join(output_dir, f"{safe_name}_policy.json")
    tf_path = os.path.join(output_dir, f"{safe_name}.tf")

    with open(json_path, "w") as f:
        json.dump(suggested_policy, f, indent=2)

    role_res_name = f"{safe_name}_role"
    attach_res_name = f"{safe_name}_attach"

    tf_policy = (
        f'resource "aws_iam_policy" "{safe_name}" {{\n'
        f'  name   = "{standard_role_name}-policy"\n'
        f"  policy = <<POLICY\n{json.dumps(suggested_policy, indent=2)}\nPOLICY\n}}\n\n"
    )

    assume_principal = principal_arn or "REPLACE_WITH_PRINCIPAL_ARN"
    assume_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": assume_principal},
                "Action": "sts:AssumeRole",
            }
        ],
    }

    tf_role = (
        f'resource "aws_iam_role" "{role_res_name}" {{\n'
        f'  name = "{standard_role_name}-role"\n'
        f"  assume_role_policy = <<POLICY\n{json.dumps(assume_policy, indent=2)}\nPOLICY\n}}\n\n"
    )

    tf_attach = (
        f'resource "aws_iam_role_policy_attachment" "{attach_res_name}" {{\n'
        f'  role       = aws_iam_role.{role_res_name}.name\n'
        f'  policy_arn = aws_iam_policy.{safe_name}.arn\n'
        f"}}\n"
    )

    with open(tf_path, "w") as f:
        f.write(tf_policy + tf_role + tf_attach)

    return {"json": json_path, "tf": tf_path}
