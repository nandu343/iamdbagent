"""Analyzer module: runs Neo4j queries and forwards findings to a local LLM (Ollama) for recommendations.

Features:
- `find_zombie_permissions(driver, days=90)` runs a Cypher query to find permissions not used in `days` days.
- `ollama_generate(system_prompt, user_prompt, model)` sends prompts to a local Ollama HTTP API if available.
- `analyze(uri, user, password, days=90, model=None)` orchestrates query -> LLM -> parsed JSON output.

The LLM is instructed to act as a Senior IAM Engineer and return structured JSON recommendations.
"""
from neo4j import GraphDatabase
import datetime
import json
import requests
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


def _get_driver(uri: str, user: str, password: str):
    return GraphDatabase.driver(uri, auth=(user, password))


def find_zombie_permissions(driver, days: int = 90) -> List[Dict[str, Any]]:
    """Return list of permissions not used in the last `days` days.

    Each item contains: action, resource, last_used, roles (list of role names)
    """
    cutoff_clause = f"datetime() - duration({{days: {days}}})"
    q = (
        "MATCH (r:Role)-[:HAS_PERMISSION]->(p:Permission)"
        " WHERE datetime(p.last_used) < "
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
    q = (
        "MATCH (u:User) WHERE NOT u:Admin "
        "MATCH path = (u)-[*1..$max_hops]->(perm:Permission) "
        "WHERE toLower(perm.action) CONTAINS 'delete' OR toLower(perm.action) CONTAINS 'passrole' OR perm.action = '*' "
        "RETURN u.name AS user, perm.action AS action, perm.resource AS resource, path LIMIT 200"
    )

    with driver.session() as session:
        res = session.run(q, max_hops=max_hops)
        out = []
        for record in res:
            path = record["path"]
            nodes = []
            # `path` is a neo4j.graph.Path; extract node labels and properties
            for n in path.nodes:
                nodes.append({"labels": list(n.labels), "props": dict(n)})
            out.append({
                "user": record["user"],
                "action": record["action"],
                "resource": record["resource"],
                "path": nodes,
            })
    return out


def ollama_generate(system_prompt: str, user_prompt: str, model: Optional[str] = None, timeout: int = 30) -> str:
    """Send prompts to a local Ollama instance. Falls back to a simple heuristic if Ollama isn't reachable.

    Expects Ollama HTTP API at http://localhost:11434/api/generate
    Body: {"model": "<model>", "prompt": "<combined prompt>"}
    """
    url = "http://localhost:11434/api/generate"
    model = model or "llama2"
    combined = f"<SYSTEM>\n{system_prompt}\n</SYSTEM>\n<USER>\n{user_prompt}\n</USER>"
    try:
        resp = requests.post(url, json={"model": model, "prompt": combined}, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        # Ollama may stream; try to extract text safely
        if isinstance(data, dict) and "output" in data:
            return data["output"]
        if isinstance(data, dict) and "text" in data:
            return data["text"]
        return json.dumps(data)
    except Exception as e:
        logger.warning("Ollama not reachable (%s). Falling back to local summary.", e)
        # Fallback: echo a minimal JSON recommendation for quick testing
        fallback = {
            "summary": "Ollama unavailable; returning synthetic recommendation",
            "recommendations": [],
        }
        return json.dumps(fallback)


def _build_system_prompt() -> str:
    return (
        "You are a Senior IAM Engineer. Given raw findings from an IAM graph and any transitive path contexts, produce a "
        "single JSON object with the following schema:\n{\n  \"findings\": [ {\n    \"action\": \"<action>\",\n    \"resource\": \"<resource>\",\n    \"last_used\": \"<iso>\",\n    \"roles\": [\"role1\"],\n    \"risk\": \"LOW|MEDIUM|HIGH\",\n    \"justification\": \"<text>\",\n    \"suggested_policy\": {\n      \"Version\": \"2012-10-17\",\n      \"Statement\": [ { \"Effect\": \"Allow\", \"Action\": [\"...\"], \"Resource\": [\"...\"] } ]\n    },\n    \"remediation_steps\": [\"Remove user from group X\", \"Detach policy Y from role Z\"]\n  } ],\n  \"shadow_admin_paths\": [ {\n    \"user\": \"<user>\",\n    \"action\": \"<action>\",\n    \"resource\": \"<resource>\",\n    \"path\": [ { \"labels\": [\"User\"], \"props\": {\"name\": \"Alice\"} }, ... ]\n  } ],\n  \"overall_risk\": \"LOW|MEDIUM|HIGH\",\n  \"summary\": \"<text>\"\n}\n\nBe explicit: for each shadow path, recommend the minimum change to break the transitive path (a single actionable remediation like 'Remove Alice from group X' or 'Detach policy ARN')."
    )


def analyze(uri: str, user: str, password: str, days: int = 90, model: Optional[str] = None) -> Dict[str, Any]:
    """Run zombie-permission detection and send findings to the LLM, returning parsed JSON.

    Returns the parsed JSON if LLM returns valid JSON, else returns a dict with `raw` key.
    """
    driver = _get_driver(uri, user, password)
    findings = find_zombie_permissions(driver, days=days)
    shadow_paths = find_shadow_admin_paths(driver, max_hops=6)
    driver.close()

    system_prompt = _build_system_prompt()
    user_prompt = (
        f"Findings:\n{json.dumps(findings, indent=2)}\n\n"
        f"Shadow_Admin_Paths:\n{json.dumps(shadow_paths, indent=2)}\n\n"
        "Provide structured recommendations as JSON."
    )
    llm_out = ollama_generate(system_prompt, user_prompt, model=model)

    # Try to parse JSON from LLM output
    try:
        parsed = json.loads(llm_out)
        # attach raw detection context for traceability
        parsed.setdefault("_context", {})
        parsed["_context"]["findings"] = findings
        parsed["_context"]["shadow_paths"] = shadow_paths
        return parsed
    except Exception:
        return {"raw": llm_out, "findings": findings, "shadow_paths": shadow_paths}


if __name__ == "__main__":
    import os
    uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    user = os.getenv("NEO4J_USER", "neo4j")
    password = os.getenv("NEO4J_PASS", "password")
    out = analyze(uri, user, password)
    print(json.dumps(out, indent=2))


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
    """Compute Jaccard similarity between all role pairs.

    Returns list of {role_a, role_b, intersection, union, jaccard}
    """
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
    """Identify clusters of roles with pairwise similarity >= threshold using graph connectivity.

    Returns list of clusters: {roles: [...], permissions: [...]}
    """
    role_perms = _get_roles_permissions(driver)
    sims = compute_role_similarities(role_perms)

    # build adjacency
    adj = {r: set() for r in role_perms.keys()}
    for s in sims:
        if s["jaccard"] >= threshold:
            adj[s["role_a"]].add(s["role_b"])
            adj[s["role_b"]].add(s["role_a"])

    # find connected components
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
            # compute union of permissions
            perms_union = set()
            for role in comp:
                perms_union.update(role_perms.get(role, set()))
            clusters.append({"roles": comp, "permissions": sorted(list(perms_union))})
    return clusters


def _build_consolidation_prompt(cluster: Dict[str, Any]) -> str:
    """Create a system/user prompt asking the LLM to propose a standardized role for the cluster."""
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


def consolidate_roles(uri: str, user: str, password: str, threshold: float = 0.8, model: Optional[str] = None) -> Dict[str, Any]:
    """Find similar role clusters and ask the LLM to suggest consolidated roles.

    Returns a dict with `clusters` each containing LLM recommendations.
    """
    driver = _get_driver(uri, user, password)
    clusters = find_similar_role_clusters(driver, threshold=threshold)
    results = []
    for c in clusters:
        prompt = _build_consolidation_prompt(c)
        llm_out = ollama_generate(_build_system_prompt(), prompt, model=model)
        try:
            parsed = json.loads(llm_out)
        except Exception:
            parsed = {"raw": llm_out}
        results.append({"cluster": c, "recommendation": parsed})
    driver.close()
    return {"clusters": results}
