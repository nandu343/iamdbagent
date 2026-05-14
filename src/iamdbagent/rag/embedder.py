"""IAM graph vectorization: embed nodes and build a static knowledge base in Neo4j.

Exports:
- `make_embed_fn(backend, model)` -> Callable[[str], List[float]]
- `embed_iam_graph(uri, user, password, embed_fn)` -> stats dict
- `seed_knowledge_base(uri, user, password, embed_fn)` -> int (entries created)
- `ensure_vector_indexes(driver, dimensions)` -> None

Supported embedding backends:
  openai  — text-embedding-3-small (1536-dim). Requires OPENAI_API_KEY.
  ollama  — nomic-embed-text (768-dim). Requires local Ollama instance.
  local   — all-MiniLM-L6-v2 via sentence-transformers (384-dim). Requires pip install sentence-transformers.
"""
import logging
import os
from typing import Callable, Dict, List, Any

from neo4j import GraphDatabase

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Static IAM risk knowledge base
# Each entry: (action_pattern, mitre_id, narrative)
# These get embedded and stored as :KnowledgeEntry nodes for RAG retrieval.
# ---------------------------------------------------------------------------
_IAM_KNOWLEDGE: List[Dict[str, str]] = [
    # Privilege escalation via service binding
    {
        "action": "iam:PassRole",
        "mitre": "T1078.004",
        "text": (
            "iam:PassRole enables privilege escalation by letting a user assign a "
            "high-privilege IAM role to a compute service (Lambda, EC2, Glue, ECS). "
            "An attacker with this permission and CreateFunction can invoke code as an "
            "admin-level role without directly assuming it. [MITRE T1078.004 Cloud Accounts]"
        ),
    },
    {
        "action": "iam:CreateRole + iam:AttachRolePolicy",
        "mitre": "T1098",
        "text": (
            "Combining iam:CreateRole and iam:AttachRolePolicy allows self-escalation: "
            "a user creates a new role with AdministratorAccess and then attaches it to "
            "themselves or a service they control. Least-privilege requires these actions "
            "be restricted to identity/IAM teams only. [MITRE T1098 Account Manipulation]"
        ),
    },
    # Account lifecycle abuse
    {
        "action": "iam:DeleteUser",
        "mitre": "T1531",
        "text": (
            "iam:DeleteUser can be used post-compromise to delete accounts and destroy "
            "audit trails, or to lock out legitimate administrators during an attack. "
            "This permission should be restricted to break-glass accounts and audited "
            "with CloudTrail alerts. [MITRE T1531 Account Access Removal]"
        ),
    },
    {
        "action": "iam:CreateUser",
        "mitre": "T1136.003",
        "text": (
            "iam:CreateUser permits creation of persistent backdoor accounts. Attackers "
            "create shadow admin users to maintain access after initial credentials are "
            "rotated. Should require MFA and be restricted to provisioning pipelines. "
            "[MITRE T1136.003 Create Cloud Account]"
        ),
    },
    {
        "action": "iam:UpdateAccessKey",
        "mitre": "T1098.001",
        "text": (
            "iam:UpdateAccessKey can reactivate disabled access keys, restoring attacker "
            "access after a security team disables credentials. Pair with CloudTrail "
            "alerting and restrict to IAM automation roles. [MITRE T1098.001 Additional Cloud Credentials]"
        ),
    },
    # Policy manipulation
    {
        "action": "iam:PutUserPolicy / iam:PutRolePolicy",
        "mitre": "T1548",
        "text": (
            "Inline policy write permissions (PutUserPolicy, PutRolePolicy) allow "
            "an actor to escalate their own privileges by injecting an inline policy "
            "with broad Allow statements. These are among the highest-risk IAM actions "
            "and should be absent from any non-admin role. [MITRE T1548 Abuse Elevation Control Mechanism]"
        ),
    },
    {
        "action": "iam:AttachUserPolicy",
        "mitre": "T1548",
        "text": (
            "iam:AttachUserPolicy lets a user attach any managed policy (including "
            "AdministratorAccess) to themselves. Combined with iam:ListPolicies it "
            "becomes trivial self-escalation. Should be paired with a permission boundary "
            "enforcing condition keys. [MITRE T1548]"
        ),
    },
    # Wildcard permissions
    {
        "action": "*",
        "mitre": "T1078",
        "text": (
            "Wildcard action (*) grants full access to all AWS services and operations. "
            "This is equivalent to AdministratorAccess and violates the principle of "
            "least privilege. Any role or user with Action:* Resource:* should be "
            "treated as a critical finding and remediated immediately. [MITRE T1078 Valid Accounts]"
        ),
    },
    {
        "action": "iam:*",
        "mitre": "T1098",
        "text": (
            "iam:* grants complete control over IAM: create/delete users, roles, policies, "
            "access keys. An identity with iam:* can trivially escalate to full admin. "
            "Should be replaced with scoped permissions and restricted to dedicated "
            "IAM-management roles with MFA enforcement. [MITRE T1098]"
        ),
    },
    {
        "action": "s3:*",
        "mitre": "T1530",
        "text": (
            "s3:* on resource:* provides read and write access to all S3 buckets in the "
            "account including sensitive data stores. Attackers use this for data "
            "exfiltration. Replace with scoped actions (s3:GetObject, s3:PutObject) on "
            "specific bucket ARNs. [MITRE T1530 Data from Cloud Storage Object]"
        ),
    },
    {
        "action": "ec2:*",
        "mitre": "T1578",
        "text": (
            "ec2:* allows creating, modifying, and terminating compute instances. "
            "Attackers can spin up instances for crypto mining, exfiltrate data by "
            "attaching EBS volumes, or snapshot sensitive disks. Scope to specific "
            "ec2 actions required for the workload. [MITRE T1578 Modify Cloud Compute Infrastructure]"
        ),
    },
    # Secrets & credential access
    {
        "action": "secretsmanager:GetSecretValue",
        "mitre": "T1555",
        "text": (
            "secretsmanager:GetSecretValue on Resource:* allows reading all secrets in "
            "the account including database passwords, API keys, and TLS certificates. "
            "Restrict to specific secret ARNs and audit with CloudTrail. "
            "[MITRE T1555 Credentials from Password Stores]"
        ),
    },
    {
        "action": "kms:Decrypt",
        "mitre": "T1486",
        "text": (
            "kms:Decrypt on Resource:* enables decryption of any KMS-encrypted data "
            "in the account. This bypasses data-at-rest encryption protections. "
            "Scope to specific KMS key ARNs relevant to the workload. "
            "[MITRE T1486 Data Encrypted for Impact / credential theft]"
        ),
    },
    # Zombie / unused permission risk
    {
        "action": "zombie_permission_never_used",
        "mitre": "T1078",
        "text": (
            "Permissions that have never been used (last_used: null) are high-confidence "
            "candidates for removal. They expand the blast radius of compromise without "
            "providing business value. Removing them reduces attack surface with zero "
            "operational impact. Always verify with the resource owner before removal. "
            "[MITRE T1078 Valid Accounts — standing privilege reduction]"
        ),
    },
    {
        "action": "zombie_permission_stale_90d",
        "mitre": "T1078",
        "text": (
            "Permissions unused for 90+ days indicate role scope creep or abandoned "
            "service accounts. They should be removed or moved to a restricted role "
            "requiring explicit re-approval. Access reviews every 60-90 days align with "
            "SOC2 and ISO 27001 controls. [MITRE T1078]"
        ),
    },
    # Role consolidation patterns
    {
        "action": "role_consolidation_best_practice",
        "mitre": "N/A",
        "text": (
            "Roles with Jaccard similarity >= 0.8 are strong consolidation candidates. "
            "Merging them reduces IAM policy sprawl, simplifies auditing, and eliminates "
            "duplicate permission grants. The consolidated role should use the union of "
            "permissions scoped to specific resources rather than wildcards. "
            "Assign a clear naming convention (e.g., svc-<team>-<function>-role)."
        ),
    },
    {
        "action": "service_account_hardening",
        "mitre": "T1078.004",
        "text": (
            "Service accounts (non-human identities) should follow least-privilege strictly: "
            "no console access, rotating credentials, scoped to specific resources. "
            "Service accounts with AdministratorAccess or iam:* are critical risk — "
            "they should be replaced with task-specific roles and use instance profiles "
            "or OIDC federation instead of long-lived access keys. [MITRE T1078.004]"
        ),
    },
    # SailPoint-specific patterns
    {
        "action": "sailpoint_access_certification",
        "mitre": "N/A",
        "text": (
            "SailPoint access certifications that have not been completed for 90+ days "
            "indicate entitlements that lack formal business justification. "
            "Uncertified entitlements should be auto-revoked or escalated to the "
            "access owner. This aligns with SOX and HIPAA periodic access review requirements."
        ),
    },
    {
        "action": "sailpoint_segregation_of_duties",
        "mitre": "T1078",
        "text": (
            "Segregation of Duties (SoD) conflicts occur when a single identity holds "
            "entitlements that together allow both initiating and approving a transaction. "
            "In SailPoint, SoD policies should block entitlement combinations like "
            "AP_CREATE_VENDOR + AP_APPROVE_PAYMENT. Undetected SoD violations are a "
            "primary fraud vector. [MITRE T1078 — insider threat / account abuse]"
        ),
    },
    {
        "action": "sailpoint_orphan_account",
        "mitre": "T1531",
        "text": (
            "Orphan accounts in SailPoint are identities no longer associated with an "
            "active employee or contractor (correlated identity = null). These accounts "
            "retain all previously granted access and represent standing unauthorized "
            "access. They should be disabled immediately and queued for formal deprovisioning. "
            "[MITRE T1531 Account Access Removal]"
        ),
    },
    {
        "action": "sailpoint_role_mining",
        "mitre": "N/A",
        "text": (
            "SailPoint role mining identifies natural permission groupings across identities. "
            "When 80%+ of users in a population share the same entitlement set, those "
            "entitlements should be codified into a business role for automatic assignment "
            "and deprovisioning. This reduces manual access requests by 60-80% in practice."
        ),
    },
    # Broad data access
    {
        "action": "dynamodb:* / rds-data:ExecuteStatement",
        "mitre": "T1213",
        "text": (
            "Wildcard database permissions allow dumping all records from application "
            "databases. Scope to specific table ARNs and use VPC endpoint policies to "
            "prevent exfiltration paths. Enable CloudTrail data events on DynamoDB "
            "for anomaly detection. [MITRE T1213 Data from Information Repositories]"
        ),
    },
    # Lambda / compute abuse
    {
        "action": "lambda:InvokeFunction",
        "mitre": "T1648",
        "text": (
            "lambda:InvokeFunction on Resource:* lets any caller invoke all Lambda "
            "functions in the account, including those with privileged execution roles. "
            "Combined with iam:PassRole, this is a common privilege escalation path. "
            "Restrict to specific function ARNs and add resource-based policies. "
            "[MITRE T1648 Serverless Execution]"
        ),
    },
]


# ---------------------------------------------------------------------------
# Embedding backends
# ---------------------------------------------------------------------------

def _embed_openai(text: str, model: str) -> List[float]:
    import openai
    key = os.getenv("OPENAI_API_KEY")
    if not key:
        raise RuntimeError("OPENAI_API_KEY not set")
    client = openai.OpenAI(api_key=key)
    resp = client.embeddings.create(input=[text], model=model)
    return resp.data[0].embedding


def _embed_ollama(text: str, model: str) -> List[float]:
    import requests
    resp = requests.post(
        "http://localhost:11434/api/embeddings",
        json={"model": model, "prompt": text},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["embedding"]


def _embed_local(text: str, model: str) -> List[float]:
    try:
        from sentence_transformers import SentenceTransformer
    except ImportError as exc:
        raise ImportError(
            "sentence-transformers not installed. Run: pip install sentence-transformers"
        ) from exc
    _model = SentenceTransformer(model)
    return _model.encode(text).tolist()


_DEFAULT_MODELS = {
    "openai": "text-embedding-3-small",
    "ollama": "nomic-embed-text",
    "local": "all-MiniLM-L6-v2",
}

_DIMENSIONS = {
    "openai": 1536,
    "ollama": 768,
    "local": 384,
}


def make_embed_fn(backend: str = "openai", model: str = None) -> Callable[[str], List[float]]:
    """Return a callable embed_fn(text) -> List[float] for the given backend."""
    backend = backend.lower()
    resolved_model = model or _DEFAULT_MODELS.get(backend)
    if not resolved_model:
        raise ValueError(f"Unknown embedding backend: {backend}. Use openai, ollama, or local.")

    if backend == "openai":
        return lambda text: _embed_openai(text, resolved_model)
    if backend == "ollama":
        return lambda text: _embed_ollama(text, resolved_model)
    if backend == "local":
        return lambda text: _embed_local(text, resolved_model)
    raise ValueError(f"Unknown embedding backend: {backend}")


def dimensions_for_backend(backend: str) -> int:
    return _DIMENSIONS.get(backend.lower(), 1536)


# ---------------------------------------------------------------------------
# Neo4j vector index management
# ---------------------------------------------------------------------------

def ensure_vector_indexes(driver, dimensions: int) -> None:
    """Create vector indexes on Permission, Role, Policy, and KnowledgeEntry nodes."""
    indexes = [
        ("idx_permission_embedding", "Permission"),
        ("idx_role_embedding", "Role"),
        ("idx_policy_embedding", "Policy"),
        ("idx_knowledge_embedding", "KnowledgeEntry"),
    ]
    with driver.session() as session:
        for idx_name, label in indexes:
            session.run(
                f"CREATE VECTOR INDEX `{idx_name}` IF NOT EXISTS "
                f"FOR (n:{label}) ON (n.embedding) "
                f"OPTIONS {{indexConfig: {{`vector.dimensions`: {dimensions}, "
                f"`vector.similarity_function`: 'cosine'}}}}"
            )
    logger.info("Vector indexes ensured (dimensions=%d)", dimensions)


# ---------------------------------------------------------------------------
# Text representations for graph nodes
# ---------------------------------------------------------------------------

def _permission_text(action: str, resource: str) -> str:
    return f"IAM permission: {action} on resource {resource}"


def _role_text(name: str, actions: List[str]) -> str:
    actions_str = ", ".join(actions[:20]) if actions else "none"
    return f"IAM role: {name} with permissions: {actions_str}"


def _policy_text(name: str, actions: List[str]) -> str:
    actions_str = ", ".join(actions[:20]) if actions else "none"
    return f"IAM policy or access profile: {name} grants: {actions_str}"


def _knowledge_text(entry: Dict[str, str]) -> str:
    return entry["text"]


# ---------------------------------------------------------------------------
# Main vectorization functions
# ---------------------------------------------------------------------------

def embed_iam_graph(
    uri: str,
    user: str,
    password: str,
    embed_fn: Callable[[str], List[float]],
    backend: str = "openai",
) -> Dict[str, int]:
    """Embed all Permission, Role, and Policy nodes in Neo4j and store embeddings.

    Returns stats dict: {permissions, roles, policies}.
    """
    from neo4j import GraphDatabase
    driver = GraphDatabase.driver(uri, auth=(user, password))
    dims = len(embed_fn("test"))
    ensure_vector_indexes(driver, dims)

    stats: Dict[str, int] = {"permissions": 0, "roles": 0, "policies": 0}

    with driver.session() as session:
        # Permissions
        perms = session.run(
            "MATCH (p:Permission) RETURN p.action AS action, p.resource AS resource, elementId(p) AS eid"
        ).data()
        for p in perms:
            text = _permission_text(p["action"] or "", p["resource"] or "")
            emb = embed_fn(text)
            session.run(
                "MATCH (p:Permission {action: $action, resource: $resource}) SET p.embedding = $emb",
                action=p["action"], resource=p["resource"], emb=emb,
            )
            stats["permissions"] += 1

        # Roles — include their permission actions as context
        roles = session.run(
            "MATCH (r:Role) "
            "OPTIONAL MATCH (r)-[:HAS_PERMISSION]->(p:Permission) "
            "RETURN r.name AS name, elementId(r) AS eid, collect(p.action) AS actions"
        ).data()
        for r in roles:
            text = _role_text(r["name"] or "", r["actions"] or [])
            emb = embed_fn(text)
            session.run(
                "MATCH (r:Role {name: $name}) SET r.embedding = $emb",
                name=r["name"], emb=emb,
            )
            stats["roles"] += 1

        # Policies — include granted actions as context
        policies = session.run(
            "MATCH (pol:Policy) "
            "OPTIONAL MATCH (pol)-[:GRANTS]->(p:Permission) "
            "RETURN pol.arn AS arn, pol.name AS name, collect(p.action) AS actions"
        ).data()
        for pol in policies:
            text = _policy_text(pol["name"] or pol["arn"] or "", pol["actions"] or [])
            emb = embed_fn(text)
            session.run(
                "MATCH (pol:Policy {arn: $arn}) SET pol.embedding = $emb",
                arn=pol["arn"], emb=emb,
            )
            stats["policies"] += 1

    driver.close()
    logger.info("IAM graph embedded: %s", stats)
    return stats


def seed_knowledge_base(
    uri: str,
    user: str,
    password: str,
    embed_fn: Callable[[str], List[float]],
) -> int:
    """Embed and upsert the static IAM risk knowledge base as :KnowledgeEntry nodes.

    Returns the number of entries written.
    """
    from neo4j import GraphDatabase
    driver = GraphDatabase.driver(uri, auth=(user, password))
    dims = len(embed_fn("test"))
    ensure_vector_indexes(driver, dims)

    count = 0
    with driver.session() as session:
        for entry in _IAM_KNOWLEDGE:
            text = _knowledge_text(entry)
            emb = embed_fn(text)
            session.run(
                "MERGE (k:KnowledgeEntry {action: $action}) "
                "SET k.mitre = $mitre, k.text = $text, k.embedding = $emb",
                action=entry["action"],
                mitre=entry["mitre"],
                text=text,
                emb=emb,
            )
            count += 1

    driver.close()
    logger.info("Knowledge base seeded: %d entries", count)
    return count
