"""Neo4j upsert loader for IAM entities with a seed helper.

This module provides two primary functions:
- `load_iam_graph(uri, user, password, data)` — idempotent upserts for Users, Roles, Policies
- `seed_mock_data(uri, user, password)` — injects a small 'Zombie Permission' scenario

Nodes created/used:
- `:User {name, arn}`
- `:Role {name, arn}`
- `:Policy {arn, name}`
- `:Permission {action, resource, last_used}`

Relationships:
- (User)-[:HAS_ROLE]->(Role)
- (Role)-[:HAS_POLICY]->(Policy)
- (User)-[:HAS_POLICY]->(Policy)
- (Role)-[:HAS_PERMISSION]->(Permission)
"""
from neo4j import GraphDatabase
import logging
import datetime

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


def _get_driver(uri: str, user: str, password: str):
    return GraphDatabase.driver(uri, auth=(user, password))


def _tx_upsert_user(tx, user_name, arn=None):
    tx.run(
        "MERGE (u:User {name: $name}) SET u.arn = $arn",
        name=user_name,
        arn=arn,
    )


def _tx_upsert_role(tx, role_name, arn=None):
    tx.run(
        "MERGE (r:Role {name: $name}) SET r.arn = $arn",
        name=role_name,
        arn=arn,
    )


def _tx_upsert_permission(tx, action, resource, last_used_iso=None):
    tx.run(
        "MERGE (p:Permission {action: $action, resource: $resource}) SET p.last_used = $last_used",
        action=action,
        resource=resource,
        last_used=last_used_iso,
    )


def load_iam_graph(uri: str, user: str, password: str, data: dict):
    """Upsert IAM graph entities into Neo4j.

    This function is intentionally minimal and idempotent.
    """
    driver = _get_driver(uri, user, password)
    with driver.session() as session:
        # policies (managed)
        for p in data.get("policies", []):
            arn = p.get("Arn")
            name = p.get("PolicyName")
            session.execute_write(lambda tx, a, n: tx.run("MERGE (p:Policy {arn:$arn}) SET p.name=$name", arn=a, name=n), arn, name)

        # roles
        for r in data.get("roles", []):
            role_name = r.get("RoleName")
            session.execute_write(_tx_upsert_role, role_name, r.get("Arn"))
            # attached managed policies
            for ap in r.get("AttachedPolicies", []):
                session.execute_write(lambda tx, a, n: tx.run("MERGE (p:Policy {arn:$arn}) SET p.name=$name", arn=a, name=n), ap.get("PolicyArn"), ap.get("PolicyName"))
                session.execute_write(
                    lambda tx, rn, arn: tx.run(
                        "MATCH (r:Role {name:$role_name}) MATCH (p:Policy {arn:$arn}) MERGE (r)-[:HAS_POLICY]->(p)",
                        role_name=rn,
                        arn=arn,
                    ),
                    role_name,
                    ap.get("PolicyArn"),
                )

        # users
        for u in data.get("users", []):
            username = u.get("UserName")
            session.execute_write(_tx_upsert_user, username, u.get("Arn"))
            for ap in u.get("AttachedPolicies", []):
                session.execute_write(lambda tx, a, n: tx.run("MERGE (p:Policy {arn:$arn}) SET p.name=$name", arn=a, name=n), ap.get("PolicyArn"), ap.get("PolicyName"))
                session.execute_write(
                    lambda tx, un, arn: tx.run(
                        "MATCH (u:User {name:$user_name}) MATCH (p:Policy {arn:$arn}) MERGE (u)-[:HAS_POLICY]->(p)",
                        user_name=un,
                        arn=arn,
                    ),
                    username,
                    ap.get("PolicyArn"),
                )

    driver.close()


def seed_mock_data(uri: str, user: str, password: str):
    """Seed a 'Zombie Permission' scenario into Neo4j.

    - Create User `Alice`
    - Create Role `CloudOps`
    - Create two Permission nodes:
      - `s3:ListBucket` last_used 2 days ago
      - `iam:DeleteUser` last_used 180 days ago
    - Link: (Alice)-[:HAS_ROLE]->(CloudOps), (CloudOps)-[:HAS_PERMISSION]->(Permission)
    """
    now = datetime.datetime.utcnow()
    two_days_ago = (now - datetime.timedelta(days=2)).isoformat() + "Z"
    one_eighty_days_ago = (now - datetime.timedelta(days=180)).isoformat() + "Z"

    driver = _get_driver(uri, user, password)
    with driver.session() as session:
        # Upsert user and role
        session.execute_write(_tx_upsert_user, "Alice", None)
        session.execute_write(_tx_upsert_role, "CloudOps", None)

        # Link Alice -> CloudOps
        session.execute_write(lambda tx: tx.run("MATCH (u:User {name:$u}) MATCH (r:Role {name:$r}) MERGE (u)-[:HAS_ROLE]->(r)", u="Alice", r="CloudOps"))

        # Permissions
        session.execute_write(_tx_upsert_permission, "s3:ListBucket", "*", two_days_ago)
        session.execute_write(_tx_upsert_permission, "iam:DeleteUser", "*", one_eighty_days_ago)

        # Link role -> permissions
        session.execute_write(lambda tx: tx.run(
            "MATCH (r:Role {name:$r}) MATCH (p:Permission {action:$a, resource:$res}) MERGE (r)-[:HAS_PERMISSION]->(p)",
            r="CloudOps", a="s3:ListBucket", res="*",
        ))
        session.execute_write(lambda tx: tx.run(
            "MATCH (r:Role {name:$r}) MATCH (p:Permission {action:$a, resource:$res}) MERGE (r)-[:HAS_PERMISSION]->(p)",
            r="CloudOps", a="iam:DeleteUser", res="*",
        ))

        # Add a non-human service account with AdministratorAccess (unused)
        svc_name = "svc-backup"
        session.execute_write(_tx_upsert_user, svc_name, None)
        # create a managed policy node for AdministratorAccess
        admin_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
        session.execute_write(lambda tx, a, n: tx.run("MERGE (p:Policy {arn:$arn}) SET p.name=$name", arn=a, name=n), admin_arn, "AdministratorAccess")
        # create a broad Permission node that represents admin privileges
        session.execute_write(_tx_upsert_permission, "*", "*", one_eighty_days_ago)
        # link policy -> permission
        session.execute_write(lambda tx: tx.run(
            "MATCH (p:Policy {arn:$arn}) MATCH (perm:Permission {action:$a, resource:$r}) MERGE (p)-[:GRANTS]->(perm)",
            arn=admin_arn, a="*", r="*",
        ))
        # link service account -> policy (attached)
        session.execute_write(lambda tx: tx.run(
            "MATCH (u:User {name:$u}) MATCH (p:Policy {arn:$arn}) MERGE (u)-[:HAS_POLICY]->(p)",
            u=svc_name, arn=admin_arn,
        ))

        # Add service account for Terraform runner with an unused iam:* permission
        svc_tf = "svc-terraform-runner"
        session.execute_write(_tx_upsert_user, svc_tf, None)
        # create a Permission node for iam:*
        session.execute_write(_tx_upsert_permission, "iam:*", "*", one_eighty_days_ago)
        # attach directly to user (simulates inline over-privileged creds)
        session.execute_write(lambda tx: tx.run(
            "MATCH (u:User {name:$u}) MATCH (p:Permission {action:$a, resource:$r}) MERGE (u)-[:HAS_PERMISSION]->(p)",
            u=svc_tf, a="iam:*", r="*",
        ))

    driver.close()


def load_sailpoint_graph(uri: str, user: str, password: str, data: dict):
    """Load SailPoint IAM data into Neo4j.

    Extends load_iam_graph with:
    - Permission nodes from entitlements
    - Policy-[:GRANTS]->Permission edges
    - Role-[:HAS_PERMISSION]->Permission propagation through policies
    - Identity->Role assignments via HAS_ROLE
    """
    load_iam_graph(uri, user, password, data)

    driver = _get_driver(uri, user, password)
    with driver.session() as session:
        # Permission nodes from entitlements
        for ent in data.get("entitlements", []):
            action = ent.get("attribute") or ent.get("name")
            resource = ent.get("sourceName") or ent.get("value") or "*"
            session.execute_write(_tx_upsert_permission, action, resource, None)

        # Policy-[:GRANTS]->Permission from access-profile documents
        for pol in data.get("policies", []):
            ap_arn = pol.get("Arn")
            for stmt in pol.get("Document", []):
                for action in stmt.get("actions", []):
                    for resource in stmt.get("resources", []):
                        session.execute_write(
                            lambda tx, arn, a, r: tx.run(
                                "MATCH (pol:Policy {arn:$arn}) "
                                "MATCH (perm:Permission {action:$action, resource:$resource}) "
                                "MERGE (pol)-[:GRANTS]->(perm)",
                                arn=arn, action=a, resource=r,
                            ),
                            ap_arn, action, resource,
                        )

        # Propagate Role-[:HAS_PERMISSION] through HAS_POLICY->GRANTS chain
        session.execute_write(lambda tx: tx.run(
            "MATCH (r:Role)-[:HAS_POLICY]->(pol:Policy)-[:GRANTS]->(perm:Permission) "
            "MERGE (r)-[:HAS_PERMISSION]->(perm)"
        ))

        # Identity role assignments (HAS_ROLE relationships)
        for user_obj in data.get("users", []):
            username = user_obj.get("UserName")
            for role_id in user_obj.get("Roles", []):
                session.execute_write(
                    lambda tx, un, rid: tx.run(
                        "MATCH (u:User {name:$user_name}) "
                        "MATCH (r:Role) WHERE r.arn = $role_id OR r.name = $role_id "
                        "MERGE (u)-[:HAS_ROLE]->(r)",
                        user_name=un, role_id=rid,
                    ),
                    username, role_id,
                )

    driver.close()
    logger.info("SailPoint graph loaded: %d identities, %d roles, %d access profiles, %d entitlements",
                len(data.get("users", [])), len(data.get("roles", [])),
                len(data.get("policies", [])), len(data.get("entitlements", [])))


if __name__ == "__main__":
    print("neo4j_loader: provides `load_iam_graph`, `load_sailpoint_graph`, and `seed_mock_data`")
