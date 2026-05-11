# iamdbagent — Phase 1: Graph Data Ingestion (MVP)

Goal: provide a read-only IAM data ingestion pipeline that extracts Users, Roles and Permissions and loads them into Neo4j as a graph (Identity → Role → Permission).

Quickstart

1. Create a Python virtualenv and install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2. Run the extractor and load into Neo4j (example):

```bash
# local Neo4j running at bolt://localhost:7687
python -m iamdbagent.cli fetch-aws --profile default --neo4j-uri bolt://localhost:7687 --neo4j-user neo4j --neo4j-pass secret
```

Architecture

- `src/iamdbagent/ingest/aws_iam.py`: AWS IAM extractor (read-only)
- `src/iamdbagent/graph/neo4j_loader.py`: Neo4j upsert helpers
- `src/iamdbagent/cli.py`: CLI wrapper

Next steps

- Add telemetry ingestion (CloudTrail / Access Advisor)
- Add pathfinding queries to detect transitive admin paths
- Add role-mining clustering and RAG-based reasoning
