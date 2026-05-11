# iamdbagent — AI-Driven IAM Auditing Agent

Connects to a Neo4j graph of IAM data (loaded from AWS or SailPoint), detects zombie permissions and shadow admin paths, and uses an LLM to produce risk-scored findings with remediation steps and generated Terraform/JSON IaC.

---

## What it does

| Capability | Description |
|---|---|
| **Zombie detection** | Finds permissions unused for N days (including never-used) |
| **Shadow admin paths** | Traces transitive privilege escalation paths from non-admin users to high-risk permissions |
| **LLM risk scoring** | Scores each finding 1–10, maps to MITRE ATT&CK techniques, estimates post-remediation score |
| **Role consolidation** | Clusters similar roles by Jaccard similarity, proposes a single consolidated role |
| **IaC generation** | Writes Terraform + IAM policy JSON for each remediation suggestion |
| **Web dashboard** | Streamlit UI for interactive analysis and before/after risk comparison |

---

## Prerequisites

- Python 3.9+
- Neo4j 5.x running locally or remotely
- One of: [Ollama](https://ollama.com) (local), OpenAI API key, or Anthropic API key

---

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Set environment variables (or pass as CLI flags):

```bash
export NEO4J_URI=bolt://localhost:7687
export NEO4J_USER=neo4j
export NEO4J_PASS=secret

# For OpenAI backend
export OPENAI_API_KEY=sk-...

# For Anthropic backend
export ANTHROPIC_API_KEY=sk-ant-...
```

---

## Loading IAM data

### Option A — Mock data (quickstart, no AWS needed)

```bash
PYTHONPATH=src python -m src.cli seed \
  --neo4j-uri bolt://localhost:7687 \
  --neo4j-user neo4j \
  --neo4j-pass secret
```

### Option B — Real AWS IAM

```bash
python -m iamdbagent.cli fetch-aws \
  --profile default \
  --neo4j-uri bolt://localhost:7687 \
  --neo4j-user neo4j \
  --neo4j-pass secret
```

This calls AWS IAM read-only APIs (list_users, list_roles, list_policies) and loads them into Neo4j.

---

## Running analysis

### CLI

**Analyze zombie permissions and shadow paths:**

```bash
PYTHONPATH=src python -m src.cli analyze \
  --neo4j-uri bolt://localhost:7687 \
  --neo4j-user neo4j \
  --neo4j-pass secret \
  --backend ollama \
  --days 90
```

With Anthropic or OpenAI backend:

```bash
PYTHONPATH=src python -m src.cli analyze \
  --backend anthropic \
  --model claude-sonnet-4-6 \
  --neo4j-uri bolt://localhost:7687 \
  --neo4j-user neo4j \
  --neo4j-pass secret
```

**Preview remediation without writing files:**

```bash
PYTHONPATH=src python -m src.cli analyze \
  --backend ollama \
  --neo4j-uri bolt://localhost:7687 \
  --neo4j-user neo4j \
  --neo4j-pass secret \
  --dry-run
```

**Export Terraform + JSON IaC to disk (only findings with risk score ≥ 7):**

```bash
PYTHONPATH=src python -m src.cli analyze \
  --backend ollama \
  --neo4j-uri bolt://localhost:7687 \
  --neo4j-user neo4j \
  --neo4j-pass secret \
  --export \
  --export-dir staged_changes \
  --min-risk-score 7
```

**Find and consolidate similar roles:**

```bash
PYTHONPATH=src python -m src.cli consolidate \
  --neo4j-uri bolt://localhost:7687 \
  --neo4j-user neo4j \
  --neo4j-pass secret \
  --threshold 0.8 \
  --export
```

**Interactive review mode (confirm before writing each file):**

```bash
PYTHONPATH=src python -m src.cli review \
  --mode analyze \
  --neo4j-uri bolt://localhost:7687 \
  --neo4j-user neo4j \
  --neo4j-pass secret
```

### CLI options reference

| Flag | Default | Description |
|---|---|---|
| `--backend` | `ollama` | LLM backend: `ollama`, `openai`, `anthropic` |
| `--model` | backend default | Model name (e.g. `llama2`, `gpt-4o-mini`, `claude-sonnet-4-6`) |
| `--days` | `90` | Zombie threshold in days |
| `--threshold` | `0.8` | Jaccard similarity threshold for role clustering |
| `--export` | off | Write IaC files to `--export-dir` |
| `--export-dir` | `staged_changes/` | Output directory for IaC files |
| `--dry-run` | off | Preview what would be written, without writing |
| `--min-risk-score` | `0` | Filter findings below this score (1–10) |

---

## Web dashboard

Two Streamlit dashboards are available:

**Graph dashboard** — zombie permissions + shadow path network graph:

```bash
PYTHONPATH=src streamlit run src/app.py
```

**Risk findings dashboard** — sortable findings table with before/after risk scores:

```bash
PYTHONPATH=src streamlit run src/ui.py
```

Both read Neo4j connection details from the sidebar. The risk dashboard has a **Run Analysis** button that triggers the LLM pipeline and stores results in session state.

---

## Running tests

```bash
PYTHONPATH=src python -m pytest tests/ -v
```

---

## Architecture

```
src/
├── analyzer.py              # Cypher queries + LLM dispatch + IaC generation
├── remediator.py            # Stage/preview IaC files, compute permission deltas
├── cli.py                   # Click CLI (seed, analyze, consolidate, review)
├── app.py                   # Streamlit graph dashboard
├── ui.py                    # Streamlit risk findings dashboard
└── iamdbagent/
    ├── cli.py               # fetch-aws command
    ├── ingest/
    │   └── aws_iam.py       # AWS IAM read-only extractor (boto3)
    └── graph/
        └── neo4j_loader.py  # Neo4j upsert helpers + mock data seeder

tests/
├── test_analyzer.py         # Unit tests: Cypher queries, LLM validation, IaC generation
└── test_remediator.py       # Unit tests: staging, preview, permission delta
```

### Neo4j graph schema

```
(:User)-[:HAS_ROLE]->(:Role)-[:HAS_POLICY]->(:Policy)-[:GRANTS]->(:Permission)
(:Role)-[:HAS_PERMISSION]->(:Permission)

Permission { action, resource, last_used }
```

---

## IaC output

Generated files land in `staged_changes/` (or `--export-dir`):

- `<role_name>_policy.json` — IAM policy JSON
- `<role_name>.tf` — Terraform resource blocks (`aws_iam_policy`, `aws_iam_role`, `aws_iam_role_policy_attachment`)
- `remediation.tf` — combined Terraform for all findings in one apply

> **Before applying:** update `assume_role_policy` principal — the generator emits `REPLACE_WITH_PRINCIPAL_ARN` as a placeholder when no principal is specified.
