# iamdbagent — AI-Driven IAM Auditing Agent

Connects to a Neo4j graph of IAM data (loaded from **SailPoint IdentityNow** or **AWS**), detects zombie permissions and shadow admin paths, and uses an LLM to produce risk-scored findings with remediation steps and generated Terraform/JSON IaC.

---

## What it does

| Capability | Description |
|---|---|
| **Zombie detection** | Finds permissions unused for N days (including never-used) |
| **Shadow admin paths** | Traces transitive privilege escalation paths from non-admin users to high-risk permissions |
| **LLM risk scoring** | Scores each finding 1–10, maps to MITRE ATT&CK techniques, estimates post-remediation score |
| **SailPoint-aware** | Detects SailPoint data and prompts the LLM for IdentityNow-specific remediations |
| **Role consolidation** | Clusters similar roles by Jaccard similarity, proposes a single consolidated role |
| **IaC generation** | Writes Terraform + IAM policy JSON for each remediation suggestion |
| **Web dashboard** | Streamlit UI for interactive analysis and before/after risk comparison |
| **RAG** | Optional vector-search retrieval injects IAM security knowledge into every LLM call |

---

## Quickstart (5 minutes)

```bash
# 1. Clone and install
git clone https://github.com/your-org/iamdbagent.git
cd iamdbagent
cp .env.example .env          # fill in at least NEO4J_PASS and one LLM key

# 2. Start Neo4j
docker compose up -d neo4j

# 3. Install the CLI
pip install -e .

# 4. Pre-flight check
iamdbagent doctor --neo4j-pass secret --backend anthropic

# 5. Load demo data and analyze
iamdbagent seed --neo4j-pass secret
iamdbagent analyze --neo4j-pass secret --backend anthropic --dry-run
```

---

## Prerequisites

- Python 3.9+
- Docker (for Neo4j via docker-compose) **or** a Neo4j 5.x instance
- One of: Anthropic API key, OpenAI API key, or [Ollama](https://ollama.com) (local)

---

## Setup

### 1. Start Neo4j

```bash
docker compose up -d neo4j
# Neo4j Browser available at http://localhost:7474 (neo4j / secret)
```

Or bring your own Neo4j 5.x instance (community edition supported).

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env — at minimum set NEO4J_PASS and your chosen LLM key
```

### 3. Install

```bash
pip install -e .
iamdbagent --help   # should list all 8 commands
```

---

## Loading IAM data

### Option A — Mock data (quickstart, no external services)

```bash
iamdbagent seed --neo4j-pass secret
```

### Option B — SailPoint IdentityNow

```bash
# Credentials via env vars (recommended) or CLI flags
export SAILPOINT_TENANT_URL=https://your-org.api.identitynow.com
export SAILPOINT_CLIENT_ID=your-client-id
export SAILPOINT_CLIENT_SECRET=your-client-secret

iamdbagent fetch-sailpoint --neo4j-pass secret
```

Create a dedicated OAuth2 client in **SailPoint Admin → API Management → OAuth Clients** with
read-only scopes (`idn:*:read`). The extractor pulls identities, roles, access profiles, and
entitlements via the V3 API.

**Note on zombie detection:** `last_used` on Permission nodes is populated from
`attributes.lastLoginDate` on SailPoint identities. If this attribute is not surfaced in your
tenant, permissions will have `last_used=null` — they will appear as zombie candidates and should
be reviewed with context (they may be legitimately provisioned but not yet exercised).

### Option C — Real AWS IAM

```bash
iamdbagent fetch-aws --neo4j-pass secret --profile default
```

---

## Running analysis

### Analyze (zombie permissions + shadow paths)

```bash
# Anthropic (recommended)
iamdbagent analyze --neo4j-pass secret --backend anthropic

# OpenAI
iamdbagent analyze --neo4j-pass secret --backend openai --model gpt-4o-mini

# Ollama (local, no API key)
iamdbagent analyze --neo4j-pass secret --backend ollama --model llama2
```

**Preview remediation without writing files:**

```bash
iamdbagent analyze --neo4j-pass secret --backend anthropic --dry-run
```

**Export Terraform + JSON IaC (only high-risk findings):**

```bash
iamdbagent analyze --neo4j-pass secret --backend anthropic \
  --export --export-dir staged_changes --min-risk-score 7
```

### Role consolidation

```bash
iamdbagent consolidate --neo4j-pass secret --backend anthropic --threshold 0.8 --export
```

### Interactive review (confirm before writing each file)

```bash
iamdbagent review --mode analyze --neo4j-pass secret --backend anthropic
```

### Enable RAG (optional, improves accuracy)

Run `embed` once after loading data. Uses Neo4j's built-in vector indexes.

```bash
iamdbagent embed --neo4j-pass secret --embed-backend openai
iamdbagent analyze --neo4j-pass secret --backend anthropic --embed-backend openai
```

### Pre-flight check

```bash
iamdbagent doctor --neo4j-pass secret --backend anthropic
```

---

## Web dashboard

```bash
# Graph dashboard — zombie permissions + shadow path network
streamlit run src/iamdbagent/app.py

# Risk findings dashboard — sortable table with before/after risk scores
streamlit run src/iamdbagent/ui.py
```

Both read Neo4j connection details from the sidebar. The risk dashboard has a **Run Analysis**
button that triggers the LLM pipeline.

---

## CLI reference

| Command | Description |
|---|---|
| `seed` | Seed mock IAM data into Neo4j (demo, no external services) |
| `fetch-aws` | Pull real AWS IAM data into Neo4j |
| `fetch-sailpoint` | Pull SailPoint IdentityNow data into Neo4j |
| `embed` | Vectorize graph + seed RAG knowledge base |
| `analyze` | Detect zombies + shadow paths, score with LLM |
| `consolidate` | Find similar roles, propose consolidation via LLM |
| `review` | Interactive confirm-before-write flow |
| `doctor` | Pre-flight connectivity checks |

| Flag | Default | Description |
|---|---|---|
| `--backend` | `ollama` | LLM backend: `ollama`, `openai`, `anthropic` |
| `--model` | backend default | Model name (e.g. `claude-sonnet-4-6`, `gpt-4o-mini`, `llama2`) |
| `--days` | `90` | Zombie threshold in days |
| `--threshold` | `0.8` | Jaccard similarity threshold for role clustering |
| `--export` | off | Write IaC files to `--export-dir` |
| `--export-dir` | `staged_changes/` | Output directory for IaC files |
| `--dry-run` | off | Preview what would be written, without writing |
| `--min-risk-score` | `0` | Filter findings below this score (1–10) |
| `--embed-backend` | off | RAG backend: `openai`, `ollama`, `local` |

---

## Running tests

```bash
python -m pytest tests/ -v
```

---

## Architecture

```
src/iamdbagent/
├── main.py              # Unified CLI (seed, embed, analyze, consolidate, review,
│                        #   fetch-aws, fetch-sailpoint, doctor)
├── analyzer.py          # Cypher queries + LLM dispatch + SailPoint detection + IaC generation
├── remediator.py        # Stage/preview IaC files, compute permission deltas
├── app.py               # Streamlit graph dashboard
├── ui.py                # Streamlit risk findings dashboard
├── ingest/
│   ├── aws_iam.py       # AWS IAM read-only extractor (boto3)
│   └── sailpoint_iam.py # SailPoint V3 API extractor (OAuth2, retry, last_used from activity)
├── graph/
│   └── neo4j_loader.py  # Neo4j upsert helpers + mock data seeder
└── rag/
    ├── embedder.py      # Vectorization (OpenAI / Ollama / local)
    └── retriever.py     # Vector search + context formatting

docker-compose.yml       # Neo4j 5.x + optional Ollama
Makefile                 # make install / up / seed / analyze / test
.env.example             # All required env vars with explanations
```

### Neo4j graph schema

```
(:User)-[:HAS_ROLE]->(:Role)-[:HAS_POLICY]->(:Policy)-[:GRANTS]->(:Permission)
(:Role)-[:HAS_PERMISSION]->(:Permission)

Permission { action, resource, last_used }
Role       { name, arn, Source }          # Source = "sailpoint:role" for SailPoint data
```

---

## IaC output

Generated files land in `staged_changes/` (or `--export-dir`):

- `<role_name>_policy.json` — IAM policy JSON
- `<role_name>.tf` — Terraform resource blocks (`aws_iam_policy`, `aws_iam_role`, `aws_iam_role_policy_attachment`)
- `remediation.tf` — combined Terraform for all findings in one apply

> **Before applying:** update `assume_role_policy` principal — the generator emits `REPLACE_WITH_PRINCIPAL_ARN` as a placeholder when no principal is specified.
