"""Unified CLI entry point for iamdbagent.

All commands are available via the `iamdbagent` command after `pip install -e .`

Commands:
  seed            Populate Neo4j with mock IAM data (demo / quickstart)
  embed           Vectorize the IAM graph + seed RAG knowledge base
  analyze         Detect zombie permissions + shadow paths, score with LLM
  consolidate     Find similar roles and propose consolidation via LLM
  review          Interactive confirm-before-write remediation flow
  fetch-aws       Pull real AWS IAM data into Neo4j
  fetch-sailpoint Pull SailPoint IdentityNow data into Neo4j
  doctor          Pre-flight connectivity checks
"""
import click
import json
import os
import requests as _requests

from .graph.neo4j_loader import seed_mock_data
from .rag.embedder import make_embed_fn, embed_iam_graph, seed_knowledge_base
from .analyzer import analyze as run_analysis, consolidate_roles
from .remediator import (
    stage_consolidation, stage_analysis_fix,
    preview_consolidation, preview_analysis_fix,
)
from .ingest.aws_iam import extract_aws_iam
from .ingest.sailpoint_iam import extract_sailpoint_iam, SailPointClient
from .graph.neo4j_loader import load_iam_graph, load_sailpoint_graph


@click.group()
def cli():
    """iamdbagent — AI-driven IAM auditing agent for SailPoint and AWS."""
    pass


# ── Shared Neo4j options ──────────────────────────────────────────────────────

_neo4j_opts = [
    click.option("--neo4j-uri", default="bolt://localhost:7687", show_default=True,
                 envvar="NEO4J_URI", help="Neo4j URI"),
    click.option("--neo4j-user", default="neo4j", show_default=True,
                 envvar="NEO4J_USER", help="Neo4j username"),
    click.option("--neo4j-pass", required=True, envvar="NEO4J_PASS", help="Neo4j password"),
]


def _add_neo4j_opts(fn):
    for opt in reversed(_neo4j_opts):
        fn = opt(fn)
    return fn


# ── seed ─────────────────────────────────────────────────────────────────────

@cli.command()
@_add_neo4j_opts
def seed(neo4j_uri, neo4j_user, neo4j_pass):
    """Seed mock IAM data into Neo4j (idempotent, no external services needed).

    Creates a small demo graph with zombie permissions and shadow admin paths
    so you can run `analyze` without connecting to AWS or SailPoint.
    """
    seed_mock_data(neo4j_uri, neo4j_user, neo4j_pass)
    click.echo("Seeded mock IAM data into Neo4j.")


# ── embed ─────────────────────────────────────────────────────────────────────

@cli.command()
@_add_neo4j_opts
@click.option("--embed-backend", default=None, type=click.Choice(["openai", "ollama", "local"]),
              help="Embedding backend for vectorizing the graph")
@click.option("--embed-model", default=None, help="Embedding model override (default per backend)")
@click.option("--knowledge-only", is_flag=True, default=False,
              help="Only (re)seed the knowledge base, skip embedding graph nodes")
def embed(neo4j_uri, neo4j_user, neo4j_pass, embed_backend, embed_model, knowledge_only):
    """Vectorize the IAM graph and seed the RAG knowledge base in Neo4j.

    Run this once after loading data; re-run after schema changes.
    Requires running `seed`, `fetch-aws`, or `fetch-sailpoint` first.

    Example:
      iamdbagent embed --neo4j-pass secret --embed-backend openai
    """
    backend = embed_backend or "openai"
    click.echo(f"Building embed_fn with backend={backend}, model={embed_model or 'default'}")
    embed_fn = make_embed_fn(backend=backend, model=embed_model)

    click.echo("Seeding IAM risk knowledge base...")
    n = seed_knowledge_base(neo4j_uri, neo4j_user, neo4j_pass, embed_fn)
    click.echo(f"  {n} knowledge entries written")

    if not knowledge_only:
        click.echo("Embedding IAM graph nodes (Permission, Role, Policy)...")
        stats = embed_iam_graph(neo4j_uri, neo4j_user, neo4j_pass, embed_fn, backend=backend)
        click.echo(f"  Embedded: {stats}")

    click.echo("Done. Run `analyze` or `consolidate` with --embed-backend to enable RAG.")


# ── analyze ───────────────────────────────────────────────────────────────────

@cli.command()
@_add_neo4j_opts
@click.option("--days", default=90, show_default=True,
              help="Days threshold to consider a permission zombie")
@click.option("--model", default=None, help="LLM model name (e.g. claude-sonnet-4-6, gpt-4o-mini, llama2)")
@click.option("--backend", default="ollama", show_default=True,
              help="LLM backend: ollama | openai | anthropic")
@click.option("--embed-backend", default=None, type=click.Choice(["openai", "ollama", "local"]),
              help="Enable RAG by specifying an embedding backend (requires prior `embed` run)")
@click.option("--embed-model", default=None, help="Embedding model override")
@click.option("--export", is_flag=True, default=False,
              help="Write suggested IaC files to --export-dir")
@click.option("--export-dir", default="staged_changes", show_default=True,
              help="Directory to write IaC files to")
@click.option("--dry-run", is_flag=True, default=False,
              help="Preview what would be staged without writing files")
@click.option("--min-risk-score", default=0, show_default=True,
              help="Only include findings at or above this risk score (1-10)")
def analyze(neo4j_uri, neo4j_user, neo4j_pass, days, model, backend,
            embed_backend, embed_model, export, export_dir, dry_run, min_risk_score):
    """Detect zombie permissions + shadow admin paths, then score with an LLM.

    Add --embed-backend to enable RAG: findings are embedded and semantically
    matched against the IAM risk knowledge base before the LLM call.
    Requires running `embed` first.

    Examples:
      iamdbagent analyze --neo4j-pass secret --backend anthropic
      iamdbagent analyze --neo4j-pass secret --backend openai --export --min-risk-score 7
    """
    embed_fn = None
    if embed_backend:
        embed_fn = make_embed_fn(backend=embed_backend, model=embed_model)
        click.echo(f"RAG enabled (embed_backend={embed_backend})", err=True)

    result = run_analysis(neo4j_uri, neo4j_user, neo4j_pass, days=days, model=model,
                          backend=backend, embed_fn=embed_fn)
    if min_risk_score > 0 and isinstance(result.get("findings"), list):
        result["findings"] = [f for f in result["findings"] if (f.get("risk_score") or 0) >= min_risk_score]
    click.echo(json.dumps(result, indent=2))
    if dry_run:
        preview = preview_analysis_fix(result)
        click.echo("DRY RUN — no files written:")
        click.echo(json.dumps(preview, indent=2))
    elif export:
        out = stage_analysis_fix(result, output_dir=export_dir)
        click.echo(json.dumps(out, indent=2))


# ── consolidate ───────────────────────────────────────────────────────────────

@cli.command()
@_add_neo4j_opts
@click.option("--threshold", default=0.8, show_default=True,
              help="Jaccard similarity threshold for clustering (0-1)")
@click.option("--model", default=None, help="LLM model name")
@click.option("--backend", default="ollama", show_default=True,
              help="LLM backend: ollama | openai | anthropic")
@click.option("--embed-backend", default=None, type=click.Choice(["openai", "ollama", "local"]),
              help="Enable RAG for consolidation context")
@click.option("--embed-model", default=None, help="Embedding model override")
@click.option("--export", is_flag=True, default=False, help="Write IaC files to --export-dir")
@click.option("--export-dir", default="staged_changes", show_default=True)
@click.option("--dry-run", is_flag=True, default=False)
def consolidate(neo4j_uri, neo4j_user, neo4j_pass, threshold, model, backend,
                embed_backend, embed_model, export, export_dir, dry_run):
    """Find similar roles and request consolidation recommendations from LLM."""
    embed_fn = None
    if embed_backend:
        embed_fn = make_embed_fn(backend=embed_backend, model=embed_model)
        click.echo(f"RAG enabled (embed_backend={embed_backend})", err=True)

    result = consolidate_roles(neo4j_uri, neo4j_user, neo4j_pass, threshold=threshold,
                               model=model, backend=backend, embed_fn=embed_fn)
    click.echo(json.dumps(result, indent=2))
    if dry_run:
        previews = []
        for c in result.get("clusters", []):
            p = preview_consolidation(c.get("cluster"), c.get("recommendation"))
            previews.append(p)
        click.echo("DRY RUN — no files written:")
        click.echo(json.dumps({"preview": previews}, indent=2))
    elif export:
        summaries = []
        out_dir = export_dir or "staged_changes"
        for c in result.get("clusters", []):
            s = stage_consolidation(c.get("cluster"), c.get("recommendation"), out_dir)
            summaries.append(s)
        click.echo(json.dumps({"staged": summaries}, indent=2))


# ── review ────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--mode", type=click.Choice(["analyze", "consolidate"]), default="analyze",
              help="Which analysis to review")
@_add_neo4j_opts
@click.option("--threshold", default=0.8, show_default=True)
@click.option("--days", default=90, show_default=True)
@click.option("--model", default=None)
@click.option("--backend", default="ollama", show_default=True)
@click.option("--export-dir", default="staged_changes", show_default=True)
def review(mode, neo4j_uri, neo4j_user, neo4j_pass, threshold, days, model, backend, export_dir):
    """Interactive review flow: preview remediation and type 'confirm' to write IaC."""
    if mode == "analyze":
        result = run_analysis(neo4j_uri, neo4j_user, neo4j_pass, days=days, model=model, backend=backend)
        preview = preview_analysis_fix(result)
        click.echo(json.dumps(preview, indent=2))
        choice = click.prompt("Type 'confirm' to write suggested IaC to disk, or anything else to cancel",
                              default="", show_default=False)
        if choice.strip().lower() == "confirm":
            out = stage_analysis_fix(result, output_dir=export_dir)
            click.echo(json.dumps(out, indent=2))
        else:
            click.echo("Canceled — no files were written.")
    else:
        result = consolidate_roles(neo4j_uri, neo4j_user, neo4j_pass, threshold=threshold,
                                   model=model, backend=backend)
        summaries = []
        for c in result.get("clusters", []):
            cluster = c.get("cluster")
            recommendation = c.get("recommendation")
            preview = preview_consolidation(cluster, recommendation)
            click.echo(json.dumps(preview, indent=2))
            choice = click.prompt(
                f"For cluster {cluster.get('roles')}, type 'confirm' to write IaC, or anything else to skip",
                default="", show_default=False,
            )
            if choice.strip().lower() == "confirm":
                s = stage_consolidation(cluster, recommendation, export_dir)
                summaries.append(s)
        if summaries:
            click.echo(json.dumps({"staged": summaries}, indent=2))
        else:
            click.echo("No clusters staged.")


# ── fetch-aws ─────────────────────────────────────────────────────────────────

@cli.command("fetch-aws")
@click.option("--profile", default=None, help="AWS profile name to use (default: default profile)")
@_add_neo4j_opts
def fetch_aws(profile, neo4j_uri, neo4j_user, neo4j_pass):
    """Fetch real AWS IAM entities and load into Neo4j (read-only).

    Calls AWS IAM read-only APIs: list_users, list_roles, list_policies.
    Requires valid AWS credentials in environment or ~/.aws/credentials.
    """
    import boto3
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    click.echo("Extracting AWS IAM data...")
    data = extract_aws_iam(session)
    click.echo(
        f"Fetched: {len(data.get('users', []))} users, {len(data.get('roles', []))} roles, "
        f"{len(data.get('policies', []))} policies"
    )
    load_iam_graph(neo4j_uri, neo4j_user, neo4j_pass, data)
    click.echo("Loaded AWS IAM graph into Neo4j.")


# ── fetch-sailpoint ───────────────────────────────────────────────────────────

@cli.command("fetch-sailpoint")
@click.option("--tenant-url", required=True, envvar="SAILPOINT_TENANT_URL",
              help="SailPoint tenant base URL, e.g. https://org.api.identitynow.com")
@click.option("--client-id", required=True, envvar="SAILPOINT_CLIENT_ID",
              help="OAuth2 client ID (PAT or dedicated client)")
@click.option("--client-secret", required=True, envvar="SAILPOINT_CLIENT_SECRET",
              help="OAuth2 client secret")
@_add_neo4j_opts
def fetch_sailpoint(tenant_url, client_id, client_secret, neo4j_uri, neo4j_user, neo4j_pass):
    """Fetch SailPoint IdentityNow IAM entities and load into Neo4j (read-only).

    Extracts identities (users), roles, access profiles (policies), and
    entitlements (permissions) from SailPoint V3 API, then upserts into Neo4j
    for downstream analysis.

    Credentials can be supplied via env vars:
      SAILPOINT_TENANT_URL, SAILPOINT_CLIENT_ID, SAILPOINT_CLIENT_SECRET

    After loading, run `analyze` to detect zombie permissions and shadow paths.
    Note: permissions without lastLoginDate on the associated identity will have
    last_used=null and will be flagged as zombie candidates — review carefully.
    """
    click.echo(f"Connecting to SailPoint tenant: {tenant_url}")
    data = extract_sailpoint_iam(tenant_url, client_id, client_secret)
    click.echo(
        f"Fetched: {len(data['users'])} identities, {len(data['roles'])} roles, "
        f"{len(data['policies'])} access profiles, {len(data['entitlements'])} entitlements"
    )
    if data["errors"]:
        click.echo(f"Warnings: {len(data['errors'])} partial errors — check logs", err=True)
    load_sailpoint_graph(neo4j_uri, neo4j_user, neo4j_pass, data)
    click.echo("Loaded SailPoint IAM graph into Neo4j.")


# ── doctor ────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--neo4j-uri", default="bolt://localhost:7687", show_default=True, envvar="NEO4J_URI")
@click.option("--neo4j-user", default="neo4j", show_default=True, envvar="NEO4J_USER")
@click.option("--neo4j-pass", default=None, envvar="NEO4J_PASS", help="Neo4j password")
@click.option("--backend", default="ollama", show_default=True,
              help="LLM backend to check: ollama | openai | anthropic")
def doctor(neo4j_uri, neo4j_user, neo4j_pass, backend):
    """Run pre-flight connectivity checks before analysis.

    Checks: Neo4j, LLM backend, and SailPoint (if env vars are set).
    Exits with code 1 if any required check fails.
    """
    all_ok = True

    # Neo4j
    click.echo("Checking Neo4j... ", nl=False)
    try:
        from neo4j import GraphDatabase
        drv = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_pass or ""))
        with drv.session() as s:
            s.run("RETURN 1")
        drv.close()
        click.echo(click.style("OK", fg="green"))
    except Exception as e:
        click.echo(click.style(f"FAIL ({e})", fg="red"))
        all_ok = False

    # LLM backend
    backend = (backend or "ollama").lower()
    click.echo(f"Checking LLM backend ({backend})... ", nl=False)
    try:
        if backend == "ollama":
            _requests.get("http://localhost:11434", timeout=5)
            click.echo(click.style("OK", fg="green"))
        elif backend == "openai":
            key = os.getenv("OPENAI_API_KEY", "")
            if not key:
                raise RuntimeError("OPENAI_API_KEY not set")
            click.echo(click.style(f"OK (key set: {key[:8]}...)", fg="green"))
        elif backend == "anthropic":
            key = os.getenv("ANTHROPIC_API_KEY", "")
            if not key:
                raise RuntimeError("ANTHROPIC_API_KEY not set")
            click.echo(click.style(f"OK (key set: {key[:12]}...)", fg="green"))
        else:
            click.echo(click.style(f"Unknown backend '{backend}'", fg="yellow"))
    except Exception as e:
        click.echo(click.style(f"FAIL ({e})", fg="red"))
        all_ok = False

    # SailPoint (optional — only checked if env vars present)
    sp_url = os.getenv("SAILPOINT_TENANT_URL", "")
    sp_cid = os.getenv("SAILPOINT_CLIENT_ID", "")
    sp_sec = os.getenv("SAILPOINT_CLIENT_SECRET", "")
    if sp_url and sp_cid and sp_sec:
        click.echo("Checking SailPoint IdentityNow... ", nl=False)
        try:
            client = SailPointClient(sp_url, sp_cid, sp_sec)
            client._ensure_token()
            click.echo(click.style("OK (token obtained)", fg="green"))
        except Exception as e:
            click.echo(click.style(f"FAIL ({e})", fg="red"))
            all_ok = False
    else:
        click.echo(
            "SailPoint: SKIPPED "
            "(set SAILPOINT_TENANT_URL, SAILPOINT_CLIENT_ID, SAILPOINT_CLIENT_SECRET to check)"
        )

    if all_ok:
        click.echo(click.style(
            "\nAll checks passed. Ready to run `iamdbagent seed` or `iamdbagent analyze`.",
            fg="green",
        ))
    else:
        click.echo(click.style(
            "\nSome checks failed. Fix the issues above before proceeding.", fg="red",
        ), err=True)
        raise SystemExit(1)


if __name__ == "__main__":
    cli()
