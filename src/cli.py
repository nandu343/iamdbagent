"""Top-level CLI shim so the project can be run as `python -m src.cli`.

Provides a `seed` command that calls into the package loader to populate mock data.
"""
import click
import json
from iamdbagent.graph.neo4j_loader import seed_mock_data
from iamdbagent.rag.embedder import make_embed_fn, embed_iam_graph, seed_knowledge_base
from src.analyzer import analyze as run_analysis
from src.analyzer import consolidate_roles
from src.remediator import stage_consolidation, stage_analysis_fix, preview_consolidation, preview_analysis_fix


@click.group()
def cli():
    pass


@cli.command()
@click.option("--neo4j-uri", required=True, help="Neo4j URI (bolt://host:port)")
@click.option("--neo4j-user", default="neo4j", help="Neo4j username")
@click.option("--neo4j-pass", required=True, help="Neo4j password")
def seed(neo4j_uri, neo4j_user, neo4j_pass):
    """Seed mock data into Neo4j (idempotent).

    Example:
      python -m src.cli seed --neo4j-uri bolt://localhost:7687 --neo4j-user neo4j --neo4j-pass secret
    """
    seed_mock_data(neo4j_uri, neo4j_user, neo4j_pass)
    click.echo("Seeded mock IAM data into Neo4j")


@cli.command()
@click.option("--neo4j-uri", required=True, help="Neo4j URI (bolt://host:port)")
@click.option("--neo4j-user", default="neo4j", help="Neo4j username")
@click.option("--neo4j-pass", required=True, help="Neo4j password")
@click.option("--embed-backend", default=None,
              type=click.Choice(["openai", "ollama", "local"]),
              help="Embedding backend to use for vectorizing the graph")
@click.option("--embed-model", default=None, help="Embedding model override (default per backend)")
@click.option("--knowledge-only", is_flag=True, default=False,
              help="Only (re)seed the knowledge base, skip embedding graph nodes")
def embed(neo4j_uri, neo4j_user, neo4j_pass, embed_backend, embed_model, knowledge_only):
    """Vectorize the IAM graph and seed the RAG knowledge base in Neo4j.

    Creates vector indexes on Permission, Role, Policy, and KnowledgeEntry nodes,
    then embeds each node and writes the vector to the `embedding` property.
    Run this once after loading data; re-run after schema changes.

    Example:
      python -m src.cli embed --neo4j-uri bolt://localhost:7687 --neo4j-pass secret --embed-backend openai
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

    click.echo("Done. Run analyze or consolidate with --embed-backend to enable RAG.")


@cli.command()
@click.option("--neo4j-uri", required=True, help="Neo4j URI (bolt://host:port)")
@click.option("--neo4j-user", default="neo4j", help="Neo4j username")
@click.option("--neo4j-pass", required=True, help="Neo4j password")
@click.option("--days", default=90, help="Days threshold to consider a permission zombie")
@click.option("--model", default=None, help="LLM model to use (model name for selected backend)")
@click.option("--backend", default="ollama", help="LLM backend to use: ollama|openai|anthropic")
@click.option("--embed-backend", default=None,
              type=click.Choice(["openai", "ollama", "local"]),
              help="Enable RAG: embed queries and retrieve context before LLM call")
@click.option("--embed-model", default=None, help="Embedding model override")
@click.option("--export", is_flag=True, default=False, help="Write suggested IaC to disk in deployments/")
@click.option("--export-dir", default="staged_changes", help="Directory to write IaC files to")
@click.option("--dry-run", is_flag=True, default=False, help="Preview what would be staged without writing files")
@click.option("--min-risk-score", default=0, help="Only include findings at or above this risk score (1-10)")
def analyze(neo4j_uri, neo4j_user, neo4j_pass, days, model, backend, embed_backend, embed_model,
            export, export_dir, dry_run, min_risk_score):
    """Run analysis on the Neo4j DB and solicit a recommendation from local LLM.

    Add --embed-backend to enable RAG: findings are embedded and semantically
    matched against the IAM risk knowledge base before the LLM call.
    Requires running `embed` first.
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


@cli.command()
@click.option("--neo4j-uri", required=True, help="Neo4j URI (bolt://host:port)")
@click.option("--neo4j-user", default="neo4j", help="Neo4j username")
@click.option("--neo4j-pass", required=True, help="Neo4j password")
@click.option("--threshold", default=0.8, help="Jaccard similarity threshold for clustering (0-1)")
@click.option("--model", default=None, help="LLM model to use (model name for selected backend)")
@click.option("--backend", default="ollama", help="LLM backend to use: ollama|openai|anthropic")
@click.option("--embed-backend", default=None,
              type=click.Choice(["openai", "ollama", "local"]),
              help="Enable RAG: embed role/permission context before LLM consolidation call")
@click.option("--embed-model", default=None, help="Embedding model override")
@click.option("--export", is_flag=True, default=False, help="Write suggested IaC to disk in deployments/")
@click.option("--export-dir", default="staged_changes", help="Directory to write IaC files to")
@click.option("--dry-run", is_flag=True, default=False, help="Preview what would be staged without writing files")
def consolidate(neo4j_uri, neo4j_user, neo4j_pass, threshold, model, backend, embed_backend, embed_model,
                export, export_dir, dry_run):
    """Find similar roles and request consolidation recommendations from LLM."""
    embed_fn = None
    if embed_backend:
        embed_fn = make_embed_fn(backend=embed_backend, model=embed_model)
        click.echo(f"RAG enabled (embed_backend={embed_backend})", err=True)

    result = consolidate_roles(neo4j_uri, neo4j_user, neo4j_pass, threshold=threshold, model=model,
                               backend=backend, embed_fn=embed_fn)
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
        out_dir = export_dir or "deployments"
        for c in result.get("clusters", []):
            cluster = c.get("cluster")
            recommendation = c.get("recommendation")
            s = stage_consolidation(cluster, recommendation, out_dir)
            summaries.append(s)
        click.echo(json.dumps({"staged": summaries}, indent=2))


@cli.command()
@click.option("--mode", type=click.Choice(["analyze", "consolidate"]), default="analyze", help="Which analysis to review")
@click.option("--neo4j-uri", required=True, help="Neo4j URI (bolt://host:port)")
@click.option("--neo4j-user", default="neo4j", help="Neo4j username")
@click.option("--neo4j-pass", required=True, help="Neo4j password")
@click.option("--threshold", default=0.8, help="Jaccard similarity threshold for clustering (0-1)")
@click.option("--days", default=90, help="Days threshold to consider a permission zombie")
@click.option("--model", default=None, help="LLM model to use (model name for selected backend)")
@click.option("--backend", default="ollama", help="LLM backend to use: ollama|openai|anthropic")
@click.option("--export-dir", default="staged_changes", help="Directory to write IaC files to")
def review(mode, neo4j_uri, neo4j_user, neo4j_pass, threshold, days, model, backend, export_dir):
    """Interactive review flow: preview remediation and require typing 'confirm' to write IaC."""
    if mode == "analyze":
        result = run_analysis(neo4j_uri, neo4j_user, neo4j_pass, days=days, model=model, backend=backend)
        preview = preview_analysis_fix(result)
        click.echo(json.dumps(preview, indent=2))
        choice = click.prompt("Type 'confirm' to write suggested IaC to disk, or anything else to cancel", default="", show_default=False)
        if choice.strip().lower() == "confirm":
            out = stage_analysis_fix(result, output_dir=export_dir)
            click.echo(json.dumps(out, indent=2))
        else:
            click.echo("Canceled — no files were written.")
    else:
        result = consolidate_roles(neo4j_uri, neo4j_user, neo4j_pass, threshold=threshold, model=model, backend=backend)
        summaries = []
        for c in result.get("clusters", []):
            cluster = c.get("cluster")
            recommendation = c.get("recommendation")
            preview = preview_consolidation(cluster, recommendation)
            click.echo(json.dumps(preview, indent=2))
            choice = click.prompt(f"For cluster {cluster.get('roles')}, type 'confirm' to write IaC, or anything else to skip", default="", show_default=False)
            if choice.strip().lower() == "confirm":
                s = stage_consolidation(cluster, recommendation, export_dir)
                summaries.append(s)
        if summaries:
            click.echo(json.dumps({"staged": summaries}, indent=2))
        else:
            click.echo("No clusters staged.")


if __name__ == "__main__":
    cli()
