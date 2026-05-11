"""Top-level CLI shim so the project can be run as `python -m src.cli`.

Provides a `seed` command that calls into the package loader to populate mock data.
"""
import click
import json
from iamdbagent.graph.neo4j_loader import seed_mock_data
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
@click.option("--days", default=90, help="Days threshold to consider a permission zombie")
@click.option("--model", default=None, help="LLM model to use (model name for selected backend)")
@click.option("--backend", default="ollama", help="LLM backend to use: ollama|openai|anthropic")
@click.option("--export", is_flag=True, default=False, help="Write suggested IaC to disk in deployments/")
@click.option("--export-dir", default="staged_changes", help="Directory to write IaC files to")
@click.option("--dry-run", is_flag=True, default=False, help="Preview what would be staged without writing files")
@click.option("--min-risk-score", default=0, help="Only include findings at or above this risk score (1-10)")
def analyze(neo4j_uri, neo4j_user, neo4j_pass, days, model, backend, export, export_dir, dry_run, min_risk_score):
    """Run analysis on the Neo4j DB and solicit a recommendation from local LLM."""
    result = run_analysis(neo4j_uri, neo4j_user, neo4j_pass, days=days, model=model, backend=backend)
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
@click.option("--export", is_flag=True, default=False, help="Write suggested IaC to disk in deployments/")
@click.option("--export-dir", default="staged_changes", help="Directory to write IaC files to")
@click.option("--dry-run", is_flag=True, default=False, help="Preview what would be staged without writing files")
def consolidate(neo4j_uri, neo4j_user, neo4j_pass, threshold, model, backend, export, export_dir, dry_run):
    """Find similar roles and request consolidation recommendations from LLM."""
    result = consolidate_roles(neo4j_uri, neo4j_user, neo4j_pass, threshold=threshold, model=model, backend=backend)
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
