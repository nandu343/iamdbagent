"""Top-level CLI shim so the project can be run as `python -m src.cli`.

Provides a `seed` command that calls into the package loader to populate mock data.
"""
import click
import json
from iamdbagent.graph.neo4j_loader import seed_mock_data
from src.analyzer import analyze as run_analysis
from src.analyzer import consolidate_roles


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
@click.option("--model", default=None, help="LLM model to use (ollama model name)")
def analyze(neo4j_uri, neo4j_user, neo4j_pass, days, model):
    """Run analysis on the Neo4j DB and solicit a recommendation from local LLM."""
    result = run_analysis(neo4j_uri, neo4j_user, neo4j_pass, days=days, model=model)
    click.echo(json.dumps(result, indent=2))


@cli.command()
@click.option("--neo4j-uri", required=True, help="Neo4j URI (bolt://host:port)")
@click.option("--neo4j-user", default="neo4j", help="Neo4j username")
@click.option("--neo4j-pass", required=True, help="Neo4j password")
@click.option("--threshold", default=0.8, help="Jaccard similarity threshold for clustering (0-1)")
@click.option("--model", default=None, help="LLM model to use (ollama model name)")
def consolidate(neo4j_uri, neo4j_user, neo4j_pass, threshold, model):
    """Find similar roles and request consolidation recommendations from LLM."""
    result = consolidate_roles(neo4j_uri, neo4j_user, neo4j_pass, threshold=threshold, model=model)
    click.echo(json.dumps(result, indent=2))


if __name__ == "__main__":
    cli()
