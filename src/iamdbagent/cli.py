"""CLI entrypoints for iamdbagent (minimal)."""
import click
import boto3
from .ingest.aws_iam import extract_aws_iam
from .graph.neo4j_loader import load_iam_graph


@click.group()
def cli():
    pass


@cli.command()
@click.option("--profile", default=None, help="AWS profile name to use")
@click.option("--neo4j-uri", required=True, help="Neo4j URI, e.g. bolt://localhost:7687")
@click.option("--neo4j-user", default="neo4j", help="Neo4j user")
@click.option("--neo4j-pass", default=None, help="Neo4j password")
def fetch_aws(profile, neo4j_uri, neo4j_user, neo4j_pass):
    """Fetch AWS IAM entities and load into Neo4j (read-only).

    This command is conservative and will only read from AWS.
    """
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    data = extract_aws_iam(session)
    if not neo4j_pass:
        raise click.UsageError("--neo4j-pass is required for loading data into Neo4j")
    load_iam_graph(neo4j_uri, neo4j_user, neo4j_pass, data)
    click.echo("Loaded IAM data into Neo4j")


if __name__ == "__main__":
    cli()
