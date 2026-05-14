"""CLI entrypoints for iamdbagent (minimal)."""
import click
import boto3
from .ingest.aws_iam import extract_aws_iam
from .ingest.sailpoint_iam import extract_sailpoint_iam
from .graph.neo4j_loader import load_iam_graph, load_sailpoint_graph


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


@cli.command()
@click.option("--tenant-url", required=True, envvar="SAILPOINT_TENANT_URL",
              help="SailPoint tenant base URL, e.g. https://org.api.identitynow.com")
@click.option("--client-id", required=True, envvar="SAILPOINT_CLIENT_ID",
              help="OAuth2 client ID (PAT or dedicated client)")
@click.option("--client-secret", required=True, envvar="SAILPOINT_CLIENT_SECRET",
              help="OAuth2 client secret")
@click.option("--neo4j-uri", required=True, help="Neo4j URI, e.g. bolt://localhost:7687")
@click.option("--neo4j-user", default="neo4j", help="Neo4j user")
@click.option("--neo4j-pass", required=True, help="Neo4j password")
def fetch_sailpoint(tenant_url, client_id, client_secret, neo4j_uri, neo4j_user, neo4j_pass):
    """Fetch SailPoint IdentityNow IAM entities and load into Neo4j (read-only).

    Extracts identities (users), roles, access profiles (policies), and
    entitlements (permissions) from SailPoint V3 API, then upserts into Neo4j
    for downstream analysis.

    Credentials can be supplied via env vars:
    SAILPOINT_TENANT_URL, SAILPOINT_CLIENT_ID, SAILPOINT_CLIENT_SECRET
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
    click.echo("Loaded SailPoint IAM graph into Neo4j")


if __name__ == "__main__":
    cli()
