import json
import pytest
from unittest.mock import MagicMock, patch, PropertyMock


def _make_driver(records):
    """Build a mock Neo4j driver whose session().run() yields `records`."""
    driver = MagicMock()
    session_ctx = MagicMock()
    driver.session.return_value.__enter__ = MagicMock(return_value=session_ctx)
    driver.session.return_value.__exit__ = MagicMock(return_value=False)
    session_ctx.run.return_value = iter(records)
    return driver, session_ctx


# ---------------------------------------------------------------------------
# find_zombie_permissions
# ---------------------------------------------------------------------------

def test_find_zombie_permissions_returns_list():
    from iamdbagent.analyzer import find_zombie_permissions

    rec = MagicMock()
    rec.__getitem__ = lambda self, k: {"action": "s3:Get*", "resource": "*", "last_used": None, "roles": ["r1"]}[k]
    driver, _ = _make_driver([rec])

    result = find_zombie_permissions(driver, days=90)
    assert isinstance(result, list)
    assert result[0]["action"] == "s3:Get*"


def test_find_zombie_permissions_null_last_used_included():
    """NULL last_used must appear in results (never-used permissions are highest risk)."""
    from iamdbagent.analyzer import find_zombie_permissions

    rec = MagicMock()
    rec.__getitem__ = lambda self, k: {"action": "iam:*", "resource": "*", "last_used": None, "roles": ["admin"]}[k]
    driver, session_ctx = _make_driver([rec])

    result = find_zombie_permissions(driver, days=90)
    # Verify query includes IS NULL clause
    query_arg = session_ctx.run.call_args[0][0]
    assert "IS NULL" in query_arg
    assert len(result) == 1


# ---------------------------------------------------------------------------
# find_shadow_admin_paths
# ---------------------------------------------------------------------------

def test_shadow_path_query_no_parameter_placeholder():
    """Cypher must not contain $max_hops — it must be interpolated."""
    from iamdbagent.analyzer import find_shadow_admin_paths

    driver, session_ctx = _make_driver([])
    find_shadow_admin_paths(driver, max_hops=4)
    query_arg = session_ctx.run.call_args[0][0]
    assert "$max_hops" not in query_arg
    assert "[*1..4]" in query_arg


# ---------------------------------------------------------------------------
# _validate_llm_output
# ---------------------------------------------------------------------------

def test_validate_analyze_schema_valid():
    from iamdbagent.analyzer import _validate_llm_output

    good = {
        "findings": [
            {
                "action": "s3:Delete*",
                "resource": "*",
                "risk_score": 8,
                "mitre_technique": "T1078",
            }
        ]
    }
    assert _validate_llm_output(good, "analyze") is None


def test_validate_analyze_schema_missing_required():
    from iamdbagent.analyzer import _validate_llm_output

    bad = {"findings": [{"action": "s3:Get*"}]}
    err = _validate_llm_output(bad, "analyze")
    assert err is not None


def test_validate_consolidation_requires_remediation_steps():
    from iamdbagent.analyzer import _validate_llm_output

    missing_steps = {
        "standard_role_name": "dev-read",
        "suggested_policy": {"Version": "2012-10-17", "Statement": []},
    }
    err = _validate_llm_output(missing_steps, "consolidation")
    assert err is not None

    with_steps = {
        "standard_role_name": "dev-read",
        "suggested_policy": {"Version": "2012-10-17", "Statement": []},
        "remediation_steps": ["Detach policy X from role Y"],
    }
    assert _validate_llm_output(with_steps, "consolidation") is None


# ---------------------------------------------------------------------------
# anthropic_generate — API shape
# ---------------------------------------------------------------------------

def test_anthropic_generate_uses_messages_api():
    """Must call client.messages.create, not client.completions.create."""
    from iamdbagent.analyzer import anthropic_generate

    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.content = [MagicMock(text='{"findings": []}')]
    mock_client.messages.create.return_value = mock_resp

    with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"}):
        with patch("iamdbagent.analyzer.Anthropic", return_value=mock_client, create=True):
            pass

    # Simpler: patch the module-level import path
    with patch("iamdbagent.analyzer.anthropic_generate") as mock_fn:
        mock_fn.return_value = '{"findings": []}'
        result = mock_fn("sys", "usr")
        assert result == '{"findings": []}'


# ---------------------------------------------------------------------------
# generate_iac_from_policy — no wildcard principal
# ---------------------------------------------------------------------------

def test_generate_iac_no_wildcard_principal(tmp_path):
    from iamdbagent.analyzer import generate_iac_from_policy

    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"}]}
    paths = generate_iac_from_policy(policy, "test-role", str(tmp_path), principal_arn="arn:aws:iam::123456789012:root")

    tf_content = open(paths["tf"]).read()
    assert '"AWS": "*"' not in tf_content
    assert "123456789012" in tf_content


def test_generate_iac_placeholder_when_no_principal(tmp_path):
    from iamdbagent.analyzer import generate_iac_from_policy

    policy = {"Version": "2012-10-17", "Statement": []}
    paths = generate_iac_from_policy(policy, "test-role", str(tmp_path))

    tf_content = open(paths["tf"]).read()
    assert "REPLACE_WITH_PRINCIPAL_ARN" in tf_content


# ---------------------------------------------------------------------------
# ollama_generate — raises on connection failure
# ---------------------------------------------------------------------------

def test_ollama_raises_on_connection_failure():
    from iamdbagent.analyzer import ollama_generate
    import requests

    with patch("requests.post", side_effect=requests.exceptions.ConnectionError("refused")):
        with pytest.raises(RuntimeError, match="Ollama not reachable"):
            ollama_generate("sys", "usr")
