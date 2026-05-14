"""RAG retriever: semantic search over the embedded IAM graph and knowledge base.

Exports:
- `retrieve_iam_context(driver, query_texts, embed_fn, top_k=5)` -> str
  Returns a formatted string of relevant IAM knowledge + similar graph nodes
  ready for injection into an LLM system prompt.
"""
import logging
from typing import Callable, Dict, List, Any

logger = logging.getLogger(__name__)


def _vector_query_nodes(session, index_name: str, embedding: List[float], top_k: int) -> List[Dict]:
    """Run a Neo4j vector similarity query. Returns list of {node props, score}."""
    try:
        result = session.run(
            "CALL db.index.vector.queryNodes($index, $k, $embedding) "
            "YIELD node, score "
            "RETURN properties(node) AS props, labels(node) AS labels, score",
            index=index_name,
            k=top_k,
            embedding=embedding,
        )
        return [{"props": r["props"], "labels": r["labels"], "score": r["score"]} for r in result]
    except Exception as exc:
        # Index may not exist yet (user hasn't run embed command)
        logger.debug("Vector query failed on %s: %s", index_name, exc)
        return []


def _format_knowledge_hit(hit: Dict) -> str:
    props = hit["props"]
    score = hit["score"]
    mitre = props.get("mitre", "")
    text = props.get("text", "")
    mitre_tag = f" [MITRE: {mitre}]" if mitre and mitre != "N/A" else ""
    return f"[Relevance {score:.2f}]{mitre_tag} {text}"


def _format_permission_hit(hit: Dict) -> str:
    props = hit["props"]
    score = hit["score"]
    action = props.get("action", "?")
    resource = props.get("resource", "*")
    last_used = props.get("last_used")
    staleness = f", last_used={last_used}" if last_used else ", NEVER USED"
    return f"[Relevance {score:.2f}] Similar permission in graph: {action} on {resource}{staleness}"


def retrieve_iam_context(
    driver,
    query_texts: List[str],
    embed_fn: Callable[[str], List[float]],
    top_k: int = 5,
) -> str:
    """Retrieve semantically relevant IAM knowledge and graph context for a list of query strings.

    Args:
        driver: Neo4j driver instance.
        query_texts: List of texts describing the findings being analyzed.
        embed_fn: Callable that converts text -> embedding vector.
        top_k: Number of similar nodes to retrieve per query.

    Returns:
        A formatted string block to inject into the LLM system prompt.
    """
    if not query_texts:
        return ""

    knowledge_hits: List[str] = []
    graph_hits: List[str] = []
    seen_texts: set = set()

    with driver.session() as session:
        for query_text in query_texts:
            try:
                emb = embed_fn(query_text)
            except Exception as exc:
                logger.warning("Embedding failed for query '%s': %s", query_text[:60], exc)
                continue

            # Retrieve from knowledge base
            for hit in _vector_query_nodes(session, "idx_knowledge_embedding", emb, top_k):
                text = hit["props"].get("text", "")
                if text and text not in seen_texts:
                    seen_texts.add(text)
                    knowledge_hits.append(_format_knowledge_hit(hit))

            # Retrieve similar Permission nodes already in the graph
            for hit in _vector_query_nodes(session, "idx_permission_embedding", emb, min(top_k, 3)):
                action = hit["props"].get("action", "")
                resource = hit["props"].get("resource", "")
                key = f"{action}|{resource}"
                if key not in seen_texts:
                    seen_texts.add(key)
                    graph_hits.append(_format_permission_hit(hit))

    if not knowledge_hits and not graph_hits:
        return ""

    sections: List[str] = []
    if knowledge_hits:
        sections.append(
            "RELEVANT IAM SECURITY KNOWLEDGE (from vector similarity search):\n"
            + "\n".join(f"  • {h}" for h in knowledge_hits[:top_k])
        )
    if graph_hits:
        sections.append(
            "SIMILAR PERMISSIONS FOUND IN THIS GRAPH:\n"
            + "\n".join(f"  • {h}" for h in graph_hits[:top_k])
        )

    return "\n\n".join(sections)


def build_finding_queries(findings: List[Dict], shadow_paths: List[Dict]) -> List[str]:
    """Convert raw analyzer findings into query strings for embedding lookup."""
    queries: List[str] = []

    for f in findings:
        action = f.get("action", "")
        resource = f.get("resource", "*")
        last_used = f.get("last_used")
        staleness = "never used" if not last_used else f"last used {last_used}"
        queries.append(f"IAM zombie permission: {action} on {resource}, {staleness}")

    for sp in shadow_paths[:10]:
        user = sp.get("user", "?")
        action = sp.get("action", "?")
        queries.append(f"Shadow admin path: user {user} has transitive access to {action}")

    return queries
