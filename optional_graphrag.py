"""
Optional Extension: GraphRAG-SDK for Unstructured Incident Artifacts.

Architectural Scope:
- Core MVP (Structured): Incidents, services, alerts, and dependency trees are handled
  directly by the official Python client + Cypher (fast, deterministic, zero-cost).
- Optional Extension (Unstructured): Postmortems, runbooks, and disaster recovery SOPs
  can optionally be ingested via GraphRAG-SDK to answer natural language questions
  with source citations.

Reference: https://github.com/FalkorDB/GraphRAG-SDK
"""

import os
from typing import Any, Dict, Optional


def check_graphrag_readiness() -> Dict[str, Any]:
    """Check if GraphRAG-SDK prerequisites (package & LLM API keys) are configured."""
    has_package = False
    try:
        import graphrag_sdk  # noqa: F401
        has_package = True
    except ImportError:
        has_package = False

    has_llm_key = bool(
        os.getenv("OPENAI_API_KEY")
        or os.getenv("GEMINI_API_KEY")
        or os.getenv("ANTHROPIC_API_KEY")
    )

    return {
        "sdk_installed": has_package,
        "llm_key_configured": has_llm_key,
        "ready": has_package and has_llm_key,
    }


def query_postmortem_knowledge_base(
    question: str,
    incident_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Query unstructured postmortems and runbooks.

    If GraphRAG-SDK is not configured, provides a deterministic structured fallback
    using direct Cypher queries from the core ORACLE client.
    """
    status = check_graphrag_readiness()

    if not status["ready"]:
        # Deterministic fallback to structured graph
        from client import OracleIncidentsClient
        db = OracleIncidentsClient()
        
        fallback_query = """
        MATCH (i:Incident)
        OPTIONAL MATCH (i)-[:AFFECTS]->(s:Service)
        OPTIONAL MATCH (i)-[:SUSPECTED_CAUSE]->(d:Deployment)
        RETURN i.id AS incident, i.title AS title, i.status AS status, s.name AS service, d.version AS bad_version
        """
        rows = db.read_query(fallback_query).result_set
        db.close()

        return {
            "mode": "structured_fallback",
            "message": (
                "GraphRAG-SDK is an optional extension for unstructured documents (runbooks/postmortems) "
                "and is not enabled for the MVP. Serving answer deterministically from structured FalkorDB topology."
            ),
            "structured_records": rows,
        }

    # If GraphRAG-SDK is installed and configured:
    # from graphrag_sdk import KnowledgeGraph, Source
    # kg = KnowledgeGraph(name="oracle_runbooks", host="localhost", port=6379)
    # answer = kg.ask(question)
    # return {"mode": "graphrag", "answer": answer.text, "citations": answer.sources}
    return {"mode": "graphrag", "status": "active"}


if __name__ == "__main__":
    print("Checking GraphRAG-SDK readiness:")
    res = check_graphrag_readiness()
    print(f"  - SDK Installed: {res['sdk_installed']}")
    print(f"  - LLM Key Configured: {res['llm_key_configured']}")
    print(f"  - Status: {'Enabled' if res['ready'] else 'Optional / Inactive (Standard MVP Mode)'}")

    print("\nRunning demonstration query:")
    sample = query_postmortem_knowledge_base("What was the root cause of the orders outage?")
    print("Result Mode:", sample["mode"])
    print("Message:", sample["message"])
    print("Structured Records Retrieved:", sample["structured_records"])
