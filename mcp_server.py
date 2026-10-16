"""
Official MCP (Model Context Protocol) Server for ORACLE.

Exposes the 7 required domain tools:
1. get_incident_context(incident_id)
2. trace_candidate_causes(incident_id)
3. get_blast_radius(service_id, max_depth)
4. get_evidence_chain(incident_id)
5. get_deployment_history(service_id)
6. get_vulnerable_services(vulnerability_id)
7. get_service_owner(service_id)

Security Guarantee:
- Read-only execution via GRAPH.RO_QUERY.
- Fixed parameterized Cypher queries.
- Zero arbitrary write or shell command execution.
"""

from typing import Any, Dict, List
from mcp.server.mcpserver import MCPServer
from graph_service import GraphService

server = MCPServer("oracle-incident-mcp-server")
graph_svc = GraphService()


@server.tool()
def get_incident_context(incident_id: str) -> Dict[str, Any]:
    """Retrieve incident metadata, connected alerts, and observed services."""
    return graph_svc.get_incident_context(incident_id)


@server.tool()
def trace_candidate_causes(incident_id: str) -> List[Dict[str, Any]]:
    """Traverse dependency tree and discover candidate root causes (deployments, vulnerabilities)."""
    return graph_svc.trace_candidate_causes(incident_id)


@server.tool()
def get_blast_radius(service_id: str, max_depth: int = 4) -> Dict[str, Any]:
    """Compute downstream blast radius by traversing consumer dependencies."""
    return graph_svc.get_blast_radius(service_id, max_depth=max_depth)


@server.tool()
def get_evidence_chain(incident_id: str) -> List[Dict[str, Any]]:
    """Retrieve linked supporting and contradictory evidence items."""
    return graph_svc.get_evidence_chain(incident_id)


@server.tool()
def get_deployment_history(service_id: str) -> List[Dict[str, Any]]:
    """Retrieve deployment history and status for a service."""
    return graph_svc.get_deployment_history(service_id)


@server.tool()
def get_vulnerable_services(vulnerability_id: str) -> List[Dict[str, Any]]:
    """Find services using packages affected by a specific vulnerability."""
    return graph_svc.get_vulnerable_services(vulnerability_id)


@server.tool()
def get_service_owner(service_id: str) -> Dict[str, Any]:
    """Lookup the owning team and on-call engineer for a service."""
    return graph_svc.get_service_owner(service_id)


if __name__ == "__main__":
    import json

    print("=== Testing 7 Official MCP Tools ===")
    ctx = get_incident_context("INC-101")
    print(f"✓ get_incident_context: {ctx.get('title')} ({ctx.get('total_alerts')} alerts)")

    causes = trace_candidate_causes("INC-101")
    print(f"✓ trace_candidate_causes: Found {len(causes)} candidates (top: {causes[0]['entity_id']})")

    blast = get_blast_radius("postgres-orders")
    print(f"✓ get_blast_radius: {blast['total_impacted_services']} impacted services, Tier 0: {blast['tier_0_compromised']}")

    ev = get_evidence_chain("INC-101")
    print(f"✓ get_evidence_chain: {len(ev)} evidence items (stances: {[e['stance'] for e in ev]})")

    deps = get_deployment_history("postgres-orders")
    print(f"✓ get_deployment_history: {len(deps)} deployments for postgres-orders")

    vulns = get_vulnerable_services("CVE-2026-4412")
    print(f"✓ get_vulnerable_services: {len(vulns)} services affected by CVE-2026-4412")

    owner = get_service_owner("order-service")
    print(f"✓ get_service_owner: {owner.get('team_name')} (On-call: {owner.get('on_call')})")

    print("\n✓ All 7 MCP domain tools verified against FalkorDB.")
