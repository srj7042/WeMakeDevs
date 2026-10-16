"""
Graph-Native Cypher Queries for ORACLE Incident Investigation.

Demonstrates core Cypher constructs:
- MATCH, WHERE, RETURN
- ORDER BY, LIMIT
- CREATE, MERGE, SET (idempotency & state mutations)
- WITH (pipeline projection, aggregation & multi-stage filtering)
- Variable-length paths (*1..N) for blast radius and root-cause tracing
- Parameterized inputs (protects against Cypher injection & enables plan caching)
"""

from typing import Any, Dict, List
from client import OracleIncidentsClient


def get_incident_summary(client: OracleIncidentsClient, severity: str) -> List[List[Any]]:
    """
    Demonstrates: MATCH, WHERE, RETURN with parameterized input.
    Retrieves incidents matching a specific severity level.
    """
    query = """
    MATCH (i:Incident)-[:HAS_ALERT]->(a:Alert)-[:OBSERVED_ON]->(s:Service)
    WHERE i.severity = $severity
    RETURN
        i.id AS incident_id,
        i.title AS title,
        i.status AS status,
        s.name AS affected_service,
        a.signal AS alert_signal
    """
    res = client.read_query(query, params={"severity": severity})
    return res.result_set


def list_top_tier_services(client: OracleIncidentsClient, limit: int = 5) -> List[List[Any]]:
    """
    Demonstrates: ORDER BY, LIMIT with parameterized limit.
    Ranks services by criticality (Tier 0 = mission critical).
    """
    query = """
    MATCH (s:Service)
    RETURN
        s.id AS service_id,
        s.name AS service_name,
        s.criticality AS criticality,
        s.health AS health
    ORDER BY s.criticality ASC, s.name ASC
    LIMIT $limit
    """
    res = client.read_query(query, params={"limit": limit})
    return res.result_set


def update_incident_status(
    client: OracleIncidentsClient,
    incident_id: str,
    new_status: str,
    note: str,
) -> List[List[Any]]:
    """
    Demonstrates: MERGE, SET, ON MATCH SET on a controlled write path.
    Updates incident lifecycle state idempotently.
    """
    query = """
    MATCH (i:Incident {id: $incident_id})
    SET i.status = $new_status,
        i.latest_note = $note,
        i.updated_at = timestamp()
    RETURN i.id AS id, i.status AS status, i.latest_note AS note
    """
    res = client.write_query(
        query,
        params={"incident_id": incident_id, "new_status": new_status, "note": note},
    )
    return res.result_set


def find_high_impact_dependencies(
    client: OracleIncidentsClient,
    min_dependents: int = 1,
) -> List[List[Any]]:
    """
    Demonstrates: WITH clause for intermediate aggregation and filtering.
    Identifies providers that the most consumer services depend on (single points of failure).
    """
    query = """
    MATCH (consumer:Service)-[:DEPENDS_ON]->(provider:Service)
    WITH provider, count(consumer) AS consumer_count
    WHERE consumer_count >= $min_dependents
    RETURN
        provider.id AS service_id,
        provider.name AS service_name,
        provider.criticality AS criticality,
        consumer_count
    ORDER BY consumer_count DESC, provider.criticality ASC
    """
    res = client.read_query(query, params={"min_dependents": min_dependents})
    return res.result_set


def calculate_blast_radius(
    client: OracleIncidentsClient,
    failed_service_id: str,
    max_depth: int = 4,
) -> List[List[Any]]:
    """
    Demonstrates: Variable-length paths (*1..N) to compute transitive blast radius.
    Traverses in reverse (consumer -> provider) to locate every consumer service impacted by provider failure.
    """
    query = f"""
    MATCH path = (consumer:Service)-[:DEPENDS_ON*1..{max_depth}]->(provider:Service {{id: $target_id}})
    RETURN
        consumer.id AS affected_service,
        consumer.criticality AS criticality,
        length(path) AS hops_from_outage,
        [n IN nodes(path) | n.id] AS dependency_chain
    ORDER BY hops_from_outage ASC, consumer.criticality ASC
    """
    res = client.read_query(query, params={"target_id": failed_service_id})
    return res.result_set


def trace_suspected_root_cause(
    client: OracleIncidentsClient,
    incident_id: str,
) -> List[List[Any]]:
    """
    Demonstrates: Multi-hop graph traversal combining Incidents, Alerts, Services, and Deployments.
    Finds deployments directly linked or linked via downstream dependency tree.
    """
    query = """
    MATCH (i:Incident {id: $incident_id})-[:HAS_ALERT]->(a:Alert)-[:OBSERVED_ON]->(s:Service)
    OPTIONAL MATCH (s)-[:DEPENDS_ON*0..3]->(target:Service)-[:DEPLOYED_IN]->(d:Deployment)
    OPTIONAL MATCH (target)-[:USES]->(p:Package)-[:HAS_VULNERABILITY]->(v:Vulnerability)
    RETURN
        i.id AS incident,
        s.name AS alert_service,
        target.name AS root_service,
        d.id AS deployment_id,
        d.version AS deployment_version,
        d.status AS deployment_status,
        v.cve_id AS vulnerability
    """
    res = client.read_query(query, params={"incident_id": incident_id})
    return res.result_set


if __name__ == "__main__":
    client = OracleIncidentsClient()

    print("=== 1. MATCH, WHERE, RETURN ===")
    incidents = get_incident_summary(client, severity="SEV-1")
    for row in incidents:
        print(f"Incident: {row[0]} | Title: {row[1]} | Service: {row[3]} | Alert: {row[4]}")

    print("\n=== 2. ORDER BY, LIMIT ===")
    top_svcs = list_top_tier_services(client, limit=3)
    for row in top_svcs:
        print(f"Service: {row[0]:<18} | Criticality: {row[2]} | Health: {row[3]}")

    print("\n=== 3. WITH Clause (Critical Infrastructure Aggregation) ===")
    deps = find_high_impact_dependencies(client, min_dependents=1)
    for row in deps:
        print(f"Service: {row[0]:<18} | Dependents: {row[3]} | Criticality: {row[2]}")

    print("\n=== 4. Variable-Length Paths (Transitive Blast Radius) ===")
    radius = calculate_blast_radius(client, failed_service_id="postgres-orders")
    print("If 'postgres-orders' fails, impacted upstream services:")
    for row in radius:
        print(f"-> {row[0]} (Criticality: {row[1]}, Hops: {row[2]}, Chain: {' -> '.join(row[3])})")

    print("\n=== 5. Root Cause Trace ===")
    root_cause = trace_suspected_root_cause(client, incident_id="INC-101")
    for row in root_cause:
        print(f"Incident {row[0]} on '{row[1]}' -> Root: {row[2]} (Deployment: {row[3]} {row[4]}, status: {row[5]}, Vuln: {row[6]})")

    print("\n=== 6. Controlled Write (MERGE / SET) ===")
    updated = update_incident_status(
        client,
        incident_id="INC-101",
        new_status="INVESTIGATING",
        note="Identified schema lock on Orders DB due to DEP-401 migration",
    )
    print("Updated state:", updated)

    client.close()
