"""
Path Analysis & Traversal for ORACLE Incident Investigation.

Focuses on:
1. Bounded Cypher Path Traversal (*1..N) - primary, declarative, and easy to validate.
2. Shortest Path (shortestPath in WITH) - concise entity-to-entity connection.
3. Explicit BFS Traversal - level-by-level frontier exploration (for comparison/demo).
4. Deliberate omission of PageRank / Community Detection (avoiding vanity complexity).
"""

from collections import deque
from typing import Any, Dict, List, Optional
from client import OracleIncidentsClient


def bounded_cypher_traversal(
    client: OracleIncidentsClient,
    start_service_id: str,
    max_depth: int = 3,
) -> List[Dict[str, Any]]:
    """
    Recommended Primary Approach: Bounded Cypher Path Traversal (*1..N).

    Uses FalkorDB's native Cypher engine to explore dependencies up to max_depth.
    Predictable, bounded execution time, and simple to validate.
    """
    query = f"""
    MATCH path = (start:Service {{id: $start_id}})-[:DEPENDS_ON*1..{max_depth}]->(downstream:Service)
    RETURN
        downstream.id AS service_id,
        downstream.name AS service_name,
        downstream.criticality AS criticality,
        length(path) AS depth,
        [n IN nodes(path) | n.id] AS path_chain
    ORDER BY depth ASC, downstream.criticality ASC
    """
    res = client.read_query(query, params={"start_id": start_service_id})
    return [
        {
            "service_id": row[0],
            "service_name": row[1],
            "criticality": row[2],
            "depth": row[3],
            "path": row[4],
        }
        for row in res.result_set
    ]


def find_shortest_path(
    client: OracleIncidentsClient,
    from_service_id: str,
    to_service_id: str,
) -> Optional[Dict[str, Any]]:
    """
    Concise Entity Connection: FalkorDB shortestPath() in WITH clause.

    Finds the shortest dependency or incident connection between two nodes.
    Backed by FalkorDB's C/GraphBLAS matrix-based pathfinder.
    """
    query = """
    MATCH (src:Service {id: $src_id}), (dst:Service {id: $dst_id})
    WITH shortestPath((src)-[:DEPENDS_ON*]->(dst)) AS p
    RETURN
        [n IN nodes(p) | n.id] AS path_nodes,
        length(p) AS distance
    """
    res = client.read_query(query, params={"src_id": from_service_id, "dst_id": to_service_id})
    if not res.result_set or res.result_set[0][0] is None:
        return None

    row = res.result_set[0]
    return {
        "path": row[0],
        "distance": row[1],
    }


def explicit_bfs_traversal(
    client: OracleIncidentsClient,
    start_service_id: str,
    max_depth: int = 3,
) -> List[Dict[str, Any]]:
    """
    Procedural BFS: Demonstrates level-by-level frontier expansion.

    Optional: Use only when the demo explicitly requires step-by-step
    frontier inspection or progressive level-by-level UI animation.
    """
    visited = {start_service_id}
    queue = deque([(start_service_id, 0, [start_service_id])])
    discovered = []

    # Single-hop neighbor query for frontier expansion
    hop_query = """
    MATCH (s:Service {id: $current_id})-[:DEPENDS_ON]->(neighbor:Service)
    RETURN neighbor.id AS id, neighbor.name AS name, neighbor.criticality AS criticality
    """

    while queue:
        current_id, depth, path = queue.popleft()
        if depth >= max_depth:
            continue

        res = client.read_query(hop_query, params={"current_id": current_id})
        for row in res.result_set:
            neighbor_id, neighbor_name, criticality = row[0], row[1], row[2]
            if neighbor_id not in visited:
                visited.add(neighbor_id)
                new_path = path + [neighbor_id]
                entry = {
                    "service_id": neighbor_id,
                    "service_name": neighbor_name,
                    "criticality": criticality,
                    "depth": depth + 1,
                    "path": new_path,
                }
                discovered.append(entry)
                queue.append((neighbor_id, depth + 1, new_path))

    return discovered


if __name__ == "__main__":
    client = OracleIncidentsClient()

    print("=== 1. Bounded Cypher Path Traversal (*1..3) ===")
    cypher_results = bounded_cypher_traversal(client, start_service_id="api-gateway", max_depth=3)
    for r in cypher_results:
        print(f"Depth {r['depth']}: {r['service_id']} ({r['criticality']}) | Chain: {' -> '.join(r['path'])}")

    print("\n=== 2. FalkorDB Shortest Path (Concise Connection) ===")
    sp = find_shortest_path(client, from_service_id="api-gateway", to_service_id="postgres-orders")
    if sp:
        print(f"Shortest path from 'api-gateway' to 'postgres-orders':")
        print(f"Distance: {sp['distance']} hops | Path: {' -> '.join(sp['path'])}")

    print("\n=== 3. Explicit BFS Traversal (Step-by-Step Frontier) ===")
    bfs_results = explicit_bfs_traversal(client, start_service_id="api-gateway", max_depth=3)
    for r in bfs_results:
        print(f"Level {r['depth']}: {r['service_id']} | Path: {' -> '.join(r['path'])}")

    # Sanity check: verify that both discover the same service set
    cypher_services = {r["service_id"] for r in cypher_results}
    bfs_services = {r["service_id"] for r in bfs_results}
    assert cypher_services == bfs_services, f"Mismatch: {cypher_services} != {bfs_services}"
    print(f"\n✓ Consistency Verified: Both discovered {len(cypher_services)} services across identical depth bounds.")

    client.close()
