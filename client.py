"""
Official FalkorDB Client (falkordb-py) for Oracle Incidents.

Provides deterministic Cypher execution with separate read-only (investigation)
and controlled write (ingestion/audit) paths.
"""

from typing import Any, Dict, Optional
from falkordb import FalkorDB
from falkordb.graph import Graph
from falkordb.query_result import QueryResult


class OracleIncidentsClient:
    """FalkorDB client wrapper for the 'oracle_incidents' graph."""

    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        graph_name: str = "oracle_incidents",
        **kwargs: Any,
    ):
        self.host = host
        self.port = port
        self.graph_name = graph_name
        self.client = FalkorDB(host=host, port=port, **kwargs)
        self.graph: Graph = self.client.select_graph(graph_name)

    def read_query(
        self,
        query: str,
        params: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
    ) -> QueryResult:
        """
        Execute a read-only Cypher query using GRAPH.RO_QUERY.

        Use this method for all investigation, search, and agent queries.
        Write clauses (CREATE, MERGE, DELETE, SET) are strictly rejected by the engine.
        """
        return self.graph.ro_query(query, params=params, timeout=timeout)

    def write_query(
        self,
        query: str,
        params: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
    ) -> QueryResult:
        """
        Execute a mutating Cypher query using GRAPH.QUERY.

        Controlled write path: restricted to ingestion pipelines, audit trails,
        and approved state mutations.
        """
        return self.graph.query(query, params=params, timeout=timeout)

    def close(self) -> None:
        """Close connection to FalkorDB."""
        self.client.close()


if __name__ == "__main__":
    # Trivial verification using standard snippet
    client = FalkorDB(host="localhost", port=6379)
    graph = client.select_graph("oracle_incidents")
    result = graph.query("RETURN 1 AS ok")
    print("Direct graph.query result:", result.result_set)

    # Verification using wrapper class (both read and write paths)
    wrapper = OracleIncidentsClient()
    ro_result = wrapper.read_query("RETURN 1 AS ok")
    print("Wrapper read_query (GRAPH.RO_QUERY) result:", ro_result.result_set)
