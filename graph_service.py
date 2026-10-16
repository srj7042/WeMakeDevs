"""
Graph Query Service for ORACLE.

Executes bounded, parameterized Cypher queries against FalkorDB.
Enforces read-only execution (GRAPH.RO_QUERY) for investigation operations.
"""

from typing import Any, Dict, List, Optional
from client import OracleIncidentsClient


class GraphService:
    """Encapsulates all domain-specific FalkorDB Cypher queries."""

    def __init__(self, client: Optional[OracleIncidentsClient] = None):
        self.client = client or OracleIncidentsClient()

    def list_incidents(self) -> List[Dict[str, Any]]:
        """List all incidents in the graph."""
        query = """
        MATCH (i:Incident)
        OPTIONAL MATCH (i)-[:HAS_ALERT]->(a:Alert)-[:OBSERVED_ON]->(s:Service)
        RETURN
            i.id AS id,
            i.title AS title,
            i.severity AS severity,
            i.status AS status,
            i.created_at AS created_at,
            count(DISTINCT a) AS alert_count,
            collect(DISTINCT s.name) AS affected_services
        ORDER BY i.created_at DESC
        """
        res = self.client.read_query(query)
        incidents = []
        for r in res.result_set:
            incidents.append({
                "id": r[0],
                "title": r[1],
                "severity": r[2],
                "status": r[3],
                "created_at": r[4],
                "alert_count": r[5],
                "affected_services": r[6],
                "is_synthetic": True,
            })
        return incidents

    def get_incident_context(self, incident_id: str) -> Dict[str, Any]:
        """
        MCP Tool 1: Retrieve incident metadata, connected alerts, and observed services.
        """
        q_inc = """
        MATCH (i:Incident {id: $id})
        RETURN i.id, i.title, i.description, i.severity, i.status, i.created_at
        """
        res_inc = self.client.read_query(q_inc, params={"id": incident_id})
        if not res_inc.result_set:
            return {"error": f"Incident '{incident_id}' not found"}

        inc_row = res_inc.result_set[0]
        q_alerts = """
        MATCH (i:Incident {id: $id})-[:HAS_ALERT]->(a:Alert)-[:OBSERVED_ON]->(s:Service)
        OPTIONAL MATCH (t:Team)-[:OWNS]->(s)
        RETURN
            a.id AS alert_id,
            a.alert_type AS alert_type,
            a.observed_value AS observed_value,
            a.threshold AS threshold,
            a.triggered_at AS triggered_at,
            s.id AS service_id,
            s.name AS service_name,
            s.criticality AS criticality,
            s.status AS service_status,
            t.name AS team_name
        ORDER BY a.triggered_at ASC
        """
        res_alerts = self.client.read_query(q_alerts, params={"id": incident_id})
        alerts = []
        for a in res_alerts.result_set:
            alerts.append({
                "alert_id": a[0],
                "alert_type": a[1],
                "observed_value": a[2],
                "threshold": a[3],
                "triggered_at": a[4],
                "service": {
                    "id": a[5],
                    "name": a[6],
                    "criticality": a[7],
                    "status": a[8],
                    "owner_team": a[9] or "Unassigned",
                },
            })

        return {
            "incident_id": inc_row[0],
            "title": inc_row[1],
            "description": inc_row[2],
            "severity": inc_row[3],
            "status": inc_row[4],
            "created_at": inc_row[5],
            "alerts": alerts,
            "total_alerts": len(alerts),
            "is_synthetic": True,
        }

    def trace_candidate_causes(self, incident_id: str) -> List[Dict[str, Any]]:
        """
        MCP Tool 2: Traverse dependency paths and find candidate root causes
        (recent deployments, failed migrations, vulnerabilities) connected to alert services.
        """
        query = """
        MATCH (i:Incident {id: $id})-[:HAS_ALERT]->(a:Alert)-[:OBSERVED_ON]->(alert_svc:Service)
        MATCH (alert_svc)-[:DEPENDS_ON*0..3]->(target_svc:Service)
        OPTIONAL MATCH (target_svc)-[:DEPLOYED_IN]->(d:Deployment)
        OPTIONAL MATCH (target_svc)-[:USES]->(p:Package)-[:HAS_VULNERABILITY]->(v:Vulnerability)
        RETURN DISTINCT
            target_svc.id AS service_id,
            target_svc.name AS service_name,
            target_svc.criticality AS criticality,
            d.id AS deployment_id,
            d.version AS deployment_version,
            d.status AS deployment_status,
            d.deployed_at AS deployed_at,
            v.cve_id AS cve_id,
            v.severity AS vuln_severity,
            v.description AS vuln_desc
        """
        res = self.client.read_query(query, params={"id": incident_id})
        candidates = []
        seen = set()

        for r in res.result_set:
            svc_id, svc_name, crit, dep_id, dep_ver, dep_stat, dep_time, cve, v_sev, v_desc = r

            # Check deployment candidate
            if dep_id and (svc_id, dep_id) not in seen:
                seen.add((svc_id, dep_id))
                is_failed = dep_stat in ["failed", "failed_migration", "error"]
                candidates.append({
                    "cause_type": "DEPLOYMENT",
                    "confidence_score": 0.95 if is_failed else 0.40,
                    "service_id": svc_id,
                    "service_name": svc_name,
                    "criticality": crit,
                    "entity_id": dep_id,
                    "version": dep_ver,
                    "status": dep_stat,
                    "timestamp": dep_time,
                    "summary": f"Deployment {dep_id} ({dep_ver}) on {svc_name} with status '{dep_stat}'",
                    "is_failure": is_failed,
                })

            # Check vulnerability candidate
            if cve and (svc_id, cve) not in seen:
                seen.add((svc_id, cve))
                candidates.append({
                    "cause_type": "VULNERABILITY",
                    "confidence_score": 0.70 if v_sev == "HIGH" else 0.50,
                    "service_id": svc_id,
                    "service_name": svc_name,
                    "criticality": crit,
                    "entity_id": cve,
                    "severity": v_sev,
                    "summary": f"Known vulnerability {cve} ({v_sev}) in package on {svc_name}: {v_desc}",
                    "is_failure": False,
                })

        candidates.sort(key=lambda c: c["confidence_score"], reverse=True)
        return candidates

    def get_blast_radius(self, service_id: str, max_depth: int = 4) -> Dict[str, Any]:
        """
        MCP Tool 3: Reverse-direction downstream blast radius traversal.
        Finds all consumer services that depend on service_id up to max_depth.
        Deduplicates by service_id to prevent multiple paths from inflating service count.
        """
        if not service_id or not isinstance(service_id, str):
            return {
                "root_service_id": str(service_id),
                "total_impacted_services": 0,
                "tier_0_compromised": False,
                "impacted_services": [],
                "is_synthetic": True,
            }

        depth = max(1, min(int(max_depth), 6))
        query = f"""
        MATCH path = (consumer:Service)-[:DEPENDS_ON*1..{depth}]->(provider:Service {{id: $id}})
        RETURN
            consumer.id AS service_id,
            consumer.name AS service_name,
            consumer.criticality AS criticality,
            consumer.status AS status,
            length(path) AS hop_distance,
            [n IN nodes(path) | n.id] AS dependency_chain
        ORDER BY hop_distance ASC, consumer.criticality ASC
        """
        res = self.client.read_query(query, params={"id": service_id.strip()})
        impacted = []
        seen_services = set()
        for r in res.result_set:
            sid = r[0]
            if sid not in seen_services:
                seen_services.add(sid)
                impacted.append({
                    "service_id": sid,
                    "service_name": r[1],
                    "criticality": r[2],
                    "status": r[3],
                    "hop_distance": r[4],
                    "dependency_chain": r[5],
                })

        tier_0_impact = any(s["criticality"] == "Tier 0" for s in impacted)
        return {
            "root_service_id": service_id.strip(),
            "total_impacted_services": len(impacted),
            "tier_0_compromised": tier_0_impact,
            "impacted_services": impacted,
            "is_synthetic": True,
        }

    def get_evidence_chain(self, incident_id: str) -> List[Dict[str, Any]]:
        """
        MCP Tool 4: Retrieve evidence nodes linked to the incident,
        distinguishing supporting observations from contradictory / ruling-out signals.
        """
        query = """
        MATCH (e:Evidence)-[:SUPPORTS]->(i:Incident {id: $id})
        OPTIONAL MATCH (e)-[:OBSERVED]->(s:Service)
        OPTIONAL MATCH (e)-[:REFERS_TO]->(d:Deployment)
        RETURN
            e.id AS evidence_id,
            COALESCE(e.kind, e.source_type) AS kind,
            COALESCE(e.observation, e.kind) AS observation,
            COALESCE(e.timestamp, e.observed_at) AS timestamp,
            s.id AS service_id,
            s.name AS service_name,
            d.id AS deployment_id,
            d.version AS deployment_version,
            e.source_ref AS source_ref
        ORDER BY timestamp ASC
        """
        res = self.client.read_query(query, params={"id": incident_id})
        evidence_list = []
        for r in res.result_set:
            obs = r[2] or ""
            is_contradictory = "ruling out" in obs.lower() or "ruled out" in obs.lower()
            evidence_list.append({
                "evidence_id": r[0],
                "source_type": r[1],
                "kind": r[1],
                "observation": obs,
                "timestamp": r[3],
                "observed_at": r[3],
                "service_id": r[4],
                "service_name": r[5],
                "deployment_id": r[6],
                "deployment_version": r[7],
                "source_ref": r[8],
                "stance": "CONTRADICTORY" if is_contradictory else "SUPPORTING",
                "is_synthetic": True,
            })
        return evidence_list

    def get_deployment_history(self, service_id: str, limit: int = 5) -> List[Dict[str, Any]]:
        """
        MCP Tool 5: Retrieve deployment history for a specific service.
        """
        bounded_limit = max(1, min(int(limit), 20))
        query = """
        MATCH (s:Service {id: $id})-[:DEPLOYED_IN]->(d:Deployment)
        RETURN
            d.id AS deployment_id,
            d.version AS version,
            d.status AS status,
            d.commit_sha AS commit_sha,
            COALESCE(d.timestamp, d.deployed_at) AS timestamp
        ORDER BY timestamp DESC
        LIMIT $limit
        """
        res = self.client.read_query(query, params={"id": service_id, "limit": bounded_limit})
        deployments = []
        for r in res.result_set:
            deployments.append({
                "deployment_id": r[0],
                "version": r[1],
                "status": r[2],
                "commit_sha": r[3],
                "timestamp": r[4],
                "deployed_at": r[4],
                "is_synthetic": True,
            })
        return deployments

    def get_vulnerable_services(self, vulnerability_id: str) -> List[Dict[str, Any]]:
        """
        MCP Tool 6: Find all services using a package affected by vulnerability_id.
        """
        query = """
        MATCH (s:Service)-[:USES]->(p:Package)-[:HAS_VULNERABILITY]->(v:Vulnerability)
        WHERE v.id = $vid OR v.cve_id = $vid
        RETURN
            s.id AS service_id,
            s.name AS service_name,
            s.criticality AS criticality,
            p.name AS package_name,
            p.version AS package_version,
            v.cve_id AS cve_id,
            v.severity AS severity,
            v.description AS description
        """
        res = self.client.read_query(query, params={"vid": vulnerability_id})
        services = []
        for r in res.result_set:
            services.append({
                "service_id": r[0],
                "service_name": r[1],
                "criticality": r[2],
                "package_name": r[3],
                "package_version": r[4],
                "cve_id": r[5],
                "severity": r[6],
                "description": r[7],
                "is_synthetic": True,
            })
        return services

    def get_service_owner(self, service_id: str) -> Dict[str, Any]:
        """
        MCP Tool 7: Lookup owning team and on-call contact for service_id.
        """
        query = """
        MATCH (t:Team)-[:OWNS]->(s:Service {id: $id})
        RETURN
            t.id AS team_id,
            t.name AS team_name,
            t.contact AS contact,
            t.on_call AS on_call,
            s.id AS service_id,
            s.name AS service_name,
            s.criticality AS criticality
        """
        res = self.client.read_query(query, params={"id": service_id})
        if not res.result_set:
            return {"error": f"No owner team mapped for service '{service_id}'"}
        r = res.result_set[0]
        return {
            "team_id": r[0],
            "team_name": r[1],
            "contact": r[2],
            "on_call": r[3],
            "service_id": r[4],
            "service_name": r[5],
            "criticality": r[6],
            "is_synthetic": True,
        }

    def close(self) -> None:
        self.client.close()
