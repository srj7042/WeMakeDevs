"""
Deterministic Synthetic Graph Seeder for ImpactGraph (FalkorDB Track 01).

Implements the official Track 01 graph data model:
Entities:
  - Incident, Alert, Service, Package, Vulnerability, Deployment, Evidence, Team, Action
Relationships:
  - (Incident)-[:TRIGGERED_BY]->(Alert)  (and [:HAS_ALERT])
  - (Alert)-[:FIRED_ON]->(Service)        (and [:OBSERVED_ON])
  - (ConsumerService)-[:DEPENDS_ON]->(ProviderService)
  - (Service)-[:USES]->(Package)
  - (Package)-[:HAS_VULNERABILITY]->(Vulnerability)
  - (Service)-[:HAS_DEPLOYMENT]->(Deployment) (and [:DEPLOYED_IN])
  - (Service)-[:OWNED_BY]->(Team)             (and (Team)-[:OWNS]->(Service))
  - (Incident)-[:RECOMMENDS]->(Action)
  - (Evidence)-[:SUPPORTS]->(Incident)
  - (Evidence)-[:OBSERVED]->(Service)
  - (Evidence)-[:REFERS_TO]->(Deployment)

Every node and edge is seeded idempotently via MERGE statements and tagged with is_synthetic: true.
"""

from typing import Dict
from client import OracleIncidentsClient


def init_schema(client: OracleIncidentsClient) -> None:
    """Create range indexes on primary identifiers and searchable names."""
    indexes = [
        "CREATE INDEX FOR (i:Incident) ON (i.id)",
        "CREATE INDEX FOR (a:Alert) ON (a.id)",
        "CREATE INDEX FOR (s:Service) ON (s.id)",
        "CREATE INDEX FOR (s:Service) ON (s.name)",
        "CREATE INDEX FOR (p:Package) ON (p.id)",
        "CREATE INDEX FOR (p:Package) ON (p.name)",
        "CREATE INDEX FOR (v:Vulnerability) ON (v.id)",
        "CREATE INDEX FOR (d:Deployment) ON (d.id)",
        "CREATE INDEX FOR (e:Evidence) ON (e.id)",
        "CREATE INDEX FOR (t:Team) ON (t.id)",
        "CREATE INDEX FOR (act:Action) ON (act.id)",
    ]
    for idx_query in indexes:
        try:
            client.write_query(idx_query)
        except Exception as e:
            if "already indexed" not in str(e).lower() and "equivalent" not in str(e).lower():
                raise e


def seed_graph(client: OracleIncidentsClient) -> None:
    """Idempotently load synthetic incident knowledge graph."""

    # 1. Teams
    teams = [
        {"id": "team-checkout", "name": "Checkout Platform Team", "contact": "checkout-oncall@example.internal", "on_call": "Alice Chen"},
        {"id": "team-platform", "name": "Core Platform & Infra", "contact": "platform-oncall@example.internal", "on_call": "Bob Martinez"},
        {"id": "team-payments", "name": "Payments Engineering", "contact": "payments-oncall@example.internal", "on_call": "Carol Zhang"},
        {"id": "team-inventory", "name": "Inventory & Logistics", "contact": "inventory-oncall@example.internal", "on_call": "Dave Wilson"},
        {"id": "team-data", "name": "Data Storage Reliability", "contact": "dba-oncall@example.internal", "on_call": "Eva Schmidt"},
        {"id": "team-growth", "name": "Growth & Engagement", "contact": "growth-dev@example.internal", "on_call": "Frank Miller"},
        {"id": "team-security", "name": "Security & Compliance", "contact": "sec-oncall@example.internal", "on_call": "Grace Hopper"},
    ]
    q_team = """
    MERGE (t:Team {id: $id})
    ON CREATE SET
        t.name = $name,
        t.contact = $contact,
        t.on_call = $on_call,
        t.is_synthetic = true,
        t.created_at = timestamp()
    ON MATCH SET
        t.last_seen = timestamp()
    """
    for t in teams:
        client.write_query(q_team, params=t)

    # 2. Services: id, name, criticality, health
    services = [
        {"id": "web-portal", "name": "Web Customer Portal", "criticality": "Tier 0", "health": "DEGRADED", "team_id": "team-platform"},
        {"id": "api-gateway", "name": "API Gateway", "criticality": "Tier 0", "health": "HEALTHY", "team_id": "team-platform"},
        {"id": "auth-service", "name": "Auth Service", "criticality": "Tier 1", "health": "DEGRADED", "team_id": "team-platform"},
        {"id": "order-service", "name": "Order Service", "criticality": "Tier 1", "health": "DEGRADED", "team_id": "team-checkout"},
        {"id": "payment-service", "name": "Payment Service", "criticality": "Tier 1", "health": "DEGRADED", "team_id": "team-payments"},
        {"id": "payment-vault", "name": "Payment Vault Hardware Service", "criticality": "Tier 3", "health": "HEALTHY", "team_id": "team-payments"},
        {"id": "inventory-service", "name": "Inventory Service", "criticality": "Tier 2", "health": "HEALTHY", "team_id": "team-inventory"},
        {"id": "postgres-orders", "name": "Orders Primary Database", "criticality": "Tier 3", "health": "OUTAGE", "team_id": "team-data"},
        {"id": "redis-auth", "name": "Auth Token Cache", "criticality": "Tier 3", "health": "HEALTHY", "team_id": "team-platform"},
        {"id": "notification-service", "name": "Notification Service", "criticality": "Tier 2", "health": "HEALTHY", "team_id": "team-growth"},
    ]
    q_service = """
    MERGE (s:Service {id: $id})
    ON CREATE SET
        s.name = $name,
        s.criticality = $criticality,
        s.health = $health,
        s.status = $health,
        s.is_synthetic = true,
        s.created_at = timestamp()
    ON MATCH SET
        s.health = $health,
        s.status = $health,
        s.last_seen = timestamp()
    """
    q_team_owns = """
    MATCH (t:Team {id: $team_id}), (s:Service {id: $service_id})
    MERGE (t)-[r1:OWNS]->(s)
    ON CREATE SET r1.is_synthetic = true, r1.created_at = timestamp()
    MERGE (s)-[r2:OWNED_BY]->(t)
    ON CREATE SET r2.is_synthetic = true, r2.created_at = timestamp()
    """
    for s in services:
        client.write_query(q_service, params={"id": s["id"], "name": s["name"], "criticality": s["criticality"], "health": s["health"]})
        client.write_query(q_team_owns, params={"team_id": s["team_id"], "service_id": s["id"]})

    # 3. Dependencies: 3+ levels deep chains
    # web-portal -> api-gateway -> order-service -> payment-service -> payment-vault (4 hops)
    # web-portal -> api-gateway -> order-service -> postgres-orders (3 hops)
    # web-portal -> api-gateway -> auth-service -> redis-auth (3 hops)
    dependencies = [
        {"from": "web-portal", "to": "api-gateway"},
        {"from": "api-gateway", "to": "auth-service"},
        {"from": "api-gateway", "to": "order-service"},
        {"from": "auth-service", "to": "redis-auth"},
        {"from": "order-service", "to": "payment-service"},
        {"from": "order-service", "to": "inventory-service"},
        {"from": "order-service", "to": "postgres-orders"},
        {"from": "payment-service", "to": "payment-vault"},
    ]
    q_dep = """
    MATCH (src:Service {id: $from_id}), (dst:Service {id: $to_id})
    MERGE (src)-[r:DEPENDS_ON]->(dst)
    ON CREATE SET r.is_synthetic = true, r.created_at = timestamp()
    """
    for d in dependencies:
        client.write_query(q_dep, params={"from_id": d["from"], "to_id": d["to"]})

    # 4. Packages & Vulnerabilities
    packages = [
        {"id": "pkg-pg-pool", "name": "pg-connection-pool", "version": "v3.2.1", "risk_status": "VULNERABLE", "service_id": "order-service"},
        {"id": "pkg-jwt-verify", "name": "fast-jwt", "version": "v2.0.4", "risk_status": "VULNERABLE", "service_id": "auth-service"},
        {"id": "pkg-crypto-vault", "name": "crypto-vault", "version": "v1.4.2", "risk_status": "VULNERABLE", "service_id": "payment-service"},
        {"id": "pkg-redis-client", "name": "redis-py-cluster", "version": "v5.0.1", "risk_status": "SECURE", "service_id": "redis-auth"},
    ]
    q_pkg = """
    MATCH (s:Service {id: $service_id})
    MERGE (p:Package {id: $id})
    ON CREATE SET
        p.name = $name,
        p.version = $version,
        p.risk_status = $risk_status,
        p.is_synthetic = true,
        p.created_at = timestamp()
    MERGE (s)-[r:USES]->(p)
    ON CREATE SET r.is_synthetic = true
    """
    for p in packages:
        client.write_query(q_pkg, params=p)

    vulnerabilities = [
        {
            "id": "vuln-cve-2026-4412",
            "cve_id": "CVE-2026-4412",
            "severity": "HIGH",
            "affected_version": "< v3.2.2",
            "description": "Connection leak under unreleased transactions during slow lock acquisition",
            "package_id": "pkg-pg-pool",
        },
        {
            "id": "vuln-cve-2026-3108",
            "cve_id": "CVE-2026-3108",
            "severity": "HIGH",
            "affected_version": "<= v2.0.4",
            "description": "Cryptographic signature validation bypass via algorithm confusion in fast-jwt",
            "package_id": "pkg-jwt-verify",
        },
        {
            "id": "vuln-cve-2026-5511",
            "cve_id": "CVE-2026-5511",
            "severity": "MEDIUM",
            "affected_version": "<= v1.4.2",
            "description": "Unbounded worker thread memory leak in crypto-vault under concurrent batch payload encryption",
            "package_id": "pkg-crypto-vault",
        },
    ]
    q_vuln = """
    MATCH (p:Package {id: $package_id})
    MERGE (v:Vulnerability {id: $id})
    ON CREATE SET
        v.cve_id = $cve_id,
        v.severity = $severity,
        v.affected_version = $affected_version,
        v.description = $description,
        v.is_synthetic = true,
        v.created_at = timestamp()
    MERGE (p)-[r:HAS_VULNERABILITY]->(v)
    ON CREATE SET r.is_synthetic = true
    """
    for v in vulnerabilities:
        client.write_query(q_vuln, params=v)

    # 5. Deployments: both [:DEPLOYED_IN] and [:HAS_DEPLOYMENT]
    deployments = [
        {
            "id": "DEP-401",
            "version": "v2.14.0",
            "status": "failed_migration",
            "commit_sha": "f8a12c9",
            "timestamp": 1792130400000,
            "deployed_at": 1792130400000,
            "service_id": "postgres-orders",
        },
        {
            "id": "DEP-402",
            "version": "v1.8.3",
            "status": "completed",
            "commit_sha": "a4d9821",
            "timestamp": 1792123200000,
            "deployed_at": 1792123200000,
            "service_id": "order-service",
        },
        {
            "id": "DEP-403",
            "version": "v3.1.0-rc1",
            "status": "completed",
            "commit_sha": "c5b2901",
            "timestamp": 1792135000000,
            "deployed_at": 1792135000000,
            "service_id": "payment-service",
        },
        {
            "id": "DEP-404",
            "version": "v2.0.4",
            "status": "completed",
            "commit_sha": "e9f1342",
            "timestamp": 1791700000000,
            "deployed_at": 1791700000000,
            "service_id": "auth-service",
        },
    ]
    q_deploy = """
    MATCH (s:Service {id: $service_id})
    MERGE (d:Deployment {id: $id})
    ON CREATE SET
        d.version = $version,
        d.status = $status,
        d.timestamp = $timestamp,
        d.deployed_at = $deployed_at,
        d.commit_sha = $commit_sha,
        d.is_synthetic = true,
        d.created_at = timestamp()
    ON MATCH SET
        d.status = $status
    MERGE (s)-[r1:DEPLOYED_IN]->(d)
    ON CREATE SET r1.is_synthetic = true
    MERGE (s)-[r2:HAS_DEPLOYMENT]->(d)
    ON CREATE SET r2.is_synthetic = true
    """
    for dep in deployments:
        client.write_query(q_deploy, params=dep)

    # 6. Incidents: 3 distinct incident scenarios
    incidents = [
        {
            "id": "INC-101",
            "title": "Cascading checkout latency spike and order creation failure",
            "description": "Elevated 5xx errors on checkout API. Orders database connection pool exhaustion observed following schema migration deployment.",
            "severity": "SEV-1",
            "status": "ACTIVE",
            "created_at": 1792132000000,
        },
        {
            "id": "INC-102",
            "title": "Authentication token validation bypass & auth service degradation",
            "description": "Surge in 500 errors and token signature validation anomalies on auth service after upstream WAF detected forged JWT algorithm headers.",
            "severity": "SEV-1",
            "status": "ACTIVE",
            "created_at": 1792134100000,
        },
        {
            "id": "INC-103",
            "title": "Intermittent payment processing timeouts & 504 gateway errors",
            "description": "Elevated transaction latency and timeouts on payment-service. Competing hypotheses between recent gRPC deployment DEP-403 and crypto-vault memory leak.",
            "severity": "SEV-2",
            "status": "ACTIVE",
            "created_at": 1792135200000,
        },
    ]
    q_inc = """
    MERGE (i:Incident {id: $id})
    ON CREATE SET
        i.title = $title,
        i.description = $description,
        i.severity = $severity,
        i.status = $status,
        i.created_at = $created_at,
        i.is_synthetic = true
    ON MATCH SET
        i.status = $status
    """
    for inc in incidents:
        client.write_query(q_inc, params=inc)

    # 7. Alerts: both [:HAS_ALERT] / [:TRIGGERED_BY] and [:OBSERVED_ON] / [:FIRED_ON]
    alerts = [
        # INC-101 Alerts
        {
            "id": "ALT-901",
            "signal": "ConnectionPoolExhausted",
            "alert_type": "ConnectionPoolExhausted",
            "source": "prometheus:postgres_pool_utilization",
            "timestamp": 1792131900000,
            "triggered_at": 1792131900000,
            "observed_value": "100%",
            "threshold": "85%",
            "incident_id": "INC-101",
            "service_id": "postgres-orders",
        },
        {
            "id": "ALT-902",
            "signal": "High5xxErrorRate",
            "alert_type": "High5xxErrorRate",
            "source": "datadog:http_5xx_rate",
            "timestamp": 1792131950000,
            "triggered_at": 1792131950000,
            "observed_value": "42.5%",
            "threshold": "1.0%",
            "incident_id": "INC-101",
            "service_id": "order-service",
        },
        {
            "id": "ALT-903",
            "signal": "LatencyP99Spike",
            "alert_type": "LatencyP99Spike",
            "source": "envoy:ingress_latency_p99",
            "timestamp": 1792131980000,
            "triggered_at": 1792131980000,
            "observed_value": "8450ms",
            "threshold": "500ms",
            "incident_id": "INC-101",
            "service_id": "api-gateway",
        },
        # INC-102 Alerts
        {
            "id": "ALT-910",
            "signal": "HighAuth500Rate",
            "alert_type": "HighAuth500Rate",
            "source": "datadog:auth_500_rate",
            "timestamp": 1792134000000,
            "triggered_at": 1792134000000,
            "observed_value": "38.2%",
            "threshold": "0.5%",
            "incident_id": "INC-102",
            "service_id": "auth-service",
        },
        {
            "id": "ALT-911",
            "signal": "TokenVerificationFailureSpike",
            "alert_type": "TokenVerificationFailureSpike",
            "source": "envoy:jwt_verification_failed",
            "timestamp": 1792134050000,
            "triggered_at": 1792134050000,
            "observed_value": "1420 req/min",
            "threshold": "5 req/min",
            "incident_id": "INC-102",
            "service_id": "auth-service",
        },
        # INC-103 Alerts
        {
            "id": "ALT-920",
            "signal": "PaymentGatewayTimeout",
            "alert_type": "PaymentGatewayTimeout",
            "source": "datadog:payment_p99_latency",
            "timestamp": 1792135100000,
            "triggered_at": 1792135100000,
            "observed_value": "3200ms",
            "threshold": "300ms",
            "incident_id": "INC-103",
            "service_id": "payment-service",
        },
        {
            "id": "ALT-921",
            "signal": "UpstreamGateway504Rate",
            "alert_type": "UpstreamGateway504Rate",
            "source": "envoy:upstream_504_rate",
            "timestamp": 1792135150000,
            "triggered_at": 1792135150000,
            "observed_value": "14.8%",
            "threshold": "0.2%",
            "incident_id": "INC-103",
            "service_id": "order-service",
        },
    ]
    q_alert = """
    MATCH (i:Incident {id: $incident_id}), (s:Service {id: $service_id})
    MERGE (a:Alert {id: $id})
    ON CREATE SET
        a.signal = $signal,
        a.alert_type = $alert_type,
        a.source = $source,
        a.timestamp = $timestamp,
        a.triggered_at = $triggered_at,
        a.observed_value = $observed_value,
        a.threshold = $threshold,
        a.is_synthetic = true,
        a.created_at = timestamp()
    MERGE (i)-[r1:HAS_ALERT]->(a)
    ON CREATE SET r1.is_synthetic = true
    MERGE (i)-[r2:TRIGGERED_BY]->(a)
    ON CREATE SET r2.is_synthetic = true
    MERGE (a)-[r3:OBSERVED_ON]->(s)
    ON CREATE SET r3.is_synthetic = true
    MERGE (a)-[r4:FIRED_ON]->(s)
    ON CREATE SET r4.is_synthetic = true
    """
    for alt in alerts:
        client.write_query(q_alert, params=alt)

    # 8. Evidence: Supporting, Contradictory, and Unknown/Missing Evidence
    evidences = [
        # INC-101 Evidence
        {
            "id": "EVD-001",
            "kind": "LOG_LOCK_TIMEOUT",
            "source_type": "LOG_LOCK_TIMEOUT",
            "source_ref": "log://postgres-orders/var/log/postgresql.log#L1042",
            "observed_at": 1792130520000,
            "timestamp": 1792130520000,
            "observation": "Exclusive table lock acquired by ALTER TABLE orders_add_index during DEP-401 migration timed out after 300s, leaving pending client connections in wait state.",
            "incident_id": "INC-101",
            "service_id": "postgres-orders",
            "deployment_id": "DEP-401",
        },
        {
            "id": "EVD-002",
            "kind": "APM_METRIC",
            "source_type": "APM_METRIC",
            "source_ref": "apm://order-service/metrics/hikaricp.active_connections",
            "observed_at": 1792131880000,
            "timestamp": 1792131880000,
            "observation": "HikariCP active connections reached maximum limit (100/100). Thread dump reveals 86 worker threads blocked on connection acquisition.",
            "incident_id": "INC-101",
            "service_id": "order-service",
            "deployment_id": "DEP-401",
        },
        {
            "id": "EVD-003",
            "kind": "NETWORK_HEALTH",
            "source_type": "NETWORK_HEALTH",
            "source_ref": "netcheck://payment-service/ingress/packet_loss",
            "observed_at": 1792132020000,
            "timestamp": 1792132020000,
            "observation": "Zero packet loss and 2.1ms round-trip latency verified on payment-service ingress. Payment gateway ruled out as cause of checkout degradation.",
            "incident_id": "INC-101",
            "service_id": "payment-service",
            "deployment_id": "DEP-402",
        },
        # INC-102 Evidence (Vulnerable Package Confirmed)
        {
            "id": "EVD-101",
            "kind": "SECURITY_LOG",
            "source_type": "SECURITY_LOG",
            "source_ref": "waf://auth-service/access_log#L4821",
            "observed_at": 1792134020000,
            "timestamp": 1792134020000,
            "observation": "WAF captured 1,420 token verification bypass attempts exploiting CVE-2026-3108 with forged null/none algorithm headers in JWT requests.",
            "incident_id": "INC-102",
            "service_id": "auth-service",
            "deployment_id": None,
        },
        {
            "id": "EVD-102",
            "kind": "PACKAGE_AUDIT",
            "source_type": "PACKAGE_AUDIT",
            "source_ref": "trivy://auth-service/sbom/packages.json",
            "observed_at": 1792134040000,
            "timestamp": 1792134040000,
            "observation": "Static container inspection confirmed fast-jwt v2.0.4 dependency contains known critical flaw CVE-2026-3108 allowing unsigned JWT forgery.",
            "incident_id": "INC-102",
            "service_id": "auth-service",
            "deployment_id": None,
        },
        {
            "id": "EVD-103",
            "kind": "DEPLOY_AUDIT",
            "source_type": "DEPLOY_AUDIT",
            "source_ref": "ci://auth-service/deployments/DEP-404",
            "observed_at": 1792134060000,
            "timestamp": 1792134060000,
            "observation": "DEP-404 was deployed 120 hours ago with zero subsequent configuration changes. Ruling out recent deployment regression as root cause.",
            "incident_id": "INC-102",
            "service_id": "auth-service",
            "deployment_id": "DEP-404",
        },
        # INC-103 Evidence (Ambiguous Competing Hypotheses + Missing Telemetry)
        {
            "id": "EVD-201",
            "kind": "METRIC_ANOMALY",
            "source_type": "METRIC_ANOMALY",
            "source_ref": "datadog://payment-service/latency.p99",
            "observed_at": 1792135110000,
            "timestamp": 1792135110000,
            "observation": "Payment p99 processing time increased 8x immediately following deployment DEP-403 at 1792135000000.",
            "incident_id": "INC-103",
            "service_id": "payment-service",
            "deployment_id": "DEP-403",
        },
        {
            "id": "EVD-202",
            "kind": "MEMORY_LOG",
            "source_type": "MEMORY_LOG",
            "source_ref": "jvm://payment-service/gc.log#L882",
            "observed_at": 1792135120000,
            "timestamp": 1792135120000,
            "observation": "Off-heap native memory consumption escalated to 94% following batch encryption calls in crypto-vault package.",
            "incident_id": "INC-103",
            "service_id": "payment-service",
            "deployment_id": None,
        },
        {
            "id": "EVD-203",
            "kind": "TELEMETRY_GAP",
            "source_type": "TELEMETRY_GAP",
            "source_ref": "monitoring://payment-service/profiler",
            "observed_at": 1792135140000,
            "timestamp": 1792135140000,
            "observation": "Heap dump profile collection failed during incident peak due to disk quota exhaustion. Memory leak vs gRPC regression remains UNKNOWN.",
            "incident_id": "INC-103",
            "service_id": "payment-service",
            "deployment_id": None,
        },
    ]

    q_evidence_with_dep = """
    MATCH (i:Incident {id: $incident_id}), (s:Service {id: $service_id}), (d:Deployment {id: $deployment_id})
    MERGE (e:Evidence {id: $id})
    ON CREATE SET
        e.kind = $kind,
        e.source_type = $source_type,
        e.source_ref = $source_ref,
        e.observed_at = $observed_at,
        e.timestamp = $timestamp,
        e.observation = $observation,
        e.is_synthetic = true,
        e.created_at = timestamp()
    MERGE (e)-[r1:SUPPORTS]->(i)
    ON CREATE SET r1.is_synthetic = true
    MERGE (e)-[r2:OBSERVED]->(s)
    ON CREATE SET r2.is_synthetic = true
    MERGE (e)-[r3:REFERS_TO]->(d)
    ON CREATE SET r3.is_synthetic = true
    """

    q_evidence_no_dep = """
    MATCH (i:Incident {id: $incident_id}), (s:Service {id: $service_id})
    MERGE (e:Evidence {id: $id})
    ON CREATE SET
        e.kind = $kind,
        e.source_type = $source_type,
        e.source_ref = $source_ref,
        e.observed_at = $observed_at,
        e.timestamp = $timestamp,
        e.observation = $observation,
        e.is_synthetic = true,
        e.created_at = timestamp()
    MERGE (e)-[r1:SUPPORTS]->(i)
    ON CREATE SET r1.is_synthetic = true
    MERGE (e)-[r2:OBSERVED]->(s)
    ON CREATE SET r2.is_synthetic = true
    """

    for ev in evidences:
        if ev.get("deployment_id"):
            client.write_query(q_evidence_with_dep, params=ev)
        else:
            client.write_query(q_evidence_no_dep, params={
                "id": ev["id"],
                "kind": ev["kind"],
                "source_type": ev["source_type"],
                "source_ref": ev["source_ref"],
                "observed_at": ev["observed_at"],
                "timestamp": ev["timestamp"],
                "observation": ev["observation"],
                "incident_id": ev["incident_id"],
                "service_id": ev["service_id"],
            })

    # 9. Actions: (Incident)-[:RECOMMENDS]->(Action)
    actions = [
        {
            "id": "ACT-101",
            "incident_id": "INC-101",
            "action_type": "SIMULATE_ROLLBACK",
            "target": "postgres-orders",
            "description": "Revert migration DEP-401 to release table locks and clear connection backlog",
            "risk_level": "MEDIUM",
            "status": "PROPOSED",
        },
        {
            "id": "ACT-102",
            "incident_id": "INC-102",
            "action_type": "SIMULATE_SERVICE_ISOLATION",
            "target": "auth-service",
            "description": "Isolate vulnerable auth token endpoint and deploy fast-jwt patch",
            "risk_level": "HIGH",
            "status": "PROPOSED",
        },
        {
            "id": "ACT-103",
            "incident_id": "INC-103",
            "action_type": "SIMULATE_ROLLBACK",
            "target": "payment-service",
            "description": "Simulate rollback of payment-service DEP-403 to v3.0.9 while memory dump is gathered",
            "risk_level": "LOW",
            "status": "PROPOSED",
        },
    ]
    q_action = """
    MATCH (i:Incident {id: $incident_id})
    MERGE (act:Action {id: $id})
    ON CREATE SET
        act.action_type = $action_type,
        act.target = $target,
        act.description = $description,
        act.risk_level = $risk_level,
        act.status = $status,
        act.is_synthetic = true,
        act.created_at = timestamp()
    MERGE (i)-[r:RECOMMENDS]->(act)
    ON CREATE SET r.is_synthetic = true
    """
    for act in actions:
        client.write_query(q_action, params=act)


def get_graph_counts(client: OracleIncidentsClient) -> Dict[str, int]:
    """Retrieve total count of nodes and relationships in the graph."""
    q_n = "MATCH (n) RETURN count(n)"
    q_e = "MATCH ()-[r]->() RETURN count(r)"
    nodes = client.read_query(q_n).result_set[0][0]
    edges = client.read_query(q_e).result_set[0][0]
    return {"nodes": nodes, "edges": edges}


def run() -> None:
    client = OracleIncidentsClient()
    print("--- Seeding ImpactGraph Track 01 Graph (Pass 1) ---")
    init_schema(client)
    seed_graph(client)
    stats1 = get_graph_counts(client)
    print(f"Pass 1: {stats1['nodes']} nodes, {stats1['edges']} relationships.")

    print("\n--- Testing Idempotency (Pass 2) ---")
    init_schema(client)
    seed_graph(client)
    stats2 = get_graph_counts(client)
    print(f"Pass 2: {stats2['nodes']} nodes, {stats2['edges']} relationships.")

    assert stats1 == stats2, f"Idempotency violation! {stats1} != {stats2}"
    print("\n✓ Idempotent Seeding Verified: Repeatable execution confirmed zero duplication.")
    client.close()


if __name__ == "__main__":
    run()
