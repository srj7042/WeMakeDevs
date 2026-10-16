"""
Comprehensive Automated Test Suite for ORACLE.

Validates:
A. Environment & database connectivity.
B. Graph data model & query paths.
C. MCP domain tools.
D. Orchestrator findings & evidence grounding.
E. Safety policy:
   - Unapproved proposals cannot execute.
   - Agent self-approval is blocked.
   - Unknown action types are rejected.
   - Double-execution is prevented.
   - Audit trail contains state transitions and simulated outcomes.
F. FastAPI endpoint contracts & HTTP status codes.
"""

import pytest
from fastapi.testclient import TestClient

from main import app
from graph_service import GraphService
from orchestrator import InvestigationOrchestrator
from action_policy import ActionPolicyManager


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def graph_svc():
    svc = GraphService()
    yield svc
    svc.close()


@pytest.fixture
def policy_mgr():
    mgr = ActionPolicyManager(storage_file="test_audit_trail.json")
    mgr.reset()
    yield mgr
    mgr.reset()


# --- Test Suite A: Database & Health ---

def test_health_check(client):
    """Verify GET /health reports FalkorDB connection status."""
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "HEALTHY"
    assert data["database"] == "FalkorDB"
    assert data["database_connected"] is True
    assert data["is_synthetic"] is True


# --- Test Suite B: Graph Data Model & Traversal ---

def test_list_incidents(client):
    """Verify GET /incidents returns seeded incidents."""
    res = client.get("/incidents")
    assert res.status_code == 200
    data = res.json()
    assert len(data) >= 1
    assert any(i["id"] == "INC-101" for i in data)


def test_get_incident_context(graph_svc):
    """Verify Tool 1: get_incident_context returns incident and connected alerts."""
    ctx = graph_svc.get_incident_context("INC-101")
    assert ctx["incident_id"] == "INC-101"
    assert ctx["severity"] == "SEV-1"
    assert ctx["total_alerts"] >= 2
    # Check alert types
    alert_types = [a["alert_type"] for a in ctx["alerts"]]
    assert "ConnectionPoolExhausted" in alert_types
    assert "High5xxErrorRate" in alert_types


def test_trace_candidate_causes(graph_svc):
    """Verify Tool 2: trace_candidate_causes discovers deployments and vulnerabilities."""
    causes = graph_svc.trace_candidate_causes("INC-101")
    assert len(causes) >= 2
    # Primary suspect should be DEP-401 failed migration
    top = causes[0]
    assert top["entity_id"] == "DEP-401"
    assert top["is_failure"] is True
    assert top["confidence_score"] >= 0.90


def test_get_blast_radius(graph_svc):
    """Verify Tool 3: get_blast_radius traverses downstream consumer dependencies."""
    radius = graph_svc.get_blast_radius("postgres-orders", max_depth=4)
    assert radius["root_service_id"] == "postgres-orders"
    assert radius["total_impacted_services"] >= 2
    assert radius["tier_0_compromised"] is True  # api-gateway is Tier 0
    service_ids = [s["service_id"] for s in radius["impacted_services"]]
    assert "order-service" in service_ids
    assert "api-gateway" in service_ids


def test_get_evidence_chain(graph_svc):
    """Verify Tool 4: get_evidence_chain returns supporting and contradictory evidence."""
    evidence = graph_svc.get_evidence_chain("INC-101")
    assert len(evidence) >= 3
    ev_ids = [e["evidence_id"] for e in evidence]
    assert "EVD-001" in ev_ids
    assert "EVD-002" in ev_ids
    assert "EVD-003" in ev_ids
    # Check stance separation
    stances = {e["evidence_id"]: e["stance"] for e in evidence}
    assert stances["EVD-001"] == "SUPPORTING"
    assert stances["EVD-003"] == "CONTRADICTORY"


def test_service_owner_and_deployments(graph_svc):
    """Verify Tools 5 & 7: deployment history and team ownership."""
    deps = graph_svc.get_deployment_history("postgres-orders")
    assert len(deps) >= 1
    assert deps[0]["deployment_id"] == "DEP-401"

    owner = graph_svc.get_service_owner("order-service")
    assert owner["team_id"] == "team-checkout"
    assert owner["on_call"] == "Alice Chen"


def test_missing_incident_handling(client):
    """Verify 404 behavior for unknown incident IDs."""
    res = client.get("/incidents/INC-NONEXISTENT")
    assert res.status_code == 404


# --- Test Suite C: Orchestrator & Evidence Grounding ---

def test_investigation_orchestrator():
    """Verify orchestrator synthesizes findings into OBSERVED/INFERRED/UNKNOWN."""
    orch = InvestigationOrchestrator()
    report = orch.investigate("INC-101")
    assert report.incident_id == "INC-101"
    assert report.mode == "DETERMINISTIC"

    # Check finding categorization
    categories = {f.category for f in report.findings}
    assert "OBSERVED" in categories
    assert "INFERRED" in categories
    assert "UNKNOWN" in categories

    # Check candidate hypotheses
    hyp_ids = [h.hypothesis_id for h in report.candidate_hypotheses]
    assert "HYP-1" in hyp_ids  # Schema Lock
    assert "HYP-2" in hyp_ids  # Ruled out network issue

    # Proposed action must be created in PENDING_APPROVAL state
    assert report.proposed_action is not None
    assert report.proposed_action.status == "PENDING_APPROVAL"
    assert report.proposed_action.action_type == "SIMULATE_ROLLBACK"


# --- Test Suite D: Action Policy, Safety Constraints & Audit ---

def test_action_policy_unapproved_proposal(policy_mgr):
    """Safety check: Creating proposal does NOT execute it."""
    prop = policy_mgr.create_proposal(
        incident_id="INC-101",
        action_type="SIMULATE_ROLLBACK",
        target="DEP-401",
        rationale="Test rollback",
        evidence_refs=["EVD-001"],
    )
    assert prop.status == "PENDING_APPROVAL"
    assert prop.approved_by is None
    assert prop.simulated_outcome is None


def test_action_policy_rejects_agent_self_approval(policy_mgr):
    """Safety check: Agent self-approval is strictly forbidden."""
    prop = policy_mgr.create_proposal(
        incident_id="INC-101",
        action_type="SIMULATE_ROLLBACK",
        target="DEP-401",
        rationale="Test rollback",
        evidence_refs=["EVD-001"],
    )
    with pytest.raises(ValueError, match="Agent self-approval is forbidden"):
        policy_mgr.approve_and_simulate(prop.id, actor="agent", approved=True)

    with pytest.raises(ValueError, match="Agent self-approval is forbidden"):
        policy_mgr.approve_and_simulate(prop.id, actor="AI", approved=True)


def test_action_policy_rejects_unknown_action_type(policy_mgr):
    """Safety check: Reject actions not on allowlist."""
    with pytest.raises(ValueError, match="not in allowlist"):
        policy_mgr.create_proposal(
            incident_id="INC-101",
            action_type="DROP_DATABASE",  # Dangerous / unallowed action
            target="postgres-orders",
            rationale="Malicious or unallowed action",
            evidence_refs=[],
        )


def test_action_policy_human_approval_and_simulation(policy_mgr):
    """Safety check: Human approval executes simulation and records audit entry."""
    prop = policy_mgr.create_proposal(
        incident_id="INC-101",
        action_type="SIMULATE_ROLLBACK",
        target="DEP-401",
        rationale="Rollback table locks",
        evidence_refs=["EVD-001", "EVD-002"],
    )

    executed = policy_mgr.approve_and_simulate(prop.id, actor="Sarah OnCall", approved=True)
    assert executed.status == "EXECUTED"
    assert executed.approved_by == "Sarah OnCall"
    assert executed.simulated_outcome["success"] is True
    assert executed.simulated_outcome["simulation_type"] == "ROLLBACK_SIMULATION"

    # Verify audit trail
    audit = policy_mgr.get_audit_trail("INC-101")
    assert len(audit) == 1
    entry = audit[0]
    assert entry.proposal_id == prop.id
    assert entry.actor == "Sarah OnCall"
    assert entry.approval_status == "EXECUTED"
    assert "EVD-001" in entry.evidence_refs


def test_action_policy_prevents_double_execution(policy_mgr):
    """Safety check: Consumed proposals cannot be re-executed."""
    prop = policy_mgr.create_proposal(
        incident_id="INC-101",
        action_type="ACKNOWLEDGE_INCIDENT",
        target="INC-101",
        rationale="Acknowledge",
        evidence_refs=[],
    )
    policy_mgr.approve_and_simulate(prop.id, actor="Alice Chen", approved=True)

    # Attempt second approval on same proposal
    with pytest.raises(ValueError, match="cannot be processed"):
        policy_mgr.approve_and_simulate(prop.id, actor="Bob Martinez", approved=True)


# --- Test Suite E: End-to-End FastAPI Endpoints ---

def test_api_investigate_endpoint(client):
    """Verify POST /incidents/{id}/investigate produces full report."""
    res = client.post("/incidents/INC-101/investigate")
    assert res.status_code == 200
    report = res.json()
    assert report["incident_id"] == "INC-101"
    assert "findings" in report
    assert "candidate_hypotheses" in report
    assert "blast_radius" in report
    assert report["proposed_action"]["status"] == "PENDING_APPROVAL"


def test_api_evidence_endpoint(client):
    """Verify GET /incidents/{id}/evidence returns evidence records."""
    res = client.get("/incidents/INC-101/evidence")
    assert res.status_code == 200
    evidence = res.json()
    assert len(evidence) >= 3


def test_api_propose_and_approve_flow(client):
    """Verify end-to-end proposal, approval, simulation, and audit API flow."""
    # 1. Propose action
    prop_res = client.post("/actions/propose", json={
        "incident_id": "INC-101",
        "action_type": "SIMULATE_ESCALATION",
        "target": "team-checkout",
        "rationale": "Escalate to checkout team",
        "evidence_refs": ["EVD-001"],
        "parameters": {"on_call": "Alice Chen"}
    })
    assert prop_res.status_code == 201
    proposal = prop_res.json()
    p_id = proposal["id"]
    assert proposal["status"] == "PENDING_APPROVAL"

    # 2. Reject agent self-approval via API
    agent_approve = client.post(f"/actions/{p_id}/approve", json={
        "actor": "agent",
        "approved": True
    })
    assert agent_approve.status_code == 400
    assert "Agent self-approval is forbidden" in agent_approve.json()["detail"]

    # 3. Approve by human operator
    human_approve = client.post(f"/actions/{p_id}/approve", json={
        "actor": "Lead SRE John Doe",
        "approved": True
    })
    assert human_approve.status_code == 200
    executed = human_approve.json()
    assert executed["status"] == "EXECUTED"
    assert executed["simulated_outcome"]["success"] is True

    # 4. Check audit log
    audit_res = client.get("/audit?incident_id=INC-101")
    assert audit_res.status_code == 200
    audit = audit_res.json()
    assert len(audit) >= 1
    assert any(a["proposal_id"] == p_id for a in audit)


# --- Test Suite F: Acceptance Criteria Direct Verification ---

def test_disconnected_service_excluded(graph_svc):
    """Acceptance criterion 2: Disconnected service (notification-service) is excluded."""
    ctx = graph_svc.get_incident_context("INC-101")
    alert_services = [a["service"]["id"] for a in ctx["alerts"]]
    assert "notification-service" not in alert_services

    blast = graph_svc.get_blast_radius("postgres-orders", max_depth=4)
    impacted_ids = [s["service_id"] for s in blast["impacted_services"]]
    assert "notification-service" not in impacted_ids


def test_competing_hypotheses_and_uncertainty_reporting():
    """Acceptance criteria 3 & 4: Competing hypotheses and explicit uncertainty reporting."""
    orch = InvestigationOrchestrator()
    report = orch.investigate("INC-101")

    # Competing hypotheses check
    hypo_map = {h.hypothesis_id: h for h in report.candidate_hypotheses}
    assert "HYP-1" in hypo_map  # Deployment root cause
    assert "HYP-2" in hypo_map  # Network outage (ruled out)
    assert "HYP-3" in hypo_map  # Vulnerability (competing)

    # Differentiated by evidence
    assert "EVD-001" in hypo_map["HYP-1"].supporting_evidence
    assert "EVD-003" in hypo_map["HYP-2"].contradicting_evidence
    assert hypo_map["HYP-2"].likelihood == "RULED_OUT"

    # Uncertainty / UNKNOWN findings reported rather than fabricated
    unknown_findings = [f for f in report.findings if f.category == "UNKNOWN"]
    assert len(unknown_findings) >= 2
    assert any("disk i/o" in f.title.lower() or "disk" in f.description.lower() for f in unknown_findings)


def test_supported_simulation_actions(policy_mgr):
    """Step 10 verification: simulate_service_isolation and create_remediation_ticket."""
    # 1. simulate_service_isolation
    prop_iso = policy_mgr.create_proposal(
        incident_id="INC-101",
        action_type="simulate_service_isolation",
        target="order-service",
        rationale="Isolate degraded order service",
        evidence_refs=["ALT-902"],
    )
    res_iso = policy_mgr.approve_and_simulate(prop_iso.id, actor="Ops Engineer Jane", approved=True)
    assert res_iso.status == "EXECUTED"
    assert res_iso.simulated_outcome["simulation_type"] == "SERVICE_ISOLATION_SIMULATION"

    # 2. create_remediation_ticket
    prop_tick = policy_mgr.create_proposal(
        incident_id="INC-101",
        action_type="create_remediation_ticket",
        target="postgres-orders",
        rationale="Fix schema migration locks",
        evidence_refs=["EVD-001"],
    )
    res_tick = policy_mgr.approve_and_simulate(prop_tick.id, actor="Ops Engineer Jane", approved=True)
    assert res_tick.status == "EXECUTED"
    assert res_tick.simulated_outcome["simulation_type"] == "REMEDIATION_TICKET_SIMULATION"
    assert "ticket_id" in res_tick.simulated_outcome


def test_seed_idempotency_assertion():
    """Acceptance criterion 8: Seed reruns do not duplicate graph nodes or edges."""
    from seed import get_graph_counts, seed_graph
    from client import OracleIncidentsClient
    c = OracleIncidentsClient()
    before = get_graph_counts(c)
    seed_graph(c)
    after = get_graph_counts(c)
    assert before == after
    c.close()


def test_phase2_multi_incident_dataset(graph_svc):
    """Phase 2: Verify 3 distinct incident scenarios are seeded and queryable."""
    incidents = graph_svc.list_incidents()
    inc_ids = {i["id"] for i in incidents}
    assert "INC-101" in inc_ids
    assert "INC-102" in inc_ids
    assert "INC-103" in inc_ids

    # INC-102: Vulnerable package root cause
    ctx_102 = graph_svc.get_incident_context("INC-102")
    assert ctx_102["incident_id"] == "INC-102"
    assert len(ctx_102["alerts"]) >= 2
    causes_102 = graph_svc.trace_candidate_causes("INC-102")
    vuln_causes_102 = [c for c in causes_102 if c["cause_type"] == "VULNERABILITY"]
    assert any(c["entity_id"] == "CVE-2026-3108" and c["service_id"] == "auth-service" for c in vuln_causes_102)

    # INC-103: Ambiguous incident with competing deployment and vulnerability
    ctx_103 = graph_svc.get_incident_context("INC-103")
    assert ctx_103["incident_id"] == "INC-103"
    causes_103 = graph_svc.trace_candidate_causes("INC-103")
    has_dep_103 = any(c["cause_type"] == "DEPLOYMENT" and c["entity_id"] == "DEP-403" for c in causes_103)
    has_vuln_103 = any(c["cause_type"] == "VULNERABILITY" and c["entity_id"] == "CVE-2026-5511" for c in causes_103)
    assert has_dep_103 and has_vuln_103

    # Evidence chain for INC-103 contains UNKNOWN telemetry gap
    ev_103 = graph_svc.get_evidence_chain("INC-103")
    assert any(e["kind"] == "TELEMETRY_GAP" or "UNKNOWN" in e["observation"] for e in ev_103)


def test_phase2_deep_dependency_chain(graph_svc):
    """Phase 2: Verify 3+ levels dependency chain traversal in reverse blast radius."""
    blast = graph_svc.get_blast_radius("payment-vault", max_depth=5)
    assert blast["root_service_id"] == "payment-vault"
    # Expected upstream chain: payment-service (1) <- order-service (2) <- api-gateway (3) <- web-portal (4)
    impacted_services = {s["service_id"]: s["hop_distance"] for s in blast["impacted_services"]}
    assert "payment-service" in impacted_services
    assert "order-service" in impacted_services
    assert "api-gateway" in impacted_services
    assert "web-portal" in impacted_services
    assert impacted_services["web-portal"] >= 4


def test_phase2_required_schema_and_indexes():
    """Phase 2: Verify required indexes and Track 01 schema relationships exist."""
    from client import OracleIncidentsClient
    c = OracleIncidentsClient()

    # Required indexes from Track 01 spec: Incident.id, Service.name, Deployment.id, Package.name
    res_inc = c.read_query("MATCH (i:Incident {id: 'INC-101'}) RETURN i.id").result_set
    assert len(res_inc) == 1 and res_inc[0][0] == "INC-101"

    res_svc = c.read_query("MATCH (s:Service {name: 'Order Service'}) RETURN s.id").result_set
    assert len(res_svc) == 1 and res_svc[0][0] == "order-service"

    res_dep = c.read_query("MATCH (d:Deployment {id: 'DEP-401'}) RETURN d.id").result_set
    assert len(res_dep) == 1 and res_dep[0][0] == "DEP-401"

    res_pkg = c.read_query("MATCH (p:Package {name: 'fast-jwt'}) RETURN p.id").result_set
    assert len(res_pkg) == 1 and res_pkg[0][0] == "pkg-jwt-verify"

    # Track 01 Relationships
    rel_checks = [
        "MATCH (i:Incident)-[:TRIGGERED_BY]->(a:Alert) RETURN count(*)",
        "MATCH (a:Alert)-[:FIRED_ON]->(s:Service) RETURN count(*)",
        "MATCH (s1:Service)-[:DEPENDS_ON]->(s2:Service) RETURN count(*)",
        "MATCH (s:Service)-[:USES]->(p:Package) RETURN count(*)",
        "MATCH (s:Service)-[:HAS_DEPLOYMENT]->(d:Deployment) RETURN count(*)",
        "MATCH (s:Service)-[:OWNED_BY]->(t:Team) RETURN count(*)",
        "MATCH (i:Incident)-[:RECOMMENDS]->(act:Action) RETURN count(*)",
    ]
    for rel_q in rel_checks:
        res = c.read_query(rel_q).result_set
        assert res[0][0] > 0, f"Relationship check failed: {rel_q}"

    c.close()

