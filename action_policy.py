"""
Action Proposal and Approval Policy for ORACLE.

Enforces human-in-the-loop safety constraints:
1. Fixed allowlist of simulated actions:
   - SIMULATE_ROLLBACK
   - SIMULATE_ESCALATION
   - ACKNOWLEDGE_INCIDENT
2. Agent creates proposals in PENDING_APPROVAL state; creating a proposal NEVER executes it.
3. Unapproved proposals CANNOT execute.
4. Agent self-approval is strictly forbidden (requires explicit human actor).
5. Proposals cannot be re-executed or modified once consumed (prevents duplicate execution).
6. Simulated actions never touch real infrastructure.
7. Complete audit trail recording proposal, approval, simulation outcome, and evidence refs.
"""

import json
import os
import time
import uuid
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

ALLOWED_ACTION_TYPES = {
    "SIMULATE_ROLLBACK",
    "SIMULATE_ESCALATION",
    "ACKNOWLEDGE_INCIDENT",
    "SIMULATE_SERVICE_ISOLATION",
    "CREATE_REMEDIATION_TICKET",
}

AUDIT_LOG_FILE = "audit_trail.json"


class ActionProposal(BaseModel):
    id: str
    incident_id: str
    action_type: str
    target: str
    rationale: str
    evidence_refs: List[str] = Field(default_factory=list)
    parameters: Dict[str, Any] = Field(default_factory=dict)
    status: str = "PENDING_APPROVAL"  # PENDING_APPROVAL, APPROVED, REJECTED, EXECUTED
    created_at: float
    approved_by: Optional[str] = None
    approved_at: Optional[float] = None
    simulated_outcome: Optional[Dict[str, Any]] = None


class AuditEntry(BaseModel):
    audit_id: str
    proposal_id: str
    incident_id: str
    action_type: str
    target: str
    actor: str
    approval_status: str
    evidence_refs: List[str]
    simulated_outcome: Optional[Dict[str, Any]]
    timestamp: float


class ActionPolicyManager:
    """Manages lifecycle of action proposals, approvals, simulated executions, and audit logs."""

    def __init__(self, storage_file: str = AUDIT_LOG_FILE):
        self.storage_file = storage_file
        self.proposals: Dict[str, ActionProposal] = {}
        self.audit_trail: List[AuditEntry] = []
        self._load_audit_trail()

    def _load_audit_trail(self) -> None:
        """Load persisted audit entries if available."""
        if os.path.exists(self.storage_file):
            try:
                with open(self.storage_file, "r") as f:
                    data = json.load(f)
                    for item in data.get("audit_trail", []):
                        self.audit_trail.append(AuditEntry(**item))
                    for p_id, p_data in data.get("proposals", {}).items():
                        self.proposals[p_id] = ActionProposal(**p_data)
            except Exception:
                pass

    def _persist(self) -> None:
        """Persist state to lightweight JSON file."""
        try:
            with open(self.storage_file, "w") as f:
                json.dump({
                    "audit_trail": [entry.model_dump() for entry in self.audit_trail],
                    "proposals": {k: v.model_dump() for k, v in self.proposals.items()},
                }, f, indent=2)
        except Exception:
            pass

    def create_proposal(
        self,
        incident_id: str,
        action_type: str,
        target: str,
        rationale: str,
        evidence_refs: List[str],
        parameters: Optional[Dict[str, Any]] = None,
    ) -> ActionProposal:
        """
        Create a new action proposal.
        The action is strictly created in PENDING_APPROVAL state and will NOT execute.
        """
        normalized_type = action_type.strip().upper()
        if normalized_type not in ALLOWED_ACTION_TYPES:
            raise ValueError(f"Action '{action_type}' rejected: not in allowlist {list(ALLOWED_ACTION_TYPES)}")

        proposal_id = f"ACT-PROP-{uuid.uuid4().hex[:8].upper()}"
        proposal = ActionProposal(
            id=proposal_id,
            incident_id=incident_id,
            action_type=normalized_type,
            target=target,
            rationale=rationale,
            evidence_refs=evidence_refs,
            parameters=parameters or {},
            status="PENDING_APPROVAL",
            created_at=time.time(),
        )
        self.proposals[proposal_id] = proposal
        self._persist()
        return proposal

    def approve_and_simulate(
        self,
        proposal_id: str,
        actor: str,
        approved: bool = True,
    ) -> ActionProposal:
        """
        Approve (or reject) and execute a simulated response.
        Enforces human approval, checks proposal validity, prevents double-execution.
        """
        if proposal_id not in self.proposals:
            raise ValueError(f"Proposal '{proposal_id}' not found.")

        proposal = self.proposals[proposal_id]

        if proposal.status != "PENDING_APPROVAL":
            raise ValueError(
                f"Proposal '{proposal_id}' cannot be processed: current status is '{proposal.status}'. "
                "Double execution or re-approval of consumed proposals is strictly prohibited."
            )

        # Enforce human-in-the-loop: Agent cannot approve its own proposal
        if not actor or actor.strip().lower() in ["agent", "oracle_agent", "ai", "system", "llm"]:
            raise ValueError("Agent self-approval is forbidden. An explicit human actor must approve the action.")

        now = time.time()
        proposal.approved_by = actor
        proposal.approved_at = now

        if not approved:
            proposal.status = "REJECTED"
            proposal.simulated_outcome = {
                "success": False,
                "reason": "Rejected by human reviewer",
                "timestamp": now,
            }
        else:
            proposal.status = "EXECUTED"
            proposal.simulated_outcome = self._execute_simulation(proposal)

        # Record immutable audit entry
        audit_entry = AuditEntry(
            audit_id=f"AUDIT-{uuid.uuid4().hex[:8].upper()}",
            proposal_id=proposal.id,
            incident_id=proposal.incident_id,
            action_type=proposal.action_type,
            target=proposal.target,
            actor=actor,
            approval_status=proposal.status,
            evidence_refs=proposal.evidence_refs,
            simulated_outcome=proposal.simulated_outcome,
            timestamp=now,
        )
        self.audit_trail.append(audit_entry)
        self._persist()
        return proposal

    def _execute_simulation(self, proposal: ActionProposal) -> Dict[str, Any]:
        """
        Simulate the outcome of an approved action in a safe sandbox.
        Never touches real cloud infrastructure or production databases.
        """
        now = time.time()
        if proposal.action_type == "SIMULATE_ROLLBACK":
            return {
                "success": True,
                "simulation_type": "ROLLBACK_SIMULATION",
                "target_deployment": proposal.target,
                "steps_simulated": [
                    f"1. Drained active client traffic from target '{proposal.target}'",
                    "2. Reverted schema migration step to restore prior table locks",
                    "3. Reset HikariCP database connection pool limit",
                    "4. Verified p99 latency returned to baseline (<150ms)",
                ],
                "expected_recovery_time_sec": 45,
                "timestamp": now,
                "synthetic_note": "This is a simulated outcome verified on synthetic telemetry.",
            }
        elif proposal.action_type == "SIMULATE_ESCALATION":
            return {
                "success": True,
                "simulation_type": "PAGERDUTY_ESCALATION_SIMULATION",
                "target_team": proposal.target,
                "notification_sent_to": proposal.parameters.get("on_call", "On-Call Engineer"),
                "summary": f"Incident {proposal.incident_id} escalated to {proposal.target} with evidence package {proposal.evidence_refs}",
                "timestamp": now,
                "synthetic_note": "Synthetic notification dispatched in sandbox mode.",
            }
        elif proposal.action_type == "ACKNOWLEDGE_INCIDENT":
            return {
                "success": True,
                "simulation_type": "INCIDENT_ACKNOWLEDGEMENT",
                "incident_id": proposal.incident_id,
                "new_status": "ACKNOWLEDGED",
                "timestamp": now,
                "synthetic_note": "Incident state updated in synthetic audit register.",
            }
        elif proposal.action_type == "SIMULATE_SERVICE_ISOLATION":
            return {
                "success": True,
                "simulation_type": "SERVICE_ISOLATION_SIMULATION",
                "target_service": proposal.target,
                "steps_simulated": [
                    f"1. Removed service '{proposal.target}' from ingress routing pool",
                    "2. Enabled circuit breaker on upstream consumer dependencies",
                    "3. Verified traffic shed successfully without packet drop",
                ],
                "timestamp": now,
                "synthetic_note": "Synthetic service isolation simulated in sandbox.",
            }
        elif proposal.action_type == "CREATE_REMEDIATION_TICKET":
            return {
                "success": True,
                "simulation_type": "REMEDIATION_TICKET_SIMULATION",
                "target": proposal.target,
                "ticket_id": f"TICK-{uuid.uuid4().hex[:6].upper()}",
                "priority": "P1",
                "assigned_to": proposal.parameters.get("assignee", "checkout-platform"),
                "evidence_linked": proposal.evidence_refs,
                "timestamp": now,
                "synthetic_note": "Synthetic remediation ticket created in audit register.",
            }
        return {"success": False, "error": f"Unknown action type '{proposal.action_type}'"}

    def get_audit_trail(self, incident_id: Optional[str] = None) -> List[AuditEntry]:
        """Retrieve audit log entries, optionally filtered by incident_id."""
        if incident_id:
            return [e for e in self.audit_trail if e.incident_id == incident_id]
        return list(reversed(self.audit_trail))

    def reset(self) -> None:
        """Reset state (for test isolation)."""
        self.proposals.clear()
        self.audit_trail.clear()
        if os.path.exists(self.storage_file):
            try:
                os.remove(self.storage_file)
            except Exception:
                pass


# Global singleton
action_policy_mgr = ActionPolicyManager()
