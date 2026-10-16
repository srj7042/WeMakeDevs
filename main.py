"""
ORACLE FastAPI Application.

Provides clean REST endpoints for the incident investigation console:
- GET /health
- GET /incidents
- GET /incidents/{incident_id}
- POST /incidents/{incident_id}/investigate
- GET /incidents/{incident_id}/evidence
- POST /actions/propose
- POST /actions/{action_id}/approve
- GET /audit
"""

from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from client import OracleIncidentsClient
from graph_service import GraphService
from orchestrator import InvestigationReport, orchestrator
from action_policy import ActionProposal, AuditEntry, action_policy_mgr

app = FastAPI(
    title="ImpactGraph Incident Intelligence API",
    description="Trace the cause. Map the impact. Act with evidence.",
    version="1.0.0",
)

# Configure CORS for local development frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

graph_svc = GraphService()


class HealthResponse(BaseModel):
    status: str
    database: str
    database_connected: bool
    is_synthetic: bool = True
    falkordb_graph: str = "oracle_incidents"


class CreateProposalRequest(BaseModel):
    incident_id: str
    action_type: str
    target: str
    rationale: str
    evidence_refs: List[str] = Field(default_factory=list)
    parameters: Dict[str, Any] = Field(default_factory=dict)


class ApproveActionRequest(BaseModel):
    actor: str = Field(..., description="Name of the human operator approving/rejecting the action")
    approved: bool = Field(True, description="True to approve and simulate, False to reject")


@app.get("/health", response_model=HealthResponse)
def health_check() -> HealthResponse:
    """Verify backend health and FalkorDB connectivity."""
    db_connected = False
    try:
        # Run lightweight ping query against FalkorDB
        res = graph_svc.client.read_query("RETURN 1")
        db_connected = bool(res.result_set)
    except Exception:
        db_connected = False

    return HealthResponse(
        status="HEALTHY" if db_connected else "DEGRADED",
        database="FalkorDB" if db_connected else "DISCONNECTED",
        database_connected=db_connected,
    )


@app.get("/incidents")
def list_incidents() -> List[Dict[str, Any]]:
    """List all incidents in the graph."""
    try:
        return graph_svc.list_incidents()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to query incidents: {str(e)}")


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: str) -> Dict[str, Any]:
    """Retrieve incident metadata, connected alerts, and observed services."""
    ctx = graph_svc.get_incident_context(incident_id)
    if "error" in ctx:
        raise HTTPException(status_code=404, detail=ctx["error"])
    return ctx


@app.post("/incidents/{incident_id}/investigate", response_model=InvestigationReport)
def investigate_incident(incident_id: str) -> InvestigationReport:
    """
    Trigger evidence-grounded graph investigation for an incident.
    Invokes domain tools, synthesizes findings into OBSERVED/INFERRED/UNKNOWN,
    and proposes a simulated response requiring human approval.
    """
    try:
        return orchestrator.investigate(incident_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Investigation failed: {str(e)}")


@app.get("/incidents/{incident_id}/evidence")
def get_incident_evidence(incident_id: str) -> List[Dict[str, Any]]:
    """Retrieve supporting and contradictory evidence items for an incident."""
    try:
        evidence = graph_svc.get_evidence_chain(incident_id)
        if not evidence:
            raise HTTPException(status_code=404, detail=f"No evidence records found for incident '{incident_id}'")
        return evidence
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch evidence: {str(e)}")


@app.post("/actions/propose", response_model=ActionProposal, status_code=status.HTTP_201_CREATED)
def propose_action(req: CreateProposalRequest) -> ActionProposal:
    """
    Propose an allowlisted simulated action.
    The action is created in PENDING_APPROVAL state and will NOT execute until approved.
    """
    try:
        return action_policy_mgr.create_proposal(
            incident_id=req.incident_id,
            action_type=req.action_type,
            target=req.target,
            rationale=req.rationale,
            evidence_refs=req.evidence_refs,
            parameters=req.parameters,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create proposal: {str(e)}")


@app.post("/actions/{action_id}/approve", response_model=ActionProposal)
def approve_action(action_id: str, req: ApproveActionRequest) -> ActionProposal:
    """
    Explicitly approve and execute a simulated action proposal.
    Rejects agent self-approval, invalid states, or duplicate execution attempts.
    """
    try:
        return action_policy_mgr.approve_and_simulate(
            proposal_id=action_id,
            actor=req.actor,
            approved=req.approved,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Approval execution failed: {str(e)}")


@app.get("/audit", response_model=List[AuditEntry])
def get_audit_trail(incident_id: Optional[str] = None) -> List[AuditEntry]:
    """Retrieve immutable audit log of proposed and executed simulated actions."""
    return action_policy_mgr.get_audit_trail(incident_id=incident_id)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
