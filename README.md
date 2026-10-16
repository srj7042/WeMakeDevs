# ImpactGraph

> **Trace the cause. Map the impact. Act with evidence.**

**ImpactGraph** is a graph-native AI incident investigation agent built on **[FalkorDB](https://docs.falkordb.com)** for **FalkorDB Graph Hacks (Track 01: Agents That Act on Connected Data)**.

It navigates connected infrastructure topology, telemetry signals, and deployment history to isolate root causes, map multi-hop blast radius, evaluate competing hypotheses, and propose auditable remediation actions with strict human-in-the-loop approval.

---

## Architecture

```
┌────────────────────────────────────────────────────────┐
│             ImpactGraph Cockpit (React + Vite)         │
│          http://localhost:5173 (Topology & SSE)        │
└───────────────────────────┬────────────────────────────┘
                            │ REST / SSE
┌───────────────────────────▼────────────────────────────┐
│              FastAPI Backend (Port 8000)               │
│        Investigation Orchestrator & Action Policy      │
└─────────────┬────────────────────────────┬─────────────┘
              │ Python Calls               │ stdio / JSON-RPC
┌─────────────▼──────────────┐ ┌───────────▼─────────────┐
│  Graph Service (FalkorDB)  │ │   MCP Tool Server       │
│  - Parameterized Cypher    │ │   - 7 Domain Tools      │
│  - Read-Only (GRAPH.RO)    │ │   - Bounded Traversal   │
└─────────────┬──────────────┘ └─────────────────────────┘
              │ Redis Protocol (Port 6379)
┌─────────────▼──────────────────────────────────────────┐
│                   FalkorDB Container                   │
│         Sparse-matrix GraphBLAS engine in C            │
│           Web Browser Debugger on Port 3000            │
└────────────────────────────────────────────────────────┘
```

---

## Graph Schema

### Entities
- `Incident`: Tracked production outages (`INC-101`, `INC-102`, `INC-103`).
- `Alert`: Metric spikes and telemetry anomalies (`ALT-901`..`ALT-921`).
- `Service`: System microservices with tier classifications (`Tier 0` to `Tier 3`).
- `Package`: Software dependencies and runtime libraries.
- `Vulnerability`: Known CVE entries with severity ratings.
- `Deployment`: Release records, schema migrations, and Git commit references.
- `Evidence`: Grounded telemetry observations (logs, metrics, audit trails).
- `Team`: Owning teams and on-call engineer contacts.
- `Action`: Proposed remediation steps requiring human approval.

### Relationships
- `(Incident)-[:TRIGGERED_BY]->(Alert)`
- `(Alert)-[:FIRED_ON]->(Service)`
- `(Service)-[:DEPENDS_ON]->(Service)` *(up to 4-hop deep chains)*
- `(Service)-[:USES]->(Package)-[:HAS_VULNERABILITY]->(Vulnerability)`
- `(Service)-[:HAS_DEPLOYMENT]->(Deployment)`
- `(Service)-[:OWNED_BY]->(Team)`
- `(Incident)-[:RECOMMENDS]->(Action)`
- `(Evidence)-[:SUPPORTS]->(Incident)`
- `(Evidence)-[:OBSERVED]->(Service)`

---

## Commands to Run the Project

### 1. Start FalkorDB
```bash
docker run -d -p 6379:6379 -p 3000:3000 --name falkordb falkordb/falkordb:latest
```
*(FalkorDB Web UI is available at [http://localhost:3000](http://localhost:3000))*

### 2. Setup Python Environment & Seed Graph
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python seed.py
```
*(Loads 3 incidents, 4-hop dependency chains, CVE records, and indexes idempotently)*

### 3. Start Backend Server
```bash
source .venv/bin/activate
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```
- API Root: [http://localhost:8000](http://localhost:8000)
- Interactive Swagger Docs: [http://localhost:8000/docs](http://localhost:8000/docs)
- Health Check: [http://localhost:8000/health](http://localhost:8000/health)

### 4. Start Frontend Cockpit
```bash
cd frontend
npm install
npm run dev
```
- Open [http://localhost:5173](http://localhost:5173) in your browser.

### 5. Run Test Suite
```bash
source .venv/bin/activate
pytest test_oracle.py -v
```
*(Executes 24 automated tests verifying graph queries, schema constraints, MCP tools, action policies, and API contracts)*

---

## API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | FalkorDB connectivity and engine status |
| `GET` | `/incidents` | List active incidents with alert counts and affected services |
| `GET` | `/incidents/{id}/context` | Incident metadata, triggered alerts, and service tiers |
| `POST` | `/incidents/{id}/investigate` | Run evidence-grounded investigation orchestrator |
| `GET` | `/incidents/{id}/evidence` | Supporting and contradictory evidence chains |
| `GET` | `/services/{id}/blast-radius` | Reverse downstream dependency impact traversal |
| `POST` | `/proposals` | Create remediation proposal in `PENDING_APPROVAL` status |
| `POST` | `/proposals/{id}/approve` | Human gate approval & safe execution simulation |
| `GET` | `/audit-trail` | Immutable audit log of all decisions and outcomes |

---

## Key Capabilities

1. **Deterministic & Fast**: Operates sub-millisecond graph queries directly on FalkorDB via sparse-matrix GraphBLAS. No mandatory LLM keys required.
2. **Reverse Blast Radius**: Computes multi-tier downstream impact to detect Tier 0 compromises before taking action.
3. **Competing Hypotheses**: Evaluates candidate causes side-by-side using supporting vs. contradictory evidence and reports `UNKNOWN` when telemetry is missing.
4. **Human-in-the-Loop Gate**: The agent can only propose actions. Agent self-approval is blocked; every execution requires an explicit human decision and records an immutable audit trail.

---

## Authors & Team

- **Suraj Jaiswal** ([@srj7042](https://github.com/srj7042))
- **Sujal Kumar** ([@sujalkumar1029-gif](https://github.com/sujalkumar1029-gif))
- **Shreyas Rajure** ([@cipheroot6](https://github.com/cipheroot6))
- **Naman Pandey** ([@Naman-in-ml](https://github.com/Naman-in-ml))
