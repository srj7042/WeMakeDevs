import { useState, useEffect } from 'react';

interface Incident {
  id: string;
  title: string;
  description?: string;
  severity: string;
  status: string;
  created_at: number;
  alert_count: number;
  affected_services: string[];
  is_synthetic: boolean;
}

interface Finding {
  category: 'OBSERVED' | 'INFERRED' | 'UNKNOWN';
  title: string;
  description: string;
  evidence_refs: string[];
  graph_path?: string[];
}

interface CandidateHypothesis {
  hypothesis_id: string;
  title: string;
  likelihood: 'HIGH' | 'MEDIUM' | 'LOW' | 'RULED_OUT';
  confidence_score: number;
  supporting_evidence: string[];
  contradicting_evidence: string[];
  root_cause_entity: Record<string, any>;
  rationale: string;
}

interface ActionProposal {
  id: string;
  incident_id: string;
  action_type: string;
  target: string;
  rationale: string;
  evidence_refs: string[];
  parameters: Record<string, any>;
  status: 'PENDING_APPROVAL' | 'APPROVED' | 'REJECTED' | 'EXECUTED';
  created_at: number;
  approved_by?: string;
  approved_at?: number;
  simulated_outcome?: Record<string, any>;
}

interface InvestigationReport {
  incident_id: string;
  title: string;
  severity: string;
  status: string;
  summary: string;
  mode: string;
  findings: Finding[];
  candidate_hypotheses: CandidateHypothesis[];
  blast_radius: {
    root_service_id: string;
    total_impacted_services: number;
    tier_0_compromised: boolean;
    impacted_services: Array<{
      service_id: string;
      service_name: string;
      criticality: string;
      status: string;
      hop_distance: number;
      dependency_chain: string[];
    }>;
  };
  evidence_chain: Array<{
    evidence_id: string;
    source_type: string;
    observation: string;
    timestamp: number;
    service_name?: string;
    deployment_id?: string;
    stance: 'SUPPORTING' | 'CONTRADICTORY';
  }>;
  deployments: Array<{
    deployment_id: string;
    version: string;
    status: string;
    commit_sha: string;
    deployed_at: number;
  }>;
  recommended_next_step: string;
  confidence_explanation: string;
  proposed_action?: ActionProposal;
}

interface AuditEntry {
  audit_id: string;
  proposal_id: string;
  incident_id: string;
  action_type: string;
  target: string;
  actor: string;
  approval_status: string;
  evidence_refs: string[];
  simulated_outcome?: Record<string, any>;
  timestamp: number;
}

const API_BASE = 'http://localhost:8000';

export default function App() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>('INC-101');
  const [report, setReport] = useState<InvestigationReport | null>(null);
  const [auditTrail, setAuditTrail] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [operatorName, setOperatorName] = useState<string>('Jane Doe');
  const [actionError, setActionError] = useState<string | null>(null);
  const [dbHealthy, setDbHealthy] = useState<boolean>(true);
  const [activeFindingTab, setActiveFindingTab] = useState<'ALL' | 'OBSERVED' | 'INFERRED' | 'UNKNOWN'>('ALL');
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    return (localStorage.getItem('impactgraph_theme') as 'dark' | 'light') || 'dark';
  });

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('impactgraph_theme', theme);
  }, [theme]);

  useEffect(() => {
    fetchHealth();
    fetchIncidents();
    fetchAudit();
  }, []);

  const fetchHealth = async () => {
    try {
      const res = await fetch(`${API_BASE}/health`);
      const data = await res.json();
      setDbHealthy(data.database_connected);
    } catch {
      setDbHealthy(false);
    }
  };

  const fetchIncidents = async () => {
    try {
      const res = await fetch(`${API_BASE}/incidents`);
      const data = await res.json();
      setIncidents(data);
    } catch (err) {
      console.error('Failed to load incidents', err);
    }
  };

  const fetchAudit = async () => {
    try {
      const res = await fetch(`${API_BASE}/audit`);
      const data = await res.json();
      setAuditTrail(data);
    } catch (err) {
      console.error('Failed to load audit trail', err);
    }
  };

  const handleInvestigate = async () => {
    if (!selectedIncidentId) return;
    setLoading(true);
    setActionError(null);
    try {
      const res = await fetch(`${API_BASE}/incidents/${selectedIncidentId}/investigate`, {
        method: 'POST',
      });
      if (!res.ok) throw new Error('Investigation failed');
      const data = await res.json();
      setReport(data);
      fetchAudit();
    } catch (err: any) {
      setActionError(err.message || 'Investigation error');
    } finally {
      setLoading(false);
    }
  };

  const handleApproveAction = async (approved: boolean) => {
    if (!report?.proposed_action) return;
    setActionError(null);
    try {
      const res = await fetch(`${API_BASE}/actions/${report.proposed_action.id}/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ actor: operatorName, approved }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || 'Action failed');
      }
      setReport(prev => (prev ? { ...prev, proposed_action: data } : null));
      fetchAudit();
    } catch (err: any) {
      setActionError(err.message);
    }
  };

  const selectedIncident = incidents.find(i => i.id === selectedIncidentId);

  const filteredFindings = report?.findings.filter(f => {
    if (activeFindingTab === 'ALL') return true;
    return f.category === activeFindingTab;
  });

  return (
    <div>
      {/* Top Navigation */}
      <header className="app-header">
        <div className="brand-section">
          <div className="logo-badge">IMPACTGRAPH</div>
          <div>
            <div className="brand-title">ImpactGraph</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Trace the cause • Map the impact • Act with evidence
            </div>
          </div>
        </div>
        <div className="header-actions">
          <div className="status-indicator">
            <div className={`status-dot ${dbHealthy ? '' : 'disconnected'}`} />
            <span style={{ fontFamily: 'var(--font-mono)' }}>
              FalkorDB: {dbHealthy ? 'Connected' : 'Offline'}
            </span>
          </div>
          <span style={{ color: 'var(--border-color)' }}>•</span>
          <span style={{ color: 'var(--accent-primary)', fontFamily: 'var(--font-mono)' }}>
            <code>oracle_incidents</code>
          </span>
          <button
            className="theme-toggle-btn"
            onClick={() => setTheme(prev => (prev === 'dark' ? 'light' : 'dark'))}
            title={`Switch to ${theme === 'dark' ? 'Light' : 'Dark'} theme`}
          >
            {theme === 'dark' ? '☀️ Light' : '🌙 Dark'}
          </button>
        </div>
      </header>

      {/* Main Grid */}
      <div className="main-layout">
        {/* Sidebar */}
        <aside className="sidebar">
          <div>
            <div className="sidebar-title">Incidents ({incidents.length})</div>
            {incidents.map(inc => (
              <div
                key={inc.id}
                className={`incident-card ${selectedIncidentId === inc.id ? 'active' : ''}`}
                onClick={() => {
                  setSelectedIncidentId(inc.id);
                  setReport(null);
                }}
              >
                <div className="card-header-row">
                  <span className={`sev-badge ${inc.severity === 'SEV-1' ? 'sev-1' : 'sev-2'}`}>
                    {inc.severity}
                  </span>
                  <span className="status-badge">{inc.status}</span>
                </div>
                <div className="card-title">{inc.title}</div>
                <div className="card-footer">
                  <span style={{ color: 'var(--accent-primary)', fontWeight: 600 }}>{inc.id}</span>
                  <span>{inc.alert_count} Alerts</span>
                </div>
              </div>
            ))}
          </div>
        </aside>

        {/* Content Panel */}
        <main className="content-area">
          {/* Hero Banner */}
          {selectedIncident && (
            <div className="incident-hero">
              <div className="hero-header">
                <div>
                  <div className="hero-title">
                    <span className={`sev-badge ${selectedIncident.severity === 'SEV-1' ? 'sev-1' : 'sev-2'}`}>
                      {selectedIncident.severity}
                    </span>
                    <span>{selectedIncident.id}: {selectedIncident.title}</span>
                  </div>
                </div>
                <button
                  className="btn-investigate"
                  onClick={handleInvestigate}
                  disabled={loading}
                >
                  {loading ? '🔍 Investigating...' : '⚡ Investigate'}
                </button>
              </div>

              {selectedIncident.description && (
                <div className="hero-desc">{selectedIncident.description}</div>
              )}

              <div className="hero-stats-bar">
                <div className="stat-item">
                  <span className="stat-label">Impacted Services</span>
                  <span className="stat-value">{selectedIncident.affected_services.join(', ')}</span>
                </div>
                <div className="stat-item">
                  <span className="stat-label">Active Alerts</span>
                  <span className="stat-value" style={{ color: 'var(--accent-primary)' }}>
                    {selectedIncident.alert_count} Active
                  </span>
                </div>
                <div className="stat-item">
                  <span className="stat-label">Engine</span>
                  <span className="stat-value" style={{ color: 'var(--accent-primary)', fontFamily: 'var(--font-mono)' }}>
                    FalkorDB MCP
                  </span>
                </div>
              </div>
            </div>
          )}

          {/* Loading Animation */}
          {loading && (
            <div className="section-card" style={{ textAlign: 'center', padding: '40px', border: '1px solid var(--accent-primary-border)' }}>
              <div style={{ fontSize: '1.15rem', fontWeight: 700, color: 'var(--accent-primary)', marginBottom: '8px' }}>
                Investigating Incident
              </div>
              <div style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', fontFamily: 'var(--font-mono)' }}>
                Traversing topology & citing evidence chains...
              </div>
            </div>
          )}

          {/* Report Section */}
          {report && !loading && (
            <>
              {/* Executive Summary */}
              <div className="section-card">
                <div className="section-header">
                  <div className="section-title">Investigation Summary</div>
                </div>
                <p style={{ color: 'var(--text-primary)', fontSize: '0.92rem', lineHeight: '1.6' }}>
                  {report.summary}
                </p>
                <div style={{ marginTop: '14px', padding: '12px', background: 'var(--accent-primary-bg)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--accent-primary-border)' }}>
                  <strong style={{ color: 'var(--accent-primary)', fontFamily: 'var(--font-mono)' }}>Confidence:</strong>{' '}
                  <span style={{ color: 'var(--text-secondary)', fontSize: '0.88rem' }}>{report.confidence_explanation}</span>
                </div>
              </div>

              {/* Candidate Hypotheses */}
              <div className="section-card">
                <div className="section-header">
                  <div className="section-title">Root-Cause Hypotheses</div>
                </div>
                <div className="hypotheses-grid">
                  {report.candidate_hypotheses.map(hypo => (
                    <div key={hypo.hypothesis_id} className={`hypo-card ${hypo.likelihood.toLowerCase()}`}>
                      <div>
                        <div className="hypo-header">
                          <span style={{ fontWeight: 800, fontSize: '0.78rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                            {hypo.hypothesis_id}
                          </span>
                          <span className={`likelihood-pill ${hypo.likelihood.toLowerCase()}`}>
                            {hypo.likelihood} ({(hypo.confidence_score * 100).toFixed(0)}%)
                          </span>
                        </div>
                        <div className="hypo-title">{hypo.title}</div>
                        <div className="hypo-rationale">{hypo.rationale}</div>
                      </div>

                      <div className="evidence-tags">
                        {hypo.supporting_evidence.map(ev => (
                          <span key={ev} className="tag-evidence">✓ {ev}</span>
                        ))}
                        {hypo.contradicting_evidence.map(ev => (
                          <span key={ev} className="tag-contradicting">✗ {ev}</span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Blast Radius & Graph Topology */}
              <div className="section-card">
                <div className="section-header">
                  <div className="section-title">
                    Downstream Blast Radius
                    <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginLeft: '10px', fontWeight: 500 }}>
                      ({report.blast_radius.total_impacted_services} Impacted)
                    </span>
                  </div>
                  {report.blast_radius.tier_0_compromised && (
                    <span style={{ background: 'var(--accent-red-bg)', color: 'var(--accent-red)', border: '1px solid var(--accent-red-border)', padding: '2px 8px', borderRadius: '4px', fontSize: '0.72rem', fontWeight: 800, fontFamily: 'var(--font-mono)' }}>
                      Tier 0 Impacted
                    </span>
                  )}
                </div>

                <div className="blast-tree">
                  <div className="tree-flow">
                    {/* Root Service */}
                    <div className="tree-node outage">
                      <div style={{ fontSize: '0.65rem', color: 'var(--accent-red)', fontWeight: 800, fontFamily: 'var(--font-mono)' }}>
                        ORIGIN FAULT
                      </div>
                      <div style={{ fontWeight: 700, color: 'var(--text-primary)', fontSize: '0.95rem', marginTop: '2px' }}>
                        {report.blast_radius.root_service_id}
                      </div>
                      <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>Root Cause</div>
                    </div>

                    {/* Impacted Downstream Services */}
                    {report.blast_radius.impacted_services.length === 0 ? (
                      <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginLeft: '12px' }}>
                        No downstream impact detected.
                      </div>
                    ) : (
                      report.blast_radius.impacted_services.map(svc => (
                        <div key={svc.service_id} style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                          <div className="tree-arrow">← [:DEPENDS_ON]</div>
                          <div className={`tree-node ${svc.criticality === 'Tier 0' ? 'critical-tier0' : 'degraded'}`}>
                            <div style={{ fontSize: '0.65rem', color: svc.criticality === 'Tier 0' ? 'var(--accent-primary)' : 'var(--accent-amber)', fontWeight: 800, fontFamily: 'var(--font-mono)' }}>
                              HOP {svc.hop_distance} • {svc.criticality}
                            </div>
                            <div style={{ fontWeight: 700, color: 'var(--text-primary)', fontSize: '0.95rem', marginTop: '2px' }}>
                              {svc.service_name}
                            </div>
                            <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
                              <code>{svc.service_id}</code> ({svc.status})
                            </div>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </div>

              {/* Categorized Findings */}
              <div className="section-card">
                <div className="section-header">
                  <div className="section-title">Findings</div>
                  <div style={{ display: 'flex', gap: '6px' }}>
                    {(['ALL', 'OBSERVED', 'INFERRED', 'UNKNOWN'] as const).map(tab => (
                      <button
                        key={tab}
                        onClick={() => setActiveFindingTab(tab)}
                        style={{
                          background: activeFindingTab === tab ? 'var(--accent-primary)' : 'var(--bg-secondary)',
                          color: activeFindingTab === tab ? '#FAF9F6' : 'var(--text-secondary)',
                          fontSize: '0.72rem',
                          fontWeight: 700,
                          padding: '5px 12px',
                          borderRadius: 'var(--radius-sm)',
                          border: activeFindingTab === tab ? '1px solid var(--accent-primary)' : '1px solid var(--border-color)',
                          fontFamily: 'var(--font-mono)',
                        }}
                      >
                        {tab}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="findings-grid">
                  {filteredFindings?.map((finding, idx) => (
                    <div key={idx} className="finding-card">
                      <span className={`finding-category-pill category-${finding.category.toLowerCase()}`}>
                        {finding.category}
                      </span>
                      <div className="finding-title">{finding.title}</div>
                      <div className="finding-desc">{finding.description}</div>
                      {finding.evidence_refs.length > 0 && (
                        <div style={{ marginTop: '8px', display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                          {finding.evidence_refs.map(ref => (
                            <span key={ref} className="tag-evidence">{ref}</span>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {/* Evidence Provenance Table */}
              <div className="section-card">
                <div className="section-header">
                  <div className="section-title">Linked Evidence</div>
                </div>
                <table className="audit-table">
                  <thead>
                    <tr>
                      <th>ID</th>
                      <th>Type</th>
                      <th>Target</th>
                      <th>Observation</th>
                      <th>Stance</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.evidence_chain.map(ev => (
                      <tr key={ev.evidence_id}>
                        <td><code style={{ color: 'var(--accent-primary)' }}>{ev.evidence_id}</code></td>
                        <td><span className="tag-evidence">{ev.source_type}</span></td>
                        <td>{ev.service_name || 'N/A'} {ev.deployment_id ? `(${ev.deployment_id})` : ''}</td>
                        <td>{ev.observation}</td>
                        <td>
                          <span className={ev.stance === 'SUPPORTING' ? 'tag-evidence' : 'tag-contradicting'}>
                            {ev.stance}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Proposed Action Box */}
              {report.proposed_action && (
                <div className="action-box">
                  <div className="action-header">
                    <div>
                      <span style={{ fontSize: '0.7rem', fontWeight: 800, color: 'var(--accent-primary)', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>
                        Proposed Action
                      </span>
                      <h3 style={{ color: 'var(--text-primary)', fontSize: '1.15rem', marginTop: '2px' }}>
                        {report.proposed_action.action_type}: <code>{report.proposed_action.target}</code>
                      </h3>
                    </div>
                    <span className={`action-status-pill status-${report.proposed_action.status.toLowerCase().replace('_', '-')}`}>
                      {report.proposed_action.status}
                    </span>
                  </div>

                  <p style={{ color: 'var(--text-secondary)', fontSize: '0.88rem', marginBottom: '10px', lineHeight: '1.5' }}>
                    <strong style={{ color: 'var(--text-primary)' }}>Rationale:</strong> {report.proposed_action.rationale}
                  </p>

                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '10px', fontFamily: 'var(--font-mono)' }}>
                    Evidence: {report.proposed_action.evidence_refs.join(', ')}
                  </div>

                  {actionError && (
                    <div style={{ color: 'var(--accent-red)', background: 'var(--accent-red-bg)', border: '1px solid var(--accent-red-border)', padding: '8px 12px', borderRadius: '4px', fontSize: '0.82rem', marginBottom: '10px' }}>
                      ⚠️ {actionError}
                    </div>
                  )}

                  {report.proposed_action.status === 'PENDING_APPROVAL' && (
                    <div className="approval-form">
                      <label style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                        Operator:
                      </label>
                      <input
                        type="text"
                        className="operator-input"
                        value={operatorName}
                        onChange={e => setOperatorName(e.target.value)}
                        placeholder="Operator Name"
                      />
                      <button className="btn-approve" onClick={() => handleApproveAction(true)}>
                        ✓ Approve & Run
                      </button>
                      <button className="btn-reject" onClick={() => handleApproveAction(false)}>
                        ✗ Reject
                      </button>
                    </div>
                  )}

                  {/* Simulated Outcome Display */}
                  {report.proposed_action.status === 'EXECUTED' && report.proposed_action.simulated_outcome && (
                    <div className="outcome-box">
                      <div style={{ fontWeight: 700, color: 'var(--accent-primary)', fontSize: '0.9rem', marginBottom: '6px' }}>
                        ✓ Executed by {report.proposed_action.approved_by}
                      </div>
                      <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginBottom: '8px' }}>
                        Est. Recovery: <strong style={{ color: 'var(--text-primary)' }}>{report.proposed_action.simulated_outcome.expected_recovery_time_sec}s</strong>
                      </div>
                      <ul style={{ paddingLeft: '18px', fontSize: '0.82rem', color: 'var(--text-primary)' }}>
                        {report.proposed_action.simulated_outcome.steps_simulated?.map((step: string, i: number) => (
                          <li key={i} style={{ marginBottom: '3px' }}>{step}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}

              {/* Audit Trail Section */}
              <div className="section-card">
                <div className="section-header">
                  <div className="section-title">Audit Trail</div>
                </div>
                {auditTrail.length === 0 ? (
                  <div style={{ color: 'var(--text-muted)', fontSize: '0.82rem' }}>No audit actions recorded.</div>
                ) : (
                  <table className="audit-table">
                    <thead>
                      <tr>
                        <th>Audit ID</th>
                        <th>Proposal</th>
                        <th>Action</th>
                        <th>Target</th>
                        <th>Actor</th>
                        <th>Status</th>
                        <th>Time</th>
                      </tr>
                    </thead>
                    <tbody>
                      {auditTrail.map(entry => (
                        <tr key={entry.audit_id}>
                          <td><code style={{ color: 'var(--accent-primary)' }}>{entry.audit_id}</code></td>
                          <td><code>{entry.proposal_id}</code></td>
                          <td><strong style={{ color: 'var(--text-primary)' }}>{entry.action_type}</strong></td>
                          <td><code>{entry.target}</code></td>
                          <td>{entry.actor}</td>
                          <td>
                            <span className={entry.approval_status === 'EXECUTED' ? 'tag-evidence' : 'tag-contradicting'}>
                              {entry.approval_status}
                            </span>
                          </td>
                          <td style={{ fontFamily: 'var(--font-mono)' }}>{new Date(entry.timestamp * 1000).toLocaleTimeString()}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </>
          )}
        </main>
      </div>
    </div>
  );
}
