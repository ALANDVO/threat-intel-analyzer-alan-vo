import React, { useEffect, useState } from "react";
import { Download, Sparkles, AlertTriangle, CheckCircle2, AlertCircle, RefreshCw, FileText } from "lucide-react";
import { api } from "../api/client";
import { SecurityBriefing, ThreatScan } from "../types";
import { useAuth } from "../context/AuthContext";

export const BriefingView: React.FC<{ initialScanId?: string }> = ({ initialScanId }) => {
  const { user } = useAuth();
  const [briefings, setBriefings] = useState<SecurityBriefing[]>([]);
  const [selected, setSelected] = useState<SecurityBriefing | null>(null);
  const [scans, setScans] = useState<ThreatScan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [advisoryLoading, setAdvisoryLoading] = useState(false);
  const [advisoryError, setAdvisoryError] = useState<string | null>(null);
  const [showGenModal, setShowGenModal] = useState(false);
  const [title, setTitle] = useState("Executive Security Briefing");
  const [date, setDate] = useState(new Date().toISOString().split("T")[0]);
  const [scanId, setScanId] = useState(initialScanId || "");

  const fetchData = async () => {
    try {
      setLoading(true); setError(null);
      const [b, s] = await Promise.all([api.briefings.list(1, 20), api.scans.list(1, 20)]);
      setBriefings(b.items); setScans(s.items);
      if (b.items.length && !selected) setSelected(b.items[0]);
      if (s.items.length && !scanId) setScanId(s.items[0].id);
    } catch (e: any) { setError(e.message || "Failed to load"); }
    finally { setLoading(false); }
  };

  useEffect(() => { fetchData(); }, []);

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setLoading(true); setError(null);
      const res = await api.briefings.generate(title, date, scanId || undefined);
      setShowGenModal(false); setMsg(`Briefing generated for ${res.target_date}`);
      setBriefings([res, ...briefings]); setSelected(res);
    } catch (e: any) { setError(e.message || "Generation failed"); }
    finally { setLoading(false); }
  };

  const handleRequestAdvisory = async () => {
    if (!selected) return;
    try {
      setAdvisoryLoading(true); setAdvisoryError(null);
      const res = await api.briefings.requestAdvisory(selected.id);
      setSelected({ ...selected, advisory_narrative: res.advisory_narrative, advisory_provider: res.advisory_provider, advisory_disclaimer: res.advisory_disclaimer });
      setMsg("Advisory narrative generated");
    } catch (e: any) { setAdvisoryError(e.message || "Advisory failed"); }
    finally { setAdvisoryLoading(false); }
  };

  return (
    <div className="briefings-view">
      <div className="view-header">
        <div><h2>Executive Security Briefings & Mitigation Playbooks</h2><p className="view-subtitle">Executive summaries, prioritized threats, and actionable playbooks.</p></div>
        {user?.role !== "viewer" && <button className="btn-primary" onClick={() => setShowGenModal(true)}><FileText size={16} /> Synthesize Briefing</button>}
      </div>
      {msg && <div className="alert-box alert-success"><CheckCircle2 size={18} /><span>{msg}</span><button className="alert-close" onClick={() => setMsg(null)}>×</button></div>}
      {error && <div className="alert-box alert-danger"><AlertCircle size={18} /><span>{error}</span><button className="alert-close" onClick={() => setError(null)}>×</button></div>}
      {loading ? <div className="state-container"><p>Loading briefings...</p></div> : (
        <div className="briefings-layout">
          <div className="briefings-sidebar">
            <h3>Briefing Reports</h3>
            <div className="scan-list-nav">
              {briefings.map(b => (
                <div key={b.id} className={`scan-nav-item ${selected?.id === b.id ? "active" : ""}`} onClick={() => setSelected(b)}>
                  <div className="scan-nav-title">{b.title}</div>
                  <div className="scan-nav-meta"><span>{b.target_date}</span><span className="badge badge-neutral">{b.summary_stats.total_findings} Findings</span></div>
                </div>
              ))}
            </div>
          </div>
          <div className="briefing-content-panel">
            {selected ? (
              <div>
                <div className="briefing-banner">
                  <div><h3>{selected.title}</h3><div className="text-muted text-xs">Date: <strong>{selected.target_date}</strong> | By: <strong>{selected.created_by}</strong></div></div>
                  <a href={api.briefings.exportMarkdownUrl(selected.id)} download className="btn-secondary btn-sm"><Download size={14} /> Download Markdown</a>
                </div>
                <div className="briefing-section mt-3"><h4>1. Executive Summary</h4><p className="text-sm">{selected.executive_summary}</p></div>
                <div className="briefing-section mt-3">
                  <h4>2. Exposure Metrics</h4>
                  <div className="metrics-grid mt-2">
                    {[["Critical", selected.summary_stats.critical_count, "text-danger", "border-danger"], ["High", selected.summary_stats.high_count, "text-warning", "border-warning"], ["KEV Active", selected.summary_stats.cisa_kev_active_count, "text-info", "border-info"], ["Internet Facing", selected.summary_stats.internet_exposed_count, "", ""]].map(([l, v, c, b]) => (
                      <div key={l as string} className={`stat-pill ${b}`}><span>{l}</span><strong className={c as string}>{v}</strong></div>
                    ))}
                  </div>
                </div>
                <div className="briefing-section mt-3">
                  <h4>3. Prioritized Threat Matrix</h4>
                  <div className="table-responsive">
                    <table className="data-table">
                      <thead><tr><th>Tier</th><th>CVE</th><th>Asset</th><th>Component</th><th>Score</th><th>Action</th></tr></thead>
                      <tbody>{selected.top_threats.map((t, i) => (
                        <tr key={i}>
                          <td><span className={`badge badge-${t.priority_tier.toLowerCase()}`}>{t.priority_tier}</span></td>
                          <td className="font-mono text-accent font-bold">{t.cve_id}</td>
                          <td className="font-semibold">{t.asset_name}</td>
                          <td><code>{t.asset_component}</code> v{t.asset_version}</td>
                          <td>{t.composite_risk_score}</td>
                          <td className="text-xs text-warning">{t.remediation}</td>
                        </tr>
                      ))}</tbody>
                    </table>
                  </div>
                </div>
                <div className="briefing-section mt-3">
                  <h4>4. Actionable Remediation Playbook</h4>
                  <div className="playbook-steps mt-2">{selected.mitigation_playbook.map((s, i) => (
                    <div key={i} className="playbook-card mb-2">
                      <span className="badge badge-neutral">{s.phase.toUpperCase()}</span>
                      <h5 className="mt-1">{s.title}</h5>
                      <p className="text-sm">{s.description}</p>
                      <div className="text-xs text-muted mt-1">Asset: <strong>{s.target_asset}</strong> | CVE: <strong>{s.target_cve}</strong></div>
                    </div>
                  ))}</div>
                </div>
                <div className="briefing-section mt-3">
                  <div className="panel-header">
                    <div><h4>5. Contextual AI Threat Advisory (Opt-In)</h4><p className="text-xs text-muted">Offline-first core. Grounded narrative requires LLM_API_KEY.</p></div>
                    {user?.role !== "viewer" && !selected.advisory_narrative && (
                      <button className="btn-accent btn-sm" disabled={advisoryLoading} onClick={handleRequestAdvisory}>
                        {advisoryLoading ? <><RefreshCw size={14} className="animate-spin mr-1" /> Querying...</> : <><Sparkles size={14} className="mr-1" /> Request Advisory</>}
                      </button>
                    )}
                  </div>
                  {advisoryError && <div className="alert-box alert-danger mt-2"><AlertTriangle size={18} /><span>{advisoryError}</span></div>}
                  {selected.advisory_narrative && (
                    <div className="mt-2">
                      <div className="alert-box alert-warning"><AlertTriangle size={16} className="inline mr-1" /><span>{selected.advisory_disclaimer}</span></div>
                      <div className="text-xs text-muted mb-1">Provider: <code>{selected.advisory_provider}</code></div>
                      <div className="text-sm">{selected.advisory_narrative}</div>
                    </div>
                  )}
                </div>
              </div>
            ) : <div className="state-container"><p>Select or generate a briefing.</p></div>}
          </div>
        </div>
      )}
      {showGenModal && (
        <div className="modal-backdrop"><div className="modal-box"><div className="modal-header"><h3>Synthesize Briefing</h3><button className="modal-close" onClick={() => setShowGenModal(false)}>×</button></div>
        <form onSubmit={handleGenerate} className="modal-body form-grid">
          <div className="span-2"><label>Title *</label><input required value={title} onChange={e => setTitle(e.target.value)} /></div>
          <div><label>Target Date *</label><input type="date" required value={date} onChange={e => setDate(e.target.value)} /></div>
          <div><label>Source Scan *</label><select required value={scanId} onChange={e => setScanId(e.target.value)}>{scans.map(s => <option key={s.id} value={s.id}>{s.title}</option>)}</select></div>
          <div className="modal-actions span-2"><button type="button" className="btn-secondary" onClick={() => setShowGenModal(false)}>Cancel</button><button type="submit" className="btn-primary">Synthesize</button></div>
        </form></div></div>
      )}
    </div>
  );
};
