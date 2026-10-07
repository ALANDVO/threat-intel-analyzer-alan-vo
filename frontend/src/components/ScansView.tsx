import React, { useEffect, useState } from "react";
import { Zap, Download, FileText, ShieldCheck, Info, CheckCircle2, AlertCircle } from "lucide-react";
import { api } from "../api/client";
import { ScanFinding, ThreatScan } from "../types";
import { useAuth } from "../context/AuthContext";

export const ScansView: React.FC<{ onGenerateBriefing?: (scanId: string) => void }> = ({ onGenerateBriefing }) => {
  const { user } = useAuth();
  const [scans, setScans] = useState<ThreatScan[]>([]);
  const [selectedScan, setSelectedScan] = useState<ThreatScan | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showRunModal, setShowRunModal] = useState(false);
  const [activeScoreBreakdown, setActiveScoreBreakdown] = useState<ScanFinding | null>(null);
  const [scanTitle, setScanTitle] = useState("Production Attack Surface Scan");
  const [targetEnv, setTargetEnv] = useState("production");
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  const fetchScans = async () => {
    try {
      setLoading(true); setError(null);
      const res = await api.scans.list(1, 20);
      setScans(res.items);
      if (res.items.length > 0 && !selectedScan) setSelectedScan(await api.scans.get(res.items[0].id));
    } catch (e: any) { setError(e.message || "Failed to load scans"); }
    finally { setLoading(false); }
  };

  useEffect(() => { fetchScans(); }, []);

  const handleSelectScan = async (scanId: string) => {
    try { setLoading(true); setSelectedScan(await api.scans.get(scanId)); }
    catch (e: any) { setError(e.message || "Failed to load scan"); }
    finally { setLoading(false); }
  };

  const handleRunScan = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setError(null); setLoading(true);
      const s = await api.scans.run(scanTitle, targetEnv || undefined);
      setShowRunModal(false); setActionSuccess(`Scan completed: ${s.findings_count} correlations found.`);
      setScans([s, ...scans]); setSelectedScan(s);
    } catch (e: any) { setError(e.message || "Scan failed"); }
    finally { setLoading(false); }
  };

  return (
    <div className="scans-view">
      <div className="view-header">
        <div><h2>Attack Surface Correlation Scans</h2><p className="view-subtitle">Matching asset versions against vulnerability intelligence specs.</p></div>
        {user?.role !== "viewer" && <button className="btn-primary" onClick={() => setShowRunModal(true)}><Zap size={16} /> Execute Scan</button>}
      </div>
      {actionSuccess && <div className="alert-box alert-success"><CheckCircle2 size={18} /><span>{actionSuccess}</span><button className="alert-close" onClick={() => setActionSuccess(null)}>×</button></div>}
      {error && <div className="alert-box alert-danger"><AlertCircle size={18} /><span>{error}</span><button className="alert-close" onClick={() => setError(null)}>×</button></div>}
      {loading ? <div className="state-container"><p>Analyzing threat correlations...</p></div> : (
        <div className="scans-layout">
          <div className="scans-sidebar">
            <h3>Scan History</h3>
            <div className="scan-list-nav">
              {scans.map(s => (
                <div key={s.id} className={`scan-nav-item ${selectedScan?.id === s.id ? "active" : ""}`} onClick={() => handleSelectScan(s.id)}>
                  <div className="scan-nav-title">{s.title}</div>
                  <div className="scan-nav-meta"><span>{new Date(s.created_at).toLocaleDateString()}</span><span className="badge badge-danger">{s.critical_count} Crit</span><span className="badge badge-neutral">{s.findings_count} Total</span></div>
                </div>
              ))}
            </div>
          </div>
          <div className="scan-details-panel">
            {selectedScan ? (
              <div>
                <div className="scan-banner">
                  <div><h3>{selectedScan.title}</h3><div className="scan-meta-tags">Target: <strong>{selectedScan.target_environment || "All"}</strong> | Assets: <strong>{selectedScan.scanned_assets_count}</strong></div></div>
                  <div className="header-actions">
                    <a href={api.scans.exportUrl(selectedScan.id)} target="_blank" rel="noreferrer" className="btn-secondary btn-sm"><Download size={14} /> Export JSON</a>
                    {onGenerateBriefing && user?.role !== "viewer" && <button className="btn-primary btn-sm" onClick={() => onGenerateBriefing(selectedScan.id)}><FileText size={14} /> Briefing</button>}
                  </div>
                </div>
                <div className="metrics-grid mt-3">
                  {[["Critical", selectedScan.critical_count, "text-danger", "border-danger"], ["High", selectedScan.high_count, "text-warning", "border-warning"], ["Medium", selectedScan.medium_count, "text-info", "border-info"], ["Low", selectedScan.low_count, "", ""]].map(([lbl, val, cls, bcls]) => (
                    <div key={lbl as string} className={`stat-pill ${bcls}`}><span>{lbl}</span><strong className={cls as string}>{val}</strong></div>
                  ))}
                </div>
                <h4 className="mt-4 mb-2">Correlated Vulnerabilities ({selectedScan.findings?.length || 0})</h4>
                {(!selectedScan.findings || selectedScan.findings.length === 0) ? (
                  <div className="state-container"><ShieldCheck size={36} className="text-success" /><p>No matching vulnerabilities found!</p></div>
                ) : (
                  <div className="table-responsive">
                    <table className="data-table">
                      <thead><tr><th>Priority</th><th>Score</th><th>Asset</th><th>CVE</th><th>Reason</th><th>Remediation</th></tr></thead>
                      <tbody>{selectedScan.findings.map(f => (
                        <tr key={f.id}>
                          <td><span className={`badge badge-${f.priority_tier.toLowerCase()}`}>{f.priority_tier}</span></td>
                          <td><button className="btn-secondary btn-sm font-bold" onClick={() => setActiveScoreBreakdown(f)}>{f.composite_risk_score} / 100 <Info size={12} className="inline ml-1" /></button></td>
                          <td><div className="font-semibold">{f.asset_name}</div><div className="text-xs text-muted"><code>{f.asset_component}</code> v{f.asset_version}</div></td>
                          <td><span className="font-mono text-accent font-bold">{f.cve_id}</span></td>
                          <td className="text-xs">{f.match_reason}</td>
                          <td className="text-xs text-warning">{f.remediation_recommendation}</td>
                        </tr>
                      ))}</tbody>
                    </table>
                  </div>
                )}
              </div>
            ) : <div className="state-container"><p>Select a scan to inspect findings.</p></div>}
          </div>
        </div>
      )}
      {showRunModal && (
        <div className="modal-backdrop"><div className="modal-box"><div className="modal-header"><h3>Execute Correlation Scan</h3><button className="modal-close" onClick={() => setShowRunModal(false)}>×</button></div>
        <form onSubmit={handleRunScan} className="modal-body form-grid">
          <div className="span-2"><label>Title *</label><input required value={scanTitle} onChange={e => setScanTitle(e.target.value)} /></div>
          <div className="span-2"><label>Environment</label><select value={targetEnv} onChange={e => setTargetEnv(e.target.value)}><option value="production">Production</option><option value="staging">Staging</option><option value="internal">Internal</option><option value="">All</option></select></div>
          <div className="modal-actions span-2"><button type="button" className="btn-secondary" onClick={() => setShowRunModal(false)}>Cancel</button><button type="submit" className="btn-primary">Execute</button></div>
        </form></div></div>
      )}
      {activeScoreBreakdown && (
        <div className="modal-backdrop" onClick={() => setActiveScoreBreakdown(null)}><div className="modal-box" onClick={e => e.stopPropagation()}><div className="modal-header"><h3>Score Breakdown: {activeScoreBreakdown.cve_id}</h3><button className="modal-close" onClick={() => setActiveScoreBreakdown(null)}>×</button></div>
        <div className="modal-body">
          {[["CVSS Component", activeScoreBreakdown.score_breakdown.cvss_component], ["EPSS Exploitability", activeScoreBreakdown.score_breakdown.epss_component], ["CISA KEV Boost", activeScoreBreakdown.score_breakdown.cisa_kev_boost], ["Exposure Boost", activeScoreBreakdown.score_breakdown.exposure_boost], ["Subtotal", activeScoreBreakdown.score_breakdown.raw_subtotal], ["Multiplier", `x${activeScoreBreakdown.score_breakdown.criticality_multiplier}`]].map(([k, v]) => <div key={k as string}>{k}: <strong>{v}</strong></div>)}
          <div className="mt-2 font-bold text-accent">Final Score: {activeScoreBreakdown.composite_risk_score} / 100 ({activeScoreBreakdown.priority_tier})</div>
        </div></div></div>
      )}
    </div>
  );
};
