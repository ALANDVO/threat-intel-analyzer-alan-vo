import React, { useEffect, useState } from "react";
import { AlertTriangle, ShieldCheck, Server, Activity, ArrowRight, RefreshCw, Zap, Cpu } from "lucide-react";
import { api } from "../api/client";
import { ThreatScan, Vulnerability, Asset, MLEvalResult } from "../types";
import { useAuth } from "../context/AuthContext";

export const DashboardOverview: React.FC<{ onNavigate: (tab: string) => void }> = ({ onNavigate }) => {
  const { user } = useAuth();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [totalVulns, setTotalVulns] = useState(0);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [totalAssets, setTotalAssets] = useState(0);
  const [recentScans, setRecentScans] = useState<ThreatScan[]>([]);
  const [mlEval, setMlEval] = useState<MLEvalResult | null>(null);

  const fetchDashboardData = async () => {
    try {
      setLoading(true); setError(null);
      const [vRes, aRes, sRes, mRes] = await Promise.all([
        api.vulnerabilities.list({ page_size: 100 }),
        api.assets.list({ page_size: 100 }),
        api.scans.list(1, 5),
        api.ml.evaluate().catch(() => null)
      ]);
      setVulns(vRes.items); setTotalVulns(vRes.total);
      setAssets(aRes.items); setTotalAssets(aRes.total);
      setRecentScans(sRes.items);
      if (mRes) setMlEval(mRes);
    } catch (e: any) { setError(e.message || "Failed to load metrics"); }
    finally { setLoading(false); }
  };

  useEffect(() => { fetchDashboardData(); }, []);

  if (loading) return <div className="state-container"><RefreshCw className="animate-spin text-accent" size={36} /><p>Aggregating threat metrics...</p></div>;
  if (error) return <div className="state-container"><AlertTriangle size={36} className="text-danger" /><h3>Failed to Load Dashboard</h3><p>{error}</p><button className="btn-secondary" onClick={fetchDashboardData}>Retry</button></div>;

  const crit = vulns.filter(v => v.severity === "critical").length;
  const kev = vulns.filter(v => v.is_cisa_kev).length;
  const exp = assets.filter(a => a.internet_exposed).length;

  return (
    <div className="dashboard-view">
      <div className="view-header">
        <div><h2>Security Posture & Intelligence Dashboard</h2><p className="view-subtitle">Attack surface correlation, CVSS telemetry, and exposure metrics.</p></div>
        <div className="header-actions">
          <button className="btn-secondary" onClick={fetchDashboardData}><RefreshCw size={16} /> Refresh</button>
          {user?.role !== "viewer" && <button className="btn-primary" onClick={() => onNavigate("scans")}><Zap size={16} /> Launch Scan</button>}
        </div>
      </div>
      <div className="metrics-grid">
        {[
          ["Critical CVE Exposures", crit, "CVSS 9.0–10.0", "border-danger", "text-danger", AlertTriangle],
          ["CISA KEV Active", kev, "In-the-wild attacks", "border-warning", "text-warning", Activity],
          ["Enrolled Assets", totalAssets, `${exp} internet-exposed`, "border-info", "", Server],
          ["Total Cataloged CVEs", totalVulns, "Verified threat DB", "border-success", "", ShieldCheck]
        ].map(([l, v, fn, bc, tc, Icon]: any) => (
          <div key={l} className={`metric-card ${bc}`}>
            <div className="metric-icon"><Icon size={24} className={tc} /></div>
            <div><span className="metric-label">{l}</span><div className={`metric-value ${tc}`}>{v}</div><span className="metric-footnote">{fn}</span></div>
          </div>
        ))}
      </div>
      {mlEval && (
        <div className="panel-box mb-4">
          <div className="panel-header"><h3><Cpu size={16} className="inline mr-1 text-accent" /> AI / ML Model Benchmark: Threat Taxonomy Evaluation</h3><span className="badge badge-success">Deterministic Baseline</span></div>
          <div className="metrics-grid mt-2">
            <div className="stat-pill"><span>Samples:</span><strong>{mlEval.sample_count} records</strong></div>
            <div className="stat-pill border-success"><span>Accuracy:</span><strong className="text-success">{(mlEval.accuracy * 100).toFixed(1)}%</strong></div>
            <div className="stat-pill border-info"><span>Macro F1:</span><strong className="text-info">{mlEval.macro_f1}</strong></div>
            <div className="stat-pill"><span>Algorithm:</span><strong className="text-xs">{mlEval.baseline_model}</strong></div>
          </div>
        </div>
      )}
      <div className="dashboard-columns">
        <div className="panel-box">
          <div className="panel-header"><h3>Recent Correlation Scans</h3><button className="btn-secondary btn-sm" onClick={() => onNavigate("scans")}>All Scans <ArrowRight size={14} /></button></div>
          {recentScans.length === 0 ? <p className="text-muted text-sm mt-2">No correlation scans executed yet.</p> : (
            <table className="data-table">
              <thead><tr><th>Scan Title</th><th>Assets</th><th>Findings</th><th>Crit/High</th></tr></thead>
              <tbody>{recentScans.map(s => (
                <tr key={s.id}>
                  <td className="font-semibold">{s.title}</td><td>{s.scanned_assets_count}</td>
                  <td><span className="badge badge-neutral">{s.findings_count}</span></td>
                  <td><span className="badge badge-danger">{s.critical_count}</span> <span className="badge badge-warning">{s.high_count}</span></td>
                </tr>
              ))}</tbody>
            </table>
          )}
        </div>
        <div className="panel-box">
          <div className="panel-header"><h3>Active Threat Intelligence Signals</h3><button className="btn-secondary btn-sm" onClick={() => onNavigate("vulnerabilities")}>Catalog <ArrowRight size={14} /></button></div>
          {vulns.length === 0 ? <p className="text-muted text-sm mt-2">Threat catalog is empty.</p> : (
            <div>{vulns.filter(v => v.severity === "critical" || v.is_cisa_kev).slice(0, 3).map(v => (
              <div key={v.id} className="threat-signal-card mb-2">
                <div className="view-header mb-1"><div><span className="font-mono text-accent font-bold">{v.id}</span> <span className={`badge badge-${v.severity}`}>{v.severity.toUpperCase()}</span>{v.is_cisa_kev && <span className="badge badge-kev ml-1">KEV</span>}</div><span>CVSS {v.cvss_v3_score}</span></div>
                <p className="text-sm">{v.title}</p>
              </div>
            ))}</div>
          )}
        </div>
      </div>
    </div>
  );
};
