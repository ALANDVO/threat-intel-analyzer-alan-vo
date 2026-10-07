import React, { useEffect, useState } from "react";
import { ShieldAlert, RefreshCw, Filter, AlertCircle } from "lucide-react";
import { api } from "../api/client";
import { AuditLog } from "../types";
export const AuditLogView: React.FC = () => {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionFilter, setActionFilter] = useState("");
  const fetchLogs = async () => {
  try {
  setLoading(true); setError(null);
  const res = await api.audit.list(page, 20, actionFilter || undefined);
  setLogs(res.items); setTotal(res.total);
  } catch (err: any) { setError(err.message || "Failed to load audit logs"); }
  finally { setLoading(false); }
  };
  useEffect(() => { fetchLogs(); }, [page, actionFilter]);
  return (
  <div className="audit-view">
  <div className="view-header">
  <div><h2>System Audit Trail & Compliance Log</h2><p className="view-subtitle">Immutable event records for vulnerability mutations and scans.</p></div>
  <button className="btn-secondary" onClick={fetchLogs}><RefreshCw size={16} /> Refresh</button>
  </div>
  {error && <div className="alert-box alert-danger"><AlertCircle size={18} /><span>{error}</span></div>}
  <div className="toolbar-container">
  <div className="filter-group">
  <span className="filter-label"><Filter size={14} /> Action:</span>
  {["", "vulnerability.create", "asset.create", "scan.execute", "briefing.generate"].map((act) => (
  <button key={act} className={`filter-chip ${actionFilter === act ? "active" : ""}`} onClick={() => { setActionFilter(act); setPage(1); }}>
  {act ? act.replace(".", " / ") : "ALL"}
  </button>
  ))}
  </div>
  </div>
  {loading ? <div className="state-container loading-state"><p>Loading audit trail...</p></div> : logs.length === 0 ? (
  <div className="state-container empty-state"><ShieldAlert size={48} className="text-muted" /><h3>No Audit Records</h3></div>
  ) : (
  <div className="table-responsive">
  <table className="data-table">
  <thead><tr><th>Timestamp</th><th>Actor</th><th>Role</th><th>Action</th><th>Target</th><th>Details</th></tr></thead>
  <tbody>{logs.map((log) => (
  <tr key={log.id}>
  <td className="text-xs font-mono text-muted">{new Date(log.created_at).toISOString()}</td>
  <td className="font-semibold text-white">{log.actor_email}</td>
  <td><span className={`user-role-tag role-${log.actor_role}`}>{log.actor_role}</span></td>
  <td><code>{log.action}</code></td>
  <td className="text-xs"><span className="badge badge-neutral">{log.resource_type}</span> {log.resource_id}</td>
  <td className="text-xs font-mono text-muted">{JSON.stringify(log.details)}</td>
  </tr>
  ))}</tbody>
  </table>
  <div className="pagination-bar">
  <span>Showing {logs.length} of {total} records</span>
  <div className="pagination-controls">
  <button className="btn-secondary btn-sm" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>Prev</button>
  <button className="btn-secondary btn-sm" disabled={logs.length < 20 || page * 20 >= total} onClick={() => setPage((p) => p + 1)}>Next</button>
  </div>
  </div>
  </div>
  )}
  </div>
  );
};
