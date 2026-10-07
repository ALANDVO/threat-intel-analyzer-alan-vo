import React, { useState } from "react";
import { AuthProvider, useAuth } from "./context/AuthContext";
import { Navbar } from "./components/Navbar";
import { DashboardOverview } from "./components/DashboardOverview";
import { VulnerabilitiesView } from "./components/VulnerabilitiesView";
import { AssetsView } from "./components/AssetsView";
import { ScansView } from "./components/ScansView";
import { BriefingView } from "./components/BriefingView";
import { AuditLogView } from "./components/AuditLogView";
import { Shield, Lock } from "lucide-react";
const MainContent: React.FC = () => {
  const [activeTab, setActiveTab] = useState<string>("overview");
  const [briefingScanId, setBriefingScanId] = useState<string | undefined>(undefined);
  const { authenticated, loading, demoMode, loginAsDemo } = useAuth();
  if (loading) return <div className="state-container full-page"><div className="spinner"></div><p className="mt-3">Loading Threat Intel Analyzer...</p></div>;
  if (!authenticated) {
  return (
  <div className="login-splash-page">
  <div className="login-card">
  <div className="login-header">
  <Shield size={48} className="text-accent mb-2" />
  <h1>Threat Intel Analyzer</h1>
  <p className="subtitle">AI-powered threat intelligence platform ingesting CVEs, IOC feeds, and tech stack correlation.</p>
  </div>
  <div className="login-body">
  {demoMode ? (
  <div className="demo-login-box">
  <span className="demo-badge">LOCAL DEMO MODE ACTIVE</span>
  <p className="text-sm text-muted mb-4">Demo mode binds localhost and provides immediate evaluation roles.</p>
  <div className="demo-button-stack">
  <button className="btn-primary w-full" onClick={() => loginAsDemo("analyst")}>Sign In as Security Analyst</button>
  <button className="btn-secondary w-full" onClick={() => loginAsDemo("admin")}>Sign In as Administrator</button>
  <button className="btn-secondary w-full" onClick={() => loginAsDemo("viewer")}>Sign In as Read-Only Viewer</button>
  </div>
  </div>
  ) : (
  <div className="oidc-login-box">
  <p className="text-sm text-muted mb-4">Enterprise authentication via Keycloak OIDC and federated SAML.</p>
  <a href="/api/v1/auth/login" className="btn-primary btn-lg w-full flex-center"><Lock size={16} className="mr-2" /> Continue with Keycloak SSO</a>
  </div>
  )}
  </div>
  <div className="login-footer"><span>Built by <strong>Alan Vo</strong> (<a href="mailto:alanvo@gmail.com">alanvo@gmail.com</a>)</span></div>
  </div>
  </div>
  );
  }
  return (
  <div className="app-shell">
  <Navbar activeTab={activeTab} setActiveTab={setActiveTab} />
  <main className="main-content">
  {activeTab === "overview" && <DashboardOverview onNavigate={setActiveTab} />}
  {activeTab === "vulnerabilities" && <VulnerabilitiesView />}
  {activeTab === "assets" && <AssetsView />}
  {activeTab === "scans" && <ScansView onGenerateBriefing={(id) => { setBriefingScanId(id); setActiveTab("briefings"); }} />}
  {activeTab === "briefings" && <BriefingView initialScanId={briefingScanId} />}
  {activeTab === "audit" && <AuditLogView />}
  </main>
  <footer className="app-footer">
  <div><strong>Threat Intel Analyzer</strong> — Developed by <a href="https://github.com/ALANDVO" target="_blank" rel="noreferrer">Alan Vo</a> (<a href="mailto:alanvo@gmail.com">alanvo@gmail.com</a>) | MIT License</div>
  </footer>
  </div>
  );
};
export const App: React.FC = () => (<AuthProvider><MainContent /></AuthProvider>);
export default App;
