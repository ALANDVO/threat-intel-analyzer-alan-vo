import React from "react";
import { Shield, LogOut, AlertTriangle } from "lucide-react";
import { useAuth } from "../context/AuthContext";
export const Navbar: React.FC<{ activeTab: string; setActiveTab: (tab: string) => void }> = ({ activeTab, setActiveTab }) => {
  const { user, authenticated, demoMode, loginAsDemo, logout } = useAuth();
  const navItems = [
  { id: "overview", label: "Overview" },
  { id: "vulnerabilities", label: "Vulnerabilities & IOCs" },
  { id: "assets", label: "Tech Stack Assets" },
  { id: "scans", label: "Correlation Scans" },
  { id: "briefings", label: "Executive Briefings" },
  ...(user?.role === "admin" ? [{ id: "audit", label: "Audit Log" }] : [])
  ];
  return (
  <header className="navbar-container">
  {demoMode && (
  <div className="demo-mode-banner">
  <div className="flex-center"><AlertTriangle size={14} className="banner-icon" /><span>DEMO MODE (Localhost Only — Refused in Prod)</span></div>
  {authenticated && (
  <div className="demo-role-switcher">
  <span>Switch:</span>
  <button className={`role-chip ${user?.role === "viewer" ? "active" : ""}`} onClick={() => loginAsDemo("viewer")}>Viewer</button>
  <button className={`role-chip ${user?.role === "analyst" ? "active" : ""}`} onClick={() => loginAsDemo("analyst")}>Analyst</button>
  <button className={`role-chip ${user?.role === "admin" ? "active" : ""}`} onClick={() => loginAsDemo("admin")}>Admin</button>
  </div>
  )}
  </div>
  )}
  <div className="navbar-main">
  <div className="navbar-brand" onClick={() => setActiveTab("overview")}>
  <div className="brand-logo"><Shield size={24} /></div>
  <div className="brand-titles"><span className="brand-name">Threat Intel Analyzer</span><span className="brand-subtitle">by Alan Vo</span></div>
  </div>
  {authenticated && (
  <nav className="navbar-links">
  {navItems.map((item) => (
  <button key={item.id} className={`nav-link ${activeTab === item.id ? "active" : ""}`} onClick={() => setActiveTab(item.id)}>{item.label}</button>
  ))}
  </nav>
  )}
  <div className="navbar-actions">
  {authenticated && user ? (
  <div className="user-profile-badge">
  <div className="user-details"><span className="user-name">{user.full_name || user.username}</span><span className={`user-role-tag role-${user.role}`}>{user.role.toUpperCase()}</span></div>
  <button className="btn-logout" onClick={logout} title="Sign Out"><LogOut size={16} /></button>
  </div>
  ) : (
  demoMode ? <button className="btn-primary btn-sm" onClick={() => loginAsDemo("analyst")}>Demo Login</button> :
  <a href="/api/v1/auth/login" className="btn-primary btn-sm">Keycloak Login</a>
  )}
  </div>
  </div>
  </header>
  );
};
