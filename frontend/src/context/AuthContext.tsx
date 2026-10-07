import React, { createContext, useContext, useEffect, useState } from "react";
import { api } from "../api/client";
import { Role, UserProfile } from "../types";
interface AuthContextType {
  user: UserProfile | null;
  authenticated: boolean;
  loading: boolean;
  demoMode: boolean;
  oidcConfigured: boolean;
  error: string | null;
  loginAsDemo: (role: Role) => Promise<void>;
  loginOidc: () => Promise<void>;
  logout: () => Promise<void>;
  refreshAuth: () => Promise<void>;
}
const AuthContext = createContext<AuthContextType | undefined>(undefined);
export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<UserProfile | null>(null);
  const [authenticated, setAuthenticated] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(true);
  const [demoMode, setDemoMode] = useState<boolean>(false);
  const [oidcConfigured, setOidcConfigured] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const refreshAuth = async () => {
  try {
  setLoading(true);
  setError(null);
  const status = await api.auth.getStatus();
  setAuthenticated(status.authenticated);
  setUser(status.user);
  setDemoMode(status.demo_mode);
  setOidcConfigured(status.oidc_configured);
  } catch (err: any) {
  setError(err.message || "Failed to load authentication status");
  setAuthenticated(false);
  setUser(null);
  } finally {
  setLoading(false);
  }
  };
  useEffect(() => {
  refreshAuth();
  }, []);
  const loginAsDemo = async (role: Role) => {
  try {
  setLoading(true);
  setError(null);
  const res = await api.auth.demoLogin(role);
  setUser(res.user);
  setAuthenticated(true);
  } catch (err: any) {
  setError(err.message || "Demo login failed");
  throw err;
  } finally {
  setLoading(false);
  }
  };
  const loginOidc = async () => {
  try {
  const res = await api.auth.getLoginUrl();
  window.location.href = res.auth_url;
  } catch (err: any) {
  setError(err.message || "Failed to initialize OIDC login");
  }
  };
  const logout = async () => {
  try {
  setLoading(true);
  await api.auth.logout();
  setUser(null);
  setAuthenticated(false);
  } catch (err: any) {
  setError(err.message || "Logout failed");
  } finally {
  setLoading(false);
  }
  };
  return (
  <AuthContext.Provider
  value={{
  user,
  authenticated,
  loading,
  demoMode,
  oidcConfigured,
  error,
  loginAsDemo,
  loginOidc,
  logout,
  refreshAuth
  }}
  >
  {children}
  </AuthContext.Provider>
  );
};
export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
  throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
};
