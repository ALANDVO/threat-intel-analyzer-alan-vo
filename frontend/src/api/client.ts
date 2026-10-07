import { Asset, AuthStatus, AuditLog, MLEvalResult, PaginatedResponse, Role, SecurityBriefing, ThreatScan, Vulnerability } from "../types";

const gc = (n: string) => document.cookie.match(new RegExp(`(^| )${n}=([^;]+)`))?.[2] ? decodeURIComponent(document.cookie.match(new RegExp(`(^| )${n}=([^;]+)`))![2]) : null;
const qs = (o: Record<string, any>) => new URLSearchParams(Object.entries(o).filter(([_, v]) => v !== undefined && v !== "").map(([k, v]) => [k, String(v)])).toString();

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); this.name = "ApiError"; }
}

async function req<T>(url: string, opts: RequestInit = {}): Promise<T> {
  const h = new Headers(opts.headers || {});
  h.set("Accept", "application/json");
  const m = (opts.method || "GET").toUpperCase();
  if (["POST", "PUT", "DELETE", "PATCH"].includes(m)) {
    const c = gc("threat_intel_csrf");
    if (c) h.set("X-CSRF-Token", c);
    if (!h.has("Content-Type") && !(opts.body instanceof FormData)) h.set("Content-Type", "application/json");
  }
  const r = await fetch(url, { ...opts, headers: h, credentials: "include" });
  if (!r.ok) {
    let msg = `Request failed (${r.status})`;
    try { msg = (await r.json()).detail || msg; } catch {}
    throw new ApiError(r.status, msg);
  }
  return r.status === 204 ? ({} as T) : r.json();
}

const p = (url: string, b: any, m = "POST") => req<any>(url, { method: m, body: JSON.stringify(b) });

export const api = {
  auth: {
    getStatus: () => req<AuthStatus>("/api/v1/auth/me"),
    getLoginUrl: () => req<{ auth_url: string }>("/api/v1/auth/login"),
    logout: () => req<{ message: string }>("/api/v1/auth/logout", { method: "POST" }),
    demoLogin: (role: Role) => p("/api/v1/auth/demo-login", { role })
  },
  vulnerabilities: {
    list: (params: any = {}) => req<PaginatedResponse<Vulnerability>>(`/api/v1/vulnerabilities?${qs(params)}`),
    get: (id: string) => req<Vulnerability>(`/api/v1/vulnerabilities/${id}`),
    create: (d: any) => p("/api/v1/vulnerabilities", d),
    importBatch: (vulnerabilities: any) => p("/api/v1/vulnerabilities/import", { vulnerabilities }),
    extractIOCs: (raw_text: string) => p("/api/v1/vulnerabilities/extract-iocs", { raw_text }),
    delete: (id: string) => req<void>(`/api/v1/vulnerabilities/${id}`, { method: "DELETE" })
  },
  assets: {
    list: (params: any = {}) => req<PaginatedResponse<Asset>>(`/api/v1/assets?${qs(params)}`),
    get: (id: string) => req<Asset>(`/api/v1/assets/${id}`),
    create: (d: any) => p("/api/v1/assets", d),
    update: (id: string, d: any) => p(`/api/v1/assets/${id}`, d, "PUT"),
    delete: (id: string) => req<void>(`/api/v1/assets/${id}`, { method: "DELETE" })
  },
  scans: {
    run: (title: string, target_environment?: string) => p("/api/v1/scans/run", { title, target_environment }),
    list: (page = 1, page_size = 10) => req<PaginatedResponse<ThreatScan>>(`/api/v1/scans?${qs({ page, page_size })}`),
    get: (id: string) => req<ThreatScan>(`/api/v1/scans/${id}`),
    exportUrl: (id: string) => `/api/v1/scans/${id}/export`
  },
  briefings: {
    generate: (title: string, target_date: string, scan_id?: string) => p("/api/v1/briefings/generate", { title, target_date, scan_id }),
    list: (page = 1, page_size = 10) => req<PaginatedResponse<SecurityBriefing>>(`/api/v1/briefings?${qs({ page, page_size })}`),
    get: (id: string) => req<SecurityBriefing>(`/api/v1/briefings/${id}`),
    requestAdvisory: (id: string) => req<any>(`/api/v1/briefings/${id}/advisory`, { method: "POST" }),
    exportMarkdownUrl: (id: string) => `/api/v1/briefings/${id}/export-markdown`
  },
  audit: { list: (page = 1, page_size = 20, action?: string) => req<PaginatedResponse<AuditLog>>(`/api/v1/audit?${qs({ page, page_size, action })}`) },
  ml: {
    evaluate: () => req<MLEvalResult>("/api/v1/ml/evaluate"),
    classify: (text: string) => p("/api/v1/ml/classify", { text })
  },
  health: { check: () => req<any>("/healthz") }
};
