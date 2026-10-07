import { render, screen, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { ScansView } from "../components/ScansView";
import { api } from "../api/client";
import { AuthProvider } from "../context/AuthContext";

vi.mock("../api/client", () => ({
  api: {
    auth: {
      getStatus: vi.fn()
    },
    scans: {
      list: vi.fn(),
      get: vi.fn(),
      run: vi.fn(),
      exportUrl: vi.fn().mockReturnValue("/api/v1/scans/scan-1/export")
    }
  }
}));

describe("ScansView Component", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(api.auth.getStatus).mockResolvedValue({
      authenticated: true,
      user: {
        id: "usr-1",
        email: "analyst@example.com",
        username: "analyst",
        full_name: "Security Analyst",
        role: "analyst",
        is_active: true,
        created_at: "2026-10-07T00:00:00Z"
      },
      csrf_token: "csrf-val",
      demo_mode: true,
      oidc_configured: false
    });
  });

  it("renders correlation scan findings with composite score and remediation advice", async () => {
    const mockScan = {
      id: "scan-1",
      title: "Production Perimeter Scan",
      target_environment: "production",
      scanned_assets_count: 5,
      findings_count: 1,
      critical_count: 1,
      high_count: 0,
      medium_count: 0,
      low_count: 0,
      created_by: "analyst@example.com",
      created_at: "2026-10-07T00:00:00Z",
      findings: [
        {
          id: "f-1",
          scan_id: "scan-1",
          asset_id: "a-1",
          vulnerability_id: "CVE-2021-44228",
          asset_name: "logging-service-prod",
          asset_component: "log4j",
          asset_version: "2.14.1",
          cve_id: "CVE-2021-44228",
          cvss_score: 10.0,
          epss_score: 0.97,
          is_cisa_kev: true,
          asset_criticality: "tier_1",
          internet_exposed: true,
          composite_risk_score: 100.0,
          priority_tier: "CRITICAL" as const,
          match_reason: "Component 'log4j' version '2.14.1' matches affected spec '< 2.15.0'.",
          score_breakdown: {
            cvss_component: 40.0,
            epss_component: 24.25,
            cisa_kev_boost: 15.0,
            exposure_boost: 10.0,
            raw_subtotal: 89.25,
            criticality_multiplier: 1.2,
            final_score: 100.0
          },
          remediation_recommendation: "Upgrade log4j on logging-service-prod from 2.14.1 to 2.16.0.",
          created_at: "2026-10-07T00:00:00Z"
        }
      ]
    };

    vi.mocked(api.scans.list).mockResolvedValue({
      items: [mockScan],
      total: 1,
      page: 1,
      page_size: 20,
      total_pages: 1
    });

    vi.mocked(api.scans.get).mockResolvedValue(mockScan);

    render(
      <AuthProvider>
        <ScansView />
      </AuthProvider>
    );

    await waitFor(() => {
      expect(screen.getAllByText("Production Perimeter Scan").length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText("logging-service-prod")).toBeInTheDocument();
      expect(screen.getByText("CVE-2021-44228")).toBeInTheDocument();
      expect(screen.getByText(/Upgrade log4j on logging-service-prod/i)).toBeInTheDocument();
    });
  });
});
