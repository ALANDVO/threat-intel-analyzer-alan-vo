import { render, screen, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { VulnerabilitiesView } from "../components/VulnerabilitiesView";
import { api } from "../api/client";
import { AuthProvider } from "../context/AuthContext";

vi.mock("../api/client", () => ({
  api: {
    auth: {
      getStatus: vi.fn()
    },
    vulnerabilities: {
      list: vi.fn(),
      create: vi.fn(),
      delete: vi.fn(),
      extractIOCs: vi.fn()
    }
  }
}));

describe("VulnerabilitiesView Component", () => {
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

  it("renders vulnerability list with CVE IDs, severity badges, and CISA KEV tags", async () => {
    vi.mocked(api.vulnerabilities.list).mockResolvedValue({
      items: [
        {
          id: "CVE-2024-3094",
          title: "XZ Utils Embedded Malicious Backdoor",
          description: "Malicious backdoor in liblzma SSH authentication path",
          severity: "critical",
          cvss_v3_score: 10.0,
          epss_score: 0.88,
          is_cisa_kev: true,
          affected_packages: [{ component: "xz-utils", version_range: ">= 5.6.0" }],
          iocs: [{ type: "ipv4", value: "198.51.100.42", defanged: "198.51.100[.]42" }],
          source: "NVD",
          tags: ["backdoor"],
          created_at: "2026-10-07T00:00:00Z",
          updated_at: "2026-10-07T00:00:00Z"
        }
      ],
      total: 1,
      page: 1,
      page_size: 10,
      total_pages: 1
    });

    render(
      <AuthProvider>
        <VulnerabilitiesView />
      </AuthProvider>
    );

    await waitFor(() => {
      expect(screen.getByText("CVE-2024-3094")).toBeInTheDocument();
      expect(screen.getByText("XZ Utils Embedded Malicious Backdoor")).toBeInTheDocument();
      expect(screen.getAllByText("CRITICAL").length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByText("KEV").length).toBeGreaterThanOrEqual(1);
    });
  });

  it("displays empty state when no records match filter criteria", async () => {
    vi.mocked(api.vulnerabilities.list).mockResolvedValue({
      items: [],
      total: 0,
      page: 1,
      page_size: 10,
      total_pages: 0
    });

    render(
      <AuthProvider>
        <VulnerabilitiesView />
      </AuthProvider>
    );

    await waitFor(() => {
      expect(screen.getByText("No Vulnerabilities Found")).toBeInTheDocument();
    });
  });
});
