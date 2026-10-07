import { render, screen, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import App from "../App";
import { api } from "../api/client";

vi.mock("../api/client", () => ({
  api: {
    auth: {
      getStatus: vi.fn(),
      demoLogin: vi.fn(),
      logout: vi.fn()
    },
    vulnerabilities: { list: vi.fn() },
    assets: { list: vi.fn() },
    scans: { list: vi.fn() }
  }
}));

describe("App Root Component", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders splash login screen when unauthenticated in demo mode", async () => {
    vi.mocked(api.auth.getStatus).mockResolvedValue({
      authenticated: false,
      user: null,
      csrf_token: null,
      demo_mode: true,
      oidc_configured: false
    });

    render(<App />);

    await waitFor(() => {
      expect(screen.getByText("Threat Intel Analyzer")).toBeInTheDocument();
    });

    expect(screen.getByText(/LOCAL DEMO MODE ACTIVE/i)).toBeInTheDocument();
    expect(screen.getByText(/Sign In as Security Analyst/i)).toBeInTheDocument();
    expect(screen.getByText(/alanvo@gmail.com/i)).toBeInTheDocument();
  });

  it("renders dashboard and navigation when authenticated", async () => {
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
      csrf_token: "mock-csrf-token",
      demo_mode: false,
      oidc_configured: true
    });

    vi.mocked(api.vulnerabilities.list).mockResolvedValue({
      items: [],
      total: 0,
      page: 1,
      page_size: 10,
      total_pages: 1
    });

    vi.mocked(api.assets.list).mockResolvedValue({
      items: [],
      total: 0,
      page: 1,
      page_size: 10,
      total_pages: 1
    });

    vi.mocked(api.scans.list).mockResolvedValue({
      items: [],
      total: 0,
      page: 1,
      page_size: 5,
      total_pages: 1
    });

    render(<App />);

    await waitFor(() => {
      expect(screen.getByText("Security Analyst")).toBeInTheDocument();
      expect(screen.getByText("Overview")).toBeInTheDocument();
      expect(screen.getByText("Vulnerabilities & IOCs")).toBeInTheDocument();
      expect(screen.getByText("Tech Stack Assets")).toBeInTheDocument();
    });
  });
});
