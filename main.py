#!/usr/bin/env python3
"""threat-intel-analyzer-alan-vo — AI-powered threat intelligence platform that ingests CVEs, IOC feeds, and news to produce prioritized, actionable security briefings with LLM-generated context and risk scoring."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from llm_client import LLM
def scan(args):
    """Scan a tech stack against known CVEs using LLM risk scoring."""
    llm = LLM()
    stack = args.stack.split(",")
    print(f"Scanning stack: {stack}")
    # Load CVE data
    cves = load_cves(min_severity=args.severity)
    print(f"Loaded {len(cves)} CVEs (severity >= {args.severity})")
    # Score each CVE against the stack
    results = []
    for cve in cves:
        score = llm.classify(
            text=f"CVE: {cve['id']}\nDescription: {cve['description']}\nAffected: {cve['affected']}\nStack: {stack}",
            categories=["critical", "high", "medium", "low", "not-affected"],
            instructions=f"Assess this CVE against our tech stack: {stack}. Consider exploitability, patch availability, and business impact.\n"
        )
        results.append({"cve": cve, "assessment": score})
    # Sort by risk
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "not-affected": 4}
    results.sort(key=lambda x: sev_order.get(x["assessment"]["category"], 5))
    # Output
    top = [r for r in results if r["assessment"]["category"] in ("critical", "high")]
    print(f"\n{'='*60}\nTOP RISKS: {len(top)}\n{'='*60}")
    for r in top[:10]:
        print(f"  {r['cve']['id']} [{r['assessment']['category'].upper()}] {r['cve']['description'][:80]}")
        print(f"    Why: {r['assessment']['reasoning'][:100]}")
    if args.output:
        write_brief(results, args.output)
    return results

def query(args):
    """Natural language query against threat intel."""
    llm = LLM()
    cves = load_cves()
    context = json.dumps([{"id": c["id"], "desc": c["description"][:100]} for c in cves[:50]], indent=2)
    answer = llm.generate(
        f"Threat database (top 50 by severity):\n{context}\n\nQuestion: {args.text}\n\nGive specific CVE IDs, risk levels, and recommended actions.",
        system="You are a senior security analyst. Be specific, cite CVE IDs, and prioritize by exploitability."
    )
    print(f"\n{'='*60}\nANSWER\n{'='*60}\n{answer}")

def brief(args):
    """Generate a security briefing."""
    llm = LLM()
    cves = load_cves(min_severity="high")
    summary = llm.generate(
        f"Generate an executive security briefing for {args.date}.\nTop CVEs: {json.dumps(cves[:20], indent=2)}\n\nFormat: 1) Executive Summary 2) Top 5 Threats 3) Recommended Actions 4) Watch List",
        system="You are a CISO writing a briefing for the board. Concise, actionable, no fluff."
    )
    print(summary)
    if args.output:
        with open(args.output, "w") as f:
            f.write(f"# Security Briefing — {args.date}\n\n{summary}\n")
        print(f"\nWritten to {args.output}")

def load_cves(min_severity="medium"):
    """Load CVEs from local cache or NVD API."""
    cache = os.path.join(os.path.dirname(__file__), "cve_cache.json")
    if os.path.exists(cache):
        with open(cache) as f:
            cves = json.load(f)
    else:
        cves = fetch_nvd(min_severity)
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    min_rank = sev_rank.get(min_severity, 2)
    return [c for c in cves if sev_rank.get(c.get("severity", "low"), 1) >= min_rank]

def fetch_nvd(min_severity="medium"):
    """Fetch from NVD API."""
    import requests
    r = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params={"keywordSearch": "RCE", "resultsPerPage": 50}, timeout=30)
    r.raise_for_status()
    data = r.json()
    cves = []
    for item in data.get("vulnerabilities", []):
        c = item["cve"]
        score = 0
        for m in c.get("metrics", {}).get("cvssMetricV31", []):
            score = max(score, m["cvssData"]["baseScore"])
        desc = c.get("descriptions", [{}])[0].get("value", "")
        cves.append({"id": c["id"], "description": desc, "severity": "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low", "affected": "", "score": score})
    with open(os.path.join(os.path.dirname(__file__), "cve_cache.json"), "w") as f:
        json.dump(cves, f)
    return cves

def write_brief(results, path):
    lines = [f"# Security Scan Results\n", f"Generated: {datetime.datetime.now().isoformat()}\n", f"Total CVEs assessed: {len(results)}\n"]
    for r in results[:20]:
        lines.append(f"## {r['cve']['id']} [{r['assessment']['category'].upper()}]")
        lines.append(f"Score: {r['assessment']['confidence']}")
        lines.append(f"Reasoning: {r['assessment']['reasoning']}")
        lines.append("")
    with open(path, "w") as f:
        f.write("\n".join(lines))


if __name__ == "__main__":
    main()
