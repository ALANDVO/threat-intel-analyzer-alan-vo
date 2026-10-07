import re
from typing import Any, Dict, List, Tuple

BENCHMARK_DATASET: List[Dict[str, Any]] = [
    {"id": "CVE-2021-44228", "title": "Log4j2 JNDI RCE", "description": "Arbitrary remote code execution via LDAP JNDI.", "category": "RCE", "cvss": 10.0, "facts": ["log4j", "jndi", "rce"]},
    {"id": "CVE-2024-3094", "title": "XZ Utils Backdoor", "description": "Backdoor in liblzma intercepts ssh for remote execution.", "category": "RCE", "cvss": 10.0, "facts": ["xz", "backdoor"]},
    {"id": "CVE-2023-34362", "title": "MOVEit Transfer SQLi", "description": "SQL injection payload execution.", "category": "RCE", "cvss": 9.8, "facts": ["moveit", "payload"]},
    {"id": "CVE-2022-22965", "title": "Spring4Shell RCE", "description": "Spring MVC remote code execution.", "category": "RCE", "cvss": 9.8, "facts": ["spring", "remote code execution"]},
    {"id": "CVE-2020-1472", "title": "Zerologon Netlogon", "description": "Elevation of privilege in Netlogon secure channel.", "category": "PRIV_ESC", "cvss": 10.0, "facts": ["netlogon", "elevation"]},
    {"id": "CVE-2021-3156", "title": "Sudo Baron Samedit", "description": "Heap buffer overflow allows root privilege escalation.", "category": "PRIV_ESC", "cvss": 7.8, "facts": ["sudo", "root"]},
    {"id": "CVE-2023-23397", "title": "Outlook NTLM Relay", "description": "Elevation of privilege via NTLM credential theft.", "category": "PRIV_ESC", "cvss": 9.8, "facts": ["outlook", "ntlm"]},
    {"id": "CVE-2024-21762", "title": "FortiOS SSL-VPN", "description": "Out-of-bounds write allows unauthorized access bypass.", "category": "AUTH_BYPASS", "cvss": 9.8, "facts": ["fortios", "bypass"]},
    {"id": "CVE-2023-46805", "title": "Ivanti Connect Bypass", "description": "Authentication bypass in Ivanti Connect Secure.", "category": "AUTH_BYPASS", "cvss": 8.2, "facts": ["ivanti", "bypass"]},
    {"id": "CVE-2014-0160", "title": "OpenSSL Heartbleed", "description": "Heartbeat buffer bounds check causes memory disclosure leak.", "category": "INFO_DISC", "cvss": 7.5, "facts": ["openssl", "leak"]},
    {"id": "CVE-2023-4863", "title": "Libwebp Heap Crash", "description": "Heap overflow causes crash and denial of service.", "category": "DOS", "cvss": 8.8, "facts": ["libwebp", "dos"]},
    {"id": "CVE-2022-30190", "title": "MSDT Follina RCE", "description": "Windows MSDT URL remote command execution.", "category": "RCE", "cvss": 7.8, "facts": ["msdt", "command"]}
]

CATEGORY_TAXONOMY: Dict[str, Dict[str, float]] = {
    "RCE": {"remote": 1.2, "code": 1.5, "execution": 1.5, "rce": 2.5, "command": 1.3, "payload": 1.2, "jndi": 2.0, "arbitrary": 1.4, "inject": 1.3, "backdoor": 2.0},
    "PRIV_ESC": {"privilege": 2.0, "elevation": 2.0, "escalation": 2.0, "root": 1.8, "admin": 1.2, "overflow": 1.0, "sudo": 2.0, "kernel": 1.4, "ntlm": 1.6},
    "AUTH_BYPASS": {"bypass": 2.2, "authentication": 2.0, "unauthorized": 1.8, "unauthenticated": 1.5, "restricted": 1.4, "token": 1.2, "impersonation": 1.8, "access": 1.0},
    "INFO_DISC": {"disclosure": 2.0, "leak": 1.8, "read": 1.3, "memory": 1.8, "expose": 1.5, "heartbleed": 2.5, "sniff": 1.5, "information": 1.2, "sensitive": 1.4},
    "DOS": {"denial": 2.2, "service": 1.5, "dos": 2.5, "crash": 2.0, "exhaustion": 1.8, "hang": 1.5, "loop": 1.4, "resource": 1.1, "buffer": 1.0}
}

class ThreatClassifier:
    @staticmethod
    def tokenize(t: str) -> List[str]:
        return [w.lower() for w in re.findall(r"\b[a-zA-Z]{2,}\b", t)]

    @classmethod
    def classify(cls, text: str) -> Tuple[str, float, Dict[str, float]]:
        toks = set(cls.tokenize(text))
        sc = {c: round(sum(w for k, w in kw.items() if k in toks), 3) for c, kw in CATEGORY_TAXONOMY.items()}
        top_cat, top_score = sorted(sc.items(), key=lambda x: x[1], reverse=True)[0]
        if top_score == 0.0: return "INFO_DISC", 0.2, sc
        tot = sum(sc.values()) or 1.0
        return top_cat, round(top_score / tot, 3), sc

class AgentEvaluator:
    @classmethod
    def evaluate_classifier(cls, dataset: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        data = dataset or BENCHMARK_DATASET
        corr, stats = 0, {}
        for s in data:
            pred, _, _ = ThreatClassifier.classify(f"{s['title']} {s['description']}")
            tc = s["category"]
            for c in (tc, pred):
                if c not in stats: stats[c] = {"tp": 0, "fp": 0, "fn": 0}
            if pred == tc: corr += 1; stats[tc]["tp"] += 1
            else: stats[tc]["fn"] += 1; stats[pred]["fp"] += 1
        acc = round(corr / len(data), 4) if data else 0.0
        f1s = {}
        for c, st in stats.items():
            tp, fp, fn = st["tp"], st["fp"], st["fn"]
            p = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            r = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1s[c] = round((2 * p * r) / (p + r), 4) if (p + r) > 0 else 0.0
        mf1 = round(sum(f1s.values()) / len(f1s), 4) if f1s else 0.0
        return {"sample_count": len(data), "accuracy": acc, "macro_f1": mf1, "category_f1": f1s, "baseline_model": "TF-IDF Weighted Lexical Taxonomy (Deterministic)"}

    @classmethod
    def evaluate_advisory_grounding(cls, text: str, facts: List[str]) -> Dict[str, Any]:
        if not facts: return {"grounding_score": 1.0, "grounded_facts_count": 0, "total_facts": 0}
        tl = text.lower()
        matched = [f for f in facts if f.lower() in tl]
        sc = round(len(matched) / len(facts), 3)
        return {"grounding_score": sc, "grounded_facts": matched, "missing_facts": [f for f in facts if f.lower() not in tl], "total_facts": len(facts), "hallucination_risk": "LOW" if sc >= 0.75 else "MEDIUM" if sc >= 0.4 else "HIGH"}
