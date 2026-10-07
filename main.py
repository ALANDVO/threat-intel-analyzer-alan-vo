"""threat-intel-analyzer-alan-vo CLI tool — Alan Vo (alanvo@gmail.com, GitHub ALANDVO)."""
import argparse, datetime, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backend'))
from app.core.database import SessionLocal, init_db
from app.models.entities import VulnerabilityEntity
from app.services.correlation_engine import RiskScorer

def load_cves(min_sev='medium'):
    init_db(); db = SessionLocal()
    try:
        from app.main import seed_sample_intel; seed_sample_intel()
        rk = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        return [{'id': c.id, 'title': c.title, 'severity': c.severity, 'score': c.cvss_v3_score, 'epss': c.epss_score, 'is_cisa_kev': c.is_cisa_kev, 'affected_packages': c.affected_packages} for c in db.query(VulnerabilityEntity).all() if rk.get(c.severity.lower(), 1) >= rk.get(min_sev.lower(), 2)]
    finally: db.close()

def scan(args):
    stk = [s.strip().lower() for s in args.stack.split(',') if s.strip()]
    res = []
    for c in load_cves(args.severity):
        for p in c.get('affected_packages', []):
            if p.get('component', '').lower() in stk:
                sc, tr, _ = RiskScorer.calculate_composite_score(c['score'], c['epss'], c['is_cisa_kev'], internet_exposed=True, criticality='tier_1')
                res.append({'cve': c, 'assessment': {'category': tr.lower(), 'score': sc, 'component': p['component']}})
                break
    o = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    res.sort(key=lambda x: o.get(x['assessment']['category'], 4))
    print(f"\nTOP RISKS: {len(res)}")
    for r in res[:10]: print(f"  {r['cve']['id']} [{r['assessment']['category'].upper()}] - {r['assessment']['score']}/100: {r['cve']['title']}")
    if args.output:
        with open(args.output, 'w') as f: f.write('\n'.join(f"- {r['cve']['id']}: {r['assessment']['score']}" for r in res))
    return res

def query(args):
    t = args.text.lower()
    for c in [c for c in load_cves('low') if t in c['id'].lower() or t in c['title'].lower()][:10]:
        print(f"- {c['id']} [{c['severity'].upper()}] CVSS {c['score']}: {c['title']}")

def brief(args):
    cves = load_cves('high')
    b = f"# Security Briefing — {args.date}\n" + '\n'.join(f"- {c['id']}: CVSS {c['score']} ({c['title']})" for c in cves[:5])
    print(b)
    if args.output:
        with open(args.output, 'w') as f: f.write(b)

def evaluate_ml(args):
    from app.services.ml_eval import AgentEvaluator
    r = AgentEvaluator.evaluate_classifier()
    print(f"Model: {r['baseline_model']} | Samples: {r['sample_count']} | Acc: {r['accuracy']*100:.1f}% | Macro F1: {r['macro_f1']:.4f}")
    return r

def main():
    p = argparse.ArgumentParser(description='Threat Intel Analyzer')
    sub = p.add_subparsers(dest='command')
    s = sub.add_parser('scan'); s.add_argument('--stack', default='nginx,log4j,xz-utils'); s.add_argument('--severity', default='medium'); s.add_argument('--output')
    b = sub.add_parser('brief'); b.add_argument('--date', default=datetime.date.today().isoformat()); b.add_argument('--output')
    q = sub.add_parser('query'); q.add_argument('text')
    sub.add_parser('eval')
    srv = sub.add_parser('serve'); srv.add_argument('--host', default='127.0.0.1'); srv.add_argument('--port', type=int, default=8000)
    a = p.parse_args()
    if a.command == 'scan': scan(a)
    elif a.command == 'brief': brief(a)
    elif a.command == 'query': query(a)
    elif a.command == 'eval': evaluate_ml(a)
    elif a.command == 'serve':
        import uvicorn; uvicorn.run('app.main:app', host=a.host, port=a.port)
    else: p.print_help()

if __name__ == '__main__': main()
