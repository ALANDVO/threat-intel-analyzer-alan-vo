import math, re
from typing import Dict, List, Tuple
from app.models.schemas import IOCItem

class CVSS31Calculator:
    AV = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}
    AC = {'L': 0.77, 'H': 0.44}
    UI = {'N': 0.85, 'R': 0.62}
    CIA = {'H': 0.56, 'L': 0.22, 'N': 0.0}
    PR = {'U': {'N': 0.85, 'L': 0.62, 'H': 0.27}, 'C': {'N': 0.85, 'L': 0.68, 'H': 0.5}}

    @staticmethod
    def _round_up(val: float) -> float:
        iv = round(val * 100000)
        return iv / 100000.0 if iv % 10000 == 0 else (math.floor(iv / 10000) + 1) / 10.0

    @classmethod
    def calculate(cls, vector_str: str) -> Tuple[float, str]:
        m = {p.split(':', 1)[0].upper(): p.split(':', 1)[1].upper() for p in vector_str.strip().split('/') if ':' in p}
        s = m.get('S', 'U')
        av, ac = cls.AV.get(m.get('AV', 'N'), 0.85), cls.AC.get(m.get('AC', 'L'), 0.77)
        pr = cls.PR.get(s, cls.PR['U']).get(m.get('PR', 'N'), 0.85)
        ui = cls.UI.get(m.get('UI', 'N'), 0.85)
        c, i, a = cls.CIA.get(m.get('C', 'N'), 0.0), cls.CIA.get(m.get('I', 'N'), 0.0), cls.CIA.get(m.get('A', 'N'), 0.0)
        iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)
        if iss <= 0.0: return 0.0, 'low'
        imp = 6.42 * iss if s == 'U' else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        exp = 8.22 * av * ac * pr * ui
        base = 0.0 if imp <= 0.0 else cls._round_up(min(imp + exp, 10.0)) if s == 'U' else cls._round_up(min(1.08 * (imp + exp), 10.0))
        sc = round(base, 1)
        return sc, 'critical' if sc >= 9.0 else 'high' if sc >= 7.0 else 'medium' if sc >= 4.0 else 'low'

class IOCParser:
    PATTERNS = {
        'url': re.compile(r"\bhttps?://[a-zA-Z0-9\-\._~:/\?#\[\]@!$&'\(\)\*\+,;=%]+\b"),
        'cidr': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}/(?:[0-9]|[1-2][0-9]|3[0-2])\b'),
        'ipv4': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
        'ipv6': re.compile(r'\b(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}\b'),
        'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
        'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
        'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
        'domain': re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,24}\b')
    }
    TLDS = {'com', 'org', 'net', 'io', 'gov', 'edu', 'mil', 'co', 'ru', 'cn', 'de', 'uk', 'xyz', 'biz', 'info'}

    @classmethod
    def defang(cls, text: str) -> str:
        return text.replace('http://', 'hxxp://').replace('https://', 'hxxps://').replace('.', '[.]')

    @classmethod
    def refang(cls, text: str) -> str:
        return text.replace('hxxp://', 'http://').replace('hxxps://', 'https://').replace('[.]', '.').replace('[:]', ':')

    @staticmethod
    def is_valid_ipv4(ip: str) -> bool:
        pts = ip.split('.')
        return len(pts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in pts)

    @classmethod
    def extract_iocs(cls, raw_text: str) -> List[IOCItem]:
        ref = cls.refang(raw_text)
        res: Dict[Tuple[str, str], IOCItem] = {}
        cidr_ips = set()
        for m in cls.PATTERNS['cidr'].finditer(ref):
            v = m.group()
            if cls.is_valid_ipv4(v.split('/')[0]):
                res['cidr', v] = IOCItem(type='cidr', value=v, defanged=cls.defang(v))
                cidr_ips.add(v.split('/')[0])
        for m in cls.PATTERNS['ipv4'].finditer(ref):
            v = m.group()
            if cls.is_valid_ipv4(v) and v not in cidr_ips:
                res['ipv4', v] = IOCItem(type='ipv4', value=v, defanged=cls.defang(v))
        for m in cls.PATTERNS['ipv6'].finditer(ref):
            v = m.group(); res['ipv6', v] = IOCItem(type='ipv6', value=v, defanged=cls.defang(v))
        for t in ('sha256', 'sha1', 'md5'):
            for m in cls.PATTERNS[t].finditer(ref):
                v = m.group().lower(); res[t, v] = IOCItem(type=t, value=v, defanged=v)
        for m in cls.PATTERNS['url'].finditer(ref):
            v = m.group(); res['url', v] = IOCItem(type='url', value=v, defanged=cls.defang(v))
        for m in cls.PATTERNS['domain'].finditer(ref):
            v = m.group()
            if v.split('.')[-1].lower() in cls.TLDS and not cls.is_valid_ipv4(v):
                res['domain', v] = IOCItem(type='domain', value=v, defanged=cls.defang(v))
        return list(res.values())
