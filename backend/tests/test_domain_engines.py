"""Unit tests for deterministic CVSS v3.1 calculator and IOC parser/defanger."""
import pytest
from app.services.threat_engine import CVSS31Calculator, IOCParser


def test_cvss_calculator_critical_scope_changed():
    # Log4Shell vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H -> 10.0 Critical
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    score, sev = CVSS31Calculator.calculate(vector)
    assert score == 10.0
    assert sev == "critical"


def test_cvss_calculator_high_scope_unchanged():
    # Spring4Shell vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -> 9.8 Critical
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    score, sev = CVSS31Calculator.calculate(vector)
    assert score == 9.8
    assert sev == "critical"


def test_cvss_calculator_medium_and_low():
    # Network, High complexity, High PR, UI required: CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N -> ~3.1 Low
    vector = "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N"
    score, sev = CVSS31Calculator.calculate(vector)
    assert score < 4.0
    assert sev == "low"


def test_cvss_calculator_zero_impact():
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
    score, sev = CVSS31Calculator.calculate(vector)
    assert score == 0.0
    assert sev == "low"


def test_ioc_parser_extraction_and_defanging():
    threat_text = (
        "Adversary beaconed to C2 server at 198.51.100.42 and domain evil-threat[.]org over https://malware-drop.com/payload.bin. "
        "Associated dropper hash sha256 is 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f13a61d82b540. "
        "Secondary subnet targeted: 10.200.0.0/16."
    )
    iocs = IOCParser.extract_iocs(threat_text)
    types_found = {i.type: i for i in iocs}

    assert "ipv4" in types_found
    assert types_found["ipv4"].value == "198.51.100.42"
    assert types_found["ipv4"].defanged == "198[.]51[.]100[.]42"

    domain_values = [i.value for i in iocs if i.type == "domain"]
    assert any("evil-threat" in d for d in domain_values)

    assert "sha256" in types_found
    assert types_found["sha256"].value == "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f13a61d82b540"

    assert "cidr" in types_found
    assert types_found["cidr"].value == "10.200.0.0/16"


def test_ioc_parser_boundary_and_invalid_inputs():
    # Invalid IP octets should not be matched as valid IPv4
    invalid_text = "Attempted connection to 999.888.777.666 and 300.1.2.3 and localhost"
    iocs = IOCParser.extract_iocs(invalid_text)
    ip_values = [i.value for i in iocs if i.type == "ipv4"]
    assert "999.888.777.666" not in ip_values
    assert "300.1.2.3" not in ip_values


def test_ioc_parser_refanging():
    defanged = "hxxps://attacker[.]org/gate[.]php on 10[.]0[.]1[.]5"
    refanged = IOCParser.refang(defanged)
    assert refanged == "https://attacker.org/gate.php on 10.0.1.5"
