from app.services.ml_eval import AgentEvaluator, ThreatClassifier

def test_threat_classifier_rce():
    text = "Critical arbitrary remote code execution vulnerability via JNDI LDAP lookup"
    category, conf, scores = ThreatClassifier.classify(text)
    assert category == "RCE"
    assert conf > 0.4
    assert scores["RCE"] > scores["DOS"]

def test_threat_classifier_priv_esc():
    text = "Local user elevation of privilege vulnerability in sudo allowing root access"
    category, conf, _ = ThreatClassifier.classify(text)
    assert category == "PRIV_ESC"
    assert conf > 0.3

def test_threat_classifier_boundary_empty():
    category, conf, scores = ThreatClassifier.classify("")
    assert category == "INFO_DISC"
    assert conf == 0.2

def test_evaluator_benchmark_metrics():
    res = AgentEvaluator.evaluate_classifier()
    assert res["sample_count"] == 12
    assert res["accuracy"] >= 0.8
    assert res["macro_f1"] >= 0.8
    assert "RCE" in res["category_f1"]
    assert "PRIV_ESC" in res["category_f1"]

def test_advisory_grounding_evaluation():
    facts = ["log4j", "jndi", "ldap", "remote code execution"]
    grounded_text = "The log4j library is exposed to a remote code execution attack via jndi and ldap lookups."
    eval_res = AgentEvaluator.evaluate_advisory_grounding(grounded_text, facts)
    assert eval_res["grounding_score"] == 1.0
    assert eval_res["hallucination_risk"] == "LOW"

    hallucinated_text = "This is a generic database error with no details."
    eval_res_poor = AgentEvaluator.evaluate_advisory_grounding(hallucinated_text, facts)
    assert eval_res_poor["grounding_score"] == 0.0
    assert eval_res_poor["hallucination_risk"] == "HIGH"
