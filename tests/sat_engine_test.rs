use exactor_waf_guardian::engine::ExactorSatEngine;
use exactor_waf_guardian::types::{AttackCategory, AttackDecision, HttpRequestPayload};

#[test]
fn test_sqli_detection() {
    let engine = ExactorSatEngine::new();
    let payload = HttpRequestPayload::new(
        "GET",
        "/items",
        "id=1' OR '1'='1",
        "",
    );

    // Warmup cold regex singletons
    let _ = engine.evaluate_payload(&payload);
    let proof = engine.evaluate_payload(&payload);
    assert!(proof.is_violation);
    assert_eq!(proof.action, AttackDecision::Block);
    assert_eq!(proof.category, AttackCategory::SqlInjection);
    assert!(proof.matched_rules.iter().any(|r| r.rule_id == "SAT-SQLI-01"));
    assert!(proof.formal_proof_latex.contains("SAT-SQLI-01"));
    assert!(proof.formal_proof_latex.contains("BLOCK"));
    assert!(proof.causal_proof.contains("ACTION_BLOCK"));
    assert!(proof.execution_time_us < 1000.0, "Latency must be sub-millisecond (< 1000 µs), was {:.2} µs", proof.execution_time_us);
}

#[test]
fn test_sqli_union_select() {
    let engine = ExactorSatEngine::new();
    let payload = HttpRequestPayload::new(
        "GET",
        "/api/v1/products",
        "category=1 UNION SELECT username, password FROM users--",
        "",
    );

    let proof = engine.evaluate_payload(&payload);
    assert!(proof.is_violation);
    assert_eq!(proof.action, AttackDecision::Block);
    assert_eq!(proof.category, AttackCategory::SqlInjection);
    assert!(proof.matched_rules.iter().any(|r| r.rule_id == "SAT-SQLI-02"));
    assert!(proof.causal_proof.contains("ACTION_BLOCK"));
}

#[test]
fn test_xss_detection() {
    let engine = ExactorSatEngine::new();
    let payload = HttpRequestPayload::new(
        "POST",
        "/comment",
        "",
        "<script>alert(document.cookie)</script>",
    );

    let proof = engine.evaluate_payload(&payload);
    assert!(proof.is_violation);
    assert_eq!(proof.action, AttackDecision::Block);
    assert_eq!(proof.category, AttackCategory::Xss);
    assert!(proof.matched_rules.iter().any(|r| r.rule_id == "SAT-XSS-01"));
    assert!(proof.formal_proof_latex.contains("BLOCK"));
    assert!(proof.causal_proof.contains("ACTION_BLOCK"));
}

#[test]
fn test_xss_event_handler() {
    let engine = ExactorSatEngine::new();
    let payload = HttpRequestPayload::new(
        "GET",
        "/search",
        "q=<img src=x onerror=alert(1)>",
        "",
    );

    let proof = engine.evaluate_payload(&payload);
    assert!(proof.is_violation);
    assert_eq!(proof.action, AttackDecision::Block);
    assert_eq!(proof.category, AttackCategory::Xss);
    assert!(proof.matched_rules.iter().any(|r| r.rule_id == "SAT-XSS-02"));
    assert!(proof.causal_proof.contains("ACTION_BLOCK"));
}

#[test]
fn test_rce_detection() {
    let engine = ExactorSatEngine::new();
    let payload = HttpRequestPayload::new(
        "POST",
        "/api/ping",
        "",
        "ip=127.0.0.1; cat /etc/passwd",
    );

    let proof = engine.evaluate_payload(&payload);
    assert!(proof.is_violation);
    assert_eq!(proof.action, AttackDecision::Block);
    assert_eq!(proof.category, AttackCategory::CommandInjection);
    assert!(proof.matched_rules.iter().any(|r| r.rule_id == "SAT-RCE-01"));
    assert!(proof.formal_proof_latex.contains("BLOCK"));
    assert!(proof.causal_proof.contains("ACTION_BLOCK"));
}

#[test]
fn test_path_traversal_detection() {
    let engine = ExactorSatEngine::new();
    let payload = HttpRequestPayload::new(
        "GET",
        "/download",
        "file=../../../../etc/passwd",
        "",
    );

    let proof = engine.evaluate_payload(&payload);
    assert!(proof.is_violation);
    assert_eq!(proof.action, AttackDecision::Block);
    assert_eq!(proof.category, AttackCategory::PathTraversal);
    assert!(proof.matched_rules.iter().any(|r| r.rule_id == "SAT-PATH-01"));
    assert!(proof.formal_proof_latex.contains("BLOCK"));
    assert!(proof.causal_proof.contains("ACTION_BLOCK"));
}

#[test]
fn test_ssrf_detection() {
    let engine = ExactorSatEngine::new();
    let payload = HttpRequestPayload::new(
        "GET",
        "/proxy",
        "url=http://169.254.169.254/latest/meta-data/",
        "",
    );

    let proof = engine.evaluate_payload(&payload);
    assert!(proof.is_violation);
    assert_eq!(proof.action, AttackDecision::Block);
    assert_eq!(proof.category, AttackCategory::Ssrf);
    assert!(proof.matched_rules.iter().any(|r| r.rule_id == "SAT-SSRF-01"));
    assert!(proof.formal_proof_latex.contains("BLOCK"));
    assert!(proof.causal_proof.contains("ACTION_BLOCK"));
}

#[test]
fn test_benign_traffic_passes_with_zero_false_positives() {
    let engine = ExactorSatEngine::new();
    let payload = HttpRequestPayload::new(
        "POST",
        "/api/v1/users",
        "",
        r#"{"username": "alice", "role": "developer", "email": "alice@exactor.tech"}"#,
    );

    let proof = engine.evaluate_payload(&payload);
    assert!(!proof.is_violation);
    assert_eq!(proof.action, AttackDecision::Allow);
    assert_eq!(proof.category, AttackCategory::Benign);
    assert!(proof.matched_rules.is_empty());
    assert!(proof.formal_proof_latex.contains("ALLOW"));
    assert!(proof.causal_proof.contains("ACTION_ALLOW"));
}
