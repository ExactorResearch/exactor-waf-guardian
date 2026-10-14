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

#[test]
fn test_graphql_introspection_blocked() {
    let engine = ExactorSatEngine::new();
    let payload = HttpRequestPayload::new(
        "POST",
        "/graphql",
        "",
        r#"{"query": "query IntrospectionQuery { __schema { types { name } } }"}"#,
    );

    let proof = engine.evaluate_payload(&payload);
    assert!(proof.is_violation);
    assert_eq!(proof.action, AttackDecision::Block);
    assert_eq!(proof.category, AttackCategory::GraphqlAbuse);
    assert!(proof.matched_rules.iter().any(|r| r.rule_id == "SAT-GQL-01"));
    assert!(proof.active_islands.contains(&"ISLAND-GRAPHQL".to_string()));
    assert!(proof.causal_proof.contains("ACTION_BLOCK"));
}

#[test]
fn test_graphql_deep_nesting_dos_blocked() {
    let engine = ExactorSatEngine::new();
    // 8 levels of nested curly braces
    let nested_query = r#"{"query": "{ user { posts { comments { author { posts { comments { author { id } } } } } } } }"}"#;
    let payload = HttpRequestPayload::new(
        "POST",
        "/graphql",
        "",
        nested_query,
    );

    let proof = engine.evaluate_payload(&payload);
    assert!(proof.is_violation);
    assert_eq!(proof.action, AttackDecision::Block);
    assert_eq!(proof.category, AttackCategory::GraphqlAbuse);
    assert!(proof.matched_rules.iter().any(|r| r.rule_id == "SAT-GQL-02"));
    assert!(proof.active_islands.contains(&"ISLAND-GRAPHQL".to_string()));
}

#[test]
fn test_graphql_batch_array_blocked() {
    let engine = ExactorSatEngine::new();
    let batch_query = r#"[{"query": "{ user(id: 1) { name } }"}, {"query": "{ user(id: 2) { name } }"}]"#;
    let payload = HttpRequestPayload::new(
        "POST",
        "/api/gql",
        "",
        batch_query,
    );

    let proof = engine.evaluate_payload(&payload);
    assert!(proof.is_violation);
    assert_eq!(proof.action, AttackDecision::Block);
    assert_eq!(proof.category, AttackCategory::GraphqlAbuse);
    assert!(proof.matched_rules.iter().any(|r| r.rule_id == "SAT-GQL-03"));
}

#[test]
fn test_prototype_pollution_blocked() {
    let engine = ExactorSatEngine::new();
    let payload = HttpRequestPayload::new(
        "POST",
        "/api/v1/profile",
        "",
        r#"{"__proto__": {"isAdmin": true}}"#,
    );

    let proof = engine.evaluate_payload(&payload);
    assert!(proof.is_violation);
    assert_eq!(proof.action, AttackDecision::Block);
    assert_eq!(proof.category, AttackCategory::PrototypePollution);
    assert!(proof.matched_rules.iter().any(|r| r.rule_id == "SAT-JSON-01"));
    assert!(proof.active_islands.contains(&"ISLAND-JSON-PROTO".to_string()));
}

#[test]
fn test_json_schema_nesting_bomb_blocked() {
    let engine = ExactorSatEngine::new();
    // 25 levels of nesting
    let mut bomb = String::new();
    for _ in 0..25 {
        bomb.push_str(r#"{"nested": "#);
    }
    bomb.push_str(r#""depth""#);
    for _ in 0..25 {
        bomb.push('}');
    }

    let payload = HttpRequestPayload::new(
        "POST",
        "/api/v1/data",
        "",
        bomb,
    );

    let proof = engine.evaluate_payload(&payload);
    assert!(proof.is_violation);
    assert_eq!(proof.action, AttackDecision::Block);
    assert_eq!(proof.category, AttackCategory::PrototypePollution);
    assert!(proof.matched_rules.iter().any(|r| r.rule_id == "SAT-JSON-02"));
}

#[test]
fn test_grpc_status_injection_blocked() {
    let engine = ExactorSatEngine::new();
    let mut payload = HttpRequestPayload::new(
        "POST",
        "/grpc.BankService/Transfer",
        "",
        "",
    );
    payload.headers.insert("content-type".to_string(), "application/grpc".to_string());
    payload.headers.insert("grpc-status".to_string(), "0".to_string()); // Injected status trailer

    let proof = engine.evaluate_payload(&payload);
    assert!(proof.is_violation);
    assert_eq!(proof.action, AttackDecision::Block);
    assert_eq!(proof.category, AttackCategory::GrpcSmuggling);
    assert!(proof.matched_rules.iter().any(|r| r.rule_id == "SAT-GRPC-01"));
    assert!(proof.active_islands.contains(&"ISLAND-GRPC".to_string()));
}

#[test]
fn test_jwt_alg_none_blocked() {
    let engine = ExactorSatEngine::new();
    // Header {"alg": "none", "typ": "JWT"} -> Base64URL: eyJhbGciOiAibm9uZSIgfQ
    // Payload {"user": "admin"} -> Base64URL: eyJ1c2VyIjogImFkbWluIn0
    let jwt_token = "eyJhbGciOiAibm9uZSIgfQ.eyJ1c2VyIjogImFkbWluIn0.";
    let mut payload = HttpRequestPayload::new(
        "GET",
        "/api/v1/protected",
        "",
        "",
    );
    payload.headers.insert("authorization".to_string(), format!("Bearer {}", jwt_token));

    let proof = engine.evaluate_payload(&payload);
    assert!(proof.is_violation);
    assert_eq!(proof.action, AttackDecision::Block);
    assert_eq!(proof.category, AttackCategory::JwtTampering);
    assert!(proof.matched_rules.iter().any(|r| r.rule_id == "SAT-JWT-01"));
    assert!(proof.active_islands.contains(&"ISLAND-JWT".to_string()));
}

#[test]
fn test_jwt_kid_traversal_blocked() {
    let engine = ExactorSatEngine::new();
    // Header {"alg": "HS256", "kid": "../../../../dev/null"} -> Base64URL: eyJhbGciOiAiSFMyNTYiLCAia2lkIjogIi4uLy4uLy4uL2Rldi9udWxsIn0
    // Payload {"user": "admin"} -> Base64URL: eyJ1c2VyIjogImFkbWluIn0
    let jwt_token = "eyJhbGciOiAiSFMyNTYiLCAia2lkIjogIi4uLy4uLy4uL2Rldi9udWxsIn0.eyJ1c2VyIjogImFkbWluIn0.signature";
    let mut payload = HttpRequestPayload::new(
        "GET",
        "/api/v1/protected",
        "",
        "",
    );
    payload.headers.insert("authorization".to_string(), format!("Bearer {}", jwt_token));

    let proof = engine.evaluate_payload(&payload);
    assert!(proof.is_violation);
    assert_eq!(proof.action, AttackDecision::Block);
    assert_eq!(proof.category, AttackCategory::JwtTampering);
    assert!(proof.matched_rules.iter().any(|r| r.rule_id == "SAT-JWT-02"));
    assert!(proof.active_islands.contains(&"ISLAND-JWT".to_string()));
}

#[test]
fn test_stateful_sliding_window_rate_limiting() {
    use exactor_waf_guardian::stateful::{StatefulConfig, StatefulRateLimiter};

    let engine = ExactorSatEngine::new();
    let limiter = StatefulRateLimiter::new(StatefulConfig {
        enabled: true,
        window_secs: 60,
        num_buckets: 12,
        global_limit_per_window: 5, // Limit 5 requests
        auth_limit_per_window: 3,
        ban_duration_secs: 60,
        redis_url: None,
    });

    let payload = HttpRequestPayload {
        id: "req1".to_string(),
        method: "GET".to_string(),
        path: "/api/data".to_string(),
        query_string: "".to_string(),
        headers: std::collections::HashMap::new(),
        body: "".to_string(),
        client_ip: Some("192.168.1.100".to_string()),
    };

    // First 5 requests must pass
    for _ in 0..5 {
        let verdict = limiter.check_and_update(&payload);
        assert!(!verdict.is_violation);
        let proof = engine.evaluate_payload_with_verdict(&payload, Some(&verdict));
        assert!(!proof.is_violation);
        assert_eq!(proof.action, AttackDecision::Allow);
    }

    // 6th request must trigger rate limit burst!
    let verdict = limiter.check_and_update(&payload);
    assert!(verdict.is_violation);
    assert!(verdict.is_rate_limit);

    let proof = engine.evaluate_payload_with_verdict(&payload, Some(&verdict));
    assert!(proof.is_violation);
    assert_eq!(proof.action, AttackDecision::Block);
    assert_eq!(proof.category, AttackCategory::RateLimitDdos);
    assert!(proof.matched_rules.iter().any(|r| r.rule_id == "SAT-STATE-01"));
    assert!(proof.active_islands.contains(&"ISLAND-STATEFUL".to_string()));
    assert!(proof.causal_proof.contains("ACTION_BLOCK"));
}

#[test]
fn test_stateful_credential_stuffing_detection() {
    use exactor_waf_guardian::stateful::{StatefulConfig, StatefulRateLimiter};

    let engine = ExactorSatEngine::new();
    let limiter = StatefulRateLimiter::new(StatefulConfig {
        enabled: true,
        window_secs: 60,
        num_buckets: 12,
        global_limit_per_window: 100,
        auth_limit_per_window: 3, // Only 3 auth attempts allowed in 60s
        ban_duration_secs: 60,
        redis_url: None,
    });

    let auth_payload = HttpRequestPayload {
        id: "auth1".to_string(),
        method: "POST".to_string(),
        path: "/api/v1/auth/login".to_string(),
        query_string: "".to_string(),
        headers: std::collections::HashMap::new(),
        body: r#"{"username":"admin","password":"password123"}"#.to_string(),
        client_ip: Some("10.0.0.42".to_string()),
    };

    // First 3 login attempts pass
    for _ in 0..3 {
        let verdict = limiter.check_and_update(&auth_payload);
        assert!(!verdict.is_violation);
    }

    // 4th login attempt triggers credential stuffing invariant!
    let verdict = limiter.check_and_update(&auth_payload);
    assert!(verdict.is_violation);
    assert!(verdict.is_credential_stuffing);

    let proof = engine.evaluate_payload_with_verdict(&auth_payload, Some(&verdict));
    assert!(proof.is_violation);
    assert_eq!(proof.action, AttackDecision::Block);
    assert_eq!(proof.category, AttackCategory::CredentialStuffing);
    assert!(proof.matched_rules.iter().any(|r| r.rule_id == "SAT-STATE-02"));
    assert!(proof.active_islands.contains(&"ISLAND-STATEFUL".to_string()));
}

