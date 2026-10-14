use regex::Regex;
use std::sync::OnceLock;

/// Extracted GraphQL AST tokens and violation flags.
#[derive(Debug, Clone, Default)]
pub struct GraphqlTokens {
    pub is_graphql: bool,
    pub has_introspection: bool,
    pub has_deep_nesting: bool,
    pub has_batching: bool,
    pub max_depth: usize,
    pub active_tokens: Vec<String>,
}

static RE_GQL_INTROSPECTION: OnceLock<Regex> = OnceLock::new();
static RE_GQL_BATCH_ARRAY: OnceLock<Regex> = OnceLock::new();
static RE_GQL_ALIAS_BATCH: OnceLock<Regex> = OnceLock::new();

fn init_graphql_regexes() {
    let _ = RE_GQL_INTROSPECTION.get_or_init(|| {
        Regex::new(r#"(?i)__schema\b|__type\b|__directive\b"#).unwrap()
    });
    let _ = RE_GQL_BATCH_ARRAY.get_or_init(|| {
        Regex::new(r#"^\s*\[\s*\{.*"query"\s*:"#).unwrap()
    });
    let _ = RE_GQL_ALIAS_BATCH.get_or_init(|| {
        Regex::new(r#"\b([a-zA-Z0-9_]+)\s*:\s*([a-zA-Z0-9_]+)\s*\("#).unwrap()
    });
}

pub struct GraphqlAstAnalyzer;

impl GraphqlAstAnalyzer {
    /// Inspects whether the incoming request targets GraphQL and analyzes its AST grammar.
    pub fn analyze(path: &str, body: &str, query_str: &str) -> GraphqlTokens {
        init_graphql_regexes();
        let mut tokens = GraphqlTokens::default();

        let path_lower = path.to_ascii_lowercase();
        let is_gql_path = path_lower.contains("/graphql") || path_lower.contains("/gql");
        let has_query_param = query_str.to_ascii_lowercase().contains("query=");
        let has_query_in_body = body.contains("\"query\"") || body.contains("'query'");
        let starts_with_raw_gql = {
            let trimmed = body.trim_start();
            trimmed.starts_with("query ") || trimmed.starts_with("query{")
                || trimmed.starts_with("mutation ") || trimmed.starts_with("mutation{")
                || (trimmed.starts_with('{') && !trimmed.starts_with("{\"") && !trimmed.starts_with("{ \""))
        };

        if !is_gql_path && !has_query_param && !has_query_in_body && !starts_with_raw_gql {
            return tokens;
        }

        // Extract raw query string for AST inspection
        let raw_query = if let Ok(parsed_json) = serde_json::from_str::<serde_json::Value>(body) {
            if let Some(arr) = parsed_json.as_array() {
                let has_gql = arr.iter().any(|item| item.get("query").is_some());
                if !has_gql && !is_gql_path {
                    return tokens; // Not GraphQL
                }
                if arr.len() > 1 {
                    tokens.has_batching = true;
                    tokens.active_tokens.push("GRAPHQL_BATCH_ARRAY_OVERLOAD".to_string());
                }
                arr.iter()
                    .filter_map(|item| item.get("query").and_then(|q| q.as_str()))
                    .collect::<Vec<_>>()
                    .join("\n")
            } else if let Some(q) = parsed_json.get("query").and_then(|q| q.as_str()) {
                q.to_string()
            } else if is_gql_path {
                body.to_string()
            } else {
                return tokens; // Standard JSON payload without query field
            }
        } else {
            // Check if query is in URL query parameters
            if has_query_param {
                query_str.to_string()
            } else {
                body.to_string()
            }
        };

        tokens.is_graphql = true;

        // 1. Check Introspection Query flooding
        if let Some(re) = RE_GQL_INTROSPECTION.get() {
            if re.is_match(&raw_query) || re.is_match(body) {
                tokens.has_introspection = true;
                tokens.active_tokens.push("GRAPHQL_INTROSPECTION_PROBE".to_string());
            }
        }

        // 2. Check Batching via multiple aliases
        if let Some(re) = RE_GQL_ALIAS_BATCH.get() {
            let alias_count = re.find_iter(&raw_query).count();
            if alias_count >= 5 {
                tokens.has_batching = true;
                tokens.active_tokens.push("GRAPHQL_ALIAS_BATCHING_AMPLIFICATION".to_string());
            }
        }
        if let Some(re) = RE_GQL_BATCH_ARRAY.get() {
            if re.is_match(body) && !tokens.has_batching {
                tokens.has_batching = true;
                tokens.active_tokens.push("GRAPHQL_BATCH_ARRAY_OVERLOAD".to_string());
            }
        }

        // 3. Check AST Nesting Depth (calculate curly brace depth skipping strings and comments)
        let max_depth = Self::calculate_ast_depth(&raw_query);
        tokens.max_depth = max_depth;
        // Depth limit: Banking APIs typically enforce max depth of 6 or 7
        if max_depth > 6 {
            tokens.has_deep_nesting = true;
            tokens.active_tokens.push("GRAPHQL_DEEP_RECURSIVE_AST_EXHAUSTION".to_string());
        }

        tokens
    }

    /// Accurately counts AST brace depth, skipping string literals and line comments (#).
    fn calculate_ast_depth(query: &str) -> usize {
        let mut max_depth = 0usize;
        let mut current_depth = 0usize;
        let mut in_string = false;
        let mut escape_next = false;
        let mut in_comment = false;

        for ch in query.chars() {
            if in_comment {
                if ch == '\n' || ch == '\r' {
                    in_comment = false;
                }
                continue;
            }

            if in_string {
                if escape_next {
                    escape_next = false;
                } else if ch == '\\' {
                    escape_next = true;
                } else if ch == '"' {
                    in_string = false;
                }
                continue;
            }

            match ch {
                '#' => in_comment = true,
                '"' => in_string = true,
                '{' => {
                    current_depth += 1;
                    if current_depth > max_depth {
                        max_depth = current_depth;
                    }
                }
                '}' => {
                    if current_depth > 0 {
                        current_depth -= 1;
                    }
                }
                _ => {}
            }
        }

        max_depth
    }
}
