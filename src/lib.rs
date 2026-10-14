pub mod api;
pub mod ast;
pub mod benchmark;
pub mod cloud;
pub mod config;
pub mod engine;
pub mod ledger;
pub mod proxy;
pub mod stateful;
pub mod types;

pub use ast::{AstLexer, FeatureBinarizer, FeatureVector};
pub use cloud::{ExactorCloudClient, SimplifyRequest, SimplifyResponse};
pub use config::WafConfig;
pub use engine::{DynamicCompiledClause, ExactorSatEngine};
pub use ledger::{AuditRecord, SqliteLedger};
pub use proxy::{proxy_handler, ProxyState};
pub use stateful::{StatefulConfig, StatefulRateLimiter, StatefulVerdict};
pub use types::{
    AttackCategory, AttackDecision, CertaintyIsland, DeductionRule, ExecutionPath,
    HttpRequestPayload, ProofChain, WafMetricsSnapshot,
};

