//! Envoy Proxy integration suite for Exactor WAF Guardian.
//! Provides native ext_authz HTTP/gRPC filter services and configuration helpers.

pub mod ext_authz;

pub use ext_authz::{create_envoy_authz_router, EnvoyAuthzState};
