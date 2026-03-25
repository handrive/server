//! Rate limiting middleware for API endpoints.
//!
//! Implements two layers of rate limiting:
//! - Global: Protects the server from being overwhelmed
//! - Per-IP: Prevents a single client from hogging resources
//!
//! Uses the Governor crate with token bucket algorithm.
//! Returns HTTP 429 with standard rate limit headers when exceeded.

use std::{net::IpAddr, num::NonZeroU32, sync::Arc};

use crate::env_utils::get_env_or_default;

use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use governor::{
    clock::DefaultClock,
    middleware::NoOpMiddleware,
    state::{InMemoryState, NotKeyed, keyed::DefaultKeyedStateStore},
    Quota, RateLimiter,
};
use serde_json::json;

/// Type alias for the global rate limiter.
pub type GlobalRateLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// Type alias for the per-IP rate limiter.
pub type PerIpRateLimiter = RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock, NoOpMiddleware>;

/// Combined rate limiters for both global and per-IP limiting.
#[derive(Clone)]
pub struct RateLimiters {
    pub global: Arc<GlobalRateLimiter>,
    pub per_ip: Arc<PerIpRateLimiter>,
}

/// Rate limit configuration.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum requests per second (global).
    pub global_rps: u32,
    /// Burst capacity for global limiter.
    pub global_burst: u32,
    /// Maximum requests per second per IP.
    pub per_ip_rps: u32,
    /// Burst capacity per IP.
    pub per_ip_burst: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            global_rps: 1000,
            global_burst: 2000,
            per_ip_rps: 50,
            per_ip_burst: 100,
        }
    }
}

impl RateLimitConfig {
    /// Load rate limit configuration from environment variables.
    pub fn from_env() -> Self {
        Self {
            global_rps: get_env_or_default("RATE_LIMIT_RPS", 1000),
            global_burst: get_env_or_default("RATE_LIMIT_BURST", 2000),
            per_ip_rps: get_env_or_default("RATE_LIMIT_PER_IP_RPS", 50),
            per_ip_burst: get_env_or_default("RATE_LIMIT_PER_IP_BURST", 100),
        }
    }

    /// Create rate limiters from this configuration.
    pub fn create_limiters(&self) -> RateLimiters {
        let global_quota = Quota::per_second(NonZeroU32::new(self.global_rps).unwrap())
            .allow_burst(NonZeroU32::new(self.global_burst).unwrap());

        let per_ip_quota = Quota::per_second(NonZeroU32::new(self.per_ip_rps).unwrap())
            .allow_burst(NonZeroU32::new(self.per_ip_burst).unwrap());

        RateLimiters {
            global: Arc::new(RateLimiter::direct(global_quota)),
            per_ip: Arc::new(RateLimiter::keyed(per_ip_quota)),
        }
    }

    /// Create a global-only rate limiter (for backwards compatibility).
    pub fn create_limiter(&self) -> Arc<GlobalRateLimiter> {
        let quota = Quota::per_second(NonZeroU32::new(self.global_rps).unwrap())
            .allow_burst(NonZeroU32::new(self.global_burst).unwrap());

        Arc::new(RateLimiter::direct(quota))
    }
}

/// Rate limit response with standard headers.
fn rate_limit_response(reason: &str) -> Response {
    let body = Json(json!({ "error": "Rate limit exceeded", "reason": reason }));
    (StatusCode::TOO_MANY_REQUESTS, body).into_response()
}

/// Extract client IP from request.
///
/// Checks in order:
///   1. X-Forwarded-For header (first IP — set by reverse proxy)
///   2. X-Real-IP header
///   3. Direct connection IP
///
/// In production the server is only reachable via the reverse proxy (Caddy),
/// so forwarded headers are always trustworthy. In local dev, no proxy means
/// no forwarded headers, so it naturally falls back to the direct connection IP.
fn extract_client_ip<B>(request: &Request<B>) -> Option<IpAddr> {
    // Check X-Forwarded-For header (common for proxies/load balancers)
    if let Some(forwarded_for) = request
        .headers()
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
    {
        // Take the first IP in the chain (original client)
        if let Some(first_ip) = forwarded_for.split(',').next() {
            if let Ok(ip) = first_ip.trim().parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }

    // Check X-Real-IP header
    if let Some(real_ip) = request
        .headers()
        .get("X-Real-IP")
        .and_then(|v| v.to_str().ok())
    {
        if let Ok(ip) = real_ip.trim().parse::<IpAddr>() {
            return Some(ip);
        }
    }

    // Fall back to direct connection IP
    request
        .extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip())
}

/// Rate limiting middleware layer with both global and per-IP limits.
///
/// Checks both limiters and returns 429 if either limit is exceeded.
pub async fn rate_limit_middleware(
    State(limiters): State<RateLimiters>,
    request: Request<Body>,
    next: Next,
) -> Response {
    // Check global rate limit first
    if limiters.global.check().is_err() {
        tracing::warn!(
            method = %request.method(),
            uri = %request.uri(),
            "Global rate limit exceeded"
        );
        return rate_limit_response("global");
    }

    // Check per-IP rate limit
    if let Some(client_ip) = extract_client_ip(&request) {
        if limiters.per_ip.check_key(&client_ip).is_err() {
            tracing::warn!(
                method = %request.method(),
                uri = %request.uri(),
                client_ip = %client_ip,
                "Per-IP rate limit exceeded"
            );
            return rate_limit_response("per_ip");
        }
    }

    // Request allowed, proceed
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = RateLimitConfig::default();
        assert_eq!(config.global_rps, 1000);
        assert_eq!(config.global_burst, 2000);
        assert_eq!(config.per_ip_rps, 50);
        assert_eq!(config.per_ip_burst, 100);
    }

    #[test]
    fn test_create_limiters() {
        let config = RateLimitConfig {
            global_rps: 10,
            global_burst: 20,
            per_ip_rps: 5,
            per_ip_burst: 10,
        };
        let limiters = config.create_limiters();

        // Should allow global_burst requests on global limiter
        for _ in 0..20 {
            assert!(limiters.global.check().is_ok());
        }
        // Should be rate limited after burst
        assert!(limiters.global.check().is_err());
    }

    #[test]
    fn test_per_ip_limiter() {
        let config = RateLimitConfig {
            global_rps: 1000,
            global_burst: 2000,
            per_ip_rps: 5,
            per_ip_burst: 10,
        };
        let limiters = config.create_limiters();

        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();

        // IP1 should allow per_ip_burst requests
        for _ in 0..10 {
            assert!(limiters.per_ip.check_key(&ip1).is_ok());
        }
        // IP1 should be rate limited
        assert!(limiters.per_ip.check_key(&ip1).is_err());

        // IP2 should still have its own quota
        for _ in 0..10 {
            assert!(limiters.per_ip.check_key(&ip2).is_ok());
        }
        assert!(limiters.per_ip.check_key(&ip2).is_err());
    }

    #[test]
    fn test_create_limiter_backwards_compat() {
        let config = RateLimitConfig::default();
        let limiter = config.create_limiter();

        // Should work with global quota
        assert!(limiter.check().is_ok());
    }
}
