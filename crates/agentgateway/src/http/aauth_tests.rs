#[cfg(test)]
mod tests {
    use crate::http::{Request, Body};
    use crate::http::aauth::{AAuth, Mode, RequiredScheme, ChallengeConfig, AAuthPolicyError, JwksCache};
    use crate::telemetry::log::RequestLog;
    use crate::client::Client;
    use crate::BackendConfig;
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};
    use std::sync::Arc;
    use std::net::{SocketAddr, IpAddr, Ipv4Addr};
    use std::time::Instant;
    use crate::transport::stream::TCPConnectionInfo;

    fn make_test_client() -> Client {
        Client::new(
            &crate::client::Config {
                resolver_cfg: ResolverConfig::default(),
                resolver_opts: ResolverOpts::default(),
            },
            None,
            BackendConfig::default(),
            None,
        )
    }

    fn make_test_aauth(mode: Mode, required_scheme: RequiredScheme) -> AAuth {
        AAuth::new(
            mode,
            required_scheme,
            60,
            None,
            JwksCache::default(),
            make_test_client(),
        )
    }

    fn make_min_req_log() -> RequestLog {
        use std::collections::HashMap;
        use frozen_collections::FzHashSet;
        use prometheus_client::registry::Registry;
        use crate::telemetry::log::{LoggingFields, MetricFields};
        use crate::telemetry::{log, trc, metrics::Metrics};

        let log_cfg = log::Config {
            filter: None,
            fields: LoggingFields::default(),
            metric_fields: Arc::new(MetricFields::default()),
            excluded_metrics: FzHashSet::default(),
            level: "info".to_string(),
            format: crate::LoggingFormat::Text,
        };
        let tracing_cfg = trc::Config {
            endpoint: None,
            headers: HashMap::new(),
            protocol: trc::Protocol::Grpc,
            fields: LoggingFields::default(),
            random_sampling: None,
            client_sampling: None,
            path: "/v1/traces".to_string(),
        };
        let cel = log::CelLogging::new(log_cfg, tracing_cfg);
        let mut prom = Registry::default();
        let metrics = Arc::new(Metrics::new(&mut prom, FzHashSet::default()));
        let start = Instant::now();
        let tcp_info = TCPConnectionInfo {
            peer_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
            local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
            start,
            raw_peer_addr: None,
        };
        RequestLog::new(cel, metrics, start, tcp_info)
    }

    #[tokio::test]
    async fn test_aauth_missing_signature_optional_mode() {
        let aauth = make_test_aauth(Mode::Optional, RequiredScheme::Hwk);

        let mut req = Request::new(Body::empty());
        *req.uri_mut() = "https://example.com/api/data".parse().unwrap();
        *req.method_mut() = http::Method::GET;

        let mut log = make_min_req_log();
        
        // Should allow request without signature in Optional mode
        let result = aauth.apply(Some(&mut log), &mut req, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_aauth_missing_signature_strict_mode() {
        let aauth = make_test_aauth(Mode::Strict, RequiredScheme::Hwk);

        let mut req = Request::new(Body::empty());
        *req.uri_mut() = "https://example.com/api/data".parse().unwrap();
        *req.method_mut() = http::Method::GET;

        let mut log = make_min_req_log();
        
        // Should reject request without signature in Strict mode
        let result = aauth.apply(Some(&mut log), &mut req, None).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AAuthPolicyError::MissingSignature));
    }

    #[tokio::test]
    async fn test_challenge_response_hwk() {
        let aauth = make_test_aauth(Mode::Strict, RequiredScheme::Hwk);

        let challenge = aauth.build_challenge_response(None);
        assert_eq!(challenge, "httpsig");
    }

    #[tokio::test]
    async fn test_challenge_response_jwks() {
        let aauth = make_test_aauth(Mode::Strict, RequiredScheme::Jwks);

        let challenge = aauth.build_challenge_response(None);
        assert_eq!(challenge, "httpsig; identity=?1");
    }

    #[tokio::test]
    async fn test_challenge_response_jwt() {
        let challenge_config = Some(ChallengeConfig {
            auth_server: "https://auth.example.com".to_string(),
        });
        let aauth = AAuth::new(
            Mode::Strict,
            RequiredScheme::Jwt,
            60,
            challenge_config,
            JwksCache::default(),
            make_test_client(),
        );

        let challenge = aauth.build_challenge_response(None);
        assert!(challenge.contains("httpsig; auth-token"));
        assert!(challenge.contains("auth_server=\"https://auth.example.com\""));
    }

    #[test]
    fn test_jwks_cache_insert_and_get() {
        use aauth::keys::jwk::JWK;
        
        let cache = JwksCache::default();
        let agent_id = "https://agent.example.com";
        let kid1 = "key-1";
        let kid2 = "key-2";
        
        // Create test JWKs
        let jwk1 = JWK {
            kty: "OKP".to_string(),
            crv: Some("Ed25519".to_string()),
            x: Some("JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs".to_string()),
            y: None,
            d: None,
            n: None,
            e: None,
            kid: Some(kid1.to_string()),
            alg: None,
            extra: serde_json::Map::new(),
        };
        let jwk2 = JWK {
            kty: "OKP".to_string(),
            crv: Some("Ed25519".to_string()),
            x: Some("JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs".to_string()),
            y: None,
            d: None,
            n: None,
            e: None,
            kid: Some(kid2.to_string()),
            alg: None,
            extra: serde_json::Map::new(),
        };
        
        // Insert keys
        cache.insert(agent_id, &[jwk1.clone(), jwk2.clone()]);
        
        // Retrieve keys
        assert_eq!(cache.get(agent_id, kid1).unwrap().kid, Some(kid1.to_string()));
        assert_eq!(cache.get(agent_id, kid2).unwrap().kid, Some(kid2.to_string()));
        
        // Non-existent key
        assert!(cache.get(agent_id, "non-existent").is_none());
        
        // Non-existent agent
        assert!(cache.get("https://other.example.com", kid1).is_none());
    }

    #[test]
    fn test_jwk_to_ed25519_public_key() {
        use aauth::keys::jwk::JWK;
        
        let jwk = JWK {
            kty: "OKP".to_string(),
            crv: Some("Ed25519".to_string()),
            x: Some("JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs".to_string()),
            y: None,
            d: None,
            n: None,
            e: None,
            kid: Some("test-key".to_string()),
            alg: None,
            extra: serde_json::Map::new(),
        };
        
        // Should successfully convert
        let pubkey = jwk.to_ed25519_public_key();
        assert!(pubkey.is_ok());
        
        // Wrong kty should fail
        let wrong_kty = JWK {
            kty: "EC".to_string(),
            crv: Some("P-256".to_string()),
            x: Some("test".to_string()),
            y: None,
            d: None,
            n: None,
            e: None,
            kid: None,
            alg: None,
            extra: serde_json::Map::new(),
        };
        assert!(wrong_kty.to_ed25519_public_key().is_err());
        
        // Wrong crv should fail
        let wrong_crv = JWK {
            kty: "OKP".to_string(),
            crv: Some("P-256".to_string()),
            x: Some("test".to_string()),
            y: None,
            d: None,
            n: None,
            e: None,
            kid: None,
            alg: None,
            extra: serde_json::Map::new(),
        };
        assert!(wrong_crv.to_ed25519_public_key().is_err());
    }
}
