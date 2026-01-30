#[cfg(test)]
mod tests {
    use crate::http::{Request, Body};
    use crate::http::aauth::{AAuth, Mode, RequiredScheme, ChallengeConfig, AAuthPolicyError};
    use crate::telemetry::log::RequestLog;
    use std::sync::Arc;
    use std::net::{SocketAddr, IpAddr, Ipv4Addr};
    use std::time::Instant;
    use crate::transport::stream::TCPConnectionInfo;

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
        let aauth = AAuth::new(
            Mode::Optional,
            RequiredScheme::Hwk,
            60,
            None,
        );

        let mut req = Request::new(Body::empty());
        *req.uri_mut() = "https://example.com/api/data".parse().unwrap();
        *req.method_mut() = http::Method::GET;

        let mut log = make_min_req_log();
        
        // Should allow request without signature in Optional mode
        let result = aauth.apply(Some(&mut log), &mut req).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_aauth_missing_signature_strict_mode() {
        let aauth = AAuth::new(
            Mode::Strict,
            RequiredScheme::Hwk,
            60,
            None,
        );

        let mut req = Request::new(Body::empty());
        *req.uri_mut() = "https://example.com/api/data".parse().unwrap();
        *req.method_mut() = http::Method::GET;

        let mut log = make_min_req_log();
        
        // Should reject request without signature in Strict mode
        let result = aauth.apply(Some(&mut log), &mut req).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AAuthPolicyError::MissingSignature));
    }

    #[tokio::test]
    async fn test_challenge_response_hwk() {
        let aauth = AAuth::new(
            Mode::Strict,
            RequiredScheme::Hwk,
            60,
            None,
        );

        let challenge = aauth.build_challenge_response(None);
        assert_eq!(challenge, "httpsig");
    }

    #[tokio::test]
    async fn test_challenge_response_jwks() {
        let aauth = AAuth::new(
            Mode::Strict,
            RequiredScheme::Jwks,
            60,
            None,
        );

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
        );

        let challenge = aauth.build_challenge_response(None);
        assert!(challenge.contains("httpsig; auth-token"));
        assert!(challenge.contains("auth_server=\"https://auth.example.com\""));
    }
}
