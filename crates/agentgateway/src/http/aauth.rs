use std::collections::HashMap;
use std::str::FromStr;

use ::cel::types::dynamic::DynamicType;
use serde_json::{Map, Value};
use aauth::{
    headers::SignatureKey,
    signing::{verify_signature, SignatureScheme, resolve_hwk_public_key},
    errors::AAuthError as LibAAuthError,
};

use crate::client::Client;
use crate::http::Request;
use crate::telemetry::log::RequestLog;
use crate::*;

#[cfg(test)]
#[path = "aauth_tests.rs"]
mod tests;

#[derive(Debug, thiserror::Error)]
pub enum AAuthPolicyError {
    #[error("AAuth verification failed: {0}")]
    VerificationFailed(String),
    
    #[error("missing signature headers")]
    MissingSignature,
    
    #[error("insufficient authentication level")]
    InsufficientLevel,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct LocalAAuthConfig {
    #[serde(default)]
    pub mode: Mode,
    pub required_scheme: String, // "hwk", "jwks", "jwt"
    #[serde(default = "default_timestamp_tolerance")]
    pub timestamp_tolerance: u64,
    pub challenge: Option<LocalChallengeConfig>,
}

fn default_timestamp_tolerance() -> u64 {
    60
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct LocalChallengeConfig {
    pub auth_server: String,
    // TODO: Add resource token issuer config
}

impl LocalAAuthConfig {
    pub async fn try_into(self, _client: Client) -> Result<AAuth, AAuthPolicyError> {
        let required_scheme = RequiredScheme::from_str(&self.required_scheme)
            .map_err(|e| AAuthPolicyError::VerificationFailed(format!("invalid required_scheme: {}", e)))?;
        
        let challenge_config = self.challenge.map(|c| ChallengeConfig {
            auth_server: c.auth_server,
        });

        Ok(AAuth::new(
            self.mode,
            required_scheme,
            self.timestamp_tolerance,
            challenge_config,
        ))
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct AAuth {
    mode: Mode,
    required_scheme: RequiredScheme,
    timestamp_tolerance: u64,
    challenge_config: Option<ChallengeConfig>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct ChallengeConfig {
    pub auth_server: String,
    // TODO: Add resource token issuer config
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub enum RequiredScheme {
    Hwk,   // Any signature is sufficient
    Jwks,  // Must have verifiable identity
    Jwt,   // Must have authorization token
}

#[derive(Default, Debug, Clone, Copy, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub enum Mode {
    /// A valid signature must be present and meet required scheme
    #[default]
    Strict,
    /// If signature exists, validate it. Otherwise allow.
    Optional,
    /// Requests are never rejected. Useful for logging/claims extraction.
    Permissive,
}

#[derive(Clone, Debug, Default)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[cfg_attr(feature = "schema", schemars(with = "Map<String, Value>"))]
pub struct AAuthClaims {
    pub inner: Map<String, Value>,
}

impl DynamicType for AAuthClaims {
    fn materialize(&self) -> cel::Value<'_> {
        self.inner.materialize()
    }

    fn field(&self, field: &str) -> Option<cel::Value<'_>> {
        self.inner.field(field)
    }
}

impl AAuth {
    pub fn new(
        mode: Mode,
        required_scheme: RequiredScheme,
        timestamp_tolerance: u64,
        challenge_config: Option<ChallengeConfig>,
    ) -> Self {
        AAuth {
            mode,
            required_scheme,
            timestamp_tolerance,
            challenge_config,
        }
    }

    pub async fn apply(
        &self,
        _log: Option<&mut RequestLog>,
        req: &mut Request,
    ) -> Result<(), AAuthPolicyError> {
        // Extract signature headers
        let sig_key_header = req.headers().get("Signature-Key")
            .and_then(|h| h.to_str().ok());
        let sig_input_header = req.headers().get("Signature-Input")
            .and_then(|h| h.to_str().ok());
        let sig_header = req.headers().get("Signature")
            .and_then(|h| h.to_str().ok());

        // Check if signature is present
        let has_signature = sig_key_header.is_some() 
            && sig_input_header.is_some() 
            && sig_header.is_some();

        if !has_signature {
            if self.mode == Mode::Strict {
                return Err(AAuthPolicyError::MissingSignature);
            }
            // Optional/Permissive: allow request without signature
            return Ok(());
        }

        // Convert headers to HashMap for verification
        let mut header_map = HashMap::new();
        for (name, value) in req.headers() {
            if let Ok(value_str) = value.to_str() {
                header_map.insert(name.as_str().to_string(), value_str.to_string());
            }
        }

        // Build URL from request
        let uri = req.uri();
        let scheme = uri.scheme().map(|s| s.as_str()).unwrap_or("https");
        let authority = uri.authority()
            .map(|a| a.as_str())
            .or_else(|| req.headers().get("host").and_then(|h| h.to_str().ok()))
            .ok_or_else(|| AAuthPolicyError::VerificationFailed("missing authority".to_string()))?;
        let url = format!("{}://{}{}", scheme, authority, uri.path_and_query().map(|pq| pq.as_str()).unwrap_or(""));

        // Read body if present
        let body = if req.headers().contains_key("content-length") || req.headers().contains_key("content-digest") {
            // Try to peek at body, but don't consume it
            // For now, we'll verify without body - full implementation would buffer it
            None
        } else {
            None
        };

        // Verify signature
        // Note: resolver must be Send + Sync for async context
        fn resolver(sig_key: &SignatureKey) -> Result<aauth::keys::ed25519::PublicKey, LibAAuthError> {
            resolve_hwk_public_key(sig_key)
        }

        let verify_result = verify_signature(
            req.method().as_str(),
            &url,
            &header_map,
            body,
            self.timestamp_tolerance,
            &resolver,
        ).await.map_err(|e| AAuthPolicyError::VerificationFailed(e.to_string()))?;

        if !verify_result.valid {
            if self.mode == Mode::Strict {
                return Err(AAuthPolicyError::VerificationFailed("signature invalid".to_string()));
            }
            if self.mode == Mode::Permissive {
                return Ok(());
            }
            // Optional: allow invalid signature
            return Ok(());
        }

        // Check if scheme meets required level
        let scheme_ok = match (self.required_scheme, &verify_result.scheme) {
            (RequiredScheme::Hwk, _) => true,
            (RequiredScheme::Jwks, SignatureScheme::Jwks) => true,
            (RequiredScheme::Jwks, SignatureScheme::Jwt) => true,
            (RequiredScheme::Jwt, SignatureScheme::Jwt) => true,
            _ => false,
        };

        if !scheme_ok {
            // Return challenge response
            return Err(AAuthPolicyError::InsufficientLevel);
        }

        // Store claims
        let mut claims_map = Map::new();
        claims_map.insert("scheme".to_string(), Value::String(format!("{:?}", verify_result.scheme)));
        if let Some(agent) = verify_result.agent_id {
            claims_map.insert("agent".to_string(), Value::String(agent));
        }
        if let Some(delegate) = verify_result.agent_delegate {
            claims_map.insert("agent_delegate".to_string(), Value::String(delegate));
        }
        if let Some(jwt_claims) = verify_result.claims {
            claims_map.insert("jwt_claims".to_string(), Value::Object(jwt_claims));
        }
        claims_map.insert("thumbprint".to_string(), Value::String(String::new())); // TODO: extract from signature key
        
        let claims = AAuthClaims {
            inner: claims_map,
        };

        req.extensions_mut().insert(claims);

        Ok(())
    }

    pub fn build_challenge_response(&self, _current_scheme: Option<SignatureScheme>) -> String {
        match self.required_scheme {
            RequiredScheme::Hwk => "httpsig".to_string(),
            RequiredScheme::Jwks => "httpsig; identity=?1".to_string(),
            RequiredScheme::Jwt => {
                // TODO: Generate resource token if challenge_config is present
                format!(
                    "httpsig; auth-token; resource_token=\"\"; auth_server=\"{}\"",
                    self.challenge_config.as_ref().map(|c| c.auth_server.as_str()).unwrap_or("")
                )
            }
        }
    }
}

impl FromStr for RequiredScheme {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "hwk" => Ok(RequiredScheme::Hwk),
            "jwks" => Ok(RequiredScheme::Jwks),
            "jwt" => Ok(RequiredScheme::Jwt),
            _ => Err(format!("unknown scheme: {}", s)),
        }
    }
}
