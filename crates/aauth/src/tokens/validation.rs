//! JWT validation utilities for AAuth tokens
//!
//! This module provides shared utilities for validating agent+jwt and auth+jwt tokens
//! and extracting the cnf.jwk claim for HTTP message signature verification.

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::errors::AAuthError;
use crate::keys::jwk::JWK;

/// The `cnf` (confirmation) claim containing the proof-of-possession key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnfClaim {
    /// The JWK for the key bound to this token
    pub jwk: JWK,
}

/// Result of validating an AAuth JWT token
#[derive(Debug, Clone)]
pub struct JwtValidationResult {
    /// The issuer (iss claim)
    pub issuer: String,
    /// The subject (sub claim) - optional
    pub subject: Option<String>,
    /// The agent identifier - for auth+jwt this is the `agent` claim, for agent+jwt this is `iss`
    pub agent_id: Option<String>,
    /// The delegate identifier - for agent+jwt this is `sub`
    pub agent_delegate: Option<String>,
    /// Scopes from auth+jwt tokens
    pub scopes: Option<Vec<String>>,
    /// The cnf.jwk claim containing the bound public key
    pub cnf_jwk: JWK,
    /// All claims from the token
    pub claims: Map<String, Value>,
}

/// Decode JWT header without validation to extract metadata
pub fn decode_jwt_header(jwt: &str) -> Result<jsonwebtoken::Header, AAuthError> {
    decode_header(jwt).map_err(|e| AAuthError::JwtValidationError(format!("invalid JWT header: {}", e)))
}

/// Decode JWT claims without signature validation (for extracting issuer before JWKS fetch)
/// 
/// WARNING: This does NOT validate the signature. Only use to extract claims needed
/// for JWKS discovery (like `iss`). The token MUST be validated with `validate_jwt`
/// before trusting any claims.
pub fn decode_jwt_claims_unverified(jwt: &str) -> Result<Map<String, Value>, AAuthError> {
    // Split JWT into parts
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(AAuthError::JwtValidationError("invalid JWT format".to_string()));
    }

    // Decode payload (second part)
    let payload_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        parts[1],
    )
    .map_err(|e| AAuthError::JwtValidationError(format!("invalid JWT payload encoding: {}", e)))?;

    let claims: Map<String, Value> = serde_json::from_slice(&payload_bytes)
        .map_err(|e| AAuthError::JwtValidationError(format!("invalid JWT payload JSON: {}", e)))?;

    Ok(claims)
}

/// Validate a JWT token using a JWK for signature verification
///
/// Supports multiple key types:
/// - OKP/Ed25519 (EdDSA) - typically used by agent tokens
/// - RSA (RS256, RS384, RS512) - typically used by auth servers like Keycloak
/// - EC (ES256, ES384) - also supported
///
/// # Arguments
/// * `jwt` - The JWT token string
/// * `signing_jwk` - The JWK used to sign the token (from issuer's JWKS)
/// * `expected_typ` - Optional expected `typ` header value (e.g., "agent+jwt", "auth+jwt")
///
/// # Returns
/// The validated claims as a JSON map
pub fn validate_jwt(
    jwt: &str,
    signing_jwk: &JWK,
    expected_typ: Option<&str>,
) -> Result<Map<String, Value>, AAuthError> {
    // Check typ header if expected
    if let Some(expected) = expected_typ {
        let header = decode_jwt_header(jwt)?;
        let typ = header.typ.as_deref().unwrap_or("");
        if typ != expected {
            return Err(AAuthError::JwtValidationError(format!(
                "expected typ={}, got typ={}",
                expected, typ
            )));
        }
    }

    // Build decoding key and determine algorithms based on JWK type
    let (decoding_key, algorithms) = match signing_jwk.kty.as_str() {
        "OKP" => {
            // Ed25519/EdDSA
            let crv = signing_jwk.crv.as_deref().unwrap_or("");
            if crv != "Ed25519" {
                return Err(AAuthError::JwtValidationError(format!(
                    "unsupported OKP curve: {}", crv
                )));
            }
            let x = signing_jwk.x.as_ref().ok_or_else(|| {
                AAuthError::JwtValidationError("OKP JWK missing x parameter".to_string())
            })?;
            let key = DecodingKey::from_ed_components(x)
                .map_err(|e| AAuthError::JwtValidationError(format!("invalid Ed25519 key: {}", e)))?;
            (key, vec![Algorithm::EdDSA])
        }
        "RSA" => {
            // RSA keys (RS256, RS384, RS512)
            let n = signing_jwk.n.as_ref().ok_or_else(|| {
                AAuthError::JwtValidationError("RSA JWK missing n parameter".to_string())
            })?;
            let e = signing_jwk.e.as_ref().ok_or_else(|| {
                AAuthError::JwtValidationError("RSA JWK missing e parameter".to_string())
            })?;
            let key = DecodingKey::from_rsa_components(n, e)
                .map_err(|e| AAuthError::JwtValidationError(format!("invalid RSA key: {}", e)))?;
            // Support all RSA algorithms
            (key, vec![Algorithm::RS256, Algorithm::RS384, Algorithm::RS512])
        }
        "EC" => {
            // Elliptic curve keys (ES256, ES384)
            let x = signing_jwk.x.as_ref().ok_or_else(|| {
                AAuthError::JwtValidationError("EC JWK missing x parameter".to_string())
            })?;
            let y = signing_jwk.y.as_ref().ok_or_else(|| {
                AAuthError::JwtValidationError("EC JWK missing y parameter".to_string())
            })?;
            let key = DecodingKey::from_ec_components(x, y)
                .map_err(|e| AAuthError::JwtValidationError(format!("invalid EC key: {}", e)))?;
            // Support ES256 and ES384
            (key, vec![Algorithm::ES256, Algorithm::ES384])
        }
        other => {
            return Err(AAuthError::JwtValidationError(format!(
                "unsupported key type: {}", other
            )));
        }
    };

    // Configure validation
    let mut validation = Validation::new(algorithms[0]);
    validation.algorithms = algorithms;
    // Disable audience validation (AAuth tokens may not have aud)
    validation.validate_aud = false;
    // We'll validate issuer separately if needed
    validation.set_required_spec_claims::<&str>(&[]);

    // Decode and validate
    let token_data = decode::<Map<String, Value>>(jwt, &decoding_key, &validation)
        .map_err(|e| AAuthError::JwtValidationError(format!("JWT validation failed: {}", e)))?;

    Ok(token_data.claims)
}

/// Extract the cnf.jwk claim from JWT claims
pub fn extract_cnf_jwk(claims: &Map<String, Value>) -> Result<JWK, AAuthError> {
    let cnf = claims.get("cnf").ok_or_else(|| {
        AAuthError::JwtValidationError("missing cnf claim".to_string())
    })?;

    let cnf_obj = cnf.as_object().ok_or_else(|| {
        AAuthError::JwtValidationError("cnf claim is not an object".to_string())
    })?;

    let jwk_value = cnf_obj.get("jwk").ok_or_else(|| {
        AAuthError::JwtValidationError("missing cnf.jwk claim".to_string())
    })?;

    let jwk: JWK = serde_json::from_value(jwk_value.clone())
        .map_err(|e| AAuthError::JwtValidationError(format!("invalid cnf.jwk: {}", e)))?;

    Ok(jwk)
}

/// Extract a string claim from JWT claims
pub fn get_string_claim(claims: &Map<String, Value>, name: &str) -> Option<String> {
    claims.get(name).and_then(|v| v.as_str()).map(|s| s.to_string())
}

/// Extract scopes from the `scope` claim (space-separated string)
pub fn get_scopes(claims: &Map<String, Value>) -> Option<Vec<String>> {
    claims.get("scope")
        .and_then(|v| v.as_str())
        .map(|s| s.split_whitespace().map(|s| s.to_string()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_cnf_jwk() {
        let mut claims = Map::new();
        let mut cnf = serde_json::Map::new();
        cnf.insert("jwk".to_string(), serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
        }));
        claims.insert("cnf".to_string(), Value::Object(cnf));

        let jwk = extract_cnf_jwk(&claims).unwrap();
        assert_eq!(jwk.kty, "OKP");
        assert_eq!(jwk.crv, Some("Ed25519".to_string()));
    }

    #[test]
    fn test_extract_cnf_jwk_missing() {
        let claims = Map::new();
        let result = extract_cnf_jwk(&claims);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_scopes() {
        let mut claims = Map::new();
        claims.insert("scope".to_string(), Value::String("read write admin".to_string()));
        
        let scopes = get_scopes(&claims).unwrap();
        assert_eq!(scopes, vec!["read", "write", "admin"]);
    }
}
