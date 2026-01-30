//! Auth token (auth+jwt) validation per AAuth spec Section 7
//!
//! Auth tokens are JWTs that:
//! - Have typ="auth+jwt" in the header
//! - Are signed by an authorization server
//! - Contain a cnf.jwk claim with the public key for HTTP signature verification
//! - iss identifies the authorization server
//! - agent identifies the agent making the request
//! - sub identifies the user who authorized the agent
//! - scope contains the granted permissions

use serde_json::{Map, Value};

use crate::errors::AAuthError;
use crate::keys::jwk::JWK;
use crate::tokens::validation::{
    decode_jwt_claims_unverified, decode_jwt_header, extract_cnf_jwk, get_scopes, get_string_claim,
    validate_jwt,
};

/// Result of validating an auth+jwt token
#[derive(Debug, Clone)]
pub struct AuthTokenResult {
    /// The authorization server (iss claim)
    pub issuer: String,
    /// The agent identifier (agent claim)
    pub agent_id: String,
    /// The user identifier (sub claim) - optional
    pub user_id: Option<String>,
    /// The granted scopes (scope claim) - optional
    pub scopes: Option<Vec<String>>,
    /// The intended audience (aud claim) - optional
    pub audience: Option<String>,
    /// The cnf.jwk public key for HTTP signature verification
    pub cnf_jwk: JWK,
    /// All claims from the token
    pub claims: Map<String, Value>,
}

/// Validate auth+jwt token per AAuth spec Section 7
///
/// This function validates the JWT signature using the provided signing JWK (from the auth server's JWKS).
/// The caller is responsible for:
/// 1. Extracting the issuer from the token (using `get_auth_token_issuer`)
/// 2. Fetching the JWKS from the auth server
/// 3. Finding the correct key by `kid`
///
/// # Arguments
/// * `jwt` - The auth+jwt token string
/// * `signing_jwk` - The JWK from the auth server's JWKS used to sign this token
///
/// # Returns
/// `AuthTokenResult` containing the issuer, agent_id, user_id, scopes, and cnf.jwk
pub fn validate_auth_token(jwt: &str, signing_jwk: &JWK) -> Result<AuthTokenResult, AAuthError> {
    // Check typ header
    let header = decode_jwt_header(jwt)?;
    let typ = header.typ.as_deref().unwrap_or("");
    if typ != "auth+jwt" {
        return Err(AAuthError::JwtValidationError(format!(
            "expected typ=auth+jwt, got typ={}",
            typ
        )));
    }

    // Validate JWT signature
    let claims = validate_jwt(jwt, signing_jwk, None)?;

    // Extract required claims
    let issuer = get_string_claim(&claims, "iss").ok_or_else(|| {
        AAuthError::JwtValidationError("missing iss claim in auth token".to_string())
    })?;

    let agent_id = get_string_claim(&claims, "agent").ok_or_else(|| {
        AAuthError::JwtValidationError("missing agent claim in auth token".to_string())
    })?;

    // Extract optional claims
    let user_id = get_string_claim(&claims, "sub");
    let scopes = get_scopes(&claims);
    let audience = get_string_claim(&claims, "aud");

    // Extract cnf.jwk
    let cnf_jwk = extract_cnf_jwk(&claims)?;

    Ok(AuthTokenResult {
        issuer,
        agent_id,
        user_id,
        scopes,
        audience,
        cnf_jwk,
        claims,
    })
}

/// Get the issuer (auth server) from an auth token without validation
///
/// Use this to determine which JWKS to fetch before calling `validate_auth_token`.
/// WARNING: The token has not been validated at this point - do not trust these claims
/// for anything other than JWKS discovery.
pub fn get_auth_token_issuer(jwt: &str) -> Result<String, AAuthError> {
    let claims = decode_jwt_claims_unverified(jwt)?;
    get_string_claim(&claims, "iss")
        .ok_or_else(|| AAuthError::JwtValidationError("missing iss claim".to_string()))
}

/// Get the key ID (kid) from an auth token header
///
/// Use this to find the correct key in the auth server's JWKS.
pub fn get_auth_token_kid(jwt: &str) -> Result<Option<String>, AAuthError> {
    let header = decode_jwt_header(jwt)?;
    Ok(header.kid)
}

/// Extract public key from auth token's cnf.jwk claim without full validation
///
/// This extracts the cnf.jwk from the token payload. Note that this does NOT validate
/// the token signature - you should call `validate_auth_token` first to ensure
/// the token is trustworthy.
pub fn extract_auth_token_key(jwt: &str) -> Result<JWK, AAuthError> {
    let claims = decode_jwt_claims_unverified(jwt)?;
    extract_cnf_jwk(&claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test helper to create a simple JWT structure (not cryptographically valid)
    fn make_test_claims() -> Map<String, Value> {
        let mut claims = Map::new();
        claims.insert("iss".to_string(), Value::String("https://auth.example.com".to_string()));
        claims.insert("agent".to_string(), Value::String("https://agent.example.com".to_string()));
        claims.insert("sub".to_string(), Value::String("user-456".to_string()));
        claims.insert("scope".to_string(), Value::String("read write".to_string()));
        claims.insert("aud".to_string(), Value::String("https://resource.example.com".to_string()));
        
        let mut cnf = serde_json::Map::new();
        cnf.insert("jwk".to_string(), serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
        }));
        claims.insert("cnf".to_string(), Value::Object(cnf));
        
        claims
    }

    #[test]
    fn test_extract_auth_token_key_from_claims() {
        let claims = make_test_claims();
        let jwk = extract_cnf_jwk(&claims).unwrap();
        assert_eq!(jwk.kty, "OKP");
    }

    #[test]
    fn test_get_scopes_from_claims() {
        let claims = make_test_claims();
        let scopes = get_scopes(&claims).unwrap();
        assert_eq!(scopes, vec!["read", "write"]);
    }
}
