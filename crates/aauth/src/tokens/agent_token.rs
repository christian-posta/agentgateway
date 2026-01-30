//! Agent token (agent+jwt) validation per AAuth spec Section 5
//!
//! Agent tokens are JWTs that:
//! - Have typ="agent+jwt" or typ="at+jwt" in the header
//! - Are signed by the agent server (issuer)
//! - Contain a cnf.jwk claim with the public key for HTTP signature verification
//! - iss identifies the agent server
//! - sub (optional) identifies the delegate

use serde_json::{Map, Value};

use crate::errors::AAuthError;
use crate::keys::jwk::JWK;
use crate::tokens::validation::{
    decode_jwt_claims_unverified, decode_jwt_header, extract_cnf_jwk, get_string_claim, validate_jwt,
};

/// Result of validating an agent+jwt token
#[derive(Debug, Clone)]
pub struct AgentTokenResult {
    /// The agent identifier (iss claim)
    pub agent_id: String,
    /// The delegate identifier (sub claim) - optional
    pub delegate_id: Option<String>,
    /// The cnf.jwk public key for HTTP signature verification
    pub cnf_jwk: JWK,
    /// All claims from the token
    pub claims: Map<String, Value>,
}

/// Validate agent+jwt token per AAuth spec Section 5
///
/// This function validates the JWT signature using the provided signing JWK (from the agent's JWKS).
/// The caller is responsible for:
/// 1. Extracting the issuer from the token (using `get_agent_token_issuer`)
/// 2. Fetching the JWKS from `{iss}/.well-known/aauth-agent`
/// 3. Finding the correct key by `kid`
///
/// # Arguments
/// * `jwt` - The agent+jwt token string
/// * `signing_jwk` - The JWK from the agent's JWKS used to sign this token
///
/// # Returns
/// `AgentTokenResult` containing the agent_id (iss), delegate_id (sub), and cnf.jwk
pub fn validate_agent_token(jwt: &str, signing_jwk: &JWK) -> Result<AgentTokenResult, AAuthError> {
    // Check typ header - accept both "agent+jwt" and "at+jwt"
    let header = decode_jwt_header(jwt)?;
    let typ = header.typ.as_deref().unwrap_or("");
    if typ != "agent+jwt" && typ != "at+jwt" {
        return Err(AAuthError::JwtValidationError(format!(
            "expected typ=agent+jwt or at+jwt, got typ={}",
            typ
        )));
    }

    // Validate JWT signature
    let claims = validate_jwt(jwt, signing_jwk, None)?;

    // Extract required claims
    let agent_id = get_string_claim(&claims, "iss").ok_or_else(|| {
        AAuthError::JwtValidationError("missing iss claim in agent token".to_string())
    })?;

    let delegate_id = get_string_claim(&claims, "sub");

    // Extract cnf.jwk
    let cnf_jwk = extract_cnf_jwk(&claims)?;

    Ok(AgentTokenResult {
        agent_id,
        delegate_id,
        cnf_jwk,
        claims,
    })
}

/// Get the issuer (agent server) from an agent token without validation
///
/// Use this to determine which JWKS to fetch before calling `validate_agent_token`.
/// WARNING: The token has not been validated at this point - do not trust these claims
/// for anything other than JWKS discovery.
pub fn get_agent_token_issuer(jwt: &str) -> Result<String, AAuthError> {
    let claims = decode_jwt_claims_unverified(jwt)?;
    get_string_claim(&claims, "iss")
        .ok_or_else(|| AAuthError::JwtValidationError("missing iss claim".to_string()))
}

/// Get the key ID (kid) from an agent token header
///
/// Use this to find the correct key in the agent's JWKS.
pub fn get_agent_token_kid(jwt: &str) -> Result<Option<String>, AAuthError> {
    let header = decode_jwt_header(jwt)?;
    Ok(header.kid)
}

/// Extract public key from agent token's cnf.jwk claim without full validation
///
/// This extracts the cnf.jwk from the token payload. Note that this does NOT validate
/// the token signature - you should call `validate_agent_token` first to ensure
/// the token is trustworthy.
pub fn extract_agent_token_key(jwt: &str) -> Result<JWK, AAuthError> {
    let claims = decode_jwt_claims_unverified(jwt)?;
    extract_cnf_jwk(&claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test helper to create a simple JWT structure (not cryptographically valid)
    fn make_test_claims() -> Map<String, Value> {
        let mut claims = Map::new();
        claims.insert("iss".to_string(), Value::String("https://agent.example.com".to_string()));
        claims.insert("sub".to_string(), Value::String("delegate-123".to_string()));
        
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
    fn test_extract_agent_token_key_from_claims() {
        let claims = make_test_claims();
        let jwk = extract_cnf_jwk(&claims).unwrap();
        assert_eq!(jwk.kty, "OKP");
        assert_eq!(jwk.crv, Some("Ed25519".to_string()));
    }
}
