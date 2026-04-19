//! Agent token (aa-agent+jwt) validation per AAuth spec Section 5
//!
//! Agent tokens are JWTs that:
//! - Have typ="aa-agent+jwt" in the header
//! - Are signed by the agent server (issuer)
//! - Contain a cnf.jwk claim with the public key for HTTP signature verification
//! - iss identifies the agent server (HTTPS URL, host-only)
//! - sub (REQUIRED) is the stable agent identifier across key rotations
//! - dwk (REQUIRED) must be "aauth-agent.json" - names the discovery document
//! - jti (REQUIRED) is a unique identifier for replay detection

use serde_json::{Map, Value};

use crate::errors::AAuthError;
use http_sig::keys::jwk::JWK;
use crate::tokens::validation::{
	decode_jwt_claims_unverified, decode_jwt_header, extract_cnf_jwk, get_string_claim,
	is_acceptable_jwt_issuer_url, validate_jwt,
};

/// The `typ` header value required for AAuth agent tokens
pub const AGENT_TOKEN_TYP: &str = "aa-agent+jwt";

/// The required `dwk` claim value for agent tokens
pub const AGENT_TOKEN_DWK: &str = "aauth-agent.json";

/// Result of validating an aa-agent+jwt token
#[derive(Debug, Clone)]
pub struct AgentTokenResult {
	/// The agent server URL (iss claim)
	pub agent_id: String,
	/// The stable agent identifier (sub claim) - REQUIRED per spec
	pub subject: String,
	/// The discovery document name (dwk claim) — always "aauth-agent.json"
	pub dwk: String,
	/// The unique token identifier (jti claim)
	pub jti: String,
	/// The cnf.jwk public key for HTTP signature verification
	pub cnf_jwk: JWK,
	/// All claims from the token
	pub claims: Map<String, Value>,
}

/// Validate aa-agent+jwt token per AAuth spec Section 5
///
/// This function validates the JWT signature using the provided signing JWK (from the agent's JWKS).
/// The caller is responsible for:
/// 1. Extracting the issuer from the token (using `get_agent_token_issuer`)
/// 2. Fetching the JWKS from `{iss}/.well-known/aauth-agent.json`
/// 3. Finding the correct key by `kid`
///
/// # Arguments
/// * `jwt` - The aa-agent+jwt token string
/// * `signing_jwk` - The JWK from the agent's JWKS used to sign this token
pub fn validate_agent_token(
	jwt: &str,
	signing_jwk: &JWK,
	expected_audience: Option<&str>,
	allow_insecure_http_issuer: bool,
) -> Result<AgentTokenResult, AAuthError> {
	// Check typ header — must be "aa-agent+jwt"
	let header = decode_jwt_header(jwt)?;
	let typ = header.typ.as_deref().unwrap_or("");
	if typ != AGENT_TOKEN_TYP {
		return Err(AAuthError::JwtValidationError(format!(
			"expected typ={}, got typ={}",
			AGENT_TOKEN_TYP, typ
		)));
	}

	// Validate JWT signature (also validates exp and iat)
	let claims = validate_jwt(jwt, signing_jwk, None)?;

	// Validate aud claim if an expected audience is provided
	if let Some(expected_aud) = expected_audience {
		if let Some(aud_val) = claims.get("aud") {
			let has_audience = match aud_val {
				Value::String(s) => s == expected_aud,
				Value::Array(arr) => arr
					.iter()
					.filter_map(|v| v.as_str())
					.any(|s| s == expected_aud),
				_ => false,
			};
			if !has_audience {
				return Err(AAuthError::AudienceMismatch);
			}
		}
	}

	// Extract required claims
	let agent_id = get_string_claim(&claims, "iss").ok_or_else(|| {
		AAuthError::MissingClaim("iss".to_string())
	})?;
	if !is_acceptable_jwt_issuer_url(&agent_id, allow_insecure_http_issuer) {
		return Err(AAuthError::InvalidIssuerUrl);
	}

	// sub is REQUIRED in agent tokens — the stable agent identifier
	let subject = get_string_claim(&claims, "sub")
		.ok_or_else(|| AAuthError::MissingClaim("sub".to_string()))?;

	// dwk is REQUIRED — must be "aauth-agent.json"
	let dwk = get_string_claim(&claims, "dwk")
		.ok_or_else(|| AAuthError::MissingClaim("dwk".to_string()))?;
	if dwk != AGENT_TOKEN_DWK {
		return Err(AAuthError::JwtValidationError(format!(
			"agent token dwk must be \"{}\", got \"{}\"",
			AGENT_TOKEN_DWK, dwk
		)));
	}

	// jti is REQUIRED for replay detection
	let jti = get_string_claim(&claims, "jti")
		.ok_or_else(|| AAuthError::MissingClaim("jti".to_string()))?;

	// Extract cnf.jwk
	let cnf_jwk = extract_cnf_jwk(&claims)?;

	Ok(AgentTokenResult {
		agent_id,
		subject,
		dwk,
		jti,
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

	fn make_test_claims() -> Map<String, Value> {
		let mut claims = Map::new();
		claims.insert(
			"iss".to_string(),
			Value::String("https://agent.example.com".to_string()),
		);
		claims.insert("sub".to_string(), Value::String("aauth:local@agent.example.com".to_string()));
		claims.insert("dwk".to_string(), Value::String("aauth-agent.json".to_string()));
		claims.insert("jti".to_string(), Value::String("unique-token-id-123".to_string()));

		let mut cnf = serde_json::Map::new();
		cnf.insert(
			"jwk".to_string(),
			serde_json::json!({
					"kty": "OKP",
					"crv": "Ed25519",
					"x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
			}),
		);
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
