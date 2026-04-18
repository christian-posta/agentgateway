//! Auth token (aa-auth+jwt) validation per AAuth spec Section 7
//!
//! Auth tokens are JWTs that:
//! - Have typ="aa-auth+jwt" in the header
//! - Are signed by an authorization server
//! - Contain a cnf.jwk claim with the public key for HTTP signature verification
//! - iss identifies the authorization server (HTTPS URL, host-only)
//! - agent identifies the agent making the request (matches sub from the agent token)
//! - act (REQUIRED, RFC 8693) actor claim — act.sub MUST match the agent claim
//! - dwk (REQUIRED) names the discovery document ("aauth-access.json" or "aauth-person.json")
//! - jti (REQUIRED) unique identifier for replay detection
//! - sub identifies the user who authorized the agent (optional)
//! - scope contains the granted permissions (optional)
//! - At least one of sub or scope MUST be present

use serde_json::{Map, Value};

use crate::errors::AAuthError;
use crate::keys::jwk::JWK;
use crate::tokens::validation::{
	decode_jwt_claims_unverified, decode_jwt_header, extract_cnf_jwk, get_scopes, get_string_claim,
	is_acceptable_jwt_issuer_url, validate_jwt,
};

/// The `typ` header value required for AAuth auth tokens
pub const AUTH_TOKEN_TYP: &str = "aa-auth+jwt";

/// Result of validating an aa-auth+jwt token
#[derive(Debug, Clone)]
pub struct AuthTokenResult {
	/// The authorization server (iss claim)
	pub issuer: String,
	/// The agent identifier (agent claim) — matches sub from the agent token
	pub agent_id: String,
	/// The actor claim sub (act.sub) — MUST match agent_id
	pub act_sub: String,
	/// The discovery document name (dwk claim)
	pub dwk: String,
	/// The unique token identifier (jti claim)
	pub jti: String,
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

fn claim_matches_audience(claims: &Map<String, Value>, expected_audience: &str) -> bool {
	match claims.get("aud") {
		Some(Value::String(aud)) => aud == expected_audience,
		Some(Value::Array(values)) => values
			.iter()
			.filter_map(Value::as_str)
			.any(|aud| aud == expected_audience),
		_ => false,
	}
}

/// Extract act.sub from the act claim per RFC 8693
fn extract_act_sub(claims: &Map<String, Value>) -> Result<String, AAuthError> {
	let act = claims
		.get("act")
		.ok_or_else(|| AAuthError::MissingClaim("act".to_string()))?;
	let act_obj = act
		.as_object()
		.ok_or_else(|| AAuthError::JwtValidationError("act claim is not an object".to_string()))?;
	act_obj
		.get("sub")
		.and_then(|v| v.as_str())
		.map(|s| s.to_string())
		.ok_or_else(|| AAuthError::MissingClaim("act.sub".to_string()))
}

/// Validate aa-auth+jwt token per AAuth spec Section 7
///
/// This function validates the JWT signature using the provided signing JWK (from the auth server's JWKS).
/// The caller is responsible for:
/// 1. Extracting the issuer from the token (using `get_auth_token_issuer`)
/// 2. Fetching the JWKS from the auth server
/// 3. Finding the correct key by `kid`
///
/// # Arguments
/// * `jwt` - The aa-auth+jwt token string
/// * `signing_jwk` - The JWK from the auth server's JWKS used to sign this token
/// * `expected_audience` - The audience this resource server expects
/// * `expected_agent` - The agent identifier to match against the `agent` claim (optional)
pub fn validate_auth_token(
	jwt: &str,
	signing_jwk: &JWK,
	expected_audience: &str,
	expected_agent: Option<&str>,
	allow_insecure_http_issuer: bool,
) -> Result<AuthTokenResult, AAuthError> {
	// Check typ header — must be "aa-auth+jwt"
	let header = decode_jwt_header(jwt)?;
	let typ = header.typ.as_deref().unwrap_or("");
	if typ != AUTH_TOKEN_TYP {
		return Err(AAuthError::JwtValidationError(format!(
			"expected typ={}, got typ={}",
			AUTH_TOKEN_TYP, typ
		)));
	}

	// Validate JWT signature (also validates exp and iat)
	let claims = validate_jwt(jwt, signing_jwk, None)?;

	// Extract required claims
	let issuer = get_string_claim(&claims, "iss")
		.ok_or_else(|| AAuthError::MissingClaim("iss".to_string()))?;
	if !is_acceptable_jwt_issuer_url(&issuer, allow_insecure_http_issuer) {
		return Err(AAuthError::InvalidIssuerUrl);
	}

	let agent_id = get_string_claim(&claims, "agent")
		.ok_or_else(|| AAuthError::MissingClaim("agent".to_string()))?;
	if let Some(expected_agent) = expected_agent {
		if agent_id != expected_agent {
			return Err(AAuthError::JwtValidationError(format!(
				"auth token agent mismatch: expected {}, got {}",
				expected_agent, agent_id
			)));
		}
	}

	if !claim_matches_audience(&claims, expected_audience) {
		return Err(AAuthError::AudienceMismatch);
	}

	// act claim is REQUIRED per spec; act.sub MUST match agent claim
	let act_sub = extract_act_sub(&claims)?;
	if act_sub != agent_id {
		return Err(AAuthError::ActClaimMismatch);
	}

	// dwk is REQUIRED
	let dwk = get_string_claim(&claims, "dwk")
		.ok_or_else(|| AAuthError::MissingClaim("dwk".to_string()))?;

	// jti is REQUIRED for replay detection
	let jti = get_string_claim(&claims, "jti")
		.ok_or_else(|| AAuthError::MissingClaim("jti".to_string()))?;

	// Extract optional claims
	let user_id = get_string_claim(&claims, "sub");
	let scopes = get_scopes(&claims);
	let audience = get_string_claim(&claims, "aud");
	if user_id.is_none() && scopes.is_none() {
		return Err(AAuthError::JwtValidationError(
			"auth token must contain at least one of sub or scope".to_string(),
		));
	}

	// Extract cnf.jwk
	let cnf_jwk = extract_cnf_jwk(&claims)?;

	Ok(AuthTokenResult {
		issuer,
		agent_id,
		act_sub,
		dwk,
		jti,
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

	fn make_test_claims() -> Map<String, Value> {
		let mut claims = Map::new();
		claims.insert(
			"iss".to_string(),
			Value::String("https://auth.example.com".to_string()),
		);
		claims.insert(
			"agent".to_string(),
			Value::String("aauth:local@agent.example.com".to_string()),
		);
		claims.insert("sub".to_string(), Value::String("user-456".to_string()));
		claims.insert("scope".to_string(), Value::String("read write".to_string()));
		claims.insert(
			"aud".to_string(),
			Value::String("https://resource.example.com".to_string()),
		);
		claims.insert("dwk".to_string(), Value::String("aauth-access.json".to_string()));
		claims.insert("jti".to_string(), Value::String("unique-auth-token-456".to_string()));

		// act claim per RFC 8693
		let mut act = serde_json::Map::new();
		act.insert(
			"sub".to_string(),
			Value::String("aauth:local@agent.example.com".to_string()),
		);
		claims.insert("act".to_string(), Value::Object(act));

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

	#[test]
	fn test_extract_act_sub() {
		let claims = make_test_claims();
		let act_sub = extract_act_sub(&claims).unwrap();
		assert_eq!(act_sub, "aauth:local@agent.example.com");
	}
}
