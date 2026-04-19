use crate::digest::calculate_content_digest;
use crate::errors::Error;
use crate::headers::{SignatureKey, parse_signature, parse_signature_input, parse_signature_key};
use crate::keys::ed25519::{PublicKey, public_key_from_bytes, verify};
use crate::signing::signature_base::build_signature_base;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Get header value with case-insensitive key lookup (HTTP headers are case-insensitive).
fn get_header<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a String> {
	headers.get(name).or_else(|| {
		headers
			.iter()
			.find(|(k, _)| k.eq_ignore_ascii_case(name))
			.map(|(_, v)| v)
	})
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureScheme {
	Hwk,  // Pseudonymous - inline public key
	Jwks, // Identified - JWKS discovery
	Jwt,  // Authorized - JWT with cnf claim
}

#[derive(Debug, Clone)]
pub struct VerificationResult {
	pub valid: bool,
	pub scheme: SignatureScheme,
	pub agent_id: Option<String>,       // For jwks/jwt schemes
	pub agent_delegate: Option<String>, // For jwt with agent token
	pub claims: Option<serde_json::Map<String, serde_json::Value>>, // JWT claims if present
}

/// Verify HTTP Message Signature per RFC 9421 and AAuth profile
///
/// Algorithm:
/// 1. Extract and parse Signature-Key header
/// 2. Extract and parse Signature-Input header
/// 3. Extract and parse Signature header
/// 4. VERIFY LABEL CONSISTENCY (all three must match)
/// 5. Verify created timestamp is within tolerance
/// 6. Verify signature-key is in covered components
/// 7. Resolve public key based on scheme
/// 8. Rebuild signature base from request and Signature-Input
/// 9. Verify Ed25519 signature
/// 10. If body present and content-digest covered, verify Content-Digest
///
/// If `authority_override` is provided (e.g. "hostname:port" from the gateway's route and listener),
/// it is used as the @authority component when rebuilding the signature base. Otherwise the
/// authority is derived from the URL (host + port if present).
pub fn verify_signature(
	method: &str,
	url: &str,
	headers: &HashMap<String, String>,
	_body: Option<&[u8]>,
	timestamp_tolerance: u64,
	public_key_resolver: &(dyn Fn(&SignatureKey) -> Result<PublicKey, Error> + Send + Sync),
	authority_override: Option<&str>,
) -> Result<VerificationResult, Error> {
	// 1-3. Extract and parse headers (case-insensitive: proxy may send lowercase keys)
	let sig_key_header = get_header(headers, "Signature-Key")
        .ok_or_else(|| {
            tracing::debug!(header_keys = ?headers.keys().collect::<Vec<_>>(), "signature verification: missing Signature-Key header");
            Error::MissingSignatureKey
        })?;
	let sig_input_header =
		get_header(headers, "Signature-Input").ok_or(Error::MissingSignatureInput)?;
	let sig_header = get_header(headers, "Signature").ok_or(Error::MissingSignature)?;

	tracing::debug!(
		signature_key = sig_key_header.as_str(),
		"parsed signature headers"
	);

	let sig_key = parse_signature_key(sig_key_header)?;
	let sig_input = parse_signature_input(sig_input_header)?;
	let (sig_label, sig_bytes) = parse_signature(sig_header)?;

	tracing::debug!(scheme = %sig_key.scheme, label = %sig_key.label, sig_bytes_len = sig_bytes.len(), "signature key and input parsed");

	// 4. Verify label consistency
	if sig_key.label != sig_input.label || sig_key.label != sig_label {
		tracing::debug!(sig_key_label = %sig_key.label, sig_input_label = %sig_input.label, sig_label = %sig_label, "label mismatch");
		return Err(Error::LabelMismatch);
	}

	// 5. Verify timestamp
	let now = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap()
		.as_secs();
	let time_diff = if now > sig_input.params.created {
		now - sig_input.params.created
	} else {
		sig_input.params.created - now
	};
	if time_diff > timestamp_tolerance {
		tracing::debug!(
			created = sig_input.params.created,
			now,
			time_diff,
			tolerance = timestamp_tolerance,
			"signature timestamp outside tolerance"
		);
		return Err(Error::TimestampExpired);
	}

	// 6. Verify required components are covered
	let required_components = ["@method", "@authority", "@path", "signature-key"];
	for req_comp in required_components {
		if !sig_input.components.iter().any(|c| c == req_comp) {
			tracing::debug!(
				missing_component = req_comp,
				"required component missing from signature base"
			);
			return Err(Error::InvalidSignature(format!(
				"missing required component: {}",
				req_comp
			)));
		}
	}

	if headers.contains_key("content-digest") {
		if !sig_input.components.iter().any(|c| c == "content-digest") {
			tracing::debug!("request has content-digest but it is not covered");
			return Err(Error::InvalidSignature(
				"missing content-digest in covered components".to_string(),
			));
		}
	}

	if headers.contains_key("authorization") {
		if !sig_input.components.iter().any(|c| c == "authorization") {
			tracing::debug!("request has authorization header but it is not covered");
			return Err(Error::InvalidSignature(
				"missing authorization in covered components".to_string(),
			));
		}
	}

	// 7. Resolve public key based on scheme
	tracing::debug!(scheme = %sig_key.scheme, id = ?sig_key.params.get("id"), kid = ?sig_key.params.get("kid"), "resolving public key");
	let public_key = public_key_resolver(&sig_key).map_err(|e| {
		tracing::debug!(error = %e, "public key resolution failed");
		e
	})?;
	let scheme = match sig_key.scheme.as_str() {
		"hwk" => SignatureScheme::Hwk,
		"jwks_uri" => SignatureScheme::Jwks,
		"jwt" => SignatureScheme::Jwt,
		s => return Err(Error::UnsupportedScheme(s.to_string())),
	};

	// Parse URL to extract authority, path, query
	let parsed_url = url::Url::parse(url)?;
	let authority: String = if let Some(override_auth) = authority_override {
		override_auth.to_string()
	} else {
		let host = parsed_url
			.host_str()
			.ok_or_else(|| Error::InvalidHeader("missing host in URL".to_string()))?;
		let port = parsed_url.port();
		format!(
			"{}{}",
			host,
			port.map(|p| format!(":{}", p)).unwrap_or_default()
		)
	};
	let path = parsed_url.path();
	let query = parsed_url.query();

	// 8. Rebuild signature base
	let signature_base = build_signature_base(
		method,
		&authority,
		path,
		query,
		headers,
		&sig_input
			.components
			.iter()
			.map(|s| s.as_str())
			.collect::<Vec<_>>(),
		&sig_input.params,
	)?;

	tracing::debug!(
			signature_base_len = signature_base.len(),
			signature_base = %signature_base.replace('\n', "\\n"),
			"rebuilt signature base for verification"
	);

	// 9. Verify Ed25519 signature
	let is_valid = verify(signature_base.as_bytes(), &sig_bytes, &public_key);
	if !is_valid {
		tracing::debug!(
			sig_bytes_len = sig_bytes.len(),
			expected_sig_len = 64,
			"Ed25519 signature verification failed: signature invalid"
		);
		return Err(Error::InvalidSignature(
			"signature verification failed".to_string(),
		));
	}
	tracing::debug!("Ed25519 signature verification succeeded");

	// 10. Verify Content-Digest if body is present and content-digest is covered
	if let Some(body_bytes) = _body {
		if sig_input.components.iter().any(|c| c == "content-digest") {
			let cd_header = get_header(headers, "content-digest")
				.ok_or_else(|| Error::InvalidSignature("content-digest in covered components but header missing".to_string()))?;
			// Try sha-256 first, then sha-512
			let expected = if cd_header.contains("sha-256") {
				calculate_content_digest(body_bytes, "sha-256")
			} else {
				calculate_content_digest(body_bytes, "sha-512")
			};
			if cd_header.as_str() != expected {
				return Err(Error::ContentDigestMismatch);
			}
		}
	}

	// Extract agent identity for jwks/jwt schemes
	let agent_id = match scheme {
		SignatureScheme::Jwks => sig_key.params.get("id").cloned(),
		SignatureScheme::Jwt => {
			// For jwt scheme, agent_id would come from JWT claims
			// This will be handled in token validation
			None
		},
		SignatureScheme::Hwk => None,
	};

	Ok(VerificationResult {
		valid: true,
		scheme,
		agent_id,
		agent_delegate: None, // Will be populated during JWT validation
		claims: None,         // Will be populated during JWT validation
	})
}

/// Resolve public key from Signature-Key header for hwk scheme
pub fn resolve_hwk_public_key(sig_key: &SignatureKey) -> Result<PublicKey, Error> {
	if sig_key.scheme != "hwk" {
		return Err(Error::UnsupportedScheme(sig_key.scheme.clone()));
	}

	let x = sig_key
		.params
		.get("x")
		.ok_or_else(|| Error::InvalidKey("missing x parameter".to_string()))?;

	public_key_from_bytes(x)
}

#[cfg(test)]
mod tests {}
