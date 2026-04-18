use crate::errors::AAuthError;
use crate::keys::jwk::JWK;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct SignatureKey {
	pub label: String,
	pub scheme: String, // "hwk", "jwks_uri", "jwt", "x509"
	pub params: HashMap<String, String>,
}

/// Parse Signature-Key header
/// Formats:
///   label=(scheme=hwk kty="OKP" crv="Ed25519" x="...")
///   label=(scheme=jwks_uri id="https://agent.example" kid="key-1")
///   label=(scheme=jwt jwt="eyJ...")
///   label=scheme;param1=val1;param2=val2
pub fn parse_signature_key(header: &str) -> Result<SignatureKey, AAuthError> {
	// Extract label (everything before '=')
	let parts: Vec<&str> = header.splitn(2, '=').collect();
	if parts.len() != 2 {
		return Err(AAuthError::InvalidHeader(format!(
			"invalid signature-key header: {}",
			header
		)));
	}

	let label = parts[0].trim().to_string();
	let value = parts[1].trim();

	// Check if parenthesized format: label=(...)
	if value.starts_with('(') && value.ends_with(')') {
		let inner = &value[1..value.len() - 1];
		parse_parenthesized_format(label, inner)
	} else {
		// Semicolon format: label=scheme;param1=val1;param2=val2
		parse_semicolon_format(label, value)
	}
}

fn parse_parenthesized_format(label: String, inner: &str) -> Result<SignatureKey, AAuthError> {
	let mut scheme = String::new();
	let mut params = HashMap::new();

	// Split by whitespace, but handle quoted values
	let mut parts = Vec::new();
	let mut current = String::new();
	let mut in_quotes = false;

	for ch in inner.chars() {
		match ch {
			'"' => {
				in_quotes = !in_quotes;
				current.push(ch);
			},
			' ' if !in_quotes => {
				if !current.is_empty() {
					parts.push(current.clone());
					current.clear();
				}
			},
			_ => current.push(ch),
		}
	}
	if !current.is_empty() {
		parts.push(current);
	}

	for part in parts {
		if part.contains('=') {
			let kv: Vec<&str> = part.splitn(2, '=').collect();
			if kv.len() != 2 {
				return Err(AAuthError::InvalidHeader(format!(
					"invalid param format: {}",
					part
				)));
			}

			let key = kv[0].trim().to_string();
			let val = kv[1].trim().trim_matches('"').to_string();

			if key == "scheme" {
				scheme = val;
			} else {
				params.insert(key, val);
			}
		} else if scheme.is_empty() {
			// First part without '=' might be scheme=value format
			if part.starts_with("scheme=") {
				scheme = part
					.strip_prefix("scheme=")
					.unwrap()
					.trim_matches('"')
					.to_string();
			} else {
				return Err(AAuthError::InvalidHeader(format!(
					"missing scheme: {}",
					part
				)));
			}
		}
	}

	if scheme.is_empty() {
		return Err(AAuthError::InvalidHeader("missing scheme".to_string()));
	}

	Ok(SignatureKey {
		label,
		scheme,
		params,
	})
}

fn parse_semicolon_format(label: String, value: &str) -> Result<SignatureKey, AAuthError> {
	let parts: Vec<&str> = value.split(';').collect();
	if parts.is_empty() {
		return Err(AAuthError::InvalidHeader("empty value".to_string()));
	}

	let scheme = parts[0].trim().to_string();
	let mut params = HashMap::new();

	for part in parts.iter().skip(1) {
		let kv: Vec<&str> = part.splitn(2, '=').collect();
		if kv.len() == 2 {
			let key = kv[0].trim().to_string();
			let val = kv[1].trim().trim_matches('"').to_string();
			params.insert(key, val);
		}
	}

	Ok(SignatureKey {
		label,
		scheme,
		params,
	})
}

/// Build Signature-Key header for hwk scheme (RFC 8941 Structured Fields format)
///
/// Output: `sig1=hwk;kty="OKP";crv="Ed25519";x="..."`
pub fn build_signature_key_hwk(label: &str, jwk: &JWK) -> Result<String, AAuthError> {
	let mut parts = vec!["hwk".to_string()];

	parts.push(format!("kty=\"{}\"", jwk.kty));
	if let Some(ref crv) = jwk.crv {
		parts.push(format!("crv=\"{}\"", crv));
	}
	if let Some(ref x) = jwk.x {
		parts.push(format!("x=\"{}\"", x));
	}

	Ok(format!("{}={}", label, parts.join(";")))
}

/// Build Signature-Key header for jwks_uri scheme (RFC 8941 Structured Fields format)
///
/// Output: `sig1=jwks_uri;id="https://...";dwk="aauth-agent.json";kid="key-1"`
///
/// `dwk` is REQUIRED per the HTTP Signature Keys spec — it names the well-known metadata
/// document used to discover the JWKS.
pub fn build_signature_key_jwks(label: &str, id: &str, kid: &str, dwk: &str) -> String {
	format!(
		"{}=jwks_uri;id=\"{}\";dwk=\"{}\";kid=\"{}\"",
		label, id, dwk, kid
	)
}

/// Build Signature-Key header for jwt scheme (RFC 8941 Structured Fields format)
///
/// Output: `sig1=jwt;jwt="eyJ..."`
pub fn build_signature_key_jwt(label: &str, jwt: &str) -> String {
	format!("{}=jwt;jwt=\"{}\"", label, jwt)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::keys::jwk::JWK;

	#[test]
	fn test_parse_signature_key_hwk_semicolon() {
		let header = r#"sig1=hwk;kty="OKP";crv="Ed25519";x="JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs""#;
		let sig_key = parse_signature_key(header).unwrap();
		assert_eq!(sig_key.label, "sig1");
		assert_eq!(sig_key.scheme, "hwk");
		assert_eq!(sig_key.params.get("kty"), Some(&"OKP".to_string()));
		assert_eq!(sig_key.params.get("crv"), Some(&"Ed25519".to_string()));
	}

	#[test]
	fn test_parse_signature_key_hwk_legacy_parenthesized() {
		// Legacy format — still parseable for backward compat
		let header = r#"sig1=(scheme=hwk kty="OKP" crv="Ed25519" x="JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs")"#;
		let sig_key = parse_signature_key(header).unwrap();
		assert_eq!(sig_key.label, "sig1");
		assert_eq!(sig_key.scheme, "hwk");
		assert_eq!(sig_key.params.get("kty"), Some(&"OKP".to_string()));
	}

	#[test]
	fn test_parse_signature_key_jwks() {
		let header = r#"sig1=jwks_uri;id="https://agent.example";dwk="aauth-agent.json";kid="key-1""#;
		let sig_key = parse_signature_key(header).unwrap();
		assert_eq!(sig_key.label, "sig1");
		assert_eq!(sig_key.scheme, "jwks_uri");
		assert_eq!(
			sig_key.params.get("id"),
			Some(&"https://agent.example".to_string())
		);
		assert_eq!(sig_key.params.get("kid"), Some(&"key-1".to_string()));
		assert_eq!(sig_key.params.get("dwk"), Some(&"aauth-agent.json".to_string()));
	}

	#[test]
	fn test_build_signature_key_hwk() {
		let jwk = JWK {
			kty: "OKP".to_string(),
			crv: Some("Ed25519".to_string()),
			x: Some("JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs".to_string()),
			y: None,
			d: None,
			n: None,
			e: None,
			kid: None,
			alg: None,
			extra: Default::default(),
		};
		let header = build_signature_key_hwk("sig1", &jwk).unwrap();
		assert_eq!(
			header,
			r#"sig1=hwk;kty="OKP";crv="Ed25519";x="JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs""#
		);
	}

	#[test]
	fn test_build_signature_key_jwks() {
		let header = build_signature_key_jwks(
			"sig1",
			"https://agent.example",
			"key-1",
			"aauth-agent.json",
		);
		assert_eq!(
			header,
			r#"sig1=jwks_uri;id="https://agent.example";dwk="aauth-agent.json";kid="key-1""#
		);
	}
}
