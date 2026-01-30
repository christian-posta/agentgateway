use std::collections::HashMap;
use crate::keys::jwk::JWK;
use crate::errors::AAuthError;

#[derive(Debug, Clone)]
pub struct SignatureKey {
    pub label: String,
    pub scheme: String, // "hwk", "jwks", "jwt", "x509"
    pub params: HashMap<String, String>,
}

/// Parse Signature-Key header
/// Formats:
///   label=(scheme=hwk kty="OKP" crv="Ed25519" x="...")
///   label=(scheme=jwks id="https://agent.example" kid="key-1")
///   label=(scheme=jwt jwt="eyJ...")
///   label=scheme;param1=val1;param2=val2
pub fn parse_signature_key(header: &str) -> Result<SignatureKey, AAuthError> {
    // Extract label (everything before '=')
    let parts: Vec<&str> = header.splitn(2, '=').collect();
    if parts.len() != 2 {
        return Err(AAuthError::InvalidHeader(format!("invalid signature-key header: {}", header)));
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
            }
            ' ' if !in_quotes => {
                if !current.is_empty() {
                    parts.push(current.clone());
                    current.clear();
                }
            }
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
                return Err(AAuthError::InvalidHeader(format!("invalid param format: {}", part)));
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
                scheme = part.strip_prefix("scheme=").unwrap().trim_matches('"').to_string();
            } else {
                return Err(AAuthError::InvalidHeader(format!("missing scheme: {}", part)));
            }
        }
    }

    if scheme.is_empty() {
        return Err(AAuthError::InvalidHeader("missing scheme".to_string()));
    }

    Ok(SignatureKey { label, scheme, params })
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

    Ok(SignatureKey { label, scheme, params })
}

/// Build Signature-Key header for hwk scheme
pub fn build_signature_key_hwk(label: &str, jwk: &JWK) -> Result<String, AAuthError> {
    let mut parts = vec![format!("scheme=hwk")];
    
    parts.push(format!("kty=\"{}\"", jwk.kty));
    if let Some(ref crv) = jwk.crv {
        parts.push(format!("crv=\"{}\"", crv));
    }
    if let Some(ref x) = jwk.x {
        parts.push(format!("x=\"{}\"", x));
    }

    Ok(format!("{}=({})", label, parts.join(" ")))
}

/// Build Signature-Key header for jwks scheme
pub fn build_signature_key_jwks(
    label: &str,
    id: &str,
    kid: &str,
    well_known: Option<&str>,
) -> String {
    let mut parts = vec![
        format!("scheme=jwks"),
        format!("id=\"{}\"", id),
        format!("kid=\"{}\"", kid),
    ];

    if let Some(wk) = well_known {
        parts.push(format!("well-known=\"{}\"", wk));
    }

    format!("{}=({})", label, parts.join(" "))
}

/// Build Signature-Key header for jwt scheme
pub fn build_signature_key_jwt(label: &str, jwt: &str) -> String {
    format!("{}=(scheme=jwt jwt=\"{}\")", label, jwt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::jwk::JWK;

    #[test]
    fn test_parse_signature_key_hwk() {
        let header = r#"sig1=(scheme=hwk kty="OKP" crv="Ed25519" x="JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs")"#;
        let sig_key = parse_signature_key(header).unwrap();
        assert_eq!(sig_key.label, "sig1");
        assert_eq!(sig_key.scheme, "hwk");
        assert_eq!(sig_key.params.get("kty"), Some(&"OKP".to_string()));
        assert_eq!(sig_key.params.get("crv"), Some(&"Ed25519".to_string()));
    }

    #[test]
    fn test_parse_signature_key_jwks() {
        let header = r#"sig1=(scheme=jwks id="https://agent.example" kid="key-1" well-known="aauth-agent")"#;
        let sig_key = parse_signature_key(header).unwrap();
        assert_eq!(sig_key.label, "sig1");
        assert_eq!(sig_key.scheme, "jwks");
        assert_eq!(sig_key.params.get("id"), Some(&"https://agent.example".to_string()));
        assert_eq!(sig_key.params.get("kid"), Some(&"key-1".to_string()));
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
        assert!(header.contains("scheme=hwk"));
        assert!(header.contains("kty=\"OKP\""));
        assert!(header.contains("crv=\"Ed25519\""));
    }

    #[test]
    fn test_build_signature_key_jwks() {
        let header = build_signature_key_jwks("sig1", "https://agent.example", "key-1", Some("aauth-agent"));
        assert_eq!(header, r#"sig1=(scheme=jwks id="https://agent.example" kid="key-1" well-known="aauth-agent")"#);
    }
}
