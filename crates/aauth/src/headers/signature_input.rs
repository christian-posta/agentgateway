use crate::errors::AAuthError;

#[derive(Debug, Clone)]
pub struct SignatureInput {
    pub label: String,
    pub components: Vec<String>,
    pub params: SignatureParams,
}

#[derive(Debug, Clone)]
pub struct SignatureParams {
    pub created: u64,
    pub keyid: Option<String>,
    pub nonce: Option<String>,
    pub alg: Option<String>,
}

/// Parse Signature-Input header
/// Format: label=("comp1" "comp2" "comp3");created=1234567890;keyid="key-1"
pub fn parse_signature_input(header: &str) -> Result<SignatureInput, AAuthError> {
    // Split label from params
    let parts: Vec<&str> = header.splitn(2, '=').collect();
    if parts.len() != 2 {
        return Err(AAuthError::InvalidHeader(format!("invalid signature-input header: {}", header)));
    }

    let label = parts[0].trim().to_string();
    let rest = parts[1].trim();

    // Extract components (in parentheses)
    let components_start = rest.find('(').ok_or_else(|| {
        AAuthError::InvalidHeader("missing components list".to_string())
    })?;
    let components_end = rest[components_start..].find(')').ok_or_else(|| {
        AAuthError::InvalidHeader("unclosed components list".to_string())
    })? + components_start;

    let components_str = &rest[components_start + 1..components_end];
    let components: Vec<String> = components_str
        .split_whitespace()
        .map(|s| s.trim_matches('"').to_string())
        .collect();

    // Parse parameters after the components
    let params_str = &rest[components_end + 1..];
    let mut params = SignatureParams {
        created: 0,
        keyid: None,
        nonce: None,
        alg: None,
    };

    for param in params_str.split(';') {
        let param = param.trim();
        if param.is_empty() {
            continue;
        }

        if let Some(created_str) = param.strip_prefix("created=") {
            params.created = created_str.parse().map_err(|_| {
                AAuthError::InvalidHeader(format!("invalid created timestamp: {}", created_str))
            })?;
        } else if let Some(keyid_str) = param.strip_prefix("keyid=") {
            params.keyid = Some(keyid_str.trim_matches('"').to_string());
        } else if let Some(nonce_str) = param.strip_prefix("nonce=") {
            params.nonce = Some(nonce_str.trim_matches('"').to_string());
        } else if let Some(alg_str) = param.strip_prefix("alg=") {
            params.alg = Some(alg_str.trim_matches('"').to_string());
        }
    }

    Ok(SignatureInput { label, components, params })
}

/// Build Signature-Input header
/// Format: label=("comp1" "comp2" ...);created={timestamp}[;keyid="{keyid}"][;nonce="{nonce}"]
pub fn build_signature_input(
    label: &str,
    components: &[&str],
    params: &SignatureParams,
) -> String {
    let comps_str = components
        .iter()
        .map(|c| format!("\"{}\"", c))
        .collect::<Vec<_>>()
        .join(" ");

    let mut result = format!("{}=({});created={}", label, comps_str, params.created);

    if let Some(ref keyid) = params.keyid {
        result.push_str(&format!(";keyid=\"{}\"", keyid));
    }

    if let Some(ref nonce) = params.nonce {
        result.push_str(&format!(";nonce=\"{}\"", nonce));
    }

    if let Some(ref alg) = params.alg {
        result.push_str(&format!(";alg=\"{}\"", alg));
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_signature_input() {
        let header = r#"sig1=("@method" "@authority" "@path" "signature-key");created=1730217600"#;
        let sig_input = parse_signature_input(header).unwrap();
        assert_eq!(sig_input.label, "sig1");
        assert_eq!(sig_input.components, vec!["@method", "@authority", "@path", "signature-key"]);
        assert_eq!(sig_input.params.created, 1730217600);
    }

    #[test]
    fn test_parse_signature_input_with_keyid() {
        let header = r#"sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519""#;
        let sig_input = parse_signature_input(header).unwrap();
        assert_eq!(sig_input.label, "sig-b26");
        assert_eq!(sig_input.params.keyid, Some("test-key-ed25519".to_string()));
    }

    #[test]
    fn test_build_signature_input() {
        let params = SignatureParams {
            created: 1730217600,
            keyid: None,
            nonce: None,
            alg: None,
        };
        let header = build_signature_input("sig1", &["@method", "@authority", "@path"], &params);
        assert_eq!(header, r#"sig1=("@method" "@authority" "@path");created=1730217600"#);
    }
}
