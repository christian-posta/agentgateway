use std::collections::HashMap;
use crate::headers::signature_input::SignatureParams;
use crate::errors::AAuthError;

/// Build signature base per RFC 9421 Section 2.5
/// 
/// This is the MOST CRITICAL AND ERROR-PRONE PART
/// 
/// Algorithm:
/// 1. For each component in covered_components (IN ORDER):
///    - If starts with '@', it's a derived component
///    - Otherwise, it's a header name (case-insensitive lookup)
/// 2. Derived components:
///    - @method -> HTTP method (uppercase)
///    - @authority -> Host (lowercase, include port if non-standard)
///    - @path -> Path component
///    - @query -> Query string WITH leading "?" (even if empty query, use "?")
///    - signature-key -> Value of Signature-Key header
/// 3. Build each line: "{component}": {value}
///    - Component name is double-quoted
///    - Single space after colon
///    - NO trailing newline on last component line
/// 4. Build @signature-params line:
///    - "("{comp1}" "{comp2}" ...);created={ts}[;keyid="{kid}"]..."
///    - Add as: "@signature-params": {params_string}
/// 5. Join all lines with single LF (0x0A)
pub fn build_signature_base(
    method: &str,
    authority: &str,
    path: &str,
    query: Option<&str>,
    headers: &HashMap<String, String>,
    covered_components: &[&str],
    signature_params: &SignatureParams,
    signature_key_value: &str,
) -> Result<String, AAuthError> {
    let mut lines = Vec::new();

    for component in covered_components {
        let value = if component.starts_with('@') {
            match *component {
                "@method" => method.to_uppercase(),
                "@authority" => authority.to_lowercase(),
                "@path" => path.to_string(),
                "@query" => {
                    if let Some(q) = query {
                        if q.starts_with('?') {
                            q.to_string()
                        } else {
                            format!("?{}", q)
                        }
                    } else {
                        "?".to_string()
                    }
                }
                "signature-key" => signature_key_value.to_string(),
                _ => {
                    return Err(AAuthError::InvalidHeader(format!("unknown derived component: {}", component)));
                }
            }
        } else {
            // Header name - case-insensitive lookup
            let header_value = headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(component))
                .map(|(_, v)| v.as_str())
                .ok_or_else(|| {
                    AAuthError::InvalidHeader(format!("missing header: {}", component))
                })?;
            
            // Normalize header value (trim whitespace, collapse multiple spaces)
            header_value.trim().to_string()
        };

        // Component name is lowercase in signature base
        let component_lower = component.to_lowercase();
        lines.push(format!("\"{}\": {}", component_lower, value));
    }

    // Build @signature-params line
    let comps_str = covered_components
        .iter()
        .map(|c| format!("\"{}\"", c.to_lowercase()))
        .collect::<Vec<_>>()
        .join(" ");

    let mut params_str = format!("({});created={}", comps_str, signature_params.created);

    if let Some(ref keyid) = signature_params.keyid {
        params_str.push_str(&format!(";keyid=\"{}\"", keyid));
    }

    if let Some(ref nonce) = signature_params.nonce {
        params_str.push_str(&format!(";nonce=\"{}\"", nonce));
    }

    if let Some(ref alg) = signature_params.alg {
        params_str.push_str(&format!(";alg=\"{}\"", alg));
    }

    lines.push(format!("\"@signature-params\": {}", params_str));

    // Join with single LF (0x0A), no trailing newline
    Ok(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::headers::signature_input::SignatureParams;
    use std::collections::HashMap;

    #[test]
    fn test_signature_base_simple_get() {
        let mut headers = HashMap::new();
        headers.insert("Host".to_string(), "resource.example".to_string());
        
        let sig_key = "sig1=(scheme=hwk kty=\"OKP\" crv=\"Ed25519\" x=\"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs\")";
        headers.insert("Signature-Key".to_string(), sig_key.to_string());

        let params = SignatureParams {
            created: 1730217600,
            keyid: None,
            nonce: None,
            alg: None,
        };

        let components = vec!["@method", "@authority", "@path", "signature-key"];
        let base = build_signature_base(
            "GET",
            "resource.example",
            "/api/data",
            None,
            &headers,
            &components,
            &params,
            sig_key,
        ).unwrap();

        let expected = "\"@method\": GET\n\"@authority\": resource.example\n\"@path\": /api/data\n\"signature-key\": sig1=(scheme=hwk kty=\"OKP\" crv=\"Ed25519\" x=\"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs\")\n\"@signature-params\": (\"@method\" \"@authority\" \"@path\" \"signature-key\");created=1730217600";
        assert_eq!(base, expected);
    }

    #[test]
    fn test_signature_base_with_query() {
        let mut headers = HashMap::new();
        headers.insert("Host".to_string(), "resource.example".to_string());
        
        let sig_key = "sig1=(scheme=hwk kty=\"OKP\" crv=\"Ed25519\" x=\"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs\")";
        headers.insert("Signature-Key".to_string(), sig_key.to_string());

        let params = SignatureParams {
            created: 1730217600,
            keyid: None,
            nonce: None,
            alg: None,
        };

        let components = vec!["@method", "@authority", "@path", "@query", "signature-key"];
        let base = build_signature_base(
            "GET",
            "resource.example",
            "/api/data",
            Some("user=alice&limit=10"),
            &headers,
            &components,
            &params,
            sig_key,
        ).unwrap();

        assert!(base.contains("\"@query\": ?user=alice&limit=10"));
    }
}
