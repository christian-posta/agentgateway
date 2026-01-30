use crate::encoding::base64_decode;
use crate::errors::AAuthError;

/// Parse Signature header: label=:base64signature:
/// Returns (label, signature_bytes)
pub fn parse_signature(header: &str) -> Result<(String, Vec<u8>), AAuthError> {
    let parts: Vec<&str> = header.splitn(2, '=').collect();
    if parts.len() != 2 {
        return Err(AAuthError::InvalidHeader(format!("invalid signature header: {}", header)));
    }

    let label = parts[0].trim().to_string();
    let value = parts[1].trim();

    // Remove colons around base64 value
    if !value.starts_with(':') || !value.ends_with(':') {
        return Err(AAuthError::InvalidHeader(format!("signature value must be wrapped in colons: {}", value)));
    }

    let base64_value = &value[1..value.len() - 1];
    let signature_bytes = base64_decode(base64_value)?;

    Ok((label, signature_bytes))
}

/// Build Signature header: label=:base64signature:
pub fn build_signature(label: &str, signature: &[u8]) -> String {
    use crate::encoding::base64_encode;
    let base64_sig = base64_encode(signature);
    format!("{}=:{}:", label, base64_sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_signature() {
        let header = "sig1=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:";
        let (label, sig_bytes) = parse_signature(header).unwrap();
        assert_eq!(label, "sig1");
        assert_eq!(sig_bytes.len(), 64); // Ed25519 signature is 64 bytes
    }

    #[test]
    fn test_build_signature() {
        let sig_bytes = vec![0u8; 64];
        let header = build_signature("sig1", &sig_bytes);
        assert!(header.starts_with("sig1=:"));
        assert!(header.ends_with(":"));
    }
}
