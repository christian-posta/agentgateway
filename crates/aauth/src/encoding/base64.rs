use crate::errors::AAuthError;

use base64::{Engine, engine::general_purpose};

/// Standard Base64 encoding (RFC 4648) with padding
pub fn base64_encode(bytes: &[u8]) -> String {
    general_purpose::STANDARD.encode(bytes)
}

/// Standard Base64 decoding (RFC 4648) with padding
pub fn base64_decode(s: &str) -> Result<Vec<u8>, AAuthError> {
    general_purpose::STANDARD
        .decode(s)
        .map_err(AAuthError::from)
}

/// Base64URL encoding without padding (for JWK values)
pub fn base64url_encode(bytes: &[u8]) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Base64URL decoding (handles missing padding)
pub fn base64url_decode(s: &str) -> Result<Vec<u8>, AAuthError> {
    general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(AAuthError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_encode() {
        let input = b"hello world";
        let encoded = base64_encode(input);
        assert_eq!(encoded, "aGVsbG8gd29ybGQ=");
    }

    #[test]
    fn test_base64_decode() {
        let encoded = "aGVsbG8gd29ybGQ=";
        let decoded = base64_decode(encoded).unwrap();
        assert_eq!(decoded, b"hello world");
    }

    #[test]
    fn test_base64url_encode() {
        let input = b"hello world";
        let encoded = base64url_encode(input);
        assert_eq!(encoded, "aGVsbG8gd29ybGQ");
    }

    #[test]
    fn test_base64url_decode() {
        let encoded = "aGVsbG8gd29ybGQ";
        let decoded = base64url_decode(encoded).unwrap();
        assert_eq!(decoded, b"hello world");
    }
}
