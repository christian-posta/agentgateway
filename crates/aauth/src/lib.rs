pub mod encoding;
pub mod digest;
pub mod keys;
pub mod headers;
pub mod signing;
pub mod tokens;
pub mod errors;

pub use errors::AAuthError;
pub use signing::{SignatureScheme, VerificationResult};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::calculate_content_digest;
    use crate::keys::{jwk::JWK, jwk_thumbprint::calculate_jwk_thumbprint};
    use crate::headers::{parse_signature_key, build_signature_key_hwk};
    use serde_json::json;

    #[test]
    fn test_content_digest_from_vectors() {
        let body = b"{\"hello\": \"world\"}";
        let digest = calculate_content_digest(body, "sha-256");
        assert_eq!(
            digest,
            "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"
        );
    }

    #[test]
    fn test_jwk_thumbprint_from_vectors() {
        let jwk_json = json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
        });
        let jwk: JWK = serde_json::from_value(jwk_json).unwrap();
        let thumbprint = calculate_jwk_thumbprint(&jwk).unwrap();
        assert_eq!(thumbprint, "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U");
    }

    #[test]
    fn test_signature_key_parsing() {
        let header = r#"sig1=(scheme=hwk kty="OKP" crv="Ed25519" x="JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs")"#;
        let sig_key = parse_signature_key(header).unwrap();
        assert_eq!(sig_key.label, "sig1");
        assert_eq!(sig_key.scheme, "hwk");
        assert_eq!(sig_key.params.get("kty"), Some(&"OKP".to_string()));
    }
}
