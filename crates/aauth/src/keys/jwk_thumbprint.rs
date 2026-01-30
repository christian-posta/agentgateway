use sha2::{Digest, Sha256};
use crate::keys::jwk::JWK;
use crate::encoding::base64url_encode;
use crate::errors::AAuthError;

/// Calculate JWK Thumbprint per RFC 7638
/// 
/// Algorithm:
/// 1. Build canonical JSON with ONLY required members, SORTED alphabetically
/// 2. SHA-256 hash the canonical JSON bytes
/// 3. Base64URL encode WITHOUT padding
pub fn calculate_jwk_thumbprint(jwk: &JWK) -> Result<String, AAuthError> {
    let canonical = jwk.canonical_json()?;
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let hash = hasher.finalize();
    Ok(base64url_encode(&hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwk_thumbprint_ed25519() {
        let json = r#"{"kty":"OKP","crv":"Ed25519","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"}"#;
        let jwk = JWK::parse(json).unwrap();
        let thumbprint = calculate_jwk_thumbprint(&jwk).unwrap();
        // Expected from test vectors: kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k
        // But test vectors show: poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U
        // Let's verify against the actual expected value
        assert_eq!(thumbprint, "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U");
    }
}
