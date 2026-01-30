use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use rand::RngCore;
use crate::encoding::{base64url_decode, base64url_encode};
use crate::errors::AAuthError;

pub type PrivateKey = SigningKey;
pub type PublicKey = VerifyingKey;

/// Generate a new Ed25519 keypair
pub fn generate_keypair() -> (PrivateKey, PublicKey) {
    let mut secret_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret_bytes);
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Sign data with a private key
pub fn sign(data: &[u8], private_key: &PrivateKey) -> Vec<u8> {
    private_key.sign(data).to_bytes().to_vec()
}

/// Verify a signature with a public key
pub fn verify(data: &[u8], signature: &[u8], public_key: &PublicKey) -> bool {
    if signature.len() != 64 {
        return false;
    }
    let sig_bytes: [u8; 64] = match signature.try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig = Signature::from_bytes(&sig_bytes);
    public_key.verify(data, &sig).is_ok()
}

/// Create a private key from bytes (base64url encoded)
pub fn private_key_from_bytes(bytes: &str) -> Result<PrivateKey, AAuthError> {
    let decoded = base64url_decode(bytes)?;
    if decoded.len() != 32 {
        return Err(AAuthError::InvalidKey(format!("invalid key length: {}", decoded.len())));
    }
    let key_bytes: [u8; 32] = decoded.try_into().unwrap();
    Ok(SigningKey::from_bytes(&key_bytes))
}

/// Create a public key from bytes (base64url encoded)
pub fn public_key_from_bytes(bytes: &str) -> Result<PublicKey, AAuthError> {
    let decoded = base64url_decode(bytes)?;
    if decoded.len() != 32 {
        return Err(AAuthError::InvalidKey(format!("invalid key length: {}", decoded.len())));
    }
    let key_bytes: [u8; 32] = decoded.try_into().unwrap();
    VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| AAuthError::InvalidKey(format!("invalid public key: {}", e)))
}

/// Encode public key to base64url
pub fn public_key_to_base64url(key: &PublicKey) -> String {
    base64url_encode(key.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_sign_verify() {
        let (private_key, public_key) = generate_keypair();
        let data = b"hello world";
        let signature = sign(data, &private_key);
        assert!(verify(data, &signature, &public_key));
    }

    #[test]
    fn test_public_key_encoding() {
        let (private_key, public_key) = generate_keypair();
        let encoded = public_key_to_base64url(&public_key);
        let decoded = public_key_from_bytes(&encoded).unwrap();
        assert_eq!(public_key.as_bytes(), decoded.as_bytes());
    }
}
