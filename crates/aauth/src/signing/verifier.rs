use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::headers::{parse_signature_key, parse_signature_input, parse_signature, SignatureKey};
use crate::keys::ed25519::{verify, PublicKey, public_key_from_bytes};
use crate::keys::jwk::JWK;
use crate::signing::signature_base::build_signature_base;
use crate::errors::AAuthError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureScheme {
    Hwk,   // Pseudonymous - inline public key
    Jwks,  // Identified - JWKS discovery
    Jwt,   // Authorized - JWT with cnf claim
}

#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub valid: bool,
    pub scheme: SignatureScheme,
    pub agent_id: Option<String>,      // For jwks/jwt schemes
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
pub async fn verify_signature(
    method: &str,
    url: &str,
    headers: &HashMap<String, String>,
    body: Option<&[u8]>,
    timestamp_tolerance: u64,
    public_key_resolver: &(dyn Fn(&SignatureKey) -> Result<PublicKey, AAuthError> + Send + Sync),
) -> Result<VerificationResult, AAuthError> {
    // 1-3. Extract and parse headers
    let sig_key_header = headers.get("Signature-Key")
        .ok_or(AAuthError::MissingSignatureKey)?;
    let sig_input_header = headers.get("Signature-Input")
        .ok_or(AAuthError::MissingSignatureInput)?;
    let sig_header = headers.get("Signature")
        .ok_or(AAuthError::MissingSignature)?;

    let sig_key = parse_signature_key(sig_key_header)?;
    let sig_input = parse_signature_input(sig_input_header)?;
    let (sig_label, sig_bytes) = parse_signature(sig_header)?;

    // 4. Verify label consistency
    if sig_key.label != sig_input.label || sig_key.label != sig_label {
        return Err(AAuthError::LabelMismatch);
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
        return Err(AAuthError::TimestampExpired);
    }

    // 6. Verify signature-key is in covered components
    if !sig_input.components.iter().any(|c| c == "signature-key") {
        return Err(AAuthError::SignatureKeyNotCovered);
    }

    // 7. Resolve public key based on scheme
    let public_key = public_key_resolver(&sig_key)?;
    let scheme = match sig_key.scheme.as_str() {
        "hwk" => SignatureScheme::Hwk,
        "jwks" => SignatureScheme::Jwks,
        "jwt" => SignatureScheme::Jwt,
        s => return Err(AAuthError::UnsupportedScheme(s.to_string())),
    };

    // Parse URL to extract authority, path, query
    let parsed_url = url::Url::parse(url)?;
    let authority = parsed_url.host_str()
        .ok_or_else(|| AAuthError::InvalidHeader("missing host in URL".to_string()))?;
    let path = parsed_url.path();
    let query = parsed_url.query();

    // 8. Rebuild signature base
    let signature_base = build_signature_base(
        method,
        authority,
        path,
        query,
        headers,
        &sig_input.components.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        &sig_input.params,
        sig_key_header,
    )?;

    // 9. Verify Ed25519 signature
    let is_valid = verify(signature_base.as_bytes(), &sig_bytes, &public_key);
    if !is_valid {
        return Err(AAuthError::InvalidSignature("signature verification failed".to_string()));
    }

    // TODO: 10. Verify Content-Digest if present

    // Extract agent identity for jwks/jwt schemes
    let agent_id = match scheme {
        SignatureScheme::Jwks => sig_key.params.get("id").cloned(),
        SignatureScheme::Jwt => {
            // For jwt scheme, agent_id would come from JWT claims
            // This will be handled in token validation
            None
        }
        SignatureScheme::Hwk => None,
    };

    Ok(VerificationResult {
        valid: true,
        scheme,
        agent_id,
        agent_delegate: None, // Will be populated during JWT validation
        claims: None, // Will be populated during JWT validation
    })
}

/// Resolve public key from Signature-Key header for hwk scheme
pub fn resolve_hwk_public_key(sig_key: &SignatureKey) -> Result<PublicKey, AAuthError> {
    if sig_key.scheme != "hwk" {
        return Err(AAuthError::UnsupportedScheme(sig_key.scheme.clone()));
    }

    let x = sig_key.params.get("x")
        .ok_or_else(|| AAuthError::InvalidKey("missing x parameter".to_string()))?;

    public_key_from_bytes(x)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::ed25519::generate_keypair;
    use crate::signing::signer::sign_request;

}
