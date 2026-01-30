use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::headers::{build_signature_key_hwk, build_signature_key_jwks, build_signature_key_jwt, build_signature_input, build_signature, SignatureParams};
use crate::keys::ed25519::{sign, PrivateKey, public_key_to_base64url};
use crate::keys::jwk::JWK;
use crate::digest::calculate_content_digest;
use crate::signing::signature_base::build_signature_base;
use crate::errors::AAuthError;

pub struct SignatureHeaders {
    pub signature_input: String,
    pub signature: String,
    pub signature_key: String,
}

/// Sign an HTTP request per RFC 9421 and AAuth profile
/// 
/// Algorithm:
/// 1. Parse URL to extract authority, path, query
/// 2. Build Signature-Key header based on scheme
/// 3. Add Signature-Key to headers
/// 4. Determine covered components:
///    - Always: @method, @authority, @path, signature-key
///    - If query present: add @query
///    - If body present: add content-type, content-digest
/// 5. Add Content-Digest header if body present
/// 6. Build signature base
/// 7. Sign signature base bytes with Ed25519
/// 8. Build Signature-Input header
/// 9. Build Signature header
/// 10. Return all three headers
pub async fn sign_request(
    method: &str,
    url: &str,
    headers: &mut HashMap<String, String>,
    body: Option<&[u8]>,
    private_key: &PrivateKey,
    scheme: &str,
    scheme_params: &HashMap<String, String>,
) -> Result<SignatureHeaders, AAuthError> {
    // 1. Parse URL
    let parsed_url = url::Url::parse(url)?;
    let authority = parsed_url.host_str()
        .ok_or_else(|| AAuthError::InvalidHeader("missing host in URL".to_string()))?;
    let path = parsed_url.path();
    let query = parsed_url.query();

    // 2-3. Build and add Signature-Key header
    let label = "sig1";
    let signature_key = match scheme {
        "hwk" => {
            let public_key = private_key.verifying_key();
            let x = public_key_to_base64url(&public_key);
            let jwk = JWK {
                kty: "OKP".to_string(),
                crv: Some("Ed25519".to_string()),
                x: Some(x),
                y: None,
                d: None,
                n: None,
                e: None,
                kid: None,
                alg: None,
                extra: Default::default(),
            };
            build_signature_key_hwk(label, &jwk)?
        }
        "jwks" => {
            let id = scheme_params.get("id")
                .ok_or_else(|| AAuthError::InvalidHeader("missing id for jwks scheme".to_string()))?;
            let kid = scheme_params.get("kid")
                .ok_or_else(|| AAuthError::InvalidHeader("missing kid for jwks scheme".to_string()))?;
            let well_known = scheme_params.get("well-known").map(|s| s.as_str());
            build_signature_key_jwks(label, id, kid, well_known)
        }
        "jwt" => {
            let jwt = scheme_params.get("jwt")
                .ok_or_else(|| AAuthError::InvalidHeader("missing jwt for jwt scheme".to_string()))?;
            build_signature_key_jwt(label, jwt)
        }
        _ => return Err(AAuthError::UnsupportedScheme(scheme.to_string())),
    };

    headers.insert("Signature-Key".to_string(), signature_key.clone());

    // 4. Determine covered components
    let mut components = vec!["@method", "@authority", "@path", "signature-key"];
    if query.is_some() {
        components.push("@query");
    }
    if body.is_some() {
        components.push("content-type");
        components.push("content-digest");
    }

    // 5. Add Content-Digest if body present
    if let Some(body_bytes) = body {
        let digest = calculate_content_digest(body_bytes, "sha-256");
        headers.insert("Content-Digest".to_string(), digest);
    }

    // 6. Build signature base
    let created = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let params = SignatureParams {
        created,
        keyid: None,
        nonce: None,
        alg: None,
    };

    let signature_base = build_signature_base(
        method,
        authority,
        path,
        query,
        headers,
        &components,
        &params,
        &signature_key,
    )?;

    // 7. Sign signature base
    let signature_bytes = sign(signature_base.as_bytes(), private_key);

    // 8-9. Build headers
    let signature_input = build_signature_input(label, &components, &params);
    let signature = build_signature(label, &signature_bytes);

    Ok(SignatureHeaders {
        signature_input,
        signature,
        signature_key,
    })
}
