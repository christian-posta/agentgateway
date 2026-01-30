use serde::{Deserialize, Serialize};
use serde_json::Value;
use crate::errors::AAuthError;
use crate::keys::ed25519::{PublicKey, public_key_from_bytes};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JWK {
    pub kty: String, // "OKP", "EC", "RSA"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>, // "Ed25519", "P-256", etc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>, // Public key X coordinate (base64url)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>, // EC Y coordinate (base64url)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>, // Private key (base64url)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>, // RSA modulus (base64url)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>, // RSA exponent (base64url)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>, // Key ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>, // Algorithm
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

impl JWK {
    pub fn parse(json: &str) -> Result<Self, AAuthError> {
        serde_json::from_str(json).map_err(AAuthError::from)
    }

    pub fn serialize(&self) -> Result<String, AAuthError> {
        serde_json::to_string(self).map_err(AAuthError::from)
    }

    /// Build canonical JSON for thumbprint (only required members, sorted)
    pub fn canonical_json(&self) -> Result<String, AAuthError> {
        let mut map = serde_json::Map::new();
        
        match self.kty.as_str() {
            "OKP" => {
                map.insert("crv".to_string(), Value::String(
                    self.crv.clone().ok_or_else(|| AAuthError::InvalidKey("OKP missing crv".to_string()))?
                ));
                map.insert("kty".to_string(), Value::String(self.kty.clone()));
                map.insert("x".to_string(), Value::String(
                    self.x.clone().ok_or_else(|| AAuthError::InvalidKey("OKP missing x".to_string()))?
                ));
            }
            "EC" => {
                map.insert("crv".to_string(), Value::String(
                    self.crv.clone().ok_or_else(|| AAuthError::InvalidKey("EC missing crv".to_string()))?
                ));
                map.insert("kty".to_string(), Value::String(self.kty.clone()));
                map.insert("x".to_string(), Value::String(
                    self.x.clone().ok_or_else(|| AAuthError::InvalidKey("EC missing x".to_string()))?
                ));
                map.insert("y".to_string(), Value::String(
                    self.y.clone().ok_or_else(|| AAuthError::InvalidKey("EC missing y".to_string()))?
                ));
            }
            "RSA" => {
                map.insert("e".to_string(), Value::String(
                    self.e.clone().ok_or_else(|| AAuthError::InvalidKey("RSA missing e".to_string()))?
                ));
                map.insert("kty".to_string(), Value::String(self.kty.clone()));
                map.insert("n".to_string(), Value::String(
                    self.n.clone().ok_or_else(|| AAuthError::InvalidKey("RSA missing n".to_string()))?
                ));
            }
            _ => return Err(AAuthError::InvalidKey(format!("unsupported kty: {}", self.kty))),
        }

        serde_json::to_string(&Value::Object(map)).map_err(AAuthError::from)
    }

    /// Convert OKP/Ed25519 JWK to PublicKey
    pub fn to_ed25519_public_key(&self) -> Result<PublicKey, AAuthError> {
        if self.kty != "OKP" {
            return Err(AAuthError::InvalidKey(format!("expected OKP, got {}", self.kty)));
        }
        let crv = self.crv.as_ref().ok_or_else(|| AAuthError::InvalidKey("missing crv".to_string()))?;
        if crv != "Ed25519" {
            return Err(AAuthError::InvalidKey(format!("expected Ed25519, got {}", crv)));
        }
        let x = self.x.as_ref().ok_or_else(|| AAuthError::InvalidKey("missing x".to_string()))?;
        public_key_from_bytes(x)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwk_parse_okp() {
        let json = r#"{"kty":"OKP","crv":"Ed25519","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"}"#;
        let jwk = JWK::parse(json).unwrap();
        assert_eq!(jwk.kty, "OKP");
        assert_eq!(jwk.crv, Some("Ed25519".to_string()));
        assert_eq!(jwk.x, Some("JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs".to_string()));
    }

    #[test]
    fn test_jwk_canonical_okp() {
        let json = r#"{"kty":"OKP","crv":"Ed25519","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs","kid":"test"}"#;
        let jwk = JWK::parse(json).unwrap();
        let canonical = jwk.canonical_json().unwrap();
        assert_eq!(canonical, r#"{"crv":"Ed25519","kty":"OKP","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"}"#);
    }
}
