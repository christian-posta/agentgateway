use thiserror::Error;

#[derive(Debug, Error)]
pub enum AAuthError {
    #[error("missing Signature-Key header")]
    MissingSignatureKey,

    #[error("missing Signature-Input header")]
    MissingSignatureInput,

    #[error("missing Signature header")]
    MissingSignature,

    #[error("label mismatch across headers")]
    LabelMismatch,

    #[error("signature-key must be a covered component")]
    SignatureKeyNotCovered,

    #[error("signature created timestamp outside valid window")]
    TimestampExpired,

    #[error("signature verification failed: {0}")]
    InvalidSignature(String),

    #[error("unsupported signature scheme: {0}")]
    UnsupportedScheme(String),

    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("failed to fetch JWKS: {0}")]
    JwksFetchError(String),

    #[error("JWT validation failed: {0}")]
    JwtValidationError(String),

    #[error("invalid header format: {0}")]
    InvalidHeader(String),

    #[error("base64 decode error: {0}")]
    Base64Error(#[from] base64::DecodeError),

    #[error("JSON parse error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("URL parse error: {0}")]
    UrlError(#[from] url::ParseError),

    #[error("invalid key format: {0}")]
    InvalidKey(String),
}
