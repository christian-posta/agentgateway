use thiserror::Error;

/// AAuth protocol errors.
///
/// Signing-layer variants (from `http-sig`) are retained here for backward compatibility
/// with existing consumers. New code should prefer matching on `http_sig::Error` directly.
#[derive(Debug, Error)]
pub enum AAuthError {
	// --- HTTP signing layer (from http-sig) ---
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

	#[error("content-digest verification failed")]
	ContentDigestMismatch,

	#[error("invalid header format: {0}")]
	InvalidHeader(String),

	#[error("invalid key format: {0}")]
	InvalidKey(String),

	#[error("base64 decode error: {0}")]
	Base64Error(#[from] base64::DecodeError),

	#[error("URL parse error: {0}")]
	UrlError(#[from] url::ParseError),

	#[error("JSON parse error: {0}")]
	JsonError(#[from] serde_json::Error),

	// --- AAuth protocol layer ---
	#[error("failed to fetch JWKS: {0}")]
	JwksFetchError(String),

	#[error("JWT validation failed: {0}")]
	JwtValidationError(String),

	#[error("audience mismatch")]
	AudienceMismatch,

	#[error("missing required claim: {0}")]
	MissingClaim(String),

	#[error("invalid issuer URL: must be https with host only (no port, path, query, or fragment)")]
	InvalidIssuerUrl,

	#[error("act claim sub does not match agent identifier")]
	ActClaimMismatch,
}

impl From<http_sig::Error> for AAuthError {
	fn from(e: http_sig::Error) -> Self {
		match e {
			http_sig::Error::MissingSignatureKey => AAuthError::MissingSignatureKey,
			http_sig::Error::MissingSignatureInput => AAuthError::MissingSignatureInput,
			http_sig::Error::MissingSignature => AAuthError::MissingSignature,
			http_sig::Error::LabelMismatch => AAuthError::LabelMismatch,
			http_sig::Error::SignatureKeyNotCovered => AAuthError::SignatureKeyNotCovered,
			http_sig::Error::TimestampExpired => AAuthError::TimestampExpired,
			http_sig::Error::InvalidSignature(s) => AAuthError::InvalidSignature(s),
			http_sig::Error::UnsupportedScheme(s) => AAuthError::UnsupportedScheme(s),
			http_sig::Error::UnsupportedAlgorithm(s) => AAuthError::UnsupportedAlgorithm(s),
			http_sig::Error::ContentDigestMismatch => AAuthError::ContentDigestMismatch,
			http_sig::Error::InvalidHeader(s) => AAuthError::InvalidHeader(s),
			http_sig::Error::InvalidKey(s) => AAuthError::InvalidKey(s),
			http_sig::Error::Base64Error(e) => AAuthError::InvalidKey(e.to_string()),
			http_sig::Error::UrlError(e) => AAuthError::InvalidHeader(e.to_string()),
			http_sig::Error::JsonError(e) => AAuthError::JsonError(e),
		}
	}
}
