use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ::cel::types::dynamic::DynamicType;
use parking_lot::RwLock;
use serde::Deserialize;
use serde_json::{Map, Value};
use aauth::{
    headers::SignatureKey,
    signing::{verify_signature, SignatureScheme, resolve_hwk_public_key},
    errors::AAuthError as LibAAuthError,
    tokens::{
        decode_jwt_header, decode_jwt_claims_unverified, validate_jwt, extract_cnf_jwk,
        get_string_claim,
    },
};

use crate::client::Client;
use crate::http::{Body, Request};
use crate::telemetry::log::RequestLog;
use crate::*;

#[cfg(test)]
#[path = "aauth_tests.rs"]
mod tests;

/// Cached JWKS keyed by agent id
#[derive(Clone, Default)]
pub struct JwksCache {
    inner: Arc<RwLock<HashMap<String, CachedJwks>>>,
}

struct CachedJwks {
    keys: HashMap<String, aauth::keys::jwk::JWK>,  // kid -> JWK
    fetched_at: Instant,
}

impl JwksCache {
    const TTL: Duration = Duration::from_secs(300); // 5 minutes

    /// Get a key from cache by agent id and kid
    pub fn get(&self, id: &str, kid: &str) -> Option<aauth::keys::jwk::JWK> {
        let cache = self.inner.read();
        let cached = cache.get(id)?;
        
        // Check if cache entry is still valid
        if cached.fetched_at.elapsed() > Self::TTL {
            return None;
        }
        
        cached.keys.get(kid).cloned()
    }

    /// Insert JWKS keys into cache for an agent id
    pub fn insert(&self, id: &str, keys: &[aauth::keys::jwk::JWK]) {
        let mut cache = self.inner.write();
        let mut key_map = HashMap::new();
        
        for jwk in keys {
            if let Some(kid) = &jwk.kid {
                key_map.insert(kid.clone(), jwk.clone());
            }
        }
        
        cache.insert(id.to_string(), CachedJwks {
            keys: key_map,
            fetched_at: Instant::now(),
        });
    }
}

/// Agent metadata response from /.well-known/aauth-agent
#[derive(Deserialize)]
struct AgentMetadata {
    jwks_uri: String,
    // agent: String,  // optional
}

/// JWKS response
#[derive(Deserialize)]
struct JwksResponse {
    keys: Vec<aauth::keys::jwk::JWK>,
}

#[derive(Debug, thiserror::Error)]
pub enum AAuthPolicyError {
    #[error("AAuth verification failed: {0}")]
    VerificationFailed(String),
    
    #[error("missing signature headers")]
    MissingSignature,
    
    #[error("insufficient authentication level")]
    InsufficientLevel,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct LocalAAuthConfig {
    #[serde(default)]
    pub mode: Mode,
    pub required_scheme: String, // "hwk", "jwks", "jwt"
    #[serde(default = "default_timestamp_tolerance")]
    pub timestamp_tolerance: u64,
    pub challenge: Option<LocalChallengeConfig>,
}

fn default_timestamp_tolerance() -> u64 {
    60
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct LocalChallengeConfig {
    pub auth_server: String,
    // TODO: Add resource token issuer config
}

impl LocalAAuthConfig {
    pub async fn try_into(self, client: Client) -> Result<AAuth, AAuthPolicyError> {
        let required_scheme = RequiredScheme::from_str(&self.required_scheme)
            .map_err(|e| AAuthPolicyError::VerificationFailed(format!("invalid required_scheme: {}", e)))?;
        
        let challenge_config = self.challenge.map(|c| ChallengeConfig {
            auth_server: c.auth_server,
        });

        Ok(AAuth::new(
            self.mode,
            required_scheme,
            self.timestamp_tolerance,
            challenge_config,
            JwksCache::default(),
            client,
        ))
    }
}

#[derive(Clone)]
pub struct AAuth {
    mode: Mode,
    required_scheme: RequiredScheme,
    timestamp_tolerance: u64,
    challenge_config: Option<ChallengeConfig>,
    jwks_cache: JwksCache,
    #[cfg_attr(feature = "schema", schemars(skip))]
    client: Client,
}

impl std::fmt::Debug for AAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AAuth")
            .field("mode", &self.mode)
            .field("required_scheme", &self.required_scheme)
            .field("timestamp_tolerance", &self.timestamp_tolerance)
            .field("challenge_config", &self.challenge_config)
            .field("jwks_cache", &"<cache>")
            .field("client", &"<client>")
            .finish()
    }
}

impl serde::Serialize for AAuth {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("AAuth", 5)?;
        state.serialize_field("mode", &self.mode)?;
        state.serialize_field("required_scheme", &self.required_scheme)?;
        state.serialize_field("timestamp_tolerance", &self.timestamp_tolerance)?;
        state.serialize_field("challenge_config", &self.challenge_config)?;
        state.serialize_field("jwks_cache", &"<cache>")?;
        state.end()
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct ChallengeConfig {
    pub auth_server: String,
    // TODO: Add resource token issuer config
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub enum RequiredScheme {
    Hwk,   // Any signature is sufficient
    Jwks,  // Must have verifiable identity
    Jwt,   // Must have authorization token
}

#[derive(Default, Debug, Clone, Copy, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub enum Mode {
    /// A valid signature must be present and meet required scheme
    #[default]
    Strict,
    /// If signature exists, validate it. Otherwise allow.
    Optional,
    /// Requests are never rejected. Useful for logging/claims extraction.
    Permissive,
}

#[derive(Clone, Debug, Default)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[cfg_attr(feature = "schema", schemars(with = "Map<String, Value>"))]
pub struct AAuthClaims {
    pub inner: Map<String, Value>,
}

impl DynamicType for AAuthClaims {
    fn materialize(&self) -> cel::Value<'_> {
        self.inner.materialize()
    }

    fn field(&self, field: &str) -> Option<cel::Value<'_>> {
        self.inner.field(field)
    }
}

/// Fetch JSON from a URL using the client
async fn fetch_json<T: serde::de::DeserializeOwned>(
    client: &Client,
    url: &str,
) -> Result<T, anyhow::Error> {
    tracing::debug!(url = %url, "fetch_json: starting HTTP request");
    
    let req = ::http::Request::builder()
        .uri(url)
        .body(Body::empty())
        .map_err(|e| {
            tracing::debug!(url = %url, error = %e, "fetch_json: failed to build request");
            anyhow::anyhow!("failed to build request: {}", e)
        })?;
    
    let resp = client
        .simple_call(req)
        .await
        .map_err(|e| {
            tracing::debug!(url = %url, error = %e, "fetch_json: HTTP request failed");
            anyhow::anyhow!("failed to fetch {}: {}", url, e)
        })?;
    
    tracing::debug!(url = %url, status = %resp.status(), "fetch_json: HTTP response received");
    
    crate::json::from_response_body::<T>(resp)
        .await
        .map_err(|e| {
            tracing::debug!(url = %url, error = %e, "fetch_json: failed to parse JSON response");
            anyhow::anyhow!("failed to parse JSON from {}: {}", url, e)
        })
}

impl AAuth {
    pub fn new(
        mode: Mode,
        required_scheme: RequiredScheme,
        timestamp_tolerance: u64,
        challenge_config: Option<ChallengeConfig>,
        jwks_cache: JwksCache,
        client: Client,
    ) -> Self {
        AAuth {
            mode,
            required_scheme,
            timestamp_tolerance,
            challenge_config,
            jwks_cache,
            client,
        }
    }

    /// Fetch JWKS for an agent, using cache if available
    async fn get_jwks_key(
        &self,
        id: &str,
        kid: &str,
        well_known: Option<&str>,
    ) -> Result<aauth::keys::jwk::JWK, AAuthPolicyError> {
        tracing::debug!(agent_id = id, kid = kid, well_known = ?well_known, "JWKS: starting key lookup");
        
        // 1. Check cache
        if let Some(jwk) = self.jwks_cache.get(id, kid) {
            tracing::debug!(agent_id = id, kid = kid, "JWKS: cache hit");
            return Ok(jwk);
        }
        tracing::debug!(agent_id = id, kid = kid, "JWKS: cache miss, fetching from network");
        
        // 2. Build metadata URL: {id}/.well-known/{well_known}
        let well_known = well_known.unwrap_or("aauth-agent");
        let metadata_url = format!("{}/.well-known/{}", id.trim_end_matches('/'), well_known);
        tracing::debug!(metadata_url = %metadata_url, "JWKS: fetching agent metadata");
        
        // 3. Fetch metadata
        let metadata: AgentMetadata = fetch_json(&self.client, &metadata_url)
            .await
            .map_err(|e| {
                tracing::info!(
                    metadata_url = %metadata_url,
                    error = %e,
                    "AAuth JWKS: failed to fetch agent metadata"
                );
                AAuthPolicyError::VerificationFailed(format!("fetch metadata: {}", e))
            })?;
        
        tracing::debug!(jwks_uri = %metadata.jwks_uri, "JWKS: metadata fetched, extracting jwks_uri");
        
        // 4. Fetch JWKS from jwks_uri
        tracing::debug!(jwks_uri = %metadata.jwks_uri, "JWKS: fetching JWKS");
        let jwks: JwksResponse = fetch_json(&self.client, &metadata.jwks_uri)
            .await
            .map_err(|e| {
                tracing::info!(
                    jwks_uri = %metadata.jwks_uri,
                    error = %e,
                    "AAuth JWKS: failed to fetch JWKS"
                );
                AAuthPolicyError::VerificationFailed(format!("fetch jwks: {}", e))
            })?;
        
        tracing::debug!(key_count = jwks.keys.len(), "JWKS: fetched, caching {} keys", jwks.keys.len());
        
        // 5. Cache and find key by kid
        self.jwks_cache.insert(id, &jwks.keys);
        
        let found_key = self.jwks_cache.get(id, kid);
        if found_key.is_none() {
            let available_kids: Vec<&str> = jwks.keys.iter()
                .filter_map(|k| k.kid.as_deref())
                .collect();
            tracing::info!(
                agent_id = id,
                requested_kid = kid,
                available_kids = ?available_kids,
                "AAuth JWKS: key not found in JWKS (requested kid not in available keys)"
            );
        } else {
            tracing::debug!(agent_id = id, kid = kid, "JWKS: key found and cached");
        }
        
        found_key
            .ok_or_else(|| AAuthPolicyError::VerificationFailed(format!("key {} not found in JWKS", kid)))
    }

    /// Apply AAuth verification. If `verification_authority` is provided (e.g. "hostname:port"
    /// from the route hostname and listener port), it is used as the @authority when rebuilding
    /// the signature base so verification matches what the client signed.
    pub async fn apply(
        &self,
        _log: Option<&mut RequestLog>,
        req: &mut Request,
        verification_authority: Option<&str>,
    ) -> Result<(), AAuthPolicyError> {
        tracing::debug!(
            mode = ?self.mode,
            required_scheme = ?self.required_scheme,
            method = %req.method(),
            uri = %req.uri(),
            "AAuth: starting verification"
        );

        // AAuth protocol well-known paths and JWKS are public; skip HTTPSig verification even in Strict mode
        let path = req.uri().path();
        if path.starts_with("/.well-known/aauth-") || path.ends_with("/jwks.json") {
            tracing::debug!(path = %path, "AAuth: skipping verification for well-known path");
            return Ok(());
        }

        // Extract signature headers
        let sig_key_header = req.headers().get("Signature-Key")
            .and_then(|h| h.to_str().ok());
        let sig_input_header = req.headers().get("Signature-Input")
            .and_then(|h| h.to_str().ok());
        let sig_header = req.headers().get("Signature")
            .and_then(|h| h.to_str().ok());

        tracing::debug!(
            has_sig_key = sig_key_header.is_some(),
            has_sig_input = sig_input_header.is_some(),
            has_sig = sig_header.is_some(),
            "AAuth: signature headers check"
        );

        // Check if signature is present
        let has_signature = sig_key_header.is_some() 
            && sig_input_header.is_some() 
            && sig_header.is_some();

        if !has_signature {
            tracing::debug!(mode = ?self.mode, "AAuth: signature headers missing");
            if self.mode == Mode::Strict {
                return Err(AAuthPolicyError::MissingSignature);
            }
            // Optional/Permissive: allow request without signature
            tracing::debug!("AAuth: allowing request without signature (optional/permissive mode)");
            return Ok(());
        }

        // Pre-parse signature-key to determine scheme
        let sig_key_str = sig_key_header.unwrap();
        tracing::debug!(signature_key_header = sig_key_str, "AAuth: parsing signature-key header");
        
        let parsed_sig_key = aauth::headers::parse_signature_key(sig_key_str)
            .map_err(|e| {
                tracing::debug!(error = %e, "AAuth: failed to parse signature-key header");
                AAuthPolicyError::VerificationFailed(e.to_string())
            })?;

        tracing::debug!(
            scheme = %parsed_sig_key.scheme,
            label = %parsed_sig_key.label,
            params = ?parsed_sig_key.params,
            "AAuth: signature-key parsed"
        );

        // Pre-fetch JWKS key if needed (for jwks scheme)
        let prefetched_key: Option<aauth::keys::ed25519::PublicKey> = 
            if parsed_sig_key.scheme == "jwks" {
                tracing::debug!("AAuth: scheme=jwks, starting JWKS key resolution");
                
                let id = parsed_sig_key.params.get("id")
                    .ok_or_else(|| {
                        tracing::info!("AAuth: jwks scheme missing 'id' parameter in signature-key");
                        AAuthPolicyError::VerificationFailed("jwks: missing id".to_string())
                    })?;
                let kid = parsed_sig_key.params.get("kid")
                    .ok_or_else(|| {
                        tracing::info!("AAuth: jwks scheme missing 'kid' parameter in signature-key");
                        AAuthPolicyError::VerificationFailed("jwks: missing kid".to_string())
                    })?;
                let well_known = parsed_sig_key.params.get("well-known").map(|s| s.as_str());
                
                tracing::debug!(
                    agent_id = id,
                    kid = kid,
                    well_known = ?well_known,
                    "AAuth: fetching JWKS key"
                );
                
                let jwk = self.get_jwks_key(id, kid, well_known).await?;
                
                tracing::debug!(
                    agent_id = id,
                    kid = kid,
                    jwk_kty = %jwk.kty,
                    jwk_crv = ?jwk.crv,
                    "AAuth: JWK retrieved, converting to Ed25519 public key"
                );
                
                let pubkey = jwk.to_ed25519_public_key()
                    .map_err(|e| {
                        tracing::info!(
                            agent_id = id,
                            kid = kid,
                            error = %e,
                            "AAuth: failed to convert JWK to Ed25519 public key (key must be OKP/Ed25519)"
                        );
                        AAuthPolicyError::VerificationFailed(e.to_string())
                    })?;
                
                tracing::debug!(
                    agent_id = id,
                    kid = kid,
                    "AAuth: JWK successfully converted to Ed25519 public key"
                );
                
                Some(pubkey)
            } else {
                tracing::debug!(scheme = %parsed_sig_key.scheme, "AAuth: scheme is not jwks, skipping JWKS fetch");
                None
            };

        // Pre-validate JWT and extract cnf.jwk key (for jwt scheme)
        // Also capture JWT claims for later use
        let (prefetched_jwt_key, jwt_claims): (Option<aauth::keys::ed25519::PublicKey>, Option<(String, Option<String>, serde_json::Map<String, serde_json::Value>)>) = 
            if parsed_sig_key.scheme == "jwt" {
                tracing::debug!("AAuth: scheme=jwt, starting JWT validation");
                
                // 1. Extract JWT from params
                let jwt = parsed_sig_key.params.get("jwt")
                    .ok_or_else(|| {
                        tracing::info!("AAuth: jwt scheme missing 'jwt' parameter in signature-key");
                        AAuthPolicyError::VerificationFailed("jwt: missing jwt parameter".to_string())
                    })?;
                
                // 2. Decode header to get kid and typ
                let header = decode_jwt_header(jwt)
                    .map_err(|e| {
                        tracing::info!(error = %e, "AAuth: failed to decode JWT header");
                        AAuthPolicyError::VerificationFailed(format!("jwt: invalid header: {}", e))
                    })?;
                
                let typ = header.typ.as_deref().unwrap_or("");
                tracing::debug!(typ = typ, kid = ?header.kid, "AAuth: JWT header decoded");
                
                // 3. Decode claims (unverified) to get issuer
                let unverified_claims = decode_jwt_claims_unverified(jwt)
                    .map_err(|e| {
                        tracing::info!(error = %e, "AAuth: failed to decode JWT claims");
                        AAuthPolicyError::VerificationFailed(format!("jwt: invalid claims: {}", e))
                    })?;
                
                let issuer = get_string_claim(&unverified_claims, "iss")
                    .ok_or_else(|| {
                        tracing::info!("AAuth: JWT missing 'iss' claim");
                        AAuthPolicyError::VerificationFailed("jwt: missing iss claim".to_string())
                    })?;
                
                let kid = header.kid.as_ref()
                    .ok_or_else(|| {
                        tracing::info!("AAuth: JWT missing 'kid' in header");
                        AAuthPolicyError::VerificationFailed("jwt: missing kid in header".to_string())
                    })?;
                
                // 4. Fetch JWKS from issuer's well-known endpoint
                // - agent+jwt tokens: issuer is agent server, use .well-known/aauth-agent
                // - auth+jwt tokens: issuer is auth server (OIDC), use .well-known/openid-configuration
                let well_known = match typ {
                    "agent+jwt" | "at+jwt" => "aauth-agent",
                    "auth+jwt" => "openid-configuration",
                    _ => "aauth-agent", // default to aauth-agent for unknown types
                };
                
                tracing::debug!(issuer = %issuer, kid = %kid, well_known = well_known, "AAuth: fetching JWKS for JWT validation");
                
                let signing_jwk = self.get_jwks_key(&issuer, kid, Some(well_known)).await?;
                
                tracing::debug!(
                    issuer = %issuer,
                    kid = %kid,
                    jwk_kty = %signing_jwk.kty,
                    "AAuth: JWKS key fetched for JWT validation"
                );
                
                // 5. Validate JWT signature
                let validated_claims = validate_jwt(jwt, &signing_jwk, None)
                    .map_err(|e| {
                        tracing::info!(error = %e, "AAuth: JWT signature validation failed");
                        AAuthPolicyError::VerificationFailed(format!("jwt: validation failed: {}", e))
                    })?;
                
                tracing::debug!("AAuth: JWT signature validated successfully");
                
                // 6. Extract cnf.jwk
                let cnf_jwk = extract_cnf_jwk(&validated_claims)
                    .map_err(|e| {
                        tracing::info!(error = %e, "AAuth: failed to extract cnf.jwk from JWT");
                        AAuthPolicyError::VerificationFailed(format!("jwt: missing cnf.jwk: {}", e))
                    })?;
                
                tracing::debug!(
                    cnf_jwk_kty = %cnf_jwk.kty,
                    cnf_jwk_crv = ?cnf_jwk.crv,
                    "AAuth: cnf.jwk extracted from JWT"
                );
                
                // 7. Convert cnf.jwk to Ed25519 public key
                let pubkey = cnf_jwk.to_ed25519_public_key()
                    .map_err(|e| {
                        tracing::info!(error = %e, "AAuth: failed to convert cnf.jwk to Ed25519 key");
                        AAuthPolicyError::VerificationFailed(format!("jwt: invalid cnf.jwk: {}", e))
                    })?;
                
                // 8. Extract agent identity based on token type
                let (agent_id, agent_delegate) = match typ {
                    "agent+jwt" | "at+jwt" => {
                        // agent+jwt: iss is agent identity, sub is delegate
                        let agent = issuer.clone();
                        let delegate = get_string_claim(&validated_claims, "sub");
                        (agent, delegate)
                    }
                    "auth+jwt" => {
                        // auth+jwt: agent claim is agent identity, sub is user
                        let agent = get_string_claim(&validated_claims, "agent")
                            .unwrap_or_else(|| issuer.clone());
                        let user = get_string_claim(&validated_claims, "sub");
                        (agent, user)
                    }
                    _ => {
                        // Unknown type, use issuer as agent
                        (issuer.clone(), None)
                    }
                };
                
                tracing::debug!(
                    agent_id = %agent_id,
                    agent_delegate = ?agent_delegate,
                    "AAuth: JWT successfully validated, cnf.jwk extracted"
                );
                
                (Some(pubkey), Some((agent_id, agent_delegate, validated_claims)))
            } else {
                (None, None)
            };

        // Convert headers to HashMap for verification
        let mut header_map = HashMap::new();
        for (name, value) in req.headers() {
            if let Ok(value_str) = value.to_str() {
                header_map.insert(name.as_str().to_string(), value_str.to_string());
            }
        }

        // Build URL from request
        let uri = req.uri();
        let scheme = uri.scheme().map(|s| s.as_str()).unwrap_or("https");
        let authority = uri.authority()
            .map(|a| a.as_str())
            .or_else(|| req.headers().get("host").and_then(|h| h.to_str().ok()))
            .ok_or_else(|| AAuthPolicyError::VerificationFailed("missing authority".to_string()))?;
        let url = format!("{}://{}{}", scheme, authority, uri.path_and_query().map(|pq| pq.as_str()).unwrap_or(""));

        // Read body if present
        let body = if req.headers().contains_key("content-length") || req.headers().contains_key("content-digest") {
            // Try to peek at body, but don't consume it
            // For now, we'll verify without body - full implementation would buffer it
            None
        } else {
            None
        };

        // Resolver that handles hwk, jwks, and jwt schemes
        let prefetched_key_clone = prefetched_key.clone();
        let prefetched_jwt_key_clone = prefetched_jwt_key.clone();
        let resolver = move |sig_key: &SignatureKey| -> Result<aauth::keys::ed25519::PublicKey, LibAAuthError> {
            tracing::debug!(scheme = %sig_key.scheme, "AAuth resolver: resolving public key");
            
            match sig_key.scheme.as_str() {
                "hwk" => {
                    tracing::debug!("AAuth resolver: using hwk scheme");
                    resolve_hwk_public_key(sig_key).map_err(|e| {
                        tracing::debug!(error = %e, "AAuth resolver: hwk resolution failed");
                        e
                    })
                },
                "jwks" => {
                    tracing::debug!("AAuth resolver: using jwks scheme");
                    prefetched_key_clone.clone()
                        .ok_or_else(|| {
                            tracing::debug!("AAuth resolver: jwks key was not pre-fetched");
                            LibAAuthError::JwksFetchError("key not pre-fetched".to_string())
                        })
                },
                "jwt" => {
                    tracing::debug!("AAuth resolver: using jwt scheme");
                    prefetched_jwt_key_clone.clone()
                        .ok_or_else(|| {
                            tracing::debug!("AAuth resolver: jwt key was not pre-validated");
                            LibAAuthError::JwtValidationError("jwt not pre-validated".to_string())
                        })
                },
                s => {
                    tracing::debug!(scheme = s, "AAuth resolver: unsupported scheme");
                    Err(LibAAuthError::UnsupportedScheme(s.to_string()))
                },
            }
        };

        tracing::debug!(
            method = %req.method(),
            url = %url,
            timestamp_tolerance = self.timestamp_tolerance,
            "AAuth: calling verify_signature"
        );
        
        let verify_result = verify_signature(
            req.method().as_str(),
            &url,
            &header_map,
            body,
            self.timestamp_tolerance,
            &resolver,
            verification_authority,
        ).await.map_err(|e| {
            tracing::info!(error = %e, "AAuth: signature verification failed");
            AAuthPolicyError::VerificationFailed(e.to_string())
        })?;
        
        tracing::debug!(
            valid = verify_result.valid,
            scheme = ?verify_result.scheme,
            agent_id = ?verify_result.agent_id,
            "AAuth: signature verification completed"
        );

        if !verify_result.valid {
            tracing::debug!(mode = ?self.mode, "AAuth: signature invalid");
            if self.mode == Mode::Strict {
                return Err(AAuthPolicyError::VerificationFailed("signature invalid".to_string()));
            }
            if self.mode == Mode::Permissive {
                tracing::debug!("AAuth: permissive mode, allowing invalid signature");
                return Ok(());
            }
            // Optional: allow invalid signature
            tracing::debug!("AAuth: optional mode, allowing invalid signature");
            return Ok(());
        }

        // required_scheme is minimum level (Hwk < Jwks < Jwt). Any scheme >= required is allowed.
        let scheme_ok = match (self.required_scheme, &verify_result.scheme) {
            (RequiredScheme::Hwk, _) => true, // Hwk minimum: allow Hwk, Jwks, Jwt
            (RequiredScheme::Jwks, SignatureScheme::Jwks) => true,
            (RequiredScheme::Jwks, SignatureScheme::Jwt) => true,
            (RequiredScheme::Jwt, SignatureScheme::Jwt) => true,
            _ => false,
        };

        if !scheme_ok {
            tracing::debug!(
                required_scheme = ?self.required_scheme,
                actual_scheme = ?verify_result.scheme,
                "AAuth: scheme does not meet required level"
            );
            // Return challenge response
            return Err(AAuthPolicyError::InsufficientLevel);
        }
        
        tracing::debug!("AAuth: verification successful, scheme meets requirements");

        // Store claims - merge verification result with JWT claims if available
        let mut claims_map = Map::new();
        claims_map.insert("scheme".to_string(), Value::String(format!("{:?}", verify_result.scheme)));
        
        // For JWT scheme, use the pre-validated JWT claims
        // For other schemes, use the verify_result
        if let Some((agent_id, agent_delegate, validated_jwt_claims)) = jwt_claims {
            claims_map.insert("agent".to_string(), Value::String(agent_id));
            if let Some(delegate) = agent_delegate {
                claims_map.insert("agent_delegate".to_string(), Value::String(delegate));
            }
            claims_map.insert("jwt_claims".to_string(), Value::Object(validated_jwt_claims));
        } else {
            // Non-JWT scheme - use verify_result
            if let Some(agent) = verify_result.agent_id {
                claims_map.insert("agent".to_string(), Value::String(agent));
            }
            if let Some(delegate) = verify_result.agent_delegate {
                claims_map.insert("agent_delegate".to_string(), Value::String(delegate));
            }
            if let Some(jwt_claims) = verify_result.claims {
                claims_map.insert("jwt_claims".to_string(), Value::Object(jwt_claims));
            }
        }
        claims_map.insert("thumbprint".to_string(), Value::String(String::new())); // TODO: extract from signature key
        
        let claims = AAuthClaims {
            inner: claims_map,
        };

        req.extensions_mut().insert(claims);

        Ok(())
    }

    pub fn build_challenge_response(&self, _current_scheme: Option<SignatureScheme>) -> String {
        match self.required_scheme {
            RequiredScheme::Hwk => "httpsig".to_string(),
            RequiredScheme::Jwks => "httpsig; identity=?1".to_string(),
            RequiredScheme::Jwt => {
                // TODO: Generate resource token if challenge_config is present
                format!(
                    "httpsig; auth-token; resource_token=\"\"; auth_server=\"{}\"",
                    self.challenge_config.as_ref().map(|c| c.auth_server.as_str()).unwrap_or("")
                )
            }
        }
    }
}

impl FromStr for RequiredScheme {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "hwk" => Ok(RequiredScheme::Hwk),
            "jwks" => Ok(RequiredScheme::Jwks),
            "jwt" => Ok(RequiredScheme::Jwt),
            _ => Err(format!("unknown scheme: {}", s)),
        }
    }
}
