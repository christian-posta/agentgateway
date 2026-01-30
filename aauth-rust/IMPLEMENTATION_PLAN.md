# AAuth Implementation Plan for Rust (and TypeScript)

## Overview

This document provides a complete implementation plan for the AAuth HTTP Message Signing library. It is designed to be handed off to an AI model or developer for implementation.

**What you're building**: A library that implements HTTP Message Signing per RFC 9421, with the AAuth profile extensions including the Signature-Key header for key discovery.

**Reference implementations**: Python (`aauth/`) and Java (`services/src/main/java/org/keycloak/protocol/aauth/`)

**Test vectors**: `aauth-test-vectors.json` - Your implementation MUST pass all tests

**Cross-validation**: `aauth_validator.py` - Use this to compare your output against the reference

---

## Part 1: Implementation Order (Critical Path)

Implement in this exact order - each step depends on the previous:

### Step 1: Base64 Utilities
```
File: src/encoding/base64.rs

Functions needed:
- base64_encode(bytes) -> String           # Standard Base64 (RFC 4648)
- base64_decode(str) -> bytes              # Standard Base64
- base64url_encode(bytes) -> String        # Base64URL without padding
- base64url_decode(str) -> bytes           # Base64URL (handle missing padding)

CRITICAL NOTES:
- JWK values (x, y, d, n, e) use Base64URL WITHOUT padding
- Signature header uses standard Base64 WITH colons: :base64value:
- Content-Digest uses standard Base64 WITH colons: sha-256=:base64value:
```

### Step 2: Content-Digest (RFC 9530)
```
File: src/digest/content_digest.rs

Function: calculate_content_digest(body: &[u8], algorithm: &str) -> String

Input: body bytes, algorithm ("sha-256" or "sha-512")
Output: "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"

Algorithm:
1. Hash body with SHA-256 or SHA-512
2. Base64 encode the hash (standard Base64)
3. Format as: {algorithm}=:{base64}:

TEST CASE (from test vectors):
  Input: {"hello": "world"}
  SHA-256 output: sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
```

### Step 3: JWK Thumbprint (RFC 7638)
```
File: src/keys/jwk_thumbprint.rs

Function: calculate_jwk_thumbprint(jwk: &JWK) -> String

Algorithm:
1. Build canonical JSON with ONLY required members, SORTED alphabetically:
   - OKP: {"crv":"...","kty":"OKP","x":"..."}
   - EC:  {"crv":"...","kty":"EC","x":"...","y":"..."}
   - RSA: {"e":"...","kty":"RSA","n":"..."}
2. SHA-256 hash the canonical JSON bytes
3. Base64URL encode WITHOUT padding

CRITICAL: 
- Keys MUST be sorted alphabetically
- NO whitespace in JSON
- Only include the required members (no kid, alg, etc.)

TEST CASE:
  Input JWK: {"kty":"OKP","crv":"Ed25519","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"}
  Canonical: {"crv":"Ed25519","kty":"OKP","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"}
  Output: kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k
```

### Step 4: JWK Parsing and Serialization
```
File: src/keys/jwk.rs

Structs:
  struct JWK {
    kty: String,          // "OKP", "EC", "RSA"
    crv: Option<String>,  // "Ed25519", "P-256", etc.
    x: Option<String>,    // Public key X coordinate (base64url)
    y: Option<String>,    // EC Y coordinate (base64url)
    d: Option<String>,    // Private key (base64url)
    n: Option<String>,    // RSA modulus (base64url)
    e: Option<String>,    // RSA exponent (base64url)
    kid: Option<String>,  // Key ID
    alg: Option<String>,  // Algorithm
  }

Functions:
  - jwk_to_public_key(jwk: &JWK) -> PublicKey
  - public_key_to_jwk(key: &PublicKey) -> JWK
  - parse_jwk(json: &str) -> JWK
  - serialize_jwk(jwk: &JWK) -> String
```

### Step 5: Ed25519 Key Operations
```
File: src/keys/ed25519.rs

Functions:
  - generate_keypair() -> (PrivateKey, PublicKey)
  - sign(data: &[u8], private_key: &PrivateKey) -> Vec<u8>
  - verify(data: &[u8], signature: &[u8], public_key: &PublicKey) -> bool
  - private_key_from_bytes(bytes: &[u8]) -> PrivateKey
  - public_key_from_bytes(bytes: &[u8]) -> PublicKey

Use: ed25519-dalek crate for Rust, tweetnacl or noble-ed25519 for TypeScript

CRITICAL: Ed25519 signatures are DETERMINISTIC - same input always produces same signature
```

### Step 6: Signature-Key Header Parsing/Building
```
File: src/headers/signature_key.rs

The Signature-Key header format (RFC 8941 Structured Fields Dictionary):
  label=(scheme=hwk kty="OKP" crv="Ed25519" x="...")
  label=(scheme=jwks id="https://agent.example" kid="key-1")
  label=(scheme=jwt jwt="eyJ...")

Struct:
  struct SignatureKey {
    label: String,
    scheme: String,        // "hwk", "jwks", "jwt", "x509"
    params: HashMap<String, String>,
  }

Functions:
  - parse_signature_key(header: &str) -> SignatureKey
  - build_signature_key_hwk(label: &str, jwk: &JWK) -> String
  - build_signature_key_jwks(label: &str, id: &str, kid: &str, well_known: Option<&str>) -> String
  - build_signature_key_jwt(label: &str, jwt: &str) -> String

Parsing algorithm:
1. Match: label=(...) or label=scheme;param1=val1;param2=val2
2. Extract label (everything before '=')
3. If parenthesized format: extract scheme and params from inside ()
4. If semicolon format: first value is scheme, rest are params
5. Remove quotes from string values
```

### Step 7: Signature-Input Header Parsing/Building
```
File: src/headers/signature_input.rs

Format: label=("comp1" "comp2" "comp3");created=1234567890;keyid="key-1"

Struct:
  struct SignatureInput {
    label: String,
    components: Vec<String>,
    params: SignatureParams,
  }

  struct SignatureParams {
    created: u64,
    keyid: Option<String>,
    nonce: Option<String>,
    alg: Option<String>,
  }

Functions:
  - parse_signature_input(header: &str) -> SignatureInput
  - build_signature_input(label: &str, components: &[&str], params: &SignatureParams) -> String

Building format:
  {label}=("{comp1}" "{comp2}" ...);created={timestamp}[;keyid="{keyid}"][;nonce="{nonce}"]
```

### Step 8: Signature Header Parsing/Building
```
File: src/headers/signature.rs

Format: label=:base64signature:

Functions:
  - parse_signature(header: &str) -> (String, Vec<u8>)  // (label, signature_bytes)
  - build_signature(label: &str, signature: &[u8]) -> String

CRITICAL: Uses standard Base64 (not URL-safe), wrapped in colons
```

### Step 9: Signature Base Construction (RFC 9421 Section 2.5)
```
File: src/signing/signature_base.rs

THIS IS THE MOST CRITICAL AND ERROR-PRONE PART

Function: build_signature_base(
    method: &str,
    authority: &str,
    path: &str,
    query: Option<&str>,
    headers: &HashMap<String, String>,
    covered_components: &[&str],
    signature_params: &SignatureParams,
) -> String

Algorithm:
1. For each component in covered_components (IN ORDER):
   - If starts with '@', it's a derived component
   - Otherwise, it's a header name (case-insensitive lookup)

2. Derived components:
   - @method -> HTTP method (uppercase)
   - @authority -> Host (lowercase, include port if non-standard)
   - @path -> Path component
   - @query -> Query string WITH leading "?" (even if empty query, use "?")
   - signature-key -> Value of Signature-Key header

3. Build each line: "{component}": {value}
   - Component name is double-quoted
   - Single space after colon
   - NO trailing newline on last component line

4. Build @signature-params line:
   - "("{comp1}" "{comp2}" ...);created={ts}[;keyid="{kid}"]..."
   - Add as: "@signature-params": {params_string}

5. Join all lines with single LF (0x0A)

EXAMPLE:
  "@method": GET
  "@authority": resource.example
  "@path": /api/data
  "signature-key": sig1=(scheme=hwk kty="OKP" crv="Ed25519" x="...")
  "@signature-params": ("@method" "@authority" "@path" "signature-key");created=1730217600

CRITICAL NOTES:
- @query MUST include leading "?" per RFC 9421 Section 2.2.7
- Lines separated by LF only (not CRLF)
- NO trailing newline after @signature-params
- Header lookups are case-insensitive
- Component names in signature base are lowercase
```

### Step 10: Request Signing
```
File: src/signing/signer.rs

Function: sign_request(
    method: &str,
    url: &str,           // Full URL to parse
    headers: &mut HashMap<String, String>,
    body: Option<&[u8]>,
    private_key: &PrivateKey,
    scheme: &str,        // "hwk", "jwks", "jwt"
    scheme_params: &HashMap<String, String>,  // id, kid, jwt, etc.
) -> Result<SignatureHeaders>

Returns:
  struct SignatureHeaders {
    signature_input: String,
    signature: String,
    signature_key: String,
  }

Algorithm:
1. Parse URL to extract authority, path, query
2. Build Signature-Key header based on scheme
3. Add Signature-Key to headers
4. Determine covered components:
   - Always: @method, @authority, @path, signature-key
   - If query present: add @query
   - If body present: add content-type, content-digest
5. Add Content-Digest header if body present
6. Build signature base
7. Sign signature base bytes with Ed25519
8. Build Signature-Input header
9. Build Signature header
10. Return all three headers
```

### Step 11: Signature Verification
```
File: src/signing/verifier.rs

Function: verify_signature(
    method: &str,
    url: &str,
    headers: &HashMap<String, String>,
    body: Option<&[u8]>,
    public_key_resolver: &dyn Fn(&SignatureKey) -> Result<PublicKey>,
) -> Result<VerificationResult>

Returns:
  struct VerificationResult {
    valid: bool,
    agent_id: Option<String>,  // For jwks/jwt schemes
    scheme: String,
  }

Algorithm:
1. Extract and parse Signature-Key header
2. Extract and parse Signature-Input header  
3. Extract and parse Signature header
4. VERIFY LABEL CONSISTENCY (all three must match)
5. Verify created timestamp is within 60 seconds of now
6. Verify signature-key is in covered components
7. Resolve public key based on scheme:
   - hwk: Extract directly from Signature-Key params
   - jwks: Fetch from metadata (out of scope for basic impl)
   - jwt: Validate JWT, extract cnf.jwk
8. Rebuild signature base from request and Signature-Input
9. Verify Ed25519 signature
10. If body present and content-digest covered, verify Content-Digest
```

---

## Part 2: AAuth-Specific Requirements

### Label Consistency (Section 10.1.1)
The same label MUST appear in all three headers:
```
Signature-Input: sig1=...
Signature: sig1=...
Signature-Key: sig1=...
```
Reject if labels don't match.

### Required Covered Components (Section 10.3)
Always required:
- @method
- @authority
- @path
- signature-key

Conditional:
- @query: MUST include if request has query string, MUST NOT if no query
- content-type, content-digest: MUST include if request has body

### Timestamp Validation (Section 10.4)
```
created timestamp MUST be within 60 seconds of receiver's current time
|now - created| <= 60
```

### Signature Schemes

**scheme=hwk (Pseudonymous)**
```
Signature-Key: sig1=(scheme=hwk kty="OKP" crv="Ed25519" x="base64url_public_key")
```
- No identity verification
- Key material inline in header

**scheme=jwks (Identified)**
```
Signature-Key: sig1=(scheme=jwks id="https://agent.example" kid="key-1" well-known="aauth-agent")
```
- Requires JWKS fetch: {id}/.well-known/{well-known} -> jwks_uri -> JWKS
- Match key by kid

**scheme=jwt (Token-based)**
```
Signature-Key: sig1=(scheme=jwt jwt="eyJ...")
```
- Validate JWT signature
- Extract public key from cnf.jwk claim
- Agent identity from iss (agent+jwt) or agent claim (auth+jwt)

---

## Part 3: Token Handling

### Agent Token (agent+jwt)
```json
Header: {"typ": "agent+jwt", "alg": "EdDSA", "kid": "..."}
Payload: {
  "iss": "https://agent-server.example",
  "sub": "agent-delegate-id",
  "exp": 1704067200,
  "cnf": {"jwk": {"kty": "OKP", "crv": "Ed25519", "x": "..."}}
}
```

### Auth Token (auth+jwt)
```json
Header: {"typ": "auth+jwt", "alg": "EdDSA", "kid": "..."}
Payload: {
  "iss": "https://auth-server.example",
  "aud": "https://resource.example",
  "sub": "user-id",
  "agent": "https://agent.example",
  "scope": "data.read data.write",
  "exp": 1704067200,
  "cnf": {"jwk": {...}}
}
```

### Resource Token (resource+jwt)
```json
Header: {"typ": "resource+jwt", "alg": "EdDSA", "kid": "..."}
Payload: {
  "iss": "https://resource.example",
  "aud": "https://auth-server.example",
  "agent": "https://agent.example",
  "agent_jkt": "base64url_sha256_thumbprint",
  "scope": "data.read",
  "exp": 1704067200
}
```

---

## Part 4: Rust-Specific Guidance

### Recommended Crates
```toml
[dependencies]
ed25519-dalek = "2"           # Ed25519 signatures
sha2 = "0.10"                 # SHA-256, SHA-512
base64 = "0.21"               # Base64 encoding
serde = { version = "1", features = ["derive"] }
serde_json = "1"              # JSON parsing
url = "2"                     # URL parsing
thiserror = "1"               # Error handling
```

### Module Structure
```
src/
├── lib.rs
├── encoding/
│   ├── mod.rs
│   └── base64.rs
├── digest/
│   ├── mod.rs
│   └── content_digest.rs
├── keys/
│   ├── mod.rs
│   ├── jwk.rs
│   ├── jwk_thumbprint.rs
│   └── ed25519.rs
├── headers/
│   ├── mod.rs
│   ├── signature_key.rs
│   ├── signature_input.rs
│   └── signature.rs
├── signing/
│   ├── mod.rs
│   ├── signature_base.rs
│   ├── signer.rs
│   └── verifier.rs
├── tokens/
│   ├── mod.rs
│   ├── agent_token.rs
│   ├── auth_token.rs
│   └── resource_token.rs
└── errors.rs
```

### Error Types
```rust
#[derive(Debug, thiserror::Error)]
pub enum AAuthError {
    #[error("Invalid header format: {0}")]
    InvalidHeader(String),
    
    #[error("Signature verification failed: {0}")]
    SignatureError(String),
    
    #[error("Label mismatch across headers")]
    LabelMismatch,
    
    #[error("Timestamp outside valid window")]
    TimestampExpired,
    
    #[error("Missing required component: {0}")]
    MissingComponent(String),
    
    #[error("Unsupported scheme: {0}")]
    UnsupportedScheme(String),
}
```

---

## Part 5: TypeScript-Specific Guidance

### Recommended Packages
```json
{
  "dependencies": {
    "@noble/ed25519": "^2.0.0",
    "jose": "^5.0.0"
  }
}
```

### Module Structure
```
src/
├── index.ts
├── encoding/
│   └── base64.ts
├── digest/
│   └── contentDigest.ts
├── keys/
│   ├── jwk.ts
│   ├── jwkThumbprint.ts
│   └── ed25519.ts
├── headers/
│   ├── signatureKey.ts
│   ├── signatureInput.ts
│   └── signature.ts
├── signing/
│   ├── signatureBase.ts
│   ├── signer.ts
│   └── verifier.ts
└── tokens/
    ├── agentToken.ts
    ├── authToken.ts
    └── resourceToken.ts
```

---

## Part 6: Testing Strategy

### Unit Test Each Component
1. Base64 encode/decode (both standard and URL-safe)
2. Content-Digest calculation
3. JWK Thumbprint calculation
4. Signature-Key parsing and building
5. Signature-Input parsing and building
6. Signature base construction (MOST CRITICAL)
7. Ed25519 sign/verify

### Integration Tests
1. Sign and verify a GET request
2. Sign and verify a POST request with body
3. Sign and verify with query string
4. Verify RFC 9421 B.2.6 test vector (Ed25519)

### Cross-Implementation Validation
```bash
# Generate reference from Python
python aauth_validator.py generate --output reference.json

# Generate from your implementation
your-impl generate-test-outputs --output candidate.json

# Compare
python aauth_validator.py validate --reference reference.json --candidate candidate.json
```

---

## Part 7: Common Pitfalls

### Signature Base Issues
1. **Wrong newlines**: Use LF only, not CRLF
2. **Trailing newline**: NO newline after @signature-params
3. **@query format**: MUST include leading "?"
4. **Header case**: Lookup case-insensitive, output lowercase
5. **Component order**: Must match order in Signature-Input

### Base64 Issues
1. **URL-safe vs standard**: JWK uses URL-safe, Signature uses standard
2. **Padding**: JWK has no padding, handle missing padding on decode
3. **Colons**: Signature header wraps base64 in colons

### Timestamp Issues
1. **Units**: Unix timestamp in SECONDS (not milliseconds)
2. **Tolerance**: Default 60 seconds, configurable

### Label Issues
1. **Consistency**: Must match across all three headers
2. **Format**: Usually "sig1" or "sig", alphanumeric

---

## Part 8: Validation Checklist

Before considering implementation complete:

- [ ] `aauth-test-vectors.json` - All content_digest_tests pass
- [ ] `aauth-test-vectors.json` - All jwk_thumbprint_tests pass  
- [ ] `aauth-test-vectors.json` - All signature_base_tests pass (byte-for-byte)
- [ ] `aauth-test-vectors.json` - All signature_key_header_tests pass
- [ ] RFC 9421 B.2.6 test vector - Signature verifies
- [ ] Cross-validation with Python reference - All comparisons pass
- [ ] Sign/verify round-trip works for all request types
- [ ] Label mismatch correctly rejected
- [ ] Expired timestamp correctly rejected
- [ ] Missing signature-key in components correctly rejected

---

## Quick Reference: Test Key

Use this Ed25519 key for all testing (from RFC 9421):

```
Public X (base64url): JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs
Private D (base64url): n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU

JWK Thumbprint: kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k
```

---

## Getting Started

1. Create new Rust project: `cargo new aauth-rs --lib`
2. Add dependencies to Cargo.toml
3. Copy `aauth-test-vectors.json` to project
4. Implement Step 1 (Base64), write tests
5. Implement Step 2 (Content-Digest), verify against test vectors
6. Continue through steps, testing each one
7. Run cross-validation against Python reference
8. Celebrate when all tests pass! 🎉
