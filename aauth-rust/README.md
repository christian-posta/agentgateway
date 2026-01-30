# AAuth Rust Implementation

This directory contains the Rust implementation of AAuth (Agent-to-Agent Authentication) for the agentgateway project.

## Overview

AAuth implements HTTP Message Signing per RFC 9421 with the AAuth profile extensions. It provides:

- **HTTP Message Signing**: Cryptographic signatures for HTTP requests
- **Progressive Authentication**: Three levels (pseudonymous, identified, authorized)
- **Agent Identity**: Verifiable agent identities via JWKS
- **Authorization Integration**: CEL-based authorization using AAuth claims

## Structure

```
aauth-rust/
├── IMPLEMENTATION_PLAN.md    # Detailed implementation plan
├── TESTING.md                 # Testing guide
├── CONFIGURATION.md          # Configuration guide
├── README.md                 # This file
├── aauth-test-vectors.json   # Test vectors for validation
├── aauth_validator.py        # Python reference validator
└── reference_outputs.json     # Reference outputs from Python
```

## Quick Start

### Running Tests

```bash
# Run all aauth crate tests
cargo test --package aauth --lib

# Run gateway integration tests
cargo test --package agentgateway --lib http::aauth

# Run specific test
cargo test --package aauth --lib test_content_digest_from_vectors
```

### Basic Configuration

```yaml
policies:
  - aauth:
      mode: strict
      requiredScheme: jwks
      timestampTolerance: 60
```

See [CONFIGURATION.md](CONFIGURATION.md) for detailed configuration options.

## Implementation Status

### ✅ Completed

- Base64 encoding/decoding (standard and URL-safe)
- Content-Digest calculation (RFC 9530)
- JWK parsing and thumbprint calculation (RFC 7638)
- Ed25519 key operations
- Signature-Key, Signature-Input, and Signature header parsing
- Signature base construction (RFC 9421 Section 2.5)
- Request signing and signature verification
- Gateway policy integration
- Progressive authentication challenges
- CEL authorization integration

### ⚠️ Partial

- JWT token validation (stub - needs JWT library integration)
- JWKS fetching (stub - needs HTTP client integration)
- Resource token issuance (stub - needs implementation)

### 📋 TODO

- Full JWT validation for agent+jwt and auth+jwt tokens
- JWKS fetching and caching
- Resource token issuance for jwt scheme challenges
- End-to-end integration tests
- Performance benchmarks
- Additional signature algorithms (RSA, EC)

## Architecture

The implementation consists of two main parts:

### 1. aauth-rs Library (`crates/aauth/`)

A standalone Rust library implementing the core AAuth functionality:

- **encoding/**: Base64 utilities
- **digest/**: Content-Digest calculation
- **keys/**: JWK operations and Ed25519 cryptography
- **headers/**: HTTP header parsing and building
- **signing/**: Signature base construction and verification
- **tokens/**: JWT token validation (stub)

### 2. Gateway Integration (`crates/agentgateway/src/http/aauth.rs`)

Policy implementation for agentgateway:

- Signature verification
- Progressive authentication challenges
- Claims extraction for CEL
- Configuration parsing

## Usage Examples

### Signing a Request

```rust
use aauth::signing::signer::sign_request;
use aauth::keys::ed25519::{generate_keypair, PrivateKey};
use std::collections::HashMap;

let (private_key, _) = generate_keypair();
let mut headers = HashMap::new();
headers.insert("Host".to_string(), "example.com".to_string());

let result = sign_request(
    "GET",
    "https://example.com/api/data",
    &mut headers,
    None,
    &private_key,
    "hwk",
    &HashMap::new(),
).await?;

// Add signature headers to your HTTP request
headers.insert("Signature-Key".to_string(), result.signature_key);
headers.insert("Signature-Input".to_string(), result.signature_input);
headers.insert("Signature".to_string(), result.signature);
```

### Verifying a Signature

```rust
use aauth::signing::verifier::{verify_signature, resolve_hwk_public_key};
use std::collections::HashMap;

let headers: HashMap<String, String> = /* from HTTP request */;
let url = "https://example.com/api/data";

fn resolver(sig_key: &SignatureKey) -> Result<PublicKey, AAuthError> {
    resolve_hwk_public_key(sig_key)
}

let result = verify_signature(
    "GET",
    &url,
    &headers,
    None,
    60, // timestamp tolerance
    &resolver,
).await?;

if result.valid {
    println!("Signature verified! Scheme: {:?}", result.scheme);
    if let Some(agent) = result.agent_id {
        println!("Agent: {}", agent);
    }
}
```

## Testing

See [TESTING.md](TESTING.md) for detailed testing instructions.

### Test Vectors

The implementation is validated against test vectors in `aauth-test-vectors.json`:

- Content digest tests
- JWK thumbprint tests
- Signature base construction tests
- Header parsing tests
- Label consistency tests

### Cross-Implementation Validation

Compare against the Python reference implementation:

```bash
python aauth_validator.py generate --output reference_outputs.json
# Compare with Rust implementation outputs
```

## Configuration

See [CONFIGURATION.md](CONFIGURATION.md) for detailed configuration options and examples.

### Key Configuration Options

- **mode**: `strict` | `optional` | `permissive`
- **requiredScheme**: `hwk` | `jwks` | `jwt`
- **timestampTolerance**: seconds (default: 60)
- **challenge**: Configuration for jwt scheme challenges

## Integration with Gateway

AAuth is integrated as a traffic policy in agentgateway:

1. **Policy Application**: Runs early in the request pipeline, before other auth policies
2. **Challenge Generation**: Returns `Agent-Auth` headers when authentication is insufficient
3. **Claims Storage**: Stores verified claims in request extensions for CEL authorization
4. **Error Handling**: Returns appropriate HTTP status codes and error messages

## References

- [AAuth Specification](../SPEC.md)
- [RFC 9421: HTTP Message Signing](https://www.rfc-editor.org/rfc/rfc9421.html)
- [RFC 9530: Content-Digest](https://www.rfc-editor.org/rfc/rfc9530.html)
- [RFC 7638: JWK Thumbprint](https://www.rfc-editor.org/rfc/rfc7638.html)
- [Implementation Plan](IMPLEMENTATION_PLAN.md)

## Contributing

When adding new features:

1. Add tests to `crates/aauth/src/lib.rs` or module-specific test files
2. Update test vectors if adding new test cases
3. Update this README and relevant documentation
4. Ensure all tests pass: `cargo test --package aauth --lib`

## License

Apache-2.0 (same as agentgateway project)
