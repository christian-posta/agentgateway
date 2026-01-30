# AAuth Rust Library - Testing Guide

This document describes how to run tests for the AAuth Rust library and verify the implementation against the test vectors.

## Running Tests

### Unit Tests

Run all unit tests for the aauth crate:

```bash
cargo test --package aauth --lib
```

Run tests for a specific module:

```bash
# Test base64 encoding
cargo test --package aauth --lib encoding

# Test content digest
cargo test --package aauth --lib digest

# Test JWK thumbprint
cargo test --package aauth --lib keys::jwk_thumbprint

# Test signature base construction
cargo test --package aauth --lib signing::signature_base

# Test header parsing
cargo test --package aauth --lib headers
```

### Integration Tests

Run gateway integration tests:

```bash
# Run all AAuth integration tests
cargo test --package agentgateway --lib http::aauth

# Run specific test
cargo test --package agentgateway --lib http::aauth::tests::test_aauth_missing_signature_optional_mode

# Run with output
cargo test --package agentgateway --lib http::aauth -- --nocapture
```

**Available Integration Tests:**

- `test_aauth_missing_signature_optional_mode`: Verifies Optional mode allows requests without signatures
- `test_aauth_missing_signature_strict_mode`: Verifies Strict mode rejects requests without signatures  
- `test_challenge_response_hwk`: Verifies hwk scheme challenge response format
- `test_challenge_response_jwks`: Verifies jwks scheme challenge response format
- `test_challenge_response_jwt`: Verifies jwt scheme challenge response format

### Test Vectors

The implementation includes tests that verify against the test vectors in `aauth-test-vectors.json`:

- **Content Digest Tests**: Verify SHA-256 and SHA-512 digest calculation
- **JWK Thumbprint Tests**: Verify RFC 7638 thumbprint calculation
- **Signature Base Tests**: Verify RFC 9421 signature base construction
- **Header Parsing Tests**: Verify Signature-Key, Signature-Input, and Signature header parsing

### Running Specific Test Cases

```bash
# Run a specific test
cargo test --package aauth --lib test_content_digest_from_vectors

# Run tests matching a pattern
cargo test --package aauth --lib -- --test-threads=1 jwk

# Run with output
cargo test --package aauth --lib -- --nocapture
```

## Test Vectors Validation

The test vectors file (`aauth-test-vectors.json`) contains reference implementations for:

1. **Content Digest Tests** (`content_digest_tests`)
   - SHA-256 and SHA-512 digest calculation
   - Expected format: `sha-256=:base64value:`

2. **JWK Thumbprint Tests** (`jwk_thumbprint_tests`)
   - RFC 7638 thumbprint calculation
   - Canonical JSON construction
   - Base64URL encoding

3. **Signature Base Tests** (`signature_base_tests`)
   - RFC 9421 Section 2.5 signature base construction
   - Component ordering and formatting
   - Line separator handling (LF only)

4. **Signature Key Header Tests** (`signature_key_header_tests`)
   - Parsing hwk, jwks, and jwt schemes
   - Building signature-key headers

5. **Label Consistency Tests** (`label_consistency_tests`)
   - Verifying labels match across all three headers

## Example Test Output

### Unit Tests (aauth crate)

```
running 25 tests
test encoding::base64::tests::test_base64_encode ... ok
test encoding::base64::tests::test_base64_decode ... ok
test encoding::base64::tests::test_base64url_encode ... ok
test encoding::base64::tests::test_base64url_decode ... ok
test digest::content_digest::tests::test_content_digest_sha256 ... ok
test digest::content_digest::tests::test_content_digest_sha512 ... ok
test keys::jwk_thumbprint::tests::test_jwk_thumbprint_ed25519 ... ok
test keys::jwk::tests::test_jwk_parse_okp ... ok
test keys::jwk::tests::test_jwk_canonical_okp ... ok
test keys::ed25519::tests::test_generate_and_sign_verify ... ok
test keys::ed25519::tests::test_public_key_encoding ... ok
test headers::signature_key::tests::test_parse_signature_key_hwk ... ok
test headers::signature_key::tests::test_parse_signature_key_jwks ... ok
test headers::signature_key::tests::test_build_signature_key_hwk ... ok
test headers::signature_key::tests::test_build_signature_key_jwks ... ok
test headers::signature_input::tests::test_parse_signature_input ... ok
test headers::signature_input::tests::test_parse_signature_input_with_keyid ... ok
test headers::signature_input::tests::test_build_signature_input ... ok
test headers::signature::tests::test_parse_signature ... ok
test headers::signature::tests::test_build_signature ... ok
test signing::signature_base::tests::test_signature_base_simple_get ... ok
test signing::signature_base::tests::test_signature_base_with_query ... ok
test lib::tests::test_content_digest_from_vectors ... ok
test lib::tests::test_jwk_thumbprint_from_vectors ... ok
test lib::tests::test_signature_key_parsing ... ok

test result: ok. 25 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

### Integration Tests (agentgateway)

```
running 5 tests
test http::aauth::tests::tests::test_aauth_missing_signature_optional_mode ... ok
test http::aauth::tests::tests::test_aauth_missing_signature_strict_mode ... ok
test http::aauth::tests::tests::test_challenge_response_hwk ... ok
test http::aauth::tests::tests::test_challenge_response_jwks ... ok
test http::aauth::tests::tests::test_challenge_response_jwt ... ok

test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 306 filtered out
```

## Debugging Failed Tests

If a test fails, you can run it with more verbose output:

```bash
# Run with backtrace
RUST_BACKTRACE=1 cargo test --package aauth --lib test_content_digest_from_vectors

# Run with detailed output
cargo test --package aauth --lib -- --nocapture --test-threads=1
```

## Cross-Implementation Validation

To validate against the Python reference implementation:

```bash
# Generate reference outputs from Python
cd aauth-rust
python aauth_validator.py generate --output reference_outputs.json

# Compare with Rust implementation (when implemented)
cargo run --package aauth --bin validate-test-vectors -- reference_outputs.json
```

## Test Coverage

Current test coverage includes:

### Unit Tests (aauth crate)

- ✅ Base64 encoding/decoding (standard and URL-safe)
- ✅ Content-Digest calculation (SHA-256, SHA-512) - validated against test vectors
- ✅ JWK thumbprint calculation - validated against test vectors
- ✅ Signature-Key header parsing and building
- ✅ Signature-Input header parsing and building
- ✅ Signature header parsing and building
- ✅ Signature base construction
- ✅ Ed25519 key generation and signing
- ⚠️ JWT token validation (stub - needs JWT library integration)
- ⚠️ JWKS fetching (stub - needs HTTP client integration)

### Integration Tests (agentgateway)

- ✅ Optional mode: allows requests without signatures
- ✅ Strict mode: rejects requests without signatures
- ✅ Challenge response generation for hwk scheme
- ✅ Challenge response generation for jwks scheme
- ✅ Challenge response generation for jwt scheme
- ⚠️ End-to-end signature verification (needs full request/response cycle)
- ⚠️ Claims extraction and CEL integration (needs verification with actual signatures)

## Next Steps for Testing

1. **End-to-End Tests**: Add tests that sign and verify complete HTTP requests
2. **JWKS Integration**: Add tests for fetching and validating JWKS
3. **JWT Validation**: Add tests for agent+jwt and auth+jwt token validation
4. **Error Cases**: Add tests for all error conditions
5. **Performance Tests**: Add benchmarks for signature verification
