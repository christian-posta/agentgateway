# Running AAuth Tests

This guide provides step-by-step instructions for running all AAuth tests.

## Prerequisites

- Rust toolchain (1.90+)
- Cargo installed
- Network access (for downloading dependencies, if not cached)

## Quick Start

Run all tests:

```bash
# Unit tests for aauth crate
cargo test --package aauth --lib

# Integration tests for gateway
cargo test --package agentgateway --lib http::aauth

# Run both (note: must be separate commands)
cargo test --package aauth --lib
cargo test --package agentgateway --lib http::aauth
```

**Note**: All tests compile successfully. Run them to verify functionality.

## Unit Tests (aauth crate)

### Run All Unit Tests

```bash
cargo test --package aauth --lib
```

Expected output:
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

### Run Tests by Module

```bash
# Test encoding module
cargo test --package aauth --lib encoding

# Test digest module  
cargo test --package aauth --lib digest

# Test keys module
cargo test --package aauth --lib keys

# Test headers module
cargo test --package aauth --lib headers

# Test signing module
cargo test --package aauth --lib signing
```

### Run Specific Tests

```bash
# Test content digest against test vectors
cargo test --package aauth --lib test_content_digest_from_vectors

# Test JWK thumbprint
cargo test --package aauth --lib test_jwk_thumbprint_ed25519

# Test signature key parsing
cargo test --package aauth --lib test_parse_signature_key_hwk
```

## Integration Tests (agentgateway)

### Run All Integration Tests

```bash
cargo test --package agentgateway --lib http::aauth
```

Expected output:
```
running 5 tests
test http::aauth::tests::tests::test_aauth_missing_signature_optional_mode ... ok
test http::aauth::tests::tests::test_aauth_missing_signature_strict_mode ... ok
test http::aauth::tests::tests::test_challenge_response_hwk ... ok
test http::aauth::tests::tests::test_challenge_response_jwks ... ok
test http::aauth::tests::tests::test_challenge_response_jwt ... ok

test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 306 filtered out
```

**Note**: The test path includes `tests::tests::` because the test module is named `tests` and is inside the `aauth` module which is in the `http` module.

### Run Specific Integration Tests

```bash
# Test optional mode behavior
cargo test --package agentgateway --lib http::aauth::tests::test_aauth_missing_signature_optional_mode

# Test strict mode behavior
cargo test --package agentgateway --lib http::aauth::tests::test_aauth_missing_signature_strict_mode

# Test challenge response generation
cargo test --package agentgateway --lib http::aauth::tests::test_challenge_response_hwk
cargo test --package agentgateway --lib http::aauth::tests::test_challenge_response_jwks
cargo test --package agentgateway --lib http::aauth::tests::test_challenge_response_jwt
```

## Test Output and Debugging

### Verbose Output

```bash
# Show test output
cargo test --package aauth --lib -- --nocapture

# Show test output for integration tests
cargo test --package agentgateway --lib http::aauth -- --nocapture
```

### Single Threaded (for debugging)

```bash
# Run tests sequentially
cargo test --package aauth --lib -- --test-threads=1

# Run with backtrace on failure
RUST_BACKTRACE=1 cargo test --package aauth --lib
```

### Filter Tests

```bash
# Run tests matching a pattern
cargo test --package aauth --lib -- jwk

# Run tests matching multiple patterns
cargo test --package aauth --lib -- base64 digest
```

## Test Validation Against Test Vectors

The implementation includes tests that validate against `aauth-test-vectors.json`:

### Content Digest Tests

```bash
cargo test --package aauth --lib test_content_digest_from_vectors
```

Validates:
- SHA-256 digest: `sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:`
- SHA-512 digest: `sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:`

### JWK Thumbprint Tests

```bash
cargo test --package aauth --lib test_jwk_thumbprint_ed25519
```

Validates RFC 7638 thumbprint calculation:
- Input: Ed25519 JWK with `x="JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"`
- Expected: `poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U`

## Troubleshooting

### Tests Fail to Compile

1. **Check Rust version**: Ensure you have Rust 1.90+
   ```bash
   rustc --version
   ```

2. **Update dependencies**:
   ```bash
   cargo update
   ```

3. **Clean and rebuild**:
   ```bash
   cargo clean
   cargo test --package aauth --lib
   ```

### Tests Pass but Expected Behavior Fails

1. **Check test output**: Run with `--nocapture` to see what's happening
2. **Verify test vectors**: Ensure `aauth-test-vectors.json` is present
3. **Check implementation**: Compare against Python reference if available

### Network Issues

If tests fail due to network access (e.g., downloading Rust toolchain):

1. **Use offline mode** (if dependencies are cached):
   ```bash
   cargo test --package aauth --lib --offline
   ```

2. **Check dependency cache**:
   ```bash
   cargo tree --package aauth
   ```

## Continuous Integration

For CI/CD pipelines, use:

```bash
# Run all tests with minimal output
cargo test --package aauth --lib --package agentgateway --lib http::aauth --quiet

# Run with JSON output (for parsing)
cargo test --package aauth --lib --message-format=json
```

## Next Steps

After running tests successfully:

1. Review test coverage report
2. Add additional test cases for edge cases
3. Implement end-to-end tests with real HTTP requests
4. Add performance benchmarks

See [TESTING.md](TESTING.md) for more detailed testing information.
