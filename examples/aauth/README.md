# AAuth (Agent-to-Agent Authentication) Example

This example demonstrates how to configure and use AAuth (Agent-to-Agent Authentication) policy in agentgateway.

## Overview

AAuth implements HTTP Message Signatures per RFC 9421 with the current AAuth draft profile. It provides progressive authentication levels:

- **hwk** (Pseudonymous): Any HTTP signature is sufficient
- **jwks_uri** (Identified): Requires verifiable agent identity via JWKS
- **jwt** (Authorized): Requires authorization token from auth server

## Configuration

The checked-in example config demonstrates:

- strict AAuth verification
- identity-only access using `requiredScheme: jwks`
- CEL authorization based on `aauth.*` fields

```yaml
policies:
  - aauth:
      mode: strict           # strict | optional | permissive
      requiredScheme: jwks   # hwk | jwks | jwt
      timestampTolerance: 60 # seconds (default: 60)
      challenge:
        authServer: "https://auth.example.com"
  - authorization:
      - allow: 'aauth.agent == "https://trusted-agent.example" && (aauth.scheme == "jwks_uri" || (aauth.scheme == "jwt" && aauth.user != null))'
```

`requiredScheme` still uses config values `hwk | jwks | jwt`. The identified wire-level signature scheme exposed in CEL is `jwks_uri`, matching `SPEC_UPDATED.md`.

### Policy Modes

- **strict**: A valid signature meeting the required scheme must be present
- **optional**: If a signature exists, validate it. Otherwise allow the request
- **permissive**: Never reject requests. Useful for logging and claims extraction

### Required Schemes

- **hwk**: Accepts any HTTP signature (pseudonymous authentication)
- **jwks**: Requires verifiable agent identity via `scheme=jwks_uri` discovery
- **jwt**: Requires authorization token from an auth server

## Progressive Authentication

When a client presents a lower authentication level than required, the gateway responds with an `AAuth` header indicating what's needed:

- For `hwk`: `AAuth: require=pseudonym`
- For `jwks`: `AAuth: require=identity`
- For `jwt`: `AAuth: require=auth-token; resource-token=""; auth-server="..."`

## CEL Authorization

AAuth claims are available for CEL-based authorization:

```yaml
authorization:
  - allow: 'aauth.scheme == "jwks_uri" && aauth.agent == "https://trusted-agent.example"'
```

For an `auth+jwt` request where you want both the agent and a delegated user:

```yaml
authorization:
  - allow: 'aauth.scheme == "jwt" && aauth.agent == "https://trusted-agent.example" && aauth.user != null'
```

Available fields:
- `aauth.scheme`: Authentication scheme used (`"hwk"`, `"jwks_uri"`, `"jwt"`)
- `aauth.agent`: Agent identifier (for jwks/jwt schemes)
- `aauth.agent_delegate`: Agent delegate identifier (for jwt with agent token)
- `aauth.user`: End-user identifier from an `auth+jwt` token, if present
- `aauth.scope`: Authorized scopes from an `auth+jwt` token, if present
- `aauth.token_type`: `"agent+jwt"` or `"auth+jwt"` for JWT-backed requests
- `aauth.jwt_claims`: Full validated JWT claims
- `aauth.thumbprint`: JWK thumbprint of the signing key

## Running the Example

1. Start the gateway with the example configuration:
   ```bash
   agentgateway --config examples/aauth/config.yaml
   ```

2. Make a request without signature. In strict mode the gateway rejects it:
   ```bash
   curl http://localhost:8080/
   ```

3. The gateway returns `401 Unauthorized` with a JSON body such as `{"error":"invalid_signature",...}`.

4. Retry with a valid identified signature from `https://trusted-agent.example`. That request satisfies both the AAuth policy and the CEL authorization rule in `config.yaml`.

5. If you change `requiredScheme` to `jwt`, the gateway challenges with `AAuth: require=auth-token; ...`, and CEL can then use fields like `aauth.user`, `aauth.scope`, and `aauth.token_type`.

## References

- [AAuth Specification](../SPEC.md)
- [RFC 9421: HTTP Message Signing](https://www.rfc-editor.org/rfc/rfc9421.html)
- [RFC 9530: Content-Digest](https://www.rfc-editor.org/rfc/rfc9530.html)
- [RFC 7638: JWK Thumbprint](https://www.rfc-editor.org/rfc/rfc7638.html)
