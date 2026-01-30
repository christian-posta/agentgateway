# AAuth (Agent-to-Agent Authentication) Example

This example demonstrates how to configure and use AAuth (Agent-to-Agent Authentication) policy in agentgateway.

## Overview

AAuth implements HTTP Message Signing per RFC 9421 with the AAuth profile extensions. It provides progressive authentication levels:

- **hwk** (Pseudonymous): Any HTTP signature is sufficient
- **jwks** (Identified): Requires verifiable agent identity via JWKS
- **jwt** (Authorized): Requires authorization token from auth server

## Configuration

```yaml
policies:
  - aauth:
      mode: strict           # strict | optional | permissive
      requiredScheme: jwks   # hwk | jwks | jwt
      timestampTolerance: 60 # seconds (default: 60)
      challenge:
        authServer: "https://auth.example.com"
```

### Policy Modes

- **strict**: A valid signature meeting the required scheme must be present
- **optional**: If a signature exists, validate it. Otherwise allow the request
- **permissive**: Never reject requests. Useful for logging and claims extraction

### Required Schemes

- **hwk**: Accepts any HTTP signature (pseudonymous authentication)
- **jwks**: Requires verifiable agent identity via JWKS discovery
- **jwt**: Requires authorization token from an auth server

## Progressive Authentication

When a client presents a lower authentication level than required, the gateway responds with an `Agent-Auth` header indicating what's needed:

- For `hwk`: `Agent-Auth: httpsig`
- For `jwks`: `Agent-Auth: httpsig; identity=?1`
- For `jwt`: `Agent-Auth: httpsig; auth-token; resource_token="..."; auth_server="..."`

## CEL Authorization

AAuth claims are available for CEL-based authorization:

```yaml
authorization:
  - when: 'aauth.scheme == "jwt" && aauth.agent == "https://trusted-agent.example"'
    allow: true
```

Available fields:
- `aauth.scheme`: Authentication scheme used ("hwk", "jwks", "jwt")
- `aauth.agent`: Agent identifier (for jwks/jwt schemes)
- `aauth.agent_delegate`: Agent delegate identifier (for jwt with agent token)
- `aauth.thumbprint`: JWK thumbprint of the signing key

## Running the Example

1. Start the gateway with the example configuration:
   ```bash
   agentgateway --config examples/aauth/config.yaml
   ```

2. Make a request without signature (will be rejected in strict mode):
   ```bash
   curl http://localhost:8080/
   ```

3. The gateway will respond with `401 Unauthorized` and an `Agent-Auth` header indicating what's required.

## References

- [AAuth Specification](../SPEC.md)
- [RFC 9421: HTTP Message Signing](https://www.rfc-editor.org/rfc/rfc9421.html)
- [RFC 9530: Content-Digest](https://www.rfc-editor.org/rfc/rfc9530.html)
- [RFC 7638: JWK Thumbprint](https://www.rfc-editor.org/rfc/rfc7638.html)
