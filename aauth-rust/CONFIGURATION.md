# AAuth Configuration Guide

This document describes how to configure AAuth policy in agentgateway.

## Basic Configuration

Add AAuth policy to your gateway configuration:

```yaml
gateways:
  - name: default
    listeners:
      - port: 8080
        protocol: HTTP
        routes:
          - name: protected-route
            match:
              - path:
                  type: Prefix
                  value: /api
            backends:
              - name: backend
                type: static
                endpoints:
                  - address: 127.0.0.1:8081
            policies:
              - aauth:
                  mode: strict
                  requiredScheme: jwks
                  timestampTolerance: 60
```

## Configuration Options

### `mode` (optional, default: `strict`)

Controls how the policy handles missing or invalid signatures:

- **`strict`**: A valid signature meeting the required scheme must be present. Requests without valid signatures are rejected.
- **`optional`**: If a signature exists, validate it. Otherwise allow the request to proceed.
- **`permissive`**: Never reject requests. Useful for logging and claims extraction without enforcement.

```yaml
policies:
  - aauth:
      mode: optional  # Allow requests without signatures
```

### `requiredScheme` (required)

Specifies the minimum authentication level required:

- **`hwk`**: Pseudonymous authentication. Any HTTP signature is sufficient.
- **`jwks`**: Identified authentication. Requires verifiable agent identity via JWKS discovery.
- **`jwt`**: Authorized authentication. Requires authorization token from an auth server.

```yaml
policies:
  - aauth:
      requiredScheme: jwt  # Require full authorization
```

### `timestampTolerance` (optional, default: `60`)

Maximum allowed time difference (in seconds) between the signature's `created` timestamp and the current time. Signatures outside this window are rejected.

```yaml
policies:
  - aauth:
      timestampTolerance: 120  # Allow 2-minute window
```

### `challenge` (optional)

Configuration for generating challenge responses when authentication is insufficient. Required when `requiredScheme` is `jwt`.

```yaml
policies:
  - aauth:
      requiredScheme: jwt
      challenge:
        authServer: "https://auth.example.com"
        # TODO: resourceTokenIssuer configuration
```

## Progressive Authentication Examples

### Example 1: Pseudonymous Authentication (hwk)

Accept any HTTP signature for abuse prevention:

```yaml
policies:
  - aauth:
      mode: strict
      requiredScheme: hwk
      timestampTolerance: 60
```

**Client Response**: When no signature is present, gateway responds with:
```
HTTP/1.1 401 Unauthorized
Agent-Auth: httpsig
```

### Example 2: Identified Authentication (jwks)

Require verifiable agent identity:

```yaml
policies:
  - aauth:
      mode: strict
      requiredScheme: jwks
      timestampTolerance: 60
```

**Client Response**: When signature is missing or uses hwk scheme, gateway responds with:
```
HTTP/1.1 401 Unauthorized
Agent-Auth: httpsig; identity=?1
```

### Example 3: Authorized Authentication (jwt)

Require authorization token:

```yaml
policies:
  - aauth:
      mode: strict
      requiredScheme: jwt
      timestampTolerance: 60
      challenge:
        authServer: "https://auth.example.com"
```

**Client Response**: When signature is missing or uses hwk/jwks scheme, gateway responds with:
```
HTTP/1.1 401 Unauthorized
Agent-Auth: httpsig; auth-token; resource_token="..."; auth_server="https://auth.example.com"
```

## Combining with Other Policies

AAuth can be combined with other authentication and authorization policies:

```yaml
policies:
  # AAuth for HTTP Message Signing
  - aauth:
      mode: strict
      requiredScheme: jwks
  
  # JWT for bearer token validation (if needed)
  - jwt:
      mode: optional
      issuer: "https://auth.example.com"
      jwks:
        uri: "https://auth.example.com/.well-known/jwks.json"
  
  # CEL-based authorization using AAuth claims
  - authorization:
      - when: 'aauth.scheme == "jwt" && aauth.agent == "https://trusted-agent.example"'
        allow: true
      - when: 'aauth.scheme == "jwks"'
        allow: true
      - deny: true
```

## CEL Authorization with AAuth Claims

AAuth claims are available in CEL expressions for authorization:

```yaml
policies:
  - aauth:
      mode: strict
      requiredScheme: jwks
  
  - authorization:
      - when: |
          aauth.scheme == "jwt" && 
          aauth.agent == "https://trusted-agent.example" &&
          aauth.jwt_claims.scope.has("data.write")
        allow: true
      - when: 'aauth.scheme == "jwks" && aauth.agent.startsWith("https://agents.example/")'
        allow: true
      - deny: true
```

### Available AAuth Claims

- `aauth.scheme`: Authentication scheme used (`"hwk"`, `"jwks"`, or `"jwt"`)
- `aauth.agent`: Agent identifier (present for `jwks` and `jwt` schemes)
- `aauth.agent_delegate`: Agent delegate identifier (present for `jwt` with agent token)
- `aauth.thumbprint`: JWK thumbprint of the signing key
- `aauth.jwt_claims`: Full JWT claims object (present for `jwt` scheme)

## Gateway-Level vs Route-Level Configuration

### Gateway-Level (applies to all routes)

```yaml
gateways:
  - name: default
    policies:
      - aauth:
          mode: strict
          requiredScheme: jwks
    listeners:
      - port: 8080
        protocol: HTTP
        routes:
          - name: route1
            # Inherits gateway-level AAuth policy
```

### Route-Level (overrides gateway-level)

```yaml
gateways:
  - name: default
    policies:
      - aauth:
          mode: strict
          requiredScheme: jwks
    listeners:
      - port: 8080
        protocol: HTTP
        routes:
          - name: public-route
            match:
              - path:
                  type: Prefix
                  value: /public
            policies:
              - aauth:
                  mode: optional  # Override: allow unsigned requests
                  requiredScheme: hwk
          - name: protected-route
            match:
              - path:
                  type: Prefix
                  value: /api
            # Uses gateway-level AAuth policy (strict, jwks)
```

## Complete Example Configuration

```yaml
gateways:
  - name: default
    listeners:
      - port: 8080
        protocol: HTTP
        routes:
          # Public endpoint - optional authentication
          - name: public
            match:
              - path:
                  type: Prefix
                  value: /public
            backends:
              - name: backend
                type: static
                endpoints:
                  - address: 127.0.0.1:8081
            policies:
              - aauth:
                  mode: optional
                  requiredScheme: hwk
          
          # Protected endpoint - require identified agents
          - name: protected
            match:
              - path:
                  type: Prefix
                  value: /api
            backends:
              - name: backend
                type: static
                endpoints:
                  - address: 127.0.0.1:8081
            policies:
              - aauth:
                  mode: strict
                  requiredScheme: jwks
                  timestampTolerance: 60
              
              - authorization:
                  - when: 'aauth.agent == "https://trusted-agent.example"'
                    allow: true
                  - deny: true
          
          # Admin endpoint - require full authorization
          - name: admin
            match:
              - path:
                  type: Prefix
                  value: /admin
            backends:
              - name: backend
                type: static
                endpoints:
                  - address: 127.0.0.1:8081
            policies:
              - aauth:
                  mode: strict
                  requiredScheme: jwt
                  timestampTolerance: 60
                  challenge:
                    authServer: "https://auth.example.com"
              
              - authorization:
                  - when: |
                      aauth.scheme == "jwt" &&
                      aauth.jwt_claims.scope.has("admin")
                    allow: true
                  - deny: true
```

## Troubleshooting

### Signature Verification Fails

1. **Check timestamp tolerance**: Ensure `timestampTolerance` is sufficient for clock skew
2. **Verify signature headers**: Ensure `Signature-Key`, `Signature-Input`, and `Signature` headers are present
3. **Check label consistency**: All three headers must use the same label
4. **Verify signature-key coverage**: `signature-key` must be in the covered components

### Challenge Response Not Sent

- Ensure `mode` is `strict` (optional/permissive modes don't send challenges)
- Check that the required scheme is higher than what the client presented
- Verify the `challenge` configuration is present for `jwt` scheme

### Claims Not Available in CEL

- Ensure signature verification succeeded (check logs)
- Verify the scheme provides the claim you're accessing (e.g., `agent` only for `jwks`/`jwt`)
- Check that AAuth policy runs before authorization policy

## References

- [AAuth Specification](../SPEC.md)
- [RFC 9421: HTTP Message Signing](https://www.rfc-editor.org/rfc/rfc9421.html)
- [RFC 9530: Content-Digest](https://www.rfc-editor.org/rfc/rfc9530.html)
- [RFC 7638: JWK Thumbprint](https://www.rfc-editor.org/rfc/rfc7638.html)
