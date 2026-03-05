# Play: API Security Review

Review API definitions and implementations against the OWASP API Security Top 10, identifying vulnerabilities in authentication, authorization, data exposure, and input validation.

## Trigger Conditions

Use this skill when:
- Reviewing an OpenAPI/Swagger specification
- Auditing REST, GraphQL, or gRPC API implementations
- A user asks to check their API for security issues
- Reviewing API gateway or middleware configuration

## Inputs

- OpenAPI/Swagger spec file (YAML or JSON) — preferred
- API source code (route handlers, controllers, middleware)
- API gateway/middleware configuration (Kong, nginx, Envoy, API Gateway)
- (Optional) Authentication/authorization implementation details

## Procedure

### 1. API Surface Mapping

If an OpenAPI spec is available, parse it to enumerate:
- All endpoints (method + path)
- Authentication requirements per endpoint
- Request parameters (path, query, header, body) and their schemas
- Response schemas and status codes
- Rate limiting headers or documentation

If no spec exists, derive the surface from code:
- Scan route definitions, controller annotations, or handler registrations
- Map middleware chains per route (auth, validation, rate limiting)

### 2. Assess Each API Security Top 10 Risk

#### API1: Broken Object Level Authorization (BOLA/IDOR)

- [ ] Do endpoints use predictable IDs (sequential integers)?
- [ ] Is object ownership verified on every access (not just authentication)?
- [ ] Can user A access user B's resources by changing the ID?
- [ ] Are batch/list endpoints filtered by the requesting user's permissions?
- [ ] Do file/resource download endpoints verify authorization?

Check: For every endpoint that takes an object ID, trace the code to confirm authorization checking.

#### API2: Broken Authentication

- [ ] Are there endpoints that should require authentication but don't?
- [ ] Is authentication consistently enforced (middleware, not per-handler)?
- [ ] Are token validation and session management robust?
- [ ] Is there brute-force protection on login/auth endpoints?
- [ ] Are tokens transmitted securely (HTTPS, secure cookies, not in URLs)?
- [ ] Are password reset flows secure (rate-limited, time-limited tokens)?

#### API3: Broken Object Property Level Authorization

- [ ] Can users modify properties they shouldn't (mass assignment)?
- [ ] Do API responses include fields the user shouldn't see?
- [ ] Are request bodies validated against a strict schema (allowlist, not blocklist)?
- [ ] Is there field-level authorization for sensitive properties (role, permissions, balance)?

#### API4: Unrestricted Resource Consumption

- [ ] Is there rate limiting? Per-user or just global?
- [ ] Are pagination limits enforced server-side?
- [ ] Are file upload sizes limited?
- [ ] Are query complexity limits in place (GraphQL depth/complexity)?
- [ ] Are batch endpoints limited in batch size?
- [ ] Are expensive operations (search, report generation) rate-limited separately?

#### API5: Broken Function Level Authorization

- [ ] Are admin endpoints separated and protected by role checks?
- [ ] Can regular users access administrative functions by guessing paths?
- [ ] Is the authorization check on the function, not just the UI that calls it?
- [ ] Are HTTP method restrictions enforced (e.g., GET allowed but PUT requires admin)?

#### API6: Unrestricted Access to Sensitive Business Flows

- [ ] Can automated tools abuse business flows (signup, purchase, reservation)?
- [ ] Are there CAPTCHA or proof-of-work mechanisms for sensitive flows?
- [ ] Are business logic rate limits in place (e.g., max purchases per hour)?

#### API7: Server Side Request Forgery (SSRF)

- [ ] Do any endpoints accept URLs as parameters?
- [ ] Are user-supplied URLs validated against an allowlist?
- [ ] Can internal services be reached via user-supplied URLs?
- [ ] Is the cloud metadata endpoint (169.254.169.254) blocked?
- [ ] Are redirects followed without validation?

#### API8: Security Misconfiguration

- [ ] Are CORS policies restrictive (not `*`)?
- [ ] Are security headers present (Content-Type, X-Content-Type-Options, etc.)?
- [ ] Are error responses generic (no stack traces, internal paths, or SQL errors)?
- [ ] Is debug mode disabled?
- [ ] Are unnecessary HTTP methods disabled?
- [ ] Is TLS properly configured?

#### API9: Improper Inventory Management

- [ ] Are there undocumented endpoints (compare spec to code)?
- [ ] Are deprecated endpoints still accessible?
- [ ] Are old API versions still running alongside new ones?
- [ ] Are development/staging endpoints exposed in production?

#### API10: Unsafe Consumption of APIs

- [ ] Does the API consume third-party APIs? Are those responses validated?
- [ ] Are third-party API responses treated as untrusted input?
- [ ] Are timeouts and circuit breakers in place for external calls?
- [ ] Is data from webhooks/callbacks validated and authenticated?

### 3. Schema Validation Depth Check

For APIs with OpenAPI specs, verify that schemas are defensive:
- Required fields are marked as required
- String fields have maxLength constraints
- Numeric fields have min/max constraints
- Enum types are used where values are bounded
- `additionalProperties: false` is set on request objects
- Format constraints are used (email, uri, date-time, uuid)

### 4. GraphQL-Specific Checks (if applicable)

- [ ] Is introspection disabled in production?
- [ ] Is query depth limiting enforced?
- [ ] Is query complexity analysis in place?
- [ ] Are field-level authorization directives applied?
- [ ] Is batching limited to prevent DoS?

## Output Format

```markdown
## API Security Review: [API Name]

### API Overview
- **Type**: REST | GraphQL | gRPC
- **Spec available**: Yes (OpenAPI 3.x) | No
- **Endpoints**: [count]
- **Auth mechanism**: [Bearer, API Key, OAuth, etc.]

### Risk Matrix
| OWASP API Ref | Risk | Severity | Status |
|--------------|------|----------|--------|
| API1 | BOLA | HIGH | Finding |
| API2 | Broken Auth | N/A | Adequate |
| ... | ... | ... | ... |

### Findings
[Standard finding template for each issue]

### Recommendations
[Prioritized list]
```

## OWASP References

- OWASP API Security Top 10 (2023)
- OWASP ASVS v5.0 — V13: API and Web Service
- OWASP Cheat Sheet: REST Security, GraphQL Security
- OWASP Testing Guide: WSTG-APIT
