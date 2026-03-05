---
name: api-security-review
description: Review API definitions and implementations against the OWASP API Security Top 10. Use when reviewing OpenAPI/Swagger specs, auditing REST/GraphQL/gRPC implementations, or checking API gateway and middleware configuration for security issues.
allowed-tools: Read, Grep, Glob, Bash, Agent
---

# API Security Review

Review API security by following the full procedure in `plays/tier1-code-analysis/api-security-review.md`.

## Steps

1. **API Surface Mapping** — Parse OpenAPI spec or scan route definitions to enumerate all endpoints, auth requirements, request/response schemas, and rate limiting.

2. **Assess Each API Security Top 10 Risk**:
   - **API1 BOLA** — Object ownership verified on every access? Predictable IDs? Batch endpoints filtered?
   - **API2 Broken Authentication** — Unauthenticated endpoints? Consistent auth middleware? Brute-force protection?
   - **API3 Broken Object Property Level Authorization** — Mass assignment? Response over-exposure? Field-level authz?
   - **API4 Unrestricted Resource Consumption** — Rate limiting? Pagination limits? Upload size limits? Query complexity limits?
   - **API5 Broken Function Level Authorization** — Admin endpoints protected? Role checks on function not UI? HTTP method restrictions?
   - **API6 Unrestricted Sensitive Business Flows** — Automated abuse prevention? CAPTCHA? Business logic rate limits?
   - **API7 SSRF** — URL parameters validated against allowlist? Internal services reachable? Cloud metadata blocked?
   - **API8 Security Misconfiguration** — CORS restrictive? Security headers present? Error responses generic? Debug disabled?
   - **API9 Improper Inventory** — Undocumented endpoints? Deprecated routes still accessible? Old API versions live?
   - **API10 Unsafe Consumption** — Third-party API responses validated? Timeouts and circuit breakers? Webhook auth?

3. **Schema Validation Depth** — For OpenAPI specs: required fields, maxLength, min/max constraints, enums, `additionalProperties: false`, format constraints.

4. **GraphQL-Specific** (if applicable) — Introspection disabled in prod? Depth limiting? Complexity analysis? Field-level authz? Batch limiting?

## Output

API overview (type, spec availability, endpoint count, auth mechanism), risk matrix for all 10 categories, findings using `templates/finding.md`, and prioritized recommendations.

## OWASP References

- OWASP API Security Top 10 (2023)
- OWASP ASVS v5.0 — V13: API and Web Service
- OWASP Cheat Sheet: REST Security, GraphQL Security
