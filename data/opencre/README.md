# OpenCRE — Cross-Standard Reference Layer

[OpenCRE](https://www.opencre.org) (Open Common Requirements Enumeration) maps security requirements across standards, creating a unified graph that links CWEs, OWASP projects, NIST, ISO 27001, and more.

## Why OpenCRE

When a finding references CWE-79, OpenCRE tells you which ASVS requirement covers it (V5.3.3), which WSTG test to run (WSTG-INPV-01), which OWASP cheat sheet applies (XSS Prevention), and which NIST 800-53 control maps to it — all through a single lookup.

This eliminates manual cross-referencing between standards and ensures findings are traceable across compliance frameworks.

## Standards Mapped

| Standard | Coverage |
|----------|----------|
| CWE | Common Weakness Enumeration (944 weaknesses) |
| OWASP Top 10 (2021) | A01-A10 |
| OWASP ASVS | Application Security Verification Standard |
| OWASP WSTG | Web Security Testing Guide |
| OWASP Proactive Controls | C1-C10 |
| OWASP Cheat Sheets | Per-topic defense guidance |
| NIST 800-53 v5 | Security and Privacy Controls |
| NIST SSDF | Secure Software Development Framework |
| ISO 27001 | Information Security Management |
| CAPEC | Common Attack Pattern Enumeration |
| Cloud Controls Matrix | CSA CCM |
| OWASP SAMM | Software Assurance Maturity Model |

## CRE Hierarchy

OpenCRE organizes security into five root domains:

| CRE ID | Domain |
|--------|--------|
| 636-660 | Technical application security controls |
| 546-564 | Cross-cutting concerns |
| 616-305 | Development processes for security |
| 862-452 | Operating processes for security |
| 567-755 | Governance processes for security |

Under **Technical application security controls** (636-660):

| CRE ID | Category |
|--------|----------|
| 633-428 | Authentication |
| 724-770 | Technical application access control |
| 503-455 | Input and output protection |
| 842-876 | Logging and error handling |
| 854-643 | Robust business logic |
| 278-646 | Secure communication |
| 126-668 | Secure data storage |
| 708-355 | Secure implemented architecture |
| 586-842 | Secure user management |
| 177-260 | Session management |
| 233-748 | Configuration hardening |

## REST API

Base URL: `https://www.opencre.org/rest/v1`

### Lookup by CRE ID

```
GET /id/{cre-id}
```

Example: `GET /id/366-835` returns the "Escape output against XSS" CRE with all linked standards.

### Lookup by Standard

```
GET /standard/{standard-name}/sectionid/{section-id}
```

Example: `GET /standard/CWE/sectionid/79` returns CREs linked to CWE-79.

### Get Root CREs

```
GET /root_cres
```

Returns all top-level CRE categories.

### Web UI

For any CRE, the web link is:

```
https://www.opencre.org/cre/{cre-id}
```

For any standard mapping:

```
https://www.opencre.org/standard/{standard-name}/{section-id}
```

## Usage in Findings

When producing a finding, include the OpenCRE link to enable cross-standard traceability:

```markdown
### [HIGH] Reflected XSS in Search Parameter

- **CWE**: CWE-79
- **OpenCRE**: [366-835](https://www.opencre.org/cre/366-835) — Escape output against XSS
- **OWASP Ref**: Top 10 A03, ASVS V5.3.3, WSTG-INPV-01
- **Location**: src/search.js:42
```

The OpenCRE link gives the reader one-click access to every related standard, cheat sheet, and test case.

## Common CRE Mappings for Playbook Skills

These are the CREs most frequently relevant to our plays:

| Finding Type | CWE | CRE ID | CRE Name |
|-------------|-----|--------|----------|
| XSS | CWE-79 | 366-835 | Escape output against XSS |
| SQL Injection | CWE-89 | 161-451 | Output encoding and injection prevention |
| Command Injection | CWE-78 | 161-451 | Output encoding and injection prevention |
| Broken Access Control | CWE-862 | 724-770 | Technical application access control |
| Auth Bypass | CWE-287 | 633-428 | Authentication |
| Sensitive Data Exposure | CWE-200 | 126-668 | Secure data storage |
| CSRF | CWE-352 | 854-643 | Robust business logic |
| Path Traversal | CWE-22 | 503-455 | Input and output protection |
| Weak Crypto | CWE-327 | 278-646 | Secure communication |
| Session Fixation | CWE-384 | 177-260 | Session management |
| Misconfiguration | CWE-16 | 233-748 | Configuration hardening |
| Logging Gaps | CWE-778 | 842-876 | Logging and error handling |

Expand this table as new plays are added. Use the API to discover CRE mappings for CWEs not listed here.
