```skill
---
name: securable-code-analysis
description: Analyze code for securable qualities using the FIASSE/SSEM framework. Use when assessing code securability, evaluating engineering attributes that impact security (analyzability, modifiability, testability, confidentiality, accountability, authenticity, availability, integrity, resilience), reviewing merge requests through a securable engineering lens, or establishing a security posture baseline. Complements vulnerability-centric reviews by focusing on whether code is able to accommodate fixes for security findings and is engineered to remain securable over time.
license: CC-BY-4.0
---

# Securable Code Analysis (FIASSE/SSEM)

Analyze code for securable engineering qualities by following the full procedure in `plays/tier0-code-analysis/securable-code-analysis.md`.

## Steps

1. **Scope & Context** — Establish language/framework, system type, data sensitivity, exposure, lifecycle stage, and team context.

2. **SSEM Attribute Assessment — Maintainability**:
   - **Analyzability** — Volume, duplication, unit size, cyclomatic complexity, comment density, time-to-understand
   - **Modifiability** — Module coupling, change impact size, regression rate, centralized security code
   - **Testability** — Code coverage, unit test density, mocking complexity, component independence

3. **SSEM Attribute Assessment — Trustworthiness**:
   - **Confidentiality** — Data classification, least privilege, encryption at rest/in transit, no sensitive data in logs
   - **Accountability** — Structured audit logging, immutable trails, entity traceability
   - **Authenticity** — Strong authentication, token integrity, mutual service auth, non-repudiation

4. **SSEM Attribute Assessment — Reliability**:
   - **Availability** — Redundancy, resource limits, rate limiting, timeouts, health checks
   - **Integrity** — Input validation at trust boundaries, output encoding, Derived Integrity Principle, Request Surface Minimization
   - **Resilience** — Defensive coding, predictable execution, strong trust boundaries, fault tolerance, error handling

5. **Transparency Assessment** — Self-documenting code, structured logging, audit trails, instrumentation, trust boundary logging.

6. **Code-Level Threat Identification** — Apply "What can go wrong?" using the Four Question Framework; map solutions to SSEM attributes.

7. **Dependency Securability** — Evaluate dependencies against SSEM attributes (analyzability, modifiability, testability, trustworthiness, reliability).

8. **Produce Findings** — SSEM attribute scorecard (HIGH/MED/LOW per attribute), findings with SSEM category, attribute, FIASSE section reference, and engineering remediation.

## Output

SSEM Attribute Scorecard (9 attributes + Transparency rated HIGH/MED/LOW), findings sorted by severity using `templates/finding.md` adapted for SSEM deficits, positive observations, prioritized recommendations, and severity count table.

## OWASP & FIASSE References

- [FIASSE RFC](https://github.com/Xcaciv/securable_software_engineering/blob/main/docs/FIASSE-RFC.md) — Framework for Integrating Application Security into Software Engineering
- ISO/IEC 25010:2011 — Software quality models (Maintainability, Reliability definitions)
- RFC 4949 — Internet Security Glossary (Trustworthiness, Integrity, Availability definitions)
- OWASP Code Review Guide
- OWASP Proactive Controls
- OWASP Top 10 (2021)
- OWASP ASVS v5.0

```
