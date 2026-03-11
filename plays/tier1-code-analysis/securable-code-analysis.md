# Play: Securable Code Analysis (FIASSE/SSEM)

Analyze code and architecture for inherent securable qualities using the Framework for Integrating Application Security into Software Engineering (FIASSE) and the Securable Software Engineering Model (SSEM). Unlike vulnerability-centric reviews that ask "Is it secure?", this play evaluates whether code possesses the fundamental engineering attributes that make software **securable** — able to adapt to and withstand evolving threats over time.

This play operationalizes the nine core SSEM attributes across three categories: **Maintainability** (Analyzability, Modifiability, Testability), **Trustworthiness** (Confidentiality, Accountability, Authenticity), and **Reliability** (Availability, Integrity, Resilience). Findings are framed as engineering improvement opportunities rather than exploit-centric vulnerabilities.

> **Reference**: [FIASSE RFC — A Framework for Integrating Application Security into Software Engineering](https://github.com/Xcaciv/securable_software_engineering/blob/main/docs/FIASSE-RFC.md) by Alton Crossley

## Trigger Conditions

Use this play when:
- Performing a proactive security posture assessment of a codebase (beyond vulnerability scanning)
- Evaluating code quality attributes that directly impact security outcomes
- Assessing whether code is engineered to be securable over its lifecycle
- Reviewing merge requests through a securable engineering lens
- Establishing a baseline of securable attributes for a project
- Guiding AI-generated code toward securable design patterns
- A user asks to assess code securability, code quality for security, or FIASSE/SSEM compliance

## Inputs

- Code files, modules, or full codebase to analyze
- (Optional) Architecture documentation or data flow diagrams
- (Optional) Target SSEM attribute focus areas
- (Optional) Prior static analysis or code quality reports
- (Optional) Dependency manifests

## Foundational Principles

Before analysis, internalize these FIASSE principles:

1. **The Securable Paradigm** — There is no static "secure" state. Software must be built with inherent qualities that enable it to adapt to evolving threats (FIASSE §2.1).
2. **Resiliently Add Computing Value** — The primary directive is to create valuable code robust enough to withstand change, stress, and attack (FIASSE §2.2).
3. **Reducing Material Impact** — The goal is to reduce the probability of material impact from cyber events, not to achieve perfect security (FIASSE §2.3).
4. **Engineer vs. Hacker Mindset** — Focus on engineering solutions, not exploit reproduction. Building securely is distinct from knowing how to compromise (FIASSE §2.4).
5. **Transparency** — A system's internal state and behavior should be observable and understandable to authorized parties (FIASSE §2.6).

## Procedure

### 1. Scope & Context

Establish the analysis context:
- **Language/Framework**: Determines which quality tools and metrics are applicable
- **System type**: Web app, API, library, CLI, agent, microservice
- **Data sensitivity**: PII, credentials, financial, health, or other regulated data
- **Exposure**: Internet-facing, internal, local-only
- **Lifecycle stage**: New development, mature codebase, legacy system under maintenance
- **Team context**: Team size, experience levels, development velocity

### 2. SSEM Attribute Assessment — Maintainability

Maintainability is the "degree of effectiveness and efficiency with which a product or system can be modified by the intended maintainers" (ISO/IEC 25010:2011). In SSEM, this directly supports the ability to respond to evolving security needs.

#### 2.1 Analyzability

> *"The ability to find the cause of a behavior within the code. Code must be understandable to find and fix vulnerabilities."* — FIASSE §3.2.1.1

| Factor | What to Measure | Target |
|--------|----------------|--------|
| Volume (LoC) | Overall codebase size; larger = harder to analyze | Track per module |
| Duplication | Percentage of duplicated code (via SAST tools) | < 5% |
| Unit Size | Lines of code per method/class/block | Methods < 30 LoC |
| Unit Complexity | Cyclomatic complexity per unit | < 10 per method |
| Component Balance | Distribution and size uniformity of top-level components | No single component > 30% of total |
| Comment Density | Ratio of meaningful comments to code | Present at trust boundaries and complex logic |
| Time to Understand | Can an unfamiliar developer understand a module's purpose quickly? | Qualitative assessment |

**Checklist:**
- [ ] Methods and functions are small, single-purpose, and clearly named
- [ ] Complex logic is commented explaining *why*, not just *what*
- [ ] Naming conventions are consistent and descriptive
- [ ] Code structure follows established patterns for the language/framework
- [ ] No dead code or commented-out blocks
- [ ] Trust boundaries are clearly identifiable in the code structure

#### 2.2 Modifiability

> *"The ability to modify code without breaking existing functionality or introducing new vulnerabilities."* — FIASSE §3.2.1.2

| Factor | What to Measure | Target |
|--------|----------------|--------|
| Duplication | Duplicated code increases risk of inconsistent changes | < 5% |
| Unit Complexity | Complex units are harder to modify safely | < 10 cyclomatic complexity |
| Module Coupling | Incoming dependencies for modules (afferent coupling) | Low; no God objects |
| Change Impact Size | Files/modules typically affected by a common change | Minimal cascade |
| Regression Rate | Percentage of changes that introduce new defects | Track over time |

**Checklist:**
- [ ] Modules are loosely coupled with clear interfaces
- [ ] Changes can be made in one area without cascading to unrelated areas
- [ ] Security-sensitive code (auth, crypto, input handling) is centralized, not scattered
- [ ] Configuration is externalized — not hardcoded in business logic
- [ ] Dependency injection or similar patterns allow component replacement
- [ ] Trust boundary handling is modular and reusable

#### 2.3 Testability

> *"The ability to write a test for a piece of code without needing to change the code under test."* — FIASSE §3.2.1.3

| Factor | What to Measure | Target |
|--------|----------------|--------|
| Code Coverage | Percentage covered by automated tests | > 80% for security-critical paths |
| Unit Test Density | Tests per KLoC or per class/module | Present for all public interfaces |
| Mocking Complexity | Setup required to isolate units for testing | Minimal; clean dependency boundaries |
| Component Independence | Code in modules with no cross-component dependencies | High independence ratio |
| Unit Coupling | Incoming dependencies that complicate isolated testing | Low |

**Checklist:**
- [ ] Security controls (auth, authz, input validation, crypto) have dedicated test suites
- [ ] Edge cases and boundary conditions are tested, including malicious inputs
- [ ] Tests can run without external dependencies (via mocking/stubbing)
- [ ] Test execution is fast enough to run on every commit
- [ ] Integration tests cover trust boundary crossings
- [ ] Negative test cases exist (what should be *rejected*)

### 3. SSEM Attribute Assessment — Trustworthiness

Trustworthiness is "the degree to which a system can be expected to achieve a set of requirements, such as security requirements" (RFC 4949). FIASSE focuses on inherent code qualities that enable trustworthiness, not overlaid controls.

#### 3.1 Confidentiality

> *"The property that data is not disclosed to system entities unless they have been authorized to know the data."* — RFC 4949

**Checklist:**
- [ ] Sensitive data types are identified and classified in the codebase
- [ ] Data access follows the principle of least privilege
- [ ] Encryption at rest is used for sensitive data storage
- [ ] Encryption in transit is enforced (TLS)
- [ ] Sensitive data is not logged or exposed in error messages
- [ ] API responses do not include unnecessary fields
- [ ] Memory handling avoids retaining sensitive data longer than needed
- [ ] Configuration separates secrets from application code

#### 3.2 Accountability

> *"The property that actions of a system entity may be traced uniquely to that entity."* — RFC 4949

**Checklist:**
- [ ] Security-sensitive actions are logged with structured data (who, what, where, when)
- [ ] Audit trails are immutable or append-only
- [ ] Authentication events (login, logout, failure) are recorded
- [ ] Authorization decisions (grant, deny) are logged
- [ ] Data modification events capture the acting entity
- [ ] Log entries include sufficient context for incident investigation
- [ ] Logging does not include sensitive data (passwords, tokens, PII)
- [ ] Permission changes create detailed audit records

#### 3.3 Authenticity

> *"The property that an entity is what it claims to be."* — ISO/IEC 27000:2018

**Checklist:**
- [ ] Authentication mechanisms use established, strong methods (MFA where appropriate)
- [ ] Token/session integrity is verified (signed JWTs, secure cookies)
- [ ] API calls between services are mutually authenticated
- [ ] Data origin is verifiable (digital signatures, checksums)
- [ ] Non-repudiation is supported — actions are irrefutably linked to entities
- [ ] Authentication and authorization events are transparently logged

### 4. SSEM Attribute Assessment — Reliability

Reliability is the "degree to which a system performs specified functions under specified conditions for a specified period of time" (ISO/IEC 25010:2011). In SSEM, this means consistent and predictable operation even under adverse conditions.

#### 4.1 Availability

> *"The property of being accessible and usable upon demand by an authorized system entity."* — RFC 4949

**Checklist:**
- [ ] Critical paths have redundancy or failover capabilities
- [ ] Resource limits are enforced (memory, CPU, connections, file handles)
- [ ] Rate limiting protects against resource exhaustion
- [ ] Timeouts are configured for all external calls
- [ ] Health check endpoints exist for monitoring
- [ ] Graceful degradation is implemented for non-critical feature failures

#### 4.2 Integrity

> *"The property that data has not been changed, destroyed, or lost in an unauthorized or accidental manner."* — RFC 4949

**Checklist:**
- [ ] Input validation is performed at trust boundaries (canonicalization, sanitization, validation)
- [ ] Output encoding prevents injection when crossing trust boundaries
- [ ] Cryptographic hashing or checksums protect critical data
- [ ] Database operations use parameterized queries exclusively
- [ ] File operations validate paths and prevent traversal
- [ ] State transitions follow a defined state machine — not client-dictated
- [ ] The **Derived Integrity Principle** is followed: values critical to system state are calculated server-side, never accepted from clients (FIASSE §6.4.1.1)
- [ ] The **Request Surface Minimization Principle** is applied: only specific expected values are extracted from requests (FIASSE §6.4.1.1)

#### 4.3 Resilience

> *"The ability to continue to operate during and after a failure and recover from the failure."* — RFC 4949

**Checklist:**
- [ ] Defensive coding: code anticipates out-of-bounds input and handles it gracefully
- [ ] Predictable execution: code behaves consistently under various conditions
- [ ] Strong trust boundaries: areas of strictly controlled execution are clearly defined
- [ ] Comprehensive error handling prevents crashes from unexpected conditions
- [ ] Null values are sandboxed to input checks and database communication
- [ ] Immutable data structures used in concurrent/threaded code
- [ ] Fault tolerance: partial system failures do not cause complete breakdown
- [ ] Recovery mechanisms handle and restore from failure states

### 5. Transparency Assessment

> *"A foundational engineering strategy that underpins several core SSEM attributes, enabling trust and simplifying analysis."* — FIASSE §2.6

Transparency is a cross-cutting concern that enables all other SSEM attributes.

**Checklist:**
- [ ] Code is self-documenting with meaningful naming and finite data types
- [ ] Structured logging is used (machine-parsable, rich context)
- [ ] Security-sensitive events have detailed, immutable audit trails (who, what, where, when, why)
- [ ] Health and performance metrics are exposed via instrumentation
- [ ] Trust boundary crossings are logged with validation outcomes
- [ ] Version control is used effectively (meaningful commits, clear history)
- [ ] Debug logging is available (optional) for deeper analysis without impacting production

### 6. Code-Level Threat Identification (FIASSE §6.2.1)

Apply the "What can go wrong?" question at the code level:

- **For merge reviews**: Scope threat identification to the changeset — clear context and responsibility
- **For static analysis results**: Use findings as starting points to think deeper using the Four Question Framework:
  1. What are we building?
  2. What can go wrong?
  3. What are we going to do about it?
  4. Did we do a good job?
- **Map solutions to SSEM attributes**: When addressing threats, consider which SSEM attributes (especially Trustworthiness and Reliability) lead to holistic architectural solutions rather than line-level patches
- **Feed back to threat model**: Code-level threats should inform design-level threat models

### 7. Dependency Securability (FIASSE §6.5)

Apply SSEM principles to dependency management:

| SSEM Attribute | Dependency Evaluation |
|---------------|----------------------|
| Analyzability | Understand full scope including transitive dependencies; maintain clear inventory with rationale |
| Modifiability | Design loosely coupled integration; facilitate easier updates, patching, or replacement |
| Testability | Ensure dependencies can be mocked/stubbed; integration points are robustly testable |
| Trustworthiness | Verify source and integrity (signed packages, checksums, trusted repositories) |
| Reliability | Assess failure modes and impact on overall system resilience |

**Checklist:**
- [ ] Each dependency has a documented rationale for inclusion
- [ ] Dependencies are pinned to specific versions with lockfiles (where applicable)
- [ ] Transitive dependencies are known and inventoried
- [ ] Unnecessary dependencies are removed
- [ ] Regular dependency maintenance is scheduled (not just CVE-reactive)
- [ ] Dependencies are evaluated against SSEM cultural values before adoption

### 8. Produce Findings

For each identified gap in SSEM attributes:

```markdown
### [SEVERITY] Title — SSEM Attribute Deficit

- **SSEM Category**: Maintainability | Trustworthiness | Reliability
- **SSEM Attribute**: Analyzability | Modifiability | Testability | Confidentiality | Accountability | Authenticity | Availability | Integrity | Resilience
- **FIASSE Section**: §X.X.X
- **CWE** (if applicable): CWE-XXX
- **Location**: file_path:line_number
- **Current State**: Description of the current code quality/state
- **Impact**: How this deficit affects the system's ability to remain securable over time
- **Evidence**: Code snippet, metric, or observation demonstrating the gap
- **Remediation**: Specific engineering improvement with code example
- **Measurement**: How to verify the improvement (quantitative metric or qualitative check)
```

**Severity mapping for SSEM deficits:**

| Severity | Criteria |
|----------|---------|
| CRITICAL | Attribute deficit directly enables exploitation or prevents incident response |
| HIGH | Attribute deficit significantly increases probability of material impact |
| MEDIUM | Attribute deficit degrades securability but does not directly enable attack |
| LOW | Attribute deficit is a code quality concern with indirect security implications |
| INFORMATIONAL | Positive observation or minor improvement opportunity |

## Output Format

```markdown
## Securable Code Analysis: [Target]

### Scope
- **Files analyzed**: [count or list]
- **Language/Framework**: [detected]
- **Analysis type**: Full codebase | Merge review | Module-targeted
- **SSEM focus**: All attributes | [specific focus areas]

### SSEM Attribute Scorecard

| Category | Attribute | Rating | Key Observation |
|----------|-----------|--------|----------------|
| Maintainability | Analyzability | HIGH/MED/LOW | [one-line summary] |
| Maintainability | Modifiability | HIGH/MED/LOW | [one-line summary] |
| Maintainability | Testability | HIGH/MED/LOW | [one-line summary] |
| Trustworthiness | Confidentiality | HIGH/MED/LOW | [one-line summary] |
| Trustworthiness | Accountability | HIGH/MED/LOW | [one-line summary] |
| Trustworthiness | Authenticity | HIGH/MED/LOW | [one-line summary] |
| Reliability | Availability | HIGH/MED/LOW | [one-line summary] |
| Reliability | Integrity | HIGH/MED/LOW | [one-line summary] |
| Reliability | Resilience | HIGH/MED/LOW | [one-line summary] |
| Cross-cutting | Transparency | HIGH/MED/LOW | [one-line summary] |

### Findings
[Findings sorted by severity using the SSEM finding template above]

### Positive Observations
[SSEM attributes that ARE well-implemented — acknowledge good engineering practices]

### Recommendations Priority
1. [Highest-impact improvement mapped to SSEM attribute]
2. [Next priority]
3. [...]

### Summary
| Severity | Count |
|----------|-------|
| CRITICAL | N |
| HIGH | N |
| MEDIUM | N |
| LOW | N |
| INFO | N |
```

## References

- [FIASSE RFC — Framework for Integrating Application Security into Software Engineering](https://github.com/Xcaciv/securable_software_engineering/blob/main/docs/FIASSE-RFC.md) — Alton Crossley
- ISO/IEC 25010:2011 — Systems and software quality models
- RFC 4949 — Internet Security Glossary
- ISO/IEC 27000:2018 — Information security management systems
- [OWASP Code Review Guide](https://owasp.org/www-project-code-review-guide/)
- [OWASP Proactive Controls](https://owasp.org/www-project-proactive-controls/)
- [OWASP Top 10 (2021)](https://owasp.org/www-project-top-ten/) — A01–A10
- [OWASP ASVS v5.0](https://owasp.org/www-project-application-security-verification-standard/)
- [OpenCRE](https://www.opencre.org) — Cross-standard requirement mappings
- [CWE](https://cwe.mitre.org) v4.19 — Common Weakness Enumeration
- Howard, R., "Cyber Security First Principles: A Reboot of Strategy and Tactics", 2019
- ASVS 5.0 reference data in `data/asvs/` — sourced from [OWASP Agent Skills Project](https://github.com/eoftedal/owasp-agent-skills-project)
- AISVS reference data in `data/aisvs/`
