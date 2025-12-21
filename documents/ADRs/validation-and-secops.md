# Introducing Claim, Assessor, and Archiving for validation in Verifiable

## Context

The Verifiable library establishes a framework for various socio-economic and technical operations within decentralized, digital signature data architectures. It is designed to enhance trustworthy decision support systems, crucial for transitioning to a regenerative future. Our focus is to integrate traditional validation with artificial intelligence, ensuring valid data usage and trust in automated decision-making.

The integration of AI into the Verifiable library addresses complex data scenarios and decision-making processes. AI's ability to efficiently parse and analyze large datasets, identify patterns, and provide data-driven insights is crucial in decentralized environments characterized by diverse and abundant data. This AI integration aims to automate and improve the accuracy of validation processes, which are essential for establishing the trustworthiness of transactions and decisions.

Artificial intelligence can significantly reduce transaction costs, demystify complex concepts, and facilitate easier collaboration. However, this potential is fully realized only when AI operates on valid data and when there's a verifiable mechanism to trust and, importantly, retrospectively review or appeal automated decisions. This need underscores our library's commitment to recording inputs, outputs, data models, platform details, and versioning—elements critical for post-process evaluation and modification of AI decisions. This means also AI risk management, so the system needs to mitigate risks associated with unintended outcomes, adversarial inputs, and biases, with the goal to build robust and reliable decision-making in decentralized systems or at least allow finding cases when that has not happened.

This decision document centers around structuring the validation, monitoring, and secure operations logic. Our primary objectives are:

1. Facilitate ease of understanding, maintenance, and operation, anticipating the construction of larger, software-intensive systems. Users of Verifiable should have the capability to monitor and refactor its functioning reliably.

2. Accommodate future extensions and evolving sets of claims, such as through refactoring and obsoleting processes.

3. Record claims for checks that either succeed or fail to ensure the execution of checks.

4. Each claim possesses a unique code correlating to a specific code point, enabling "off-Verifiable" utilization. Hence, coding needs to be adaptable to allow others to introduce identifiers.

5. Integrate validation with the runtime environment, distributed tracing, Continuous Integration Environment, version control, monitoring operations, and the secure development lifecycle along with risk and compliance monitoring.

6. Ensure ease of integration with other tools and frameworks when necessary.

7. Facilitate the translation of sector-dependent, regulatory, and other demands into software and enable discussions within the context of Verifiable and its developers.

### Additionally

a. There are plans to introduce remote claim generation and assessments potentially and other system behaviors. This will be subject to a separate ADR and will involve extensive threat modeling.

b. Point `a.` is partially driven by consideration for cross-sector, secure data operations as part of the circular and regenerative economy, and data structures. It appears such dependent data systems are governed in distributed fashion and include socio-economic, system external factors that may influence some operations. There may be need to blend them into operational systems seamlessly.

## Decision

We will introduce a `Claim`, `Assessor`, and `Archiving` model for validation.

- **Claim**: An immutable record containing a unique identifier and a boolean indicating validation result. Since these are immutable records, they can be cached and reused. NOTE: Future refactoring may introduce a chance to capture claim generation context and non-binary result, pursuant to point a. in the previous section.

- **Assessor**: Aggregates multiple Claims to provide an auditable record of a series of validation operations. A function within will interpret the success or failure based on its understanding of the context in which the claims were made. The Assessor has an identifier so it can be tracked.

- **Archiving**: Archiver has an identifier that can be tracked. Its purpose is to archive results by assessors as per user-defined functionality.

## Rationale

1. **Distributed and decentralized systems**: Claim, Assessor, and Archiving model are tailored to operate within distributed and decentralized systems, providing a structured, verifiable, and auditable mechanism to capture, assess, and archive validations and decisions across disparate systems and networks.

2. **Regulatory adherence and contractual obligations**: The immutable and traceable nature of Claims supports adherence to various sector-specific, regulatory, and contractual obligations, ensuring that actions and decisions taken by the system can be audited and verified against predefined legal and contractual frameworks.

3. **Multi-temporal and multi-stakeholder environments**: The model facilitates validations and decision-making processes that span various time scales – from real-time to slower, deliberate processes – and caters to environments where multiple stakeholders (systems, entities, or individuals) with varying obligations and operational cadences are involved.

4. **Demonstrable duty of care**: By capturing and preserving the context and outcome of each validation operation in Claims, the system demonstrates a duty of care, ensuring that actions and decisions are transparent, verifiable, and auditable, fulfilling both immediate and future verification and auditability requirements.

5. **Risk management and trust creation**: The structure facilitates risk management and trust creation in software-intensive data architectures, enabling collaboration and decision support while complying with regulatory frameworks like SSI, eIDAS, and others. This approach supports creating real trust among stakeholders and managing inherent unknowns in dynamic environments.

6. **AI Risk Management**: The Claim and Assessor models are designed to support risk management by recording and contextualizing decisions, enabling the identification and mitigation of unintended outcomes, adversarial influences, and systemic biases in AI-driven processes. This approach aligns with Verifiable's commitment to building trustworthy and reliable decentralized systems.

## Alternatives Considered

- **Single Validation Function**: This approach is hard to maintain and extend due to its monolithic nature which can become complex and hard to manage with growing requirements.

- **Third-Party Libraries**: These do not meet the specific requirements and need for fine-grained control, though they can be utilized by Verifiable users.

## Consequences

1. Maintenance and extensibility will be more straightforward for Verifiable developers also operating it.

2. Security and compliance will be improved for Verifiable developers and allow for domain-bound discussion even between different domains.

3. Initial development may require more time to set up the Claim, Assessor, and Archiving model.

4. *(Potential negative consequences or trade-offs can be listed here)*

## Extension

## Extended Architecture: Remote Assessment, AI Integration, and Regulatory Compliance

## Overview

This document extends the Claim-Assessor-Archiving model to address:

- Remote and AI-based assessors running in parallel
- OpenTelemetry integration for distributed tracing
- Regulatory retrieval and post-facto remediation
- Software provenance and attestation

## Assessment Architecture

### Execution Model

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                              ClaimIssuer                                    │
│                                                                             │
│   Input ──→ [Rule A] ──→ [Rule B] ──→ [Rule C] ──→ ClaimIssueResult         │
│                                                                             │
│   Properties:                                                               │
│   - Sequential execution (rules may have dependencies).                     │
│   - Partial results on cancellation.                                        │
│   - Exception handling per rule (FailedClaim).                              │
│   - TimeProvider injection for deterministic timestamps.                    │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CompositeClaimAssessor                              │
│                                                                             │
│   ClaimIssueResult ──┬──→ [Local Rules Assessor]     ──→ Result A           │
│                      │         (fast, in-memory)              │             │
│                      │                                        │             │
│                      ├──→ [ML Model Assessor]        ──→ Result B ──┐       │
│                      │         (local inference)              │      │      │
│                      │                                        │      │      │
│                      ├──→ [Remote AI Service]        ──→ Result C    │      │
│                      │         (LLM, specialized AI)          │      ▼      │
│                      │                                        │   Aggregate │
│                      └──→ [Compliance Service]       ──→ Result D ──┘       │
│                               (external validation)           │             │
│                                                               ▼             │
│                                               AggregatedAssessmentResult    │
│                                                                             │
│   Properties:                                                               │
│   - Parallel execution (Task.WhenAll).                                      │
│   - Individual timeout per assessor.                                        │
│   - Partial results when some assessors fail/timeout.                       │
│   - Aggregation strategies: All, Any, Majority, Quorum.                     │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           AssessmentArchiver                                │
│                                                                             │
│   AssessmentResult(s) ──→ Archive Storage                                   │
│                                                                             │
│   Captured:                                                                 │
│   - Full ClaimIssueResult with all claims.                                  │
│   - Individual assessment results.                                          │
│   - Timestamps (from TimeProvider).                                         │
│   - OpenTelemetry correlation (TraceId, SpanId, Baggage).                   │
│   - Provenance context (commit SHA, Docker SHA, SPIFFE ID).                 │
│   - Aggregation metadata (strategy, quorum, completion status).             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Assessor Types

| Type | Latency | Cancellation | Use Case |
| ---- | ------- | ------------ | -------- |
| Local Rules | ~1ms | Ignore | Schema validation, format checks |
| Local ML Model | 10-100ms | Check periodically | Fraud detection, classification |
| Remote AI Service | 100ms-10s | Pass to HTTP client | LLM analysis, complex reasoning |
| Compliance Service | 100ms-5s | Pass to HTTP client | Regulatory validation, sanctions |

### Aggregation Strategies

```csharp
enum AssessmentAggregationStrategy
{
    // All assessors must succeed. High assurance.
    AllMustSucceed,
    
    // At least one must succeed. Redundant assessors.
    AnyMustSucceed,
    
    // More than half must succeed. Voting/consensus.
    MajorityMustSucceed,
    
    // Minimum N must complete and all completed must succeed.
    // Tolerates unavailable assessors.
    QuorumMustSucceed
}
```

## OpenTelemetry Integration

### Trace Structure

```text
Trace: abc123... (W3C Trace Context)
│
├── Span: CredentialIssuanceRequest
│   │   service.name: vc-issuer
│   │   correlation.id: user-request-xyz
│   │
│   ├── Span: ClaimIssuer.GenerateClaimsAsync
│   │   │   issuer.id: default-key-did-issuer
│   │   │   rules.total: 6
│   │   │   rules.executed: 6
│   │   │   completion.status: Complete
│   │   │
│   │   ├── Span: ValidateIdEncoding
│   │   │       claim.id: KeyDidIdEncoding
│   │   │       claim.outcome: Success
│   │   │
│   │   ├── Span: ValidateKeyFormat
│   │   │       claim.id: KeyDidKeyFormat
│   │   │       claim.outcome: Success
│   │   │       subclaims.count: 4
│   │   └── ...
│   │
│   ├── Span: CompositeAssessor.AssessAsync
│   │   │   assessors.total: 4
│   │   │   assessors.completed: 3
│   │   │   assessors.faulted: 1
│   │   │   aggregation.strategy: QuorumMustSucceed
│   │   │   overall.success: true
│   │   │
│   │   ├── Span: LocalRulesAssessor
│   │   │       assessor.id: local-rules-v1
│   │   │       duration.ms: 2
│   │   │       success: true
│   │   │
│   │   ├── Span: FraudMLAssessor
│   │   │       assessor.id: fraud-ml-v2.1
│   │   │       model.version: fraud-detector-2.1.0
│   │   │       duration.ms: 45
│   │   │       success: true
│   │   │       confidence: 0.98
│   │   │
│   │   ├── Span: ComplianceService
│   │   │       assessor.id: compliance-api
│   │   │       duration.ms: 230
│   │   │       success: true
│   │   │       regulations.checked: [eIDAS, GDPR]
│   │   │
│   │   └── Span: RemoteAIAssessor
│   │           assessor.id: llm-analyzer
│   │           completion.status: Faulted
│   │           error: "Service unavailable"
│   │           duration.ms: 5002
│   │
│   └── Span: AssessmentArchiver.ArchiveAsync
│           archiver.id: regulatory-archiver
│           archive.id: arch-789
│           storage.backend: postgresql
│
Baggage:
  - correlation.id: user-request-xyz
  - docker.sha: sha256:abc123...
  - commit.sha: def456...
  - spiffe.id: spiffe://example.com/vc-issuer
  - model.versions: fraud-2.1,compliance-1.0
```

### Baggage Propagation

Baggage flows through the entire pipeline, enabling correlation:

```csharp
Activity.Current?.AddBaggage("docker.sha", Environment.GetEnvironmentVariable("IMAGE_SHA"));
Activity.Current?.AddBaggage("commit.sha", Environment.GetEnvironmentVariable("GIT_SHA"));
Activity.Current?.AddBaggage("spiffe.id", GetSpiffeId());
Activity.Current?.AddBaggage("model.versions", string.Join(",", GetLoadedModelVersions()));
```

## Regulatory Retrieval

### Query Patterns

The archive supports retrieval by multiple dimensions:

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                          Archive Query Interface                            │
│                                                                             │
│   By Identity:                                                              │
│   ├── GetByCorrelationId("did:web:example.com:user:alice")                  │
│   ├── GetBySubjectDid("did:key:z6Mk...")                                    │
│   └── GetByIssuerDid("did:web:issuer.example.com")                          │
│                                                                             │
│   By Time:                                                                  │
│   ├── GetByDateRange(2024-Q3-start, 2024-Q3-end)                            │
│   └── GetByTimestamp(exact-moment)                                          │
│                                                                             │
│   By Trace:                                                                 │
│   ├── GetByTraceId("abc123...")      → Full distributed trace               │
│   └── GetBySpanId("def456...")       → Specific operation                   │
│                                                                             │
│   By Provenance:                                                            │
│   ├── GetByCommitSha("abc123...")    → Code version                         │
│   ├── GetByDockerSha("sha256:...")   → Container image                      │
│   ├── GetBySpiffeId("spiffe://...")  → Workload identity                    │
│   └── GetByModelVersion("v2.1")      → ML model version                     │
│                                                                             │
│   By Outcome:                                                               │
│   ├── GetFailedAssessments()         → Remediation candidates               │
│   ├── GetByAssessorId("fraud-ml")    → Specific assessor results            │
│   └── GetIncompleteAssessments()     → Partial/cancelled results            │
│                                                                             │
│   By Regulation:                                                            │
│   ├── GetByRegulatoryFramework("eIDAS")                                     │
│   └── GetByComplianceStatus(failed)                                         │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Remediation Workflow

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Remediation Scenario                              │
│                                                                             │
│   1. Discovery: Model version fraud-ml-v2.0 has bias issue                 │
│                                                                             │
│   2. Query: GetByModelVersion("fraud-ml-v2.0")                             │
│             GetByDateRange(deployment-start, discovery-date)                │
│                                                                             │
│   3. Analysis: For each affected assessment:                                │
│      ├── Retrieve full ClaimIssueResult (original claims)                  │
│      ├── Retrieve AssessmentResult (decision made)                         │
│      ├── Retrieve trace (full context)                                     │
│      └── Retrieve baggage (deployment context)                             │
│                                                                             │
│   4. Re-assess: With corrected model (fraud-ml-v2.1)                       │
│      ├── Load original ClaimIssueResult                                    │
│      ├── Run new assessment                                                │
│      ├── Compare results                                                   │
│      └── Archive remediation assessment                                    │
│                                                                             │
│   5. Notification: Identify affected parties                               │
│      ├── Query by SubjectDid                                               │
│      ├── Generate remediation report                                       │
│      └── Link to original and remediated assessments                       │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Provenance Context

### What the Library Provides

The library provides only the **mechanism** for provenance flow:

```csharp
//On ClaimIssueResult, AssessmentResult, ArchivingResult:
IReadOnlyDictionary<string, string>? Baggage { get; }

//TracingUtilities captures from Activity.Current:
string? TraceId;
string? SpanId;
IReadOnlyDictionary<string, string>? Baggage;
```

The library does **not** define what keys go in baggage. Users define their own provenance structure based on their infrastructure.

### Why Archive Trace Info Separately

OTel backends (Jaeger, Tempo) may:

- Have retention limits (e.g., 30 days)
- Experience data loss
- Be unavailable during audits

Archiving `TraceId`, `SpanId`, and `Baggage` directly in assessment results provides:

- Durable provenance that survives OTel backend issues
- Self-contained audit trail
- Correlation key to reconstruct full trace if OTel data exists

### Example Usage Pattern (User Code)

This is example code showing one way to capture provenance - not part of the library:

```csharp
//At startup - capture from assembly and environment.
var buildInfo = new Dictionary<string, string>
{
    ["app.version"] = Assembly.GetEntryAssembly()?.GetName().Version?.ToString() ?? "unknown",
    ["git.sha"] = Environment.GetEnvironmentVariable("GIT_SHA") ?? "unknown",
    ["image.digest"] = Environment.GetEnvironmentVariable("IMAGE_SHA") ?? "unknown"
};

//Per-request middleware - attach to Activity.
app.Use(async (context, next) =>
{
    foreach (var (key, value) in buildInfo)
    {
        Activity.Current?.AddBaggage(key, value);
    }
    
    //Model info if using AI.
    Activity.Current?.AddBaggage("model.version", fraudModel.Version);
    
    await next();
});

//Baggage automatically flows through:
//- ClaimIssuer -> ClaimIssueResult.Baggage.
//- ClaimAssessor -> AssessmentResult.Baggage.
//- AssessmentArchiver -> ArchivingResult.Baggage.
```

### CI/CD Environment Variables

| Variable | Source | Example |
| -------- | ------ | ------- |
| `GIT_SHA` | GitHub Actions: `${{ github.sha }}` | `abc123def456...` |
| `IMAGE_SHA` | Docker build output | `sha256:e3b0c44...` |
| `BUILD_ID` | GitHub Actions: `${{ github.run_id }}` | `12345678` |
| `BUILD_TIMESTAMP` | Pipeline generated | `2024-06-01T12:00:00Z` |
| `SPIFFE_ID` | SPIRE agent | `spiffe://example.com/...` |

### Baggage Key Conventions

Provenance flows through `Activity.Baggage` as key-value pairs. Use these conventions:

| Category | Key | Example Value |
| -------- | --- | ------------- |
| **Source Control** | `git.sha` | `abc123def456...` |
| | `git.branch` | `main` |
| | `git.repository` | `github.com/org/repo` |
| **Container** | `image.digest` | `sha256:e3b0c44...` |
| | `k8s.namespace` | `production` |
| | `k8s.pod` | `vc-assessor-abc123` |
| **Identity** | `spiffe.id` | `spiffe://example.com/ns/prod/sa/assessor` |
| | `oidc.issuer` | `https://accounts.google.com` |
| **Build** | `build.id` | `12345678` |
| | `build.timestamp` | `2024-06-01T12:00:00Z` |
| **ML Models** | `model.id` | `fraud-detector` |
| | `model.version` | `v2.1.0` |
| | `model.checksum` | `sha256:model123...` |
| **Environment** | `deployment.environment` | `production` |
| | `cloud.region` | `us-east-1` |

Query archived assessments by any baggage key:

```csharp
//All assessments from a specific commit.
var affected = archive.GetByBaggageKey("git.sha", "abc123def456");

//All assessments using a specific model version.
var modelV2 = archive.GetByBaggageKey("model.version", "v2.0");

//All assessments from production.
var prod = archive.GetByBaggageKey("deployment.environment", "production");
```

### Integration with Sigstore/SPIFFE

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                     Complete Provenance Flow                                │
│                                                                             │
│   BUILD TIME (CI/CD Pipeline)                                               │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  1. Source: git commit abc123                                       │   │
│   │  2. Build: dotnet publish → assembly with version metadata          │   │
│   │  3. Sign: sigstore/cosign sign → signature + certificate            │   │
│   │  4. Attest: SLSA provenance attestation                             │   │
│   │  5. Push: container registry with signature                         │   │
│   │  6. Export: GIT_SHA, IMAGE_SHA, BUILD_ID as env vars                │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                    ↓                                        │
│   RUNTIME (Application Startup)                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  var appVersion = Assembly.GetEntryAssembly().GetName().Version;    │   │
│   │  var gitSha = Environment.GetEnvironmentVariable("GIT_SHA");        │   │
│   │  var imageDigest = Environment.GetEnvironmentVariable("IMAGE_SHA"); │   │
│   │  var spiffeId = Environment.GetEnvironmentVariable("SPIFFE_ID");    │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                    ↓                                        │
│   REQUEST TIME (Per-Request Middleware)                                     │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  using var activity = activitySource.StartActivity("Assessment");   │   │
│   │                                                                     │   │
│   │  Activity.Current?.AddBaggage("app.version", appVersion);           │   │
│   │  Activity.Current?.AddBaggage("git.sha", gitSha);                   │   │
│   │  Activity.Current?.AddBaggage("image.digest", imageDigest);         │   │
│   │  Activity.Current?.AddBaggage("model.version", model.Version);      │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                    ↓                                        │
│   ASSESSMENT TIME                                                           │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  var result = await assessor.AssessAsync(input, correlationId);     │   │
│   │                                                                     │   │
│   │  // result.Baggage inherited from Activity.Current                  │   │
│   │  // AI assessor adds: model inference time, confidence score        │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                    ↓                                        │
│   ARCHIVE TIME                                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  await archiver.ArchiveAsync(result);                               │   │
│   │                                                                     │   │
│   │  // Archived with full provenance:                                  │   │
│   │  //   - Build info (version, commit, image)                         │   │
│   │  //   - Runtime identity (SPIFFE ID)                                │   │
│   │  //   - Model info (version, checksum, training date)               │   │
│   │  //   - Trace correlation (TraceId, SpanId)                         │   │
│   │  //   - Assessment result + all claims                              │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                    ↓                                        │
│   AUDIT TIME (Days/Months/Years Later)                                      │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  // Query: "Find all assessments using model v2.0"                  │   │
│   │  var affected = archive.GetByModelVersion("v2.0");                  │   │
│   │                                                                     │   │
│   │  // For each affected assessment:                                   │   │
│   │  //   - Verify sigstore signature still valid                       │   │
│   │  //   - Lookup trace in OTel backend (Jaeger/Tempo)                 │   │
│   │  //   - Retrieve original claims for re-assessment                  │   │
│   │  //   - Generate remediation report                                 │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Attestation Chain                                    │
│                                                                             │
│   Build Time:                                                               │
│   ├── Source: GitHub commit abc123                                          │
│   ├── Build: GitHub Actions workflow #456                                   │
│   ├── Sign: Sigstore Fulcio (keyless signing)                               │
│   ├── Attest: SLSA provenance                                               │
│   └── Push: Container registry with cosign signature                        │
│                                                                             │
│   Runtime:                                                                  │
│   ├── Identity: SPIFFE SVID from SPIRE                                      │
│   │             spiffe://example.com/ns/prod/sa/vc-assessor                 │
│   ├── Verify: Sigstore bundle validates container                           │
│   └── Record: All IDs flow to archive via baggage                           │
│                                                                             │
│   Audit Time:                                                               │
│   ├── Query: Archive by SPIFFE ID or Docker SHA                             │
│   ├── Verify: Sigstore bundle still valid                                   │
│   ├── Trace: OTel backend shows full request flow                           │
│   └── Prove: Cryptographic chain from code to decision                      │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Time Handling

All components use injected `TimeProvider`:

```csharp
//Production.
var issuer = new ClaimIssuer<T>(id, rules, TimeProvider.System);

//Testing.
var fakeTime = new FakeTimeProvider(new DateTimeOffset(2024, 6, 15, 12, 0, 0, TimeSpan.Zero));
var issuer = new ClaimIssuer<T>(id, rules, fakeTime);

//Advancing time in tests.
fakeTime.Advance(TimeSpan.FromDays(30));
```

The library never calls `DateTime.UtcNow` directly. This enables:

- Deterministic testing.
- Time travel in tests.
- Consistent timestamps across distributed components.

## Cancellation Semantics

| Component | Cancellation Behavior |
| --------- | -------------------- |
| ClaimIssuer | Returns partial ClaimIssueResult |
| Simple Assessor | Ignores (fast operation) |
| AI Assessor | Propagates to HTTP client |
| CompositeAssessor | Collects completed results |
| Archiver | Propagates to storage backend |

Partial results are **never discarded**. The system preserves work completed before cancellation.

## Security Considerations

1. **Archive Immutability**: Once archived, assessments should not be modified. Use append-only storage or blockchain anchoring for high-assurance scenarios.

2. **Baggage Sanitization**: Baggage can contain sensitive data. Implement filtering before archiving.

3. **Access Control**: Archive queries should be authorized based on regulatory role and data classification.

4. **Retention**: Implement retention policies per regulatory framework (e.g., 7 years for financial, per GDPR for personal data).

## Status

Accepted.

## References

- [Explainable Artificial Intelligence (XAI) 2.0: A Manifesto of Open Challenges and Interdisciplinary Research Directions](https://arxiv.org/abs/2310.19775).
- [OpenTelemetry Specification](https://opentelemetry.io/docs/specs/)
- [W3C Trace Context](https://www.w3.org/TR/trace-context/)
- [SPIFFE/SPIRE](https://spiffe.io/)
- [Sigstore](https://www.sigstore.dev/)
- [SLSA Framework](https://slsa.dev/)

## Revision History

None.
