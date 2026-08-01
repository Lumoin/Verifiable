using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The outcome of composing the REQ-4.2-03 validation constraints of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11917204/01.02.01_60/ts_11917204v010201p.pdf">
/// ETSI TS 119 172-4 V1.2.1</see>: the constraints themselves, and the ETSI TS 119 615 clause 4.3 service
/// match they were derived from, which REQ-4.4.2-02 b) iii) requires reflecting in the applicability rules
/// checking report as an intermediate process result.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> The trust anchors inside <see cref="Constraints"/> and the matched services
/// inside <see cref="TrustAnchorServiceMatch"/> reference certificate memory owned by the
/// <see cref="TrustedList"/> the constraints were composed from; neither may outlive that list.
/// </remarks>
[DebuggerDisplay("SignatureApplicabilityConstraintsResult: {Constraints.Identifier.Value}, {Constraints.X509.TrustAnchors.Count} anchors")]
public sealed record SignatureApplicabilityConstraintsResult
{
    /// <summary>The composed validation constraints, ready as the REQ-4.2-01 validation process input.</summary>
    public required SignatureValidationConstraints Constraints { get; init; }

    /// <summary>The clause 4.3 outputs the trust anchors were read from (REQ-4.2-03 a)).</summary>
    public required ListedServicesMatchResult TrustAnchorServiceMatch { get; init; }
}


/// <summary>
/// The outcome of the technical applicability (rules) checking (TARC) process of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11917204/01.02.01_60/ts_11917204v010201p.pdf">
/// ETSI TS 119 172-4 V1.2.1 clause 4.4.2</see>: the intermediate ETSI TS 119 615 determinations and the
/// REQ-4.4.2-06 suitability determination.
/// </summary>
/// <remarks>
/// REQ-4.4.2-02 and REQ-4.4.2-05 word their conditions "respectively" for electronic signatures and
/// electronic seals, so the suitability determination is carried per dimension rather than collapsed: a
/// certificate the trusted list qualifies for both purposes keeps both determinations. The tri-state main
/// output of clause 4.4.1 reads off the two members — suitable as an EU qualified electronic signature,
/// suitable as an EU qualified electronic seal, or (both <see langword="false"/>) determined technically as
/// neither.
/// </remarks>
[DebuggerDisplay("TechnicalApplicabilityCheckResult: signature {SuitableAsQualifiedElectronicSignature}, seal {SuitableAsQualifiedElectronicSeal}")]
public sealed record TechnicalApplicabilityCheckResult
{
    /// <summary>The REQ-4.4.2-01 certificate determination (ETSI TS 119 615 clause 4.4), always performed.</summary>
    public required EuQualifiedCertificateDeterminationResult CertificateDetermination { get; init; }

    /// <summary>
    /// The REQ-4.4.2-04 device determination (ETSI TS 119 615 clause 4.5); <see langword="null"/> when
    /// REQ-4.4.2-02 b) i) stopped the process before it ran.
    /// </summary>
    public required QualifiedSignatureCreationDeviceDeterminationResult? DeviceDetermination { get; init; }

    /// <summary>The main status indication of the REQ-4.2-01 validation process this check consumed (REQ-4.4.2-06 c)).</summary>
    public required SignatureValidationIndication ValidationIndication { get; init; }

    /// <summary>The best signature time the determinations were evaluated at (<c>Date-time</c> of REQ-4.4.2-01 and REQ-4.4.2-04).</summary>
    public required DateTimeOffset BestSignatureTime { get; init; }

    /// <summary>
    /// Whether REQ-4.4.2-06 determined the digital signature technically suitable to implement an EU
    /// qualified electronic signature.
    /// </summary>
    public required bool SuitableAsQualifiedElectronicSignature { get; init; }

    /// <summary>
    /// Whether REQ-4.4.2-06 determined the digital signature technically suitable to implement an EU
    /// qualified electronic seal.
    /// </summary>
    public required bool SuitableAsQualifiedElectronicSeal { get; init; }

    /// <summary>Gets whether the signature was determined technically suitable in either dimension — the affirmative arm of the clause 4.4.1 main output.</summary>
    public bool IsTechnicallySuitable => SuitableAsQualifiedElectronicSignature || SuitableAsQualifiedElectronicSeal;
}


/// <summary>
/// Which of the REQ-4.5-01 d) ii) timing information points one
/// <see cref="ApplicabilityTimingInformation"/> states.
/// </summary>
public enum ApplicabilityTimingKind
{
    /// <summary>The claimed signing time (REQ-4.5-01 d) ii) 1)).</summary>
    ClaimedSigningTime = 0,

    /// <summary>The time of a document time-stamp or time assertion (REQ-4.5-01 d) ii) 2)).</summary>
    DocumentTimestamp = 1,

    /// <summary>The time of a signature time-stamp or time assertion (REQ-4.5-01 d) ii) 3)).</summary>
    SignatureTimestamp = 2,

    /// <summary>The time of revocation or suspension of the signer's certificate (REQ-4.5-01 d) ii) 4)).</summary>
    SigningCertificateRevocation = 3,

    /// <summary>The time of an OCSP response, or of a CRL's issuance together with its next update (REQ-4.5-01 d) ii) 5)).</summary>
    RevocationStatusInformation = 4,

    /// <summary>The best signature time (REQ-4.5-01 d) ii) 6)).</summary>
    BestSignatureTime = 5
}


/// <summary>
/// One timing information point of an applicability rules checking report, per REQ-4.5-01 d) of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11917204/01.02.01_60/ts_11917204v010201p.pdf">
/// ETSI TS 119 172-4 V1.2.1</see>: the time itself (point ii)) and, whenever applicable, its evidential
/// relevance and level of assurance (point iii)).
/// </summary>
[DebuggerDisplay("ApplicabilityTimingInformation: {Kind} at {Time}")]
public sealed record ApplicabilityTimingInformation
{
    /// <summary>Which timing information point this states.</summary>
    public required ApplicabilityTimingKind Kind { get; init; }

    /// <summary>The stated time.</summary>
    public required DateTimeOffset Time { get; init; }

    /// <summary>For <see cref="ApplicabilityTimingKind.RevocationStatusInformation"/> read off a CRL, the CRL's next update; otherwise <see langword="null"/>.</summary>
    public DateTimeOffset? NextUpdate { get; init; }

    /// <summary>The policy identifier of the time-stamping policy the issuing authority operated under (REQ-4.5-01 d) iii) 1)); <see langword="null"/> when not applicable or not known.</summary>
    public string? TimestampPolicyOid { get; init; }

    /// <summary>The accuracy of the time-stamp (REQ-4.5-01 d) iii) 2)); <see langword="null"/> when not applicable or the token states none.</summary>
    public TimeSpan? TimestampAccuracy { get; init; }

    /// <summary>
    /// The ETSI TS 119 615 clause 4.7 determination whether the time stamp is an EU qualified electronic
    /// time stamp (REQ-4.5-01 d) iii) 3) and its NOTE 3); <see langword="null"/> when not applicable or
    /// not determined.
    /// </summary>
    public TrustServiceTokenIssuerQualificationResult? TimestampQualification { get; init; }

    /// <summary>
    /// Whether the corresponding time-stamping trust anchor is absent from an EU Member State trusted list
    /// under both the <see cref="TrustServiceTypeIdentifier.QualifiedTimeStampAuthority"/> and
    /// <see cref="TrustServiceTypeIdentifier.TimeStampAuthority"/> service types — the information point
    /// REQ-4.5-01 d) i) asks the report to express.
    /// </summary>
    public bool TrustAnchorAbsentFromTrustedList { get; init; }
}


/// <summary>
/// The cryptographic suites information of an applicability rules checking report, per REQ-4.5-01 h) of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11917204/01.02.01_60/ts_11917204v010201p.pdf">
/// ETSI TS 119 172-4 V1.2.1</see>: the suites used to generate the signature under validation, the
/// potential security issues found against them, and — stated clearly, as REQ-4.2-03 e) requires — which
/// rules expressed those issues.
/// </summary>
[DebuggerDisplay("CryptographicSuitesReport: {RulesSource}, {SecurityIssues.Count} issues")]
public sealed record CryptographicSuitesReport
{
    /// <summary>The rules the security issues were expressed against: <see cref="SignatureApplicabilityRulesWellKnown.CryptographicSuitesSpecificationRulesSource"/>, or the caller's name for its national rules.</summary>
    public required string RulesSource { get; init; }

    /// <summary>The cryptographic suites the signature under validation uses.</summary>
    public IReadOnlyList<AlgorithmUse> AlgorithmsUsed { get; init; } = [];

    /// <summary>The potential security issues found, each carrying the assessed use and the time it was trusted until.</summary>
    public IReadOnlyList<AlgorithmReliabilityAssessment> SecurityIssues { get; init; } = [];
}


/// <summary>
/// The signature applicability rules checking report of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11917204/01.02.01_60/ts_11917204v010201p.pdf">
/// ETSI TS 119 172-4 V1.2.1 clause 4.5</see>: one member per REQ-4.5-01 element, plus the REQ-4.2-02 b)
/// indication of additional inputs and the REQ-4.5-02 Annex A identifiers.
/// </summary>
/// <remarks>
/// REQ-4.5-01 requires the elements "presented in a way that is meaningful to the verifier when this
/// verifier is a natural person"; the presentation members are therefore strings the Driving Application
/// renders, while the process outcomes stay typed so nothing is lost between checking and reporting.
/// NOTE 1 of clause 4.5 points at ETSI TS 119 102-2 for structuring — <see cref="DetailedOutcome"/> is
/// where that report attaches.
/// </remarks>
[DebuggerDisplay("SignatureApplicabilityCheckingReport: {AppliedRulesIdentifier}, suitable {TechnicalApplicability.IsTechnicallySuitable}")]
public sealed record SignatureApplicabilityCheckingReport
{
    /// <summary>The scope of the checking executed on the validated signature, in the specification's own words (REQ-4.5-01 a)).</summary>
    public string ScopeStatement { get; init; } = SignatureApplicabilityRulesWellKnown.ScopeStatement;

    /// <summary>The dotted-decimal identifier of the applicability rule set the checking ran under (REQ-4.5-02, Annex A 1).</summary>
    public required string AppliedRulesIdentifier { get; init; }

    /// <summary>The data representing the signer from the <c>Subject</c> field of the signing certificate (REQ-4.5-01 b)).</summary>
    public required string SignerSubject { get; init; }

    /// <summary>The data of the signing certificate's <c>Subject Alternative Name</c> extension, when present (REQ-4.5-01 b)); empty otherwise.</summary>
    public IReadOnlyList<string> SubjectAlternativeNames { get; init; } = [];

    /// <summary>Whether a pseudonym was used at the best signature time, which the report has to indicate clearly (REQ-4.5-01 c)).</summary>
    public required bool UsesPseudonym { get; init; }

    /// <summary>The timing information points and their evidential relevance (REQ-4.5-01 d)).</summary>
    public IReadOnlyList<ApplicabilityTimingInformation> TimingInformation { get; init; } = [];

    /// <summary>The presentation of the data covered by the signature (REQ-4.5-01 e)).</summary>
    public IReadOnlyList<string> SignedDataPresentations { get; init; } = [];

    /// <summary>The signature attributes included in the signature, each stating whether it was signed or unsigned (REQ-4.5-01 f)).</summary>
    public IReadOnlyList<SignatureAttributeFacts> SignatureAttributes { get; init; } = [];

    /// <summary>The technical applicability checking outcome — the overall status of the checking (REQ-4.5-01 g)).</summary>
    public required TechnicalApplicabilityCheckResult TechnicalApplicability { get; init; }

    /// <summary>The REQ-4.2-01 validation conclusion — the reasons behind the overall status, in the ETSI EN 319 102-1 vocabulary REQ-4.5-01 g)'s NOTE 6 points at.</summary>
    public required SignatureValidationConclusion ValidationConclusion { get; init; }

    /// <summary>The clause 4.3 service match the trust anchors came from, reflected here as an intermediate process result (REQ-4.4.2-02 b) iii)); <see langword="null"/> when the caller did not retain it.</summary>
    public ListedServicesMatchResult? TrustAnchorServiceMatch { get; init; }

    /// <summary>The cryptographic suites information (REQ-4.5-01 h)); <see langword="null"/> when the caller supplied none.</summary>
    public CryptographicSuitesReport? CryptographicSuites { get; init; }

    /// <summary>The freshness of the revocation status information used for the signing certificate with respect to the best signature time (REQ-4.5-01 i)); <see langword="null"/> when no revocation status information was used.</summary>
    public TimeSpan? SigningCertificateRevocationFreshness { get; init; }

    /// <summary>The optional detailed outcome of each checking step (REQ-4.5-01 j)), as the ETSI TS 119 102-2 report clause 4.5's NOTE 1 suggests; <see langword="null"/> when not attached.</summary>
    public SignatureValidationReportElement? DetailedOutcome { get; init; }

    /// <summary>
    /// The warnings stating each failure of the signature to comply with one of the REQ-4.3-01 signature
    /// formats, with the reasons for the failure — the reporting half of REQ-4.2-03 g), whose other half is
    /// that such a failure never invalidates the signature. Empty when no format-compliance failure was
    /// found.
    /// </summary>
    public IReadOnlyList<string> FormatComplianceWarnings { get; init; } = [];

    /// <summary>The additional inputs or requirements the validation service used beyond this specification's minimum, which REQ-4.2-02 b) requires clearly indicated; empty when none were used.</summary>
    public IReadOnlyList<string> AdditionalRequirementsIndications { get; init; } = [];

    /// <summary>The Annex A 2 digital signature type determined for the signature (REQ-4.5-02); <see langword="null"/> when the checking process cannot determine one.</summary>
    public string? SignatureTypeIdentifier { get; init; }
}


/// <summary>
/// The inputs <see cref="SignatureApplicabilityRules.BuildReport"/> composes a
/// <see cref="SignatureApplicabilityCheckingReport"/> from: the process outcomes the library produced, and
/// the presentation elements only the Driving Application can state.
/// </summary>
public sealed record SignatureApplicabilityReportInputs
{
    /// <summary>The rule set the checking ran under.</summary>
    public required EuSignatureApplicabilityRuleSet RuleSet { get; init; }

    /// <summary>The technical applicability checking outcome.</summary>
    public required TechnicalApplicabilityCheckResult TechnicalApplicability { get; init; }

    /// <summary>The REQ-4.2-01 validation conclusion the checking consumed.</summary>
    public required SignatureValidationConclusion ValidationConclusion { get; init; }

    /// <summary>The signing certificate's extracted facts, from which the REQ-4.5-01 c) pseudonym indication is derived.</summary>
    public required QualifiedCertificateFacts SigningCertificateFacts { get; init; }

    /// <summary>The rendering of the signing certificate's <c>Subject</c> field (REQ-4.5-01 b)).</summary>
    public required string SignerSubject { get; init; }

    /// <summary>The rendering of the signing certificate's <c>Subject Alternative Name</c> entries, when present (REQ-4.5-01 b)).</summary>
    public IReadOnlyList<string> SubjectAlternativeNames { get; init; } = [];

    /// <summary>The clause 4.3 service match the constraints were composed from, when the caller retained it.</summary>
    public ListedServicesMatchResult? TrustAnchorServiceMatch { get; init; }

    /// <summary>The timing information points (REQ-4.5-01 d)).</summary>
    public IReadOnlyList<ApplicabilityTimingInformation> TimingInformation { get; init; } = [];

    /// <summary>The presentation of the signed data (REQ-4.5-01 e)).</summary>
    public IReadOnlyList<string> SignedDataPresentations { get; init; } = [];

    /// <summary>The signature's attributes with their signed/unsigned scope (REQ-4.5-01 f)), as the format binding surfaced them.</summary>
    public IReadOnlyList<SignatureAttributeFacts> SignatureAttributes { get; init; } = [];

    /// <summary>The cryptographic suites information (REQ-4.5-01 h)).</summary>
    public CryptographicSuitesReport? CryptographicSuites { get; init; }

    /// <summary>The revocation freshness observed for the signing certificate (REQ-4.5-01 i)).</summary>
    public TimeSpan? SigningCertificateRevocationFreshness { get; init; }

    /// <summary>The detailed ETSI TS 119 102-2 report to attach (REQ-4.5-01 j)).</summary>
    public SignatureValidationReportElement? DetailedOutcome { get; init; }

    /// <summary>The warnings stating each REQ-4.3-01 format-compliance failure and its reasons (REQ-4.2-03 g)).</summary>
    public IReadOnlyList<string> FormatComplianceWarnings { get; init; } = [];

    /// <summary>The additional inputs or requirements used beyond the specification's minimum (REQ-4.2-02 b)).</summary>
    public IReadOnlyList<string> AdditionalRequirementsIndications { get; init; } = [];
}
