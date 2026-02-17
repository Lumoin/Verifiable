using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Core.SelectiveDisclosure;

/// <summary>
/// The complete decision record for a disclosure computation, capturing all
/// inputs, intermediate results, and outputs for audit, consent, and compliance.
/// </summary>
/// <remarks>
/// <para>
/// This record is the raw data source for downstream builders that produce
/// formatted compliance artifacts:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>ISO 27560 consent receipts:</strong> A builder extracts the disclosed
/// claims, purpose, and timestamp to construct a consent receipt conforming to
/// the ISO/IEC TS 27560:2023 standard as profiled by the W3C Data Privacy Vocabulary.
/// See <see href="https://w3c.github.io/dpv/guides/consent-27560">DPV Consent 27560 Guide</see>.
/// </description></item>
/// <item><description>
/// <strong>GDPR audit logs:</strong> A builder extracts the legal basis, data
/// categories, and processing purpose for Article 30 records of processing.
/// </description></item>
/// <item><description>
/// <strong>AI accountability reports:</strong> A builder extracts policy assessor
/// names, reasons (including SHAP-style explanations from AI assessors), and
/// decision chains to produce accountability artifacts required by the EU AI Act
/// or organizational governance frameworks.
/// </description></item>
/// <item><description>
/// <strong>Internal analytics:</strong> A builder extracts match rates, lattice
/// conflict frequencies, and policy rejection rates for operational dashboards.
/// </description></item>
/// </list>
/// <para>
/// The record carries W3C Trace Context identifiers (<see cref="TraceParent"/>,
/// <see cref="TraceState"/>, <see cref="SpanId"/>) captured from <see cref="Activity.Current"/>
/// at computation time. When the computation runs within an OpenTelemetry-instrumented
/// pipeline (e.g., an OID4VP request handler), these identifiers correlate the
/// disclosure decision with the broader distributed trace. When no trace context
/// is active, these fields are <see langword="null"/>.
/// </para>
/// <para>
/// The computation always produces this record. There is no opt-in mechanism;
/// the allocation cost is negligible since the record references data already
/// computed during the disclosure pipeline.
/// </para>
/// </remarks>
/// <typeparam name="TCredential">The application-specific credential type.</typeparam>
public sealed class DisclosureDecisionRecord<TCredential>
{
    //OpenTelemetry / W3C Trace Context correlation.

    /// <summary>
    /// The W3C <c>traceparent</c> header value, captured from <see cref="Activity.Current"/>
    /// at computation time.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Format: <c>{version}-{trace-id}-{parent-id}-{trace-flags}</c>.
    /// See <see href="https://www.w3.org/TR/trace-context/#traceparent-header">W3C Trace Context</see>.
    /// </para>
    /// </remarks>
    public string? TraceParent { get; init; }

    /// <summary>
    /// The W3C <c>tracestate</c> header value, captured from <see cref="Activity.Current"/>
    /// at computation time.
    /// </summary>
    public string? TraceState { get; init; }

    /// <summary>
    /// The span ID of the disclosure computation's own activity span.
    /// </summary>
    public string? SpanId { get; init; }

    //Timing.

    /// <summary>
    /// When the computation started.
    /// </summary>
    public required DateTimeOffset Timestamp { get; init; }

    /// <summary>
    /// How long the computation took.
    /// </summary>
    public required TimeSpan Duration { get; init; }

    //Inputs.

    /// <summary>
    /// The number of candidate credentials fetched from storage.
    /// </summary>
    public required int CandidateCount { get; init; }

    //Evaluation phase.

    /// <summary>
    /// Per-credential evaluation outcomes.
    /// </summary>
    public required IReadOnlyList<CredentialEvaluationRecord> Evaluations { get; init; }

    //Lattice phase.

    /// <summary>
    /// Per-credential lattice computations for matched credentials.
    /// </summary>
    public required IReadOnlyList<LatticeComputationRecord> LatticeComputations { get; init; }

    //Policy phase.

    /// <summary>
    /// Policy assessor outcomes, in order of execution.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Each entry records which assessor ran, whether it approved, what paths it removed,
    /// and the human-readable reason. For AI assessors, the reason may contain SHAP-style
    /// feature importance explanations. For SAT solvers, it may describe which constraint
    /// was binding or unsatisfiable.
    /// </para>
    /// </remarks>
    public IReadOnlyList<PolicyAssessmentRecord>? PolicyAssessments { get; init; }

    //Final outcome.

    /// <summary>
    /// Per-credential final disclosure decisions.
    /// </summary>
    public required IReadOnlyList<CredentialDisclosureDecision<TCredential>> FinalDecisions { get; init; }

    /// <summary>
    /// Whether the overall computation satisfied all query requirements.
    /// </summary>
    public required bool Satisfied { get; init; }
}