using System;
using System.Diagnostics;
using Verifiable.Cryptography.Context;

namespace Verifiable.Cryptography;

/// <summary>
/// An immutable point-in-time observation of an entropy source's health.
/// </summary>
/// <remarks>
/// <para>
/// Captures who assessed the source, how, when, and what the outcome was.
/// The <see cref="EvidenceReference"/> is an opaque string identifier pointing
/// to diagnostic data held elsewhere — for example a TPM response code string,
/// a NIST test result identifier, or an audit report reference number. Raw bytes
/// are never stored in the event to keep it small and CloudEvents-compatible.
/// </para>
/// <para>
/// Health is a point-in-time observation, not a permanent property. Use
/// <see cref="Unknown"/> when no health information is available. Treat
/// <see cref="EntropyOutcome.Unknown"/> as potentially degraded — prefer
/// sources with known health for regulated operations.
/// </para>
/// </remarks>
[DebuggerDisplay("EntropyHealth Source={Source} Outcome={Outcome} Method={Method} At={ObservedAt}")]
public sealed record EntropyHealthObservation
{
    /// <summary>
    /// A singleton representing an unknown health state. Used when no
    /// assessment has been performed or the result is unavailable.
    /// </summary>
    public static EntropyHealthObservation Unknown { get; } = new EntropyHealthObservation
    {
        Source = EntropySource.Unknown,
        Assessor = EntropyAssessor.Unknown,
        Method = EntropyAssessmentMethod.Unknown,
        Outcome = EntropyOutcome.Unknown,
        ObservedAt = DateTimeOffset.MinValue,
        Window = null,
        EvidenceReference = null
    };


    /// <summary>The entropy source that was assessed.</summary>
    public required EntropySource Source { get; init; }

    /// <summary>Who performed the assessment.</summary>
    public required EntropyAssessor Assessor { get; init; }

    /// <summary>How the assessment was performed.</summary>
    public required EntropyAssessmentMethod Method { get; init; }

    /// <summary>The outcome of the assessment.</summary>
    public required EntropyOutcome Outcome { get; init; }

    /// <summary>When this observation was made.</summary>
    public required DateTimeOffset ObservedAt { get; init; }

    /// <summary>
    /// When the assessment covers a time window (e.g. statistical analysis
    /// over the last 60 seconds), the length of that window. <see langword="null"/>
    /// for point-in-time assessments.
    /// </summary>
    public TimeSpan? Window { get; init; }

    /// <summary>
    /// An opaque reference to supporting diagnostic data held externally.
    /// For example: a TPM response code string, a NIST test result ID,
    /// or an audit report reference number. <see langword="null"/> when no
    /// evidence reference is available.
    /// </summary>
    public string? EvidenceReference { get; init; }


    /// <summary>
    /// Returns <see langword="true"/> when this observation indicates the
    /// source was healthy at assessment time.
    /// </summary>
    public bool IsHealthy => Outcome == EntropyOutcome.Healthy;

    /// <summary>
    /// Returns <see langword="true"/> when the health outcome is known —
    /// i.e. not <see cref="EntropyOutcome.Unknown"/>.
    /// </summary>
    public bool IsKnown => Outcome != EntropyOutcome.Unknown;
}