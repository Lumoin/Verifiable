using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography.Context;

/// <summary>
/// Identifies who performed an entropy health assessment.
/// </summary>
/// <remarks>
/// Different assessors have different authority and evidence quality.
/// Self-attestation by the source is the weakest — the source could be
/// compromised. External audit is the strongest but least frequent.
/// Registry-based statistical assessment sits between the two.
/// </remarks>
[DebuggerDisplay("{EntropyAssessorNames.GetName(this),nq}")]
public readonly struct EntropyAssessor: IEquatable<EntropyAssessor>
{
    /// <summary>Gets the numeric code for this assessor.</summary>
    public int Code { get; }

    private EntropyAssessor(int code) { Code = code; }


    /// <summary>The entropy source assessed its own health (self-attestation).</summary>
    public static EntropyAssessor Source { get; } = new(0);

    /// <summary>The operating system reported health status.</summary>
    public static EntropyAssessor OperatingSystem { get; } = new(1);

    /// <summary>
    /// The entropy registry assessed health based on statistical analysis
    /// of the event stream over time.
    /// </summary>
    public static EntropyAssessor Registry { get; } = new(2);

    /// <summary>An external monitor or auditor performed the assessment.</summary>
    public static EntropyAssessor ExternalMonitor { get; } = new(3);

    /// <summary>Assessor is not known.</summary>
    public static EntropyAssessor Unknown { get; } = new(4);


    private static readonly List<EntropyAssessor> assessors =
        [Source, OperatingSystem, Registry, ExternalMonitor, Unknown];

    /// <summary>Gets all registered assessor values.</summary>
    public static IReadOnlyList<EntropyAssessor> Assessors => assessors.AsReadOnly();

    /// <summary>Creates a new assessor value. Use codes above 1000.</summary>
    public static EntropyAssessor Create(int code)
    {
        for(int i = 0; i < assessors.Count; ++i)
        {
            if(assessors[i].Code == code)
            {
                throw new ArgumentException("Code already exists.");
            }
        }

        var newAssessor = new EntropyAssessor(code);
        assessors.Add(newAssessor);
        return newAssessor;
    }

    /// <inheritdoc/>
    public override string ToString() => EntropyAssessorNames.GetName(this);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(EntropyAssessor other) => Code == other.Code;

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is EntropyAssessor other && Equals(other);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => Code;

    /// <inheritdoc/>
    public static bool operator ==(EntropyAssessor left, EntropyAssessor right) => left.Equals(right);

    /// <inheritdoc/>
    public static bool operator !=(EntropyAssessor left, EntropyAssessor right) => !left.Equals(right);
}


/// <summary>Provides human-readable names for <see cref="EntropyAssessor"/> values.</summary>
public static class EntropyAssessorNames
{
    /// <summary>Gets the name for the specified assessor.</summary>
    public static string GetName(EntropyAssessor assessor) => GetName(assessor.Code);

    /// <summary>Gets the name for the specified assessor code.</summary>
    public static string GetName(int code) => code switch
    {
        var c when c == EntropyAssessor.Source.Code => nameof(EntropyAssessor.Source),
        var c when c == EntropyAssessor.OperatingSystem.Code => nameof(EntropyAssessor.OperatingSystem),
        var c when c == EntropyAssessor.Registry.Code => nameof(EntropyAssessor.Registry),
        var c when c == EntropyAssessor.ExternalMonitor.Code => nameof(EntropyAssessor.ExternalMonitor),
        var c when c == EntropyAssessor.Unknown.Code => nameof(EntropyAssessor.Unknown),
        _ => $"Custom ({code})"
    };
}


/// <summary>
/// Identifies how an entropy health assessment was performed.
/// </summary>
[DebuggerDisplay("{EntropyAssessmentMethodNames.GetName(this),nq}")]
public readonly struct EntropyAssessmentMethod: IEquatable<EntropyAssessmentMethod>
{
    /// <summary>Gets the numeric code for this assessment method.</summary>
    public int Code { get; }

    private EntropyAssessmentMethod(int code) { Code = code; }


    /// <summary>
    /// The source ran its built-in self-test (e.g. TPM2_SelfTest).
    /// Point-in-time. Authoritative for internal state but relies on
    /// the source's own reporting.
    /// </summary>
    public static EntropyAssessmentMethod SelfTest { get; } = new(0);

    /// <summary>
    /// Online statistical tests applied to the output stream
    /// (e.g. NIST SP 800-90B adaptive proportion test).
    /// Continuous. Detects statistical anomalies in generated bytes.
    /// </summary>
    public static EntropyAssessmentMethod OnlineStatistical { get; } = new(1);

    /// <summary>
    /// External audit by a qualified assessor. Highest assurance.
    /// Periodic, not continuous.
    /// </summary>
    public static EntropyAssessmentMethod ExternalAudit { get; } = new(2);

    /// <summary>Assessment method is not known.</summary>
    public static EntropyAssessmentMethod Unknown { get; } = new(3);


    private static readonly List<EntropyAssessmentMethod> methods =
        [SelfTest, OnlineStatistical, ExternalAudit, Unknown];

    /// <summary>Gets all registered assessment method values.</summary>
    public static IReadOnlyList<EntropyAssessmentMethod> Methods => methods.AsReadOnly();

    /// <summary>Creates a new assessment method value. Use codes above 1000.</summary>
    public static EntropyAssessmentMethod Create(int code)
    {
        for(int i = 0; i < methods.Count; ++i)
        {
            if(methods[i].Code == code)
            {
                throw new ArgumentException("Code already exists.");
            }
        }

        var newMethod = new EntropyAssessmentMethod(code);
        methods.Add(newMethod);
        return newMethod;
    }

    /// <inheritdoc/>
    public override string ToString() => EntropyAssessmentMethodNames.GetName(this);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(EntropyAssessmentMethod other) => Code == other.Code;

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is EntropyAssessmentMethod other && Equals(other);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => Code;

    /// <inheritdoc/>
    public static bool operator ==(EntropyAssessmentMethod left, EntropyAssessmentMethod right) =>
        left.Equals(right);

    /// <inheritdoc/>
    public static bool operator !=(EntropyAssessmentMethod left, EntropyAssessmentMethod right) =>
        !left.Equals(right);
}


/// <summary>Provides human-readable names for <see cref="EntropyAssessmentMethod"/> values.</summary>
public static class EntropyAssessmentMethodNames
{
    /// <summary>Gets the name for the specified assessment method.</summary>
    public static string GetName(EntropyAssessmentMethod method) => GetName(method.Code);

    /// <summary>Gets the name for the specified assessment method code.</summary>
    public static string GetName(int code) => code switch
    {
        var c when c == EntropyAssessmentMethod.SelfTest.Code => nameof(EntropyAssessmentMethod.SelfTest),
        var c when c == EntropyAssessmentMethod.OnlineStatistical.Code => nameof(EntropyAssessmentMethod.OnlineStatistical),
        var c when c == EntropyAssessmentMethod.ExternalAudit.Code => nameof(EntropyAssessmentMethod.ExternalAudit),
        var c when c == EntropyAssessmentMethod.Unknown.Code => nameof(EntropyAssessmentMethod.Unknown),
        _ => $"Custom ({code})"
    };
}


/// <summary>
/// The outcome of an entropy health assessment.
/// </summary>
[DebuggerDisplay("{EntropyOutcomeNames.GetName(this),nq}")]
public readonly struct EntropyOutcome: IEquatable<EntropyOutcome>
{
    /// <summary>Gets the numeric code for this outcome.</summary>
    public int Code { get; }

    private EntropyOutcome(int code) { Code = code; }


    /// <summary>Source passed all health checks. Safe to use.</summary>
    public static EntropyOutcome Healthy { get; } = new(0);

    /// <summary>
    /// Source is operational but health checks raised warnings.
    /// Use with caution — consider alternative sources if available.
    /// </summary>
    public static EntropyOutcome Degraded { get; } = new(1);

    /// <summary>
    /// Source failed health checks. Must not be used for key material
    /// or protocol-critical nonces.
    /// </summary>
    public static EntropyOutcome Failed { get; } = new(2);

    /// <summary>Health status could not be determined.</summary>
    public static EntropyOutcome Unknown { get; } = new(3);


    private static readonly List<EntropyOutcome> outcomes =
        [Healthy, Degraded, Failed, Unknown];

    /// <summary>Gets all registered outcome values.</summary>
    public static IReadOnlyList<EntropyOutcome> Outcomes => outcomes.AsReadOnly();

    /// <summary>Creates a new outcome value. Use codes above 1000.</summary>
    public static EntropyOutcome Create(int code)
    {
        for(int i = 0; i < outcomes.Count; ++i)
        {
            if(outcomes[i].Code == code)
            {
                throw new ArgumentException("Code already exists.");
            }
        }

        var newOutcome = new EntropyOutcome(code);
        outcomes.Add(newOutcome);
        return newOutcome;
    }

    /// <inheritdoc/>
    public override string ToString() => EntropyOutcomeNames.GetName(this);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(EntropyOutcome other) => Code == other.Code;

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is EntropyOutcome other && Equals(other);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => Code;

    /// <inheritdoc/>
    public static bool operator ==(EntropyOutcome left, EntropyOutcome right) => left.Equals(right);

    /// <inheritdoc/>
    public static bool operator !=(EntropyOutcome left, EntropyOutcome right) => !left.Equals(right);
}


/// <summary>Provides human-readable names for <see cref="EntropyOutcome"/> values.</summary>
public static class EntropyOutcomeNames
{
    /// <summary>Gets the name for the specified outcome.</summary>
    public static string GetName(EntropyOutcome outcome) => GetName(outcome.Code);

    /// <summary>Gets the name for the specified outcome code.</summary>
    public static string GetName(int code) => code switch
    {
        var c when c == EntropyOutcome.Healthy.Code => nameof(EntropyOutcome.Healthy),
        var c when c == EntropyOutcome.Degraded.Code => nameof(EntropyOutcome.Degraded),
        var c when c == EntropyOutcome.Failed.Code => nameof(EntropyOutcome.Failed),
        var c when c == EntropyOutcome.Unknown.Code => nameof(EntropyOutcome.Unknown),
        _ => $"Custom ({code})"
    };
}