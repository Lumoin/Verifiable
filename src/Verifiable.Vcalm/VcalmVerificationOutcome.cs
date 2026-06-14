using System.Collections.Immutable;
using System.Diagnostics;

namespace Verifiable.Vcalm;

/// <summary>
/// The result of verifying one VCALM 1.0 §3.3.1 credential's embedded proof chain, validity period,
/// and status, before the §3.8.1 error/warning roll-up flips the overall <c>verified</c>.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="ProofResults"/> carries one entry per proof in chain order, each pairing the
/// per-proof verified outcome with the proof's <c>verificationMethod</c> as its <c>input</c>
/// (§3.3.1 <c>results.proof[]</c>). <see cref="ProblemDetails"/> gathers every §3.8.1 ProblemDetail
/// — errors and warnings both. <see cref="Verified"/> is the §3.8.1 roll-up: false iff any
/// <see cref="VcalmProblemDetail.IsError"/> entry is present.
/// </para>
/// </remarks>
[DebuggerDisplay("VcalmVerificationOutcome Verified={Verified}")]
public sealed record VcalmVerificationOutcome
{
    /// <summary>
    /// The §3.8.1 overall assertion: false iff any ERROR ProblemDetail is present, true otherwise.
    /// </summary>
    public required bool Verified { get; init; }

    /// <summary>The §3.3.1 <c>results.validFrom</c> sub-result, or <see langword="null"/> when the credential has no <c>validFrom</c>.</summary>
    public VcalmInputResult? ValidFrom { get; init; }

    /// <summary>The §3.3.1 <c>results.validUntil</c> sub-result, or <see langword="null"/> when the credential has no <c>validUntil</c>.</summary>
    public VcalmInputResult? ValidUntil { get; init; }

    /// <summary>The §3.3.1 <c>results.credentialStatus[]</c> sub-results, in entry order. Empty when the credential has no status.</summary>
    public ImmutableArray<VcalmStatusResult> StatusResults { get; init; } = ImmutableArray<VcalmStatusResult>.Empty;

    /// <summary>The §3.3.1 <c>results.proof[]</c> sub-results, in chain order.</summary>
    public ImmutableArray<VcalmInputResult> ProofResults { get; init; } = ImmutableArray<VcalmInputResult>.Empty;

    /// <summary>Every §3.8.1 ProblemDetail gathered for this credential — errors and warnings.</summary>
    public ImmutableArray<VcalmProblemDetail> ProblemDetails { get; init; } = ImmutableArray<VcalmProblemDetail>.Empty;
}


/// <summary>
/// A §3.3.1 per-step sub-result: a boolean <c>verified</c> paired with the <c>input</c> value the
/// step examined (a <c>validFrom</c> / <c>validUntil</c> string, or a proof's
/// <c>verificationMethod</c>).
/// </summary>
[DebuggerDisplay("VcalmInputResult Verified={Verified} Input={Input}")]
public sealed record VcalmInputResult
{
    /// <summary>The step's boolean result.</summary>
    public required bool Verified { get; init; }

    /// <summary>The input value the step examined.</summary>
    public required string Input { get; init; }
}


/// <summary>
/// A §3.3.1 <c>results.credentialStatus[]</c> sub-result: the integer status <c>value</c>, the
/// boolean <c>verified</c>, and the <c>input</c> status entry id.
/// </summary>
[DebuggerDisplay("VcalmStatusResult Value={Value} Verified={Verified}")]
public sealed record VcalmStatusResult
{
    /// <summary>The specific status value associated with the status entry (§3.3.1 <c>value</c>).</summary>
    public required int Value { get; init; }

    /// <summary>The status-check result (§3.3.1 <c>verified</c>): true when the credential is not revoked / suspended.</summary>
    public required bool Verified { get; init; }

    /// <summary>The status entry's <c>id</c> as the <c>input</c>, or empty when it has none.</summary>
    public required string Input { get; init; }
}
