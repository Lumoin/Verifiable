using System.Diagnostics;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Input to <see cref="TrustChainValidator"/> and the chain-level checks
/// on <see cref="FederationValidationChecks"/>. Carries the ordered chain,
/// the application-supplied trust anchor allow-list, and the pre-computed
/// per-link signature outcomes.
/// </summary>
/// <remarks>
/// <para>
/// The chain validator orchestrates per-link signature verification using
/// the registered key resolver (chunk 6's
/// <c>ResolveEntityKeyDelegate</c>) before the claim chain runs and
/// records the outcome positionally in
/// <see cref="LinkSignaturesVerified"/> — aligned 1:1 with
/// <see cref="TrustChain.Statements"/>. Position 0 is the subject's
/// Entity Configuration (self-signed); position N-1 is the Trust Anchor's
/// Entity Configuration (also self-signed); intermediate positions are
/// Subordinate Statements signed by the entity at the next position up.
/// </para>
/// </remarks>
[DebuggerDisplay("TrustChainValidationContext Length={Chain.Statements.Count} Anchors={TrustAnchors.Count}")]
public sealed record TrustChainValidationContext
{
    /// <summary>The ordered chain being validated.</summary>
    public required TrustChain Chain { get; init; }

    /// <summary>
    /// The application-supplied trust anchor allow-list. A chain validates
    /// only if its terminal Entity Configuration's
    /// <see cref="EntityStatement.Issuer"/> appears here. Comparison is
    /// ordinal on <see cref="EntityIdentifier.Value"/>.
    /// </summary>
    public required IReadOnlyCollection<EntityIdentifier> TrustAnchors { get; init; }

    /// <summary>
    /// Per-link signature verification outcomes from the validator's
    /// pre-flight, aligned 1:1 with <see cref="TrustChain.Statements"/>.
    /// Index <c>i</c> records the result of verifying
    /// <c>Statements[i]</c>'s signature against the key resolved per chunk 6's
    /// <c>ResolveEntityKeyDelegate</c>.
    /// </summary>
    public required IReadOnlyList<bool> LinkSignaturesVerified { get; init; }

    /// <summary>
    /// The instant against which the chain's effective <c>exp</c> is
    /// computed and compared.
    /// </summary>
    public required DateTimeOffset Now { get; init; }

    /// <summary>
    /// Maximum acceptable clock skew for the chain's effective-<c>exp</c>
    /// check.
    /// </summary>
    public required TimeSpan ClockSkew { get; init; }
}
