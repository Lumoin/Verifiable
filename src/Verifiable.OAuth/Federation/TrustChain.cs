using System.Diagnostics;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// An ordered sequence of <see cref="EntityStatement"/> values forming a
/// trust chain from a subject (leaf) up to a Trust Anchor per
/// <see href="https://openid.net/specs/openid-federation-1_0.html#section-4">Federation §4</see>.
/// </summary>
/// <remarks>
/// <para>
/// Position invariants:
/// </para>
/// <list type="bullet">
///   <item><description>
///     Position <c>0</c>: the subject's <see cref="EntityConfiguration"/>
///     (self-issued statement carrying the subject's own keys and metadata).
///   </description></item>
///   <item><description>
///     Positions <c>1..N-2</c>: <see cref="SubordinateStatement"/> values
///     issued by each successive superior about the entity below it,
///     walking up the federation hierarchy.
///   </description></item>
///   <item><description>
///     Position <c>N-1</c>: the Trust Anchor's
///     <see cref="EntityConfiguration"/>. The TA's Entity Configuration
///     is included in the chain because its <c>jwks</c> is needed to
///     verify the signature on the Subordinate Statement at position
///     <c>N-2</c>.
///   </description></item>
/// </list>
/// <para>
/// Structural classification only — chunk 2 ships the record shape;
/// chunk 4's <see cref="TrustChainValidator"/> enforces the position
/// invariants and walks the chain for signature verification, expiry
/// minimisation, cycle detection, and trust-anchor matching.
/// </para>
/// </remarks>
[DebuggerDisplay("TrustChain Length={Statements.Count} Subject={Subject.Issuer,nq}")]
public sealed record TrustChain
{
    /// <summary>The ordered sequence of statements from subject to Trust Anchor.</summary>
    public required IReadOnlyList<EntityStatement> Statements { get; init; }

    /// <summary>
    /// The subject's <see cref="EntityConfiguration"/> at position 0.
    /// Throws when the chain is empty or position 0 is not a self-issued
    /// statement; the trust chain validator surfaces this as a
    /// <see cref="WellKnownFederationClaimIds.ChainStartsAtSubject"/>
    /// failure rather than letting the throw escape.
    /// </summary>
    public EntityConfiguration Subject =>
        Statements.Count > 0 && Statements[0] is EntityConfiguration leafConfig
            ? leafConfig
            : throw new InvalidOperationException(
                "TrustChain position 0 must be an EntityConfiguration (the subject's self-issued statement).");

    /// <summary>
    /// The Trust Anchor's <see cref="EntityConfiguration"/> at position
    /// N-1. Throws when the chain is empty or the final position is not
    /// a self-issued statement; the trust chain validator surfaces this
    /// as a
    /// <see cref="WellKnownFederationClaimIds.ChainTerminatesAtTrustAnchor"/>
    /// failure rather than letting the throw escape.
    /// </summary>
    public EntityConfiguration TrustAnchor =>
        Statements.Count > 0 && Statements[^1] is EntityConfiguration taConfig
            ? taConfig
            : throw new InvalidOperationException(
                "TrustChain final position must be an EntityConfiguration (the Trust Anchor's self-issued statement).");
}
