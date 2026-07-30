using System.Diagnostics;
using Verifiable.JCose;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// A parsed trust-mark delegation plus the wire form needed to verify it per OpenID Federation 1.0 §7.2.2: the
/// structurally-classified <see cref="TrustMarkDelegation"/>, its JWS protected header (carrying the Trust Mark
/// Owner's signing <c>kid</c>), and the compact JWS verified against the owner's resolved key.
/// </summary>
[DebuggerDisplay("TrustMarkDelegationCandidate Owner={Delegation.Owner,nq} Id={Delegation.MarkId,nq}")]
public sealed record TrustMarkDelegationCandidate
{
    /// <summary>The structurally-classified delegation.</summary>
    public required TrustMarkDelegation Delegation { get; init; }

    /// <summary>The delegation JWS protected header (carries the owner's signing <c>kid</c>).</summary>
    public required UnverifiedJwtHeader Header { get; init; }

    /// <summary>The compact JWS form of the delegation, verified against the owner's resolved key.</summary>
    public required string CompactJws { get; init; }
}
