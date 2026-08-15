using System.Diagnostics;
using Verifiable.JCose;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// A parsed trust mark plus the wire form needed to verify it: the structurally-classified
/// <see cref="TrustMark"/>, its JWS protected header (carrying the signing <c>kid</c>), the compact JWS (verified
/// against the issuer's resolved key), and the parsed delegation when the mark was issued under a Trust Mark
/// Owner's delegation per OpenID Federation 1.0 §7.2.2.
/// </summary>
/// <remarks>
/// The caller parses the subject's <c>trust_marks</c> entries into these candidates (via
/// <see cref="TrustMarkParser"/> and, when a <c>delegation</c> claim is present,
/// <see cref="TrustMarkDelegationParser"/>); <see cref="FederationTrustMarkResolver"/> performs the
/// verification. Parsing and verification are kept separate, mirroring the rest of the federation namespace.
/// </remarks>
[DebuggerDisplay("TrustMarkCandidate Iss={Mark.Issuer,nq} Id={Mark.MarkId,nq} Delegated={Delegation != null}")]
public sealed record TrustMarkCandidate
{
    /// <summary>The structurally-classified trust mark.</summary>
    public required TrustMark Mark { get; init; }

    /// <summary>The trust mark JWS protected header (carries the signing <c>kid</c>).</summary>
    public required UnverifiedJwtHeader Header { get; init; }

    /// <summary>The compact JWS form of the trust mark, verified against the issuer's resolved key.</summary>
    public required string CompactJws { get; init; }

    /// <summary>
    /// The parsed delegation when the mark carries a <c>delegation</c> claim (§7.2.1), or
    /// <see langword="null"/> for a directly-issued mark.
    /// </summary>
    public TrustMarkDelegationCandidate? Delegation { get; init; }
}
