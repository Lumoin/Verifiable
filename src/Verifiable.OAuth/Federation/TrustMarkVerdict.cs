using System.Diagnostics;
using Verifiable.Core.Assessment;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// The verification verdict for one trust mark from
/// <see cref="FederationTrustMarkResolver.ResolveVerifiedAsync"/>: whether it is <see cref="Admitted"/>, plus the
/// per-stage outcomes that produced the verdict.
/// </summary>
/// <remarks>
/// <para>
/// A mark is admitted when its OpenID Federation 1.0 §7.3 shape checks all pass (which includes the
/// issuer-signature outcome) AND it is authorized — either directly (its issuer is in the Trust Anchor's
/// <c>trust_mark_issuers</c> for the mark id, §6.2) OR by a valid delegation from a registered Trust Mark Owner
/// (§7.2.2). Surfacing only admitted marks is the §8.3 resolve-response use case.
/// </para>
/// </remarks>
[DebuggerDisplay("TrustMarkVerdict Id={Mark.MarkId,nq} Admitted={Admitted} SigOk={SignatureVerified}")]
public sealed record TrustMarkVerdict
{
    /// <summary>The trust mark this verdict is about.</summary>
    public required TrustMark Mark { get; init; }

    /// <summary>Whether the mark is admitted (shape passed and it is authorized directly or by delegation).</summary>
    public required bool Admitted { get; init; }

    /// <summary>Whether the trust mark JWS signature verified against the issuer's chain-resolved key.</summary>
    public required bool SignatureVerified { get; init; }

    /// <summary>The §7.3 shape-validation claims (signature outcome plus exp/iat consistency).</summary>
    public required ClaimIssueResult Shape { get; init; }

    /// <summary>The §6.2 direct issuer-authorization claim.</summary>
    public required Claim IssuerAuthorization { get; init; }

    /// <summary>The §7.2.2 delegation claim, or a not-applicable claim for a directly-issued mark.</summary>
    public required Claim Delegation { get; init; }
}
