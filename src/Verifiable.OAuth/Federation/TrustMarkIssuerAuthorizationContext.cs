using Verifiable.Core.Assessment;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// <see cref="ClaimContext"/> attached to the trust-mark-issuer
/// authorization Claim (1171) when the check fails. Carries the trust
/// mark identifier, the issuer in question, and the reason the
/// authorization could not be established.
/// </summary>
public sealed record TrustMarkIssuerAuthorizationContext: ClaimContext
{
    /// <summary>The trust mark identifier being authorized.</summary>
    public required string MarkId { get; init; }

    /// <summary>The issuer the mark was signed by.</summary>
    public required EntityIdentifier Issuer { get; init; }

    /// <summary>Short string identifying the reason category.</summary>
    /// <remarks>
    /// One of: <c>"NoTrustMarkIssuersDeclared"</c> (the TA's configuration
    /// has no <c>trust_mark_issuers</c> claim at all),
    /// <c>"MarkIdNotListed"</c> (the TA declares <c>trust_mark_issuers</c>
    /// but not for this mark id), or <c>"IssuerNotInList"</c> (the mark id
    /// is listed but the issuer is not in its authorized list).
    /// Direct delegation paths route through chunk B.7.4's 1173 check
    /// rather than this one.
    /// </remarks>
    public required string Reason { get; init; }
}
