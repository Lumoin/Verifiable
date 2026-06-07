using System.Diagnostics;
using Verifiable.JCose;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// A parsed OpenID Federation 1.0 Trust Mark Delegation JWT per
/// <see href="https://openid.net/specs/openid-federation-1_0.html#section-7.2.2">Federation §7.2.2</see>.
/// </summary>
/// <remarks>
/// <para>
/// Structurally a JWS like a Trust Mark, but with different semantics:
/// the issuer is the Trust Mark Owner, the subject is the Trust Mark
/// Issuer the owner authorizes to issue marks of <see cref="MarkId"/>.
/// The signature is verified against the owner's keys read from the
/// Trust Anchor's <c>trust_mark_owners</c> claim.
/// </para>
/// </remarks>
[DebuggerDisplay("TrustMarkDelegation Owner={Owner,nq} Issuer={Issuer,nq} Id={MarkId,nq}")]
public sealed record TrustMarkDelegation
{
    /// <summary>The Trust Mark Owner authorizing the issuer (JWT <c>iss</c>).</summary>
    public required EntityIdentifier Owner { get; init; }

    /// <summary>The Trust Mark Issuer being authorized (JWT <c>sub</c>).</summary>
    public required EntityIdentifier Issuer { get; init; }

    /// <summary>When the delegation was issued (JWT <c>iat</c>).</summary>
    public required DateTimeOffset IssuedAt { get; init; }

    /// <summary>Optional delegation expiry (JWT <c>exp</c>).</summary>
    public DateTimeOffset? ExpiresAt { get; init; }

    /// <summary>The Trust Mark identifier being delegated (JWT <c>id</c>).</summary>
    public required string MarkId { get; init; }

    /// <summary>The underlying JWT payload.</summary>
    public required UnverifiedJwtPayload Payload { get; init; }
}
