using System.Diagnostics;
using Verifiable.JCose;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// A parsed OpenID Federation 1.0 Trust Mark JWT per
/// <see href="https://openid.net/specs/openid-federation-1_0.html#section-7">Federation §7</see>.
/// </summary>
/// <remarks>
/// <para>
/// Structural classification only — a <see cref="TrustMark"/> in hand
/// means the JWT shape parsed cleanly. Signature verification,
/// issuer-authorisation against the chain's
/// <see cref="WellKnownFederationClaimNames.TrustMarkIssuers"/> claim,
/// and delegation-chain validation are the
/// <see cref="TrustMarkValidator"/>'s responsibilities.
/// </para>
/// <para>
/// Mirrors <see cref="EntityStatement"/> in shape: typed Issuer, Subject,
/// IssuedAt, optional ExpiresAt, plus the mark's identifier and the raw
/// <see cref="UnverifiedJwtPayload"/> for nested-claim access
/// (<see cref="WellKnownFederationClaimNames.Delegation"/>,
/// <see cref="WellKnownFederationClaimNames.LogoUri"/>,
/// <see cref="WellKnownFederationClaimNames.Ref"/>).
/// </para>
/// </remarks>
[DebuggerDisplay("TrustMark Iss={Issuer,nq} Sub={Subject,nq} Id={MarkId,nq}")]
public sealed record TrustMark
{
    /// <summary>The Trust Mark Issuer's Entity Identifier (JWT <c>iss</c>).</summary>
    public required EntityIdentifier Issuer { get; init; }

    /// <summary>The subject the mark is about (JWT <c>sub</c>).</summary>
    public required EntityIdentifier Subject { get; init; }

    /// <summary>The instant at which this mark was issued (JWT <c>iat</c>).</summary>
    public required DateTimeOffset IssuedAt { get; init; }

    /// <summary>
    /// The instant after which this mark is no longer valid (JWT
    /// <c>exp</c>). Optional per §7.1.1: marks without <c>exp</c> have
    /// indefinite validity.
    /// </summary>
    public DateTimeOffset? ExpiresAt { get; init; }

    /// <summary>
    /// The Trust Mark type identifier (JWT <c>trust_mark_type</c>; the draft-era claim name was
    /// <c>id</c>) — a URI naming the framework asserted. The model field keeps the name
    /// <see cref="MarkId"/> while the wire claim name lives on
    /// <see cref="WellKnownFederationClaimNames.TrustMarkType"/>.
    /// </summary>
    public required string MarkId { get; init; }

    /// <summary>
    /// The underlying JWT payload. Downstream consumers read nested-object
    /// claims (<see cref="WellKnownFederationClaimNames.Delegation"/>,
    /// <c>logo_uri</c>, <c>ref</c>) via this dictionary; this record doesn't
    /// pre-deserialise them.
    /// </summary>
    public required UnverifiedJwtPayload Payload { get; init; }
}
