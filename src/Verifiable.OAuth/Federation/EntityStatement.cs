using System.Diagnostics;
using Verifiable.JCose;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// An OpenID Federation 1.0 Entity Statement per
/// <see href="https://openid.net/specs/openid-federation-1_0.html#section-3">Federation §3</see>.
/// Two concrete shapes: <see cref="EntityConfiguration"/> (self-issued,
/// <c>iss</c> == <c>sub</c>) and <see cref="SubordinateStatement"/>
/// (superior-issued, <c>iss</c> != <c>sub</c>). The discriminating field
/// is the relationship between <c>iss</c> and <c>sub</c>; classification
/// happens in <see cref="EntityStatementParser.Parse"/>.
/// </summary>
/// <remarks>
/// <para>
/// The structural records carry the primitive Federation claims
/// (<c>iss</c>, <c>sub</c>, <c>iat</c>, <c>exp</c>) as typed properties
/// plus a reference to the underlying
/// <see cref="UnverifiedJwtPayload"/> for downstream access to
/// nested-object claims (<c>jwks</c>, <c>metadata</c>,
/// <c>metadata_policy</c>, <c>authority_hints</c>, <c>constraints</c>,
/// <c>trust_marks</c>), which consumers parse on demand against the
/// JCose / JSON deserialisation surfaces.
/// </para>
/// <para>
/// "Unverified" is intentional in the carried payload type: an
/// <see cref="EntityStatement"/> is the result of structural parsing
/// only, not signature verification. The signature step is
/// <see cref="EntityStatementValidator"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("EntityStatement Iss={Issuer,nq} Sub={Subject,nq}")]
public abstract record EntityStatement
{
    /// <summary>The Entity Identifier issuing this statement.</summary>
    public required EntityIdentifier Issuer { get; init; }

    /// <summary>The Entity Identifier the statement is about.</summary>
    public required EntityIdentifier Subject { get; init; }

    /// <summary>The instant at which this statement was issued.</summary>
    public required DateTimeOffset IssuedAt { get; init; }

    /// <summary>The instant after which this statement is no longer valid.</summary>
    public required DateTimeOffset ExpiresAt { get; init; }

    /// <summary>
    /// The underlying JWT payload carrying the full claim set. Downstream
    /// consumers read federation-specific nested-object claims
    /// (<c>jwks</c>, <c>metadata</c>, <c>metadata_policy</c>, etc.) via
    /// this dictionary; they are not pre-deserialised.
    /// </summary>
    public required UnverifiedJwtPayload Payload { get; init; }
}
