using System.Diagnostics;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Application-supplied body of a Historical Keys response served at the
/// <c>federation_historical_keys_endpoint</c> per
/// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.7">Federation §8.7</see>.
/// The library produces the structural envelope claims (<c>iss</c> = the
/// entity, <c>iat</c>) and signs the JWT with the entity's federation signing
/// key; the historical <c>keys</c> array comes from the application's
/// <see cref="Server.AuthorizationServerIntegration.ResolveHistoricalKeysAsync"/>
/// delegate.
/// </summary>
/// <remarks>
/// <para>
/// Tracking which keys an entity has rotated out of its current Entity
/// Configuration, and which it has revoked, is the entity application's
/// responsibility — the library does not invent these. This record is the
/// <em>result</em> of that bookkeeping, projected onto the §8.7.3 <c>keys</c>
/// array.
/// </para>
/// <para>
/// Each JWK in <see cref="Keys"/> is a JSON object the application shapes per
/// Federation §8.7.3: <c>kid</c> (REQUIRED) and <c>exp</c> (REQUIRED), plus
/// the optional <c>iat</c>, <c>nbf</c>, and <c>revoked</c> members
/// (<c>revoked</c> being an object with a REQUIRED <c>revoked_at</c> number
/// and an OPTIONAL <c>reason</c> string). The library wraps the supplied keys
/// in the signed <c>{ iss, iat, keys }</c> envelope without inspecting them.
/// The application returns <see langword="null"/> from the delegate when it
/// has no historical keys to publish; the endpoint then responds HTTP 404.
/// </para>
/// </remarks>
[DebuggerDisplay("HistoricalKeysContribution")]
public sealed record HistoricalKeysContribution
{
    /// <summary>
    /// The <c>keys</c> claim — the array of historical (rotated and revoked)
    /// JWK objects. Required. Each entry carries at least <c>kid</c> and
    /// <c>exp</c>, and optionally <c>iat</c>, <c>nbf</c>, and a <c>revoked</c>
    /// object, per Federation §8.7.3.
    /// </summary>
    public required IReadOnlyList<IReadOnlyDictionary<string, object>> Keys { get; init; }

    /// <summary>
    /// Additional top-level claims to merge into the Historical Keys payload
    /// after the library's structural claims and the dedicated <c>keys</c>
    /// slot above. Keys that collide with library-emitted structural claims
    /// (<c>iss</c>, <c>iat</c>, <c>keys</c>) are dropped — the library wins.
    /// </summary>
    public IReadOnlyDictionary<string, object>? AdditionalClaims { get; init; }
}
