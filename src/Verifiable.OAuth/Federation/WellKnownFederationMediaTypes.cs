using System.Diagnostics;
using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// JWT <c>typ</c> header values used by OpenID Federation 1.0 per
/// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.11">RFC 8725 §3.11</see>'s
/// explicit-typing discipline. Federation entity statements, trust marks,
/// and trust mark delegations each carry a distinct <c>typ</c> so that a
/// JWT issued for one purpose cannot be substituted for another (cross-JWT
/// confusion defense).
/// </summary>
[DebuggerDisplay("WellKnownFederationMediaTypes")]
public static class WellKnownFederationMediaTypes
{
    /// <summary>The UTF-8 source literal of <see cref="EntityStatementJwt"/>.</summary>
    public static ReadOnlySpan<byte> EntityStatementJwtUtf8 => "entity-statement+jwt"u8;

    /// <summary>
    /// <c>entity-statement+jwt</c> — Entity Configuration and Subordinate
    /// Statement JWTs per
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-3.1">Federation §3.1</see>.
    /// </summary>
    public static string EntityStatementJwt { get; } = Utf8Constants.ToInternedString(EntityStatementJwtUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ResolveResponseJwt"/>.</summary>
    public static ReadOnlySpan<byte> ResolveResponseJwtUtf8 => "resolve-response+jwt"u8;

    /// <summary>
    /// <c>resolve-response+jwt</c> — Resolve Response JWTs returned from a
    /// <c>federation_resolve_endpoint</c> per
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.3">Federation §8.3</see>.
    /// A distinct <c>typ</c> from <see cref="EntityStatementJwt"/> so a
    /// resolver's signed resolution cannot be mistaken for an Entity
    /// Statement.
    /// </summary>
    public static string ResolveResponseJwt { get; } = Utf8Constants.ToInternedString(ResolveResponseJwtUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ExplicitRegistrationResponseJwt"/>.</summary>
    public static ReadOnlySpan<byte> ExplicitRegistrationResponseJwtUtf8 => "explicit-registration-response+jwt"u8;

    /// <summary>
    /// <c>explicit-registration-response+jwt</c> — the Explicit Registration
    /// Response JWT a <c>federation_registration_endpoint</c> returns per
    /// <see href="https://openid.net/specs/openid-federation-connect-1_1-final.html#section-12.2">Connect-1.1 §12.2</see> / §15.1.
    /// A distinct <c>typ</c> so the OP's registration response cannot be
    /// mistaken for a self-issued Entity Configuration or a Subordinate
    /// Statement.
    /// </summary>
    public static string ExplicitRegistrationResponseJwt { get; } = Utf8Constants.ToInternedString(ExplicitRegistrationResponseJwtUtf8);

    /// <summary>The UTF-8 source literal of <see cref="TrustMarkJwt"/>.</summary>
    public static ReadOnlySpan<byte> TrustMarkJwtUtf8 => "trust-mark+jwt"u8;

    /// <summary>
    /// <c>trust-mark+jwt</c> — Trust Mark JWTs per
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-7.1">Federation §7.1</see>.
    /// </summary>
    public static string TrustMarkJwt { get; } = Utf8Constants.ToInternedString(TrustMarkJwtUtf8);

    /// <summary>The UTF-8 source literal of <see cref="TrustMarkDelegationJwt"/>.</summary>
    public static ReadOnlySpan<byte> TrustMarkDelegationJwtUtf8 => "trust-mark-delegation+jwt"u8;

    /// <summary>
    /// <c>trust-mark-delegation+jwt</c> — Trust Mark Delegation JWTs per
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-7.2">Federation §7.2</see>.
    /// </summary>
    public static string TrustMarkDelegationJwt { get; } = Utf8Constants.ToInternedString(TrustMarkDelegationJwtUtf8);

    /// <summary>The UTF-8 source literal of <see cref="HistoricalKeysJwt"/>.</summary>
    public static ReadOnlySpan<byte> HistoricalKeysJwtUtf8 => "jwk-set+jwt"u8;

    /// <summary>
    /// <c>jwk-set+jwt</c> — the signed JWK Set JWT a
    /// <c>federation_historical_keys_endpoint</c> returns per
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.7.2">Federation §8.7.2</see>,
    /// carrying the entity's historical (rotated and revoked) Federation
    /// Entity Keys. A distinct <c>typ</c> from <see cref="EntityStatementJwt"/>
    /// so a signed historical key set cannot be mistaken for an Entity
    /// Statement.
    /// </summary>
    public static string HistoricalKeysJwt { get; } = Utf8Constants.ToInternedString(HistoricalKeysJwtUtf8);

    /// <summary>The UTF-8 source literal of <see cref="TrustMarkStatusResponseJwt"/>.</summary>
    public static ReadOnlySpan<byte> TrustMarkStatusResponseJwtUtf8 => "trust-mark-status-response+jwt"u8;

    /// <summary>
    /// <c>trust-mark-status-response+jwt</c> — the signed status JWT a
    /// <c>federation_trust_mark_status_endpoint</c> returns per
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.4">Federation §8.4</see>,
    /// carrying the queried Trust Mark and its status. A distinct <c>typ</c>
    /// from <see cref="TrustMarkJwt"/> so the issuer's signed status answer
    /// cannot be mistaken for a Trust Mark itself.
    /// </summary>
    public static string TrustMarkStatusResponseJwt { get; } = Utf8Constants.ToInternedString(TrustMarkStatusResponseJwtUtf8);
}
