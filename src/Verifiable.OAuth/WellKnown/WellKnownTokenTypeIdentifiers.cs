using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.WellKnown;

/// <summary>
/// The RFC 8693 §3 token type identifiers — the <c>urn:ietf:params:oauth:token-type:*</c> URIs carried as
/// the <c>subject_token_type</c>, <c>actor_token_type</c>, <c>requested_token_type</c>, and
/// <c>issued_token_type</c> wire values. Distinct from <see cref="WellKnownTokenTypes"/>, which holds the
/// short token-response field names (<c>access_token</c> and the like).
/// </summary>
/// <remarks>
/// Each value is the IANA-registered token-type URI; the companion <see cref="Client.TokenTypeNames"/>
/// maps typed <see cref="Client.TokenType"/> values to and from these. Comparison is ordinal.
/// </remarks>
public static class WellKnownTokenTypeIdentifiers
{
    /// <summary>The UTF-8 source literal of <see cref="AccessToken"/>.</summary>
    public static ReadOnlySpan<byte> AccessTokenUtf8 => "urn:ietf:params:oauth:token-type:access_token"u8;

    /// <summary>The RFC 8693 §3 access token type identifier.</summary>
    public static readonly string AccessToken = Utf8Constants.ToInternedString(AccessTokenUtf8);

    /// <summary>The UTF-8 source literal of <see cref="RefreshToken"/>.</summary>
    public static ReadOnlySpan<byte> RefreshTokenUtf8 => "urn:ietf:params:oauth:token-type:refresh_token"u8;

    /// <summary>The RFC 8693 §3 refresh token type identifier.</summary>
    public static readonly string RefreshToken = Utf8Constants.ToInternedString(RefreshTokenUtf8);

    /// <summary>The UTF-8 source literal of <see cref="IdToken"/>.</summary>
    public static ReadOnlySpan<byte> IdTokenUtf8 => "urn:ietf:params:oauth:token-type:id_token"u8;

    /// <summary>The RFC 8693 §3 OpenID Connect ID Token type identifier.</summary>
    public static readonly string IdToken = Utf8Constants.ToInternedString(IdTokenUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Saml1"/>.</summary>
    public static ReadOnlySpan<byte> Saml1Utf8 => "urn:ietf:params:oauth:token-type:saml1"u8;

    /// <summary>The RFC 8693 §3 SAML 1.1 assertion type identifier.</summary>
    public static readonly string Saml1 = Utf8Constants.ToInternedString(Saml1Utf8);

    /// <summary>The UTF-8 source literal of <see cref="Saml2"/>.</summary>
    public static ReadOnlySpan<byte> Saml2Utf8 => "urn:ietf:params:oauth:token-type:saml2"u8;

    /// <summary>The RFC 8693 §3 SAML 2.0 assertion type identifier.</summary>
    public static readonly string Saml2 = Utf8Constants.ToInternedString(Saml2Utf8);

    /// <summary>The UTF-8 source literal of <see cref="Jwt"/>.</summary>
    public static ReadOnlySpan<byte> JwtUtf8 => "urn:ietf:params:oauth:token-type:jwt"u8;

    /// <summary>The RFC 8693 §3 JSON Web Token type identifier.</summary>
    public static readonly string Jwt = Utf8Constants.ToInternedString(JwtUtf8);

    /// <summary>The UTF-8 source literal of <see cref="IdJag"/>.</summary>
    public static ReadOnlySpan<byte> IdJagUtf8 => "urn:ietf:params:oauth:token-type:id-jag"u8;

    /// <summary>
    /// The Identity Assertion JWT Authorization Grant token type identifier
    /// (draft-ietf-oauth-identity-assertion-authz-grant-04 (21 May 2026) §4.3 / §10.2).
    /// </summary>
    public static readonly string IdJag = Utf8Constants.ToInternedString(IdJagUtf8);

    /// <summary>The UTF-8 source literal of <see cref="NotApplicable"/>.</summary>
    public static ReadOnlySpan<byte> NotApplicableUtf8 => "N_A"u8;

    /// <summary>
    /// The <c>N_A</c> value the token endpoint's <c>token_type</c> response field carries when the issued
    /// token is not an OAuth access token — e.g. an ID-JAG returned in <c>access_token</c> for historical
    /// reasons (draft-ietf-oauth-identity-assertion-authz-grant-04 §4.3.4 / RFC 8693 §2.2.1).
    /// </summary>
    public static readonly string NotApplicable = Utf8Constants.ToInternedString(NotApplicableUtf8);


    /// <summary>Whether <paramref name="value"/> is <see cref="AccessToken"/>.</summary>
    public static bool IsAccessToken(string value) => string.Equals(value, AccessToken, StringComparison.Ordinal);

    /// <summary>Whether <paramref name="value"/> is <see cref="RefreshToken"/>.</summary>
    public static bool IsRefreshToken(string value) => string.Equals(value, RefreshToken, StringComparison.Ordinal);

    /// <summary>Whether <paramref name="value"/> is <see cref="IdToken"/>.</summary>
    public static bool IsIdToken(string value) => string.Equals(value, IdToken, StringComparison.Ordinal);

    /// <summary>Whether <paramref name="value"/> is <see cref="Saml1"/>.</summary>
    public static bool IsSaml1(string value) => string.Equals(value, Saml1, StringComparison.Ordinal);

    /// <summary>Whether <paramref name="value"/> is <see cref="Saml2"/>.</summary>
    public static bool IsSaml2(string value) => string.Equals(value, Saml2, StringComparison.Ordinal);

    /// <summary>Whether <paramref name="value"/> is <see cref="Jwt"/>.</summary>
    public static bool IsJwt(string value) => string.Equals(value, Jwt, StringComparison.Ordinal);

    /// <summary>Whether <paramref name="value"/> is <see cref="IdJag"/>.</summary>
    public static bool IsIdJag(string value) => string.Equals(value, IdJag, StringComparison.Ordinal);
}
