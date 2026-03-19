using System.Diagnostics.CodeAnalysis;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Surfaces the library's built-in <see cref="TokenProducer"/> instances on the
/// <see cref="TokenProducer"/> type itself for IntelliSense discoverability.
/// </summary>
/// <remarks>
/// <para>
/// Applications add their own producers in extension blocks that target the same
/// type, and their entries appear alongside the library's:
/// </para>
/// <code>
/// public static class MyTokenProducerExtensions
/// {
///     extension(TokenProducer)
///     {
///         public static TokenProducer MyLogoutToken => MyLogoutTokenProducer.Instance;
///         public static TokenProducer MyRefreshToken => MyRefreshTokenProducer.Instance;
///     }
/// }
///
/// options.TokenProducers =
/// [
///     TokenProducer.Rfc9068AccessToken,
///     TokenProducer.Oidc10IdToken,
///     TokenProducer.MyLogoutToken,
///     TokenProducer.MyRefreshToken
/// ];
/// </code>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible",
    Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class TokenProducerExtensions
{
    extension(TokenProducer)
    {
        /// <summary>
        /// Producer for OAuth 2.0 JWT access tokens per
        /// <see href="https://www.rfc-editor.org/rfc/rfc9068">RFC 9068</see>.
        /// </summary>
        /// <remarks>
        /// Applies to every token-endpoint request. Resolves a signing key from
        /// <see cref="Verifiable.Cryptography.Context.KeyUsageContext.TokenIssuance"/>
        /// and emits a payload with the RFC 9068 claim set
        /// (<c>iss</c>, <c>sub</c>, <c>aud</c>, <c>exp</c>, <c>iat</c>, <c>jti</c>,
        /// <c>scope</c>, <c>client_id</c>) plus <c>typ=at+jwt</c>.
        /// </remarks>
        public static TokenProducer Rfc9068AccessToken => Rfc9068AccessTokenProducer.Instance;


        /// <summary>
        /// Producer for OpenID Connect ID Tokens per
        /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OIDC Core §2</see>.
        /// </summary>
        /// <remarks>
        /// Applies only when <c>openid</c> is in the granted scope. Resolves a
        /// signing key from
        /// <see cref="Verifiable.Cryptography.Context.KeyUsageContext.IdTokenIssuance"/>
        /// and emits the OIDC Core claim set (<c>iss</c>, <c>sub</c>, <c>aud</c>,
        /// <c>exp</c>, <c>iat</c>, plus <c>nonce</c> and <c>auth_time</c> when
        /// available on the issuance context).
        /// </remarks>
        public static TokenProducer Oidc10IdToken => Oidc10IdTokenProducer.Instance;
    }
}
