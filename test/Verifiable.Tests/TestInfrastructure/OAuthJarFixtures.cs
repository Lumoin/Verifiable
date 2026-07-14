using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.Tests.OAuth;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Shared JAR (JWT-secured Authorization Request, RFC 9101) claim assembly and compact JWS
/// signing for the AuthCode JAR-by-value and JAR-PAR test corpus, built on the production
/// <see cref="UnsignedJwt"/> signing writer (<c>JwtSigningExtensions.SignAsync</c>).
/// </summary>
internal static class OAuthJarFixtures
{
    private static readonly JwtHeaderSerializer JwtHeaderSerializerDelegate =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    private static readonly JwtPayloadSerializer JwtPayloadSerializerDelegate =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload,
            TestSetup.DefaultSerializationOptions);


    /// <summary>
    /// Builds the base RFC 9101 request-object claim set: <c>iss</c>/<c>client_id</c> equal to
    /// <paramref name="clientId"/>, <c>aud</c> equal to <paramref name="material"/>'s registered
    /// issuer URL, a PKCE S256 challenge, and a 30-second <c>iat</c>/<c>nbf</c>/<c>exp</c> window
    /// anchored at <paramref name="now"/>.
    /// </summary>
    /// <param name="material">The registered client's key material; supplies the expected audience.</param>
    /// <param name="now">The instant the <c>iat</c>/<c>nbf</c>/<c>exp</c> window is anchored to.</param>
    /// <param name="clientId">The <c>iss</c>/<c>client_id</c> claim value.</param>
    /// <param name="redirectUri">The <c>redirect_uri</c> claim value.</param>
    /// <param name="state">The <c>state</c> claim value.</param>
    /// <param name="nonce">The <c>nonce</c> claim value.</param>
    /// <returns>The mutable claim dictionary, ready for per-test overrides before signing.</returns>
    internal static Dictionary<string, object> BuildBaseClaims(
        VerifierKeyMaterial material,
        DateTimeOffset now,
        string clientId,
        Uri redirectUri,
        string state,
        string nonce)
    {
        string expectedAud = material.Registration.IssuerUri!.ToString();

        return new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Iss] = clientId,
            [WellKnownJwtClaimNames.Aud] = expectedAud,
            [WellKnownJwtClaimNames.ClientId] = clientId,
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.RedirectUri] = redirectUri.ToString(),
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId,
            [OAuthRequestParameterNames.State] = state,
            [WellKnownJwtClaimNames.Nonce] = nonce,
            [OAuthRequestParameterNames.CodeChallenge] = "abcdEFGHijklMNOPqrstUVWXyz0123456789-_AAA",
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [WellKnownJwtClaimNames.Iat] = now.ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Nbf] = now.ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Exp] = (now + TimeSpan.FromSeconds(30)).ToUnixTimeSeconds()
        };
    }


    /// <summary>
    /// Signs <paramref name="claims"/> as a compact JWS using <paramref name="material"/>'s
    /// registered signing key and the <c>oauth-authz-req+jwt</c> <c>typ</c> header.
    /// </summary>
    /// <param name="material">Supplies the signing key.</param>
    /// <param name="claims">The request-object claim set.</param>
    /// <param name="cancellationToken">Propagates cancellation to the signing call.</param>
    /// <returns>The compact-serialized signed JAR.</returns>
    internal static async Task<string> BuildSignedJarAsync(
        VerifierKeyMaterial material,
        IReadOnlyDictionary<string, object> claims,
        CancellationToken cancellationToken)
    {
        return await BuildSignedJarWithKeyAsync(
            material.SigningPrivateKey, claims, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Signs <paramref name="claims"/> as a compact JWS with <paramref name="signingKey"/> and the
    /// <c>oauth-authz-req+jwt</c> <c>typ</c> header.
    /// </summary>
    /// <param name="signingKey">The key to sign with.</param>
    /// <param name="claims">The request-object claim set.</param>
    /// <param name="cancellationToken">Propagates cancellation to the signing call.</param>
    /// <returns>The compact-serialized signed JAR.</returns>
    internal static async Task<string> BuildSignedJarWithKeyAsync(
        PrivateKeyMemory signingKey,
        IReadOnlyDictionary<string, object> claims,
        CancellationToken cancellationToken)
    {
        return await BuildSignedJarWithCustomTypAsync(
            signingKey,
            WellKnownMediaTypes.Jwt.OauthAuthzReqJwt,
            claims,
            cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Signs <paramref name="claims"/> as a compact JWS with <paramref name="signingKey"/> and an
    /// explicit <paramref name="typValue"/> <c>typ</c> header, for exercising <c>typ</c> rejection.
    /// </summary>
    /// <param name="signingKey">The key to sign with.</param>
    /// <param name="typValue">The <c>typ</c> header value.</param>
    /// <param name="claims">The request-object claim set.</param>
    /// <param name="cancellationToken">Propagates cancellation to the signing call.</param>
    /// <returns>The compact-serialized signed JAR.</returns>
    internal static async Task<string> BuildSignedJarWithCustomTypAsync(
        PrivateKeyMemory signingKey,
        string typValue,
        IReadOnlyDictionary<string, object> claims,
        CancellationToken cancellationToken)
    {
        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(signingKey.Tag);

        JwtHeader header = new()
        {
            [WellKnownJwkMemberNames.Alg] = algorithm,
            [WellKnownJoseHeaderNames.Typ] = typValue
        };

        JwtPayload payload = new();
        foreach(KeyValuePair<string, object> entry in claims)
        {
            payload[entry.Key] = entry.Value;
        }

        UnsignedJwt unsigned = new(header, payload);
        using JwsMessage signed = await unsigned.SignAsync(
            signingKey,
            JwtHeaderSerializerDelegate,
            JwtPayloadSerializerDelegate,
            TestSetup.Base64UrlEncoder,
            BaseMemoryPool.Shared,
            cancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(signed, TestSetup.Base64UrlEncoder);
    }
}
