using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.OAuth.AuthCode;

/// <summary>
/// Builds and signs an AuthCode JAR (JWT Authorization Request) per
/// <see href="https://www.rfc-editor.org/rfc/rfc9101">RFC 9101</see>.
/// </summary>
/// <remarks>
/// <para>
/// The JAR carries the Authorization Request claims as JWT payload, signed by
/// the client. The Authorization Server validates the signature, projects the
/// payload into <see cref="AuthCodeRequestObject"/>, and threads the
/// PKCE/scope/redirect_uri claims through to its PAR or Authorize handler.
/// </para>
/// <para>
/// Composes <see cref="JwtHeaderExtensions.ForJar"/> for the protected header
/// (with <c>typ = oauth-authz-req+jwt</c> per RFC 9101 §4) and
/// <see cref="JwtSigningExtensions.SignAsync"/> for the JWS — the same JCose
/// composition pattern used by OID4VP JAR signing, token issuance, and the
/// Verifier attestation pipeline.
/// </para>
/// </remarks>
[DebuggerDisplay("AuthCodeJarSigning")]
public static class AuthCodeJarSigning
{
    /// <summary>
    /// Signs an AuthCode JAR carrying the supplied request claims.
    /// </summary>
    /// <param name="requestObject">The AuthCode-shaped claim set to sign as the JAR payload.</param>
    /// <param name="signingKey">The client's JAR signing key. Tag determines the JWS <c>alg</c>.</param>
    /// <param name="signingKeyId">The <c>kid</c> header parameter value.</param>
    /// <param name="headerSerializer">Serialises the JAR protected header to UTF-8 JSON bytes.</param>
    /// <param name="payloadSerializer">Serialises the JAR payload claims to UTF-8 JSON bytes.</param>
    /// <param name="base64UrlEncoder">Base64url encoder for compact JWS serialisation.</param>
    /// <param name="memoryPool">Memory pool for transient signing buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The compact-serialised JAR (<c>header.payload.signature</c>).</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "JwsMessage is disposed via the using statement before the method returns; the returned string is independent of the message.")]
    public static async ValueTask<string> SignAsync(
        AuthCodeRequestObject requestObject,
        PrivateKeyMemory signingKey,
        string signingKeyId,
        JwtHeaderSerializer headerSerializer,
        JwtPayloadSerializer payloadSerializer,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestObject);
        ArgumentNullException.ThrowIfNull(signingKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(signingKeyId);
        ArgumentNullException.ThrowIfNull(headerSerializer);
        ArgumentNullException.ThrowIfNull(payloadSerializer);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(signingKey.Tag);
        JwtHeader header = JwtHeaderExtensions.ForJar(algorithm, signingKeyId);
        JwtPayload payload = BuildPayload(requestObject);

        UnsignedJwt unsigned = new(header, payload);
        using JwsMessage jws = await unsigned.SignAsync(
            signingKey,
            headerSerializer,
            payloadSerializer,
            base64UrlEncoder,
            memoryPool,
            cancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(jws, base64UrlEncoder);
    }


    private static JwtPayload BuildPayload(AuthCodeRequestObject requestObject)
    {
        JwtPayload payload = new(capacity: 13)
        {
            [OAuthRequestParameters.ClientId] = requestObject.ClientId,
            [OAuthRequestParameters.ResponseType] = requestObject.ResponseType,
            [OAuthRequestParameters.RedirectUri] = requestObject.RedirectUri.ToString(),
            [OAuthRequestParameters.Scope] = requestObject.Scope,
            [OAuthRequestParameters.State] = requestObject.State,
            [WellKnownJwtClaims.Nonce] = requestObject.Nonce,
            [OAuthRequestParameters.CodeChallenge] = requestObject.CodeChallenge,
            [OAuthRequestParameters.CodeChallengeMethod] = requestObject.CodeChallengeMethod,
            [WellKnownJwtClaims.Iat] = requestObject.Iat.ToUnixTimeSeconds(),
            [WellKnownJwtClaims.Nbf] = requestObject.Nbf.ToUnixTimeSeconds(),
            [WellKnownJwtClaims.Exp] = requestObject.Exp.ToUnixTimeSeconds()
        };

        if(requestObject.Iss is string iss)
        {
            payload[WellKnownJwtClaims.Iss] = iss;
        }

        if(requestObject.Aud is string aud)
        {
            payload[WellKnownJwtClaims.Aud] = aud;
        }

        if(requestObject.Jti is string jti)
        {
            payload[WellKnownJwtClaims.Jti] = jti;
        }

        return payload;
    }
}
