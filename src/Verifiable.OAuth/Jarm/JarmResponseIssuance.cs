using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.OAuth.Jarm;

/// <summary>
/// Issues the JWT Response Document of a JWT-secured authorization response per
/// <see href="https://openid.net/specs/oauth-v2-jarm-final.html#section-2.1">JARM §2.1</see>.
/// The client counterpart is <see cref="JarmResponseValidation"/>; the response-mode
/// encodings of the issued JWT live in <see cref="JarmResponseEncoding"/>.
/// </summary>
/// <remarks>
/// <para>
/// The JWT carries the transmission-securing claims — <c>iss</c> (the AS issuer URL),
/// <c>aud</c> (the client the response is intended for), <c>exp</c> (a maximum lifetime
/// of 10 minutes is RECOMMENDED) — plus every authorization endpoint response parameter
/// for the response type, success or error alike (<c>code</c>/<c>state</c>, or
/// <c>error</c>/<c>error_description</c>/<c>error_uri</c>/<c>state</c>). String
/// parameter values are JSON strings; numerical values (e.g. <c>expires_in</c>) are
/// JSON numbers — pass them as the matching .NET types.
/// </para>
/// <para>
/// The JWT is signed (JARM §2.2; this primitive does not produce the optional
/// sign-then-encrypt Nested JWT — FAPI 2.0 Message Signing §6.1 recommends against
/// response encryption). Signing flows through
/// <see cref="JwtSigningExtensions.SignAsync"/> with the JWS <c>alg</c> derived from
/// the signing key's <see cref="Tag"/> — the same JCose composition as ID Token and
/// JAR signing.
/// </para>
/// </remarks>
[DebuggerDisplay("JarmResponseIssuance")]
public static class JarmResponseIssuance
{
    /// <summary>
    /// Issues a compact-serialised, signed JWT Response Document.
    /// </summary>
    /// <param name="signingKey">The Authorization Server's response-signing key. The JWS <c>alg</c> is derived from its <see cref="Tag"/>.</param>
    /// <param name="keyId">The <c>kid</c> for the protected header, so the client selects the verification key from the AS JWKS.</param>
    /// <param name="issuer">The <c>iss</c> claim — the issuer URL of the Authorization Server that created the response.</param>
    /// <param name="clientId">The <c>aud</c> claim — the <c>client_id</c> of the client the response is intended for.</param>
    /// <param name="expiresAt">The <c>exp</c> claim instant.</param>
    /// <param name="responseParameters">
    /// The authorization endpoint response parameters for the response type — success
    /// (<c>code</c>, <c>state</c>, …) or error (<c>error</c>, <c>state</c>, …). Values
    /// are emitted as their JSON types. MUST NOT contain <c>iss</c>, <c>aud</c>, or
    /// <c>exp</c> — those are this primitive's transmission-securing claims.
    /// </param>
    /// <param name="base64UrlEncoder">Base64url encoder for compact JWS serialisation.</param>
    /// <param name="headerSerializer">Serialises the protected header to UTF-8 JSON bytes.</param>
    /// <param name="payloadSerializer">Serialises the payload claims to UTF-8 JSON bytes.</param>
    /// <param name="memoryPool">Memory pool for transient signing buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The compact-serialised JWT Response Document.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="responseParameters"/> carries a key that collides
    /// with the <c>iss</c>, <c>aud</c>, or <c>exp</c> transmission-securing claims.
    /// </exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "JwsMessage is disposed via the using statement before the method returns; the returned string is independent of the message.")]
    public static async ValueTask<string> IssueAsync(
        PrivateKeyMemory signingKey,
        string keyId,
        string issuer,
        string clientId,
        DateTimeOffset expiresAt,
        IReadOnlyDictionary<string, object> responseParameters,
        EncodeDelegate base64UrlEncoder,
        JwtHeaderSerializer headerSerializer,
        JwtPayloadSerializer payloadSerializer,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(signingKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
        ArgumentException.ThrowIfNullOrWhiteSpace(issuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        ArgumentNullException.ThrowIfNull(responseParameters);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(headerSerializer);
        ArgumentNullException.ThrowIfNull(payloadSerializer);
        ArgumentNullException.ThrowIfNull(memoryPool);

        cancellationToken.ThrowIfCancellationRequested();

        JwtPayload payload = new(capacity: 3 + responseParameters.Count)
        {
            [WellKnownJwtClaimNames.Iss] = issuer,
            [WellKnownJwtClaimNames.Aud] = clientId,
            [WellKnownJwtClaimNames.Exp] = expiresAt.ToUnixTimeSeconds()
        };

        foreach(KeyValuePair<string, object> parameter in responseParameters)
        {
            if(WellKnownJwtClaimNames.IsIss(parameter.Key)
                || WellKnownJwtClaimNames.IsAud(parameter.Key)
                || WellKnownJwtClaimNames.IsExp(parameter.Key))
            {
                throw new ArgumentException(
                    $"Response parameter '{parameter.Key}' collides with a JARM §2.1 transmission-securing claim.",
                    nameof(responseParameters));
            }

            payload[parameter.Key] = parameter.Value;
        }

        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(signingKey.Tag);
        JwtHeader header = new(capacity: 2)
        {
            [WellKnownJwkMemberNames.Alg] = algorithm,
            [WellKnownJwkMemberNames.Kid] = keyId
        };

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
}
