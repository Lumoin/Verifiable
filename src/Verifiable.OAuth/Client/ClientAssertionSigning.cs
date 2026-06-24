using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.OAuth.Client;

/// <summary>
/// Builds and signs a client authentication assertion for the <c>private_key_jwt</c> client
/// authentication method per
/// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-2.2">RFC 7523 §2.2</see> and the §3
/// processing rules (with the assertion-framework requirements of
/// <see href="https://www.rfc-editor.org/rfc/rfc7521#section-4.2">RFC 7521 §4.2</see>). The client
/// presents the resulting compact JWS as the <c>client_assertion</c> token-endpoint parameter, paired
/// with <c>client_assertion_type</c> =
/// <c>urn:ietf:params:oauth:client-assertion-type:jwt-bearer</c>, proving possession of its registered
/// signing key without transmitting a shared secret.
/// </summary>
/// <remarks>
/// This is general confidential-client authentication, reusable by every confidential token call. It is
/// what an ID-JAG client uses to authenticate at both the IdP's Token Exchange endpoint (the mint) and
/// the Resource Authorization Server's JWT Bearer endpoint (the redeem), since
/// draft-ietf-oauth-identity-assertion-authz-grant §9.1 supports ID-JAG only for confidential clients
/// and §4.3.1 illustrates client authentication with a JWT Bearer client assertion. Composes
/// <see cref="JwtHeaderExtensions.ForSigning"/> and <see cref="JwtSigningExtensions.SignAsync"/> — the
/// same JCose composition the JAR signer (<see cref="AuthCode.AuthCodeJarSigning"/>) uses.
/// </remarks>
[DebuggerDisplay("ClientAssertionSigning")]
public static class ClientAssertionSigning
{
    /// <summary>
    /// Signs a <c>private_key_jwt</c> client authentication assertion (RFC 7523 §3): <c>iss</c> and
    /// <c>sub</c> are both the client identifier, <c>aud</c> is the authorization server's token endpoint
    /// (or issuer) identifier, with a unique <c>jti</c> and an expiry.
    /// </summary>
    /// <param name="clientId">The client identifier — the assertion's <c>iss</c> and <c>sub</c> (RFC 7523 §3 rules 1–2).</param>
    /// <param name="audience">
    /// The value the assertion's <c>aud</c> names — the authorization server's token endpoint URL or its
    /// issuer identifier — so the assertion is bound to the AS that authenticates the client (RFC 7523 §3 rule 3).
    /// </param>
    /// <param name="jti">A unique identifier for this assertion, enabling the AS's replay defense (RFC 7523 §3 rule 7).</param>
    /// <param name="issuedAt">The <c>iat</c> claim.</param>
    /// <param name="expiresAt">The <c>exp</c> claim limiting the assertion's validity window (RFC 7523 §3 rule 4).</param>
    /// <param name="signingKey">The client's signing key; its <see cref="Tag"/> determines the JWS <c>alg</c>.</param>
    /// <param name="signingKeyId">The <c>kid</c> header parameter value identifying the key to the AS.</param>
    /// <param name="headerSerializer">Serialises the protected header to UTF-8 JSON bytes.</param>
    /// <param name="payloadSerializer">Serialises the payload claims to UTF-8 JSON bytes.</param>
    /// <param name="base64UrlEncoder">Base64url encoder for compact JWS serialisation.</param>
    /// <param name="memoryPool">Memory pool for transient signing buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The compact-serialised client assertion (<c>header.payload.signature</c>).</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "JwsMessage is disposed via the using statement before the method returns; the returned string is independent of the message.")]
    public static async ValueTask<string> SignAsync(
        string clientId,
        string audience,
        string jti,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        PrivateKeyMemory signingKey,
        string signingKeyId,
        JwtHeaderSerializer headerSerializer,
        JwtPayloadSerializer payloadSerializer,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        ArgumentException.ThrowIfNullOrWhiteSpace(audience);
        ArgumentException.ThrowIfNullOrWhiteSpace(jti);
        ArgumentNullException.ThrowIfNull(signingKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(signingKeyId);
        ArgumentNullException.ThrowIfNull(headerSerializer);
        ArgumentNullException.ThrowIfNull(payloadSerializer);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(signingKey.Tag);
        JwtHeader header = JwtHeader.ForSigning(algorithm, WellKnownJwkValues.TypeJwt, signingKeyId);

        //RFC 7523 §3: for client authentication iss and sub are both the client_id; aud is the AS token
        //endpoint (or issuer); jti is unique (replay defense) and exp bounds the validity window.
        JwtPayload payload = new(capacity: 6)
        {
            [WellKnownJwtClaimNames.Iss] = clientId,
            [WellKnownJwtClaimNames.Sub] = clientId,
            [WellKnownJwtClaimNames.Aud] = audience,
            [WellKnownJwtClaimNames.Jti] = jti,
            [WellKnownJwtClaimNames.Iat] = issuedAt.ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Exp] = expiresAt.ToUnixTimeSeconds()
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
