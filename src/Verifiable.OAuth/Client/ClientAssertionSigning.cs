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
/// draft-ietf-oauth-identity-assertion-authz-grant-04 (21 May 2026) §9.1 supports ID-JAG only for confidential clients
/// and §4.3.1 illustrates client authentication with a JWT Bearer client assertion. Composes
/// <see cref="JwtHeaderExtensions.ForSigning"/> and <see cref="JwtSigningExtensions.SignAsync(UnsignedJwt, PrivateKeyMemory, JwtHeaderSerializer, JwtPayloadSerializer, EncodeDelegate, BaseMemoryPool, CancellationToken)"/> — the
/// same JCose composition the JAR signer (<see cref="AuthCode.AuthCodeJarSigning"/>) uses.
/// </remarks>
public static class ClientAssertionSigning
{
    /// <summary>
    /// Signs a <c>private_key_jwt</c> client authentication assertion (RFC 7523 Section 3): <c>iss</c> and
    /// <c>sub</c> are both the client identifier, <c>aud</c> is the authorization server's issuer
    /// identifier (or its token endpoint), with a unique <c>jti</c> and an expiry. The protected
    /// header's <c>typ</c> is <see cref="WellKnownJwkValues.TypeJwt"/>; the overload taking
    /// <c>type</c> names another value.
    /// </summary>
    /// <param name="clientId">The client identifier, the assertion's <c>iss</c> and <c>sub</c> (RFC 7523 Section 3 rules 1-2).</param>
    /// <param name="audience">
    /// The value the assertion's <c>aud</c> names, the authorization server's issuer identifier or its
    /// token endpoint URL, written as a single JSON string (RFC 7519 Section 4.1.3), so the assertion is
    /// bound to the AS that authenticates the client (RFC 7523 Section 3 rule 3).
    /// </param>
    /// <param name="jti">A unique identifier for this assertion, enabling the AS's replay defense (RFC 7523 Section 3 rule 7).</param>
    /// <param name="issuedAt">The <c>iat</c> claim.</param>
    /// <param name="expiresAt">The <c>exp</c> claim limiting the assertion's validity window (RFC 7523 Section 3 rule 4).</param>
    /// <param name="signingKey">The client's signing key; its <see cref="Tag"/> determines the JWS <c>alg</c>.</param>
    /// <param name="signingKeyId">The <c>kid</c> header parameter value identifying the key to the AS.</param>
    /// <param name="headerSerializer">Serialises the protected header to UTF-8 JSON bytes.</param>
    /// <param name="payloadSerializer">Serialises the payload claims to UTF-8 JSON bytes.</param>
    /// <param name="base64UrlEncoder">Base64url encoder for compact JWS serialisation.</param>
    /// <param name="memoryPool">Memory pool for transient signing buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The compact-serialised client assertion (<c>header.payload.signature</c>).</returns>
    public static ValueTask<string> SignAsync(
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
        BaseMemoryPool memoryPool,
        CancellationToken cancellationToken) =>
        SignAsync(
            clientId,
            audience,
            jti,
            issuedAt,
            expiresAt,
            signingKey,
            signingKeyId,
            WellKnownJwkValues.TypeJwt,
            headerSerializer,
            payloadSerializer,
            base64UrlEncoder,
            memoryPool,
            cancellationToken);

    /// <summary>
    /// Signs a <c>private_key_jwt</c> client authentication assertion (RFC 7523 Section 3) with an
    /// explicitly named <c>typ</c> header parameter value: <c>iss</c> and <c>sub</c> are both the client
    /// identifier, <c>aud</c> is the authorization server's issuer identifier (or its token endpoint), with
    /// a unique <c>jti</c> and an expiry.
    /// </summary>
    /// <param name="clientId">The client identifier, the assertion's <c>iss</c> and <c>sub</c> (RFC 7523 Section 3 rules 1-2).</param>
    /// <param name="audience">
    /// The value the assertion's <c>aud</c> names, the authorization server's issuer identifier or its
    /// token endpoint URL, written as a single JSON string (RFC 7519 Section 4.1.3), so the assertion is
    /// bound to the AS that authenticates the client (RFC 7523 Section 3 rule 3).
    /// </param>
    /// <param name="jti">A unique identifier for this assertion, enabling the AS's replay defense (RFC 7523 Section 3 rule 7).</param>
    /// <param name="issuedAt">The <c>iat</c> claim.</param>
    /// <param name="expiresAt">The <c>exp</c> claim limiting the assertion's validity window (RFC 7523 Section 3 rule 4).</param>
    /// <param name="signingKey">The client's signing key; its <see cref="Tag"/> determines the JWS <c>alg</c>.</param>
    /// <param name="signingKeyId">The <c>kid</c> header parameter value identifying the key to the AS.</param>
    /// <param name="type">
    /// The <c>typ</c> header parameter value: <see cref="WellKnownJwkValues.TypeJwt"/> (<c>JWT</c>) or the
    /// explicit
    /// <see cref="Verifiable.JCose.WellKnownMediaTypes.Jwt.ClientAuthenticationJwt"/>
    /// (<c>client-authentication+jwt</c>) rfc7523bis-11 Section 4 defines.
    /// </param>
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
        string type,
        JwtHeaderSerializer headerSerializer,
        JwtPayloadSerializer payloadSerializer,
        EncodeDelegate base64UrlEncoder,
        BaseMemoryPool memoryPool,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        ArgumentException.ThrowIfNullOrWhiteSpace(audience);
        ArgumentException.ThrowIfNullOrWhiteSpace(jti);
        ArgumentNullException.ThrowIfNull(signingKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(signingKeyId);
        ArgumentException.ThrowIfNullOrWhiteSpace(type);
        ArgumentNullException.ThrowIfNull(headerSerializer);
        ArgumentNullException.ThrowIfNull(payloadSerializer);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(signingKey.Tag);
        JwtHeader header = JwtHeader.ForSigning(algorithm, type, signingKeyId);
        JwtPayload payload = ClaimsOf(clientId, audience, jti, issuedAt, expiresAt);

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


    /// <summary>
    /// MACs a <c>client_secret_jwt</c> client authentication assertion (OpenID Connect Core 1.0 Section 9; RFC 7523
    /// Section 2.2): the same claims <see cref="SignAsync(string, string, string, DateTimeOffset, DateTimeOffset, PrivateKeyMemory, string, string, JwtHeaderSerializer, JwtPayloadSerializer, EncodeDelegate, BaseMemoryPool, CancellationToken)"/>
    /// writes for <c>private_key_jwt</c> - <c>iss</c> and <c>sub</c> the client identifier, <c>aud</c>, a unique
    /// <c>jti</c>, <c>iat</c> and <c>exp</c> - in a JWS whose MAC is computed under the client secret the authorization
    /// server issued: "The JWT MUST be signed using an HMAC SHA algorithm, such as HMAC SHA-256. The HMAC (Hash-based
    /// Message Authentication Code) is calculated using the octets of the UTF-8 representation of the client_secret as the
    /// shared key." The protected header names <c>alg</c> and <c>typ</c> alone: the secret is the client's own, which its
    /// identifier already names, so no <c>kid</c> is written. The MAC is computed through the registered
    /// <see cref="ComputeHmacDelegate"/> (<see cref="CryptographicKeyEvents.ComputeHmacAsync(ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, int, Tag, BaseMemoryPool, System.Collections.Frozen.FrozenDictionary{string, object}?, string?, CancellationToken)"/>),
    /// the library's one seam for an HMAC.
    /// </summary>
    /// <param name="clientId">The client identifier, the assertion's <c>iss</c> and <c>sub</c> (RFC 7523 Section 3 rules 1-2).</param>
    /// <param name="audience">The value the assertion's <c>aud</c> names, written as a single JSON string (RFC 7519 Section 4.1.3).</param>
    /// <param name="jti">A unique identifier for this assertion, enabling the AS's replay defense (RFC 7523 Section 3 rule 7).</param>
    /// <param name="issuedAt">The <c>iat</c> claim.</param>
    /// <param name="expiresAt">The <c>exp</c> claim limiting the assertion's validity window (RFC 7523 Section 3 rule 4).</param>
    /// <param name="clientSecret">The octets of the UTF-8 representation of the client secret, the MAC's key.</param>
    /// <param name="algorithm">
    /// The JWS <c>alg</c> the assertion is MACed under, one of RFC 7518 Section 3.2's HMAC algorithms:
    /// <see cref="WellKnownJwaValues.Hs256"/>, <see cref="WellKnownJwaValues.Hs384"/> or <see cref="WellKnownJwaValues.Hs512"/>.
    /// </param>
    /// <param name="type">
    /// The <c>typ</c> header parameter value: <see cref="WellKnownJwkValues.TypeJwt"/> (<c>JWT</c>) or the explicit
    /// <see cref="Verifiable.JCose.WellKnownMediaTypes.Jwt.ClientAuthenticationJwt"/> rfc7523bis-11 Section 4 defines.
    /// </param>
    /// <param name="headerSerializer">Serialises the protected header to UTF-8 JSON bytes.</param>
    /// <param name="payloadSerializer">Serialises the payload claims to UTF-8 JSON bytes.</param>
    /// <param name="base64UrlEncoder">Base64url encoder for compact JWS serialisation.</param>
    /// <param name="memoryPool">Memory pool for transient signing buffers and the MAC.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The compact-serialised client assertion (<c>header.payload.signature</c>).</returns>
    /// <exception cref="ArgumentException">
    /// <paramref name="algorithm"/> is none of the three HMAC algorithms, or <paramref name="clientSecret"/> is shorter than
    /// its hash output: RFC 7518 Section 3.2, "A key of the same size as the hash output (for instance, 256 bits for "HS256")
    /// or larger MUST be used with this algorithm."
    /// </exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "JwsMessage is disposed via the using statement before the method returns; the returned string is independent of the message.")]
    public static async ValueTask<string> SignWithClientSecretAsync(
        string clientId,
        string audience,
        string jti,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        PrivateKeyMemory clientSecret,
        string algorithm,
        string type,
        JwtHeaderSerializer headerSerializer,
        JwtPayloadSerializer payloadSerializer,
        EncodeDelegate base64UrlEncoder,
        BaseMemoryPool memoryPool,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        ArgumentException.ThrowIfNullOrWhiteSpace(audience);
        ArgumentException.ThrowIfNullOrWhiteSpace(jti);
        ArgumentNullException.ThrowIfNull(clientSecret);
        ArgumentException.ThrowIfNullOrWhiteSpace(algorithm);
        ArgumentException.ThrowIfNullOrWhiteSpace(type);
        ArgumentNullException.ThrowIfNull(headerSerializer);
        ArgumentNullException.ThrowIfNull(payloadSerializer);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

        ClientSecretMac mac = ClientSecretMac.Of(algorithm);
        int secretLength = clientSecret.AsReadOnlySpan().Length;

        if(secretLength < mac.Length)
        {
            throw new ArgumentException(
                $"RFC 7518 Section 3.2: a key of the same size as the hash output or larger MUST be used with {algorithm}; "
                + $"the client secret carries {secretLength} octets and {algorithm} needs {mac.Length}.",
                nameof(clientSecret));
        }

        //OpenID Connect Core 1.0 Section 9: the secret is the client's own, named by its identifier, so the header names
        //no kid; alg names the HMAC algorithm and typ the assertion's type.
        JwtHeader header = new(capacity: 2)
        {
            [WellKnownJwkMemberNames.Alg] = algorithm,
            [WellKnownJoseHeaderNames.Typ] = type
        };

        UnsignedJwt unsigned = new(header, ClaimsOf(clientId, audience, jti, issuedAt, expiresAt));
        using JwsMessage jws = await unsigned.SignAsync(
            clientSecret,
            headerSerializer,
            payloadSerializer,
            base64UrlEncoder,
            mac.SignAsync,
            memoryPool,
            eventSink: null,
            cancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(jws, base64UrlEncoder);
    }


    /// <summary>
    /// The claims of a client authentication assertion (RFC 7523 Section 3): for client authentication <c>iss</c> and
    /// <c>sub</c> are both the client_id; <c>aud</c> is the AS issuer identifier (or its token endpoint); <c>jti</c> is
    /// unique (replay defense) and <c>exp</c> bounds the validity window from <c>iat</c>.
    /// </summary>
    /// <param name="clientId">The client identifier.</param>
    /// <param name="audience">The audience value.</param>
    /// <param name="jti">The assertion's identifier.</param>
    /// <param name="issuedAt">The <c>iat</c> claim.</param>
    /// <param name="expiresAt">The <c>exp</c> claim.</param>
    /// <returns>The claims, in the order every client assertion carries them.</returns>
    private static JwtPayload ClaimsOf(string clientId, string audience, string jti, DateTimeOffset issuedAt, DateTimeOffset expiresAt) =>
        new(capacity: 6)
        {
            [WellKnownJwtClaimNames.Iss] = clientId,
            [WellKnownJwtClaimNames.Sub] = clientId,
            [WellKnownJwtClaimNames.Aud] = audience,
            [WellKnownJwtClaimNames.Jti] = jti,
            [WellKnownJwtClaimNames.Iat] = issuedAt.ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Exp] = expiresAt.ToUnixTimeSeconds()
        };
}
