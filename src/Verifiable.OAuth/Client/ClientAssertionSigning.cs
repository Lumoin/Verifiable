using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.OAuth.Client;

/// <summary>
/// Builds and signs a client authentication assertion per
/// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-2.2">RFC 7523 §2.2</see> and the §3
/// processing rules (with the assertion-framework requirements of
/// <see href="https://www.rfc-editor.org/rfc/rfc7521#section-4.2">RFC 7521 §4.2</see>): the <c>private_key_jwt</c>
/// assertion signed with the client's registered key, and the <c>client_secret_jwt</c> assertion MACed with the client
/// secret (OpenID Connect Core 1.0 §9), both composed once, by
/// <see cref="SignAsync(string, string, string, DateTimeOffset, DateTimeOffset, ClientAssertionKey, string, JwtHeaderSerializer, JwtPayloadSerializer, EncodeDelegate, BaseMemoryPool, CancellationToken)"/>,
/// the <see cref="ClientAssertionKey"/> supplying the header inputs and the signing operation. The client presents the
/// resulting compact JWS as the <c>client_assertion</c> token-endpoint parameter, paired with
/// <c>client_assertion_type</c> = <c>urn:ietf:params:oauth:client-assertion-type:jwt-bearer</c>.
/// </summary>
/// <remarks>
/// This is general confidential-client authentication, reusable by every confidential token call. It is
/// what an ID-JAG client uses to authenticate at both the IdP's Token Exchange endpoint (the mint) and
/// the Resource Authorization Server's JWT Bearer endpoint (the redeem), since
/// draft-ietf-oauth-identity-assertion-authz-grant-04 (21 May 2026) §9.1 supports ID-JAG only for confidential clients
/// and §4.3.1 illustrates client authentication with a JWT Bearer client assertion. Composes
/// <see cref="JwtHeaderExtensions.ForSigning"/> and <see cref="JwtSigningExtensions.SignAsync(UnsignedJwt, PrivateKeyMemory, JwtHeaderSerializer, JwtPayloadSerializer, EncodeDelegate, SigningDelegate, BaseMemoryPool, CryptoEventSink?, CancellationToken)"/> — the
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
            ClientAssertionKey.OfPrivateKey(signingKey, signingKeyId),
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
    public static ValueTask<string> SignAsync(
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
        CancellationToken cancellationToken) =>
        SignAsync(
            clientId,
            audience,
            jti,
            issuedAt,
            expiresAt,
            ClientAssertionKey.OfPrivateKey(signingKey, signingKeyId),
            type,
            headerSerializer,
            payloadSerializer,
            base64UrlEncoder,
            memoryPool,
            cancellationToken);


    /// <summary>
    /// Composes a client authentication assertion under its key, the one composition every client assertion is assembled
    /// by: the protected header the key supplies - its <c>alg</c>, the <c>typ</c> named here and its <c>kid</c> when it
    /// names one, a <c>client_secret_jwt</c> secret naming none (OpenID Connect Core 1.0 Section 9) - over RFC 7523
    /// Section 3's claims, <c>iss</c> and <c>sub</c> the client identifier, <c>aud</c>, a unique <c>jti</c>, <c>iat</c> and
    /// <c>exp</c>, signed with the key's own signing operation and serialized compact.
    /// </summary>
    /// <param name="clientId">The client identifier, the assertion's <c>iss</c> and <c>sub</c> (RFC 7523 Section 3 rules 1-2).</param>
    /// <param name="audience">
    /// The value the assertion's <c>aud</c> names, written as a single JSON string (RFC 7519 Section 4.1.3), so the assertion
    /// is bound to the AS that authenticates the client (RFC 7523 Section 3 rule 3).
    /// </param>
    /// <param name="jti">A unique identifier for this assertion, enabling the AS's replay defense (RFC 7523 Section 3 rule 7).</param>
    /// <param name="issuedAt">The <c>iat</c> claim.</param>
    /// <param name="expiresAt">The <c>exp</c> claim limiting the assertion's validity window (RFC 7523 Section 3 rule 4).</param>
    /// <param name="key">The key the assertion is signed under, supplying the header's <c>alg</c> and <c>kid</c> and the signing operation.</param>
    /// <param name="type">
    /// The <c>typ</c> header parameter value: <see cref="WellKnownJwkValues.TypeJwt"/> (<c>JWT</c>) or the explicit
    /// <see cref="Verifiable.JCose.WellKnownMediaTypes.Jwt.ClientAuthenticationJwt"/> rfc7523bis-11 Section 4 defines.
    /// </param>
    /// <param name="headerSerializer">Serialises the protected header to UTF-8 JSON bytes.</param>
    /// <param name="payloadSerializer">Serialises the payload claims to UTF-8 JSON bytes.</param>
    /// <param name="base64UrlEncoder">Base64url encoder for compact JWS serialisation.</param>
    /// <param name="memoryPool">Memory pool for transient signing buffers and the signature.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The compact-serialised client assertion (<c>header.payload.signature</c>).</returns>
    public static async ValueTask<string> SignAsync(
        string clientId,
        string audience,
        string jti,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        ClientAssertionKey key,
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
        ArgumentNullException.ThrowIfNull(key);
        ArgumentException.ThrowIfNullOrWhiteSpace(type);
        ArgumentNullException.ThrowIfNull(headerSerializer);
        ArgumentNullException.ThrowIfNull(payloadSerializer);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

        var unsigned = new UnsignedJwt(HeaderOf(key, type), ClaimsOf(clientId, audience, jti, issuedAt, expiresAt));
        using var jws = await unsigned.SignAsync(
            key.Key,
            headerSerializer,
            payloadSerializer,
            base64UrlEncoder,
            key.Sign,
            memoryPool,
            eventSink: null,
            cancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(jws, base64UrlEncoder);
    }


    /// <summary>
    /// The protected header of a client authentication assertion: the <c>alg</c> its key names, the <c>typ</c>, and the
    /// <c>kid</c> of a key naming one (RFC 7515 Section 4.1.4); a client secret names none, being the client's own, which its
    /// identifier already names (OpenID Connect Core 1.0 Section 9).
    /// </summary>
    /// <param name="key">The key the assertion is signed under.</param>
    /// <param name="type">The <c>typ</c> value.</param>
    /// <returns>The header.</returns>
    private static JwtHeader HeaderOf(ClientAssertionKey key, string type) =>
        key.KeyId is string keyId
            ? JwtHeader.ForSigning(key.Algorithm, type, keyId)
            : new JwtHeader(capacity: 2)
            {
                [WellKnownJwkMemberNames.Alg] = key.Algorithm,
                [WellKnownJoseHeaderNames.Typ] = type
            };


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
