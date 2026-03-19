using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Builds Verifier Attestation JWTs as defined in
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-12">OID4VP 1.0 §12</see>.
/// </summary>
/// <remarks>
/// <para>
/// A Verifier Attestation JWT is issued by a trust anchor and carried in the <c>jwt</c>
/// JOSE header parameter of a signed JAR when the <c>verifier_attestation:</c> Client
/// Identifier Prefix is used. It proves that the Verifier is a legitimate client
/// registered within the trust framework.
/// </para>
/// <para>
/// In production, the trust anchor issues and signs the attestation out-of-band. The
/// Verifier stores it and embeds it in JAR headers for each Authorization Request.
/// <see cref="BuildAsync"/> is used by trust anchor implementations to produce the JWT;
/// the Verifier uses it only once during onboarding.
/// </para>
/// </remarks>
public static class VerifierAttestationIssuer
{
    /// <summary>
    /// Builds and signs a Verifier Attestation JWT.
    /// </summary>
    /// <param name="issuer">
    /// The <c>iss</c> claim — the Entity Identifier of the trust anchor issuing the
    /// attestation.
    /// </param>
    /// <param name="subject">
    /// The <c>sub</c> claim — the Client Identifier of the Verifier, without the
    /// <c>verifier_attestation:</c> prefix.
    /// </param>
    /// <param name="verifierSigningPublicKey">
    /// The Verifier's JAR signing public key to embed in the <c>cnf.jwk</c> claim.
    /// The Wallet uses this key to verify the JAR signature.
    /// </param>
    /// <param name="trustAnchorPrivateKey">
    /// The trust anchor's private signing key. Used to sign the attestation JWT.
    /// </param>
    /// <param name="issuedAt">The UTC instant at which the attestation is issued.</param>
    /// <param name="expiresAt">The UTC instant at which the attestation expires.</param>
    /// <param name="headerSerializer">Delegate for serializing the JWT header.</param>
    /// <param name="payloadSerializer">Delegate for serializing the JWT payload.</param>
    /// <param name="base64UrlEncoder">Delegate for Base64Url encoding.</param>
    /// <param name="jwkConverter">
    /// Delegate that converts a public key to a JWK dictionary for the <c>cnf</c> claim.
    /// </param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The compact JWS string of the signed Verifier Attestation JWT.
    /// </returns>
    public static async ValueTask<string> BuildAsync(
        string issuer,
        string subject,
        PublicKeyMemory verifierSigningPublicKey,
        PrivateKeyMemory trustAnchorPrivateKey,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        JwtHeaderSerializer headerSerializer,
        JwtPayloadSerializer payloadSerializer,
        EncodeDelegate base64UrlEncoder,
        Func<PublicKeyMemory, Dictionary<string, object>> jwkConverter,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(verifierSigningPublicKey);
        ArgumentNullException.ThrowIfNull(trustAnchorPrivateKey);
        ArgumentNullException.ThrowIfNull(headerSerializer);
        ArgumentNullException.ThrowIfNull(payloadSerializer);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(jwkConverter);
        ArgumentNullException.ThrowIfNull(pool);

        string algorithm =
            CryptoFormatConversions.DefaultTagToJwaConverter(trustAnchorPrivateKey.Tag);

        JwtHeader header = JwtHeaderExtensions.ForVerifierAttestation(algorithm);

        Dictionary<string, object> cnfJwk = jwkConverter(verifierSigningPublicKey);

        JwtPayload payload = new()
        {
            [WellKnownJwtClaims.Iss] = issuer,
            [WellKnownJwtClaims.Sub] = subject,
            [WellKnownJwtClaims.Iat] = issuedAt.ToUnixTimeSeconds(),
            [WellKnownJwtClaims.Exp] = expiresAt.ToUnixTimeSeconds(),
            [WellKnownJwtClaims.Cnf] = new Dictionary<string, object> { [WellKnownJwkValues.Jwk] = cnfJwk }
        };

        UnsignedJwt unsigned = new(header, payload);
        JwsMessage signed = await unsigned.SignAsync(
            trustAnchorPrivateKey,
            headerSerializer,
            payloadSerializer,
            base64UrlEncoder,
            pool,
            cancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(signed, base64UrlEncoder);
    }
}
