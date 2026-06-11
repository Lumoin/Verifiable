using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Text;
using Verifiable.JCose;

namespace Verifiable.OAuth.Oid4Vci.Wallet;

/// <summary>
/// Mints the OID4VCI 1.0 §7.2.1 <c>jwt</c> holder key proof
/// (<c>openid4vci-proof+jwt</c>): a compact JWS whose JOSE header carries
/// <c>typ=openid4vci-proof+jwt</c>, the <c>alg</c> derived from the holder key
/// tag, and the holder PUBLIC key as the header <c>jwk</c> member, and whose
/// body carries <c>aud</c> (the Credential Issuer identifier), <c>nonce</c>
/// (the <c>c_nonce</c> the §7 Nonce Endpoint issued), and <c>iat</c>.
/// </summary>
/// <remarks>
/// The proof binds the holder's possession of the private key to a fresh
/// challenge so the Credential Issuer can issue a Credential bound to exactly
/// the key the Wallet proves here. The Issuer reconstructs the holder key off
/// the header <c>jwk</c>, verifies the JWS signature against it, and checks the
/// <c>nonce</c> against its <c>c_nonce</c> store before minting — the symmetric
/// counterpart to this minting step.
/// </remarks>
public static class Oid4VciProofIssuance
{
    /// <summary>The UTF-8 source literal of <see cref="ProofJwtType"/>.</summary>
    public static ReadOnlySpan<byte> ProofJwtTypeUtf8 => "openid4vci-proof+jwt"u8;

    /// <summary>
    /// The §7.2.1 <c>typ</c> header value identifying a <c>jwt</c> key proof. The
    /// Credential Issuer rejects a proof whose <c>typ</c> is anything else, so the
    /// constant is the wire contract both sides name from one source.
    /// </summary>
    public static readonly string ProofJwtType = Utf8Constants.ToInternedString(ProofJwtTypeUtf8);


    /// <summary>
    /// Builds and signs a §7.2.1 holder key proof JWS.
    /// </summary>
    /// <param name="holderPrivate">The holder's signing private key. Its tag selects the JWS <c>alg</c> and signing function.</param>
    /// <param name="holderPublic">The holder's public key, projected into the header <c>jwk</c> member.</param>
    /// <param name="audience">The Credential Issuer identifier, emitted as the <c>aud</c> claim.</param>
    /// <param name="credentialNonce">The <c>c_nonce</c> from the §7 Nonce Endpoint, emitted as the <c>nonce</c> claim.</param>
    /// <param name="issuedAt">The instant emitted as the <c>iat</c> claim (Unix seconds).</param>
    /// <param name="headerSerializer">Serializes the JOSE header to UTF-8 JSON bytes.</param>
    /// <param name="payloadSerializer">Serializes the JWT payload to UTF-8 JSON bytes.</param>
    /// <param name="base64UrlEncoder">Base64url-without-padding encoder for the JWS segments and JWK coordinates.</param>
    /// <param name="memoryPool">Memory pool for transient signing buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The compact JWS holder key proof.</returns>
    public static async ValueTask<string> BuildJwtProofAsync(
        PrivateKeyMemory holderPrivate,
        PublicKeyMemory holderPublic,
        string audience,
        string credentialNonce,
        DateTimeOffset issuedAt,
        JwtHeaderSerializer headerSerializer,
        JwtPayloadSerializer payloadSerializer,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(holderPrivate);
        ArgumentNullException.ThrowIfNull(holderPublic);
        ArgumentException.ThrowIfNullOrWhiteSpace(audience);
        ArgumentException.ThrowIfNullOrWhiteSpace(credentialNonce);
        ArgumentNullException.ThrowIfNull(headerSerializer);
        ArgumentNullException.ThrowIfNull(payloadSerializer);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

        //The JWS alg is the holder key's algorithm; the header jwk projects the
        //holder PUBLIC key so the Issuer can both pick the verification algorithm
        //and reconstruct the verifying key from the proof itself.
        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(holderPrivate.Tag);
        JsonWebKey jwk = CryptoFormatConversions.DefaultAlgorithmToJwkConverter(
            holderPublic.Tag.Get<CryptoAlgorithm>(),
            holderPublic.Tag.Get<Purpose>(),
            holderPublic.AsReadOnlySpan(),
            base64UrlEncoder);

        JwtHeader header = new(capacity: 3)
        {
            [WellKnownJwkMemberNames.Alg] = algorithm,
            [WellKnownJoseHeaderNames.Typ] = ProofJwtType,
            [Oid4VciCredentialParameterNames.Jwk] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [WellKnownJwkMemberNames.Kty] = jwk.Kty!,
                [WellKnownJwkMemberNames.Crv] = jwk.Crv!,
                [WellKnownJwkMemberNames.X] = jwk.X!,
                [WellKnownJwkMemberNames.Y] = jwk.Y!
            }
        };

        JwtPayload payload = new(capacity: 3)
        {
            [WellKnownJwtClaimNames.Aud] = audience,
            [WellKnownJwtClaimNames.Nonce] = credentialNonce,
            [WellKnownJwtClaimNames.Iat] = issuedAt.ToUnixTimeSeconds()
        };

        UnsignedJwt unsigned = new(header, payload);
        using JwsMessage jws = await unsigned.SignAsync(
            holderPrivate, headerSerializer, payloadSerializer,
            base64UrlEncoder, memoryPool, cancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(jws, base64UrlEncoder);
    }
}
