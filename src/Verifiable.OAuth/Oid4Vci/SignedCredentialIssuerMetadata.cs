using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Text;
using Verifiable.JCose;

namespace Verifiable.OAuth.Oid4Vci;

/// <summary>
/// Builds the OID4VCI 1.0 §12.2.3 <c>signed_metadata</c> JWS from an assembled Credential Issuer
/// Metadata claim set, as a LIBRARY GUARANTEE of the §12.2.3 invariants rather than an unguarded
/// application responsibility.
/// </summary>
/// <remarks>
/// <para>
/// §12.2.3: "The signed metadata MUST be secured using a JSON Web Signature (JWS) [RFC7515] and
/// contain the following elements". This helper enforces each normative element:
/// </para>
/// <list type="bullet">
/// <item>JOSE header <c>alg</c>: "REQUIRED. A digital signature algorithm identifier ... It MUST
/// NOT be <c>none</c> or an identifier for a symmetric algorithm (MAC)." — derived from the
/// signing key's tag via <see cref="CryptoFormatConversions.DefaultTagToJwaConverter"/> and
/// REJECTED when it resolves to <c>none</c> or an <c>HS*</c> MAC.</item>
/// <item>JOSE header <c>typ</c>: "REQUIRED. MUST be <c>openidvci-issuer-metadata+jwt</c>." — set
/// from <see cref="SignedMetadataType"/>.</item>
/// <item>Payload <c>sub</c>: "REQUIRED. String matching the Credential Issuer Identifier." — set
/// from the <paramref name="credentialIssuer"/> argument.</item>
/// <item>Payload <c>iat</c>: "REQUIRED. Integer for the time at which the Credential Issuer
/// Metadata was issued." — set from <paramref name="issuedAt"/>.</item>
/// <item>"All metadata parameters used by the Credential Issuer MUST be added as top-level claims
/// in the JWS payload." — every claim in <paramref name="metadata"/> is copied to the payload.</item>
/// </list>
/// <para>
/// The seam (<see cref="Server.SignCredentialIssuerMetadataDelegate"/>) stays application-owned —
/// only the deployment holds the signing key and its <c>kid</c> selection — but a seam
/// implementation that signs through this helper inherits the §12.2.3 guarantees instead of
/// re-deriving (and risking divergence from) them. The result is the compact JWS the endpoint
/// embeds verbatim as the <c>signed_metadata</c> field.
/// </para>
/// </remarks>
public static class SignedCredentialIssuerMetadata
{
    /// <summary>The UTF-8 source literal of <see cref="SignedMetadataType"/>.</summary>
    public static ReadOnlySpan<byte> SignedMetadataTypeUtf8 => "openidvci-issuer-metadata+jwt"u8;

    /// <summary>
    /// The §12.2.3 <c>typ</c> header value an explicitly-typed <c>signed_metadata</c> JWS MUST
    /// carry: "MUST be <c>openidvci-issuer-metadata+jwt</c>". A Wallet rejects a signed-metadata
    /// JWT whose <c>typ</c> is anything else, so both sides name the value from one source.
    /// </summary>
    public static readonly string SignedMetadataType = Utf8Constants.ToInternedString(SignedMetadataTypeUtf8);


    /// <summary>
    /// Composes and signs the §12.2.3 <c>signed_metadata</c> JWS over the assembled metadata claim
    /// set, enforcing every §12.2.3 invariant (typ, sub, iat, every metadata parameter as a
    /// top-level claim, and a non-<c>none</c>, non-symmetric <c>alg</c>).
    /// </summary>
    /// <param name="metadata">
    /// The assembled Credential Issuer Metadata claim set — the same values the plain §12.2.4
    /// document carries (it includes <c>credential_issuer</c>). Each entry becomes a top-level
    /// payload claim, so the signed JWT cannot diverge from the plain document.
    /// </param>
    /// <param name="credentialIssuer">
    /// The Credential Issuer Identifier, emitted as the REQUIRED <c>sub</c> claim. §12.2.3 requires
    /// <c>sub</c> to match the Credential Issuer Identifier; it MUST equal the
    /// <c>credential_issuer</c> the claim set carries.
    /// </param>
    /// <param name="signingKey">
    /// The issuer's signing key. Its <see cref="Verifiable.Cryptography.SensitiveMemory.Tag"/>
    /// selects the JWS <c>alg</c> and signing function; a key whose algorithm resolves to
    /// <c>none</c> or a symmetric MAC is rejected before any signing happens.
    /// </param>
    /// <param name="keyId">The <c>kid</c> JOSE header identifying the signing key, so a Wallet can resolve the verification key.</param>
    /// <param name="issuedAt">The instant emitted as the REQUIRED <c>iat</c> claim (Unix seconds).</param>
    /// <param name="headerSerializer">Serializes the JOSE header to UTF-8 JSON bytes.</param>
    /// <param name="payloadSerializer">Serializes the JWT payload to UTF-8 JSON bytes.</param>
    /// <param name="base64UrlEncoder">Base64url-without-padding encoder for the JWS segments.</param>
    /// <param name="memoryPool">Memory pool for transient signing buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The compact <c>signed_metadata</c> JWS.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when the signing key's algorithm resolves to <c>none</c> or a symmetric MAC, which
    /// §12.2.3 forbids for the signed-metadata JWS.
    /// </exception>
    public static async ValueTask<string> CreateAsync(
        JwtPayload metadata,
        string credentialIssuer,
        PrivateKeyMemory signingKey,
        string keyId,
        DateTimeOffset issuedAt,
        JwtHeaderSerializer headerSerializer,
        JwtPayloadSerializer payloadSerializer,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        ArgumentException.ThrowIfNullOrWhiteSpace(credentialIssuer);
        ArgumentNullException.ThrowIfNull(signingKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
        ArgumentNullException.ThrowIfNull(headerSerializer);
        ArgumentNullException.ThrowIfNull(payloadSerializer);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

        //§12.2.3 alg: "It MUST NOT be none or an identifier for a symmetric algorithm (MAC)." The
        //alg derives from the key's tag, never from caller input; the guard refuses a none/symmetric
        //value before signing so the §12.2.3 MUST holds independent of the tag→JWA mapping.
        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(signingKey.Tag);
        EnsureSignatureAlgorithmAllowed(algorithm);

        JwtHeader header = new(capacity: 3)
        {
            [WellKnownJwkMemberNames.Alg] = algorithm,
            [WellKnownJoseHeaderNames.Typ] = SignedMetadataType,
            [WellKnownJwkMemberNames.Kid] = keyId
        };

        //Every metadata parameter becomes a top-level claim (§12.2.3), then the REQUIRED
        //structural claims are layered on so they cannot be shadowed by a metadata entry.
        JwtPayload payload = new(metadata)
        {
            [WellKnownJwtClaimNames.Sub] = credentialIssuer,
            [WellKnownJwtClaimNames.Iat] = issuedAt.ToUnixTimeSeconds()
        };

        UnsignedJwt unsigned = new(header, payload);
        using JwsMessage jws = await unsigned.SignAsync(
            signingKey, headerSerializer, payloadSerializer,
            base64UrlEncoder, memoryPool, cancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(jws, base64UrlEncoder);
    }


    /// <summary>
    /// Enforces the OID4VCI 1.0 §12.2.3 JOSE-header <c>alg</c> MUST: "It MUST NOT be <c>none</c>
    /// or an identifier for a symmetric algorithm (MAC)." Throws when <paramref name="algorithm"/>
    /// is <c>none</c> or one of the <c>HS256</c> / <c>HS384</c> / <c>HS512</c> MACs, so the
    /// signed-metadata JWS can only carry a digital-signature algorithm.
    /// </summary>
    /// <param name="algorithm">The JWA algorithm identifier resolved for the signing key.</param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="algorithm"/> is <c>none</c> or a symmetric MAC.</exception>
    public static void EnsureSignatureAlgorithmAllowed(string algorithm)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(algorithm);

        if(WellKnownJwaValues.IsNone(algorithm)
            || WellKnownJwaValues.IsHs256(algorithm)
            || WellKnownJwaValues.IsHs384(algorithm)
            || WellKnownJwaValues.IsHs512(algorithm))
        {
            throw new ArgumentException(
                $"OID4VCI 1.0 §12.2.3 forbids signing the Credential Issuer Metadata with '{algorithm}': "
                + "the JWS alg MUST NOT be none or a symmetric (MAC) algorithm.",
                nameof(algorithm));
        }
    }
}
