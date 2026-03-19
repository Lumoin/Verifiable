using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Helpers for extracting Verifier Attestation JWT material from a compact JAR string
/// prior to full JAR parsing and signature verification.
/// </summary>
/// <remarks>
/// <para>
/// The Wallet uses these helpers when the <c>client_id</c> carries the
/// <c>verifier_attestation:</c> prefix (OID4VP 1.0 §5.9.3). The attestation JWT lives
/// in the <c>jwt</c> JOSE header parameter of the signed Request Object. The Wallet must
/// validate the attestation and extract the signing key from its <c>cnf</c> claim before
/// verifying the JAR signature.
/// </para>
/// <para>
/// Typical Wallet flow for <c>verifier_attestation:</c>:
/// </para>
/// <list type="number">
///   <item><description>
///     Call <see cref="TryGetVerifierAttestationJwt"/> to extract the attestation from
///     the JAR header without fully parsing the JAR payload.
///   </description></item>
///   <item><description>
///     Pass the attestation to a
///     <see cref="ResolveKeyFromVerifierAttestationDelegate"/> to validate the attestation
///     and obtain the Verifier's signing public key.
///   </description></item>
///   <item><description>
///     Verify the JAR signature using the resolved key and <c>Jws.VerifyAsync</c>.
///   </description></item>
///   <item><description>
///     Call <c>JarExtensions.ParseJar</c> to parse the verified JAR payload into a typed
///     <see cref="AuthorizationRequestObject"/>.
///   </description></item>
/// </list>
/// </remarks>
public static class JarAttestationExtensions
{
    /// <summary>
    /// Attempts to extract a <see cref="VerifierAttestationJwt"/> from the <c>jwt</c>
    /// JOSE header parameter of a compact JAR string.
    /// </summary>
    /// <param name="compactJar">The compact JWS string fetched from <c>request_uri</c>.</param>
    /// <param name="base64UrlDecoder">Delegate for Base64Url decoding.</param>
    /// <param name="headerDeserializer">
    /// Delegate for deserializing the JOSE header into a dictionary.
    /// </param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <param name="attestation">
    /// When this method returns <see langword="true"/>, contains the extracted
    /// <see cref="VerifierAttestationJwt"/>; otherwise <see langword="null"/>.
    /// </param>
    /// <returns>
    /// <see langword="true"/> if the <c>jwt</c> header parameter is present and
    /// contains a non-empty string; otherwise <see langword="false"/>.
    /// </returns>
    public static bool TryGetVerifierAttestationJwt(
        string compactJar,
        DecodeDelegate base64UrlDecoder,
        Func<ReadOnlySpan<byte>, IReadOnlyDictionary<string, object>> headerDeserializer,
        MemoryPool<byte> pool,
        out VerifierAttestationJwt? attestation)
    {
        ArgumentNullException.ThrowIfNull(compactJar);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(headerDeserializer);
        ArgumentNullException.ThrowIfNull(pool);

        //Parse only the header — the payload is not needed for attestation extraction.
        using UnverifiedJwsMessage unverified = JwsParsing.ParseCompact(
            compactJar,
            base64UrlDecoder,
            headerDeserializer,
            pool);

        UnverifiedJwtHeader header = unverified.Signatures[0].ProtectedHeader;

        if(header.TryGetValue(WellKnownJwkValues.Jwt, out object? jwtObj)
            && jwtObj is string compactJwt
            && !string.IsNullOrWhiteSpace(compactJwt))
        {
            attestation = new VerifierAttestationJwt(compactJwt);
            return true;
        }

        attestation = null;
        return false;
    }
}
