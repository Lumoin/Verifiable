using Verifiable.Cryptography;

namespace Verifiable.JCose.Sd;

/// <summary>
/// Constants for SD-CWT (Selective Disclosure CBOR Web Tokens) per
/// <see href="https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html">
/// draft-ietf-spice-sd-cwt</see>.
/// </summary>
public static class SdCwtConstants
{
    /// <summary>
    /// Unprotected header key for the <c>sd_claims</c> array containing
    /// CBOR-encoded salted disclosures (registered value 17).
    /// </summary>
    public const int SdClaimsHeaderKey = 17;

    /// <summary>
    /// Protected header key for the <c>sd_alg</c> parameter identifying the
    /// hash algorithm used for blinded claim hashes (registered value 18).
    /// </summary>
    public const int SdAlgHeaderKey = 18;

    /// <summary>
    /// Protected header key for the <c>sd_aead_encrypted_claims</c> parameter
    /// (registered value 19).
    /// </summary>
    public const int SdAeadEncryptedClaimsHeaderKey = 19;

    /// <summary>
    /// CBOR simple value used as the map key for the <c>redacted_claim_keys</c> array.
    /// </summary>
    /// <remarks>
    /// <para>
    /// When a map entry is redacted, its blinded claim hash (a <c>bstr</c>) is placed
    /// into an array under this special map key at the same level of hierarchy as the
    /// original claim. The key is CBOR simple value 59.
    /// </para>
    /// <para>
    /// Example in EDN:
    /// </para>
    /// <code>
    /// {
    ///   / redacted_claim_keys / simple(59) : [
    ///     h'af375dc3...'
    ///   ]
    /// }
    /// </code>
    /// </remarks>
    public const byte RedactedClaimKeysSimpleValue = 59;

    /// <summary>
    /// CBOR tag wrapping a blinded claim hash that replaces a redacted array element.
    /// </summary>
    /// <remarks>
    /// <para>
    /// When an array element is redacted, its value is replaced with the blinded claim
    /// hash encoded as <c>#6.60(bstr)</c>.
    /// </para>
    /// <para>
    /// Example in EDN:
    /// </para>
    /// <code>
    /// [
    ///   60(h'1b7fc8ec...')
    /// ]
    /// </code>
    /// </remarks>
    public const ulong RedactedClaimElementTag = 60;

    /// <summary>
    /// CBOR tag marking a claim as "to be redacted" in pre-issuance communication.
    /// </summary>
    public const ulong ToBeRedactedTag = 58;

    /// <summary>
    /// CBOR tag marking a location for a decoy digest in pre-issuance communication.
    /// </summary>
    public const ulong ToBeDecoyTag = 61;


    /// <summary>
    /// Converts an IANA hash algorithm name to the corresponding COSE algorithm identifier
    /// for use in the <c>sd_alg</c> protected header.
    /// </summary>
    /// <param name="ianaName">The IANA hash algorithm name (e.g., <c>"sha-256"</c>).</param>
    /// <returns>The COSE algorithm identifier.</returns>
    /// <exception cref="ArgumentException">Thrown when the algorithm name is not recognized.</exception>
    public static int GetSdAlgFromIanaName(string ianaName) => ianaName switch
    {
        WellKnownHashAlgorithms.Sha256Iana => WellKnownCoseAlgorithms.Sha256,
        WellKnownHashAlgorithms.Sha384Iana => WellKnownCoseAlgorithms.Sha384,
        WellKnownHashAlgorithms.Sha512Iana => WellKnownCoseAlgorithms.Sha512,
        _ => throw new ArgumentException($"Unsupported hash algorithm: {ianaName}.", nameof(ianaName))
    };


    /// <summary>
    /// Converts a COSE algorithm identifier to the corresponding IANA hash algorithm name.
    /// </summary>
    /// <param name="coseAlgorithmId">The COSE algorithm identifier (e.g., <c>-16</c>).</param>
    /// <returns>The IANA hash algorithm name.</returns>
    /// <exception cref="ArgumentException">Thrown when the algorithm identifier is not recognized.</exception>
    public static string GetIanaNameFromSdAlg(int coseAlgorithmId) => coseAlgorithmId switch
    {
        WellKnownCoseAlgorithms.Sha256 => WellKnownHashAlgorithms.Sha256Iana,
        WellKnownCoseAlgorithms.Sha384 => WellKnownHashAlgorithms.Sha384Iana,
        WellKnownCoseAlgorithms.Sha512 => WellKnownHashAlgorithms.Sha512Iana,
        _ => throw new ArgumentException($"Unsupported COSE algorithm identifier: {coseAlgorithmId}.", nameof(coseAlgorithmId))
    };
}