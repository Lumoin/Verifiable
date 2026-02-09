using Verifiable.Cryptography;

namespace Verifiable.Cbor.Sd;

/// <summary>
/// Constants specific to SD-CWT (Selective Disclosure CBOR Web Tokens).
/// </summary>
/// <remarks>
/// <para>
/// These constants are defined by the IETF SPICE SD-CWT specification.
/// See <see href="https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html">
/// draft-ietf-spice-sd-cwt</see>.
/// </para>
/// <para>
/// <strong>COSE Header Parameters:</strong>
/// </para>
/// <list type="bullet">
///   <item><description><c>sd_claims</c> (17) - Array of disclosures in unprotected header.</description></item>
///   <item><description><c>sd_alg</c> (18) - Hash algorithm in protected header.</description></item>
///   <item><description><c>sd_aead_encrypted_claims</c> (19) - AEAD encrypted disclosures.</description></item>
///   <item><description><c>sd_aead</c> (TBD7) - AEAD algorithm identifier.</description></item>
/// </list>
/// <para>
/// <strong>CBOR Tags:</strong>
/// </para>
/// <list type="bullet">
///   <item><description>Tag 58 - To Be Redacted (pre-issuance).</description></item>
///   <item><description>Tag 59 - Simple value for redacted_claim_keys map key.</description></item>
///   <item><description>Tag 60 - Redacted Claim Element in arrays.</description></item>
///   <item><description>Tag 61 - To Be Decoy (pre-issuance).</description></item>
/// </list>
/// </remarks>
public static class SdCwtConstants
{
    /// <summary>
    /// COSE header parameter for selective disclosure claims (disclosures array).
    /// </summary>
    /// <remarks>
    /// This header parameter appears in the unprotected header of the SD-CWT
    /// and contains all the salted disclosed claims.
    /// </remarks>
    public const int SdClaimsHeaderParameter = 17;

    /// <summary>
    /// COSE header parameter for the hash algorithm used for disclosure digests.
    /// </summary>
    /// <remarks>
    /// This header parameter appears in the protected header.
    /// The value is a COSE algorithm identifier (e.g., -16 for SHA-256).
    /// If absent, SHA-256 is the default.
    /// </remarks>
    public const int SdAlgHeaderParameter = 18;

    /// <summary>
    /// COSE header parameter for AEAD encrypted disclosures.
    /// </summary>
    public const int SdAeadEncryptedClaimsHeaderParameter = 19;

    /// <summary>
    /// CBOR simple value used as map key for redacted claim keys array.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Per the SD-CWT specification, when a map entry is redacted, its blinded claim hash
    /// is added to an array under this special map key at the same level of hierarchy.
    /// </para>
    /// <para>
    /// Example in EDN:
    /// </para>
    /// <code>
    /// {
    ///   / redacted_claim_keys / simple(59) : [
    ///     h'af375dc3...'  / hash of redacted claim /
    ///   ]
    /// }
    /// </code>
    /// </remarks>
    public const byte RedactedClaimKeysSimpleValue = 59;

    /// <summary>
    /// CBOR tag for redacted array elements.
    /// </summary>
    /// <remarks>
    /// <para>
    /// When an array element is redacted, the element value is replaced with
    /// the blinded claim hash wrapped in this tag.
    /// </para>
    /// <para>
    /// Example in EDN:
    /// </para>
    /// <code>
    /// [
    ///   60(h'1b7fc8ec...')  / redacted element /
    /// ]
    /// </code>
    /// </remarks>
    public const ulong RedactedClaimElementTag = 60;

    /// <summary>
    /// CBOR tag for "To Be Redacted" marker (pre-issuance only).
    /// </summary>
    /// <remarks>
    /// Used by holders to indicate which claims should be redacted when
    /// communicating with the issuer before credential issuance.
    /// </remarks>
    public const ulong ToBeRedactedTag = 58;

    /// <summary>
    /// CBOR tag for "To Be Decoy" marker (pre-issuance only).
    /// </summary>
    /// <remarks>
    /// Used to indicate locations where decoy digests should be inserted.
    /// </remarks>
    public const ulong ToBeDecoyTag = 61;

    /// <summary>
    /// COSE algorithm identifier for SHA-256 (-16).
    /// </summary>
    public const int Sha256AlgorithmId = -16;

    /// <summary>
    /// COSE algorithm identifier for SHA-384 (-43).
    /// </summary>
    public const int Sha384AlgorithmId = -43;

    /// <summary>
    /// COSE algorithm identifier for SHA-512 (-44).
    /// </summary>
    public const int Sha512AlgorithmId = -44;

    /// <summary>
    /// Media type for SD-CWT.
    /// </summary>
    public const string SdCwtMediaType = "application/sd-cwt";

    /// <summary>
    /// CoAP content format value for SD-CWT.
    /// </summary>
    /// <remarks>
    /// Using the numeric value is recommended over the string media type
    /// for size efficiency (3 bytes vs 19 bytes).
    /// </remarks>
    public const int SdCwtContentFormat = 293;

    /// <summary>
    /// Media type for Key Binding CWT.
    /// </summary>
    public const string KeyBindingCwtMediaType = "application/kb+cwt";

    /// <summary>
    /// CoAP content format value for Key Binding CWT.
    /// </summary>
    public const int KeyBindingCwtContentFormat = 294;

    /// <summary>
    /// Required salt length in bytes (128 bits).
    /// </summary>
    public const int SaltLengthBytes = 16;

    /// <summary>
    /// Standard CWT claim key for issuer (iss).
    /// </summary>
    public const int IssClaimKey = 1;

    /// <summary>
    /// Standard CWT claim key for subject (sub).
    /// </summary>
    public const int SubClaimKey = 2;

    /// <summary>
    /// Standard CWT claim key for audience (aud).
    /// </summary>
    public const int AudClaimKey = 3;

    /// <summary>
    /// Standard CWT claim key for expiration (exp).
    /// </summary>
    public const int ExpClaimKey = 4;

    /// <summary>
    /// Standard CWT claim key for not before (nbf).
    /// </summary>
    public const int NbfClaimKey = 5;

    /// <summary>
    /// Standard CWT claim key for issued at (iat).
    /// </summary>
    public const int IatClaimKey = 6;

    /// <summary>
    /// Standard CWT claim key for CWT ID (cti).
    /// </summary>
    public const int CtiClaimKey = 7;

    /// <summary>
    /// Standard CWT claim key for confirmation (cnf).
    /// </summary>
    public const int CnfClaimKey = 8;

    /// <summary>
    /// CWT claim key for verifiable credential type (vct).
    /// </summary>
    public const int VctClaimKey = 11;

    /// <summary>
    /// CWT claim key for client nonce (cnonce).
    /// </summary>
    public const int CnonceClaimKey = 39;

    /// <summary>
    /// COSE header parameter for algorithm (alg).
    /// </summary>
    public const int AlgHeaderParameter = 1;

    /// <summary>
    /// COSE header parameter for key ID (kid).
    /// </summary>
    public const int KidHeaderParameter = 4;

    /// <summary>
    /// COSE header parameter for content type (typ / ctyp).
    /// </summary>
    public const int TypHeaderParameter = 16;

    /// <summary>
    /// COSE header parameter for kcwt (Key Confirmation CWT).
    /// </summary>
    /// <remarks>
    /// Defined in RFC 9528. Used in SD-KBT to embed the SD-CWT.
    /// </remarks>
    public const int KcwtHeaderParameter = 13;


    /// <summary>
    /// Gets the COSE algorithm identifier for a hash algorithm name.
    /// </summary>
    /// <param name="algorithmName">The hash algorithm name (e.g., "sha-256").</param>
    /// <returns>The COSE algorithm identifier.</returns>
    /// <exception cref="ArgumentException">Thrown for unsupported algorithms.</exception>
    public static int GetCoseAlgorithmId(string algorithmName)
    {
        ArgumentNullException.ThrowIfNull(algorithmName);

        if(WellKnownHashAlgorithms.IsSha256(algorithmName))
        {
            return Sha256AlgorithmId;
        }

        if(WellKnownHashAlgorithms.IsSha384(algorithmName))
        {
            return Sha384AlgorithmId;
        }

        if(WellKnownHashAlgorithms.IsSha512(algorithmName))
        {
            return Sha512AlgorithmId;
        }

        throw new ArgumentException($"Unsupported hash algorithm: {algorithmName}", nameof(algorithmName));
    }


    /// <summary>
    /// Gets the hash algorithm name from a COSE algorithm identifier.
    /// </summary>
    /// <param name="coseAlgorithmId">The COSE algorithm identifier.</param>
    /// <returns>The hash algorithm name.</returns>
    /// <exception cref="ArgumentException">Thrown for unsupported algorithms.</exception>
    public static string GetHashAlgorithmName(int coseAlgorithmId)
    {
        return coseAlgorithmId switch
        {
            Sha256AlgorithmId => WellKnownHashAlgorithms.Sha256Iana,
            Sha384AlgorithmId => WellKnownHashAlgorithms.Sha384Iana,
            Sha512AlgorithmId => WellKnownHashAlgorithms.Sha512Iana,
            _ => throw new ArgumentException($"Unsupported COSE algorithm ID: {coseAlgorithmId}", nameof(coseAlgorithmId))
        };
    }
}