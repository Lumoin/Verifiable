namespace Verifiable.JCose;

/// <summary>
/// COSE header parameter labels as defined in
/// <see href="https://www.iana.org/assignments/cose/cose.xhtml#header-parameters">IANA COSE Header Parameters</see>.
/// </summary>
/// <remarks>
/// <para>
/// COSE uses integer labels for header parameters. Common parameters are defined
/// in RFC 9052 and RFC 9053. Application-specific parameters may be registered
/// with IANA or use values from the private use range.
/// </para>
/// <para>
/// See <see href="https://www.rfc-editor.org/rfc/rfc9052#section-3.1">RFC 9052 §3.1</see>.
/// </para>
/// </remarks>
public static class CoseHeaderParameters
{
    /// <summary>
    /// Algorithm identifier (alg).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Identifies the cryptographic algorithm used with the key.
    /// Value is int or tstr.
    /// </para>
    /// <para>
    /// See <see href="https://www.rfc-editor.org/rfc/rfc9052#section-3.1">RFC 9052 §3.1</see>.
    /// </para>
    /// </remarks>
    public const int Alg = 1;

    /// <summary>
    /// Critical headers (crit).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Array of header labels that must be understood by the recipient.
    /// </para>
    /// <para>
    /// See <see href="https://www.rfc-editor.org/rfc/rfc9052#section-3.1">RFC 9052 §3.1</see>.
    /// </para>
    /// </remarks>
    public const int Crit = 2;

    /// <summary>
    /// Content type (content type).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Describes the content carried in the payload.
    /// Value is tstr or uint (CoAP content format).
    /// </para>
    /// <para>
    /// See <see href="https://www.rfc-editor.org/rfc/rfc9052#section-3.1">RFC 9052 §3.1</see>.
    /// </para>
    /// </remarks>
    public const int ContentType = 3;

    /// <summary>
    /// Key identifier (kid).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Identifies the key used to protect the message.
    /// Value is bstr.
    /// </para>
    /// <para>
    /// See <see href="https://www.rfc-editor.org/rfc/rfc9052#section-3.1">RFC 9052 §3.1</see>.
    /// </para>
    /// </remarks>
    public const int Kid = 4;

    /// <summary>
    /// Initialization vector (IV).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Initialization vector for encryption algorithms.
    /// Value is bstr.
    /// </para>
    /// <para>
    /// See <see href="https://www.rfc-editor.org/rfc/rfc9052#section-3.1">RFC 9052 §3.1</see>.
    /// </para>
    /// </remarks>
    public const int Iv = 5;

    /// <summary>
    /// Partial initialization vector (Partial IV).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Partial IV combined with context to form full IV.
    /// Value is bstr.
    /// </para>
    /// <para>
    /// See <see href="https://www.rfc-editor.org/rfc/rfc9052#section-3.1">RFC 9052 §3.1</see>.
    /// </para>
    /// </remarks>
    public const int PartialIv = 6;

    /// <summary>
    /// Counter signature (counter signature).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Counter signatures on the content.
    /// </para>
    /// <para>
    /// See <see href="https://www.rfc-editor.org/rfc/rfc9338">RFC 9338</see>.
    /// </para>
    /// </remarks>
    public const int CounterSignature = 7;

    /// <summary>
    /// Key Confirmation CWT (kcwt).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Used in SD-KBT to embed the SD-CWT.
    /// </para>
    /// <para>
    /// See <see href="https://www.rfc-editor.org/rfc/rfc9528">RFC 9528</see>.
    /// </para>
    /// </remarks>
    public const int Kcwt = 13;

    /// <summary>
    /// Type header parameter (typ).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Declares the type of the complete COSE object.
    /// Similar to JWT "typ" header. Value is tstr or uint (CoAP content format).
    /// </para>
    /// <para>
    /// See <see href="https://www.rfc-editor.org/rfc/rfc9596">RFC 9596</see>.
    /// </para>
    /// </remarks>
    public const int Typ = 16;

    /// <summary>
    /// SD-CWT claims header parameter (sd_claims).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Array of disclosures in the unprotected header for SD-CWT.
    /// </para>
    /// <para>
    /// See <see href="https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/">draft-ietf-spice-sd-cwt</see>.
    /// </para>
    /// </remarks>
    public const int SdClaims = 17;

    /// <summary>
    /// SD-CWT hash algorithm header parameter (sd_alg).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Hash algorithm used for disclosure digests in SD-CWT.
    /// Appears in protected header. If absent, SHA-256 is default.
    /// </para>
    /// <para>
    /// See <see href="https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/">draft-ietf-spice-sd-cwt</see>.
    /// </para>
    /// </remarks>
    public const int SdAlg = 18;

    /// <summary>
    /// SD-CWT AEAD encrypted claims header parameter.
    /// </summary>
    /// <remarks>
    /// <para>
    /// AEAD encrypted disclosures for SD-CWT.
    /// </para>
    /// <para>
    /// See <see href="https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/">draft-ietf-spice-sd-cwt</see>.
    /// </para>
    /// </remarks>
    public const int SdAeadEncryptedClaims = 19;


    /// <summary>
    /// Gets the parameter name for a COSE header parameter label.
    /// </summary>
    /// <param name="label">The header parameter label.</param>
    /// <returns>The parameter name, or null if unknown.</returns>
    public static string? GetParameterName(int label) => label switch
    {
        Alg => "alg",
        Crit => "crit",
        ContentType => "content type",
        Kid => "kid",
        Iv => "IV",
        PartialIv => "Partial IV",
        CounterSignature => "counter signature",
        Kcwt => "kcwt",
        Typ => "typ",
        SdClaims => "sd_claims",
        SdAlg => "sd_alg",
        SdAeadEncryptedClaims => "sd_aead_encrypted_claims",
        _ => null
    };
}