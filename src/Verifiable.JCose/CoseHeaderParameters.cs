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
    /// Counter signature (counter signature) — the RFC 8152 version 1 full countersignature.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <strong>Deprecated by RFC 9338.</strong> <see href="https://www.rfc-editor.org/rfc/rfc9338#section-1">
    /// RFC 9338 §1</see>: "uses of 'CounterSignature' will migrate to 'CounterSignatureV2'" —
    /// see <see cref="CounterSignatureVersion2"/> (label 11). RFC 9338 §1 also states new
    /// implementations must still be able to VERIFY this label for compatibility with RFC
    /// 8152 senders; this substrate and TS 119 152-1's own CDDL (labels 11/12 only) model
    /// version 2 exclusively, so this label is rejected fail-closed at the countersignature
    /// parse site rather than accepted.
    /// </para>
    /// <para>
    /// See <see href="https://www.rfc-editor.org/rfc/rfc9338">RFC 9338</see>.
    /// </para>
    /// </remarks>
    public const int CounterSignature = 7;

    /// <summary>
    /// Countersignature0 (CounterSignature0) — the RFC 8152 version 1 abbreviated countersignature.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <strong>Deprecated by RFC 9338.</strong> <see href="https://www.rfc-editor.org/rfc/rfc9338#section-1">
    /// RFC 9338 §1</see>: "uses of 'CounterSignature0' will migrate to 'CounterSignature0V2'"
    /// — see <see cref="Countersignature0Version2"/> (label 12). Rejected fail-closed at the
    /// countersignature parse site for the same reason as <see cref="CounterSignature"/>.
    /// </para>
    /// <para>
    /// See <see href="https://www.rfc-editor.org/rfc/rfc9338">RFC 9338</see>.
    /// </para>
    /// </remarks>
    public const int CounterSignature0 = 9;

    /// <summary>
    /// Countersignature version 2 (counter signature v2) — the RFC 9338 full countersignature.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Value type <c>COSE_Countersignature / [+ COSE_Countersignature]</c> — one or more full
    /// countersignatures, each structurally a <c>COSE_Signature</c> (protected header,
    /// unprotected header, signature value). See
    /// <see href="https://www.rfc-editor.org/rfc/rfc9338#section-2">RFC 9338 §2 Table 1</see>
    /// and <see href="https://www.rfc-editor.org/rfc/rfc9338#section-3.1">RFC 9338 §3.1</see>.
    /// </para>
    /// </remarks>
    public const int CounterSignatureVersion2 = 11;

    /// <summary>
    /// Countersignature0 version 2 (counter signature v2 abbreviated) — the RFC 9338
    /// abbreviated countersignature.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Value type <c>COSE_Countersignature0</c> — a bare signature-value <c>bstr</c>, with no
    /// protected or unprotected attributes of its own. See
    /// <see href="https://www.rfc-editor.org/rfc/rfc9338#section-2">RFC 9338 §2 Table 1</see>
    /// and <see href="https://www.rfc-editor.org/rfc/rfc9338#section-3.2">RFC 9338 §3.2</see>.
    /// </para>
    /// </remarks>
    public const int Countersignature0Version2 = 12;

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
    /// CWT Claims header parameter (CWT Claims).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Carries a CBOR Web Token claims set (see <see cref="CwtPayload"/>) as a header parameter, so claims such
    /// as <c>iat</c> (<see cref="WellKnownCwtClaimNames.Iat"/>) can qualify a COSE structure directly rather
    /// than only a CWT payload. Value is a CWT claims-set map. Consumed by CB-AdES's mandatory signed <c>iat</c>
    /// carriage (<see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.1.9</see>, CB-5.1.9-06).
    /// </para>
    /// <para>
    /// See <see href="https://www.rfc-editor.org/rfc/rfc9597">RFC 9597 — CBOR Web Token (CWT) Claims in COSE
    /// Headers</see>.
    /// </para>
    /// </remarks>
    public const int CwtClaims = 15;

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
    /// X.509 certificate bag header parameter (x5bag).
    /// </summary>
    /// <remarks>
    /// <para>
    /// An unordered bag of X.509 certificates and/or CRLs, none of which is required to be the signer's own
    /// certificate — contrast with <see cref="X5Chain"/>, whose first entry is the signer's certificate. Value
    /// is a single DER certificate <c>bstr</c>, or an array of them.
    /// </para>
    /// <para>
    /// See <see href="https://www.rfc-editor.org/rfc/rfc9360#section-2">RFC 9360 §2</see>.
    /// </para>
    /// </remarks>
    public const int X5Bag = 32;

    /// <summary>
    /// X.509 certificate chain header parameter (x5chain).
    /// </summary>
    /// <remarks>
    /// <para>
    /// An ordered array of X.509 certificates carrying the signer's certificate first, followed by the
    /// remainder of the certification path in path order (<c>COSE_X509</c>). Value is a single DER certificate
    /// <c>bstr</c> (a chain of one), or an array of at least two certificate <c>bstr</c>s.
    /// </para>
    /// <para>
    /// See <see href="https://www.rfc-editor.org/rfc/rfc9360#section-2">RFC 9360 §2</see>.
    /// </para>
    /// </remarks>
    public const int X5Chain = 33;

    /// <summary>
    /// X.509 certificate thumbprint header parameter (x5t).
    /// </summary>
    /// <remarks>
    /// <para>
    /// A digest of the DER encoding of the signer's certificate (<c>COSE_CertHash</c>: a digest-algorithm
    /// identifier plus the digest value), used as a hint to identify the certificate without carrying it in
    /// full.
    /// </para>
    /// <para>
    /// See <see href="https://www.rfc-editor.org/rfc/rfc9360#section-2">RFC 9360 §2</see>.
    /// </para>
    /// </remarks>
    public const int X5T = 34;

    /// <summary>
    /// X.509 certificate URL header parameter (x5u).
    /// </summary>
    /// <remarks>
    /// <para>
    /// A URI that can be used to retrieve the signer's certificate (or certificate chain). Value is a
    /// <c>tstr</c>. A hint only — implementations may have alternative retrieval strategies if the referenced
    /// location is unavailable.
    /// </para>
    /// <para>
    /// See <see href="https://www.rfc-editor.org/rfc/rfc9360#section-2">RFC 9360 §2</see>.
    /// </para>
    /// </remarks>
    public const int X5U = 35;


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
        CounterSignature0 => "CounterSignature0",
        CounterSignatureVersion2 => "counter signature v2",
        Countersignature0Version2 => "counter signature v2 abbreviated",
        Kcwt => "kcwt",
        CwtClaims => "CWT Claims",
        Typ => "typ",
        SdClaims => "sd_claims",
        SdAlg => "sd_alg",
        SdAeadEncryptedClaims => "sd_aead_encrypted_claims",
        X5Bag => "x5bag",
        X5Chain => "x5chain",
        X5T => "x5t",
        X5U => "x5u",
        _ => null
    };
}
