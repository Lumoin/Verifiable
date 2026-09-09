using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// ECC key parameters (TPMS_ECC_PARMS).
/// </summary>
/// <remarks>
/// <para>
/// This structure defines the parameters for an ECC key in the public area.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     TPMT_SYM_DEF_OBJECT symmetric;           // Symmetric algorithm for restricted decryption keys.
///     TPMT_ECC_SCHEME scheme;                  // Signing or key exchange scheme.
///     TPMI_ECC_CURVE curveID;                  // ECC curve identifier.
///     TPMT_KDF_SCHEME kdf;                     // Optional KDF scheme.
/// } TPMS_ECC_PARMS;
/// </code>
/// <para>
/// For signing keys, scheme should be a valid signing scheme (ECDSA, etc.).
/// For storage keys, scheme should be TPM_ALG_NULL.
/// For restricted decryption keys, symmetric must be set to a supported algorithm.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 12.2.3.5, Table 229.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmsEccParms
{
    /// <summary>
    /// Gets the symmetric algorithm for restricted decryption keys.
    /// </summary>
    /// <remarks>
    /// For non-restricted or signing keys, this should be null (TPM_ALG_NULL).
    /// </remarks>
    public TpmtSymDefObject Symmetric { get; init; }

    /// <summary>
    /// Gets the signing or key exchange scheme.
    /// </summary>
    /// <remarks>
    /// For signing keys: ECDSA, SM2, ECDAA, etc.
    /// For decryption keys: ECDH or TPM_ALG_NULL.
    /// For storage keys: TPM_ALG_NULL.
    /// </remarks>
    public TpmtEccScheme Scheme { get; init; }

    /// <summary>
    /// Gets the ECC curve identifier.
    /// </summary>
    public TpmEccCurveConstants CurveId { get; init; }

    /// <summary>
    /// Gets the optional KDF scheme.
    /// </summary>
    /// <remarks>
    /// <para>
    /// TPM 2.0 Library Part 2, Table 229 (v185): "if the key is an unrestricted decryption
    /// TPM_ALG_ECDH key, an optional key derivation scheme. <b>Shall be NULL in all other cases
    /// (TPM_RC_KDF).</b> If this field is not NULL, then this key can be used with
    /// TPM2_Encapsulate() and TPM2_Decapsulate() ... the KEM is equivalent to DHKEM(curveID, kdf)
    /// from RFC 9180. Currently, TPM_ALG_HKDF is the only supported KDF for DHKEM. ...
    /// scheme.details.ecdh.hashAlg is ignored, because kdf specifies all parameters of the KDF ...
    /// If this field is NULL, then this key cannot be used with TPM2_Encapsulate() and
    /// TPM2_Decapsulate()."
    /// </para>
    /// <para>
    /// A non-NULL value here is therefore not a passive parameter but the KEM admission gate: it
    /// is what turns an unrestricted <c>TPM_ALG_ECDH</c> decryption key (<see cref="Scheme"/>,
    /// <see cref="TpmtEccScheme.Ecdh"/>) into a key <c>TPM2_Encapsulate()</c>/<c>TPM2_Decapsulate()</c>
    /// will accept — every other key shape must carry <see cref="TpmtKdfScheme.Null"/>. Once this
    /// field is HKDF, <see cref="Scheme"/>'s own hash algorithm plays no role in the KEM: the DHKEM
    /// hash is this field's <see cref="TpmtKdfScheme.HashAlg"/> alone.
    /// </para>
    /// </remarks>
    public TpmtKdfScheme Kdf { get; init; }

    /// <summary>
    /// Creates ECC parameters for a signing key.
    /// </summary>
    /// <param name="curve">The ECC curve.</param>
    /// <param name="scheme">The signing scheme.</param>
    /// <returns>The ECC parameters.</returns>
    public static TpmsEccParms ForSigning(TpmEccCurveConstants curve, TpmtEccScheme scheme) => new()
    {
        Symmetric = TpmtSymDefObject.Null,
        Scheme = scheme,
        CurveId = curve,
        Kdf = TpmtKdfScheme.Null
    };

    /// <summary>
    /// Creates ECC parameters for a storage key.
    /// </summary>
    /// <param name="curve">The ECC curve.</param>
    /// <param name="symmetric">The symmetric algorithm for child key protection.</param>
    /// <returns>The ECC parameters.</returns>
    public static TpmsEccParms ForStorage(TpmEccCurveConstants curve, TpmtSymDefObject symmetric) => new()
    {
        Symmetric = symmetric,
        Scheme = TpmtEccScheme.Null,
        CurveId = curve,
        Kdf = TpmtKdfScheme.Null
    };


    /// <summary>
    /// Creates ECC parameters for an ECDH key agreement key.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Configures TPMS_ECC_PARMS for use with TPM2_ECDH_ZGen (TPM 2.0 Library Part 3, clause 14.5):
    /// </para>
    /// <list type="bullet">
    ///   <item><description>symmetric: TPM_ALG_NULL — no symmetric scheme.</description></item>
    ///   <item><description>scheme: TPM_ALG_ECDH with TPM_ALG_SHA256.</description></item>
    ///   <item><description>curveID: as specified.</description></item>
    ///   <item><description>kdf: TPM_ALG_NULL — no key derivation function applied; raw EC point output.</description></item>
    /// </list>
    /// </remarks>
    /// <param name="curve">The ECC curve.</param>
    /// <returns>The ECC parameters configured for ECDH key agreement.</returns>
    public static TpmsEccParms ForKeyAgreement(TpmEccCurveConstants curve) => new()
    {
        Symmetric = TpmtSymDefObject.Null,
        Scheme = TpmtEccScheme.Ecdh(TpmAlgIdConstants.TPM_ALG_SHA256),
        CurveId = curve,
        Kdf = TpmtKdfScheme.Null
    };


    /// <summary>
    /// Creates ECC parameters for a KEM key usable with TPM2_Encapsulate() and TPM2_Decapsulate().
    /// </summary>
    /// <remarks>
    /// <para>
    /// Neither <see cref="ForKeyAgreement"/> (kdf NULL, the ECDH_ZGen shape) nor <see cref="ForSigning"/>
    /// nor <see cref="ForStorage"/> can express the KEM admission gate Table 229 requires: a non-NULL
    /// <see cref="Kdf"/> on an unrestricted decryption <c>TPM_ALG_ECDH</c> key (TPM 2.0 Library Part 2,
    /// Table 229; see <see cref="Kdf"/>'s remarks for the load-bearing sentences). This factory sets
    /// <c>kdf.scheme</c> to <c>TPM_ALG_HKDF</c> — "currently ... the only supported KDF for DHKEM" — which
    /// makes the resulting key DHKEM(<paramref name="curve"/>, HKDF-<paramref name="kdfHashAlg"/>) per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9180">RFC 9180</see>.
    /// </para>
    /// <para>
    /// <paramref name="curve"/> and <paramref name="kdfHashAlg"/> together select the DHKEM suite. The wire
    /// still requires <c>scheme.details.ecdh.hashAlg</c> to hold some value even though Table 229 states it
    /// "is ignored" once <see cref="Kdf"/> is non-NULL — but that ignore-note is scoped to
    /// <c>TPM2_Encapsulate()</c>/<c>TPM2_Decapsulate()</c>, not to object creation, where "all of the bits
    /// of the template are used" (Part 3, clause 24.1.1). <paramref name="schemeHashAlg"/> therefore carries
    /// the caller's own <c>scheme.details.ecdh.hashAlg</c> independently of <paramref name="kdfHashAlg"/> —
    /// the KDF's own hash is the one that actually parameterizes DHKEM's <c>ExtractAndExpand</c>.
    /// </para>
    /// </remarks>
    /// <param name="curve">The ECC curve — the DHKEM's <c>curveID</c>.</param>
    /// <param name="schemeHashAlg">The <c>scheme.details.ecdh.hashAlg</c> to carry — inert on the KEM path, but still template data that a conformant creation must echo unchanged.</param>
    /// <param name="kdfHashAlg">The HKDF hash algorithm — the DHKEM's KDF hash.</param>
    /// <returns>The ECC parameters configured as a KEM key.</returns>
    public static TpmsEccParms ForKeyEncapsulation(TpmEccCurveConstants curve, TpmAlgIdConstants schemeHashAlg, TpmAlgIdConstants kdfHashAlg) => new()
    {
        Symmetric = TpmtSymDefObject.Null,
        Scheme = TpmtEccScheme.Ecdh(schemeHashAlg),
        CurveId = curve,
        Kdf = new TpmtKdfScheme { Scheme = TpmAlgIdConstants.TPM_ALG_HKDF, HashAlg = kdfHashAlg }
    };


    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public int SerializedSize =>
        Symmetric.SerializedSize +
        Scheme.SerializedSize +
        sizeof(ushort) + //CurveID.
        Kdf.SerializedSize;

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        Symmetric.WriteTo(ref writer);
        Scheme.WriteTo(ref writer);
        writer.WriteUInt16((ushort)CurveId);
        Kdf.WriteTo(ref writer);
    }

    /// <summary>
    /// Parses ECC parameters from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <returns>The parsed ECC parameters.</returns>
    public static TpmsEccParms Parse(ref TpmReader reader)
    {
        var symmetric = TpmtSymDefObject.Parse(ref reader);
        var scheme = TpmtEccScheme.Parse(ref reader);
        var curveId = (TpmEccCurveConstants)reader.ReadUInt16();
        var kdf = TpmtKdfScheme.Parse(ref reader);

        return new TpmsEccParms
        {
            Symmetric = symmetric,
            Scheme = scheme,
            CurveId = curveId,
            Kdf = kdf
        };
    }

    private string DebuggerDisplay => $"TPMS_ECC_PARMS({CurveId}, {Scheme.Scheme})";
}
