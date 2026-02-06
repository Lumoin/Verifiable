using System.Diagnostics;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

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
/// Specification reference: TPM 2.0 Library Part 2, Section 12.2.3.6, Table 216.
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
    /// Currently has no effect in TPM commands. Should be TPM_ALG_NULL.
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