using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// Key derivation function scheme (TPMT_KDF_SCHEME).
/// </summary>
/// <remarks>
/// <para>
/// This structure defines a key derivation function for deriving symmetric keys
/// from shared secrets (e.g., ECDH Z values).
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     TPMI_ALG_KDF scheme;                     // KDF algorithm (or TPM_ALG_NULL).
///     TPMU_KDF_SCHEME details;                 // KDF parameters (if scheme != NULL).
/// } TPMT_KDF_SCHEME;
/// </code>
/// <para>
/// When scheme is TPM_ALG_NULL, details is not present on the wire.
/// Currently, KDF schemes only contain a hash algorithm parameter: v185's
/// <c>TPMU_KDF_SCHEME</c> (Table 187) adds the <c>hkdf</c> arm, <c>TPMS_KDF_SCHEME_HKDF</c>, but that
/// type is itself just <c>TPMS_SCHEME_HASH</c> (a bare <c>hashAlg</c>) — the same shape every other arm
/// already has, so this structure needs no field change to carry it.
/// </para>
/// <para>
/// <b>v185: TPM_ALG_HKDF and the ECC KEM.</b> Library v185 adds <c>TPM_ALG_HKDF</c> to
/// <c>TPMI_ALG_KDF</c> (Table 82). On an unrestricted decryption <c>TPM_ALG_ECDH</c> ECC key
/// (<see cref="TpmsEccParms.Kdf"/>), a non-<c>NULL</c> <c>kdf</c> here — HKDF is currently the only
/// admitted scheme (TPM 2.0 Library Part 2, Table 229) — marks the key usable with
/// <c>TPM2_Encapsulate()</c> and <c>TPM2_Decapsulate()</c>: the KEM those commands perform is
/// DHKEM(curveID, kdf) per <see href="https://www.rfc-editor.org/rfc/rfc9180">RFC 9180</see> (HPKE),
/// with this scheme's <see cref="HashAlg"/> the KDF's hash. This is a distinct, newer path from
/// <c>TPMS_ECC_PARMS.scheme</c>'s own <c>TPM_ALG_ECDH</c> arm (<see cref="TpmtEccScheme.Ecdh"/>), which
/// selects raw ECDH key agreement (<c>TPM2_ECDH_ZGen</c>) rather than the KEM primitive.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 11.2.3.3.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmtKdfScheme
{
    /// <summary>
    /// Gets the KDF algorithm.
    /// </summary>
    /// <remarks>
    /// Common values: TPM_ALG_KDF1_SP800_56A, TPM_ALG_KDF1_SP800_108, TPM_ALG_HKDF, TPM_ALG_NULL.
    /// </remarks>
    public TpmAlgIdConstants Scheme { get; init; }

    /// <summary>
    /// Gets the hash algorithm for the KDF.
    /// </summary>
    /// <remarks>
    /// Only meaningful when Scheme is not TPM_ALG_NULL.
    /// </remarks>
    public TpmAlgIdConstants HashAlg { get; init; }

    /// <summary>
    /// Gets whether this is a null KDF scheme.
    /// </summary>
    public bool IsNull => Scheme == TpmAlgIdConstants.TPM_ALG_NULL;

    /// <summary>
    /// Gets a null KDF scheme.
    /// </summary>
    public static TpmtKdfScheme Null => new() { Scheme = TpmAlgIdConstants.TPM_ALG_NULL };

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public int SerializedSize
    {
        get
        {
            if(IsNull)
            {
                return sizeof(ushort); // scheme only
            }

            return sizeof(ushort) + sizeof(ushort); // scheme + hashAlg
        }
    }

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        writer.WriteUInt16((ushort)Scheme);

        if(!IsNull)
        {
            writer.WriteUInt16((ushort)HashAlg);
        }
    }

    /// <summary>
    /// Parses a KDF scheme from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <returns>The parsed KDF scheme.</returns>
    public static TpmtKdfScheme Parse(ref TpmReader reader)
    {
        var scheme = (TpmAlgIdConstants)reader.ReadUInt16();

        if(scheme == TpmAlgIdConstants.TPM_ALG_NULL)
        {
            return Null;
        }

        var hashAlg = (TpmAlgIdConstants)reader.ReadUInt16();

        return new TpmtKdfScheme
        {
            Scheme = scheme,
            HashAlg = hashAlg
        };
    }

    private string DebuggerDisplay
    {
        get
        {
            if(IsNull)
            {
                return "TPMT_KDF_SCHEME(NULL)";
            }

            return $"TPMT_KDF_SCHEME({Scheme}, {HashAlg})";
        }
    }
}
