using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// ECC scheme definition (TPMT_ECC_SCHEME).
/// </summary>
/// <remarks>
/// <para>
/// This structure defines the signing or key exchange scheme for an ECC key.
/// The scheme determines how the key is used for signing (ECDSA, ECDAA, SM2, etc.)
/// or key exchange (ECDH).
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     TPMI_ALG_ECC_SCHEME scheme;              // Scheme selector (or TPM_ALG_NULL).
///     TPMU_ASYM_SCHEME details;                // Scheme parameters (if scheme != NULL).
/// } TPMT_ECC_SCHEME;
/// </code>
/// <para>
/// When scheme is TPM_ALG_NULL, details is not present on the wire.
/// For most signing schemes, details contains only a hash algorithm.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 11.2.5.6, Table 201.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmtEccScheme
{
    /// <summary>
    /// Gets the scheme algorithm.
    /// </summary>
    /// <remarks>
    /// Common values: TPM_ALG_ECDSA, TPM_ALG_ECDH, TPM_ALG_ECDAA, TPM_ALG_SM2, TPM_ALG_NULL.
    /// </remarks>
    public TpmAlgIdConstants Scheme { get; init; }

    /// <summary>
    /// Gets the hash algorithm for the scheme.
    /// </summary>
    /// <remarks>
    /// Only meaningful when Scheme is not TPM_ALG_NULL.
    /// For ECDSA: the hash algorithm used for signing.
    /// For ECDH: the KDF hash algorithm.
    /// </remarks>
    public TpmAlgIdConstants HashAlg { get; init; }

    /// <summary>
    /// Gets the count value for ECDAA schemes.
    /// </summary>
    /// <remarks>
    /// Only used for TPM_ALG_ECDAA. Zero for other schemes.
    /// </remarks>
    public ushort Count { get; init; }

    /// <summary>
    /// Gets whether this is a null scheme.
    /// </summary>
    public bool IsNull => Scheme == TpmAlgIdConstants.TPM_ALG_NULL;

    /// <summary>
    /// Gets a null ECC scheme.
    /// </summary>
    public static TpmtEccScheme Null => new() { Scheme = TpmAlgIdConstants.TPM_ALG_NULL };

    /// <summary>
    /// Creates an ECDSA scheme.
    /// </summary>
    /// <param name="hashAlg">The hash algorithm.</param>
    /// <returns>The ECC scheme.</returns>
    public static TpmtEccScheme Ecdsa(TpmAlgIdConstants hashAlg) => new()
    {
        Scheme = TpmAlgIdConstants.TPM_ALG_ECDSA,
        HashAlg = hashAlg
    };

    /// <summary>
    /// Creates an ECDH scheme.
    /// </summary>
    /// <param name="hashAlg">The KDF hash algorithm.</param>
    /// <returns>The ECC scheme.</returns>
    public static TpmtEccScheme Ecdh(TpmAlgIdConstants hashAlg) => new()
    {
        Scheme = TpmAlgIdConstants.TPM_ALG_ECDH,
        HashAlg = hashAlg
    };

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

            if(Scheme == TpmAlgIdConstants.TPM_ALG_ECDAA)
            {
                return sizeof(ushort) + sizeof(ushort) + sizeof(ushort); // scheme + hashAlg + count
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

            if(Scheme == TpmAlgIdConstants.TPM_ALG_ECDAA)
            {
                writer.WriteUInt16(Count);
            }
        }
    }

    /// <summary>
    /// Parses an ECC scheme from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <returns>The parsed ECC scheme.</returns>
    public static TpmtEccScheme Parse(ref TpmReader reader)
    {
        var scheme = (TpmAlgIdConstants)reader.ReadUInt16();

        if(scheme == TpmAlgIdConstants.TPM_ALG_NULL)
        {
            return Null;
        }

        var hashAlg = (TpmAlgIdConstants)reader.ReadUInt16();

        ushort count = 0;
        if(scheme == TpmAlgIdConstants.TPM_ALG_ECDAA)
        {
            count = reader.ReadUInt16();
        }

        return new TpmtEccScheme
        {
            Scheme = scheme,
            HashAlg = hashAlg,
            Count = count
        };
    }

    private string DebuggerDisplay
    {
        get
        {
            if(IsNull)
            {
                return "TPMT_ECC_SCHEME(NULL)";
            }

            if(Scheme == TpmAlgIdConstants.TPM_ALG_ECDAA)
            {
                return $"TPMT_ECC_SCHEME({Scheme}, {HashAlg}, count={Count})";
            }

            return $"TPMT_ECC_SCHEME({Scheme}, {HashAlg})";
        }
    }
}