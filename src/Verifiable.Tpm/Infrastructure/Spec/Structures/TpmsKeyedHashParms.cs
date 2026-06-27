using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// Parameters for a keyed-hash object (TPMS_KEYEDHASH_PARMS).
/// </summary>
/// <remarks>
/// <para>
/// A keyed-hash object is either an HMAC/XOR key (the scheme selects the algorithm and its hash) or a sealed
/// data object (scheme <c>TPM_ALG_NULL</c>, no details). Sealing data to the TPM uses the null scheme.
/// </para>
/// <para>
/// <b>Wire format:</b> TPMT_KEYEDHASH_SCHEME scheme = scheme selector (TPMI_ALG_KEYEDHASH_SCHEME, UINT16),
/// followed by TPMU_SCHEME_KEYEDHASH details — a hash algorithm (TPMI_ALG_HASH, UINT16) for HMAC/XOR, and
/// nothing for TPM_ALG_NULL.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 12.2.3.3, Table 184.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmsKeyedHashParms
{
    /// <summary>
    /// Gets the keyed-hash scheme (TPM_ALG_HMAC, TPM_ALG_XOR, or TPM_ALG_NULL).
    /// </summary>
    public TpmAlgIdConstants Scheme { get; init; }

    /// <summary>
    /// Gets the hash algorithm for the scheme; meaningful only when <see cref="Scheme"/> is not TPM_ALG_NULL.
    /// </summary>
    public TpmAlgIdConstants HashAlg { get; init; }

    /// <summary>
    /// Gets whether this is the null scheme (a sealed data object rather than an HMAC/XOR key).
    /// </summary>
    public bool IsNull => Scheme == TpmAlgIdConstants.TPM_ALG_NULL;

    /// <summary>
    /// Gets the null-scheme parameters used for a sealed data object.
    /// </summary>
    public static TpmsKeyedHashParms SealedData => new() { Scheme = TpmAlgIdConstants.TPM_ALG_NULL };

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public int SerializedSize => IsNull ? sizeof(ushort) : sizeof(ushort) + sizeof(ushort);

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
    /// Parses a keyed-hash parameters structure from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <returns>The parsed parameters.</returns>
    public static TpmsKeyedHashParms Parse(ref TpmReader reader)
    {
        var scheme = (TpmAlgIdConstants)reader.ReadUInt16();
        if(scheme == TpmAlgIdConstants.TPM_ALG_NULL)
        {
            return new TpmsKeyedHashParms { Scheme = scheme };
        }

        var hashAlg = (TpmAlgIdConstants)reader.ReadUInt16();

        return new TpmsKeyedHashParms { Scheme = scheme, HashAlg = hashAlg };
    }

    private string DebuggerDisplay => IsNull ? "TPMS_KEYEDHASH_PARMS(NULL)" : $"TPMS_KEYEDHASH_PARMS({Scheme}, {HashAlg})";
}
