using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

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
/// Currently, KDF schemes only contain a hash algorithm parameter.
/// </para>
/// <para>
/// <b>Note:</b> Per the spec, there are currently no commands where the KDF
/// parameter has effect, and in the Reference Code this field needs to be
/// set to TPM_ALG_NULL.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 11.2.3.3.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmtKdfScheme
{
    /// <summary>
    /// Gets the KDF algorithm.
    /// </summary>
    /// <remarks>
    /// Common values: TPM_ALG_KDF1_SP800_56A, TPM_ALG_KDF1_SP800_108, TPM_ALG_NULL.
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
    public int GetSerializedSize()
    {
        if(IsNull)
        {
            return sizeof(ushort); // scheme only
        }

        return sizeof(ushort) + sizeof(ushort); // scheme + hashAlg
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