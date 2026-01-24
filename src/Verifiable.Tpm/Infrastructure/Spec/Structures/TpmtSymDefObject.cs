using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// Symmetric algorithm definition for objects (TPMT_SYM_DEF_OBJECT).
/// </summary>
/// <remarks>
/// <para>
/// This structure defines a symmetric block cipher for use in object parameters.
/// If the object can be a parent, this must be the first field in the object's
/// parameter area.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     TPMI_ALG_SYM_OBJECT algorithm;           // Symmetric algorithm (or TPM_ALG_NULL).
///     TPMU_SYM_KEY_BITS keyBits;               // Key size (if algorithm != NULL).
///     TPMU_SYM_MODE mode;                      // Mode (if algorithm != NULL).
/// } TPMT_SYM_DEF_OBJECT;
/// </code>
/// <para>
/// When algorithm is TPM_ALG_NULL, keyBits and mode are not present on the wire.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 11.1.7, Table 160.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmtSymDefObject
{
    /// <summary>
    /// Gets the symmetric algorithm.
    /// </summary>
    /// <remarks>
    /// TPM_ALG_NULL indicates no symmetric algorithm.
    /// Common values: TPM_ALG_AES, TPM_ALG_SM4, TPM_ALG_CAMELLIA.
    /// </remarks>
    public TpmAlgIdConstants Algorithm { get; init; }

    /// <summary>
    /// Gets the key size in bits.
    /// </summary>
    /// <remarks>
    /// Only meaningful when Algorithm is not TPM_ALG_NULL.
    /// Common values: 128, 192, 256.
    /// </remarks>
    public ushort KeyBits { get; init; }

    /// <summary>
    /// Gets the cipher mode.
    /// </summary>
    /// <remarks>
    /// Only meaningful when Algorithm is not TPM_ALG_NULL.
    /// For parent objects, this shall be TPM_ALG_CFB.
    /// </remarks>
    public TpmAlgIdConstants Mode { get; init; }

    /// <summary>
    /// Gets whether this is a null symmetric definition.
    /// </summary>
    public bool IsNull => Algorithm == TpmAlgIdConstants.TPM_ALG_NULL;

    /// <summary>
    /// Gets a null symmetric definition.
    /// </summary>
    public static TpmtSymDefObject Null => new() { Algorithm = TpmAlgIdConstants.TPM_ALG_NULL };

    /// <summary>
    /// Creates an AES symmetric definition.
    /// </summary>
    /// <param name="keyBits">Key size in bits (128, 192, or 256).</param>
    /// <param name="mode">Cipher mode.</param>
    /// <returns>The symmetric definition.</returns>
    public static TpmtSymDefObject Aes(ushort keyBits, TpmAlgIdConstants mode) => new()
    {
        Algorithm = TpmAlgIdConstants.TPM_ALG_AES,
        KeyBits = keyBits,
        Mode = mode
    };

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public int GetSerializedSize()
    {
        if(IsNull)
        {
            return sizeof(ushort); // algorithm only
        }

        return sizeof(ushort) + sizeof(ushort) + sizeof(ushort); // algorithm + keyBits + mode
    }

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        writer.WriteUInt16((ushort)Algorithm);

        if(!IsNull)
        {
            writer.WriteUInt16(KeyBits);
            writer.WriteUInt16((ushort)Mode);
        }
    }

    /// <summary>
    /// Parses a symmetric definition from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <returns>The parsed symmetric definition.</returns>
    public static TpmtSymDefObject Parse(ref TpmReader reader)
    {
        var algorithm = (TpmAlgIdConstants)reader.ReadUInt16();

        if(algorithm == TpmAlgIdConstants.TPM_ALG_NULL)
        {
            return Null;
        }

        ushort keyBits = reader.ReadUInt16();
        var mode = (TpmAlgIdConstants)reader.ReadUInt16();

        return new TpmtSymDefObject
        {
            Algorithm = algorithm,
            KeyBits = keyBits,
            Mode = mode
        };
    }

    private string DebuggerDisplay
    {
        get
        {
            if(IsNull)
            {
                return "TPMT_SYM_DEF_OBJECT(NULL)";
            }

            return $"TPMT_SYM_DEF_OBJECT({Algorithm}, {KeyBits}, {Mode})";
        }
    }
}