using System;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// Symmetric algorithm definition for sessions (TPMT_SYM_DEF).
/// </summary>
/// <remarks>
/// <para>
/// This structure selects the algorithm used for session-based parameter encryption. Unlike
/// <see cref="TpmtSymDefObject"/> it admits <see cref="TpmAlgIdConstants.TPM_ALG_XOR"/> (XOR
/// obfuscation), which is the mandatory-to-implement parameter-encryption method; support for a
/// block cipher such as AES in CFB mode is platform specific.
/// </para>
/// <para>
/// <b>Wire format (TPM 2.0 Library Part 2, Section 11.1.6, Table 159):</b>
/// </para>
/// <code>
/// typedef struct {
///     TPMI_ALG_SYM      algorithm;   // Symmetric algorithm (or TPM_ALG_NULL).
///     TPMU_SYM_KEY_BITS keyBits;     // Present when algorithm != TPM_ALG_NULL.
///     TPMU_SYM_MODE     mode;        // Present when algorithm is a block cipher.
/// } TPMT_SYM_DEF;
/// </code>
/// <para>
/// The unions collapse on the wire so the encoded length depends on <see cref="Algorithm"/>:
/// </para>
/// <list type="bullet">
///   <item><description><see cref="TpmAlgIdConstants.TPM_ALG_NULL"/>: only <c>algorithm</c> (no keyBits, no mode).</description></item>
///   <item><description><see cref="TpmAlgIdConstants.TPM_ALG_XOR"/>: <c>algorithm</c> and <c>keyBits</c>, where the
///   <c>keyBits.xor</c> union member is a <c>TPMI_ALG_HASH</c> selecting the KDF hash, not a key size; there is
///   <b>no mode</b> for XOR (Part 2, Section 11.1.4, Table 157 - the mode union is empty under the XOR selector).</description></item>
///   <item><description>A block cipher (for example <see cref="TpmAlgIdConstants.TPM_ALG_AES"/>): <c>algorithm</c>,
///   <c>keyBits</c> (the key size in bits), and <c>mode</c>.</description></item>
/// </list>
/// <para>
/// The <c>details</c> union (Part 2, Section 11.1.5, Table 158) is empty for every algorithm and contributes no
/// wire octets.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmtSymDef
{
    /// <summary>
    /// Gets the symmetric algorithm.
    /// </summary>
    /// <remarks>
    /// <see cref="TpmAlgIdConstants.TPM_ALG_NULL"/> indicates no parameter encryption,
    /// <see cref="TpmAlgIdConstants.TPM_ALG_XOR"/> selects XOR obfuscation, and a block-cipher identifier
    /// (such as <see cref="TpmAlgIdConstants.TPM_ALG_AES"/>) selects CFB-mode encryption.
    /// </remarks>
    public TpmAlgIdConstants Algorithm { get; init; }

    /// <summary>
    /// Gets the <c>keyBits</c> union value.
    /// </summary>
    /// <remarks>
    /// For a block cipher this is the key size in bits (for example 128 or 256). For
    /// <see cref="TpmAlgIdConstants.TPM_ALG_XOR"/> this is a <c>TPMI_ALG_HASH</c> value (the KDF hash) carried
    /// in the same 16-bit field; read it through <see cref="XorHash"/>. It is not present on the wire when
    /// <see cref="Algorithm"/> is <see cref="TpmAlgIdConstants.TPM_ALG_NULL"/>.
    /// </remarks>
    public ushort KeyBits { get; init; }

    /// <summary>
    /// Gets the cipher mode.
    /// </summary>
    /// <remarks>
    /// Meaningful only for a block cipher (for parameter encryption this is
    /// <see cref="TpmAlgIdConstants.TPM_ALG_CFB"/>). It is not present on the wire for
    /// <see cref="TpmAlgIdConstants.TPM_ALG_NULL"/> or <see cref="TpmAlgIdConstants.TPM_ALG_XOR"/>.
    /// </remarks>
    public TpmAlgIdConstants Mode { get; init; }

    /// <summary>
    /// Gets whether this is a null symmetric definition (no parameter encryption).
    /// </summary>
    public bool IsNull => Algorithm == TpmAlgIdConstants.TPM_ALG_NULL;

    /// <summary>
    /// Gets whether this definition selects XOR obfuscation.
    /// </summary>
    public bool IsXor => Algorithm == TpmAlgIdConstants.TPM_ALG_XOR;

    /// <summary>
    /// Gets the KDF hash carried in <see cref="KeyBits"/> for an XOR definition.
    /// </summary>
    /// <remarks>
    /// Only meaningful when <see cref="IsXor"/> is <see langword="true"/>; for XOR the <c>keyBits.xor</c> union
    /// member overloads the 16-bit field with a <c>TPMI_ALG_HASH</c> selector (Part 2, Section 11.1.3).
    /// </remarks>
    public TpmAlgIdConstants XorHash => (TpmAlgIdConstants)KeyBits;

    /// <summary>
    /// Gets a null symmetric definition (no parameter encryption).
    /// </summary>
    public static TpmtSymDef Null => new() { Algorithm = TpmAlgIdConstants.TPM_ALG_NULL };

    /// <summary>
    /// Creates an XOR obfuscation definition keyed to the supplied KDF hash.
    /// </summary>
    /// <param name="hashAlgorithm">
    /// The hash carried in the <c>keyBits.xor</c> field on the wire. This must be the session's authHash: the
    /// XOR mask KDF uses "the hash algorithm associated with the session" (Part 1 §19.2), which the TPM and this
    /// library both take to be the session authHash, not this field. Passing a hash that differs from the
    /// session authHash negotiates an inconsistent value on the wire while both sides still key the mask with
    /// the session authHash.
    /// </param>
    /// <returns>The symmetric definition.</returns>
    public static TpmtSymDef Xor(TpmAlgIdConstants hashAlgorithm) => new()
    {
        Algorithm = TpmAlgIdConstants.TPM_ALG_XOR,
        KeyBits = (ushort)hashAlgorithm,
        Mode = TpmAlgIdConstants.TPM_ALG_NULL
    };

    /// <summary>
    /// Creates an AES CFB definition.
    /// </summary>
    /// <param name="keyBits">Key size in bits (128, 192, or 256).</param>
    /// <param name="mode">Cipher mode; for parameter encryption this is <see cref="TpmAlgIdConstants.TPM_ALG_CFB"/>.</param>
    /// <returns>The symmetric definition.</returns>
    public static TpmtSymDef Aes(ushort keyBits, TpmAlgIdConstants mode) => new()
    {
        Algorithm = TpmAlgIdConstants.TPM_ALG_AES,
        KeyBits = keyBits,
        Mode = mode
    };

    /// <summary>
    /// Gets the serialized size of this structure in octets.
    /// </summary>
    public int SerializedSize
    {
        get
        {
            if(IsNull)
            {
                //algorithm only.
                return sizeof(ushort);
            }

            if(IsXor)
            {
                //algorithm + keyBits (the KDF hash); XOR has no mode.
                return sizeof(ushort) + sizeof(ushort);
            }

            //algorithm + keyBits + mode.
            return sizeof(ushort) + sizeof(ushort) + sizeof(ushort);
        }
    }

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        writer.WriteUInt16((ushort)Algorithm);

        if(IsNull)
        {
            return;
        }

        writer.WriteUInt16(KeyBits);

        if(!IsXor)
        {
            writer.WriteUInt16((ushort)Mode);
        }
    }

    /// <summary>
    /// Parses a symmetric definition from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <returns>The parsed symmetric definition.</returns>
    public static TpmtSymDef Parse(ref TpmReader reader)
    {
        var algorithm = (TpmAlgIdConstants)reader.ReadUInt16();

        if(algorithm == TpmAlgIdConstants.TPM_ALG_NULL)
        {
            return Null;
        }

        ushort keyBits = reader.ReadUInt16();

        if(algorithm == TpmAlgIdConstants.TPM_ALG_XOR)
        {
            return new TpmtSymDef
            {
                Algorithm = algorithm,
                KeyBits = keyBits,
                Mode = TpmAlgIdConstants.TPM_ALG_NULL
            };
        }

        var mode = (TpmAlgIdConstants)reader.ReadUInt16();

        return new TpmtSymDef
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
                return "TPMT_SYM_DEF(NULL)";
            }

            if(IsXor)
            {
                return $"TPMT_SYM_DEF(XOR, {XorHash})";
            }

            return $"TPMT_SYM_DEF({Algorithm}, {KeyBits}, {Mode})";
        }
    }
}
