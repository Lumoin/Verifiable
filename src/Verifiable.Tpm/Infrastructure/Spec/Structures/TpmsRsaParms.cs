using System.Diagnostics;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// RSA key parameters (TPMS_RSA_PARMS).
/// </summary>
/// <remarks>
/// <para>
/// This structure defines the parameters for an RSA key in the public area.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     TPMT_SYM_DEF_OBJECT symmetric;           // Symmetric algorithm for restricted decryption keys.
///     TPMT_RSA_SCHEME scheme;                  // Signing or encryption scheme.
///     TPMI_RSA_KEY_BITS keyBits;               // Number of bits in the public modulus.
///     UINT32 exponent;                         // Public exponent (0 = default 2^16+1).
/// } TPMS_RSA_PARMS;
/// </code>
/// <para>
/// An exponent of zero indicates the default exponent of 2^16+1 (65537).
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 12.2.3.5, Table 215.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmsRsaParms
{
    /// <summary>
    /// Default RSA public exponent (2^16 + 1 = 65537).
    /// </summary>
    public const uint DefaultExponent = 65537;

    /// <summary>
    /// Gets the symmetric algorithm for restricted decryption keys.
    /// </summary>
    /// <remarks>
    /// For non-restricted or signing keys, this should be null (TPM_ALG_NULL).
    /// </remarks>
    public TpmtSymDefObject Symmetric { get; init; }

    /// <summary>
    /// Gets the signing or encryption scheme.
    /// </summary>
    /// <remarks>
    /// For signing keys: RSASSA or RSAPSS.
    /// For decryption keys: RSAES, OAEP, or TPM_ALG_NULL.
    /// For storage keys: TPM_ALG_NULL.
    /// </remarks>
    public TpmtRsaScheme Scheme { get; init; }

    /// <summary>
    /// Gets the number of bits in the public modulus.
    /// </summary>
    /// <remarks>
    /// Common values: 1024, 2048, 3072, 4096.
    /// </remarks>
    public ushort KeyBits { get; init; }

    /// <summary>
    /// Gets the public exponent.
    /// </summary>
    /// <remarks>
    /// Zero indicates the default exponent (65537).
    /// Non-zero values must be odd and greater than 2.
    /// </remarks>
    public uint Exponent { get; init; }

    /// <summary>
    /// Gets the effective exponent value.
    /// </summary>
    /// <remarks>
    /// Returns the actual exponent, converting zero to the default value.
    /// </remarks>
    public uint EffectiveExponent => Exponent == 0 ? DefaultExponent : Exponent;

    /// <summary>
    /// Creates RSA parameters for a signing key.
    /// </summary>
    /// <param name="keyBits">Key size in bits.</param>
    /// <param name="scheme">The signing scheme.</param>
    /// <returns>The RSA parameters.</returns>
    public static TpmsRsaParms ForSigning(ushort keyBits, TpmtRsaScheme scheme) => new()
    {
        Symmetric = TpmtSymDefObject.Null,
        Scheme = scheme,
        KeyBits = keyBits,
        Exponent = 0 // Default
    };

    /// <summary>
    /// Creates RSA parameters for a storage key.
    /// </summary>
    /// <param name="keyBits">Key size in bits.</param>
    /// <param name="symmetric">The symmetric algorithm for child key protection.</param>
    /// <returns>The RSA parameters.</returns>
    public static TpmsRsaParms ForStorage(ushort keyBits, TpmtSymDefObject symmetric) => new()
    {
        Symmetric = symmetric,
        Scheme = TpmtRsaScheme.Null,
        KeyBits = keyBits,
        Exponent = 0 //Default.
    };

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public int SerializedSize =>
        Symmetric.SerializedSize +
        Scheme.SerializedSize +
        sizeof(ushort) + //KeyBits.
        sizeof(uint);    //Exponent.

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        Symmetric.WriteTo(ref writer);
        Scheme.WriteTo(ref writer);
        writer.WriteUInt16(KeyBits);
        writer.WriteUInt32(Exponent);
    }

    /// <summary>
    /// Parses RSA parameters from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <returns>The parsed RSA parameters.</returns>
    public static TpmsRsaParms Parse(ref TpmReader reader)
    {
        var symmetric = TpmtSymDefObject.Parse(ref reader);
        var scheme = TpmtRsaScheme.Parse(ref reader);
        ushort keyBits = reader.ReadUInt16();
        uint exponent = reader.ReadUInt32();

        return new TpmsRsaParms
        {
            Symmetric = symmetric,
            Scheme = scheme,
            KeyBits = keyBits,
            Exponent = exponent
        };
    }

    private string DebuggerDisplay => $"TPMS_RSA_PARMS({KeyBits} bits, {Scheme.Scheme})";
}