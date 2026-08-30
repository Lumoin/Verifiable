using System;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Algorithms;

/// <summary>
/// TPMI_RSA_KEY_BITS — a selector constrained to the supported RSA key sizes, in bits.
/// </summary>
/// <remarks>
/// <para>
/// Used as the <c>keyBits</c> of a <c>TPMS_RSA_PARMS</c>, naming the modulus size of an RSA key.
/// </para>
/// <para>
/// <b>Valid values:</b> the sizes named in the TCG reference implementation's <c>RSA_KEY_SIZES_BITS</c> set —
/// 1024, 2048, 3072, and 4096 bits. Table 195 carries no leading <c>+</c>, so there is no NULL-admitting form.
/// Unmarshaling any other value is <c>TPM_RC_VALUE</c>.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 11.2.4.7, Table 195.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmiRsaKeyBits
{
    /// <summary>
    /// Gets the raw key size, in bits.
    /// </summary>
    public ushort Value { get; }

    /// <summary>
    /// Initializes an RSA key size selector from a raw value.
    /// </summary>
    /// <param name="value">The raw key size, in bits.</param>
    public TpmiRsaKeyBits(ushort value)
    {
        Value = value;
    }

    /// <summary>
    /// Whether a raw value is one of the supported RSA key sizes this type admits.
    /// </summary>
    /// <param name="value">The raw key size, in bits.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> is admitted.</returns>
    public static bool IsRsaKeyBits(ushort value) => value switch
    {
        1024 or 2048 or 3072 or 4096 => true,
        _ => false
    };

    /// <summary>
    /// Parses an RSA key size selector from a TPM reader, validating it against the admitted set.
    /// </summary>
    /// <param name="reader">The reader positioned at the 2-octet key size.</param>
    /// <returns>The parsed selector.</returns>
    /// <exception cref="InvalidOperationException">The value is not a supported key size (<c>TPM_RC_VALUE</c>).</exception>
    public static TpmiRsaKeyBits Parse(ref TpmReader reader)
    {
        ushort value = reader.ReadUInt16();
        if(!IsRsaKeyBits(value))
        {
            throw new InvalidOperationException($"Invalid RSA key size {value} bits. Expected 1024, 2048, 3072, or 4096.");
        }

        return new TpmiRsaKeyBits(value);
    }

    /// <summary>
    /// Creates an RSA key size selector from a raw value without validation — for a value already known good
    /// (for example one retained from a validated command).
    /// </summary>
    /// <param name="value">The raw key size, in bits.</param>
    /// <returns>The selector.</returns>
    public static TpmiRsaKeyBits FromValue(ushort value) => new(value);

    /// <summary>
    /// Writes this selector to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer) => writer.WriteUInt16(Value);

    private string DebuggerDisplay => $"TPMI_RSA_KEY_BITS({Value})";
}
