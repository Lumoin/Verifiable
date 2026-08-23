using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Spec.Algorithms;

/// <summary>
/// TPMI_ALG_SYM — a selector constrained to the symmetric algorithms implemented on the TPM.
/// </summary>
/// <remarks>
/// <para>
/// Used wherever a command or structure names a symmetric algorithm rather than a specific block cipher plus
/// mode (for example the algorithm half of a <c>TPMT_SYM_DEF</c>).
/// </para>
/// <para>
/// <b>Valid values:</b> the symmetric block ciphers — <c>TPM_ALG_AES</c>, <c>TPM_ALG_SM4</c>,
/// <c>TPM_ALG_CAMELLIA</c>, <c>TPM_ALG_TDES</c> — plus <c>TPM_ALG_XOR</c>, required to be present, and —
/// where the embedding structure admits it (the table's leading <c>+</c>) — <c>TPM_ALG_NULL</c>, also
/// required to be present in all versions of this table. Unmarshaling any other value is
/// <c>TPM_RC_SYMMETRIC</c>.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 9.33, Table 80.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmiAlgSym
{
    /// <summary>
    /// Gets the raw algorithm selector.
    /// </summary>
    public TpmAlgIdConstants Value { get; }

    /// <summary>
    /// Initializes a symmetric algorithm selector from a raw value.
    /// </summary>
    /// <param name="value">The raw algorithm selector.</param>
    public TpmiAlgSym(TpmAlgIdConstants value)
    {
        Value = value;
    }

    /// <summary>
    /// Gets whether this selector is <c>TPM_ALG_NULL</c>.
    /// </summary>
    public bool IsNull => Value == TpmAlgIdConstants.TPM_ALG_NULL;

    /// <summary>
    /// Whether a raw algorithm value is one of the symmetric algorithms this type admits.
    /// </summary>
    /// <param name="value">The raw algorithm selector.</param>
    /// <param name="isNullAdmitted">Whether <c>TPM_ALG_NULL</c> is also admitted.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> is admitted.</returns>
    public static bool IsAlgSym(TpmAlgIdConstants value, bool isNullAdmitted = false) => value switch
    {
        TpmAlgIdConstants.TPM_ALG_AES or
        TpmAlgIdConstants.TPM_ALG_SM4 or
        TpmAlgIdConstants.TPM_ALG_CAMELLIA or
        TpmAlgIdConstants.TPM_ALG_TDES or
        TpmAlgIdConstants.TPM_ALG_XOR => true,
        TpmAlgIdConstants.TPM_ALG_NULL => isNullAdmitted,
        _ => false
    };

    /// <summary>
    /// Parses a symmetric algorithm selector from a TPM reader, validating it against the admitted set.
    /// </summary>
    /// <param name="reader">The reader positioned at the 2-octet selector.</param>
    /// <param name="isNullAdmitted">Whether <c>TPM_ALG_NULL</c> is also admitted.</param>
    /// <returns>The parsed selector.</returns>
    /// <exception cref="InvalidOperationException">The value is not an admitted symmetric algorithm (<c>TPM_RC_SYMMETRIC</c>).</exception>
    public static TpmiAlgSym Parse(ref TpmReader reader, bool isNullAdmitted = false)
    {
        var value = (TpmAlgIdConstants)reader.ReadUInt16();
        if(!IsAlgSym(value, isNullAdmitted))
        {
            throw new InvalidOperationException($"Invalid symmetric algorithm 0x{(ushort)value:X4}. Expected a symmetric block cipher or TPM_ALG_XOR{(isNullAdmitted ? ", or TPM_ALG_NULL" : string.Empty)}.");
        }

        return new TpmiAlgSym(value);
    }

    /// <summary>
    /// Creates a symmetric algorithm selector from a raw value without validation — for a value already known
    /// good (for example one retained from a validated command).
    /// </summary>
    /// <param name="value">The raw algorithm selector.</param>
    /// <returns>The selector.</returns>
    public static TpmiAlgSym FromValue(TpmAlgIdConstants value) => new(value);

    /// <summary>
    /// Writes this selector to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer) => writer.WriteUInt16((ushort)Value);

    private string DebuggerDisplay => $"TPMI_ALG_SYM({Value})";
}
