using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Spec.Algorithms;

/// <summary>
/// TPMI_ALG_KDF — a selector constrained to the key and mask derivation functions implemented on the TPM.
/// </summary>
/// <remarks>
/// <para>
/// Used wherever a command or structure names a key derivation function — for example the <c>kdf</c> of a
/// <c>TPMS_SCHEME_XOR</c> or the secret-sharing KDF of an asymmetric decrypt key.
/// </para>
/// <para>
/// <b>Valid values (v185):</b> the hash-based key and mask generation functions — <c>TPM_ALG_MGF1</c>,
/// <c>TPM_ALG_KDF1_SP800_56A</c>, <c>TPM_ALG_KDF2</c>, <c>TPM_ALG_KDF1_SP800_108</c>, <c>TPM_ALG_HKDF</c> —
/// and, where the embedding structure admits it (the table's leading <c>+</c>), <c>TPM_ALG_NULL</c>.
/// Unmarshaling any other value is <c>TPM_RC_KDF</c>.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 9.36, Table 82.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmiAlgKdf
{
    /// <summary>
    /// Gets the raw algorithm selector.
    /// </summary>
    public TpmAlgIdConstants Value { get; }

    /// <summary>
    /// Initializes a KDF selector from a raw value.
    /// </summary>
    /// <param name="value">The raw algorithm selector.</param>
    public TpmiAlgKdf(TpmAlgIdConstants value)
    {
        Value = value;
    }

    /// <summary>
    /// Gets whether this selector is <c>TPM_ALG_NULL</c>.
    /// </summary>
    public bool IsNull => Value == TpmAlgIdConstants.TPM_ALG_NULL;

    /// <summary>
    /// Whether a raw algorithm value is one of the key and mask derivation functions this type admits.
    /// </summary>
    /// <param name="value">The raw algorithm selector.</param>
    /// <param name="isNullAdmitted">Whether <c>TPM_ALG_NULL</c> is also admitted.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> is admitted.</returns>
    public static bool IsKdf(TpmAlgIdConstants value, bool isNullAdmitted = false) => value switch
    {
        TpmAlgIdConstants.TPM_ALG_MGF1 or
        TpmAlgIdConstants.TPM_ALG_KDF1_SP800_56A or
        TpmAlgIdConstants.TPM_ALG_KDF2 or
        TpmAlgIdConstants.TPM_ALG_KDF1_SP800_108 or
        TpmAlgIdConstants.TPM_ALG_HKDF => true,
        TpmAlgIdConstants.TPM_ALG_NULL => isNullAdmitted,
        _ => false
    };

    /// <summary>
    /// Parses a KDF selector from a TPM reader, validating it against the admitted set.
    /// </summary>
    /// <param name="reader">The reader positioned at the 2-octet selector.</param>
    /// <param name="isNullAdmitted">Whether <c>TPM_ALG_NULL</c> is also admitted.</param>
    /// <returns>The parsed selector.</returns>
    /// <exception cref="InvalidOperationException">The value is not an admitted KDF (<c>TPM_RC_KDF</c>).</exception>
    public static TpmiAlgKdf Parse(ref TpmReader reader, bool isNullAdmitted = false)
    {
        var value = (TpmAlgIdConstants)reader.ReadUInt16();
        if(!IsKdf(value, isNullAdmitted))
        {
            throw new InvalidOperationException($"Invalid KDF 0x{(ushort)value:X4}. Expected a hash-based key or mask derivation function{(isNullAdmitted ? ", or TPM_ALG_NULL" : string.Empty)}.");
        }

        return new TpmiAlgKdf(value);
    }

    /// <summary>
    /// Creates a KDF selector from a raw value without validation — for a value already known good (for
    /// example one retained from a validated command).
    /// </summary>
    /// <param name="value">The raw algorithm selector.</param>
    /// <returns>The selector.</returns>
    public static TpmiAlgKdf FromValue(TpmAlgIdConstants value) => new(value);

    /// <summary>
    /// Writes this selector to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer) => writer.WriteUInt16((ushort)Value);

    private string DebuggerDisplay => $"TPMI_ALG_KDF({Value})";
}
