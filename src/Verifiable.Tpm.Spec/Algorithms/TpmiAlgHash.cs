using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Spec.Algorithms;

/// <summary>
/// TPMI_ALG_HASH — a selector constrained to the TCG-defined hash algorithms.
/// </summary>
/// <remarks>
/// <para>
/// Used wherever a command or structure names the hash algorithm that digests a message — for example an
/// object's <c>nameAlg</c>, or the hash algorithm carried by a signing or key-derivation scheme.
/// </para>
/// <para>
/// <b>Valid values:</b> every <see cref="TpmAlgIdConstants"/> member the TCG algorithm registry marks as a
/// hash algorithm (<see cref="TpmAlgIdExtensions.IsHashAlgorithm"/>), and — only where the embedding
/// structure admits it (the table's leading <c>+</c>) — <c>TPM_ALG_NULL</c>. Unmarshaling any other value is
/// <c>TPM_RC_HASH</c>.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 9.31, Table 77.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmiAlgHash
{
    /// <summary>
    /// Gets the raw algorithm selector.
    /// </summary>
    public TpmAlgIdConstants Value { get; }

    /// <summary>
    /// Initializes a hash algorithm selector from a raw value.
    /// </summary>
    /// <param name="value">The raw algorithm selector.</param>
    public TpmiAlgHash(TpmAlgIdConstants value)
    {
        Value = value;
    }

    /// <summary>
    /// Gets whether this selector is <c>TPM_ALG_NULL</c>.
    /// </summary>
    public bool IsNull => Value == TpmAlgIdConstants.TPM_ALG_NULL;

    /// <summary>
    /// Gets the digest size in octets this hash algorithm produces, or <see langword="null"/> when
    /// <see cref="Value"/> is not a hash algorithm (for example <c>TPM_ALG_NULL</c>).
    /// </summary>
    public int? DigestSize => Value.GetDigestSize();

    /// <summary>
    /// Whether a raw algorithm value is one of the TCG-defined hash algorithms this type admits.
    /// </summary>
    /// <param name="value">The raw algorithm selector.</param>
    /// <param name="isNullAdmitted">Whether <c>TPM_ALG_NULL</c> is also admitted.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> is admitted.</returns>
    public static bool IsAlgHash(TpmAlgIdConstants value, bool isNullAdmitted = false)
    {
        return value.IsHashAlgorithm() || (isNullAdmitted && value == TpmAlgIdConstants.TPM_ALG_NULL);
    }

    /// <summary>
    /// Parses a hash algorithm selector from a TPM reader, validating it against the admitted set.
    /// </summary>
    /// <param name="reader">The reader positioned at the 2-octet selector.</param>
    /// <param name="isNullAdmitted">Whether <c>TPM_ALG_NULL</c> is also admitted.</param>
    /// <returns>The parsed selector.</returns>
    /// <exception cref="InvalidOperationException">The value is not an admitted hash algorithm (<c>TPM_RC_HASH</c>).</exception>
    public static TpmiAlgHash Parse(ref TpmReader reader, bool isNullAdmitted = false)
    {
        var value = (TpmAlgIdConstants)reader.ReadUInt16();
        if(!IsAlgHash(value, isNullAdmitted))
        {
            throw new InvalidOperationException($"Invalid hash algorithm 0x{(ushort)value:X4}. Expected a TCG-defined hash algorithm{(isNullAdmitted ? " or TPM_ALG_NULL" : string.Empty)}.");
        }

        return new TpmiAlgHash(value);
    }

    /// <summary>
    /// Creates a hash algorithm selector from a raw value without validation — for a value already known good
    /// (for example one retained from a validated command).
    /// </summary>
    /// <param name="value">The raw algorithm selector.</param>
    /// <returns>The selector.</returns>
    public static TpmiAlgHash FromValue(TpmAlgIdConstants value) => new(value);

    /// <summary>
    /// Writes this selector to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer) => writer.WriteUInt16((ushort)Value);

    private string DebuggerDisplay => $"TPMI_ALG_HASH({Value})";
}
