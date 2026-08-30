using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Spec.Algorithms;

/// <summary>
/// TPMI_ALG_SIG_SCHEME — a selector constrained to the signature schemes.
/// </summary>
/// <remarks>
/// <para>
/// Used as the <c>sigAlg</c> of a <c>TPMT_SIGNATURE</c> and the <c>scheme</c> of a <c>TPMT_SIG_SCHEME</c>.
/// </para>
/// <para>
/// <b>Valid values:</b> every asymmetric signing scheme including the anonymous and stateful ones —
/// <c>TPM_ALG_RSASSA</c>, <c>TPM_ALG_RSAPSS</c>, <c>TPM_ALG_ECDSA</c>, <c>TPM_ALG_ECDAA</c>,
/// <c>TPM_ALG_SM2</c>, <c>TPM_ALG_ECSCHNORR</c>, <c>TPM_ALG_EDDSA</c>, <c>TPM_ALG_EDDSA_PH</c>,
/// <c>TPM_ALG_LMS</c>, <c>TPM_ALG_XMSS</c> — plus <c>TPM_ALG_HMAC</c>, present in all TPM
/// implementations, and — where the embedding structure admits it (the table's leading <c>+</c>) —
/// <c>TPM_ALG_NULL</c>. Unmarshaling any other value is <c>TPM_RC_SCHEME</c>.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 9.37, Table 83.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmiAlgSigScheme
{
    /// <summary>
    /// Gets the raw algorithm selector.
    /// </summary>
    public TpmAlgIdConstants Value { get; }

    /// <summary>
    /// Initializes a signature scheme selector from a raw value.
    /// </summary>
    /// <param name="value">The raw algorithm selector.</param>
    public TpmiAlgSigScheme(TpmAlgIdConstants value)
    {
        Value = value;
    }

    /// <summary>
    /// Gets whether this selector is <c>TPM_ALG_NULL</c>.
    /// </summary>
    public bool IsNull => Value == TpmAlgIdConstants.TPM_ALG_NULL;

    /// <summary>
    /// Whether a raw algorithm value is one of the signature schemes this type admits.
    /// </summary>
    /// <param name="value">The raw algorithm selector.</param>
    /// <param name="isNullAdmitted">Whether <c>TPM_ALG_NULL</c> is also admitted.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> is admitted.</returns>
    public static bool IsSigScheme(TpmAlgIdConstants value, bool isNullAdmitted = false) => value switch
    {
        TpmAlgIdConstants.TPM_ALG_RSASSA or
        TpmAlgIdConstants.TPM_ALG_RSAPSS or
        TpmAlgIdConstants.TPM_ALG_ECDSA or
        TpmAlgIdConstants.TPM_ALG_ECDAA or
        TpmAlgIdConstants.TPM_ALG_SM2 or
        TpmAlgIdConstants.TPM_ALG_ECSCHNORR or
        TpmAlgIdConstants.TPM_ALG_EDDSA or
        TpmAlgIdConstants.TPM_ALG_EDDSA_PH or
        TpmAlgIdConstants.TPM_ALG_LMS or
        TpmAlgIdConstants.TPM_ALG_XMSS or
        TpmAlgIdConstants.TPM_ALG_HMAC => true,
        TpmAlgIdConstants.TPM_ALG_NULL => isNullAdmitted,
        _ => false
    };

    /// <summary>
    /// Parses a signature scheme selector from a TPM reader, validating it against the admitted set.
    /// </summary>
    /// <param name="reader">The reader positioned at the 2-octet selector.</param>
    /// <param name="isNullAdmitted">Whether <c>TPM_ALG_NULL</c> is also admitted.</param>
    /// <returns>The parsed selector.</returns>
    /// <exception cref="InvalidOperationException">The value is not an admitted signature scheme (<c>TPM_RC_SCHEME</c>).</exception>
    public static TpmiAlgSigScheme Parse(ref TpmReader reader, bool isNullAdmitted = false)
    {
        var value = (TpmAlgIdConstants)reader.ReadUInt16();
        if(!IsSigScheme(value, isNullAdmitted))
        {
            throw new InvalidOperationException($"Invalid signature scheme 0x{(ushort)value:X4}. Expected an asymmetric signing scheme or TPM_ALG_HMAC{(isNullAdmitted ? ", or TPM_ALG_NULL" : string.Empty)}.");
        }

        return new TpmiAlgSigScheme(value);
    }

    /// <summary>
    /// Creates a signature scheme selector from a raw value without validation — for a value already known
    /// good (for example one retained from a validated command).
    /// </summary>
    /// <param name="value">The raw algorithm selector.</param>
    /// <returns>The selector.</returns>
    public static TpmiAlgSigScheme FromValue(TpmAlgIdConstants value) => new(value);

    /// <summary>
    /// Writes this selector to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer) => writer.WriteUInt16((ushort)Value);

    private string DebuggerDisplay => $"TPMI_ALG_SIG_SCHEME({Value})";
}
