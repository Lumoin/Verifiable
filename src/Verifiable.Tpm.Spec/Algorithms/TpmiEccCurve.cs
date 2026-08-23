using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Spec.Algorithms;

/// <summary>
/// TPMI_ECC_CURVE — a selector constrained to the ECC curves implemented by the TPM.
/// </summary>
/// <remarks>
/// <para>
/// Used as the <c>curveID</c> of a <c>TPMS_ECC_PARMS</c>, naming the named curve an ECC key or ECC
/// computation uses.
/// </para>
/// <para>
/// <b>Valid values:</b> every <see cref="TpmEccCurveConstants"/> member other than <c>TPM_ECC_NONE</c>, and —
/// where the embedding structure admits it (the table's leading <c>+</c>) — <c>TPM_ECC_NONE</c> itself.
/// Unmarshaling any other value is <c>TPM_RC_CURVE</c>.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 11.2.5.5, Table 200.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmiEccCurve
{
    /// <summary>
    /// Gets the raw curve selector.
    /// </summary>
    public TpmEccCurveConstants Value { get; }

    /// <summary>
    /// Initializes a curve selector from a raw value.
    /// </summary>
    /// <param name="value">The raw curve selector.</param>
    public TpmiEccCurve(TpmEccCurveConstants value)
    {
        Value = value;
    }

    /// <summary>
    /// Gets whether this selector is <c>TPM_ECC_NONE</c>.
    /// </summary>
    public bool IsNone => Value == TpmEccCurveConstants.TPM_ECC_NONE;

    /// <summary>
    /// Whether a raw curve value is one of the implemented curves this type admits.
    /// </summary>
    /// <param name="value">The raw curve selector.</param>
    /// <param name="isNoneAdmitted">Whether <c>TPM_ECC_NONE</c> is also admitted.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> is admitted.</returns>
    public static bool IsEccCurve(TpmEccCurveConstants value, bool isNoneAdmitted = false) => value switch
    {
        TpmEccCurveConstants.TPM_ECC_NONE => isNoneAdmitted,
        TpmEccCurveConstants.TPM_ECC_NIST_P192 or
        TpmEccCurveConstants.TPM_ECC_NIST_P224 or
        TpmEccCurveConstants.TPM_ECC_NIST_P256 or
        TpmEccCurveConstants.TPM_ECC_NIST_P384 or
        TpmEccCurveConstants.TPM_ECC_NIST_P521 or
        TpmEccCurveConstants.TPM_ECC_BN_P256 or
        TpmEccCurveConstants.TPM_ECC_BN_P638 or
        TpmEccCurveConstants.TPM_ECC_SM2_P256 or
        TpmEccCurveConstants.TPM_ECC_BP_P256_R1 or
        TpmEccCurveConstants.TPM_ECC_BP_P384_R1 or
        TpmEccCurveConstants.TPM_ECC_BP_P512_R1 or
        TpmEccCurveConstants.TPM_ECC_CURVE_25519 or
        TpmEccCurveConstants.TPM_ECC_CURVE_448 => true,
        _ => false
    };

    /// <summary>
    /// Parses a curve selector from a TPM reader, validating it against the admitted set.
    /// </summary>
    /// <param name="reader">The reader positioned at the 2-octet selector.</param>
    /// <param name="isNoneAdmitted">Whether <c>TPM_ECC_NONE</c> is also admitted.</param>
    /// <returns>The parsed selector.</returns>
    /// <exception cref="InvalidOperationException">The value is not an admitted curve (<c>TPM_RC_CURVE</c>).</exception>
    public static TpmiEccCurve Parse(ref TpmReader reader, bool isNoneAdmitted = false)
    {
        var value = (TpmEccCurveConstants)reader.ReadUInt16();
        if(!IsEccCurve(value, isNoneAdmitted))
        {
            throw new InvalidOperationException($"Invalid ECC curve 0x{(ushort)value:X4}. Expected an implemented TPM_ECC_CURVE{(isNoneAdmitted ? ", or TPM_ECC_NONE" : string.Empty)}.");
        }

        return new TpmiEccCurve(value);
    }

    /// <summary>
    /// Creates a curve selector from a raw value without validation — for a value already known good (for
    /// example one retained from a validated command).
    /// </summary>
    /// <param name="value">The raw curve selector.</param>
    /// <returns>The selector.</returns>
    public static TpmiEccCurve FromValue(TpmEccCurveConstants value) => new(value);

    /// <summary>
    /// Writes this selector to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer) => writer.WriteUInt16((ushort)Value);

    private string DebuggerDisplay => $"TPMI_ECC_CURVE({Value})";
}
