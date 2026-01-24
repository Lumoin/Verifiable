using System.Diagnostics;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// TPMI_YES_NO - interface type for boolean responses.
/// </summary>
/// <remarks>
/// <para>
/// This is a TPM interface type based on BYTE that represents a boolean value.
/// The TPM uses 0 for NO and any non-zero value for YES.
/// </para>
/// <para>
/// <b>Wire format:</b> Single byte (BYTE).
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 9.2.
/// </para>
/// </remarks>
/// <param name="Value">The raw byte value from the TPM.</param>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmiYesNo(byte Value): ITpmWireType
{
    /// <summary>
    /// Gets whether the value represents YES (non-zero).
    /// </summary>
    public bool IsYes => Value != 0;

    /// <summary>
    /// Gets whether the value represents NO (zero).
    /// </summary>
    public bool IsNo => Value == 0;

    /// <summary>
    /// Parses a TPMI_YES_NO from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <returns>The parsed value.</returns>
    public static TpmiYesNo Parse(ref TpmReader reader)
    {
        return new TpmiYesNo(reader.ReadByte());
    }

    /// <summary>
    /// Implicitly converts to bool for convenient usage.
    /// </summary>
    /// <param name="value">The TPMI_YES_NO value.</param>
    public static implicit operator bool(TpmiYesNo value) => value.IsYes;

    /// <summary>
    /// Creates a YES value.
    /// </summary>
    public static TpmiYesNo Yes => new(1);

    /// <summary>
    /// Creates a NO value.
    /// </summary>
    public static TpmiYesNo No => new(0);

    private string DebuggerDisplay => IsYes ? "TPMI_YES_NO(YES)" : "TPMI_YES_NO(NO)";
}