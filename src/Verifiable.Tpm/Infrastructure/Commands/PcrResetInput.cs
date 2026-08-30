using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_PCR_Reset command (CC = TPM_CC_PCR_Reset, 0x0000013D).
/// </summary>
/// <remarks>
/// <para>
/// Sets the register <see cref="PcrHandle"/> names to zero in every bank, when the register's attributes allow
/// a reset at the command's locality — otherwise <c>TPM_RC_LOCALITY</c> (TPM 2.0 Library Part 3, clause
/// 22.8.1). On a PC Client TPM only PCR 16 (Debug) and PCR 23 (Application Specific) are resettable by software
/// (PTP 1.07, Table 14). <c>pcrHandle</c> is a plain <c>TPMI_DH_PCR</c> (Table 142, no <c>+</c>): "if pcrHandle
/// is out of the allowed range for PCR, then the appropriate return value is TPM_RC_VALUE", and
/// <c>TPM_RH_NULL</c> is out of range.
/// </para>
/// <para>
/// <see cref="PcrHandle"/> carries Auth Index 1 with Auth Role USER: the PCR's EmptyAuth (PTP 1.07, clause 4.7,
/// item 5), exempt from dictionary-attack protection (Part 1, clause 14.7). The command has no parameters and
/// is <c>{NV}</c>.
/// </para>
/// <para>
/// See TPM 2.0 Library Part 3, clause 22.8, Table 142 - TPM2_PCR_Reset.
/// </para>
/// </remarks>
/// <param name="PcrHandle">The register to reset (<c>pcrHandle</c>, TPMI_DH_PCR).</param>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct PcrResetInput(TpmiDhPcr PcrHandle): ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_PCR_Reset;

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        //pcrHandle (TPMI_DH_PCR) only; Table 142 has no parameters.
        return sizeof(uint);
    }

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        PcrHandle.WriteTo(ref writer);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        //Table 142 has no parameter area.
    }

    /// <summary>The debugger display string.</summary>
    private string DebuggerDisplay => $"PcrResetInput(PcrHandle=0x{PcrHandle.Value:X8})";
}
