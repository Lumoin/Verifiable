using System;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_PolicyNV command (CC = 0x00000149).
/// </summary>
/// <remarks>
/// <para>
/// Authorizes a policy session only when the contents of an NV Index, at <see cref="Offset"/>, compare to
/// <see cref="OperandB"/> as specified by <see cref="Operation"/> (a TPM_EO comparison). The session's
/// policyDigest is updated as
/// <c>policyDigest = H(policyDigestold || TPM_CC_PolicyNV || H(operandB || offset || operation) || nvIndex.Name)</c>
/// (TPM 2.0 Part 4, <c>PolicyNV</c>); see <see cref="TpmPolicyDigest.ExtendForNv"/>. On a trial session the
/// comparison is skipped and only the digest is updated.
/// </para>
/// <para>
/// Command structure (TPM 2.0 Part 3, Section 23.9):
/// </para>
/// <list type="bullet">
///   <item><description>authHandle (TPMI_RH_NV_AUTH): The authorization for reading the Index (the Index itself, or a hierarchy with the matching read attribute). Requires authorization.</description></item>
///   <item><description>nvIndex (TPMI_RH_NV_INDEX): The NV Index whose contents are compared.</description></item>
///   <item><description>policySession (TPMI_SH_POLICY): The policy session handle (command handle, no authorization).</description></item>
///   <item><description>operandB (TPM2B_OPERAND): The value to compare against.</description></item>
///   <item><description>offset (UINT16): The octet offset into the NV Index data.</description></item>
///   <item><description>operation (TPM_EO): The comparison operation.</description></item>
/// </list>
/// </remarks>
/// <param name="AuthHandle">The authorization handle for reading the Index.</param>
/// <param name="NvIndex">The NV Index whose contents are compared.</param>
/// <param name="PolicySession">The policy session handle.</param>
/// <param name="OperandB">The value to compare the NV data against. The caller owns the underlying memory.</param>
/// <param name="Offset">The octet offset into the NV Index data.</param>
/// <param name="Operation">The comparison operation (TPM_EO).</param>
[DebuggerDisplay("PolicyNvInput(Index=0x{NvIndex,h}, Session=0x{PolicySession,h}, {Operation})")]
public readonly record struct PolicyNvInput(
    uint AuthHandle, uint NvIndex, uint PolicySession, ReadOnlyMemory<byte> OperandB, ushort Offset, TpmEoConstants Operation): ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_PolicyNV;

    /// <inheritdoc/>
    public int GetSerializedSize() =>
        (3 * sizeof(uint))                          //authHandle + nvIndex + policySession
        + sizeof(ushort) + OperandB.Length          //operandB (TPM2B_OPERAND)
        + sizeof(ushort)                            //offset
        + sizeof(ushort);                           //operation (TPM_EO)

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32(AuthHandle);
        writer.WriteUInt32(NvIndex);
        writer.WriteUInt32(PolicySession);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        writer.WriteTpm2b(OperandB.Span);
        writer.WriteUInt16(Offset);
        writer.WriteUInt16((ushort)Operation);
    }
}
