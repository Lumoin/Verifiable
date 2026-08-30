using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_PolicyCounterTimer command (CC = 0x0000016D).
/// </summary>
/// <remarks>
/// <para>
/// Authorizes a policy session only when the TPM's live <c>TPMS_TIME_INFO</c> (Time, Clock, resetCount,
/// restartCount, Safe — 25 octets, no padding), at <see cref="Offset"/>, compares to <see cref="OperandB"/> as
/// specified by <see cref="Operation"/> (a TPM_EO comparison). The session's policyDigest is updated as
/// <c>policyDigest = H(policyDigestold || TPM_CC_PolicyCounterTimer || H(operandB || offset || operation))</c>
/// (TPM 2.0 Part 3, Section 23.10); see <see cref="TpmPolicyDigest.ExtendForCounterTimer"/>. On a trial session
/// the comparison is skipped and only the digest is updated.
/// </para>
/// <para>
/// Command structure (TPM 2.0 Part 3, Section 23.10):
/// </para>
/// <list type="bullet">
///   <item><description>policySession (TPMI_SH_POLICY): The policy session handle (command handle, no authorization).</description></item>
///   <item><description>operandB (TPM2B_OPERAND): The value to compare against.</description></item>
///   <item><description>offset (UINT16): The octet offset into the marshaled TPMS_TIME_INFO.</description></item>
///   <item><description>operation (TPM_EO): The comparison operation.</description></item>
/// </list>
/// </remarks>
/// <param name="PolicySession">The policy session handle.</param>
/// <param name="OperandB">The value to compare the live TPMS_TIME_INFO against, at most <see cref="Tpm2bOperand.MaxSize"/> octets. The caller owns the underlying memory.</param>
/// <param name="Offset">The octet offset into the marshaled TPMS_TIME_INFO.</param>
/// <param name="Operation">The comparison operation (TPM_EO).</param>
/// <exception cref="ArgumentException"><paramref name="OperandB"/> is longer than <see cref="Tpm2bOperand.MaxSize"/>.</exception>
[DebuggerDisplay("PolicyCounterTimerInput(Session=0x{PolicySession,h}, {Operation})")]
public readonly record struct PolicyCounterTimerInput(
    uint PolicySession, ReadOnlyMemory<byte> OperandB, ushort Offset, TpmEoConstants Operation): ITpmCommandInput
{
    /// <summary>
    /// Gets the value the live <c>TPMS_TIME_INFO</c> is compared against, bounded at construction by
    /// <see cref="Tpm2bOperand.MaxSize"/>.
    /// </summary>
    public ReadOnlyMemory<byte> OperandB
    {
        get => field;
        init => field = EnsureWithinOperandBound(value);
    } = EnsureWithinOperandBound(OperandB);

    /// <summary>
    /// Refuses an operand the <c>TPM2B_OPERAND</c> wire type cannot carry, so the caller learns it at
    /// construction rather than from the TPM's <c>TPM_RC_SIZE</c> after a round trip. Part 2, clause 10.3.6,
    /// Table 94 bounds <c>TPM2B_OPERAND</c> by the digest structure's own <c>sizeof(TPMU_HA)</c>.
    /// </summary>
    /// <param name="candidate">The operand offered by the caller.</param>
    /// <returns><paramref name="candidate"/> when it is within the bound.</returns>
    /// <exception cref="ArgumentException"><paramref name="candidate"/> is longer than <see cref="Tpm2bOperand.MaxSize"/>.</exception>
    private static ReadOnlyMemory<byte> EnsureWithinOperandBound(ReadOnlyMemory<byte> candidate)
    {
        if(candidate.Length > Tpm2bOperand.MaxSize)
        {
            throw new ArgumentException($"Operand too large. Maximum is {Tpm2bOperand.MaxSize} bytes.", nameof(candidate));
        }

        return candidate;
    }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_PolicyCounterTimer;

    /// <inheritdoc/>
    public int GetSerializedSize() =>
        sizeof(uint)                                //policySession (handle area).
        + sizeof(ushort) + OperandB.Length          //operandB (TPM2B_OPERAND).
        + sizeof(ushort)                            //offset.
        + sizeof(ushort);                           //operation (TPM_EO).

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
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
