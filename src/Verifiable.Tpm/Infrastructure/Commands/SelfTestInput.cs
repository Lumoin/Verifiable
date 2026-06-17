using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_SelfTest command (TPM 2.0 Library Part 1, clause 10.3; Part 3, clause 10.2).
/// </summary>
/// <remarks>
/// <para>
/// <strong>Wire format:</strong> a single <c>fullTest</c> flag (TPMI_YES_NO, one octet). No handles,
/// no authorization, no response parameters.
/// </para>
/// </remarks>
/// <param name="IsFullTest">
/// <see langword="true"/> to test all algorithms and functional blocks; <see langword="false"/> to
/// test only those not yet tested.
/// </param>
public readonly record struct SelfTestInput(bool IsFullTest): ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_SelfTest;

    /// <inheritdoc/>
    public int GetSerializedSize() => sizeof(byte);

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        //TPM2_SelfTest has no input handles.
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer) => writer.WriteByte(IsFullTest ? (byte)1 : (byte)0);
}
