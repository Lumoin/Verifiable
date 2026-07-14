using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_ReadClock command (TPM 2.0 Library Part 3, clause 29.1).
/// </summary>
/// <remarks>
/// <para>
/// <strong>Wire format:</strong> no handles, no authorization, no command parameters. The response carries
/// the current <c>TPMS_TIME_INFO</c> — uncertified and unsigned, unlike <c>TPM2_GetTime()</c>.
/// </para>
/// </remarks>
public readonly record struct ReadClockInput: ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_ReadClock;

    /// <inheritdoc/>
    public int GetSerializedSize() => 0;

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        //TPM2_ReadClock has no input handles.
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        //TPM2_ReadClock has no command parameters.
    }
}
