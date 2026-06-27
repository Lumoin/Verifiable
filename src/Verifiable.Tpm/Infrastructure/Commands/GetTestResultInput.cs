using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_GetTestResult command (TPM 2.0 Library Part 1, clauses 10.3 and 10.4;
/// Part 3, clause 10.4).
/// </summary>
/// <remarks>
/// <para>
/// <strong>Wire format:</strong> no handles, no authorization, no command parameters. The response
/// carries an outData buffer and the test result code.
/// </para>
/// </remarks>
public readonly record struct GetTestResultInput: ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_GetTestResult;

    /// <inheritdoc/>
    public int GetSerializedSize() => 0;

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        //TPM2_GetTestResult has no input handles.
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        //TPM2_GetTestResult has no command parameters.
    }
}
