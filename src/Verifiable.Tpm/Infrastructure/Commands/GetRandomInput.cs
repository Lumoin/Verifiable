using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for TPM2_GetRandom command.
/// </summary>
/// <remarks>
/// <para>
/// This command returns the requested number of random bytes from the TPM's
/// random number generator.
/// </para>
/// <para>
/// <strong>Handle area:</strong> None (0 handles).
/// </para>
/// <para>
/// <strong>Parameter area:</strong>
/// </para>
/// <list type="bullet">
///   <item><description>bytesRequested (UINT16) - number of bytes to generate.</description></item>
/// </list>
/// <para>
/// See TPM 2.0 Part 3, Section 16.1 - TPM2_GetRandom.
/// </para>
/// </remarks>
public readonly record struct GetRandomInput(ushort BytesRequested): ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_GetRandom;

    /// <inheritdoc/>
    public int GetSerializedSize() => sizeof(ushort);

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        //GetRandom has no input handles.
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        writer.WriteUInt16(BytesRequested);
    }
}