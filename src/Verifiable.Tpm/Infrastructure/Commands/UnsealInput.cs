using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_Unseal command - recovers the data sealed in a loaded KEYEDHASH object.
/// </summary>
/// <remarks>
/// <para>
/// <c>TPM2_Unseal()</c> returns the sensitive data of a loaded sealed data object (a KEYEDHASH object created
/// with <c>TPM2_Create()</c> from a <see cref="Spec.Structures.TpmtPublic.CreateSealedDataTemplate"/> template).
/// The object must be loaded (its transient handle is the command handle) and the caller must satisfy its
/// authorization, so only this TPM - under the parent that wrapped the object - can recover the secret.
/// </para>
/// <para>
/// <b>Command structure:</b>
/// </para>
/// <code>
/// TPMI_ST_COMMAND_TAG  tag             TPM_ST_SESSIONS
/// UINT32               commandSize
/// TPM_CC               commandCode     TPM_CC_Unseal
/// TPMI_DH_OBJECT       @itemHandle     Loaded sealed data object (requires authorization)
/// </code>
/// <para>
/// The command has no parameter area. Its single response parameter (<c>outData</c>) is a sized buffer, so it
/// is eligible for session-based parameter encryption - the recovered secret can be returned over an
/// AES-CFB-encrypted channel.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 3, Section 12.7 (Table 32).
/// </para>
/// </remarks>
public readonly record struct UnsealInput: ITpmCommandInput
{
    /// <summary>
    /// Gets the handle of the loaded sealed data object (Auth Index 1, Auth Role USER).
    /// </summary>
    public required TpmiDhObject ItemHandle { get; init; }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_Unseal;

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        //One command handle, no parameter area.
        return sizeof(uint);
    }

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        ItemHandle.WriteTo(ref writer);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        //TPM2_Unseal has no parameters.
    }

    /// <summary>
    /// Creates an Unseal input for the specified loaded sealed data object.
    /// </summary>
    /// <param name="itemHandle">The transient handle of the loaded sealed data object.</param>
    /// <returns>The command input.</returns>
    public static UnsealInput ForItem(TpmiDhObject itemHandle) => new()
    {
        ItemHandle = itemHandle
    };
}
