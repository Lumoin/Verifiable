using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_ReadPublic command (CC = 0x00000173).
/// </summary>
/// <remarks>
/// <para>
/// Reads the public area of a loaded object. No authorization is required.
/// </para>
/// <para>
/// Command structure (TPM 2.0 Library Part 3, clause 12.4):
/// </para>
/// <list type="bullet">
///   <item><description>objectHandle (TPMI_DH_OBJECT): Handle of the object to read.</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class ReadPublicInput: ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_ReadPublic;

    /// <inheritdoc/>
    /// <remarks>
    /// <c>objectHandle</c> carries Auth Index None (TPM 2.0 Library Part 3, clause 12.4, Table 24) — the first
    /// session in an authorization area over this command is a companion, never an authorizer, so a decrypt or
    /// encrypt session's own <c>nonceTPM</c> never folds into session 0's command HMAC (TPM 2.0 Library Part 1,
    /// clause 16.6.5).
    /// </remarks>
    public bool IsFirstHandleAuthorized => false;

    /// <summary>
    /// Gets the handle of the object to read.
    /// </summary>
    public TpmiDhObject ObjectHandle { get; }

    /// <summary>
    /// Creates a ReadPublic input for the specified handle.
    /// </summary>
    /// <param name="objectHandle">The object handle.</param>
    /// <returns>A new <see cref="ReadPublicInput"/>.</returns>
    public static ReadPublicInput ForHandle(TpmiDhObject objectHandle)
    {
        return new ReadPublicInput(objectHandle);
    }

    private ReadPublicInput(TpmiDhObject objectHandle)
    {
        ObjectHandle = objectHandle;
    }

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        return sizeof(uint); //objectHandle (TPMI_DH_OBJECT)
    }

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        ObjectHandle.WriteTo(ref writer);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        //TPM2_ReadPublic has no parameters beyond the handle.
    }

    private string DebuggerDisplay => $"ReadPublicInput({ObjectHandle})";
}
