using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_ContextSave command - saves a session, transient object, or sequence object context
/// outside the TPM as an integrity- and confidentiality-protected TPMS_CONTEXT.
/// </summary>
/// <remarks>
/// <para>
/// "This command saves a session context, object context, or sequence object context outside the TPM. No
/// authorization sessions of any type are allowed with this command and tag is required to be
/// TPM_ST_NO_SESSIONS" (TPM 2.0 Library Part 3, clause 28.2.1). <see cref="SaveHandle"/> is the command's only
/// content, carried in the handle area with <c>Auth Index: None</c> — no authorization ladder runs at all.
/// </para>
/// <para>
/// <b>Command structure:</b>
/// </para>
/// <code>
/// TPMI_ST_COMMAND_TAG  tag             TPM_ST_NO_SESSIONS
/// UINT32               commandSize
/// TPM_CC               commandCode     TPM_CC_ContextSave
/// TPMI_DH_CONTEXT      saveHandle      handle of the resource to save
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 3, clause 28.2 (Table 224).
/// </para>
/// </remarks>
public readonly record struct ContextSaveInput(TpmiDhContext SaveHandle): ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_ContextSave;

    /// <inheritdoc/>
    /// <remarks>
    /// <c>saveHandle</c> carries Auth Index None (TPM 2.0 Library Part 3, clause 28.2.2, Table 224) — the tag
    /// is fixed <c>TPM_ST_NO_SESSIONS</c>, so this command never legitimately carries a session at all, but the
    /// declaration stands for the same reason every Auth Index None handle's does: no authorizing slot exists
    /// for a first session to fold another session's <c>nonceTPM</c> against (TPM 2.0 Library Part 1, clause
    /// 16.6.5).
    /// </remarks>
    public bool IsFirstHandleAuthorized => false;

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        //One handle-area handle (saveHandle); no parameters.
        return sizeof(uint);
    }

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        SaveHandle.WriteTo(ref writer);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        //TPM2_ContextSave() carries no parameters — saveHandle is the command's only content, and it
        //travels in the handle area (WriteHandles above), not here.
    }

    /// <summary>
    /// Creates a ContextSave input for the specified handle.
    /// </summary>
    /// <param name="handle">The raw handle value of the resource to save.</param>
    /// <returns>A <see cref="ContextSaveInput"/> for the handle.</returns>
    public static ContextSaveInput ForHandle(uint handle) => new(TpmiDhContext.FromValue(handle));
}
