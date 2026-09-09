using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_ContextLoad command - reloads a context that TPM2_ContextSave() produced and assigns it
/// a handle: the saved handle itself for a session, or a freshly drawn one for an object or sequence.
/// </summary>
/// <remarks>
/// <para>
/// "This command is used to reload a context that has been saved by TPM2_ContextSave(). No authorization
/// sessions of any type are allowed with this command and tag is required to be TPM_ST_NO_SESSIONS" (TPM 2.0
/// Library Part 3, clause 28.3.1). <see cref="Context"/> is the command's only content, carried whole as the
/// parameter area — there is no handle area at all.
/// </para>
/// <para>
/// <b>Command structure:</b>
/// </para>
/// <code>
/// TPMI_ST_COMMAND_TAG  tag             TPM_ST_NO_SESSIONS
/// UINT32               commandSize
/// TPM_CC               commandCode     TPM_CC_ContextLoad
/// TPMS_CONTEXT         context         the context blob
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 3, clause 28.3 (Table 226).
/// </para>
/// </remarks>
/// <param name="Context">
/// The context to reload. BORROWS the caller's structure: this type neither owns nor disposes it — the caller
/// retains ownership across the call, the same non-owning contract <see cref="RsaEncryptInput"/> keeps for its
/// own carriers.
/// </param>
public readonly record struct ContextLoadInput(TpmsContext Context): ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_ContextLoad;

    /// <inheritdoc/>
    public int GetSerializedSize() => Context.SerializedSize;

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        //TPM2_ContextLoad() carries no handle area — the whole command content is the context parameter
        //(WriteParameters below).
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        Context.WriteTo(ref writer);
    }
}
