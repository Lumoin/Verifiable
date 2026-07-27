using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_DictionaryAttackLockReset command (TPM 2.0 Library Part 3, clause 25.2). Resets
/// <c>failedTries</c> to zero, authorized by the lockout hierarchy.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Handle area:</strong> <c>lockHandle</c> (<c>TPMI_RH_LOCKOUT</c>) — <c>TPM_RH_LOCKOUT</c>; authorized
/// with USER role (1 handle). The caller supplies the authorizing session separately (via
/// <c>TpmCommandExecutor</c>'s session list); this type carries only the handle.
/// </para>
/// <para>
/// This command has no parameters. It is authorized, so it is sent with <c>TPM_ST_SESSIONS</c>, and is
/// permitted even while the TPM is in general Lockout mode. See TPM 2.0 Library Part 3, Section 25.2
/// (Table 180).
/// </para>
/// </remarks>
/// <param name="LockHandle">The lockout hierarchy authorizing the reset (<c>TPM_RH_LOCKOUT</c>).</param>
public readonly record struct DictionaryAttackLockResetInput(TpmRh LockHandle): ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_DictionaryAttackLockReset;

    /// <inheritdoc/>
    public int GetSerializedSize() => sizeof(uint);

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32((uint)LockHandle);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        //TPM2_DictionaryAttackLockReset has no parameters.
    }
}
