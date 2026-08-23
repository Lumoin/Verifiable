using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_Clear command (TPM 2.0 Library Part 3, clause 24.6). Removes all TPM context associated
/// with the current Owner: flushes Storage/Endorsement objects, deletes owner-created NV Indexes, rotates the
/// Storage Primary Seed (and shProof/ehProof with it), resets ownerAuth/endorsementAuth/lockoutAuth and their
/// policies to empty, and re-enables shEnable/ehEnable.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Handle area:</strong> <c>@authHandle</c> (<c>TPMI_RH_CLEAR</c>) - <c>TPM_RH_LOCKOUT</c> or
/// <c>TPM_RH_PLATFORM</c>; authorized with USER role (1 handle). The caller supplies the authorizing session
/// separately (via <c>TpmCommandExecutor</c>'s session list); this type carries only the handle.
/// </para>
/// <para>
/// This command has no parameters. <c>TPM2_ClearControl()</c> can disable it (<c>TPM_RC_DISABLED</c>); the
/// lockoutAuth arm is DA-gated like any other lockoutAuth use, while the platform arm is categorically DA-exempt
/// (TPM 2.0 Library Part 3, Section 25.1). It is authorized, so it is sent with <c>TPM_ST_SESSIONS</c>. See TPM
/// 2.0 Library Part 3, Section 24.6 (Table 184/185).
/// </para>
/// </remarks>
/// <param name="AuthHandle">The lockout or platform hierarchy authorizing the clear.</param>
public readonly record struct ClearInput(TpmRh AuthHandle): ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_Clear;

    /// <inheritdoc/>
    public int GetSerializedSize() => sizeof(uint);

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32((uint)AuthHandle);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        //TPM2_Clear has no parameters.
    }
}
