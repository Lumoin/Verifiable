using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_ClockSet command (TPM 2.0 Library Part 3, clause 29.2). Advances <c>Clock</c> forward
/// to <see cref="NewTime"/>, authorized by the owner or platform hierarchy.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Handle area:</strong> <c>@auth</c> (<c>TPMI_RH_PROVISION</c>) — <c>TPM_RH_OWNER</c> or
/// <c>TPM_RH_PLATFORM</c>; authorized with USER role (1 handle). The caller supplies the authorizing
/// session separately (via <c>TpmCommandExecutor</c>'s session list); this type carries only the handle
/// and the new time.
/// </para>
/// <para>
/// <strong>Parameter area:</strong> <c>newTime</c> (UINT64) — the requested new Clock setting in
/// milliseconds.
/// </para>
/// <para>
/// This command is authorized, so it is sent with <c>TPM_ST_SESSIONS</c>. See TPM 2.0 Library Part 3,
/// Section 29.2 (Table 204).
/// </para>
/// </remarks>
/// <param name="AuthHandle">The provisioning hierarchy authorizing the set.</param>
/// <param name="NewTime">The requested new Clock setting, in milliseconds.</param>
public readonly record struct ClockSetInput(TpmRh AuthHandle, ulong NewTime): ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_ClockSet;

    /// <inheritdoc/>
    public int GetSerializedSize() => sizeof(uint) + sizeof(ulong);

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32((uint)AuthHandle);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        writer.WriteUInt64(NewTime);
    }
}
