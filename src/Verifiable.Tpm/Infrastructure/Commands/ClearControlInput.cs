using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_ClearControl command (TPM 2.0 Library Part 3, clause 24.7). Sets or clears
/// <c>TPMA_PERMANENT.disableClear</c>, which gates whether TPM2_Clear() may execute.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Handle area:</strong> <c>@auth</c> (<c>TPMI_RH_CLEAR</c>) - <c>TPM_RH_LOCKOUT</c> or
/// <c>TPM_RH_PLATFORM</c>; authorized with USER role (1 handle). The caller supplies the authorizing session
/// separately (via <c>TpmCommandExecutor</c>'s session list); this type carries only the handle and the new
/// state.
/// </para>
/// <para>
/// <strong>Parameter area:</strong>
/// </para>
/// <list type="bullet">
///   <item><description><c>disable</c> (TPMI_YES_NO) - YES if <c>disableClear</c> is to be SET, NO if it is to
///   be CLEAR. The parameter's own spec-printed description still names it <c>disableOwnerClear</c>, a TPM 1.2
///   remnant distinct from both the wire field name and the persistent attribute it sets; preserved verbatim,
///   not normalized.</description></item>
/// </list>
/// <para>
/// Lockout Authorization may SET <c>disableClear</c> but not CLEAR it (TPM 2.0 Library Part 3, clause 24.7.1);
/// Platform Authorization may do either. This asymmetry is not encoded on the wire - both directions share the
/// same handle and Auth Role - so it is enforced by the command's own transition logic. This command is
/// authorized, so it is sent with <c>TPM_ST_SESSIONS</c>. See TPM 2.0 Library Part 3, clause 24.7 (Table
/// 203/204).
/// </para>
/// </remarks>
/// <param name="Auth">The lockout or platform hierarchy authorizing the change.</param>
/// <param name="Disable">YES to SET <c>disableClear</c>, NO to CLEAR it.</param>
public readonly record struct ClearControlInput(TpmRh Auth, TpmiYesNo Disable): ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_ClearControl;

    /// <inheritdoc/>
    public int GetSerializedSize() =>
        sizeof(uint)      //auth (handle area).
        + sizeof(byte);   //disable (TPMI_YES_NO).

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32((uint)Auth);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        Disable.WriteTo(ref writer);
    }
}
