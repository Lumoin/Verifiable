using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_HierarchyControl command (TPM 2.0 Library Part 3, clause 24.2). SETs or CLEARs one of
/// <c>phEnable</c>, <c>phEnableNV</c>, <c>shEnable</c>, or <c>ehEnable</c>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Handle area:</strong> <c>@authHandle</c> (<c>TPMI_RH_BASE_HIERARCHY</c>) - <c>TPM_RH_ENDORSEMENT</c>,
/// <c>TPM_RH_OWNER</c>, or <c>TPM_RH_PLATFORM</c>; authorized with USER role (1 handle). The caller supplies the
/// authorizing session separately (via <c>TpmCommandExecutor</c>'s session list); this type carries only the
/// handle and the target enable/state.
/// </para>
/// <para>
/// <strong>Parameter area:</strong>
/// </para>
/// <list type="bullet">
///   <item><description><c>enable</c> (TPMI_RH_ENABLES) - the enable being modified:
///   <c>TPM_RH_ENDORSEMENT</c>, <c>TPM_RH_OWNER</c>, <c>TPM_RH_PLATFORM</c>, or
///   <c>TPM_RH_PLATFORM_NV</c>.</description></item>
///   <item><description><c>state</c> (TPMI_YES_NO) - YES if the enable should be SET, NO if it should be
///   CLEAR.</description></item>
/// </list>
/// <para>
/// <c>phEnable</c> may only be CLEARed by this command - only <c>_TPM_Init</c>/TPM2_Startup() re-SETs it (TPM
/// 2.0 Library Part 1, Section 11.3). <c>shEnable</c>/<c>ehEnable</c> CLEAR under either their own hierarchy's
/// authorization or Platform Authorization, but SET only under Platform Authorization (Part 1, Sections
/// 11.4-11.5). This command is authorized, so it is sent with <c>TPM_ST_SESSIONS</c>. See TPM 2.0 Library Part
/// 3, Section 24.2 (Table 176/177).
/// </para>
/// </remarks>
/// <param name="AuthHandle">The hierarchy authorizing the change (endorsement, owner, or platform).</param>
/// <param name="Enable">The enable being modified.</param>
/// <param name="State">YES to SET the enable, NO to CLEAR it.</param>
public readonly record struct HierarchyControlInput(TpmRh AuthHandle, TpmRh Enable, TpmiYesNo State): ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_HierarchyControl;

    /// <inheritdoc/>
    public int GetSerializedSize() =>
        sizeof(uint)      //authHandle (handle area).
        + sizeof(uint)    //enable.
        + sizeof(byte);   //state (TPMI_YES_NO).

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32((uint)AuthHandle);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        writer.WriteUInt32((uint)Enable);
        State.WriteTo(ref writer);
    }
}
