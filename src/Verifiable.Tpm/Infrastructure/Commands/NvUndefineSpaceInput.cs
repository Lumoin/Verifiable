using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for TPM2_NV_UndefineSpace - removes an NV Index definition, freeing its handle.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Handle area (2 handles):</strong>
/// </para>
/// <list type="bullet">
///   <item><description>@authHandle (TPMI_RH_PROVISION) - <c>TPM_RH_OWNER</c> or <c>TPM_RH_PLATFORM</c>; authorized with USER role.</description></item>
///   <item><description>nvIndex (TPMI_RH_NV_INDEX) - the NV Index to undefine.</description></item>
/// </list>
/// <para>
/// There are no parameters and no response parameters. This command is authorized, so it is sent with
/// <c>TPM_ST_SESSIONS</c>. See TPM 2.0 Library Part 3, Section 31.4 (Table 230). It does not undefine indices
/// with the <c>TPMA_NV_POLICY_DELETE</c> attribute set (those use TPM2_NV_UndefineSpaceSpecial).
/// </para>
/// </remarks>
/// <param name="AuthHandle">The provisioning hierarchy that authorizes the removal (owner or platform).</param>
/// <param name="NvIndex">The NV Index to undefine.</param>
public readonly record struct NvUndefineSpaceInput(TpmRh AuthHandle, uint NvIndex): ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_NV_UndefineSpace;

    /// <inheritdoc/>
    public int GetSerializedSize() => sizeof(uint) + sizeof(uint); //authHandle + nvIndex.

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32((uint)AuthHandle);
        writer.WriteUInt32(NvIndex);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        //TPM2_NV_UndefineSpace has no parameters.
    }
}
