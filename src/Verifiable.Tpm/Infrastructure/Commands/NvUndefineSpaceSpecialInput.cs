using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for TPM2_NV_UndefineSpaceSpecial - removes a platform-created NV Index carrying
/// <c>TPMA_NV_POLICY_DELETE</c>, authorized by two sessions in one authorization area.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Handle area (2 handles):</strong>
/// </para>
/// <list type="bullet">
///   <item><description>@nvIndex (TPMI_RH_NV_DEFINED_INDEX) - Auth Index 1, Auth Role ADMIN: a policy session whose commandCode is TPM_CC_NV_UndefineSpaceSpecial.</description></item>
///   <item><description>@platform (TPMI_RH_PLATFORM) - Auth Index 2, Auth Role USER: password or HMAC session authorized by the platform hierarchy.</description></item>
/// </list>
/// <para>
/// There are no parameters and no response parameters. This command is authorized by two sessions, so it is
/// sent with <c>TPM_ST_SESSIONS</c>. See TPM 2.0 Library Part 3, clause 31.5 (Tables 249/250). Deletion succeeds
/// only for an Index carrying both <c>TPMA_NV_PLATFORMCREATE</c> and <c>TPMA_NV_POLICY_DELETE</c>; an Index
/// missing either answers <c>TPM_RC_ATTRIBUTES</c> — such an Index is removed with TPM2_NV_UndefineSpace()
/// instead.
/// </para>
/// </remarks>
/// <param name="NvIndex">The NV Index to delete.</param>
/// <param name="Platform">The platform hierarchy handle — always <c>TPM_RH_PLATFORM</c>, the only value <c>TPMI_RH_PLATFORM</c> admits.</param>
public readonly record struct NvUndefineSpaceSpecialInput(uint NvIndex, TpmRh Platform = TpmRh.TPM_RH_PLATFORM): ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial;

    /// <inheritdoc/>
    public int GetSerializedSize() => sizeof(uint) + sizeof(uint); //nvIndex + platform.

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32(NvIndex);
        writer.WriteUInt32((uint)Platform);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        //TPM2_NV_UndefineSpaceSpecial has no parameters.
    }
}
