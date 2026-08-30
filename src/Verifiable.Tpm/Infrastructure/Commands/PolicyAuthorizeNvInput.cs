using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_PolicyAuthorizeNV command (CC = 0x00000192).
/// </summary>
/// <remarks>
/// <para>
/// Authorizes a policy session by the authPolicy currently held in <see cref="NvIndex"/>'s NV data, letting an
/// Index's own policy stand in for the session's, so the policy an object honors can be revised by rewriting the
/// Index instead of reissuing every object that references it. The session's policyDigest is RESET and then
/// folded as <c>policyDigest = H(0...0 || TPM_CC_PolicyAuthorizeNV || nvIndex.Name)</c> (TPM 2.0 Part 3, Section
/// 23.22, equation 9); see <see cref="TpmPolicyDigest.ExtendForAuthorizeNv"/>. Reading <see cref="NvIndex"/> is
/// authorized at USER role through <see cref="AuthHandle"/>.
/// </para>
/// <para>
/// Command structure (TPM 2.0 Part 3, Section 23.22, Table 182):
/// </para>
/// <list type="bullet">
///   <item><description>authHandle (TPMI_RH_NV_AUTH): The authorization for reading the Index (Auth Index: 1, Auth Role: USER).</description></item>
///   <item><description>nvIndex (TPMI_RH_NV_INDEX): The NV Index whose held policy authorizes the session.</description></item>
///   <item><description>policySession (TPMI_SH_POLICY): The policy session handle (command handle, no authorization).</description></item>
/// </list>
/// </remarks>
/// <param name="AuthHandle">The authorization handle for reading the Index.</param>
/// <param name="NvIndex">The NV Index whose held authPolicy authorizes the session.</param>
/// <param name="PolicySession">The policy session handle.</param>
[DebuggerDisplay("PolicyAuthorizeNvInput(Index=0x{NvIndex,h}, Session=0x{PolicySession,h})")]
public readonly record struct PolicyAuthorizeNvInput(uint AuthHandle, uint NvIndex, uint PolicySession): ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_PolicyAuthorizeNV;

    /// <inheritdoc/>
    public int GetSerializedSize() => 3 * sizeof(uint); //authHandle + nvIndex + policySession; no parameters.

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32(AuthHandle);
        writer.WriteUInt32(NvIndex);
        writer.WriteUInt32(PolicySession);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        //TPM2_PolicyAuthorizeNV has no parameters beyond the three handles.
    }
}
