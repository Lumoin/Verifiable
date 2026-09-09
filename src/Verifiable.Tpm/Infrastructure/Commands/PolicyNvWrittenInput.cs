using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_PolicyNvWritten command (CC = 0x0000018F).
/// </summary>
/// <remarks>
/// <para>
/// Authorizes a policy session only when the target NV Index's TPMA_NV_WRITTEN attribute compares to
/// <see cref="IsWrittenSet"/>. The session's policyDigest is updated as
/// <c>policyDigest = H(policyDigestold || TPM_CC_PolicyNvWritten || writtenSet)</c> (TPM 2.0 Library Part 3, clause
/// 23.20); see <see cref="TpmPolicyDigest.ExtendForNvWritten"/>. On a trial session the comparison is skipped
/// and only the digest is updated.
/// </para>
/// <para>
/// Command structure (TPM 2.0 Library Part 3, clause 23.20, Table 178):
/// </para>
/// <list type="bullet">
///   <item><description>policySession (TPMI_SH_POLICY): The policy session handle (command handle, no authorization).</description></item>
///   <item><description>writtenSet (TPMI_YES_NO): The required state of TPMA_NV_WRITTEN.</description></item>
/// </list>
/// </remarks>
/// <param name="PolicySession">The policy session handle.</param>
/// <param name="IsWrittenSet"><see langword="true"/> to require TPMA_NV_WRITTEN SET (YES); <see langword="false"/> to require it CLEAR (NO).</param>
[DebuggerDisplay("PolicyNvWrittenInput(Session=0x{PolicySession,h}, IsWrittenSet={IsWrittenSet})")]
public readonly record struct PolicyNvWrittenInput(uint PolicySession, bool IsWrittenSet): ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_PolicyNvWritten;

    /// <inheritdoc/>
    /// <remarks>
    /// <c>policySession</c> carries Auth Index None (TPM 2.0 Library Part 3, clause 23.20.2, Table 178) — the
    /// first session in an authorization area over this command is a companion, never an authorizer, so a
    /// decrypt or encrypt session's own <c>nonceTPM</c> never folds into session 0's command HMAC (TPM 2.0
    /// Library Part 1, clause 16.6.5).
    /// </remarks>
    public bool IsFirstHandleAuthorized => false;

    /// <inheritdoc/>
    public int GetSerializedSize() =>
        sizeof(uint)     //policySession (handle area).
        + sizeof(byte);  //writtenSet (TPMI_YES_NO, one octet).

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32(PolicySession);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        (IsWrittenSet ? TpmiYesNo.Yes : TpmiYesNo.No).WriteTo(ref writer);
    }
}
