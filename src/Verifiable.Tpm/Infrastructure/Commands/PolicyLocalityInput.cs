using System.Diagnostics;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_PolicyLocality command (CC = 0x0000016F).
/// </summary>
/// <remarks>
/// <para>
/// Authorizes a policy session only when the command that consumes it originates from one of the localities set
/// in <see cref="Locality"/>. The session's policyDigest is updated as
/// <c>policyDigest = H(policyDigestold || TPM_CC_PolicyLocality || locality)</c> (TPM 2.0 Library Part 3, clause 23.8);
/// see <see cref="TpmPolicyDigest.ExtendForLocality"/>. On a trial session the comparison is skipped and only the
/// digest is updated.
/// </para>
/// <para>
/// Command structure (TPM 2.0 Library Part 3, clause 23.8, Table 154):
/// </para>
/// <list type="bullet">
///   <item><description>policySession (TPMI_SH_POLICY): The policy session handle (command handle, no authorization).</description></item>
///   <item><description>locality (TPMA_LOCALITY): The set of localities the policy admits.</description></item>
/// </list>
/// </remarks>
/// <param name="PolicySession">The policy session handle.</param>
/// <param name="Locality">The set of localities the policy admits (TPM 2.0 Library Part 2, clause 8.5, Table 39).</param>
[DebuggerDisplay("PolicyLocalityInput(Session=0x{PolicySession,h}, {Locality})")]
public readonly record struct PolicyLocalityInput(uint PolicySession, TpmaLocality Locality): ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_PolicyLocality;

    /// <inheritdoc/>
    /// <remarks>
    /// <c>policySession</c> carries Auth Index None (TPM 2.0 Library Part 3, clause 23.8.2, Table 154) — the
    /// first session in an authorization area over this command is a companion, never an authorizer, so a
    /// decrypt or encrypt session's own <c>nonceTPM</c> never folds into session 0's command HMAC (TPM 2.0
    /// Library Part 1, clause 16.6.5).
    /// </remarks>
    public bool IsFirstHandleAuthorized => false;

    /// <inheritdoc/>
    public int GetSerializedSize() =>
        sizeof(uint)     //policySession (handle area).
        + sizeof(byte);  //locality (TPMA_LOCALITY, one octet).

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32(PolicySession);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        writer.WriteByte((byte)Locality);
    }
}
