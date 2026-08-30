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
/// <c>policyDigest = H(policyDigestold || TPM_CC_PolicyLocality || locality)</c> (TPM 2.0 Part 3, Section 23.8);
/// see <see cref="TpmPolicyDigest.ExtendForLocality"/>. On a trial session the comparison is skipped and only the
/// digest is updated.
/// </para>
/// <para>
/// Command structure (TPM 2.0 Part 3, Section 23.8, Table 154):
/// </para>
/// <list type="bullet">
///   <item><description>policySession (TPMI_SH_POLICY): The policy session handle (command handle, no authorization).</description></item>
///   <item><description>locality (TPMA_LOCALITY): The set of localities the policy admits.</description></item>
/// </list>
/// </remarks>
/// <param name="PolicySession">The policy session handle.</param>
/// <param name="Locality">The set of localities the policy admits (TPM 2.0 Part 2, Section 8.5, Table 39).</param>
[DebuggerDisplay("PolicyLocalityInput(Session=0x{PolicySession,h}, {Locality})")]
public readonly record struct PolicyLocalityInput(uint PolicySession, TpmaLocality Locality): ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_PolicyLocality;

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
