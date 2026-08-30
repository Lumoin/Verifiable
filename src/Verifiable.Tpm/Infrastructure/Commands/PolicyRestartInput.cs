using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_PolicyRestart command (CC = 0x00000180).
/// </summary>
/// <remarks>
/// <para>
/// Resets a session's policyDigest to a Zero Digest of the session's hash size and clears
/// isPasswordNeeded/isAuthValueNeeded and any pending expiration the session had accumulated, so the same policy
/// (or trial) session can be reused for a fresh assertion sequence without a new TPM2_StartAuthSession round
/// trip. Unlike every command in <see cref="TpmPolicyAssertion"/>, this is a session lifecycle operation, not a
/// policyDigest-extending assertion — there is no corresponding host-side <c>TpmPolicyDigest.Extend*</c> formula,
/// because the result does not depend on the prior digest at all.
/// </para>
/// <para>
/// Command structure (TPM 2.0 Part 3, Section 11.2, Table 16):
/// </para>
/// <list type="bullet">
///   <item><description>sessionHandle (TPMI_HMAC_POLICY_SESSION): The session handle to restart (command handle, no authorization).</description></item>
/// </list>
/// </remarks>
/// <param name="SessionHandle">The policy (or HMAC) session handle to restart.</param>
[DebuggerDisplay("PolicyRestartInput(Session=0x{SessionHandle,h})")]
public readonly record struct PolicyRestartInput(uint SessionHandle): ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_PolicyRestart;

    /// <inheritdoc/>
    public int GetSerializedSize() => sizeof(uint); //sessionHandle (handle area); no parameters.

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32(SessionHandle);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        //TPM2_PolicyRestart has no parameters beyond the handle.
    }
}
