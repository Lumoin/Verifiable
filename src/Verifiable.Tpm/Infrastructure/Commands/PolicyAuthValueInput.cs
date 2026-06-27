using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_PolicyAuthValue command (CC = 0x0000016B).
/// </summary>
/// <remarks>
/// <para>
/// Binds a policy to the authorization value of the authorized object: at use time the session must carry an
/// HMAC over the object's authValue. The command extends the session's policyDigest as
/// <c>policyDigestnew = H_policyAlg(policyDigestold || TPM_CC_PolicyAuthValue)</c> and sets the session's
/// isAuthValueNeeded flag.
/// </para>
/// <para>
/// Command structure (TPM 2.0 Part 3, Section 23.18):
/// </para>
/// <list type="bullet">
///   <item><description>policySession (TPMI_SH_POLICY): The policy session handle (command handle, no authorization).</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class PolicyAuthValueInput: ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_PolicyAuthValue;

    /// <summary>
    /// Gets the policy session handle the assertion is applied to.
    /// </summary>
    public uint PolicySession { get; }

    private PolicyAuthValueInput(uint policySession)
    {
        PolicySession = policySession;
    }

    /// <summary>
    /// Creates a TPM2_PolicyAuthValue input for the specified policy session.
    /// </summary>
    /// <param name="policySession">The policy session handle.</param>
    /// <returns>A new <see cref="PolicyAuthValueInput"/>.</returns>
    public static PolicyAuthValueInput ForSession(uint policySession)
    {
        return new PolicyAuthValueInput(policySession);
    }

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        return sizeof(uint); //policySession (handle area); no parameters.
    }

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32(PolicySession);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        //TPM2_PolicyAuthValue has no parameters beyond the handle.
    }

    private string DebuggerDisplay => $"PolicyAuthValueInput(Session=0x{PolicySession:X8})";
}
