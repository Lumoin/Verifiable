using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_PolicyPassword command (CC = 0x0000018C).
/// </summary>
/// <remarks>
/// <para>
/// Binds a policy to the authorized object's authorization value presented as a cleartext password: at use time
/// the session's hmac field must carry the object's authValue directly rather than an HMAC over it (TPM 2.0
/// Library Part 1, clause 16.6.16, "the password takes precedence and must be present in hmac"). The command
/// extends the session's policyDigest with the SAME fold TPM2_PolicyAuthValue uses —
/// <c>policyDigestnew = H_policyAlg(policyDigestold || TPM_CC_PolicyAuthValue)</c> (TPM 2.0 Library Part 3,
/// clause 23.18) — so a single authPolicy accepts either authorization style; see
/// <see cref="TpmPolicyDigest.ExtendForPassword"/>. The command sets the session's isPasswordNeeded flag and
/// clears isAuthValueNeeded.
/// </para>
/// <para>
/// Command structure (TPM 2.0 Library Part 3, clause 23.18, Table 174):
/// </para>
/// <list type="bullet">
///   <item><description>policySession (TPMI_SH_POLICY): The policy session handle (command handle, no authorization).</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class PolicyPasswordInput: ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_PolicyPassword;

    /// <inheritdoc/>
    /// <remarks>
    /// <c>policySession</c> carries Auth Index None (TPM 2.0 Library Part 3, clause 23.18.2, Table 174) — the
    /// first session in an authorization area over this command is a companion, never an authorizer, so a
    /// decrypt or encrypt session's own <c>nonceTPM</c> never folds into session 0's command HMAC (TPM 2.0
    /// Library Part 1, clause 16.6.5).
    /// </remarks>
    public bool IsFirstHandleAuthorized => false;

    /// <summary>
    /// Gets the policy session handle the assertion is applied to.
    /// </summary>
    public uint PolicySession { get; }

    private PolicyPasswordInput(uint policySession)
    {
        PolicySession = policySession;
    }

    /// <summary>
    /// Creates a TPM2_PolicyPassword input for the specified policy session.
    /// </summary>
    /// <param name="policySession">The policy session handle.</param>
    /// <returns>A new <see cref="PolicyPasswordInput"/>.</returns>
    public static PolicyPasswordInput ForSession(uint policySession)
    {
        return new PolicyPasswordInput(policySession);
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
        //TPM2_PolicyPassword has no parameters beyond the handle.
    }

    private string DebuggerDisplay => $"PolicyPasswordInput(Session=0x{PolicySession:X8})";
}
