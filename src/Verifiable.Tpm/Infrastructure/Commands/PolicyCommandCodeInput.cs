using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_PolicyCommandCode command (CC = 0x0000016C).
/// </summary>
/// <remarks>
/// <para>
/// Restricts a policy session so the authorization it grants is valid only for a single command. The command
/// updates the session's policyDigest as
/// <c>policyDigestnew = H_policyAlg(policyDigestold || TPM_CC_PolicyCommandCode || code)</c> and records the
/// restricted command code on the session.
/// </para>
/// <para>
/// Command structure (TPM 2.0 Part 3, Section 23.4):
/// </para>
/// <list type="bullet">
///   <item><description>policySession (TPMI_SH_POLICY): The policy session handle (command handle, no authorization).</description></item>
///   <item><description>code (TPM_CC): The command code the policy is restricted to.</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class PolicyCommandCodeInput: ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_PolicyCommandCode;

    /// <summary>
    /// Gets the policy session handle the restriction is applied to.
    /// </summary>
    public uint PolicySession { get; }

    /// <summary>
    /// Gets the command code the policy is restricted to.
    /// </summary>
    public TpmCcConstants RestrictedCommand { get; }

    private PolicyCommandCodeInput(uint policySession, TpmCcConstants restrictedCommand)
    {
        PolicySession = policySession;
        RestrictedCommand = restrictedCommand;
    }

    /// <summary>
    /// Creates a TPM2_PolicyCommandCode input.
    /// </summary>
    /// <param name="policySession">The policy session handle.</param>
    /// <param name="restrictedCommand">The command code the policy is restricted to.</param>
    /// <returns>A new <see cref="PolicyCommandCodeInput"/>.</returns>
    public static PolicyCommandCodeInput Create(uint policySession, TpmCcConstants restrictedCommand)
    {
        return new PolicyCommandCodeInput(policySession, restrictedCommand);
    }

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        return sizeof(uint) +   //policySession (handle area)
               sizeof(uint);    //code (TPM_CC parameter)
    }

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32(PolicySession);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        writer.WriteUInt32((uint)RestrictedCommand);
    }

    private string DebuggerDisplay => $"PolicyCommandCodeInput(Session=0x{PolicySession:X8}, Code={RestrictedCommand})";
}
