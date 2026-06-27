using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_PolicyGetDigest command (CC = 0x00000189).
/// </summary>
/// <remarks>
/// <para>
/// Returns the current policyDigest of a policy (or trial) session, letting the host read back the digest the
/// TPM accumulated and compare it against a value computed for an object's authPolicy.
/// </para>
/// <para>
/// Command structure (TPM 2.0 Part 3, Section 23.6):
/// </para>
/// <list type="bullet">
///   <item><description>policySession (TPMI_SH_POLICY): The policy session handle (command handle, no authorization).</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class PolicyGetDigestInput: ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_PolicyGetDigest;

    /// <summary>
    /// Gets the policy session handle whose digest is read.
    /// </summary>
    public uint PolicySession { get; }

    private PolicyGetDigestInput(uint policySession)
    {
        PolicySession = policySession;
    }

    /// <summary>
    /// Creates a TPM2_PolicyGetDigest input for the specified policy session.
    /// </summary>
    /// <param name="policySession">The policy session handle.</param>
    /// <returns>A new <see cref="PolicyGetDigestInput"/>.</returns>
    public static PolicyGetDigestInput ForSession(uint policySession)
    {
        return new PolicyGetDigestInput(policySession);
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
        //TPM2_PolicyGetDigest has no parameters beyond the handle.
    }

    private string DebuggerDisplay => $"PolicyGetDigestInput(Session=0x{PolicySession:X8})";
}
