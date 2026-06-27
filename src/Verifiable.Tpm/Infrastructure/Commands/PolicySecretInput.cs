using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_PolicySecret command (CC = 0x00000151), in its immediate (no-expiration) form.
/// </summary>
/// <remarks>
/// <para>
/// Binds a policy session to the requirement that the authorization value of the entity referenced by
/// <see cref="AuthHandle"/> be provided. The command updates the session's policyDigest as
/// <c>policyDigestnew = H(policyDigestold || TPM_CC_PolicySecret || authObject.Name)</c> (with an empty
/// <c>policyRef</c>); for <c>authHandle = TPM_RH_ENDORSEMENT</c> with an empty <c>policyRef</c> this yields the
/// well-known TCG endorsement-key authorization policy. The caller must authorize <see cref="AuthHandle"/> at
/// USER role (a session in the command's authorization area).
/// </para>
/// <para>
/// Command structure (TPM 2.0 Part 3, Section 23.4):
/// </para>
/// <list type="bullet">
///   <item><description>authHandle (TPMI_DH_ENTITY): The entity whose authorization is required. Requires authorization.</description></item>
///   <item><description>policySession (TPMI_SH_POLICY): The policy session handle (command handle, no authorization).</description></item>
///   <item><description>nonceTPM (TPM2B_NONCE), cpHashA (TPM2B_DIGEST), policyRef (TPM2B_NONCE): all empty in this immediate form.</description></item>
///   <item><description>expiration (INT32): zero in this immediate form (no authorization ticket is produced).</description></item>
/// </list>
/// </remarks>
/// <param name="AuthHandle">The entity whose authorization value the policy requires (for example TPM_RH_ENDORSEMENT).</param>
/// <param name="PolicySession">The policy session handle the assertion is applied to.</param>
public readonly record struct PolicySecretInput(uint AuthHandle, uint PolicySession): ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_PolicySecret;

    /// <inheritdoc/>
    public int GetSerializedSize() =>
        sizeof(uint) + sizeof(uint)         //authHandle + policySession (handle area)
        + (3 * sizeof(ushort))              //nonceTPM + cpHashA + policyRef (empty TPM2B values)
        + sizeof(int);                      //expiration (INT32)

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32(AuthHandle);
        writer.WriteUInt32(PolicySession);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        writer.WriteUInt16(0);  //nonceTPM (empty).
        writer.WriteUInt16(0);  //cpHashA (empty).
        writer.WriteUInt16(0);  //policyRef (empty).
        writer.WriteUInt32(0);  //expiration = 0 (immediate; no ticket).
    }
}
