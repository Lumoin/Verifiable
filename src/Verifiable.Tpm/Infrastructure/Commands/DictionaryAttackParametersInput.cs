using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_DictionaryAttackParameters command (TPM 2.0 Library Part 3, clause 25.3). Sets
/// <c>maxTries</c>/<c>recoveryTime</c>/<c>lockoutRecovery</c>, authorized by the lockout hierarchy.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Handle area:</strong> <c>lockHandle</c> (<c>TPMI_RH_LOCKOUT</c>) — <c>TPM_RH_LOCKOUT</c>; authorized
/// with USER role (1 handle). The caller supplies the authorizing session separately (via
/// <c>TpmCommandExecutor</c>'s session list); this type carries only the handle and the new parameters.
/// </para>
/// <para>
/// <strong>Parameter area:</strong>
/// </para>
/// <list type="bullet">
///   <item><description><c>newMaxTries</c> (UINT32) — the new tolerated-failure count.</description></item>
///   <item><description><c>newRecoveryTime</c> (UINT32) — the new self-heal interval, in seconds; zero disables dictionary-attack protection.</description></item>
///   <item><description><c>newLockoutRecovery</c> (UINT32) — the new lockoutAuth recovery wait, in seconds; zero requires a TPM Reset to re-arm lockoutAuth.</description></item>
/// </list>
/// <para>
/// This command deliberately does not reset <c>failedTries</c> (Part 1, clause 17.8.6): lowering
/// <see cref="NewMaxTries"/> to at or below the current failure count takes the TPM into Lockout mode
/// immediately, as a side effect of the existing <c>failedTries &gt;= maxTries</c> test, with no distinct error
/// code for that transition. It is authorized, so it is sent with <c>TPM_ST_SESSIONS</c>, and is permitted even
/// while the TPM is in general Lockout mode. See TPM 2.0 Library Part 3, Section 25.3 (Table 182).
/// </para>
/// </remarks>
/// <param name="LockHandle">The lockout hierarchy authorizing the change (<c>TPM_RH_LOCKOUT</c>).</param>
/// <param name="NewMaxTries">The new tolerated-failure count before Lockout mode engages.</param>
/// <param name="NewRecoveryTime">The new self-heal interval, in seconds; zero disables dictionary-attack protection.</param>
/// <param name="NewLockoutRecovery">The new lockoutAuth recovery wait, in seconds; zero means only a TPM Reset re-arms lockoutAuth.</param>
public readonly record struct DictionaryAttackParametersInput(
    TpmRh LockHandle, uint NewMaxTries, uint NewRecoveryTime, uint NewLockoutRecovery): ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_DictionaryAttackParameters;

    /// <inheritdoc/>
    public int GetSerializedSize() =>
        sizeof(uint)      //lockHandle (handle area).
        + sizeof(uint)    //newMaxTries.
        + sizeof(uint)    //newRecoveryTime.
        + sizeof(uint);   //newLockoutRecovery.

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32((uint)LockHandle);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        writer.WriteUInt32(NewMaxTries);
        writer.WriteUInt32(NewRecoveryTime);
        writer.WriteUInt32(NewLockoutRecovery);
    }
}
