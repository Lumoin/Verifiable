using System;

namespace Verifiable.Tpm.Extensions.DictionaryAttack;

/// <summary>
/// The TPM's dictionary-attack (DA) protection parameters, as reported by the variable
/// <c>TPM_PT</c> properties.
/// </summary>
/// <remarks>
/// <para>
/// DA protection is what makes a low-entropy authorization value (such as a wallet PIN) resistant
/// to brute force: the TPM counts authorization failures and, once <see cref="LockoutCounter"/>
/// reaches <see cref="MaxAuthFail"/>, refuses further authorized use until the lockout recovers.
/// These parameters are global to the TPM, shared across every object that does not opt out of DA
/// protection.
/// </para>
/// <para>
/// The lockout counter decrements by one every <see cref="LockoutInterval"/> of TPM on-time;
/// <see cref="LockoutRecovery"/> is the wait after a failed use of the lockout authorization before
/// it may be tried again.
/// </para>
/// </remarks>
/// <param name="LockoutCounter">The current number of recorded authorization failures (<c>TPM_PT_LOCKOUT_COUNTER</c>).</param>
/// <param name="MaxAuthFail">The number of failures tolerated before lockout engages (<c>TPM_PT_MAX_AUTH_FAIL</c>).</param>
/// <param name="LockoutInterval">The time between automatic decrements of the failure counter (<c>TPM_PT_LOCKOUT_INTERVAL</c>).</param>
/// <param name="LockoutRecovery">The wait after a failed lockout-authorization use before it may be retried (<c>TPM_PT_LOCKOUT_RECOVERY</c>).</param>
public sealed record TpmDictionaryAttackParameters(
    uint LockoutCounter,
    uint MaxAuthFail,
    TimeSpan LockoutInterval,
    TimeSpan LockoutRecovery)
{
    /// <summary>
    /// Gets a value indicating whether the TPM is currently in dictionary-attack lockout, i.e. the
    /// failure counter has reached the tolerated maximum. Always <see langword="false"/> when
    /// <see cref="MaxAuthFail"/> is zero (DA protection disabled).
    /// </summary>
    public bool IsLockedOut => MaxAuthFail > 0 && LockoutCounter >= MaxAuthFail;
}
