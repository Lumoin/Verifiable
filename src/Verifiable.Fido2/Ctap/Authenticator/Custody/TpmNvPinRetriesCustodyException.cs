using System;

namespace Verifiable.Fido2.Ctap.Authenticator.Custody;

/// <summary>
/// A <see cref="TpmNvPinRetriesCustody"/> operation failed closed: the in-house simulated TPM rejected a
/// provision, verify, penalize, read, or retire against the authenticator-global <c>TPM_NT_PIN_FAIL</c> NV
/// Index (contract R-10, wavepin).
/// </summary>
/// <remarks>
/// Per contract R-10's fail-closed requirement, every TPM-side rejection this adapter can observe — a
/// <c>DefinePinFailIndexAsync</c>/<c>VerifyPinAsync</c>/<c>ReadPinCountersAsync</c>/<c>ResetPinCountAsync</c>/
/// <c>UndefinePinIndexAsync</c> result whose <see cref="Verifiable.Tpm.TpmResult{T}.IsSuccess"/> is
/// <see langword="false"/> and is not one of the two tolerated idempotency cases
/// (<c>TPM_RC_NV_DEFINED</c> inside re-provision handling, <c>TPM_RC_HANDLE</c> on retire or on the
/// undefine-if-present step of provisioning) — surfaces as this one exception type. The caller's correct
/// reaction mirrors <see cref="TpmNvSignatureCounterCustodyException"/>'s own posture: the CTAP command this
/// adapter's delegate was called from fails outright, never with a silently unrotated PIN or a persistent
/// retry budget that was not genuinely recorded.
/// </remarks>
public sealed class TpmNvPinRetriesCustodyException: Exception
{
    /// <summary>
    /// Initializes a new instance with no message.
    /// </summary>
    public TpmNvPinRetriesCustodyException()
    {
    }


    /// <summary>
    /// Initializes a new instance with a message describing which TPM operation failed closed.
    /// </summary>
    /// <param name="message">A message describing the rejection.</param>
    public TpmNvPinRetriesCustodyException(string message): base(message)
    {
    }


    /// <summary>
    /// Initializes a new instance with a message and an inner exception describing which TPM operation
    /// failed closed.
    /// </summary>
    /// <param name="message">A message describing the rejection.</param>
    /// <param name="innerException">The underlying TPM failure, if any.</param>
    public TpmNvPinRetriesCustodyException(string message, Exception innerException): base(message, innerException)
    {
    }
}
