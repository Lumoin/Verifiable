using System;

namespace Verifiable.Fido2.Ctap.Authenticator.Custody;

/// <summary>
/// A <see cref="TpmSealedStateCustody"/> operation failed closed: the in-house simulated TPM rejected a
/// seal or unseal, or a stored sealed-blob byte sequence did not parse as a well-formed
/// <see cref="Verifiable.Tpm.Extensions.Seal.TpmSealedBlob"/>.
/// </summary>
/// <remarks>
/// Per contract R-7's fail-closed requirement, every TPM-side failure this adapter can observe — a
/// <c>SealAsync</c>/<c>UnsealAsync</c> result whose <see cref="Verifiable.Tpm.TpmResult{T}.IsSuccess"/> is
/// <see langword="false"/>, or a tampered/truncated sealed-blob byte sequence that does not parse — surfaces
/// as this one exception type rather than a silently empty or partially rehydrated snapshot. The caller's
/// correct reaction is identical in every case: discard the attempt and treat the authenticator as unable
/// to rehydrate, exactly the posture <see cref="CtapAuthenticatorSnapshotException"/> already establishes
/// for a snapshot-FORMAT failure on the CTAP side of this same seam.
/// </remarks>
public sealed class TpmSealedStateCustodyException: Exception
{
    /// <summary>
    /// Initializes a new instance with no message.
    /// </summary>
    public TpmSealedStateCustodyException()
    {
    }


    /// <summary>
    /// Initializes a new instance with a message describing which TPM operation failed closed.
    /// </summary>
    /// <param name="message">A message describing the rejection.</param>
    public TpmSealedStateCustodyException(string message): base(message)
    {
    }


    /// <summary>
    /// Initializes a new instance with a message and an inner exception describing which TPM operation
    /// failed closed.
    /// </summary>
    /// <param name="message">A message describing the rejection.</param>
    /// <param name="innerException">The underlying TPM or parse failure, if any.</param>
    public TpmSealedStateCustodyException(string message, Exception innerException): base(message, innerException)
    {
    }
}
