using System;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Fido2.Tpm.Ctap.Authenticator.Custody;

/// <summary>
/// A <see cref="TpmNvSignatureCounterCustody"/> operation failed closed: the in-house simulated TPM
/// rejected a define, increment, read, or undefine against a credential's NV Counter Index.
/// </summary>
/// <remarks>
/// Per contract R-9's fail-closed requirement (wavenv), every TPM-side rejection this adapter can observe —
/// a <c>DefineCounterAsync</c>/<c>IncrementCounterAsync</c>/<c>UndefineCounterAsync</c> result whose
/// <see cref="Verifiable.Tpm.TpmResult{T}.IsSuccess"/> is <see langword="false"/> and is not the
/// tolerated "already defined" case — surfaces as this one exception type. The caller's correct reaction
/// mirrors <see cref="TpmSealedStateCustodyException"/>'s own posture: the command this adapter's delegate
/// was called from fails outright, never with a silently non-advanced or unminted counter.
/// </remarks>
[SuppressMessage("Design", "CA1515:Consider making public types internal", Justification = "Staged composition-edge code (layering-split-ledger.md): public by design so the boundary is already the future package's API boundary, per the promotability rules.")]
public sealed class TpmNvSignatureCounterCustodyException: Exception
{
    /// <summary>
    /// Initializes a new instance with no message.
    /// </summary>
    public TpmNvSignatureCounterCustodyException()
    {
    }


    /// <summary>
    /// Initializes a new instance with a message describing which TPM operation failed closed.
    /// </summary>
    /// <param name="message">A message describing the rejection.</param>
    public TpmNvSignatureCounterCustodyException(string message): base(message)
    {
    }


    /// <summary>
    /// Initializes a new instance with a message and an inner exception describing which TPM operation
    /// failed closed.
    /// </summary>
    /// <param name="message">A message describing the rejection.</param>
    /// <param name="innerException">The underlying TPM failure, if any.</param>
    public TpmNvSignatureCounterCustodyException(string message, Exception innerException): base(message, innerException)
    {
    }
}
