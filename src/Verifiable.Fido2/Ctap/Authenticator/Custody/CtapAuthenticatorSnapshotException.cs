using System;

namespace Verifiable.Fido2.Ctap.Authenticator.Custody;

/// <summary>
/// A CTAP authenticator state-custody snapshot failed to rehydrate: the bytes did not parse as the
/// versioned format this codec understands, or the parsed snapshot's personalization fingerprint did not
/// match the composed authenticator it was about to restore into.
/// </summary>
/// <remarks>
/// Per contract ruling R-2b/R-5, rehydration FAILS CLOSED on either failure — a snapshot never silently
/// re-personalizes a differently-composed authenticator, and a truncated or tampered snapshot never
/// yields a partially restored state. Both failure families share this one exception type rather than a
/// finer-grained hierarchy, since every caller's correct reaction is identical: discard the snapshot,
/// discard any state built from it, and treat the authenticator as unable to rehydrate.
/// </remarks>
public sealed class CtapAuthenticatorSnapshotException: Exception
{
    /// <summary>
    /// Initializes a new instance with no message.
    /// </summary>
    public CtapAuthenticatorSnapshotException()
    {
    }


    /// <summary>
    /// Initializes a new instance with a message describing which fail-closed check rejected the
    /// snapshot.
    /// </summary>
    /// <param name="message">A message describing the rejection.</param>
    public CtapAuthenticatorSnapshotException(string message): base(message)
    {
    }


    /// <summary>
    /// Initializes a new instance with a message and an inner exception describing which fail-closed
    /// check rejected the snapshot.
    /// </summary>
    /// <param name="message">A message describing the rejection.</param>
    /// <param name="innerException">The underlying parse failure, if any.</param>
    public CtapAuthenticatorSnapshotException(string message, Exception innerException): base(message, innerException)
    {
    }
}
