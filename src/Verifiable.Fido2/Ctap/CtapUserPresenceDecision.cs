namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The outcome of one simulated user-presence collection (CTAP 2.3 :2840's user action timeout model:
/// "waiting for direct action from the user, like a touch"), as reported by
/// <see cref="SimulateUserPresenceDelegate"/>.
/// </summary>
public enum CtapUserPresenceDecision
{
    /// <summary>
    /// Evidence of user interaction was collected: the caller proceeds exactly as if a touch had just
    /// been observed.
    /// </summary>
    Granted,

    /// <summary>
    /// The user declined: the caller aborts the command with <see cref="WellKnownCtapStatusCodes.OperationDenied"/>.
    /// </summary>
    Denied,

    /// <summary>
    /// No gesture has been made yet. On a deferring transport this parks the command for a later poll;
    /// on a non-deferring path this decision REPRESENTS an elapsed :2840 timeout — a deterministic
    /// simulator has no wall-clock wait to block on, so the provider's own answer stands in for the
    /// block-then-time-out a real, non-deferring authenticator would perform, and the caller aborts with
    /// <see cref="WellKnownCtapStatusCodes.UserActionTimeout"/> exactly as that authenticator would.
    /// </summary>
    Pending
}
