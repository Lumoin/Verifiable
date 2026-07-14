namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The outcome of one simulated built-in user verification attempt (CTAP 2.3 §6.5.3.1's
/// <c>performBuiltInUv</c>, step 7's "Perform built-in user verification" through step 9's success
/// check / step 8's timeout check), as reported by <see cref="SimulateBuiltInUvDelegate"/>.
/// </summary>
public enum CtapBuiltInUvAttemptOutcome
{
    /// <summary>
    /// The simulated gesture matched (§6.5.3.1 step 9): the caller resets <c>uvRetries</c> to its
    /// maximum and proceeds.
    /// </summary>
    Success,

    /// <summary>
    /// The simulated gesture did not match (§6.5.3.1 step 10): the already-decremented <c>uvRetries</c>
    /// stands, and the loop retries while <c>attemptsBeforeReturning</c> remains and the counter is
    /// still non-zero, or otherwise reports an error.
    /// </summary>
    MatchFailure,

    /// <summary>
    /// The simulated gesture timed out waiting for user action (§6.5.3.1 step 8): the loop stops
    /// immediately without a further attempt, even if retries remain.
    /// </summary>
    UserActionTimeout
}
