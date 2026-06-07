namespace Verifiable.OAuth.Oid4Vp.Session;

/// <summary>
/// The outcome of a single step through the OID4VP flow automaton.
/// </summary>
public enum Oid4VpStepOutcome
{
    /// <summary>
    /// A transition was found and applied. Persist <see cref="Oid4VpStepResult.State"/>
    /// and <see cref="Oid4VpStepResult.StepCount"/> before returning an HTTP response.
    /// </summary>
    Transitioned,

    /// <summary>
    /// No transition is defined for the input in the current state. The state and step
    /// count are unchanged. The controller should return HTTP 400.
    /// </summary>
    Halted,

    /// <summary>
    /// The transition delegate threw an unexpected exception. The state and step count
    /// are unchanged. The exception is in <see cref="Oid4VpStepResult.FaultException"/>.
    /// The controller should return HTTP 500.
    /// </summary>
    Faulted
}
