namespace Verifiable.Tpm.Automata;

/// <summary>
/// The basic operational phases of a TPM, as defined in TPM 2.0 Library Part 1, clause 10
/// ("TPM Operational States").
/// </summary>
/// <remarks>
/// <para>
/// The phases form the backbone of the behavioural simulator's state machine. Command
/// admissibility is gated on the current phase (see <see cref="TpmCommandPreconditions"/>),
/// mirroring the normative behaviour: pre-initialization commands are rejected with
/// <c>TPM_RC_INITIALIZE</c>, and a TPM in Failure Mode answers only <c>TPM2_GetTestResult()</c>
/// and <c>TPM2_GetCapability()</c>.
/// </para>
/// </remarks>
public enum TpmLifecyclePhase
{
    /// <summary>
    /// No power is applied (Part 1, 10.2.1). The simulator starts here and requires a
    /// <c>_TPM_Init</c> indication before it processes any command.
    /// </summary>
    PoweredOff,

    /// <summary>
    /// The TPM has received <c>_TPM_Init</c> and is awaiting <c>TPM2_Startup()</c>
    /// (Part 1, 10.2.2). Any command other than <c>TPM2_Startup()</c> is answered with
    /// <c>TPM_RC_INITIALIZE</c>.
    /// </summary>
    Initializing,

    /// <summary>
    /// The TPM has completed <c>TPM2_Startup()</c> and processes commands normally
    /// (Part 1, 10.2.3).
    /// </summary>
    Operational,

    /// <summary>
    /// An internal test failed (Part 1, 10.3 and 10.4). The TPM answers <c>TPM_RC_FAILURE</c>
    /// to every command except <c>TPM2_GetTestResult()</c> and <c>TPM2_GetCapability()</c>,
    /// and only <c>_TPM_Init</c> exits this phase.
    /// </summary>
    FailureMode
}
