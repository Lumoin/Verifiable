namespace Verifiable.Tpm.Automata;

/// <summary>
/// The outcome of the TPM's self-test, as reported by <c>TPM2_GetTestResult()</c>
/// (TPM 2.0 Library Part 1, clause 10.3).
/// </summary>
public enum TpmSelfTestStatus
{
    /// <summary>
    /// No self-test has run since the last <c>_TPM_Init</c>.
    /// </summary>
    NotRun,

    /// <summary>
    /// The self-test completed successfully.
    /// </summary>
    Passed,

    /// <summary>
    /// The self-test failed; the TPM is in <see cref="TpmLifecyclePhase.FailureMode"/>.
    /// </summary>
    Failed
}
