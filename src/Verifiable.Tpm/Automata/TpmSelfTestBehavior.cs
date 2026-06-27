namespace Verifiable.Tpm.Automata;

/// <summary>
/// Configures how the modelled TPM responds to a self-test. This lets tests drive the device into
/// <see cref="TpmLifecyclePhase.FailureMode"/> deterministically, without any cryptographic work,
/// by modelling a TPM whose internal test fails (TPM 2.0 Library Part 1, clauses 10.3 and 10.4).
/// </summary>
public enum TpmSelfTestBehavior
{
    /// <summary>The self-test passes; the TPM stays operational.</summary>
    Passes,

    /// <summary>The self-test fails; the TPM enters <see cref="TpmLifecyclePhase.FailureMode"/>.</summary>
    Fails
}
