using System;
using System.Collections.Generic;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm.Extensions.Policy;

/// <summary>
/// A fluent builder for a <see cref="TpmPolicy"/>. It accumulates assertions in order; the built policy then
/// both predicts its policyDigest (<see cref="TpmPolicy.ComputeDigest"/>) and replays itself on a session
/// (<see cref="TpmPolicy.ExecuteAsync"/>) from the one description.
/// </summary>
/// <remarks>
/// A convenience layer over the library's policy primitives (<see cref="TpmPolicyDigest"/> and the
/// <see cref="TpmDeviceExtensions"/> policy commands); for full control, use those directly.
/// </remarks>
public sealed class TpmPolicyBuilder
{
    private List<TpmPolicyAssertion> Assertions { get; } = [];

    /// <summary>
    /// Appends a TPM2_PolicyCommandCode assertion.
    /// </summary>
    /// <param name="commandCode">The command code the policy is restricted to.</param>
    /// <returns>This builder.</returns>
    public TpmPolicyBuilder WithCommandCode(TpmCcConstants commandCode)
    {
        Assertions.Add(new CommandCodePolicyAssertion(commandCode));

        return this;
    }

    /// <summary>
    /// Appends a TPM2_PolicyAuthValue assertion.
    /// </summary>
    /// <returns>This builder.</returns>
    public TpmPolicyBuilder WithAuthValue()
    {
        Assertions.Add(new AuthValuePolicyAssertion());

        return this;
    }

    /// <summary>
    /// Appends a TPM2_PolicySecret assertion against a permanent handle (empty policyRef).
    /// </summary>
    /// <param name="authHandle">The permanent handle whose authorization the policy requires (for example <c>(uint)TpmRh.TPM_RH_ENDORSEMENT</c>).</param>
    /// <returns>This builder.</returns>
    public TpmPolicyBuilder WithSecret(uint authHandle)
    {
        Assertions.Add(new SecretPolicyAssertion(authHandle));

        return this;
    }

    /// <summary>
    /// Appends a TPM2_PolicyPCR assertion.
    /// </summary>
    /// <param name="pcrBank">The PCR bank (hash algorithm).</param>
    /// <param name="pcrIndices">The PCR indices (0-23) to bind to.</param>
    /// <param name="pcrDigest">The expected digest of the selected PCR values, or empty to bind to the current state.</param>
    /// <returns>This builder.</returns>
    public TpmPolicyBuilder WithPcr(TpmAlgIdConstants pcrBank, int[] pcrIndices, ReadOnlyMemory<byte> pcrDigest = default)
    {
        Assertions.Add(new PcrPolicyAssertion(pcrBank, pcrIndices, pcrDigest));

        return this;
    }

    /// <summary>
    /// Appends a TPM2_PolicyNV assertion.
    /// </summary>
    /// <param name="authHandle">The authorization handle for reading the Index.</param>
    /// <param name="nvIndex">The NV Index whose contents are compared.</param>
    /// <param name="operandB">The value to compare against.</param>
    /// <param name="offset">The octet offset into the NV data.</param>
    /// <param name="operation">The TPM_EO comparison operation.</param>
    /// <param name="nvName">The NV Index Name (<c>nameAlg || H(TPMS_NV_PUBLIC)</c>).</param>
    /// <returns>This builder.</returns>
    public TpmPolicyBuilder WithNv(uint authHandle, uint nvIndex, ReadOnlyMemory<byte> operandB, ushort offset, TpmEoConstants operation, ReadOnlyMemory<byte> nvName)
    {
        Assertions.Add(new NvPolicyAssertion(authHandle, nvIndex, operandB, offset, operation, nvName));

        return this;
    }

    /// <summary>
    /// Appends a TPM2_PolicyOR assertion over precomputed branch digests.
    /// </summary>
    /// <param name="branchDigests">The OR branch policy digests (build each branch as a <see cref="TpmPolicy"/> and pass its computed digest).</param>
    /// <returns>This builder.</returns>
    public TpmPolicyBuilder WithOr(IReadOnlyList<ReadOnlyMemory<byte>> branchDigests)
    {
        Assertions.Add(new OrPolicyAssertion(branchDigests));

        return this;
    }

    /// <summary>
    /// Builds the immutable policy from the accumulated assertions.
    /// </summary>
    /// <returns>The built policy.</returns>
    public TpmPolicy Build() => new(Assertions.ToArray());
}
