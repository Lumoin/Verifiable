using System;
using System.Collections.Generic;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Structures;

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
    /// Appends a TPM2_PolicyCounterTimer assertion.
    /// </summary>
    /// <param name="operandB">The value to compare the live TPMS_TIME_INFO against.</param>
    /// <param name="offset">The octet offset into the marshaled TPMS_TIME_INFO.</param>
    /// <param name="operation">The TPM_EO comparison operation.</param>
    /// <returns>This builder.</returns>
    public TpmPolicyBuilder WithCounterTimer(ReadOnlyMemory<byte> operandB, ushort offset, TpmEoConstants operation)
    {
        Assertions.Add(new CounterTimerPolicyAssertion(operandB, offset, operation));

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
    /// Appends a TPM2_PolicySigned assertion. Replay always uses an empty caller nonceTPM and cpHashA (a
    /// session-unbound, command-unbound authorization).
    /// </summary>
    /// <param name="authObject">The handle of the key whose public part validates the signature.</param>
    /// <param name="authName">The Name of that key (<c>nameAlg || H(TPMT_PUBLIC)</c>).</param>
    /// <param name="policyRef">The opaque policy qualifier, or empty for none.</param>
    /// <param name="sign">The signing delegate invoked at replay time with the freshly built <c>aHash</c>.</param>
    /// <param name="signingContext">Caller-supplied context passed to <paramref name="sign"/> verbatim (no closure capture).</param>
    /// <param name="signatureScheme">The signing scheme (<c>TPM_ALG_ECDSA</c>, <c>TPM_ALG_RSASSA</c>, or <c>TPM_ALG_RSAPSS</c>).</param>
    /// <param name="schemeHashAlg">The hash algorithm the signature carries (H_authAlg).</param>
    /// <param name="expiration">The signed expiration; 0 = no expiry.</param>
    /// <returns>This builder.</returns>
    public TpmPolicyBuilder WithSigned(
        uint authObject,
        ReadOnlyMemory<byte> authName,
        ReadOnlyMemory<byte> policyRef,
        TpmPolicySignedSigningDelegate sign,
        object? signingContext,
        TpmAlgIdConstants signatureScheme,
        TpmAlgIdConstants schemeHashAlg,
        int expiration = 0)
    {
        ArgumentNullException.ThrowIfNull(sign);
        Assertions.Add(new SignedPolicyAssertion(authObject, authName, policyRef, expiration, signatureScheme, schemeHashAlg, sign, signingContext));

        return this;
    }

    /// <summary>
    /// Appends a TPM2_PolicyAuthorize assertion.
    /// </summary>
    /// <param name="approvedPolicy">The policyDigest being approved; must equal the session's current policyDigest at replay time.</param>
    /// <param name="policyRef">The opaque policy qualifier, or empty for none.</param>
    /// <param name="keySign">The Name of the key that signed the approval.</param>
    /// <param name="checkTicket">The verification ticket (a genuine TPM2_VerifySignature() ticket, or <see cref="TpmtTkVerified.Null"/> for a trial session); a borrow whose owner outlives the replay.</param>
    /// <returns>This builder.</returns>
    public TpmPolicyBuilder WithAuthorize(
        ReadOnlyMemory<byte> approvedPolicy,
        ReadOnlyMemory<byte> policyRef,
        ReadOnlyMemory<byte> keySign,
        TpmtTkVerified checkTicket)
    {
        Assertions.Add(new AuthorizePolicyAssertion(approvedPolicy, policyRef, keySign, checkTicket));

        return this;
    }

    /// <summary>
    /// Builds the immutable policy from the accumulated assertions.
    /// </summary>
    /// <returns>The built policy.</returns>
    public TpmPolicy Build() => new(Assertions.ToArray());
}
