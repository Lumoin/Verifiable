using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm.Extensions.Policy;

/// <summary>
/// Policy (enhanced authorization) extensions for <see cref="TpmDevice"/>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Channel protection.</b> The policy assertion commands (<c>PolicyCommandCode</c>, <c>PolicyAuthValue</c>)
/// and <c>PolicyGetDigest</c> carry no confidential parameters — a command code, or the public policyDigest — so
/// they run without a parameter-encryption session. The confidentiality- and integrity-sensitive step is the
/// authorized command performed under the policy session (for example <c>TPM2_Sign</c>); there the library
/// offers the maximum-security channel — a salted or bound session with AES-CFB parameter encryption and
/// response-HMAC verification — rather than an unprotected one.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "The analyzer is not up to date with latest syntax.")]
public static class TpmDeviceExtensions
{
    extension(TpmDevice device)
    {
        /// <summary>
        /// Starts a trial policy session, which accumulates a policyDigest without authorizing anything — used to
        /// compute the digest to set as an object's authPolicy.
        /// </summary>
        /// <param name="policyHash">The policy session's hash algorithm.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result containing the started session or an error.</returns>
        public ValueTask<TpmResult<StartAuthSessionResponse>> StartTrialPolicySessionAsync(
            TpmAlgIdConstants policyHash, CancellationToken cancellationToken = default)
        {
            return StartPolicySessionCoreAsync(device, TpmSeConstants.TPM_SE_TRIAL, policyHash, cancellationToken);
        }

        /// <summary>
        /// Starts a policy session for authorization. The policyDigest it accumulates must match an object's
        /// authPolicy for the session to authorize use of that object.
        /// </summary>
        /// <param name="policyHash">The policy session's hash algorithm.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result containing the started session or an error.</returns>
        public ValueTask<TpmResult<StartAuthSessionResponse>> StartPolicySessionAsync(
            TpmAlgIdConstants policyHash, CancellationToken cancellationToken = default)
        {
            return StartPolicySessionCoreAsync(device, TpmSeConstants.TPM_SE_POLICY, policyHash, cancellationToken);
        }

        /// <summary>
        /// Runs <c>TPM2_PolicyCommandCode</c>, restricting the policy session to a single command.
        /// </summary>
        /// <param name="policySession">The policy session handle.</param>
        /// <param name="restrictedCommand">The command code the policy is restricted to.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success or an error.</returns>
        public ValueTask<TpmResult<PolicyCommandCodeResponse>> PolicyCommandCodeAsync(
            uint policySession, TpmCcConstants restrictedCommand, CancellationToken cancellationToken = default)
        {
            return PolicyCommandCodeCoreAsync(device, policySession, restrictedCommand, cancellationToken);
        }

        /// <summary>
        /// Runs <c>TPM2_PolicyAuthValue</c>, binding the policy to the authorized object's authorization value.
        /// </summary>
        /// <param name="policySession">The policy session handle.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success or an error.</returns>
        public ValueTask<TpmResult<PolicyAuthValueResponse>> PolicyAuthValueAsync(
            uint policySession, CancellationToken cancellationToken = default)
        {
            return PolicyAuthValueCoreAsync(device, policySession, cancellationToken);
        }

        /// <summary>
        /// Runs <c>TPM2_PolicyPCR</c>, binding the policy to a set of PCRs.
        /// </summary>
        /// <param name="policySession">The policy session handle.</param>
        /// <param name="pcrBank">The PCR bank (hash algorithm) to select from.</param>
        /// <param name="pcrIndices">The PCR indices (0-23) to bind to.</param>
        /// <param name="pcrDigest">The expected digest of the selected PCR values, or empty to bind to the current PCR state.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success or an error.</returns>
        public ValueTask<TpmResult<PolicyPcrResponse>> PolicyPcrAsync(
            uint policySession, TpmAlgIdConstants pcrBank, int[] pcrIndices, ReadOnlyMemory<byte> pcrDigest = default, CancellationToken cancellationToken = default)
        {
            return PolicyPcrCoreAsync(device, policySession, pcrBank, pcrIndices, pcrDigest, cancellationToken);
        }

        /// <summary>
        /// Runs <c>TPM2_PolicyOR</c>, authorizing the session when its current policyDigest matches one of
        /// <paramref name="branchDigests"/> and collapsing the session to the OR digest
        /// (<c>H(0 || TPM_CC_PolicyOR || branches)</c>). On a trial session the match is skipped and the digest is
        /// set unconditionally.
        /// </summary>
        /// <param name="policySession">The policy session handle.</param>
        /// <param name="branchDigests">The allowed branch policy digests.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success or an error.</returns>
        public ValueTask<TpmResult<PolicyOrResponse>> PolicyOrAsync(
            uint policySession, IReadOnlyList<ReadOnlyMemory<byte>> branchDigests, CancellationToken cancellationToken = default)
        {
            return PolicyOrCoreAsync(device, policySession, branchDigests, cancellationToken);
        }

        /// <summary>
        /// Runs <c>TPM2_PolicyNV</c>, authorizing the session only when the contents of <paramref name="nvIndex"/>
        /// at <paramref name="offset"/> compare to <paramref name="operandB"/> as specified by
        /// <paramref name="operation"/>. The read of the Index is authorized with an empty-auth password session
        /// (the common case: an Index or hierarchy whose authorization value has not been set).
        /// </summary>
        /// <param name="authHandle">The authorization for reading the Index (the Index itself, or a hierarchy with the matching read attribute).</param>
        /// <param name="nvIndex">The NV Index whose contents are compared.</param>
        /// <param name="policySession">The policy session handle.</param>
        /// <param name="operandB">The value to compare the NV data against.</param>
        /// <param name="offset">The octet offset into the NV Index data.</param>
        /// <param name="operation">The TPM_EO comparison operation.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success or an error.</returns>
        public ValueTask<TpmResult<PolicyNvResponse>> PolicyNvAsync(
            uint authHandle, uint nvIndex, uint policySession, ReadOnlyMemory<byte> operandB, ushort offset, TpmEoConstants operation, CancellationToken cancellationToken = default)
        {
            return PolicyNvCoreAsync(device, authHandle, nvIndex, policySession, operandB, offset, operation, cancellationToken);
        }

        /// <summary>
        /// Runs <c>TPM2_PolicySecret</c> (immediate form), binding the policy to the authorization of the entity
        /// at <paramref name="authHandle"/>. The entity is authorized with an empty-auth password session — the
        /// common case for a hierarchy (owner/endorsement/platform) whose authorization value has not been set.
        /// Binding to <c>TPM_RH_ENDORSEMENT</c> yields the well-known endorsement-key authorization policy.
        /// </summary>
        /// <param name="authHandle">The entity whose authorization the policy requires (for example <c>(uint)TpmRh.TPM_RH_ENDORSEMENT</c>).</param>
        /// <param name="policySession">The policy session handle.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result containing the timeout and ticket (dispose the response) or an error.</returns>
        public ValueTask<TpmResult<PolicySecretResponse>> PolicySecretAsync(
            uint authHandle, uint policySession, CancellationToken cancellationToken = default)
        {
            return PolicySecretCoreAsync(device, authHandle, policySession, cancellationToken);
        }

        /// <summary>
        /// Runs <c>TPM2_PolicyGetDigest</c>, returning the session's current policyDigest.
        /// </summary>
        /// <param name="policySession">The policy session handle.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result containing the policyDigest (dispose the response to release it) or an error.</returns>
        public ValueTask<TpmResult<PolicyGetDigestResponse>> PolicyGetDigestAsync(
            uint policySession, CancellationToken cancellationToken = default)
        {
            return PolicyGetDigestCoreAsync(device, policySession, cancellationToken);
        }

        /// <summary>
        /// Runs <c>TPM2_FlushContext</c>, releasing a transient session or object handle.
        /// </summary>
        /// <param name="handle">The handle to flush.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success or an error.</returns>
        public ValueTask<TpmResult<FlushContextResponse>> FlushContextAsync(
            uint handle, CancellationToken cancellationToken = default)
        {
            return FlushContextCoreAsync(device, handle, cancellationToken);
        }
    }

    private static async ValueTask<TpmResult<StartAuthSessionResponse>> StartPolicySessionCoreAsync(
        TpmDevice device, TpmSeConstants sessionType, TpmAlgIdConstants policyHash, CancellationToken cancellationToken)
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);

        StartAuthSessionInput input = sessionType == TpmSeConstants.TPM_SE_TRIAL
            ? StartAuthSessionInput.CreateTrialPolicySession(policyHash)
            : StartAuthSessionInput.CreateUnboundUnsaltedPolicySession(policyHash);

        return await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            device, input, [], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<TpmResult<PolicyCommandCodeResponse>> PolicyCommandCodeCoreAsync(
        TpmDevice device, uint policySession, TpmCcConstants restrictedCommand, CancellationToken cancellationToken)
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyCommandCode, TpmResponseCodec.PolicyCommandCode);

        PolicyCommandCodeInput input = PolicyCommandCodeInput.Create(policySession, restrictedCommand);

        return await TpmCommandExecutor.ExecuteAsync<PolicyCommandCodeResponse>(
            device, input, [], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<TpmResult<PolicyAuthValueResponse>> PolicyAuthValueCoreAsync(
        TpmDevice device, uint policySession, CancellationToken cancellationToken)
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyAuthValue, TpmResponseCodec.PolicyAuthValue);

        PolicyAuthValueInput input = PolicyAuthValueInput.ForSession(policySession);

        return await TpmCommandExecutor.ExecuteAsync<PolicyAuthValueResponse>(
            device, input, [], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the PCR selection transfers to the PolicyPcrInput, which is disposed by its using declaration.")]
    private static async ValueTask<TpmResult<PolicyPcrResponse>> PolicyPcrCoreAsync(
        TpmDevice device, uint policySession, TpmAlgIdConstants pcrBank, int[] pcrIndices, ReadOnlyMemory<byte> pcrDigest, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(pcrIndices);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyPCR, TpmResponseCodec.PolicyPcr);

        using PolicyPcrInput input = PolicyPcrInput.Create(
            policySession, pcrDigest.Span, TpmlPcrSelection.Create(pcrBank, pcrIndices, pool), pool);

        return await TpmCommandExecutor.ExecuteAsync<PolicyPcrResponse>(
            device, input, [], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<TpmResult<PolicyOrResponse>> PolicyOrCoreAsync(
        TpmDevice device, uint policySession, IReadOnlyList<ReadOnlyMemory<byte>> branchDigests, CancellationToken cancellationToken)
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyOR, TpmResponseCodec.PolicyOr);

        var input = new PolicyOrInput(policySession, branchDigests);

        return await TpmCommandExecutor.ExecuteAsync<PolicyOrResponse>(
            device, input, [], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<TpmResult<PolicyNvResponse>> PolicyNvCoreAsync(
        TpmDevice device, uint authHandle, uint nvIndex, uint policySession, ReadOnlyMemory<byte> operandB, ushort offset, TpmEoConstants operation, CancellationToken cancellationToken)
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyNV, TpmResponseCodec.PolicyNv);

        //PolicyNV reads the Index, authorized at USER role; an empty-auth password session covers an Index or
        //hierarchy whose authorization value has not been set.
        using TpmPasswordSession authSession = TpmPasswordSession.CreateEmpty(pool);
        var input = new PolicyNvInput(authHandle, nvIndex, policySession, operandB, offset, operation);

        return await TpmCommandExecutor.ExecuteAsync<PolicyNvResponse>(
            device, input, [authSession], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<TpmResult<PolicySecretResponse>> PolicySecretCoreAsync(
        TpmDevice device, uint authHandle, uint policySession, CancellationToken cancellationToken)
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicySecret, TpmResponseCodec.PolicySecret);

        //PolicySecret authorizes authHandle at USER role; an empty-auth password session covers a hierarchy whose
        //authorization value has not been set (the default for owner/endorsement/platform).
        using TpmPasswordSession authSession = TpmPasswordSession.CreateEmpty(pool);
        var input = new PolicySecretInput(authHandle, policySession);

        return await TpmCommandExecutor.ExecuteAsync<PolicySecretResponse>(
            device, input, [authSession], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<TpmResult<PolicyGetDigestResponse>> PolicyGetDigestCoreAsync(
        TpmDevice device, uint policySession, CancellationToken cancellationToken)
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyGetDigest, TpmResponseCodec.PolicyGetDigest);

        PolicyGetDigestInput input = PolicyGetDigestInput.ForSession(policySession);

        return await TpmCommandExecutor.ExecuteAsync<PolicyGetDigestResponse>(
            device, input, [], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<TpmResult<FlushContextResponse>> FlushContextCoreAsync(
        TpmDevice device, uint handle, CancellationToken cancellationToken)
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        FlushContextInput input = FlushContextInput.ForHandle(handle);

        return await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            device, input, [], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }
}
