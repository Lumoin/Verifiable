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
        /// Runs <c>TPM2_PolicyCounterTimer</c>, authorizing the session only when the TPM's live
        /// <c>TPMS_TIME_INFO</c> (Time, Clock, resetCount, restartCount, Safe), at <paramref name="offset"/>,
        /// compares to <paramref name="operandB"/> as specified by <paramref name="operation"/>.
        /// </summary>
        /// <param name="policySession">The policy session handle.</param>
        /// <param name="operandB">The value to compare the live TPMS_TIME_INFO against.</param>
        /// <param name="offset">The octet offset into the marshaled TPMS_TIME_INFO.</param>
        /// <param name="operation">The TPM_EO comparison operation.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success or an error.</returns>
        public ValueTask<TpmResult<PolicyCounterTimerResponse>> PolicyCounterTimerAsync(
            uint policySession, ReadOnlyMemory<byte> operandB, ushort offset, TpmEoConstants operation, CancellationToken cancellationToken = default)
        {
            return PolicyCounterTimerCoreAsync(device, policySession, operandB, offset, operation, cancellationToken);
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
        /// Runs <c>TPM2_PolicySigned</c>, binding the policy session to a signature over
        /// <c>aHash = H_authAlg(nonceTPM || expiration || cpHashA || policyRef)</c> made by the key at
        /// <paramref name="authObject"/>. Neither <paramref name="authObject"/> nor <paramref name="policySession"/>
        /// requires authorization (TPM 2.0 Library Part 3, Section 23.3), so the command carries no authorization
        /// area at all.
        /// </summary>
        /// <param name="authObject">The handle of the key whose public part validates the signature.</param>
        /// <param name="policySession">The policy session handle being extended.</param>
        /// <param name="nonceTpm">The policy session's retained nonceTPM, or empty for a session-unbound authorization.</param>
        /// <param name="cpHashA">The digest of the command parameters being authorized, or empty if unbound.</param>
        /// <param name="policyRef">The opaque policy qualifier, or empty for none.</param>
        /// <param name="expiration">The signed expiration; 0 = no expiry, negative = ticket requested (deferred this wave).</param>
        /// <param name="signature">The signature octets: IEEE P1363 r ‖ s for ECDSA, or the raw RSA signature for RSASSA/RSAPSS.</param>
        /// <param name="signatureScheme">The signing scheme algorithm (TPM_ALG_ECDSA, TPM_ALG_RSASSA, or TPM_ALG_RSAPSS).</param>
        /// <param name="schemeHashAlg">The hash algorithm carried inside the signature (H_authAlg, which builds aHash).</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result containing the timeout and ticket (dispose the response) or an error.</returns>
        public ValueTask<TpmResult<PolicySignedResponse>> PolicySignedAsync(
            uint authObject,
            uint policySession,
            ReadOnlyMemory<byte> nonceTpm,
            ReadOnlyMemory<byte> cpHashA,
            ReadOnlyMemory<byte> policyRef,
            int expiration,
            ReadOnlyMemory<byte> signature,
            TpmAlgIdConstants signatureScheme,
            TpmAlgIdConstants schemeHashAlg,
            CancellationToken cancellationToken = default)
        {
            return PolicySignedCoreAsync(
                device, authObject, policySession, nonceTpm, cpHashA, policyRef, expiration, signature, signatureScheme, schemeHashAlg, cancellationToken);
        }

        /// <summary>
        /// Runs <c>TPM2_PolicyAuthorize</c>, authorizing the session when its policyDigest equals
        /// <paramref name="approvedPolicy"/> and <paramref name="checkTicket"/> proves <paramref name="keySign"/> signed
        /// <c>H(approvedPolicy || policyRef)</c>, then replacing the digest with
        /// <c>H(H(0...0 || TPM_CC_PolicyAuthorize || keySign) || policyRef)</c> (TPM 2.0 Library Part 3, Section
        /// 23.16) — letting the session accept a policy the authority can revise at will.
        /// </summary>
        /// <param name="policySession">The policy session handle being extended.</param>
        /// <param name="approvedPolicy">The policy digest being approved; must equal the session's current policyDigest.</param>
        /// <param name="policyRef">The opaque policy qualifier, or empty for none.</param>
        /// <param name="keySign">The Name of the key that signed the approval.</param>
        /// <param name="checkTicket">The verification ticket (a genuine <c>TPM2_VerifySignature()</c> ticket, or <see cref="TpmtTkVerified.Null"/> for a trial session); a borrow the call does not retain.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success or an error.</returns>
        public ValueTask<TpmResult<PolicyAuthorizeResponse>> PolicyAuthorizeAsync(
            uint policySession,
            ReadOnlyMemory<byte> approvedPolicy,
            ReadOnlyMemory<byte> policyRef,
            ReadOnlyMemory<byte> keySign,
            TpmtTkVerified checkTicket,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(checkTicket);

            return PolicyAuthorizeCoreAsync(device, policySession, approvedPolicy, policyRef, keySign, checkTicket, cancellationToken);
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

    private static async ValueTask<TpmResult<PolicyCounterTimerResponse>> PolicyCounterTimerCoreAsync(
        TpmDevice device, uint policySession, ReadOnlyMemory<byte> operandB, ushort offset, TpmEoConstants operation, CancellationToken cancellationToken)
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyCounterTimer, TpmResponseCodec.PolicyCounterTimer);

        var input = new PolicyCounterTimerInput(policySession, operandB, offset, operation);

        return await TpmCommandExecutor.ExecuteAsync<PolicyCounterTimerResponse>(
            device, input, [], null, pool, registry, cancellationToken).ConfigureAwait(false);
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

    private static async ValueTask<TpmResult<PolicySignedResponse>> PolicySignedCoreAsync(
        TpmDevice device,
        uint authObject,
        uint policySession,
        ReadOnlyMemory<byte> nonceTpm,
        ReadOnlyMemory<byte> cpHashA,
        ReadOnlyMemory<byte> policyRef,
        int expiration,
        ReadOnlyMemory<byte> signature,
        TpmAlgIdConstants signatureScheme,
        TpmAlgIdConstants schemeHashAlg,
        CancellationToken cancellationToken)
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicySigned, TpmResponseCodec.PolicySigned);

        //PolicySigned carries no authorization at all: neither authObject nor policySession needs one (a
        //public-key operation, TPM 2.0 Library Part 3, Section 23.3), so the executor is given no sessions and
        //frames TPM_ST_NO_SESSIONS, exactly as TPM2_VerifySignature() does.
        using PolicySignedInput input = PolicySignedInput.Create(
            authObject, policySession, nonceTpm.Span, cpHashA.Span, policyRef.Span, expiration, signature.Span, signatureScheme, schemeHashAlg, pool);

        return await TpmCommandExecutor.ExecuteAsync<PolicySignedResponse>(
            device, input, [], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<TpmResult<PolicyAuthorizeResponse>> PolicyAuthorizeCoreAsync(
        TpmDevice device,
        uint policySession,
        ReadOnlyMemory<byte> approvedPolicy,
        ReadOnlyMemory<byte> policyRef,
        ReadOnlyMemory<byte> keySign,
        TpmtTkVerified checkTicket,
        CancellationToken cancellationToken)
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyAuthorize, TpmResponseCodec.PolicyAuthorize);

        //PolicyAuthorize carries no authorization at all: policySession needs none (Part 3, Section 23.16), so
        //the executor is given no sessions and frames TPM_ST_NO_SESSIONS. The ticket type itself guarantees the
        //TPM_ST_VERIFIED tag a genuine TPM2_VerifySignature() ticket (real or NULL) always carries.
        using PolicyAuthorizeInput input = PolicyAuthorizeInput.Create(
            policySession, approvedPolicy.Span, policyRef.Span, keySign.Span,
            (ushort)checkTicket.Tag, (uint)checkTicket.Hierarchy, checkTicket.Digest, pool);

        return await TpmCommandExecutor.ExecuteAsync<PolicyAuthorizeResponse>(
            device, input, [], null, pool, registry, cancellationToken).ConfigureAwait(false);
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
