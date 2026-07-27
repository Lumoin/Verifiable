using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tpm.Extensions.Seal;

/// <summary>
/// Sealed-storage ("tie a secret to this computer") business-capability extensions for <see cref="TpmDevice"/>.
/// </summary>
/// <remarks>
/// <para>
/// These verbs compose the shipped <c>TPM2_Create</c>/<c>TPM2_Load</c>/<c>TPM2_Unseal</c>/<c>TPM2_FlushContext</c>
/// surface (TPM 2.0 Library Part 3, Sections 12.1, 12.2, 12.7, 28.4) into three business goals: seal a secret
/// under a loaded storage parent, recover it by password, and recover it under an already-satisfied policy
/// session. Every session (the parent's authorization, and — for the password arm — the sealed item's) is built
/// and disposed internally; a caller never hands in a pre-built session, matching the existing
/// <c>Extensions/DictionaryAttack</c> and <c>Extensions/Policy</c> verb groups. The one caller-visible session is
/// the POLICY session <see cref="TpmDeviceExtensions.UnsealUnderPolicyAsync"/> authorizes under, because enhanced
/// authorization is itself the user-facing model (the <c>Extensions/Policy</c> verb group starts and drives it).
/// </para>
/// <para>
/// <b>Parent constraint.</b> <paramref name="parentHandle"/> (all three verbs) must be a loaded, restricted
/// storage key (<c>TPMA_OBJECT.restricted</c> and <c>decrypt</c> set) — the same constraint
/// <see cref="Tpm2bPublic.CreateEccStorageParentTemplate"/> satisfies and the seal flow tests build with
/// <c>CreatePrimaryInput.ForEccStorageParent</c>. A non-storage parent (for example a signing key) is rejected
/// by the TPM with <c>TPM_RC_TYPE</c> (Part 3, clause 12.1) — this surface does not widen to accept one.
/// </para>
/// <para>
/// <b>Hash algorithm.</b> The sealed object's <c>nameAlg</c> and (for the policy arm) the policy session's hash
/// algorithm are both fixed to <see cref="TpmAlgIdConstants.TPM_ALG_SHA256"/>, matching every other hardcoded
/// hash choice in this library's convenience factories (for example <c>CreateInput.ForEccSigningChild</c>). A
/// caller needing a different policy digest algorithm composes <c>CreateInput</c>/<c>LoadInput</c>/
/// <c>UnsealInput</c> directly, as the flow tests under <c>TpmInHouseSimulatorPcrSealTests</c> do.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "Analyzer does not recognize C# 13 extension type syntax.")]
public static class TpmDeviceExtensions
{
    /// <summary>The hash algorithm fixed for the sealed object's nameAlg and the policy-gated unseal arm's session.</summary>
    private const TpmAlgIdConstants SealHashAlgorithm = TpmAlgIdConstants.TPM_ALG_SHA256;

    extension(TpmDevice device)
    {
        /// <summary>
        /// Seals <paramref name="data"/> into a new <c>TPM_ALG_KEYEDHASH</c> object under the loaded storage
        /// parent at <paramref name="parentHandle"/>, composing <c>TPM2_Create</c> internally.
        /// </summary>
        /// <param name="parentHandle">The loaded storage-parent handle (see the type's parent-constraint remarks).</param>
        /// <param name="parentAuth">The parent's authorization value, or empty when the parent has no auth set.</param>
        /// <param name="data">The secret to seal.</param>
        /// <param name="sealAuth">
        /// The authorization value the sealed object's <c>userAuth</c> is set to, or empty for none. This is the
        /// value a later <see cref="UnsealAsync"/> call must supply.
        /// </param>
        /// <param name="authPolicy">
        /// The authorization policy digest to bind the object to (for example a <c>TPM2_PolicyPCR</c> digest
        /// computed under <see cref="SealHashAlgorithm"/>), or empty (default) for an object with no policy gate.
        /// </param>
        /// <param name="noDa">
        /// When <see langword="true"/>, authorization failures against the sealed object never advance the
        /// dictionary-attack lockout counter. Defaults to <see langword="false"/> (dictionary-attack PROTECTED) —
        /// the secure default matching <see cref="Tpm2bPublic.CreateSealedDataTemplate"/>'s own default: a real
        /// <paramref name="sealAuth"/> is a brute-forceable secret and should count toward the shared lockout
        /// counter unless the caller has a specific reason to exempt it (for example an empty <paramref
        /// name="sealAuth"/>, where there is nothing to brute-force).
        /// </param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result containing the sealed blob to persist, or an error.</returns>
        public ValueTask<TpmResult<TpmSealedBlob>> SealAsync(
            uint parentHandle,
            ReadOnlyMemory<byte> parentAuth,
            ReadOnlyMemory<byte> data,
            ReadOnlyMemory<byte> sealAuth,
            ReadOnlyMemory<byte> authPolicy = default,
            bool noDa = false,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return SealCoreAsync(device, parentHandle, parentAuth, data, sealAuth, authPolicy, noDa, cancellationToken);
        }

        /// <summary>
        /// Recovers the secret sealed in <paramref name="sealedBlob"/> by password, composing <c>TPM2_Load</c>,
        /// <c>TPM2_Unseal</c>, and <c>TPM2_FlushContext</c> internally. The loaded transient slot is always
        /// flushed, including when the Unseal itself fails.
        /// </summary>
        /// <param name="parentHandle">The loaded storage-parent handle that wrapped <paramref name="sealedBlob"/>.</param>
        /// <param name="parentAuth">The parent's authorization value, or empty when the parent has no auth set.</param>
        /// <param name="sealedBlob">The sealed blob a prior <see cref="SealAsync"/> produced.</param>
        /// <param name="sealAuth">The sealed object's authorization value supplied at seal time, or empty for none.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>
        /// A result containing the Unseal response (dispose it to release the recovered secret) or an error. A
        /// <c>userWithAuth</c>-CLEAR sealed object (an authPolicy sealed with the template's default password-and-
        /// policy authorization narrowed to policy-only) rejects this arm with <c>TPM_RC_POLICY_FAIL</c> — use
        /// <see cref="UnsealUnderPolicyAsync"/> for such an object.
        /// </returns>
        public ValueTask<TpmResult<UnsealResponse>> UnsealAsync(
            uint parentHandle,
            ReadOnlyMemory<byte> parentAuth,
            TpmSealedBlob sealedBlob,
            ReadOnlyMemory<byte> sealAuth,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);
            ArgumentNullException.ThrowIfNull(sealedBlob);

            return UnsealCoreAsync(device, parentHandle, parentAuth, sealedBlob, sealAuth, cancellationToken);
        }

        /// <summary>
        /// Recovers the secret sealed in <paramref name="sealedBlob"/> under an already-satisfied policy session,
        /// composing <c>TPM2_Load</c>, <c>TPM2_Unseal</c>, and <c>TPM2_FlushContext</c> internally. The loaded
        /// transient slot is always flushed, including when the Unseal itself fails.
        /// </summary>
        /// <remarks>
        /// The policy session is caller-visible and caller-owned: start and drive it to satisfaction with the
        /// <c>Extensions/Policy</c> verb group (for example <c>StartPolicySessionAsync</c> + <c>PolicyPcrAsync</c>),
        /// then pass its handle here. This verb neither starts nor flushes that session — only the transient
        /// object handle <c>TPM2_Load</c> produces.
        /// </remarks>
        /// <param name="parentHandle">The loaded storage-parent handle that wrapped <paramref name="sealedBlob"/>.</param>
        /// <param name="parentAuth">The parent's authorization value, or empty when the parent has no auth set.</param>
        /// <param name="sealedBlob">The sealed blob a prior <see cref="SealAsync"/> produced.</param>
        /// <param name="policySession">
        /// The handle of a policy session whose accumulated policyDigest matches <paramref name="sealedBlob"/>'s
        /// authPolicy under <see cref="SealHashAlgorithm"/>.
        /// </param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>
        /// A result containing the Unseal response (dispose it to release the recovered secret) or an error — for
        /// example <c>TPM_RC_POLICY_FAIL</c> when the session's policyDigest does not match the sealed authPolicy.
        /// </returns>
        public ValueTask<TpmResult<UnsealResponse>> UnsealUnderPolicyAsync(
            uint parentHandle,
            ReadOnlyMemory<byte> parentAuth,
            TpmSealedBlob sealedBlob,
            uint policySession,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);
            ArgumentNullException.ThrowIfNull(sealedBlob);

            return UnsealUnderPolicyCoreAsync(device, parentHandle, parentAuth, sealedBlob, policySession, cancellationToken);
        }
    }

    [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the sealed blob transfers to the TpmResult<TpmSealedBlob> returned to the caller, who disposes it.")]
    private static async ValueTask<TpmResult<TpmSealedBlob>> SealCoreAsync(
        TpmDevice device,
        uint parentHandle,
        ReadOnlyMemory<byte> parentAuth,
        ReadOnlyMemory<byte> data,
        ReadOnlyMemory<byte> sealAuth,
        ReadOnlyMemory<byte> authPolicy,
        bool noDa,
        CancellationToken cancellationToken)
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_Create, TpmResponseCodec.CreateObject);

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(data.Span, sealAuth.Span, pool);
        using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SealHashAlgorithm, pool, authPolicy.Span, noDa);
        using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession parentSession = TpmPasswordSession.Create(parentAuth.Span, pool);

        TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            device, createInput, [parentSession], null, pool, registry, cancellationToken).ConfigureAwait(false);

        if(!createResult.IsSuccess)
        {
            return createResult.Map<TpmSealedBlob>(_ => null!);
        }

        using CreateResponse created = createResult.Value;
        TpmSealedBlob sealedBlob = TpmSealedBlob.FromCreateResponse(created, pool);

        return TpmResult<TpmSealedBlob>.Success(sealedBlob);
    }

    private static async ValueTask<TpmResult<UnsealResponse>> UnsealCoreAsync(
        TpmDevice device,
        uint parentHandle,
        ReadOnlyMemory<byte> parentAuth,
        TpmSealedBlob sealedBlob,
        ReadOnlyMemory<byte> sealAuth,
        CancellationToken cancellationToken)
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmResponseRegistry registry = CreateUnsealRegistry();

        (Tpm2bPrivate InPrivate, Tpm2bPublic InPublic) cloned = sealedBlob.CloneForLoad(pool);
        using Tpm2bPrivate inPrivate = cloned.InPrivate;
        using Tpm2bPublic inPublic = cloned.InPublic;
        using LoadInput loadInput = new(parentHandle, inPrivate, inPublic);
        using TpmPasswordSession parentSession = TpmPasswordSession.Create(parentAuth.Span, pool);

        TpmResult<LoadResponse> loadResult = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
            device, loadInput, [parentSession], null, pool, registry, cancellationToken).ConfigureAwait(false);

        if(!loadResult.IsSuccess)
        {
            return loadResult.Map<UnsealResponse>(_ => null!);
        }

        using LoadResponse loaded = loadResult.Value;
        uint itemHandle = loaded.ObjectHandle.Value;

        try
        {
            using TpmPasswordSession itemSession = TpmPasswordSession.Create(sealAuth.Span, pool);
            UnsealInput unsealInput = UnsealInput.ForItem(loaded.ObjectHandle);

            return await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                device, unsealInput, [itemSession], null, pool, registry, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            await FlushTransientHandleAsync(device, registry, itemHandle, pool, cancellationToken).ConfigureAwait(false);
        }
    }

    private static async ValueTask<TpmResult<UnsealResponse>> UnsealUnderPolicyCoreAsync(
        TpmDevice device,
        uint parentHandle,
        ReadOnlyMemory<byte> parentAuth,
        TpmSealedBlob sealedBlob,
        uint policySession,
        CancellationToken cancellationToken)
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmResponseRegistry registry = CreateUnsealRegistry();

        (Tpm2bPrivate InPrivate, Tpm2bPublic InPublic) cloned = sealedBlob.CloneForLoad(pool);
        using Tpm2bPrivate inPrivate = cloned.InPrivate;
        using Tpm2bPublic inPublic = cloned.InPublic;
        using LoadInput loadInput = new(parentHandle, inPrivate, inPublic);
        using TpmPasswordSession parentSession = TpmPasswordSession.Create(parentAuth.Span, pool);

        TpmResult<LoadResponse> loadResult = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
            device, loadInput, [parentSession], null, pool, registry, cancellationToken).ConfigureAwait(false);

        if(!loadResult.IsSuccess)
        {
            return loadResult.Map<UnsealResponse>(_ => null!);
        }

        using LoadResponse loaded = loadResult.Value;
        uint itemHandle = loaded.ObjectHandle.Value;

        try
        {
            using TpmPolicySession authorizingSession = TpmPolicySession.ForSession(policySession, SealHashAlgorithm, pool);
            UnsealInput unsealInput = UnsealInput.ForItem(loaded.ObjectHandle);

            //The policy session's HashAlgorithm is not TPM_ALG_NULL, so the executor computes a cpHash for it
            //regardless of the session carrying no HMAC key of its own (Part 1, clause 19.6) — the loaded item's
            //Name must therefore be supplied (Part 1, equation 15), exactly as the PCR-seal flow tests do.
            ReadOnlyMemory<byte>[] handleNames = [loaded.Name.Span.ToArray()];

            return await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                device, unsealInput, [authorizingSession], handleNames, pool, registry, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            await FlushTransientHandleAsync(device, registry, itemHandle, pool, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Creates a response codec registry covering the Load/Unseal/FlushContext commands both Unseal cores issue.
    /// </summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateUnsealRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_Load, TpmResponseCodec.Load);
        _ = registry.Register(TpmCcConstants.TPM_CC_Unseal, TpmResponseCodec.Unseal);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }

    /// <summary>
    /// Runs <c>TPM2_FlushContext</c> against a loaded transient handle unconditionally — the closing half of the
    /// Load/Unseal/FlushContext bracket, always attempted even when the Unseal itself failed (Part 3, clause
    /// 28.4). The flush's own outcome is discarded: the composition's contract is the Unseal result, exactly as
    /// a caller-driven Load+Unseal+FlushContext sequence would leave it.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="registry">The response codec registry (must have <c>TPM_CC_FlushContext</c> registered).</param>
    /// <param name="itemHandle">The transient handle to flush.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    private static async ValueTask FlushTransientHandleAsync(
        TpmDevice device, TpmResponseRegistry registry, uint itemHandle, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            device, FlushContextInput.ForHandle(itemHandle), [], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }
}
