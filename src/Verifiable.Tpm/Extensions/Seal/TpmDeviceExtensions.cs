using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Cryptography.Context;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Extensions.Seal;

/// <summary>
/// Sealed-storage ("tie a secret to this computer") business-capability extensions for <see cref="TpmDevice"/>.
/// </summary>
/// <remarks>
/// <para>
/// These verbs compose the shipped <c>TPM2_Create</c>/<c>TPM2_Load</c>/<c>TPM2_Unseal</c>/<c>TPM2_FlushContext</c>
/// surface (TPM 2.0 Library Part 3, clauses 12.1, 12.2, 12.7, 28.4) into three business goals: seal a secret
/// under a loaded storage parent, recover it by password, and recover it under an already-satisfied policy
/// session. Every session (the parent's authorization, and — for the password arm — the sealed item's) is built
/// and disposed internally; a caller never hands in a pre-built session, matching the existing
/// <c>Extensions/DictionaryAttack</c> and <c>Extensions/Policy</c> verb groups. The one caller-visible session is
/// the POLICY session <see cref="TpmDeviceExtensions.UnsealUnderPolicyAsync"/> authorizes under, because enhanced
/// authorization is itself the user-facing model (the <c>Extensions/Policy</c> verb group starts and drives it).
/// </para>
/// <para>
/// <b>Width.</b> A sealed data object carries at most <see cref="Tpm2bSensitiveData.MaxSize"/>
/// (<c>MAX_SYM_DATA</c>, 128) octets (Part 2, clause 11.1.13, Table 169; clause 11.1.14, Table 170) — a real
/// TPM refuses <c>TPM2_Create</c> past it with <c>TPM_RC_SIZE</c>, and <see cref="SealAsync"/> refuses it
/// client-side before the wire. The envelope verbs (<c>SealEnvelopeAsync</c>, <c>UnsealEnvelopeAsync</c>,
/// <c>UnsealEnvelopeUnderPolicyAsync</c>) lift the bound for any secret: the TPM seals a 256-bit content key and
/// the secret rides under it through an AEAD (AES-256-GCM through the library's registered functions), with the
/// serialized sealed key as the additional authenticated data so the ciphertext opens only under exactly the
/// sealed object it was bound to. An AEAD authentication failure — a tampered ciphertext, a grafted sealed key,
/// or an unsealed object that is not a content key — surfaces as the <see cref="CryptographicException"/> the
/// AEAD delegates contract; a TPM refusal rides the returned <see cref="TpmResult{T}"/> as for every other verb.
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
        /// <param name="data">The secret to seal — at most <see cref="Tpm2bSensitiveData.MaxSize"/> octets (see the type's width remarks); a wider secret takes the envelope verbs.</param>
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

        /// <summary>
        /// Seals <paramref name="data"/> of any width under the loaded storage parent at
        /// <paramref name="parentHandle"/> as an envelope: the TPM seals a fresh 256-bit content-encryption key
        /// (composing <see cref="SealAsync"/>), and the data rides under that key through
        /// <paramref name="aeadEncrypt"/> with the serialized sealed key as the additional authenticated data,
        /// so the ciphertext is bound to exactly the sealed object that opens it.
        /// </summary>
        /// <remarks>
        /// This is the verb for a secret that may exceed <see cref="Tpm2bSensitiveData.MaxSize"/> octets (see the
        /// type's width remarks); <see cref="SealAsync"/> stays the verb for a secret known to fit. The content key
        /// is drawn through the registered entropy seam (<see cref="CryptographicKeyEvents.GenerateNonce"/>).
        /// </remarks>
        /// <param name="parentHandle">The loaded storage-parent handle (see the type's parent-constraint remarks).</param>
        /// <param name="parentAuth">The parent's authorization value, or empty when the parent has no auth set.</param>
        /// <param name="data">The secret to protect, of any width.</param>
        /// <param name="sealAuth">
        /// The authorization value the sealed content key's <c>userAuth</c> is set to, or empty for none. This is
        /// the value a later <c>UnsealEnvelopeAsync</c> call must supply.
        /// </param>
        /// <param name="aeadEncrypt">The authenticated-encryption function the data is protected with under the content key.</param>
        /// <param name="authPolicy">
        /// The authorization policy digest to bind the sealed content key to (for example a <c>TPM2_PolicyPCR</c>
        /// digest computed under <see cref="SealHashAlgorithm"/>), or empty (default) for no policy gate.
        /// </param>
        /// <param name="noDa">
        /// When <see langword="true"/>, authorization failures against the sealed content key never advance the
        /// dictionary-attack lockout counter; defaults to <see langword="false"/> exactly as <see cref="SealAsync"/>'s does.
        /// </param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result containing the envelope to persist, or the TPM's refusal of the content key's seal.</returns>
        public ValueTask<TpmResult<TpmSealedEnvelope>> SealEnvelopeAsync(
            uint parentHandle,
            ReadOnlyMemory<byte> parentAuth,
            ReadOnlyMemory<byte> data,
            ReadOnlyMemory<byte> sealAuth,
            AeadEncryptDelegate aeadEncrypt,
            ReadOnlyMemory<byte> authPolicy = default,
            bool noDa = false,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);
            ArgumentNullException.ThrowIfNull(aeadEncrypt);

            return SealEnvelopeCoreAsync(device, parentHandle, parentAuth, data, sealAuth, aeadEncrypt, authPolicy, noDa, cancellationToken);
        }

        /// <summary>
        /// Seals <paramref name="data"/> of any width as an envelope exactly as
        /// <see cref="SealEnvelopeAsync(uint, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, AeadEncryptDelegate, ReadOnlyMemory{byte}, bool, CancellationToken)"/>
        /// does, resolving the authenticated-encryption function from the registered key-agreement functions
        /// (<see cref="CryptoAlgorithm.Aes256"/> / <see cref="Purpose.Encryption"/>: AES-256-GCM).
        /// </summary>
        /// <param name="parentHandle">The loaded storage-parent handle (see the type's parent-constraint remarks).</param>
        /// <param name="parentAuth">The parent's authorization value, or empty when the parent has no auth set.</param>
        /// <param name="data">The secret to protect, of any width.</param>
        /// <param name="sealAuth">The authorization value the sealed content key's <c>userAuth</c> is set to, or empty for none.</param>
        /// <param name="authPolicy">The authorization policy digest to bind the sealed content key to, or empty (default) for no policy gate.</param>
        /// <param name="noDa">When <see langword="true"/>, authorization failures against the sealed content key never advance the dictionary-attack lockout counter.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result containing the envelope to persist, or the TPM's refusal of the content key's seal.</returns>
        public ValueTask<TpmResult<TpmSealedEnvelope>> SealEnvelopeAsync(
            uint parentHandle,
            ReadOnlyMemory<byte> parentAuth,
            ReadOnlyMemory<byte> data,
            ReadOnlyMemory<byte> sealAuth,
            ReadOnlyMemory<byte> authPolicy = default,
            bool noDa = false,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return device.SealEnvelopeAsync(parentHandle, parentAuth, data, sealAuth, ResolveEnvelopeEncrypt(), authPolicy, noDa, cancellationToken);
        }

        /// <summary>
        /// Recovers the data sealed in <paramref name="envelope"/> by password: unseals the content key
        /// (composing <see cref="UnsealAsync"/>) and authenticates and decrypts the data under it through
        /// <paramref name="aeadDecrypt"/>, bound to the sealed key exactly as it was sealed.
        /// </summary>
        /// <param name="parentHandle">The loaded storage-parent handle that wrapped the envelope's content key.</param>
        /// <param name="parentAuth">The parent's authorization value, or empty when the parent has no auth set.</param>
        /// <param name="envelope">The envelope a prior <c>SealEnvelopeAsync</c> produced.</param>
        /// <param name="sealAuth">The sealed content key's authorization value supplied at seal time, or empty for none.</param>
        /// <param name="aeadDecrypt">The authenticated-decryption function the data is recovered with under the content key.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result containing the recovered data (dispose it to release the plaintext), or the TPM's refusal of the unseal.</returns>
        /// <exception cref="CryptographicException">The envelope's sealed object is not a 256-bit content key, or the ciphertext failed authentication under it.</exception>
        public ValueTask<TpmResult<DecryptedContent>> UnsealEnvelopeAsync(
            uint parentHandle,
            ReadOnlyMemory<byte> parentAuth,
            TpmSealedEnvelope envelope,
            ReadOnlyMemory<byte> sealAuth,
            AeadDecryptDelegate aeadDecrypt,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);
            ArgumentNullException.ThrowIfNull(envelope);
            ArgumentNullException.ThrowIfNull(aeadDecrypt);

            return UnsealEnvelopeCoreAsync(device, parentHandle, parentAuth, envelope, sealAuth, aeadDecrypt, cancellationToken);
        }

        /// <summary>
        /// Recovers the data sealed in <paramref name="envelope"/> by password exactly as
        /// <see cref="UnsealEnvelopeAsync(uint, ReadOnlyMemory{byte}, TpmSealedEnvelope, ReadOnlyMemory{byte}, AeadDecryptDelegate, CancellationToken)"/>
        /// does, resolving the authenticated-decryption function from the registered key-agreement functions
        /// (<see cref="CryptoAlgorithm.Aes256"/> / <see cref="Purpose.Encryption"/>: AES-256-GCM).
        /// </summary>
        /// <param name="parentHandle">The loaded storage-parent handle that wrapped the envelope's content key.</param>
        /// <param name="parentAuth">The parent's authorization value, or empty when the parent has no auth set.</param>
        /// <param name="envelope">The envelope a prior <c>SealEnvelopeAsync</c> produced.</param>
        /// <param name="sealAuth">The sealed content key's authorization value supplied at seal time, or empty for none.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result containing the recovered data (dispose it to release the plaintext), or the TPM's refusal of the unseal.</returns>
        /// <exception cref="CryptographicException">The envelope's sealed object is not a 256-bit content key, or the ciphertext failed authentication under it.</exception>
        public ValueTask<TpmResult<DecryptedContent>> UnsealEnvelopeAsync(
            uint parentHandle,
            ReadOnlyMemory<byte> parentAuth,
            TpmSealedEnvelope envelope,
            ReadOnlyMemory<byte> sealAuth,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return device.UnsealEnvelopeAsync(parentHandle, parentAuth, envelope, sealAuth, ResolveEnvelopeDecrypt(), cancellationToken);
        }

        /// <summary>
        /// Recovers the data sealed in <paramref name="envelope"/> under an already-satisfied policy session:
        /// unseals the content key (composing <see cref="UnsealUnderPolicyAsync"/>) and authenticates and decrypts
        /// the data under it through <paramref name="aeadDecrypt"/>, bound to the sealed key exactly as it was
        /// sealed. The policy session is caller-visible and caller-owned exactly as for
        /// <see cref="UnsealUnderPolicyAsync"/>.
        /// </summary>
        /// <param name="parentHandle">The loaded storage-parent handle that wrapped the envelope's content key.</param>
        /// <param name="parentAuth">The parent's authorization value, or empty when the parent has no auth set.</param>
        /// <param name="envelope">The envelope a prior <c>SealEnvelopeAsync</c> produced.</param>
        /// <param name="policySession">The handle of a policy session whose accumulated policyDigest matches the sealed content key's authPolicy under <see cref="SealHashAlgorithm"/>.</param>
        /// <param name="aeadDecrypt">The authenticated-decryption function the data is recovered with under the content key.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result containing the recovered data (dispose it to release the plaintext), or the TPM's refusal of the unseal — for example <c>TPM_RC_POLICY_FAIL</c> when the session's policyDigest does not match.</returns>
        /// <exception cref="CryptographicException">The envelope's sealed object is not a 256-bit content key, or the ciphertext failed authentication under it.</exception>
        public ValueTask<TpmResult<DecryptedContent>> UnsealEnvelopeUnderPolicyAsync(
            uint parentHandle,
            ReadOnlyMemory<byte> parentAuth,
            TpmSealedEnvelope envelope,
            uint policySession,
            AeadDecryptDelegate aeadDecrypt,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);
            ArgumentNullException.ThrowIfNull(envelope);
            ArgumentNullException.ThrowIfNull(aeadDecrypt);

            return UnsealEnvelopeUnderPolicyCoreAsync(device, parentHandle, parentAuth, envelope, policySession, aeadDecrypt, cancellationToken);
        }

        /// <summary>
        /// Recovers the data sealed in <paramref name="envelope"/> under an already-satisfied policy session
        /// exactly as
        /// <see cref="UnsealEnvelopeUnderPolicyAsync(uint, ReadOnlyMemory{byte}, TpmSealedEnvelope, uint, AeadDecryptDelegate, CancellationToken)"/>
        /// does, resolving the authenticated-decryption function from the registered key-agreement functions
        /// (<see cref="CryptoAlgorithm.Aes256"/> / <see cref="Purpose.Encryption"/>: AES-256-GCM).
        /// </summary>
        /// <param name="parentHandle">The loaded storage-parent handle that wrapped the envelope's content key.</param>
        /// <param name="parentAuth">The parent's authorization value, or empty when the parent has no auth set.</param>
        /// <param name="envelope">The envelope a prior <c>SealEnvelopeAsync</c> produced.</param>
        /// <param name="policySession">The handle of a policy session whose accumulated policyDigest matches the sealed content key's authPolicy under <see cref="SealHashAlgorithm"/>.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result containing the recovered data (dispose it to release the plaintext), or the TPM's refusal of the unseal.</returns>
        /// <exception cref="CryptographicException">The envelope's sealed object is not a 256-bit content key, or the ciphertext failed authentication under it.</exception>
        public ValueTask<TpmResult<DecryptedContent>> UnsealEnvelopeUnderPolicyAsync(
            uint parentHandle,
            ReadOnlyMemory<byte> parentAuth,
            TpmSealedEnvelope envelope,
            uint policySession,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return device.UnsealEnvelopeUnderPolicyAsync(parentHandle, parentAuth, envelope, policySession, ResolveEnvelopeDecrypt(), cancellationToken);
        }
    }

    /// <summary>The width of the content-encryption key the envelope verbs seal: AES-256.</summary>
    private const int EnvelopeContentKeyLength = 32;

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
        BaseMemoryPool pool = device.Pool;
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
        BaseMemoryPool pool = device.Pool;
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
        BaseMemoryPool pool = device.Pool;
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
            using TpmPolicySession authorizingSession = TpmPolicySession.ForSession(policySession, SealHashAlgorithm, device.Rng, pool);
            UnsealInput unsealInput = UnsealInput.ForItem(loaded.ObjectHandle);

            //The policy session's HashAlgorithm is not TPM_ALG_NULL, so the executor computes a cpHash for it
            //regardless of the session carrying no HMAC key of its own (Part 1, clause 16.6) — the loaded item's
            //Name must therefore be supplied (Part 1, clause 15.7, equation 15), exactly as the PCR-seal flow tests do.
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
    /// The seal half of the envelope composition: draws the content key, seals it through
    /// <see cref="SealCoreAsync"/>, and encrypts the data under it with the serialized sealed key as the
    /// additional authenticated data.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="parentHandle">The loaded storage-parent handle.</param>
    /// <param name="parentAuth">The parent's authorization value.</param>
    /// <param name="data">The secret to protect.</param>
    /// <param name="sealAuth">The authorization value the sealed content key's <c>userAuth</c> is set to.</param>
    /// <param name="aeadEncrypt">The authenticated-encryption function.</param>
    /// <param name="authPolicy">The authorization policy digest to bind the sealed content key to, or empty.</param>
    /// <param name="noDa">Whether the sealed content key is exempt from dictionary-attack protection.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>A result containing the envelope, or the TPM's refusal of the content key's seal.</returns>
    [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the sealed content key and of the AEAD result's carriers transfers to the TpmSealedEnvelope inside the TpmResult returned to the caller, who disposes it; the catch releases the sealed key when the encryption faults before the envelope adopts it.")]
    private static async ValueTask<TpmResult<TpmSealedEnvelope>> SealEnvelopeCoreAsync(
        TpmDevice device,
        uint parentHandle,
        ReadOnlyMemory<byte> parentAuth,
        ReadOnlyMemory<byte> data,
        ReadOnlyMemory<byte> sealAuth,
        AeadEncryptDelegate aeadEncrypt,
        ReadOnlyMemory<byte> authPolicy,
        bool noDa,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = device.Pool;

        using SymmetricKeyMemory contentKey = DrawEnvelopeContentKey(pool);
        TpmResult<TpmSealedBlob> sealResult = await SealCoreAsync(
            device, parentHandle, parentAuth, contentKey.AsReadOnlyMemory(), sealAuth, authPolicy, noDa, cancellationToken).ConfigureAwait(false);

        if(!sealResult.IsSuccess)
        {
            return sealResult.Map<TpmSealedEnvelope>(_ => null!);
        }

        TpmSealedBlob sealedKey = sealResult.Value;
        try
        {
            using AdditionalData sealedKeyOctets = TpmSealedEnvelope.SerializeAsAdditionalData(sealedKey, pool);
            AeadEncryptResult encrypted = await aeadEncrypt(data, contentKey, sealedKeyOctets, pool, cancellationToken).ConfigureAwait(false);

            return TpmResult<TpmSealedEnvelope>.Success(TpmSealedEnvelope.FromEncryption(sealedKey, encrypted));
        }
        catch
        {
            sealedKey.Dispose();
            throw;
        }
    }

    /// <summary>
    /// The password half of the envelope composition: unseals the content key through
    /// <see cref="UnsealCoreAsync"/> and opens the envelope under it.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="parentHandle">The loaded storage-parent handle.</param>
    /// <param name="parentAuth">The parent's authorization value.</param>
    /// <param name="envelope">The envelope to open.</param>
    /// <param name="sealAuth">The sealed content key's authorization value.</param>
    /// <param name="aeadDecrypt">The authenticated-decryption function.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>A result containing the recovered data, or the TPM's refusal of the unseal.</returns>
    private static async ValueTask<TpmResult<DecryptedContent>> UnsealEnvelopeCoreAsync(
        TpmDevice device,
        uint parentHandle,
        ReadOnlyMemory<byte> parentAuth,
        TpmSealedEnvelope envelope,
        ReadOnlyMemory<byte> sealAuth,
        AeadDecryptDelegate aeadDecrypt,
        CancellationToken cancellationToken)
    {
        TpmResult<UnsealResponse> unsealResult = await UnsealCoreAsync(
            device, parentHandle, parentAuth, envelope.SealedKey, sealAuth, cancellationToken).ConfigureAwait(false);

        return await OpenEnvelopeAsync(envelope, unsealResult, aeadDecrypt, device.Pool, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// The policy half of the envelope composition: unseals the content key through
    /// <see cref="UnsealUnderPolicyCoreAsync"/> and opens the envelope under it.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="parentHandle">The loaded storage-parent handle.</param>
    /// <param name="parentAuth">The parent's authorization value.</param>
    /// <param name="envelope">The envelope to open.</param>
    /// <param name="policySession">The satisfied policy session's handle.</param>
    /// <param name="aeadDecrypt">The authenticated-decryption function.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>A result containing the recovered data, or the TPM's refusal of the unseal.</returns>
    private static async ValueTask<TpmResult<DecryptedContent>> UnsealEnvelopeUnderPolicyCoreAsync(
        TpmDevice device,
        uint parentHandle,
        ReadOnlyMemory<byte> parentAuth,
        TpmSealedEnvelope envelope,
        uint policySession,
        AeadDecryptDelegate aeadDecrypt,
        CancellationToken cancellationToken)
    {
        TpmResult<UnsealResponse> unsealResult = await UnsealUnderPolicyCoreAsync(
            device, parentHandle, parentAuth, envelope.SealedKey, policySession, cancellationToken).ConfigureAwait(false);

        return await OpenEnvelopeAsync(envelope, unsealResult, aeadDecrypt, device.Pool, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Opens an envelope once its content key has been unsealed: refuses an unsealed object that is not a
    /// content key, re-derives the additional authenticated data from the envelope's own sealed key, and
    /// authenticates and decrypts the ciphertext under the key — the tail shared by the password and policy arms.
    /// </summary>
    /// <param name="envelope">The envelope to open.</param>
    /// <param name="unsealResult">The unseal of the envelope's content key.</param>
    /// <param name="aeadDecrypt">The authenticated-decryption function.</param>
    /// <param name="cancellationToken">A token observed across the decryption.</param>
    /// <returns>A result containing the recovered data, or the unseal's own refusal.</returns>
    /// <exception cref="CryptographicException">The unsealed object is not a 256-bit content key, or the ciphertext failed authentication.</exception>
    [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the recovered plaintext transfers to the TpmResult<DecryptedContent> returned to the caller, who disposes it.")]
    private static async ValueTask<TpmResult<DecryptedContent>> OpenEnvelopeAsync(
        TpmSealedEnvelope envelope, TpmResult<UnsealResponse> unsealResult, AeadDecryptDelegate aeadDecrypt, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        if(!unsealResult.IsSuccess)
        {
            return unsealResult.Map<DecryptedContent>(_ => null!);
        }

        using UnsealResponse unsealed = unsealResult.Value;
        using SymmetricKeyMemory contentKey = CarryEnvelopeContentKey(unsealed.OutData.AsReadOnlySpan(), pool);
        using AdditionalData sealedKeyOctets = envelope.SerializeSealedKeyAsAdditionalData(pool);

        DecryptedContent plaintext = await aeadDecrypt(
            envelope.Ciphertext, contentKey, envelope.Iv, envelope.Tag, sealedKeyOctets, pool, cancellationToken).ConfigureAwait(false);

        return TpmResult<DecryptedContent>.Success(plaintext);
    }

    /// <summary>
    /// Draws a fresh 256-bit content-encryption key through the registered entropy seam
    /// (<see cref="CryptographicKeyEvents.GenerateNonce"/>, the one consumer-facing choke point for random
    /// octets; the draw is re-carried as a key the moment it lands), pinned so it never moves.
    /// </summary>
    /// <param name="pool">The memory pool the key is rented from.</param>
    /// <returns>The content key; the caller owns and disposes it.</returns>
    [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the pinned key storage transfers to the returned SymmetricKeyMemory, which the caller disposes.")]
    private static SymmetricKeyMemory DrawEnvelopeContentKey(BaseMemoryPool pool)
    {
        using Nonce entropy = CryptographicKeyEvents.GenerateNonce(EnvelopeContentKeyLength, CryptoTags.AesGcmCek, pool);
        IMemoryOwner<byte> keyOwner = pool.Rent(EnvelopeContentKeyLength, AllocationKind.Pinned);
        entropy.AsReadOnlySpan().CopyTo(keyOwner.Memory.Span);

        return new SymmetricKeyMemory(keyOwner, CryptoTags.AesGcmCek);
    }

    /// <summary>
    /// Re-carries the unsealed content key octets as a pinned <see cref="SymmetricKeyMemory"/>, refusing any
    /// width other than <see cref="EnvelopeContentKeyLength"/> — an envelope whose sealed object is not a
    /// content key (a grafted foreign sealed object) never reaches the decrypt, and fails on the same channel
    /// a failed authentication does.
    /// </summary>
    /// <param name="unsealedKey">The octets <c>TPM2_Unseal</c> returned.</param>
    /// <param name="pool">The memory pool the key is rented from.</param>
    /// <returns>The content key; the caller owns and disposes it.</returns>
    /// <exception cref="CryptographicException">The unsealed value is not <see cref="EnvelopeContentKeyLength"/> octets wide.</exception>
    [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the pinned key storage transfers to the returned SymmetricKeyMemory, which the caller disposes.")]
    private static SymmetricKeyMemory CarryEnvelopeContentKey(ReadOnlySpan<byte> unsealedKey, BaseMemoryPool pool)
    {
        if(unsealedKey.Length != EnvelopeContentKeyLength)
        {
            throw new CryptographicException($"The envelope's sealed object is {unsealedKey.Length} octets wide, not a {EnvelopeContentKeyLength}-octet content key.");
        }

        IMemoryOwner<byte> keyOwner = pool.Rent(EnvelopeContentKeyLength, AllocationKind.Pinned);
        unsealedKey.CopyTo(keyOwner.Memory.Span);

        return new SymmetricKeyMemory(keyOwner, CryptoTags.AesGcmCek);
    }

    /// <summary>Resolves the envelope's authenticated-encryption function from the registered key-agreement functions.</summary>
    /// <returns>The AES-256-GCM encryption function the application registered.</returns>
    private static AeadEncryptDelegate ResolveEnvelopeEncrypt() =>
        KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveAeadEncrypt(CryptoAlgorithm.Aes256, Purpose.Encryption);

    /// <summary>Resolves the envelope's authenticated-decryption function from the registered key-agreement functions.</summary>
    /// <returns>The AES-256-GCM decryption function the application registered.</returns>
    private static AeadDecryptDelegate ResolveEnvelopeDecrypt() =>
        KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveAeadDecrypt(CryptoAlgorithm.Aes256, Purpose.Encryption);

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
        TpmDevice device, TpmResponseRegistry registry, uint itemHandle, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            device, FlushContextInput.ForHandle(itemHandle), [], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }
}
