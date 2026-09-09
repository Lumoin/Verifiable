using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Hierarchy;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;
using Verifiable.Tests.TestInfrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// One green persistent-handle case per routed command family that
/// <see cref="TpmInHouseSimulatorPersistentObjectFamilyTests"/> does not already cover — Encapsulate/Decapsulate's
/// <c>keyHandle</c>, PolicySigned's <c>authObject</c>, Load's/Duplicate's/Import's parent slots, Duplicate's
/// <c>objectHandle</c>, GetSessionAuditDigest's and NV_Certify's <c>signHandle</c>, the sequence-start/complete
/// slots, ActivateCredential's <c>activateHandle</c>, and HMAC's/HMAC_Start's <c>handle</c>. A persistent object
/// is used IN PLACE at whatever slot a command names: "The handles in this set are used to refer to either
/// transient or persistent object"
/// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
/// Specification</see>, Part 2, clause 9.3, Table 49; Part 3, clause 5.4, item 2). Each test constructs its own
/// simulator, device and registry, drives the production command path (<see cref="TpmCommandExecutor"/> with the
/// real inputs and response codecs), and persists through <see cref="TpmEvictControlHarness.EvictControlAsync"/>;
/// the Load/Duplicate/Import/HMAC/HMAC_Start slots ride <see cref="HmacKeyHarness"/>'s KEYEDHASH object plumbing.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorPersistentSlotCoverageTests
{
    /// <summary>The number of bytes in a NIST P-256 coordinate or in an ECDSA r/s component.</summary>
    private const int P256ComponentSize = 32;

    /// <summary>The session/name hash algorithm used throughout.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The persistent handle the KEM key Encapsulate/Decapsulate test persists to.</summary>
    private const uint EncapsulateDecapsulateKemKeyPersistentHandle = 0x8100_0600;

    /// <summary>The persistent handle the PolicySigned authority test persists its authObject to.</summary>
    private const uint PolicySignedAuthorityPersistentHandle = 0x8100_0601;

    /// <summary>The persistent handle the Load test persists its storage parent to.</summary>
    private const uint LoadParentPersistentHandle = 0x8100_0602;

    /// <summary>The persistent handle the Duplicate newParentHandle test persists its new parent to.</summary>
    private const uint DuplicateNewParentPersistentHandle = 0x8100_0603;

    /// <summary>The persistent handle the Duplicate objectHandle/ATTRIBUTES test persists its asymmetric key to.</summary>
    private const uint DuplicateObjectAttributesPersistentHandle = 0x8100_0604;

    /// <summary>The persistent handle the Import test persists its destination parent to.</summary>
    private const uint ImportParentPersistentHandle = 0x8100_0605;

    /// <summary>The persistent handle the GetSessionAuditDigest test persists its signer to.</summary>
    private const uint GetSessionAuditDigestSignerPersistentHandle = 0x8100_0606;

    /// <summary>The persistent handle the NV_Certify test persists its signer to.</summary>
    private const uint NvCertifySignerPersistentHandle = 0x8100_0607;

    /// <summary>The persistent handle the SignSequenceStart test persists its signer to.</summary>
    private const uint SignSequenceStartKeyPersistentHandle = 0x8100_0608;

    /// <summary>The persistent handle the VerifySequenceStart test persists its key to.</summary>
    private const uint VerifySequenceStartKeyPersistentHandle = 0x8100_0609;

    /// <summary>The persistent handle the ActivateCredential test persists its activateHandle (attest key) to.</summary>
    private const uint ActivateCredentialActivateHandlePersistentHandle = 0x8100_060A;

    /// <summary>The persistent handle the HMAC TYPE test persists its asymmetric key to.</summary>
    private const uint HmacPersistentHandle = 0x8100_060B;

    /// <summary>The persistent handle the HMAC_Start TYPE test persists its asymmetric key to.</summary>
    private const uint HmacStartPersistentHandle = 0x8100_060C;

    /// <summary>The NV Index handle the NV_Certify test defines and writes.</summary>
    private const uint NvCertifyIndexHandle = 0x0100_0F00;

    /// <summary>The Index attributes the NV_Certify test's Index is defined with — caller-authorized and dictionary-attack exempt.</summary>
    private const TpmaNv NvCertifyIndexAttributes = TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_NO_DA;

    /// <summary>The authorization value the NV_Certify test's Index is defined with.</summary>
    private static byte[] NvCertifyIndexAuth { get; } = [0x51, 0x52, 0x53, 0x54];

    /// <summary>The octets the NV_Certify test writes to its Index before certifying them.</summary>
    private static byte[] NvCertifyWrittenData { get; } = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];

    /// <summary>The fixed caller nonce the GetSessionAuditDigest test echoes into its attestation's extraData.</summary>
    private static byte[] AuditQualifyingData { get; } = "Persistent-slot audit nonce."u8.ToArray();

    /// <summary>The fixed caller nonce the NV_Certify test echoes into its attestation's extraData.</summary>
    private static byte[] NvCertifyNonce { get; } = "Persistent-slot NV_Certify nonce."u8.ToArray();

    /// <summary>The secret a MakeCredential/ActivateCredential round trip wraps and recovers.</summary>
    private static byte[] CredentialSecret { get; } =
        [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// A persisted ECC KEM key's own persistent handle admits both <c>TPM2_Encapsulate()</c>'s and
    /// <c>TPM2_Decapsulate()</c>'s <c>keyHandle</c>: an Encapsulate over the persistent handle followed by a
    /// Decapsulate of the resulting ciphertext over the SAME persistent handle recovers the identical shared
    /// secret (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clauses 14.10/14.11).
    /// </summary>
    [TestMethod]
    public async Task EncapsulateOverAPersistentKeyHandleDecapsulatesToTheSameSharedSecret()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, nameof(EncapsulateOverAPersistentKeyHandleDecapsulatesToTheSameSharedSecret)).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput kemInput = CreatePrimaryInput.ForEccKemKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmAlgIdConstants.TPM_ALG_SHA256, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, kemInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (ECC KEM key) failed: '{primaryResult.ResponseCode}'.");
        using CreatePrimaryResponse primary = primaryResult.Value;

        TpmResult<EvictControlResponse> persistResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, primary.ObjectHandle.Value, EncapsulateDecapsulateKemKeyPersistentHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(persistResult.IsSuccess, $"EvictControl (persist) failed: '{persistResult.ResponseCode}'.");

        TpmResult<FlushContextResponse> flushResult = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(primary.ObjectHandle.Value), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(flushResult.IsSuccess, $"Flushing the transient copy failed: '{flushResult.ResponseCode}'.");

        var persistedHandle = TpmiDhObject.FromValue(EncapsulateDecapsulateKemKeyPersistentHandle);
        EncapsulateInput encapsulateInput = EncapsulateInput.ForHandle(persistedHandle);
        TpmResult<EncapsulateResponse> encapsulateResult = await TpmCommandExecutor.ExecuteAsync<EncapsulateResponse>(
            tpm, encapsulateInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(encapsulateResult.IsSuccess, $"TPM2_Encapsulate() over a persistent keyHandle must succeed: '{encapsulateResult.ResponseCode}'.");
        using EncapsulateResponse encapsulated = encapsulateResult.Value;

        byte[] ciphertextBytes = encapsulated.Ciphertext.Ciphertext.ToArray();
        using DecapsulateInput decapsulateInput = DecapsulateInput.Create(persistedHandle, ciphertextBytes, pool);
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<DecapsulateResponse> decapsulateResult = await TpmCommandExecutor.ExecuteAsync<DecapsulateResponse>(
            tpm, decapsulateInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(decapsulateResult.IsSuccess, $"TPM2_Decapsulate() over the SAME persistent keyHandle must succeed: '{decapsulateResult.ResponseCode}'.");
        using DecapsulateResponse decapsulated = decapsulateResult.Value;

        Assert.AreSequenceEqual(
            encapsulated.SharedSecret.AsReadOnlySpan().ToArray(), decapsulated.SharedSecret.AsReadOnlySpan().ToArray(),
            "Encapsulating and then decapsulating over the same persistent handle must recover the identical shared secret.");
    }

    /// <summary>
    /// A persisted ECC authority key satisfies <c>TPM2_PolicySigned()</c> over its persistent
    /// <c>authObject</c> handle exactly as a transient one does; once the owner hierarchy is disabled, the SAME
    /// handle answers <c>TPM_RC_HANDLE</c> naming authObject, handle 1 of Table 144: a persistent object under a
    /// disabled hierarchy is not found, so the caller-supplied signature is never examined.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 9.3, Table 49; Part 3, clause 23.3; Part 3, clause 24.2.1</see>.
    /// </summary>
    [TestMethod]
    public async Task PolicySignedOverAPersistentAuthObjectSucceedsThenAnswersHandleUnderADisabledOwnerHierarchy()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, nameof(PolicySignedOverAPersistentAuthObjectSucceedsThenAnswersHandleUnderADisabledOwnerHierarchy)).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput authorityInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> authorityResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, authorityInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(authorityResult.IsSuccess, $"CreatePrimary (PolicySigned authority) failed: '{authorityResult.ResponseCode}'.");
        using CreatePrimaryResponse authority = authorityResult.Value;

        TpmResult<EvictControlResponse> persistResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, authority.ObjectHandle.Value, PolicySignedAuthorityPersistentHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(persistResult.IsSuccess, $"EvictControl (persist) failed: '{persistResult.ResponseCode}'.");

        byte[] policyRef = "persistent-authobject-ref"u8.ToArray();
        var authorityHandle = TpmiDhObject.FromValue(PolicySignedAuthorityPersistentHandle);

        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
            SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");

        uint policyHandle;
        byte[] nonceTpm;
        using(StartAuthSessionResponse session = startResult.Value)
        {
            policyHandle = session.SessionHandle.Value;
            Assert.IsFalse(session.NonceTPM.IsEmpty, "A policy session's nonceTPM must be a real, non-placeholder value.");
            nonceTpm = session.NonceTPM.AsReadOnlySpan().ToArray();
        }

        try
        {
            byte[] aHash = await ComputeAHashAsync(nonceTpm, 0, ReadOnlyMemory<byte>.Empty, policyRef, pool, TestContext.CancellationToken).ConfigureAwait(false);

            using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
            using SignInput signInput = SignInput.ForEcdsa(authorityHandle, aHash, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
                tpm, signInput, [signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(signResult.IsSuccess, $"TPM2_Sign() over the persistent authority handle failed: '{signResult.ResponseCode}'.");
            using SignResponse signature = signResult.Value;
            byte[] p1363Signature = ConcatenateP1363(signature.Signature.SignatureR!.AsReadOnlySpan(), signature.Signature.SignatureS!.AsReadOnlySpan());

            TpmResult<PolicySignedResponse> policySignedResult = await tpm.PolicySignedAsync(
                PolicySignedAuthorityPersistentHandle, policyHandle, nonceTpm, ReadOnlyMemory<byte>.Empty, policyRef, 0, p1363Signature,
                TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(
                policySignedResult.IsSuccess,
                $"TPM2_PolicySigned() over a persisted authObject must succeed: '{policySignedResult.ResponseCode}'.");
            policySignedResult.Value.Dispose();

            TpmResult<HierarchyControlResponse> disableResult = await tpm.DisableHierarchyWithPasswordAsync(
                TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, TpmRh.TPM_RH_OWNER, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(disableResult.IsSuccess, $"Disabling the owner hierarchy failed: '{disableResult.ResponseCode}'.");

            byte[] placeholderSignature = new byte[2 * P256ComponentSize];
            TpmResult<PolicySignedResponse> disabledResult = await tpm.PolicySignedAsync(
                PolicySignedAuthorityPersistentHandle, policyHandle, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, policyRef, 0, placeholderSignature,
                TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), disabledResult.ResponseCode,
                "A persistent entity under a disabled hierarchy resolves to nothing at PolicySigned's authObject slot (TPM 2.0 Library Part 3, clause 24.2.1), reached before the signature is ever inspected.");
        }
        finally
        {
            _ = await tpm.FlushContextAsync(policyHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A child created under a TRANSIENT storage parent loads under that parent's PERSISTENT handle once the
    /// transient copy is flushed: <c>TPM2_Load()</c>'s <c>parentHandle</c> slot (<c>TPMI_DH_PARENT</c>) admits a
    /// persistent object exactly as <c>TPM2_Create()</c>'s does
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, clause 9.3, Table 49; clause 9.4, Table 50).
    /// </summary>
    [TestMethod]
    public async Task LoadOverAPersistedStorageParentSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(LoadOverAPersistedStorageParentSucceeds), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<CreateResponse> createResult = await HmacKeyHarness.CreateHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, keyBytes: ReadOnlyMemory<byte>.Empty, TpmAlgIdConstants.TPM_ALG_SHA256,
            isSensitiveDataOrigin: true, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"TPM2_Create() (child under the transient parent) failed: '{createResult.ResponseCode}'.");
        using CreateResponse created = createResult.Value;

        TpmResult<EvictControlResponse> persistResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, LoadParentPersistentHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(persistResult.IsSuccess, $"EvictControl (persist) failed: '{persistResult.ResponseCode}'.");

        TpmResult<FlushContextResponse> flushResult = await HmacKeyHarness.FlushAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(flushResult.IsSuccess, $"Flushing the transient parent copy failed: '{flushResult.ResponseCode}'.");

        TpmResult<LoadResponse> loadResult = await HmacKeyHarness.LoadAsync(
            tpm, registry, pool, LoadParentPersistentHandle, created.OutPrivate, created.OutPublic, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            loadResult.IsSuccess,
            $"TPM2_Load() of a child created under the transient parent, loaded under the persistent handle after the transient is flushed, must succeed: '{loadResult.ResponseCode}'.");
        loadResult.Value.Dispose();
    }

    /// <summary>
    /// A duplicable KEYEDHASH object exports to a PERSISTED new parent: <c>TPM2_Duplicate()</c>'s
    /// <c>newParentHandle</c> slot (<c>TPMI_DH_OBJECT+</c>) admits a persistent object exactly as
    /// <c>TPM2_Load()</c>'s <c>parentHandle</c> does
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, clause 9.3, Table 49; Part 3, clause 13.1).
    /// </summary>
    [TestMethod]
    public async Task DuplicateNewParentHandleOverAPersistedNewParentSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(DuplicateNewParentHandleOverAPersistedNewParentSucceeds), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse sourceParent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using Tpm2bDigest duplicationPolicy = HmacKeyHarness.DuplicationPolicyDigest(pool);
        byte[] duplicationPolicyBytes = duplicationPolicy.AsReadOnlySpan().ToArray();

        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, sourceParent.ObjectHandle.Value, keyBytes: ReadOnlyMemory<byte>.Empty, TpmAlgIdConstants.TPM_ALG_SHA256,
            userAuth: default, isNoDa: true, isUserWithAuth: true, isDuplicable: true, authPolicy: duplicationPolicyBytes,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using CreatePrimaryResponse newParent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] newParentName = newParent.Name.Span.ToArray();

        TpmResult<EvictControlResponse> persistResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, newParent.ObjectHandle.Value, DuplicateNewParentPersistentHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(persistResult.IsSuccess, $"EvictControl (persist) failed: '{persistResult.ResponseCode}'.");

        TpmResult<FlushContextResponse> flushResult = await HmacKeyHarness.FlushAsync(
            tpm, registry, pool, newParent.ObjectHandle.Value, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(flushResult.IsSuccess, $"Flushing the transient new-parent copy failed: '{flushResult.ResponseCode}'.");

        using DuplicateResponse duplicated = await HmacKeyHarness.DuplicateAsync(
            tpm, registry, pool, key.Handle, key.Name.Span.ToArray(), DuplicateNewParentPersistentHandle, newParentName, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(duplicated.Duplicate.IsEmpty, "TPM2_Duplicate() to a persistent newParentHandle must produce a duplication blob.");
    }

    /// <summary>
    /// <c>TPM2_Duplicate()</c> refuses an object whose <c>fixedParent</c> attribute is SET with
    /// <c>TPM_RC_ATTRIBUTES</c>; every key this simulator's templates build sets it, so a persisted key at
    /// <c>objectHandle</c> answers <c>TPM_RC_ATTRIBUTES</c> exactly as its transient twin does, never
    /// <c>TPM_RC_HANDLE</c> — the persistent object is found and refused on its attributes
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, clause 9.3, Table 49; Part 3, clause 13.1).
    /// </summary>
    [TestMethod]
    public async Task DuplicateObjectHandleOverAPersistedAsymmetricKeyReturnsAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(DuplicateObjectHandleOverAPersistedAsymmetricKeyReturnsAttributes), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<EvictControlResponse> persistResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, key.ObjectHandle.Value, DuplicateObjectAttributesPersistentHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(persistResult.IsSuccess, $"EvictControl (persist) failed: '{persistResult.ResponseCode}'.");

        TpmResult<FlushContextResponse> flushResult = await HmacKeyHarness.FlushAsync(
            tpm, registry, pool, key.ObjectHandle.Value, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(flushResult.IsSuccess, $"Flushing the transient copy failed: '{flushResult.ResponseCode}'.");

        DuplicateInput input = new(DuplicateObjectAttributesPersistentHandle, (uint)TpmRh.TPM_RH_NULL);
        using TpmPasswordSession objectAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<DuplicateResponse> result = await TpmCommandExecutor.ExecuteAsync<DuplicateResponse>(
            tpm, input, [objectAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 0), result.ResponseCode,
            "A persisted asymmetric key's fixedParent attribute is SET, exactly as its transient twin's is; TPM2_Duplicate()'s objectHandle must be refused with TPM_RC_ATTRIBUTES, never an undesignated TPM_RC_HANDLE.");
    }

    /// <summary>
    /// A duplicated KEYEDHASH object imports under a PERSISTED destination parent: <c>TPM2_Import()</c>'s
    /// <c>parentHandle</c> slot (<c>TPMI_DH_PARENT</c>) admits a persistent object exactly as
    /// <c>TPM2_Load()</c>'s and <c>TPM2_Duplicate()</c>'s <c>newParentHandle</c> do
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, clause 9.3, Table 49; Part 3, clause 13.3).
    /// </summary>
    [TestMethod]
    public async Task ImportOverAPersistedParentSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(ImportOverAPersistedParentSucceeds), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse sourceParent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using Tpm2bDigest duplicationPolicy = HmacKeyHarness.DuplicationPolicyDigest(pool);
        byte[] duplicationPolicyBytes = duplicationPolicy.AsReadOnlySpan().ToArray();

        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyWithPublicAsync(
            tpm, registry, pool, sourceParent.ObjectHandle.Value, keyBytes: ReadOnlyMemory<byte>.Empty, TpmAlgIdConstants.TPM_ALG_SHA256,
            userAuth: default, isNoDa: true, isUserWithAuth: true, isDuplicable: true, authPolicy: duplicationPolicyBytes,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using CreatePrimaryResponse destinationParent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] destinationName = destinationParent.Name.Span.ToArray();

        TpmResult<EvictControlResponse> persistResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, destinationParent.ObjectHandle.Value, ImportParentPersistentHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(persistResult.IsSuccess, $"EvictControl (persist) failed: '{persistResult.ResponseCode}'.");

        using DuplicateResponse duplicated = await HmacKeyHarness.DuplicateAsync(
            tpm, registry, pool, key.Handle, key.Name.Span.ToArray(), ImportParentPersistentHandle, destinationName, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<FlushContextResponse> flushResult = await HmacKeyHarness.FlushAsync(
            tpm, registry, pool, destinationParent.ObjectHandle.Value, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(flushResult.IsSuccess, $"Flushing the transient destination-parent copy failed: '{flushResult.ResponseCode}'.");

        TpmResult<ImportResponse> importResult = await HmacKeyHarness.ImportAsync(
            tpm, registry, pool, ImportParentPersistentHandle, key.PublicArea!, duplicated.Duplicate, duplicated.OutSymSeed, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            importResult.IsSuccess,
            $"TPM2_Import() @parentHandle over a persisted parent must succeed: '{importResult.ResponseCode}'.");
        importResult.Value.Dispose();
    }

    /// <summary>
    /// A persisted ECC signer attests an established audit session's digest over its persistent
    /// <c>signHandle</c>: <c>TPM2_GetSessionAuditDigest()</c>'s <c>signHandle</c> slot (<c>TPMI_DH_OBJECT</c>)
    /// admits a persistent object exactly as <c>TPM2_Sign()</c>'s <c>keyHandle</c> does
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, clause 9.3, Table 49; Part 3, clause 18.5.1).
    /// </summary>
    [TestMethod]
    public async Task GetSessionAuditDigestOverAPersistedSignerSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, nameof(GetSessionAuditDigestOverAPersistedSignerSucceeds)).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput signerInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_ENDORSEMENT, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> signerResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, signerInput, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signerResult.IsSuccess, $"CreatePrimary (GetSessionAuditDigest signer) failed: '{signerResult.ResponseCode}'.");
        using CreatePrimaryResponse signer = signerResult.Value;

        TpmResult<EvictControlResponse> persistResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, signer.ObjectHandle.Value, GetSessionAuditDigestSignerPersistentHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(persistResult.IsSuccess, $"EvictControl (persist) failed: '{persistResult.ResponseCode}'.");

        TpmResult<FlushContextResponse> flushResult = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(signer.ObjectHandle.Value), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(flushResult.IsSuccess, $"Flushing the transient copy failed: '{flushResult.ResponseCode}'.");

        (uint auditHandle, TpmSession auditSession) = await EstablishAuditSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            using(auditSession)
            using(TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool))
            using(TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool))
            using(GetSessionAuditDigestInput input = GetSessionAuditDigestInput.ForEcdsa(
                TpmiDhObject.FromValue(GetSessionAuditDigestSignerPersistentHandle), TpmiShHmac.FromValue(auditHandle), AuditQualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, pool))
            {
                TpmResult<GetSessionAuditDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                    tpm, input, [privacyAdminAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(
                    result.IsSuccess,
                    $"TPM2_GetSessionAuditDigest() over a persisted signer must succeed: '{result.ResponseCode}'.");

                using GetSessionAuditDigestResponse response = result.Value;
                Assert.AreEqual(
                    TpmStConstants.TPM_ST_ATTEST_SESSION_AUDIT, response.AuditInfo.AttestationData.Type,
                    "The attestation type must be TPM_ST_ATTEST_SESSION_AUDIT.");
            }
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(auditHandle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A persisted ECC signer certifies an NV Index's contents over its persistent <c>signHandle</c>:
    /// <c>TPM2_NV_Certify()</c>'s <c>signHandle</c> slot (<c>TPMI_DH_OBJECT</c>) admits a persistent object
    /// exactly as <c>TPM2_Sign()</c>'s <c>keyHandle</c> does
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, clause 9.3, Table 49; Part 3, clause 31.16).
    /// </summary>
    [TestMethod]
    public async Task NvCertifyOverAPersistedSignerSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, nameof(NvCertifyOverAPersistedSignerSucceeds)).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        using Tpm2bAuth indexAuth = Tpm2bAuth.Create(NvCertifyIndexAuth, pool);
        using Tpm2bDigest emptyPolicy = Tpm2bDigest.Create(ReadOnlySpan<byte>.Empty, pool);
        using var publicInfo = new TpmsNvPublic(NvCertifyIndexHandle, TpmAlgIdConstants.TPM_ALG_SHA256, NvCertifyIndexAttributes, emptyPolicy, (ushort)NvCertifyWrittenData.Length);
        using var defineInput = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, indexAuth, publicInfo);
        TpmResult<NvDefineSpaceResponse> defineResult = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            tpm, defineInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"NV_DefineSpace failed: '{defineResult.ResponseCode}'.");

        using TpmPasswordSession writeAuth = TpmPasswordSession.Create(NvCertifyIndexAuth, pool);
        using Tpm2bMaxNvBuffer writeBuffer = Tpm2bMaxNvBuffer.Create(NvCertifyWrittenData, pool);
        var writeInput = new NvWriteInput(NvCertifyIndexHandle, NvCertifyIndexHandle, writeBuffer, Offset: 0);
        TpmResult<NvWriteResponse> writeResult = await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
            tpm, writeInput, [writeAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(writeResult.IsSuccess, $"NV_Write failed: '{writeResult.ResponseCode}'.");

        using CreatePrimaryInput signerInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_ENDORSEMENT, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession endorsementAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> signerResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, signerInput, [endorsementAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signerResult.IsSuccess, $"CreatePrimary (NV_Certify signer) failed: '{signerResult.ResponseCode}'.");
        using CreatePrimaryResponse signer = signerResult.Value;

        TpmResult<EvictControlResponse> persistResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, signer.ObjectHandle.Value, NvCertifySignerPersistentHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(persistResult.IsSuccess, $"EvictControl (persist) failed: '{persistResult.ResponseCode}'.");

        TpmResult<FlushContextResponse> flushResult = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(signer.ObjectHandle.Value), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(flushResult.IsSuccess, $"Flushing the transient copy failed: '{flushResult.ResponseCode}'.");

        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession certifyIndexAuth = TpmPasswordSession.Create(NvCertifyIndexAuth, pool);
        using NvCertifyInput nvCertifyInput = NvCertifyInput.ForEcdsa(
            TpmiDhObject.FromValue(NvCertifySignerPersistentHandle), NvCertifyIndexHandle, NvCertifyIndexHandle, NvCertifyNonce,
            TpmAlgIdConstants.TPM_ALG_SHA256, (ushort)NvCertifyWrittenData.Length, offset: 0, pool);

        TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
            tpm, nvCertifyInput, [signAuth, certifyIndexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_Certify() over a persisted signer must succeed: '{result.ResponseCode}'.");

        using NvCertifyResponse nvCertify = result.Value;
        TpmsAttest attest = nvCertify.CertifyInfo.AttestationData;
        Assert.AreEqual(TpmStConstants.TPM_ST_ATTEST_NV, attest.Type, "The attestation type must be TPM_ST_ATTEST_NV.");
        Assert.IsTrue(attest.Attested.Nv!.NvContents.SequenceEqual(NvCertifyWrittenData), "The attested nvContents must equal the octets this test wrote.");
    }

    /// <summary>
    /// A persisted ECC signer opens a signing sequence over its persistent <c>keyHandle</c>, and the completion
    /// slot's password form completes it against the SAME persistent handle: <c>TPM2_SignSequenceStart()</c>'s
    /// and <c>TPM2_SignSequenceComplete()</c>'s <c>keyHandle</c> slots (<c>TPMI_DH_OBJECT</c>) admit a
    /// persistent object exactly as <c>TPM2_Sign()</c>'s does
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, clause 9.3, Table 49; Part 3, clauses 17.5/20.6).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceStartOverAPersistedSignerCompletesTheSequence()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, nameof(SignSequenceStartOverAPersistedSignerCompletesTheSequence)).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput signerInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> signerResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, signerInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signerResult.IsSuccess, $"CreatePrimary (SignSequenceStart signer) failed: '{signerResult.ResponseCode}'.");
        using CreatePrimaryResponse signer = signerResult.Value;

        TpmResult<EvictControlResponse> persistResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, signer.ObjectHandle.Value, SignSequenceStartKeyPersistentHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(persistResult.IsSuccess, $"EvictControl (persist) failed: '{persistResult.ResponseCode}'.");

        TpmResult<FlushContextResponse> flushResult = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(signer.ObjectHandle.Value), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(flushResult.IsSuccess, $"Flushing the transient copy failed: '{flushResult.ResponseCode}'.");

        var persistedHandle = TpmiDhObject.FromValue(SignSequenceStartKeyPersistentHandle);
        using SignSequenceStartInput startInput = SignSequenceStartInput.Create(persistedHandle, sequenceAuth: [], pool);
        TpmResult<SignSequenceStartResponse> startResult = await TpmCommandExecutor.ExecuteAsync<SignSequenceStartResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"TPM2_SignSequenceStart() over a persisted signer must succeed: '{startResult.ResponseCode}'.");
        TpmiDhObject sequenceHandle = startResult.Value.SequenceHandle;

        byte[] message = "persisted-signer-sign-sequence"u8.ToArray();
        using TpmPasswordSession sequenceSession = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession completionKeyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignSequenceCompleteInput completeInput = SignSequenceCompleteInput.Create(sequenceHandle, persistedHandle, message, pool);
        TpmResult<SignSequenceCompleteResponse> completeResult = await TpmCommandExecutor.ExecuteAsync<SignSequenceCompleteResponse>(
            tpm, completeInput, [sequenceSession, completionKeyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            completeResult.IsSuccess,
            $"TPM2_SignSequenceComplete() over the persisted signer's own handle at the completion slot must succeed: '{completeResult.ResponseCode}'.");
        completeResult.Value.Dispose();
    }

    /// <summary>
    /// A persisted ECC key opens a verification sequence over its persistent <c>keyHandle</c>, and the
    /// completion slot's PASSWORD form verifies a real signature against it once the sequence is fed the signed
    /// message: <c>TPM2_VerifySequenceStart()</c>'s and <c>TPM2_VerifySequenceComplete()</c>'s <c>keyHandle</c>
    /// slots (<c>TPMI_DH_OBJECT</c>) admit a persistent object exactly as the sign-sequence family's do
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, clause 9.3, Table 49; Part 3, clauses 17.6/20.3).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceStartOverAPersistedKeyCompletesTheSequenceOverItsPasswordForm()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, nameof(VerifySequenceStartOverAPersistedKeyCompletesTheSequenceOverItsPasswordForm)).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput keyInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> keyResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, keyInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(keyResult.IsSuccess, $"CreatePrimary (VerifySequenceStart key) failed: '{keyResult.ResponseCode}'.");
        using CreatePrimaryResponse key = keyResult.Value;

        byte[] message = "persisted-key-verify-sequence"u8.ToArray();
        byte[] digest = await ComputeSha256Async(message, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignInput signInput = SignInput.ForEcdsa(key.ObjectHandle, digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, signInput, [signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signResult.IsSuccess, $"TPM2_Sign() (independent signature over the message) failed: '{signResult.ResponseCode}'.");
        using SignResponse signature = signResult.Value;
        byte[] p1363Signature = ConcatenateP1363(signature.Signature.SignatureR!.AsReadOnlySpan(), signature.Signature.SignatureS!.AsReadOnlySpan());

        TpmResult<EvictControlResponse> persistResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, key.ObjectHandle.Value, VerifySequenceStartKeyPersistentHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(persistResult.IsSuccess, $"EvictControl (persist) failed: '{persistResult.ResponseCode}'.");

        TpmResult<FlushContextResponse> flushResult = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(key.ObjectHandle.Value), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(flushResult.IsSuccess, $"Flushing the transient copy failed: '{flushResult.ResponseCode}'.");

        var persistedHandle = TpmiDhObject.FromValue(VerifySequenceStartKeyPersistentHandle);
        using VerifySequenceStartInput startInput = VerifySequenceStartInput.Create(persistedHandle, sequenceAuth: [], pool);
        TpmResult<VerifySequenceStartResponse> startResult = await TpmCommandExecutor.ExecuteAsync<VerifySequenceStartResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"TPM2_VerifySequenceStart() over a persisted key must succeed: '{startResult.ResponseCode}'.");
        TpmiDhObject sequenceHandle = startResult.Value.SequenceHandle;

        using TpmPasswordSession updateSession = TpmPasswordSession.CreateEmpty(pool);
        using SequenceUpdateInput updateInput = SequenceUpdateInput.Create(sequenceHandle, message, pool);
        TpmResult<SequenceUpdateResponse> updateResult = await TpmCommandExecutor.ExecuteAsync<SequenceUpdateResponse>(
            tpm, updateInput, [updateSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(updateResult.IsSuccess, $"TPM2_SequenceUpdate() failed: '{updateResult.ResponseCode}'.");

        using TpmPasswordSession completeSession = TpmPasswordSession.CreateEmpty(pool);
        using VerifySequenceCompleteInput completeInput = VerifySequenceCompleteInput.ForEcdsa(
            sequenceHandle, persistedHandle, p1363Signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifySequenceCompleteResponse> completeResult = await TpmCommandExecutor.ExecuteAsync<VerifySequenceCompleteResponse>(
            tpm, completeInput, [completeSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            completeResult.IsSuccess,
            $"TPM2_VerifySequenceComplete() (password form) over the persisted key's own handle at the completion slot must succeed: '{completeResult.ResponseCode}'.");
        completeResult.Value.Dispose();
    }

    /// <summary>
    /// A PERSISTED attest key activates a credential bound to it while its credential-protecting key stays
    /// TRANSIENT — the reverse of <see cref="TpmInHouseSimulatorEccPointCarrierTests.PersistedEndorsementKeyMakesAndActivatesACredentialAfterItsTransientIsFlushed"/>,
    /// which persists the endorsement (<c>keyHandle</c>) side: <c>TPM2_ActivateCredential()</c>'s
    /// <c>activateHandle</c> slot (<c>TPMI_DH_OBJECT</c>) admits a persistent object exactly as its
    /// <c>keyHandle</c> does
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, clause 9.3, Table 49; Part 3, clause 12.5).
    /// </summary>
    [TestMethod]
    public async Task ActivateCredentialOverAPersistedActivateHandleSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, nameof(ActivateCredentialOverAPersistedActivateHandleSucceeds)).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput credentialKeyInput = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_ENDORSEMENT, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession endorsementAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> credentialKeyResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, credentialKeyInput, [endorsementAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(credentialKeyResult.IsSuccess, $"CreatePrimary (credential-protecting key) failed: '{credentialKeyResult.ResponseCode}'.");
        using CreatePrimaryResponse credentialKey = credentialKeyResult.Value;

        using CreatePrimaryInput attestKeyInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> attestKeyResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, attestKeyInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(attestKeyResult.IsSuccess, $"CreatePrimary (attest key) failed: '{attestKeyResult.ResponseCode}'.");
        using CreatePrimaryResponse attestKey = attestKeyResult.Value;

        TpmResult<EvictControlResponse> persistResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, attestKey.ObjectHandle.Value, ActivateCredentialActivateHandlePersistentHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(persistResult.IsSuccess, $"EvictControl (persist) failed: '{persistResult.ResponseCode}'.");

        TpmResult<FlushContextResponse> flushResult = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(attestKey.ObjectHandle.Value), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(flushResult.IsSuccess, $"Flushing the transient copy failed: '{flushResult.ResponseCode}'.");

        var persistedActivateHandle = TpmiDhObject.FromValue(ActivateCredentialActivateHandlePersistentHandle);
        using MakeCredentialInput makeInput = MakeCredentialInput.Create(credentialKey.ObjectHandle, CredentialSecret, attestKey.Name.Span.ToArray(), pool);
        TpmResult<MakeCredentialResponse> makeResult = await TpmCommandExecutor.ExecuteAsync<MakeCredentialResponse>(
            tpm, makeInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(makeResult.IsSuccess, $"TPM2_MakeCredential() failed: '{makeResult.ResponseCode}'.");
        using MakeCredentialResponse made = makeResult.Value;

        using ActivateCredentialInput activateInput = ActivateCredentialInput.Create(
            persistedActivateHandle, credentialKey.ObjectHandle, made.CredentialBlob.Span, made.Secret.Span, pool);
        using TpmPasswordSession activateAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<ActivateCredentialResponse> activateResult = await TpmCommandExecutor.ExecuteAsync<ActivateCredentialResponse>(
            tpm, activateInput, [activateAuth, keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            activateResult.IsSuccess,
            $"TPM2_ActivateCredential() over a PERSISTED activateHandle (its keyHandle transient) must succeed: '{activateResult.ResponseCode}'.");

        using ActivateCredentialResponse activated = activateResult.Value;
        Assert.IsTrue(
            activated.CertInfo.AsReadOnlySpan().SequenceEqual(CredentialSecret),
            "The recovered credential must equal the secret TPM2_MakeCredential wrapped against the persisted attest key's Name.");
    }

    /// <summary>
    /// A persisted asymmetric key at <c>TPM2_HMAC()</c>'s <c>handle</c> slot is refused <c>TPM_RC_TYPE</c> ("the
    /// key type is not TPM_ALG_KEYEDHASH") exactly as a transient one is, never <c>TPM_RC_HANDLE</c> — the
    /// persistent object is found and refused on its type — mirroring
    /// <c>TpmInHouseSimulatorHmacTests.HmacOverAnAsymmetricKeyHandleIsRefusedWithType</c>'s transient case and
    /// contrasting with <c>TpmInHouseSimulatorHmacTests.HmacOverAnUnloadedHandleIsRefusedWithHandle</c>'s missing
    /// handle (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, clause 9.3, Table 49; Part 3, clause 15.5.1).
    /// </summary>
    [TestMethod]
    public async Task HmacOverAPersistedAsymmetricKeyReturnsType()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacOverAPersistedAsymmetricKeyReturnsType), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<EvictControlResponse> persistResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, HmacPersistentHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(persistResult.IsSuccess, $"EvictControl (persist) failed: '{persistResult.ResponseCode}'.");

        TpmResult<FlushContextResponse> flushResult = await HmacKeyHarness.FlushAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(flushResult.IsSuccess, $"Flushing the transient copy failed: '{flushResult.ResponseCode}'.");

        TpmResult<HmacResponse> result = await HmacKeyHarness.HmacAsync(
            tpm, registry, pool, HmacPersistentHandle, "hmac-over-a-persisted-asymmetric-key"u8.ToArray(), TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_TYPE, 0), result.ResponseCode,
            "A persisted asymmetric key must be refused with TPM_RC_TYPE, never an undesignated TPM_RC_HANDLE, exactly as its transient twin is.");
    }

    /// <summary>
    /// The <see cref="HmacOverAPersistedAsymmetricKeyReturnsType"/> cell for <c>TPM2_HMAC_Start()</c>'s
    /// <c>handle</c> slot, the same TYPE/HANDLE contrast on the sequence-opening form of the command.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, clause 9.3, Table 49; Part 3, clause 17.2.
    /// </summary>
    [TestMethod]
    public async Task HmacStartOverAPersistedAsymmetricKeyReturnsType()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacStartOverAPersistedAsymmetricKeyReturnsType), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<EvictControlResponse> persistResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, HmacStartPersistentHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(persistResult.IsSuccess, $"EvictControl (persist) failed: '{persistResult.ResponseCode}'.");

        TpmResult<FlushContextResponse> flushResult = await HmacKeyHarness.FlushAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(flushResult.IsSuccess, $"Flushing the transient copy failed: '{flushResult.ResponseCode}'.");

        TpmResult<HmacStartResponse> result = await HmacKeyHarness.HmacStartAsync(
            tpm, registry, pool, HmacStartPersistentHandle, TpmAlgIdConstants.TPM_ALG_SHA256, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_TYPE, 0), result.ResponseCode,
            "A persisted asymmetric key must be refused with TPM_RC_TYPE at TPM2_HMAC_Start(), never an undesignated TPM_RC_HANDLE, exactly as its transient twin is.");
    }

    /// <summary>Establishes a real audit session over the production wire path: an unbound HMAC session claims <c>audit</c> on one <c>TPM2_GetRandom()</c>.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The session's handle and the host session (the caller disposes the session and flushes the handle).</returns>
    private async Task<(uint SessionHandle, TpmSession Session)> EstablishAuditSessionAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (audit) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        var session = new TpmSession(new TpmHandle(started.SessionHandle.Value), started.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), pool)
        {
            SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT
        };

        var randomInput = new GetRandomInput(16);
        TpmResult<GetRandomResponse> randomResult = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
            tpm, randomInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(randomResult.IsSuccess, $"The audit-claiming TPM2_GetRandom() failed: '{randomResult.ResponseCode}'.");
        randomResult.Value.Dispose();

        return (started.SessionHandle.Value, session);
    }

    /// <summary>Computes <c>aHash = H_authAlg(nonceTPM || expiration || cpHashA || policyRef)</c> (TPM 2.0 Library Part 3, clause 23.2.2).</summary>
    /// <param name="nonceTpm">The policy session's nonceTPM.</param>
    /// <param name="expiration">The requested expiration.</param>
    /// <param name="cpHashA">The optional cpHash restriction.</param>
    /// <param name="policyRef">The policy qualifier.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The 32-octet aHash.</returns>
    private static async Task<byte[]> ComputeAHashAsync(
        ReadOnlyMemory<byte> nonceTpm, int expiration, ReadOnlyMemory<byte> cpHashA, ReadOnlyMemory<byte> policyRef, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        byte[] message = new byte[nonceTpm.Length + sizeof(int) + cpHashA.Length + policyRef.Length];
        var writer = new TpmWriter(message);
        writer.WriteBytes(nonceTpm.Span);
        writer.WriteInt32(expiration);
        writer.WriteBytes(cpHashA.Span);
        writer.WriteBytes(policyRef.Span);

        return await ComputeSha256Async(message, pool, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Computes a SHA-256 digest through the registered digest seam (not a direct framework hash).</summary>
    /// <param name="message">The message to hash.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The 32-byte digest.</returns>
    private static async Task<byte[]> ComputeSha256Async(ReadOnlyMemory<byte> message, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            message, P256ComponentSize, CryptoTags.Sha256Digest, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        return digest.AsReadOnlySpan().ToArray();
    }

    /// <summary>Concatenates the ECDSA r and s components into the IEEE P1363 <c>r ‖ s</c> form, left-padding each to <see cref="P256ComponentSize"/>.</summary>
    /// <param name="r">The signature's r component.</param>
    /// <param name="s">The signature's s component.</param>
    /// <returns>The concatenated signature.</returns>
    private static byte[] ConcatenateP1363(ReadOnlySpan<byte> r, ReadOnlySpan<byte> s)
    {
        byte[] result = new byte[2 * P256ComponentSize];
        ToFixed(r, P256ComponentSize).CopyTo(result.AsSpan(0));
        ToFixed(s, P256ComponentSize).CopyTo(result.AsSpan(P256ComponentSize));

        return result;
    }

    /// <summary>Left-pads or right-trims <paramref name="value"/> to exactly <paramref name="length"/> bytes, big-endian.</summary>
    /// <param name="value">The source octets.</param>
    /// <param name="length">The fixed output length.</param>
    /// <returns>The fixed-width array.</returns>
    private static byte[] ToFixed(ReadOnlySpan<byte> value, int length)
    {
        byte[] result = new byte[length];
        if(value.Length <= length)
        {
            value.CopyTo(result.AsSpan(length - value.Length));
        }
        else
        {
            value[^length..].CopyTo(result);
        }

        return result;
    }

    /// <summary>Creates a powered-on simulator brought to the Operational phase with <c>TPM2_Startup(CLEAR)</c>.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="simulatorId">A per-test simulator identifier.</param>
    /// <returns>The simulator (the caller owns it).</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool, string simulatorId)
    {
        var simulator = new TpmSimulator(simulatorId, signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var input = new StartupInput(TpmSuConstants.TPM_SU_CLEAR);
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);

        var writer = new TpmWriter(owner.Memory.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "TPM2_Startup(CLEAR) must succeed.");
        using TpmResponse response = result.Value;
        Assert.AreEqual(TpmLifecyclePhase.Operational, simulator.CurrentPhase, "TPM2_Startup(CLEAR) must leave the simulator Operational.");

        return simulator;
    }

    /// <summary>Creates a response codec registry covering every command this file's tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_EvictControl, TpmResponseCodec.EvictControl);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);
        _ = registry.Register(TpmCcConstants.TPM_CC_Encapsulate, TpmResponseCodec.Encapsulate);
        _ = registry.Register(TpmCcConstants.TPM_CC_Decapsulate, TpmResponseCodec.Decapsulate);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_Sign, TpmResponseCodec.Sign);
        _ = registry.Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom);
        _ = registry.Register(TpmCcConstants.TPM_CC_Create, TpmResponseCodec.CreateObject);
        _ = registry.Register(TpmCcConstants.TPM_CC_Load, TpmResponseCodec.Load);
        _ = registry.Register(TpmCcConstants.TPM_CC_Duplicate, TpmResponseCodec.Duplicate);
        _ = registry.Register(TpmCcConstants.TPM_CC_Import, TpmResponseCodec.Import);
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyCommandCode, TpmResponseCodec.PolicyCommandCode);
        _ = registry.Register(TpmCcConstants.TPM_CC_GetSessionAuditDigest, TpmResponseCodec.GetSessionAuditDigest);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Certify, TpmResponseCodec.NvCertify);
        _ = registry.Register(TpmCcConstants.TPM_CC_SignSequenceStart, TpmResponseCodec.SignSequenceStart);
        _ = registry.Register(TpmCcConstants.TPM_CC_SequenceUpdate, TpmResponseCodec.SequenceUpdate);
        _ = registry.Register(TpmCcConstants.TPM_CC_SignSequenceComplete, TpmResponseCodec.SignSequenceComplete);
        _ = registry.Register(TpmCcConstants.TPM_CC_VerifySequenceStart, TpmResponseCodec.VerifySequenceStart);
        _ = registry.Register(TpmCcConstants.TPM_CC_VerifySequenceComplete, TpmResponseCodec.VerifySequenceComplete);
        _ = registry.Register(TpmCcConstants.TPM_CC_ActivateCredential, TpmResponseCodec.ActivateCredential);
        _ = registry.Register(TpmCcConstants.TPM_CC_MakeCredential, TpmResponseCodec.MakeCredential);
        _ = registry.Register(TpmCcConstants.TPM_CC_HMAC, TpmResponseCodec.Hmac);
        _ = registry.Register(TpmCcConstants.TPM_CC_HMAC_Start, TpmResponseCodec.HmacStart);

        return registry;
    }
}
