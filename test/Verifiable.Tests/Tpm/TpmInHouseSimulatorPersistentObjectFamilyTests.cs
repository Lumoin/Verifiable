using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Hierarchy;
using Verifiable.Tpm.Spec.Algorithms;
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
/// Drives a persistent handle through the object family's commands against the in-house behavioural
/// <see cref="TpmSimulator"/> — entirely in-process, with no external assets — through the same production
/// command path the production code uses (<see cref="TpmCommandExecutor"/> with the real inputs and response
/// codecs). A persistent object is used IN PLACE at whatever slot a command names, resolving through the same
/// chain a transient object does
/// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
/// Specification</see>, Part 2, clause 9.3, Table 49; Part 3, clause 5.4, item 2).
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorPersistentObjectFamilyTests
{
    /// <summary>The number of bytes in a NIST P-256 coordinate or in an ECDSA r/s component.</summary>
    private const int P256ComponentSize = 32;

    /// <summary>The persistent handle a signing key is persisted to (owner range, 0x81000000-0x817FFFFF).</summary>
    private const uint SignerPersistentHandle = 0x8100_0300;

    /// <summary>The persistent handle a storage parent is persisted to.</summary>
    private const uint StorageParentPersistentHandle = 0x8100_0310;

    /// <summary>The persistent handle a credential-protecting key is persisted to.</summary>
    private const uint CredentialKeyPersistentHandle = 0x8100_0320;

    /// <summary>The persistent handle the disable/re-enable pair's signing key is persisted to.</summary>
    private const uint DisableReenableSignerPersistentHandle = 0x8100_0330;

    /// <summary>The persistent handle the over-session Certify test's certified subject is persisted to.</summary>
    private const uint CertifySubjectPersistentHandle = 0x8100_0340;

    /// <summary>The persistent handle the over-session Certify test's signer is persisted to.</summary>
    private const uint CertifySignerPersistentHandle = 0x8100_0350;

    /// <summary>The persistent handle the over-session SignDigest test's signer is persisted to.</summary>
    private const uint SignDigestSignerPersistentHandle = 0x8100_0360;

    /// <summary>The persistent handle the password-form TPM2_Quote() test's signer is persisted to.</summary>
    private const uint QuoterPersistentHandle = 0x8100_0500;

    /// <summary>The persistent handle the over-session TPM2_Quote() test's signer is persisted to.</summary>
    private const uint SessionQuoterPersistentHandle = 0x8100_0510;

    /// <summary>The persistent handle the TPM2_GetTime() test's signer is persisted to.</summary>
    private const uint TimeSignerPersistentHandle = 0x8100_0520;

    /// <summary>The persistent handle the TPM2_VerifyDigestSignature() test's key is persisted to.</summary>
    private const uint VerifyKeyPersistentHandle = 0x8100_0530;

    /// <summary>The persistent handle the Quote disable/re-enable pair's signer is persisted to.</summary>
    private const uint QuoteDisableReenableHandle = 0x8100_0540;

    /// <summary>The persistent handle the MakeCredential disable/re-enable pair's key is persisted to.</summary>
    private const uint CredentialKeyDisableReenableHandle = 0x8100_0550;

    /// <summary>An owner-range persistent handle an Endorsement-hierarchy object is persisted to under TPM_RH_OWNER authorization.</summary>
    private const uint EndorsementInOwnerRangeHandle = 0x8100_0560;

    /// <summary>The fixed nonce (qualifyingData) TPM2_Quote() and TPM2_GetTime() echo into their attestation's extraData.</summary>
    private static byte[] AttestationNonce { get; } = "Persistent-handle attestation nonce."u8.ToArray();

    /// <summary>The authorization value the over-session Certify test's subject key carries.</summary>
    private const string CertifySubjectPassword = "certify-subject-auth";

    /// <summary>The authorization value the over-session Certify test's signer key carries.</summary>
    private const string CertifySignerPassword = "certify-signer-auth";

    /// <summary>The authorization value the over-session SignDigest test's signer key carries.</summary>
    private const string SignDigestSignerPassword = "signdigest-signer-auth";

    /// <summary>The fixed message whose SHA-256 digest a persisted key signs.</summary>
    private static byte[] MessageBytes { get; } = "Verifiable in-house TPM persistent-handle acceptance test."u8.ToArray();

    /// <summary>A stand-in Name (nameAlg-sized) TPM2_MakeCredential() binds the wrapped secret to.</summary>
    private static byte[] BoundObjectName { get; } =
    [
        0x00, 0x0B, //TPM_ALG_SHA256 name-alg prefix (TPM 2.0 Library Part 1, clause 16).
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF
    ];

    /// <summary>The secret credential TPM2_MakeCredential() wraps.</summary>
    private static byte[] CredentialSecret { get; } =
        [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF];

    /// <summary>The secret sealed into the KEYEDHASH child TPM2_Create() builds under a persistent parent.</summary>
    private static byte[] SealedSecretBytes { get; } = "Sealed under a persistent parent."u8.ToArray();

    /// <summary>The session/name hash algorithm used throughout.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// A persistent ECC signing key signs through <c>TPM2_Sign()</c> over its 0x81 handle with a password
    /// session, verifying under the pre-read public key with the project's own independent-oracle verifier
    /// (<see cref="TpmInHouseSimulatorSignTests"/>'s recipe): the resolver chain
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, clause 9.3, Table 49) admits a persistent object at <c>TPM2_Sign()</c>'s
    /// <c>keyHandle</c> exactly as it admits a transient one.
    /// </summary>
    [TestMethod]
    public async Task PersistedEccSigningKeySignsOverItsPersistentHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (ECC signing key) failed: '{primaryResult.ResponseCode}'.");
        using CreatePrimaryResponse primary = primaryResult.Value;

        TpmResult<EvictControlResponse> persistResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, primary.ObjectHandle.Value, SignerPersistentHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(persistResult.IsSuccess, $"EvictControl (persist) failed: '{persistResult.ResponseCode}'.");

        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignInput signInput = SignInput.ForEcdsa(TpmiDhObject.FromValue(SignerPersistentHandle), digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signResult.IsSuccess, $"TPM2_Sign over the persistent handle failed: '{signResult.ResponseCode}'.");
        using SignResponse signature = signResult.Value;

        //Firewalled verify: reconstruct the public key from the pre-read public area (CreatePrimary's own
        //OutPublic), sharing no in-memory state with the signer beyond the wire bytes.
        TpmsEccPoint point = primary.OutPublic.PublicArea.Unique.Ecc!;
        var ecParameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = ToFixed(point.X.AsReadOnlySpan(), P256ComponentSize),
                Y = ToFixed(point.Y.AsReadOnlySpan(), P256ComponentSize)
            }
        };

        byte[] p1363Signature = new byte[2 * P256ComponentSize];
        ToFixed(signature.Signature.SignatureR!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(0));
        ToFixed(signature.Signature.SignatureS!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(P256ComponentSize));

        using ECDsa ecdsa = ECDsa.Create(ecParameters);
        Assert.IsTrue(
            ecdsa.VerifyHash(digest, p1363Signature),
            "A signature TPM2_Sign() produced over the persistent handle must verify against the transient key's exported public key.");
    }

    /// <summary>
    /// A persistent ECC storage parent creates a KEYEDHASH child through <c>TPM2_Create()</c> over its
    /// persistent handle: <c>TPM2_Create()</c>'s <c>parentHandle</c> slot (<c>TPMI_DH_PARENT</c>) admits a
    /// persistent object exactly as <c>TPM2_Sign()</c>'s <c>keyHandle</c> does (TPM 2.0 Library Part 2, clause
    /// 9.3, Table 49; clause 9.4, Table 50).
    /// </summary>
    [TestMethod]
    public async Task PersistedStorageParentCreatesAKeyedHashChildOverItsPersistentHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput parentInput = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> parentResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, parentInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(parentResult.IsSuccess, $"CreatePrimary storage parent failed: '{parentResult.ResponseCode}'.");
        using CreatePrimaryResponse parent = parentResult.Value;

        TpmResult<EvictControlResponse> persistResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, StorageParentPersistentHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(persistResult.IsSuccess, $"EvictControl (persist) failed: '{persistResult.ResponseCode}'.");

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SealedSecretBytes, pool);
        using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, noDa: true);
        using CreateInput createInput = new(StorageParentPersistentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession createParentAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, createInput, [createParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"TPM2_Create over the persistent parent handle failed: '{createResult.ResponseCode}'.");
        using CreateResponse sealedObject = createResult.Value;
        Assert.IsFalse(sealedObject.OutPrivate.IsEmpty, "Creating under a persistent parent must return a wrapped private blob.");
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_KEYEDHASH, sealedObject.OutPublic.PublicArea.Type, "The child must be a KEYEDHASH object.");
    }

    /// <summary>
    /// A persistent key makes a credential through <c>TPM2_MakeCredential()</c> over its persistent handle:
    /// the command's own <c>keyHandle</c> slot (<c>TPMI_DH_OBJECT</c>, no authorization) admits a persistent
    /// object exactly as the authorized slots do (TPM 2.0 Library Part 2, clause 9.3, Table 49).
    /// </summary>
    [TestMethod]
    public async Task PersistedKeyMakesACredentialOverItsPersistentHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput keyInput = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_ENDORSEMENT, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession endorsementAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> keyResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, keyInput, [endorsementAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(keyResult.IsSuccess, $"CreatePrimary (credential key) failed: '{keyResult.ResponseCode}'.");
        using CreatePrimaryResponse key = keyResult.Value;

        TpmResult<EvictControlResponse> persistResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, key.ObjectHandle.Value, CredentialKeyPersistentHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(persistResult.IsSuccess, $"EvictControl (persist) failed: '{persistResult.ResponseCode}'.");

        using MakeCredentialInput makeCredentialInput = MakeCredentialInput.Create(
            TpmiDhObject.FromValue(CredentialKeyPersistentHandle), CredentialSecret, BoundObjectName, pool);
        TpmResult<MakeCredentialResponse> makeCredentialResult = await TpmCommandExecutor.ExecuteAsync<MakeCredentialResponse>(
            tpm, makeCredentialInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(makeCredentialResult.IsSuccess, $"TPM2_MakeCredential over the persistent handle failed: '{makeCredentialResult.ResponseCode}'.");
        using MakeCredentialResponse made = makeCredentialResult.Value;
        Assert.IsFalse(made.CredentialBlob.IsEmpty, "The credential blob must not be empty.");
        Assert.IsFalse(made.Secret.IsEmpty, "The encrypted secret must not be empty.");
    }

    /// <summary>
    /// "When this command is used to CLEAR phEnable, shEnable, or ehEnable, the TPM will disable use of any
    /// persistent entity associated with the disabled hierarchy"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 24.2.1): after <c>TPM2_HierarchyControl()</c> CLEARs <c>shEnable</c>,
    /// <c>TPM2_Sign()</c> over the persisted signer's own handle answers <c>TPM_RC_HANDLE</c>, handle-encoded to the same index — the
    /// resolver's own "not found" answer for a disabled hierarchy — and once <c>shEnable</c> is SET again the
    /// same handle signs, proving the persistent record was disabled, not evicted.
    /// </summary>
    [TestMethod]
    public async Task PersistedSignerUnderADisabledOwnerHierarchyAnswersHandleThenSignsAgainAfterReEnable()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (ECC signing key) failed: '{primaryResult.ResponseCode}'.");
        using CreatePrimaryResponse primary = primaryResult.Value;

        TpmResult<EvictControlResponse> persistResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, primary.ObjectHandle.Value, DisableReenableSignerPersistentHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(persistResult.IsSuccess, $"EvictControl (persist) failed: '{persistResult.ResponseCode}'.");

        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using(TpmPasswordSession keyAuthWhileEnabled = TpmPasswordSession.CreateEmpty(pool))
        using(SignInput signWhileEnabled = SignInput.ForEcdsa(TpmiDhObject.FromValue(DisableReenableSignerPersistentHandle), digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool))
        {
            TpmResult<SignResponse> signedWhileEnabled = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
                tpm, signWhileEnabled, [keyAuthWhileEnabled], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(signedWhileEnabled.IsSuccess, $"TPM2_Sign must succeed while the owner hierarchy is enabled: '{signedWhileEnabled.ResponseCode}'.");
            signedWhileEnabled.Value.Dispose();
        }

        TpmResult<HierarchyControlResponse> disableResult = await tpm.DisableHierarchyWithPasswordAsync(
            TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, TpmRh.TPM_RH_OWNER, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(disableResult.IsSuccess, $"Disabling the owner hierarchy failed: '{disableResult.ResponseCode}'.");

        using(TpmPasswordSession keyAuthWhileDisabled = TpmPasswordSession.CreateEmpty(pool))
        using(SignInput signWhileDisabled = SignInput.ForEcdsa(TpmiDhObject.FromValue(DisableReenableSignerPersistentHandle), digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool))
        {
            TpmResult<SignResponse> signedWhileDisabled = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
                tpm, signWhileDisabled, [keyAuthWhileDisabled], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), signedWhileDisabled.ResponseCode,
                "A persistent entity under a disabled hierarchy resolves to nothing (TPM 2.0 Library Part 3, clause 24.2.1).");
        }

        TpmResult<HierarchyControlResponse> enableResult = await tpm.EnableHierarchyWithPasswordAsync(
            ReadOnlyMemory<byte>.Empty, TpmRh.TPM_RH_OWNER, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(enableResult.IsSuccess, $"Re-enabling the owner hierarchy failed: '{enableResult.ResponseCode}'.");

        using(TpmPasswordSession keyAuthAfterReEnable = TpmPasswordSession.CreateEmpty(pool))
        using(SignInput signAfterReEnable = SignInput.ForEcdsa(TpmiDhObject.FromValue(DisableReenableSignerPersistentHandle), digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool))
        {
            TpmResult<SignResponse> signedAfterReEnable = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
                tpm, signAfterReEnable, [keyAuthAfterReEnable], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(
                signedAfterReEnable.IsSuccess,
                $"TPM2_Sign must succeed again once the owner hierarchy is re-enabled, proving the persistent record was disabled, not evicted: '{signedAfterReEnable.ResponseCode}'.");
            signedAfterReEnable.Value.Dispose();
        }
    }

    /// <summary>
    /// The sequence cell: <c>TPM2_Sign()</c> at an open hash sequence's own handle answers <c>TPM_RC_KEY</c>, handle-encoded to the same index
    /// once the sequence's own authorization succeeds — a sequence object's slot has its <c>sign</c> attribute
    /// CLEAR (the reference's own <c>IsSigningObject</c> check), refused the same way
    /// <c>TPM2_Sign()</c> refuses a storage parent's handle ("If the sign attribute is not SET in the key
    /// referenced by handle, then the TPM shall return TPM_RC_KEY", Part 3, clause 20.5.1); the sequence's own
    /// <c>authValue</c> is exempt from dictionary-attack protection (Part 1, clause 29.4.6), so a correct
    /// password authorizes it exactly as <c>TPM2_SequenceUpdate()</c>'s own compare does.
    /// </summary>
    [TestMethod]
    public async Task SignWithAnOpenHashSequenceHandleAtKeyHandleAnswersBareKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] sequenceAuth = [0x51, 0x52, 0x53, 0x54];
        using HashSequenceStartInput startInput = HashSequenceStartInput.Create(sequenceAuth, TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256), pool);
        TpmResult<HashSequenceStartResponse> startResult = await TpmCommandExecutor.ExecuteAsync<HashSequenceStartResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"TPM2_HashSequenceStart() failed: '{startResult.ResponseCode}'.");
        TpmiDhObject sequenceHandle = startResult.Value.SequenceHandle;

        byte[] digest = new byte[P256ComponentSize];
        using TpmPasswordSession sequenceSession = TpmPasswordSession.Create(sequenceAuth, pool);
        using SignInput signInput = SignInput.ForEcdsa(sequenceHandle, digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, signInput, [sequenceSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_KEY, 0), signResult.ResponseCode,
            "An open sequence's slot has its sign attribute CLEAR; TPM2_Sign() must refuse it with TPM_RC_KEY once the sequence's own authorization has succeeded.");
    }

    /// <summary>
    /// The sequence cell over an HMAC session — the session form's position for the password form's own
    /// sequence arm (<see cref="SignWithAnOpenHashSequenceHandleAtKeyHandleAnswersBareKey"/>): a sequence
    /// object's slot has its <c>sign</c> attribute CLEAR — <c>keyHandle</c> is <c>TPM2_Sign()</c>'s sole handle
    /// (TPM 2.0 Library Part 3, Table 122, handle 1)
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, the reference's own <c>IsSigningObject</c> check), refused <c>TPM_RC_KEY</c>, handle-encoded to the same index
    /// only once the sequence's own authorization over the session succeeds (the reference's own
    /// <c>TPM_RCS_KEY + RC_Sign_keyHandle</c> mapping); the sequence's own <c>authValue</c> is exempt from dictionary-attack
    /// protection (Part 1, clause 29.4.6), so a WRONG session HMAC on the same slot is refused
    /// <c>TPM_RC_BAD_AUTH</c>, session-encoded to slot 0 (Part 2, clause 6.6.2), never reaching the command's
    /// own gate.
    /// </summary>
    [TestMethod]
    public async Task SignWithAnOpenHashSequenceHandleAtKeyHandleOverAnHmacSessionAnswersBareKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] sequenceAuth = [0x61, 0x62, 0x63, 0x64];
        byte[] wrongSequenceAuth = [0x71, 0x72, 0x73, 0x74];
        TpmiDhObject sequenceHandle = await StartHashSequenceAsync(tpm, registry, pool, sequenceAuth).ConfigureAwait(false);

        byte[] digest = new byte[P256ComponentSize];

        (uint wrongSessionHandle, TpmSession wrongSession) = await StartUnboundSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            wrongSession.SetAuthValue(wrongSequenceAuth, pool);
            using var wrongSignInput = new SequenceKeyedSignInput(SignInput.ForEcdsa(sequenceHandle, digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool));
            TpmResult<SignResponse> wrongResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
                tpm, wrongSignInput, [wrongSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), wrongResult.ResponseCode,
                "A wrong session HMAC over an open sequence's slot must be refused TPM_RC_BAD_AUTH at slot 0, uncharged, never reaching the command's own TPM_RC_KEY gate.");
        }
        finally
        {
            wrongSession.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, wrongSessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            session.SetAuthValue(sequenceAuth, pool);
            using var signInput = new SequenceKeyedSignInput(SignInput.ForEcdsa(sequenceHandle, digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool));
            TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
                tpm, signInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(
                HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_KEY, 0), signResult.ResponseCode,
                "An open sequence's slot has its sign attribute CLEAR; TPM2_Sign() over an HMAC session must refuse it with TPM_RC_KEY, handle-encoded to the same index once the sequence's own session authorization has succeeded.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The same sequence cell over an HMAC session for <c>TPM2_SignDigest()</c>: an open sequence's slot has
    /// its <c>sign</c> attribute CLEAR — <c>keyHandle</c> is <c>TPM2_SignDigest()</c>'s sole handle (TPM 2.0
    /// Library Part 3, Table 126, handle 1)
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, the reference's own <c>IsSigningObject</c> check), refused <c>TPM_RC_KEY</c>, handle-encoded to the same index
    /// only once the sequence's own authorization over the session succeeds (this command's own "is like
    /// TPM2_SignSequenceComplete()" gate) — the session form's position for the password
    /// form's sequence arm, so <c>TPM2_Sign()</c> and <c>TPM2_SignDigest()</c> answer the
    /// same handle alike whether authorized by password or by session.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of SignDigestInput.Create's result transfers to the SequenceKeyedSignDigestInput wrapper, which disposes it on its own Dispose; the wrapper itself is released by the enclosing using statement.")]
    public async Task SignDigestWithAnOpenHashSequenceHandleAtKeyHandleOverAnHmacSessionAnswersHandleEncodedKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] sequenceAuth = [0x65, 0x66, 0x67, 0x68];
        TpmiDhObject sequenceHandle = await StartHashSequenceAsync(tpm, registry, pool, sequenceAuth).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            session.SetAuthValue(sequenceAuth, pool);
            byte[] digest = new byte[P256ComponentSize];
            using var signDigestInput = new SequenceKeyedSignDigestInput(SignDigestInput.Create(sequenceHandle, digest, pool));
            TpmResult<SignDigestResponse> signDigestResult = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
                tpm, signDigestInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(
                HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_KEY, 0), signDigestResult.ResponseCode,
                "An open sequence's slot has its sign attribute CLEAR; TPM2_SignDigest() over an HMAC session must refuse it with TPM_RC_KEY, handle-encoded to the same index once the sequence's own session authorization has succeeded.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_SignDigest()</c> over an unbound HMAC session with a persisted signer — its transient copy flushed
    /// first, so only the persistent record can answer — signs successfully, and the signature verifies off-TPM
    /// against the pre-read public key: a persistent object admitted at the command's entry is the object the
    /// command completes with once the session's HMAC has been verified and the digest decrypted (TPM 2.0 Library
    /// Part 2, clause 9.3, Table 49).
    /// </summary>
    [TestMethod]
    public async Task PersistedSignerSignsDigestOverAnHmacSessionAfterItsTransientCopyIsFlushed()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, SignDigestSignerPassword, TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (SignDigest over-session signer) failed: '{primaryResult.ResponseCode}'.");
        using CreatePrimaryResponse primary = primaryResult.Value;

        TpmResult<EvictControlResponse> persistResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, primary.ObjectHandle.Value, SignDigestSignerPersistentHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(persistResult.IsSuccess, $"EvictControl (persist) failed: '{persistResult.ResponseCode}'.");

        TpmResult<FlushContextResponse> flushResult = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(primary.ObjectHandle.Value), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(flushResult.IsSuccess, $"Flushing the transient copy failed: '{flushResult.ResponseCode}'.");

        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);
        ReadOnlyMemory<byte>[] handleNames = [primary.Name.Span.ToArray()];

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            session.SetAuthValue(System.Text.Encoding.UTF8.GetBytes(SignDigestSignerPassword), pool);
            using SignDigestInput signDigestInput = SignDigestInput.Create(TpmiDhObject.FromValue(SignDigestSignerPersistentHandle), digest, pool);
            TpmResult<SignDigestResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
                tpm, signDigestInput, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(signResult.IsSuccess, $"TPM2_SignDigest() over an HMAC session with a persistent signer must succeed: '{signResult.ResponseCode}'.");

            using SignDigestResponse signature = signResult.Value;
            TpmsEccPoint point = primary.OutPublic.PublicArea.Unique.Ecc!;
            var ecParameters = new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = ToFixed(point.X.AsReadOnlySpan(), P256ComponentSize),
                    Y = ToFixed(point.Y.AsReadOnlySpan(), P256ComponentSize)
                }
            };

            byte[] p1363Signature = new byte[2 * P256ComponentSize];
            ToFixed(signature.Signature.SignatureR!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(0));
            ToFixed(signature.Signature.SignatureS!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(P256ComponentSize));

            using ECDsa ecdsa = ECDsa.Create(ecParameters);
            Assert.IsTrue(
                ecdsa.VerifyHash(digest, p1363Signature),
                "The signature TPM2_SignDigest() produced over the persistent handle's own session-authorized continuation must verify against the pre-read public key.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// PERSISTENT handles on BOTH authorizing slots: <c>TPM2_Certify()</c> over unbound HMAC sessions certifies a
    /// persisted subject with a persisted signer, both transient copies flushed first, and the signature verifies
    /// off-TPM against the signer's pre-read public key — each persistent object admitted at the command's entry is
    /// the object the command completes with once both sessions' HMACs have been verified (TPM 2.0 Library Part 2,
    /// clause 9.3, Table 49).
    /// </summary>
    [TestMethod]
    public async Task PersistedSubjectIsCertifiedByAPersistedSignerOverHmacSessionsAfterBothTransientCopiesAreFlushed()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput subjectInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, CertifySubjectPassword, TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession subjectOwnerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> subjectResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, subjectInput, [subjectOwnerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(subjectResult.IsSuccess, $"CreatePrimary (Certify subject) failed: '{subjectResult.ResponseCode}'.");
        using CreatePrimaryResponse subject = subjectResult.Value;

        using CreatePrimaryInput signerInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_ENDORSEMENT, CertifySignerPassword, TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession signerEndorsementAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> signerResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, signerInput, [signerEndorsementAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signerResult.IsSuccess, $"CreatePrimary (Certify signer) failed: '{signerResult.ResponseCode}'.");
        using CreatePrimaryResponse signer = signerResult.Value;

        TpmResult<EvictControlResponse> persistSubject = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, subject.ObjectHandle.Value, CertifySubjectPersistentHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(persistSubject.IsSuccess, $"EvictControl (persist subject) failed: '{persistSubject.ResponseCode}'.");

        TpmResult<EvictControlResponse> persistSigner = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, signer.ObjectHandle.Value, CertifySignerPersistentHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(persistSigner.IsSuccess, $"EvictControl (persist signer) failed: '{persistSigner.ResponseCode}'.");

        TpmResult<FlushContextResponse> flushSubject = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(subject.ObjectHandle.Value), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(flushSubject.IsSuccess, $"Flushing the subject's transient copy failed: '{flushSubject.ResponseCode}'.");

        TpmResult<FlushContextResponse> flushSigner = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(signer.ObjectHandle.Value), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(flushSigner.IsSuccess, $"Flushing the signer's transient copy failed: '{flushSigner.ResponseCode}'.");

        (uint objectSessionHandle, TpmSession objectSession) = await StartUnboundSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        (uint signSessionHandle, TpmSession signSession) = await StartUnboundSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            objectSession.SetAuthValue(System.Text.Encoding.UTF8.GetBytes(CertifySubjectPassword), pool);
            signSession.SetAuthValue(System.Text.Encoding.UTF8.GetBytes(CertifySignerPassword), pool);

            using CertifyInput certifyInput = CertifyInput.ForEcdsa(
                TpmiDhObject.FromValue(CertifySubjectPersistentHandle), TpmiDhObject.FromValue(CertifySignerPersistentHandle),
                MessageBytes.AsSpan(0, P256ComponentSize), TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            ReadOnlyMemory<byte>[] handleNames = [subject.Name.Span.ToArray(), signer.Name.Span.ToArray()];

            TpmResult<CertifyResponse> certifyResult = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
                tpm, certifyInput, [objectSession, signSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(
                certifyResult.IsSuccess,
                $"TPM2_Certify() over HMAC sessions with a persisted subject and a persisted signer must succeed: '{certifyResult.ResponseCode}'.");

            using CertifyResponse certify = certifyResult.Value;
            byte[] attestDigest = await ComputeSha256Async(certify.CertifyInfo.GetRawMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);

            TpmsEccPoint signerPoint = signer.OutPublic.PublicArea.Unique.Ecc!;
            var ecParameters = new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = ToFixed(signerPoint.X.AsReadOnlySpan(), P256ComponentSize),
                    Y = ToFixed(signerPoint.Y.AsReadOnlySpan(), P256ComponentSize)
                }
            };

            byte[] p1363Signature = new byte[2 * P256ComponentSize];
            ToFixed(certify.Signature.SignatureR!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(0));
            ToFixed(certify.Signature.SignatureS!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(P256ComponentSize));

            using ECDsa ecdsa = ECDsa.Create(ecParameters);
            Assert.IsTrue(
                ecdsa.VerifyHash(attestDigest, p1363Signature),
                "The certify signature must verify over the raw attestation bytes against the signer's pre-read public key.");
        }
        finally
        {
            objectSession.Dispose();
            signSession.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, objectSessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, signSessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A persistent ECC signing key quotes PCRs through <c>TPM2_Quote()</c> over its 0x81 handle, the signature
    /// verifying under the pre-read public key: <c>TPM2_Quote()</c>'s <c>signHandle</c> slot
    /// (<c>TPMI_DH_OBJECT</c>) admits a persistent object exactly as <c>TPM2_Sign()</c>'s <c>keyHandle</c> does —
    /// the same resolver chain
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, clause 9.3, Table 49).
    /// </summary>
    [TestMethod]
    public async Task PersistedSignerQuotesOverItsPersistentHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreatePersistedEccSignerAsync(
            tpm, registry, pool, TpmRh.TPM_RH_OWNER, QuoterPersistentHandle).ConfigureAwait(false);

        TpmResult<QuoteResponse> quoteResult = await QuoteHandleOnceAsync(tpm, registry, pool, QuoterPersistentHandle).ConfigureAwait(false);
        Assert.IsTrue(
            quoteResult.IsSuccess,
            $"TPM2_Quote over the persistent handle failed: '{(quoteResult.IsSuccess ? TpmRcConstants.TPM_RC_SUCCESS : quoteResult.ResponseCode)}'.");

        using QuoteResponse quote = quoteResult.Value;
        byte[] attestDigest = await ComputeSha256Async(quote.Quoted.GetRawMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            VerifyEcdsaP256(ak.OutPublic.PublicArea.Unique.Ecc!, quote.Signature.SignatureR!.AsReadOnlySpan(), quote.Signature.SignatureS!.AsReadOnlySpan(), attestDigest),
            "A quote TPM2_Quote() produced over the persistent handle must verify against the pre-read public key.");
    }

    /// <summary>
    /// A persistent ECC signing key attests the TPM's time image through <c>TPM2_GetTime()</c> over its 0x81
    /// handle at the <c>@signHandle</c> slot, the endorsement hierarchy's permanent handle authorizing the
    /// <c>@privacyAdminHandle</c> slot on its own empty-auth password session: <c>TPM2_GetTime()</c>'s
    /// <c>signHandle</c> slot (<c>TPMI_DH_OBJECT</c>) admits a persistent object exactly as
    /// <c>TPM2_Sign()</c>'s <c>keyHandle</c> does
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, clause 9.3, Table 49).
    /// </summary>
    [TestMethod]
    public async Task PersistedSignerGetsTimeOverItsPersistentHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreatePersistedEccSignerAsync(
            tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT, TimeSignerPersistentHandle).ConfigureAwait(false);

        using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using GetTimeInput getTimeInput = GetTimeInput.ForEcdsa(
            TpmiDhObject.FromValue(TimeSignerPersistentHandle), AttestationNonce, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<GetTimeResponse> result = await TpmCommandExecutor.ExecuteAsync<GetTimeResponse>(
            tpm, getTimeInput, [privacyAdminAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            result.IsSuccess,
            $"TPM2_GetTime over the persistent handle failed: '{(result.IsSuccess ? TpmRcConstants.TPM_RC_SUCCESS : result.ResponseCode)}'.");

        using GetTimeResponse getTime = result.Value;
        byte[] attestDigest = await ComputeSha256Async(getTime.TimeInfo.GetRawMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            VerifyEcdsaP256(ak.OutPublic.PublicArea.Unique.Ecc!, getTime.Signature.SignatureR!.AsReadOnlySpan(), getTime.Signature.SignatureS!.AsReadOnlySpan(), attestDigest),
            "The signature TPM2_GetTime() produced over the persistent handle must verify against the pre-read public key.");
    }

    /// <summary>
    /// A persistent ECC key verifies a real signature through <c>TPM2_VerifyDigestSignature()</c> over its 0x81
    /// handle: the command's <c>keyHandle</c> slot (<c>TPMI_DH_OBJECT</c>, Auth Index: None) admits a persistent
    /// object exactly as the authorized slots do
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, clause 9.3, Table 49).
    /// </summary>
    [TestMethod]
    public async Task PersistedKeyVerifiesADigestSignatureOverItsPersistentHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (VerifyDigestSignature key) failed: '{primaryResult.ResponseCode}'.");
        using CreatePrimaryResponse primary = primaryResult.Value;

        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignInput signInput = SignInput.ForEcdsa(primary.ObjectHandle, digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, signInput, [signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signResult.IsSuccess, $"TPM2_Sign failed: '{signResult.ResponseCode}'.");
        using SignResponse signature = signResult.Value;
        byte[] p1363Signature = new byte[2 * P256ComponentSize];
        ToFixed(signature.Signature.SignatureR!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(0));
        ToFixed(signature.Signature.SignatureS!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(P256ComponentSize));

        TpmResult<EvictControlResponse> persistResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, primary.ObjectHandle.Value, VerifyKeyPersistentHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(persistResult.IsSuccess, $"EvictControl (persist) failed: '{persistResult.ResponseCode}'.");

        using VerifyDigestSignatureInput verifyInput = VerifyDigestSignatureInput.ForEcdsa(
            TpmiDhObject.FromValue(VerifyKeyPersistentHandle), digest, p1363Signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifyDigestSignatureResponse> verifyResult = await TpmCommandExecutor.ExecuteAsync<VerifyDigestSignatureResponse>(
            tpm, verifyInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            verifyResult.IsSuccess,
            $"TPM2_VerifyDigestSignature over the persistent handle failed: '{(verifyResult.IsSuccess ? TpmRcConstants.TPM_RC_SUCCESS : verifyResult.ResponseCode)}'.");
        verifyResult.Value.Dispose();
    }

    /// <summary>
    /// The sequence cell for <c>TPM2_SignDigest()</c>'s password form: an open hash sequence's own handle at
    /// the <c>keyHandle</c> slot — <c>TPM2_SignDigest()</c>'s sole handle (TPM 2.0 Library Part 3, Table 126,
    /// handle 1) — answers <c>TPM_RC_KEY</c>, handle-encoded to the same index once the sequence's own authorization succeeds
    /// — a sequence object's slot has its <c>sign</c> attribute CLEAR
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, the reference's own <c>IsSigningObject</c> check), the same cell
    /// <see cref="SignWithAnOpenHashSequenceHandleAtKeyHandleAnswersBareKey"/> proves for <c>TPM2_Sign()</c>.
    /// </summary>
    [TestMethod]
    public async Task SignDigestWithAnOpenHashSequenceHandleAtKeyHandleAnswersHandleEncodedKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] sequenceAuth = [0x81, 0x82, 0x83, 0x84];
        TpmiDhObject sequenceHandle = await StartHashSequenceAsync(tpm, registry, pool, sequenceAuth).ConfigureAwait(false);

        byte[] digest = new byte[P256ComponentSize];
        using TpmPasswordSession sequenceSession = TpmPasswordSession.Create(sequenceAuth, pool);
        using SignDigestInput signDigestInput = SignDigestInput.Create(sequenceHandle, digest, pool);
        TpmResult<SignDigestResponse> signDigestResult = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
            tpm, signDigestInput, [sequenceSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_KEY, 0), signDigestResult.ResponseCode,
            "An open sequence's slot has its sign attribute CLEAR; TPM2_SignDigest() must refuse it with TPM_RC_KEY once the sequence's own authorization has succeeded.");
    }

    /// <summary>
    /// The sequence cell for <c>TPM2_VerifyDigestSignature()</c>, which carries no authorization (Auth Index:
    /// None): an open hash sequence's own handle at the <c>keyHandle</c> slot — <c>TPM2_VerifyDigestSignature()</c>'s
    /// sole handle (TPM 2.0 Library Part 3, Table 120, handle 1) — answers <c>TPM_RC_KEY</c>, handle-encoded to the same index
    /// directly at the gate — a sequence object's slot has its <c>sign</c> attribute CLEAR
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, the reference's own <c>IsSigningObject</c> check).
    /// </summary>
    [TestMethod]
    public async Task VerifyDigestSignatureWithAnOpenHashSequenceHandleAtKeyHandleAnswersBareKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] sequenceAuth = [0x91, 0x92, 0x93, 0x94];
        TpmiDhObject sequenceHandle = await StartHashSequenceAsync(tpm, registry, pool, sequenceAuth).ConfigureAwait(false);

        byte[] digest = new byte[P256ComponentSize];
        byte[] placeholderSignature = new byte[2 * P256ComponentSize];
        using VerifyDigestSignatureInput verifyInput = VerifyDigestSignatureInput.ForEcdsa(
            sequenceHandle, digest, placeholderSignature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifyDigestSignatureResponse> verifyResult = await TpmCommandExecutor.ExecuteAsync<VerifyDigestSignatureResponse>(
            tpm, verifyInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_KEY, 0), verifyResult.ResponseCode,
            "An open sequence's slot has its sign attribute CLEAR; TPM2_VerifyDigestSignature() must refuse it with TPM_RC_KEY, handle-encoded to the same index.");
    }

    /// <summary>
    /// The disable/re-enable pair at <c>TPM2_Quote()</c>'s persistent signer slot: "the TPM will disable use of
    /// any persistent entity associated with the disabled hierarchy"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 24.2.1). Quote succeeds while <c>shEnable</c> is SET, answers
    /// <c>TPM_RC_HANDLE</c>, handle-encoded to the same index, once CLEARed, and succeeds again once re-SET.
    /// </summary>
    [TestMethod]
    public async Task PersistedSignerUnderADisabledOwnerHierarchyQuotesThenQuotesAgainAfterReEnable()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreatePersistedEccSignerAsync(
            tpm, registry, pool, TpmRh.TPM_RH_OWNER, QuoteDisableReenableHandle).ConfigureAwait(false);

        TpmResult<QuoteResponse> firstQuote = await QuoteHandleOnceAsync(tpm, registry, pool, QuoteDisableReenableHandle).ConfigureAwait(false);
        Assert.IsTrue(
            firstQuote.IsSuccess,
            $"TPM2_Quote must succeed while the owner hierarchy is enabled: '{(firstQuote.IsSuccess ? TpmRcConstants.TPM_RC_SUCCESS : firstQuote.ResponseCode)}'.");
        firstQuote.Value.Dispose();

        TpmResult<HierarchyControlResponse> disableResult = await tpm.DisableHierarchyWithPasswordAsync(
            TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, TpmRh.TPM_RH_OWNER, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(disableResult.IsSuccess, $"Disabling the owner hierarchy failed: '{disableResult.ResponseCode}'.");

        TpmResult<QuoteResponse> whileDisabled = await QuoteHandleOnceAsync(tpm, registry, pool, QuoteDisableReenableHandle).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), whileDisabled.ResponseCode,
            "A persistent entity under a disabled hierarchy resolves to nothing (TPM 2.0 Library Part 3, clause 24.2.1).");

        TpmResult<HierarchyControlResponse> enableResult = await tpm.EnableHierarchyWithPasswordAsync(
            ReadOnlyMemory<byte>.Empty, TpmRh.TPM_RH_OWNER, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(enableResult.IsSuccess, $"Re-enabling the owner hierarchy failed: '{enableResult.ResponseCode}'.");

        TpmResult<QuoteResponse> afterReEnable = await QuoteHandleOnceAsync(tpm, registry, pool, QuoteDisableReenableHandle).ConfigureAwait(false);
        Assert.IsTrue(
            afterReEnable.IsSuccess,
            $"TPM2_Quote must succeed again once the owner hierarchy is re-enabled, proving the persistent record was disabled, not evicted: '{(afterReEnable.IsSuccess ? TpmRcConstants.TPM_RC_SUCCESS : afterReEnable.ResponseCode)}'.");
        afterReEnable.Value.Dispose();
    }

    /// <summary>
    /// The disable/re-enable pair at <c>TPM2_MakeCredential()</c>'s persistent key slot: "the TPM will disable
    /// use of any persistent entity associated with the disabled hierarchy"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 24.2.1). MakeCredential succeeds while <c>ehEnable</c> is SET,
    /// answers <c>TPM_RC_HANDLE</c>, handle-encoded to the same index once CLEARed, and succeeds again once re-SET.
    /// </summary>
    [TestMethod]
    public async Task PersistedKeyUnderADisabledEndorsementHierarchyMakesCredentialAnswersHandleThenSucceedsAfterReEnable()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreatePersistedEccStorageKeyAsync(
            tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT, CredentialKeyDisableReenableHandle).ConfigureAwait(false);

        TpmResult<MakeCredentialResponse> whileEnabled = await MakeCredentialOnceAsync(tpm, registry, pool, CredentialKeyDisableReenableHandle).ConfigureAwait(false);
        Assert.IsTrue(
            whileEnabled.IsSuccess,
            $"TPM2_MakeCredential must succeed while the endorsement hierarchy is enabled: '{(whileEnabled.IsSuccess ? TpmRcConstants.TPM_RC_SUCCESS : whileEnabled.ResponseCode)}'.");
        whileEnabled.Value.Dispose();

        TpmResult<HierarchyControlResponse> disableResult = await tpm.DisableHierarchyWithPasswordAsync(
            TpmRh.TPM_RH_ENDORSEMENT, ReadOnlyMemory<byte>.Empty, TpmRh.TPM_RH_ENDORSEMENT, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(disableResult.IsSuccess, $"Disabling the endorsement hierarchy failed: '{disableResult.ResponseCode}'.");

        TpmResult<MakeCredentialResponse> whileDisabled = await MakeCredentialOnceAsync(tpm, registry, pool, CredentialKeyDisableReenableHandle).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), whileDisabled.ResponseCode,
            "A persistent entity under a disabled hierarchy resolves to nothing at handle, handle 1 of Table 28 (TPM 2.0 Library Part 3, clause 24.2.1).");

        TpmResult<HierarchyControlResponse> enableResult = await tpm.EnableHierarchyWithPasswordAsync(
            ReadOnlyMemory<byte>.Empty, TpmRh.TPM_RH_ENDORSEMENT, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(enableResult.IsSuccess, $"Re-enabling the endorsement hierarchy failed: '{enableResult.ResponseCode}'.");

        TpmResult<MakeCredentialResponse> afterReEnable = await MakeCredentialOnceAsync(tpm, registry, pool, CredentialKeyDisableReenableHandle).ConfigureAwait(false);
        Assert.IsTrue(
            afterReEnable.IsSuccess,
            $"TPM2_MakeCredential must succeed again once the endorsement hierarchy is re-enabled, proving the persistent record was disabled, not evicted: '{(afterReEnable.IsSuccess ? TpmRcConstants.TPM_RC_SUCCESS : afterReEnable.ResponseCode)}'.");
        afterReEnable.Value.Dispose();
    }

    /// <summary>
    /// An Endorsement-hierarchy object persisted at an owner-range handle: item 2.2 of clause 28.5.1 admits
    /// "either the Storage or the Endorsement hierarchy" for <c>TPM_RH_OWNER</c> authorization
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 28.5.1), so the persist succeeds at an owner-range handle even
    /// though the object's own recorded hierarchy is Endorsement; once <c>ehEnable</c> is CLEARed, the SAME
    /// owner-range handle answers <c>TPM_RC_HANDLE</c>, handle-encoded to the same index — the object's RECORDED hierarchy governs
    /// resolution (Part 3, clause 24.2.1), not the handle's numeric range.
    /// </summary>
    [TestMethod]
    public async Task AnEndorsementHierarchyObjectPersistedInTheOwnerRangeUnderADisabledEndorsementHierarchyAnswersHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreatePersistedEccSignerAsync(
            tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT, EndorsementInOwnerRangeHandle).ConfigureAwait(false);

        TpmResult<ReadPublicResponse> whileEnabled = await ReadPublicAsync(tpm, registry, pool, EndorsementInOwnerRangeHandle).ConfigureAwait(false);
        Assert.IsTrue(
            whileEnabled.IsSuccess,
            $"ReadPublic must succeed while the endorsement hierarchy is enabled: '{(whileEnabled.IsSuccess ? TpmRcConstants.TPM_RC_SUCCESS : whileEnabled.ResponseCode)}'.");
        whileEnabled.Value.Dispose();

        TpmResult<HierarchyControlResponse> disableResult = await tpm.DisableHierarchyWithPasswordAsync(
            TpmRh.TPM_RH_ENDORSEMENT, ReadOnlyMemory<byte>.Empty, TpmRh.TPM_RH_ENDORSEMENT, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(disableResult.IsSuccess, $"Disabling the endorsement hierarchy failed: '{disableResult.ResponseCode}'.");

        TpmResult<ReadPublicResponse> whileDisabled = await ReadPublicAsync(tpm, registry, pool, EndorsementInOwnerRangeHandle).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), whileDisabled.ResponseCode,
            "The persistent record's OWN hierarchy (Endorsement) governs resolution, not the owner-range handle it was persisted at (TPM 2.0 Library Part 3, clause 24.2.1).");
    }

    /// <summary>
    /// <c>TPM2_Quote()</c> over an unbound HMAC session with a persisted signer — its transient copy flushed first,
    /// so only the persistent record can answer — succeeds, and the signature verifies off-TPM against the
    /// pre-read public key: the persistent object admitted at the command's entry is the object the command
    /// completes with once the session's HMAC has been verified (TPM 2.0 Library Part 2, clause 9.3, Table 49).
    /// </summary>
    [TestMethod]
    public async Task PersistedSignerQuotesOverAnHmacSessionAfterItsTransientCopyIsFlushed()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreatePersistedEccSignerAsync(
            tpm, registry, pool, TpmRh.TPM_RH_OWNER, SessionQuoterPersistentHandle).ConfigureAwait(false);

        TpmResult<FlushContextResponse> flushResult = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(ak.ObjectHandle.Value), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(flushResult.IsSuccess, $"Flushing the transient copy failed: '{flushResult.ResponseCode}'.");

        ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray()];
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(TpmAlgIdConstants.TPM_ALG_SHA256, [0], pool);
            using QuoteInput quoteInput = QuoteInput.ForEcdsa(
                TpmiDhObject.FromValue(SessionQuoterPersistentHandle), AttestationNonce, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, pool);
            TpmResult<QuoteResponse> quoteResult = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
                tpm, quoteInput, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(
                quoteResult.IsSuccess,
                $"TPM2_Quote() over an HMAC session with a persistent signer must succeed: '{(quoteResult.IsSuccess ? TpmRcConstants.TPM_RC_SUCCESS : quoteResult.ResponseCode)}'.");

            using QuoteResponse quote = quoteResult.Value;
            byte[] attestDigest = await ComputeSha256Async(quote.Quoted.GetRawMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(
                VerifyEcdsaP256(ak.OutPublic.PublicArea.Unique.Ecc!, quote.Signature.SignatureR!.AsReadOnlySpan(), quote.Signature.SignatureS!.AsReadOnlySpan(), attestDigest),
                "The signature TPM2_Quote() produced over the persistent handle's own session-authorized continuation must verify against the pre-read public key.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Opens a HASH sequence carrying <paramref name="sequenceAuth"/> and returns its handle.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sequenceAuth">The authorization value the sequence carries.</param>
    /// <returns>The started sequence's handle.</returns>
    private async Task<TpmiDhObject> StartHashSequenceAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, byte[] sequenceAuth)
    {
        using HashSequenceStartInput input = HashSequenceStartInput.Create(sequenceAuth, TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256), pool);
        TpmResult<HashSequenceStartResponse> result = await TpmCommandExecutor.ExecuteAsync<HashSequenceStartResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_HashSequenceStart() failed: '{result.ResponseCode}'.");

        return result.Value.SequenceHandle;
    }

    /// <summary>Starts an unbound, unsalted HMAC session through the production path and wraps it as a <see cref="TpmSession"/>.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The session handle and the host session; the caller owns and flushes both.</returns>
    private async Task<(uint SessionHandle, TpmSession Session)> StartUnboundSessionAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg, TestEntropy.NewCounterStream(), pool, TpmtSymDef.Null);

        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (unbound HMAC) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        var session = new TpmSession(new TpmHandle(started.SessionHandle.Value), started.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), pool, TpmtSymDef.Null)
        {
            SessionAttributes = TpmaSession.CONTINUE_SESSION
        };

        return (started.SessionHandle.Value, session);
    }

    /// <summary>
    /// Wraps a <see cref="SignInput"/> so its <c>keyHandle</c> slot at index 0 declares itself a sequence handle
    /// (<see cref="ITpmCommandInput.HandleIsSequence"/>): the production executor's own required declaration for
    /// deriving the Empty Buffer cpHash term a sequence's Name is (TPM 2.0 Library Part 1, clause 29.4.6),
    /// which <see cref="SignInput"/> itself cannot make statically since its <c>keyHandle</c> ordinarily names a
    /// real signing key.
    /// </summary>
    /// <param name="inner">The wrapped <see cref="SignInput"/>; this wrapper is its terminal owner.</param>
    private sealed class SequenceKeyedSignInput(SignInput inner): ITpmCommandInput, IDisposable
    {
        /// <inheritdoc/>
        public TpmCcConstants CommandCode => inner.CommandCode;

        /// <inheritdoc/>
        public bool FirstCommandParameterIsEncryptable => inner.FirstCommandParameterIsEncryptable;

        /// <inheritdoc/>
        public bool HandleIsSequence(int handleIndex) => handleIndex == 0;

        /// <inheritdoc/>
        public int GetSerializedSize() => inner.GetSerializedSize();

        /// <inheritdoc/>
        public void WriteHandles(ref TpmWriter writer) => inner.WriteHandles(ref writer);

        /// <inheritdoc/>
        public void WriteParameters(ref TpmWriter writer) => inner.WriteParameters(ref writer);

        /// <summary>Releases the wrapped <see cref="SignInput"/>.</summary>
        public void Dispose() => inner.Dispose();
    }

    /// <summary>
    /// Wraps a <see cref="SignDigestInput"/> so its <c>keyHandle</c> slot at index 0 declares itself a sequence
    /// handle, exactly as <see cref="SequenceKeyedSignInput"/> does for <see cref="SignInput"/>.
    /// </summary>
    /// <param name="inner">The wrapped <see cref="SignDigestInput"/>; this wrapper is its terminal owner.</param>
    private sealed class SequenceKeyedSignDigestInput(SignDigestInput inner): ITpmCommandInput, IDisposable
    {
        /// <inheritdoc/>
        public TpmCcConstants CommandCode => inner.CommandCode;

        /// <inheritdoc/>
        public bool FirstCommandParameterIsEncryptable => inner.FirstCommandParameterIsEncryptable;

        /// <inheritdoc/>
        public bool HandleIsSequence(int handleIndex) => handleIndex == 0;

        /// <inheritdoc/>
        public int GetSerializedSize() => inner.GetSerializedSize();

        /// <inheritdoc/>
        public void WriteHandles(ref TpmWriter writer) => inner.WriteHandles(ref writer);

        /// <inheritdoc/>
        public void WriteParameters(ref TpmWriter writer) => inner.WriteParameters(ref writer);

        /// <summary>Releases the wrapped <see cref="SignDigestInput"/>.</summary>
        public void Dispose() => inner.Dispose();
    }

    /// <summary>Creates an ECC P-256 signing primary under <paramref name="hierarchy"/> and persists it to <paramref name="persistentHandle"/>, returning the CreatePrimary response (the caller owns it; the transient copy stays loaded).</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The primary's hierarchy.</param>
    /// <param name="persistentHandle">The persistent handle to assign.</param>
    /// <returns>The CreatePrimary response.</returns>
    private async Task<CreatePrimaryResponse> CreatePersistedEccSignerAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy, uint persistentHandle)
    {
        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForEccSigningKey(
            hierarchy, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (ECC signing key, {hierarchy}) failed: '{primaryResult.ResponseCode}'.");
        CreatePrimaryResponse primary = primaryResult.Value;

        TpmResult<EvictControlResponse> persistResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, primary.ObjectHandle.Value, persistentHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(persistResult.IsSuccess, $"EvictControl (persist) failed: '{persistResult.ResponseCode}'.");

        return primary;
    }

    /// <summary>Creates an ECC storage-shaped primary under <paramref name="hierarchy"/> and persists it to <paramref name="persistentHandle"/>, returning the CreatePrimary response (the caller owns it; the transient copy stays loaded).</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The primary's hierarchy.</param>
    /// <param name="persistentHandle">The persistent handle to assign.</param>
    /// <returns>The CreatePrimary response.</returns>
    private async Task<CreatePrimaryResponse> CreatePersistedEccStorageKeyAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy, uint persistentHandle)
    {
        using CreatePrimaryInput keyInput = CreatePrimaryInput.ForEccStorageParent(
            hierarchy, authPassword: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> keyResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, keyInput, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(keyResult.IsSuccess, $"CreatePrimary (ECC storage key, {hierarchy}) failed: '{keyResult.ResponseCode}'.");
        CreatePrimaryResponse key = keyResult.Value;

        TpmResult<EvictControlResponse> persistResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, key.ObjectHandle.Value, persistentHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(persistResult.IsSuccess, $"EvictControl (persist) failed: '{persistResult.ResponseCode}'.");

        return key;
    }

    /// <summary>Issues a single-PCR <c>TPM2_Quote()</c> over <paramref name="signHandle"/> with an empty-auth password session, returning the raw result for the caller to assert on and dispose.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="signHandle">The signing key handle.</param>
    /// <returns>The Quote result.</returns>
    private async Task<TpmResult<QuoteResponse>> QuoteHandleOnceAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint signHandle)
    {
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(TpmAlgIdConstants.TPM_ALG_SHA256, [0], pool);
        using QuoteInput quoteInput = QuoteInput.ForEcdsa(TpmiDhObject.FromValue(signHandle), AttestationNonce, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, pool);

        return await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
            tpm, quoteInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Issues a single <c>TPM2_MakeCredential()</c> over <paramref name="keyHandle"/>, returning the raw result.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The credential-protecting key handle.</param>
    /// <returns>The MakeCredential result.</returns>
    private async Task<TpmResult<MakeCredentialResponse>> MakeCredentialOnceAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint keyHandle)
    {
        using MakeCredentialInput makeCredentialInput = MakeCredentialInput.Create(TpmiDhObject.FromValue(keyHandle), CredentialSecret, BoundObjectName, pool);

        return await TpmCommandExecutor.ExecuteAsync<MakeCredentialResponse>(
            tpm, makeCredentialInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Issues a sessionless <c>TPM2_ReadPublic()</c> for <paramref name="objectHandle"/>, returning the raw result.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="objectHandle">The handle to read.</param>
    /// <returns>The ReadPublic result.</returns>
    private async Task<TpmResult<ReadPublicResponse>> ReadPublicAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint objectHandle)
    {
        ReadPublicInput input = ReadPublicInput.ForHandle(TpmiDhObject.FromValue(objectHandle));

        return await TpmCommandExecutor.ExecuteAsync<ReadPublicResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Verifies a P-256 ECDSA signature's r/s components against a public point and digest, off-TPM, sharing no in-memory state with the signer beyond the wire bytes.</summary>
    /// <param name="point">The public key's X/Y coordinates.</param>
    /// <param name="r">The signature's r component.</param>
    /// <param name="s">The signature's s component.</param>
    /// <param name="digest">The signed digest.</param>
    /// <returns><see langword="true"/> if the signature verifies.</returns>
    private static bool VerifyEcdsaP256(TpmsEccPoint point, ReadOnlySpan<byte> r, ReadOnlySpan<byte> s, byte[] digest)
    {
        var ecParameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = ToFixed(point.X.AsReadOnlySpan(), P256ComponentSize),
                Y = ToFixed(point.Y.AsReadOnlySpan(), P256ComponentSize)
            }
        };

        byte[] p1363Signature = new byte[2 * P256ComponentSize];
        ToFixed(r, P256ComponentSize).CopyTo(p1363Signature.AsSpan(0));
        ToFixed(s, P256ComponentSize).CopyTo(p1363Signature.AsSpan(P256ComponentSize));

        using ECDsa ecdsa = ECDsa.Create(ecParameters);

        return ecdsa.VerifyHash(digest, p1363Signature);
    }

    /// <summary>Computes a SHA-256 digest through the registered digest seam (not a direct framework hash).</summary>
    /// <param name="message">The message to hash.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The 32-byte digest.</returns>
    private static async Task<byte[]> ComputeSha256Async(ReadOnlyMemory<byte> message, BaseMemoryPool pool, System.Threading.CancellationToken cancellationToken)
    {
        Tag tag = Tag.Create(HashAlgorithmName.SHA256)
            .With(Purpose.Digest)
            .With(EncodingScheme.Raw)
            .With(MaterialSemantics.Direct);

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            new ReadOnlySequence<byte>(message),
            outputByteLength: P256ComponentSize,
            tag: tag,
            pool: pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        return digest.AsReadOnlySpan().ToArray();
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
    /// <returns>The simulator (the caller owns it).</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator(
            "tpm-in-house-persistent-object-family",
            signingBackend: BouncyCastleTpmEccSigningBackend.Create(),
            rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator to move it into <see cref="TpmLifecyclePhase.Operational"/>.</summary>
    /// <param name="simulator">The simulator to bring operational.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task BringOperationalAsync(TpmSimulator simulator, BaseMemoryPool pool)
    {
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
        Assert.AreEqual(TpmLifecyclePhase.Operational, simulator.CurrentPhase);
    }

    /// <summary>Creates a response codec registry covering the commands these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_EvictControl, TpmResponseCodec.EvictControl);
        _ = registry.Register(TpmCcConstants.TPM_CC_Sign, TpmResponseCodec.Sign);
        _ = registry.Register(TpmCcConstants.TPM_CC_SignDigest, TpmResponseCodec.SignDigest);
        _ = registry.Register(TpmCcConstants.TPM_CC_Create, TpmResponseCodec.CreateObject);
        _ = registry.Register(TpmCcConstants.TPM_CC_MakeCredential, TpmResponseCodec.MakeCredential);
        _ = registry.Register(TpmCcConstants.TPM_CC_HashSequenceStart, TpmResponseCodec.HashSequenceStart);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);
        _ = registry.Register(TpmCcConstants.TPM_CC_Certify, TpmResponseCodec.Certify);
        _ = registry.Register(TpmCcConstants.TPM_CC_Quote, TpmResponseCodec.Quote);
        _ = registry.Register(TpmCcConstants.TPM_CC_GetTime, TpmResponseCodec.GetTime);
        _ = registry.Register(TpmCcConstants.TPM_CC_VerifyDigestSignature, TpmResponseCodec.VerifyDigestSignature);
        _ = registry.Register(TpmCcConstants.TPM_CC_ReadPublic, TpmResponseCodec.ReadPublic);

        return registry;
    }
}
