using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tpm;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Nv;
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
/// Reconstruction fidelity for <c>TPM2_ContextSave()</c>/<c>TPM2_ContextLoad()</c> (TPM 2.0 Library Part 3,
/// clauses 28.2 and 28.3) against the in-house behavioural <see cref="TpmSimulator"/> — entirely in-process,
/// through the same production command path every command uses (<see cref="TpmCommandExecutor"/>, the real
/// command inputs, and the real response codecs): "The encrypted data blob contains the data necessary to
/// reconstruct the full object or session context in the TPM"
/// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1,
/// clause 27.2.1</see>). Every test here proves that reconstruction NOT by inspecting the blob or the
/// simulator's internal state, but by driving a restored resource through the wire a second time — an ECC key
/// signs, an RSA key decrypts, a storage parent loads a child, a sealed object unseals, an HMAC key HMACs, a
/// bound session authorizes a following command, a policy session satisfies an object's authPolicy, and a hash
/// sequence completes to the one-shot digest — each checked against an oracle independent of the simulator's
/// own internals (the pre-save public key, an off-TPM cipher, or a second production command over the same
/// wire).
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorContextRoundTripTests
{
    /// <summary>The name/session/policy hash algorithm used throughout.</summary>
    private const TpmAlgIdConstants NameAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The RSA modulus size in bits used throughout.</summary>
    private const ushort RsaKeyBits = 2048;

    /// <summary>The RSA modulus width in octets for <see cref="RsaKeyBits"/>.</summary>
    private const int ModulusOctets = RsaKeyBits / 8;

    /// <summary>The number of bytes in a NIST P-256 coordinate.</summary>
    private const int P256ComponentSize = 32;

    /// <summary>A DA-protected NV Index this class binds a session to, from the assigned handle block.</summary>
    private const uint BoundNvIndexHandle = 0x0100_0220;

    /// <summary>The declared data size of <see cref="BoundNvIndexHandle"/>.</summary>
    private const ushort NvIndexDataSize = 16;

    /// <summary>The fixed message an ECC/RSA signing test signs; SHA-256 digested before it reaches the TPM.</summary>
    private static byte[] MessageBytes { get; } = "Verifiable in-house TPM context round-trip acceptance test."u8.ToArray();

    /// <summary>The secret a sealed object seals and later unseals.</summary>
    private static byte[] SealedSecretBytes { get; } = "Reconstruct this secret after a context round trip."u8.ToArray();

    /// <summary>The HMAC key value an HMAC key is created from.</summary>
    private static byte[] HmacKeyBytes { get; } = "context-round-trip-hmac-key"u8.ToArray();

    /// <summary>The message an HMAC key HMACs before and after its round trip.</summary>
    private static byte[] HmacMessageBytes { get; } = "authenticate me before and after a context round trip"u8.ToArray();

    /// <summary>The non-empty authValue bound to <see cref="BoundNvIndexHandle"/> — the fold a bound session's HMAC must reproduce after reload.</summary>
    private static byte[] NvIndexAuthValueBytes { get; } = [0x7A, 0x11, 0x22, 0x33, 0x44, 0x55];

    /// <summary>The octets an authorized <c>TPM2_NV_Write()</c> stores at <see cref="BoundNvIndexHandle"/>.</summary>
    private static byte[] NvWriteDataBytes { get; } = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// "The encrypted data blob contains the data necessary to reconstruct the full object or session context in
    /// the TPM" (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0
    /// Library Part 1, clause 27.2.1</see>): an ECC signing key saved and loaded draws a NEW transient handle
    /// (Part 1, clause 27.4), signs a digest at that handle, and the signature verifies off-TPM against the
    /// PRE-SAVE public key — the private scalar reconstructed byte-exact, proven independently of the
    /// simulator's own signing path.
    /// </summary>
    [TestMethod]
    public async Task EccSigningKeyRestoredAtItsNewHandleSignsAndThePreSavePublicKeyVerifies()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(EccSigningKeyRestoredAtItsNewHandleSignsAndThePreSavePublicKeyVerifies), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        uint originalHandle = key.ObjectHandle.Value;
        byte[] digest = await ComputeSha256Async(MessageBytes, pool).ConfigureAwait(false);

        using ContextSaveResponse saveResponse = await SaveContextAsync(tpm, registry, pool, originalHandle).ConfigureAwait(false);
        uint restoredHandle = await LoadContextAsync(tpm, registry, pool, saveResponse.Context).ConfigureAwait(false);
        Assert.AreNotEqual(originalHandle, restoredHandle, "An object load draws a NEW transient handle (TPM 2.0 Library Part 1, clause 27.4).");

        try
        {
            using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
            using SignInput signInput = SignInput.ForEcdsa(TpmiDhObject.FromValue(restoredHandle), digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
                tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(signResult.IsSuccess, $"TPM2_Sign() at the restored handle must succeed: '{signResult.ResponseCode}'.");

            using SignResponse signature = signResult.Value;
            TpmsEccPoint point = key.OutPublic.PublicArea.Unique.Ecc!;
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
                "A signature produced at the restored handle must verify against the PRE-SAVE public key, proving the private scalar reconstructed byte-exact.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, pool, restoredHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "The encrypted data blob contains the data necessary to reconstruct the full object or session context in
    /// the TPM" (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0
    /// Library Part 1, clause 27.2.1</see>): an RSA decrypt key restored at a new handle recovers, byte-exact,
    /// the plaintext an independent off-TPM OAEP encryption produced against the key's PRE-SAVE modulus —
    /// oracle-independent of the simulator's own RSA backend.
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptKeyRestoredDecryptsWhatItsPreSaveModulusEncryptedOffTpm()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptKeyRestoredDecryptsWhatItsPreSaveModulusEncryptedOffTpm), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateRsaDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] modulus = key.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();
        byte[] plaintext = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        byte[] cipherText = EncryptOaepOffTpm(modulus, ReadOnlySpan<byte>.Empty, plaintext);

        uint originalHandle = key.ObjectHandle.Value;
        using ContextSaveResponse saveResponse = await SaveContextAsync(tpm, registry, pool, originalHandle).ConfigureAwait(false);
        uint restoredHandle = await LoadContextAsync(tpm, registry, pool, saveResponse.Context).ConfigureAwait(false);
        Assert.AreNotEqual(originalHandle, restoredHandle, "An object load draws a NEW transient handle (TPM 2.0 Library Part 1, clause 27.4).");

        try
        {
            using Tpm2bPublicKeyRsa cipherCarrier = Tpm2bPublicKeyRsa.Create(cipherText, pool);
            using Tpm2bData labelCarrier = Tpm2bData.Create(ReadOnlySpan<byte>.Empty, pool);
            using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
            var decryptInput = new RsaDecryptInput(TpmiDhObject.FromValue(restoredHandle), cipherCarrier, TpmtRsaDecrypt.Null, labelCarrier);

            TpmResult<RsaDecryptResponse> decryptResult = await TpmCommandExecutor.ExecuteAsync<RsaDecryptResponse>(
                tpm, decryptInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(decryptResult.IsSuccess, $"TPM2_RSA_Decrypt() at the restored handle must succeed: '{decryptResult.ResponseCode}'.");

            using RsaDecryptResponse decrypted = decryptResult.Value;
            Assert.IsTrue(
                plaintext.AsSpan().SequenceEqual(decrypted.Message.Buffer),
                "The restored key must recover exactly what BouncyCastle encrypted off-TPM against the PRE-SAVE modulus.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, pool, restoredHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "If an object context is saved and subsequently reloaded, it is likely that a different handle will be
    /// assigned to the object"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1,
    /// clause 27.4</see>): an RSA storage parent restored at its new handle loads, byte-exact by Name, a child
    /// created under the ORIGINAL parent handle before the save — the parent's protection seed reconstructed
    /// intact, proven by successfully unwrapping a real wrapped blob rather than by inspecting the blob.
    /// </summary>
    [TestMethod]
    public async Task RsaStorageParentRestoredAtItsNewHandleLoadsAChildCreatedUnderTheOriginalParent()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaStorageParentRestoredAtItsNewHandleLoadsAChildCreatedUnderTheOriginalParent), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateRsaStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        uint originalParentHandle = parent.ObjectHandle.Value;

        using Tpm2bSensitiveCreate childSensitive = Tpm2bSensitiveCreate.ForSealedData(SealedSecretBytes, pool);
        using Tpm2bPublic childTemplate = Tpm2bPublic.CreateSealedDataTemplate(NameAlg, pool, noDa: true);
        using CreateInput createInput = new(originalParentHandle, childSensitive, childTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession createParentAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, createInput, [createParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"TPM2_Create() (child) failed: '{createResult.ResponseCode}'.");
        using CreateResponse child = createResult.Value;

        uint originalChildHandle;
        byte[] expectedChildName;
        using(LoadResponse loadedUnderOriginal = await LoadChildAsync(tpm, registry, pool, originalParentHandle, child.OutPrivate, child.OutPublic).ConfigureAwait(false))
        {
            originalChildHandle = loadedUnderOriginal.ObjectHandle.Value;
            expectedChildName = loadedUnderOriginal.Name.Span.ToArray();
        }

        await FlushIfPresentAsync(tpm, registry, pool, originalChildHandle).ConfigureAwait(false);

        using ContextSaveResponse saveResponse = await SaveContextAsync(tpm, registry, pool, originalParentHandle).ConfigureAwait(false);
        uint restoredParentHandle = await LoadContextAsync(tpm, registry, pool, saveResponse.Context).ConfigureAwait(false);
        Assert.AreNotEqual(originalParentHandle, restoredParentHandle, "An object load draws a NEW transient handle (TPM 2.0 Library Part 1, clause 27.4).");

        try
        {
            using LoadResponse loadedUnderRestored = await LoadChildAsync(tpm, registry, pool, restoredParentHandle, child.OutPrivate, child.OutPublic).ConfigureAwait(false);
            Assert.IsTrue(
                expectedChildName.AsSpan().SequenceEqual(loadedUnderRestored.Name.Span),
                "The child's Name loaded under the restored parent must equal the Name loaded under the original parent, byte for byte.");

            await FlushIfPresentAsync(tpm, registry, pool, loadedUnderRestored.ObjectHandle.Value).ConfigureAwait(false);
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, pool, restoredParentHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "The encrypted data blob contains the data necessary to reconstruct the full object or session context in
    /// the TPM" (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0
    /// Library Part 1, clause 27.2.1</see>): a sealed KEYEDHASH object restored at a new handle unseals to the
    /// exact secret it was sealed with, and its Name and QualifiedName — pure functions of the object's own
    /// public area (TPM 2.0 Library Part 1, clause 13, Table 9) — are unchanged through <c>TPM2_ReadPublic()</c>
    /// at that new handle.
    /// </summary>
    [TestMethod]
    public async Task SealedObjectRestoredUnsealsToTheSealedDataAndItsIdentitySurvives()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SealedObjectRestoredUnsealsToTheSealedDataAndItsIdentitySurvives), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SealedSecretBytes, pool);
        using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(NameAlg, pool, noDa: true);
        using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession createParentAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, createInput, [createParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"TPM2_Create() (seal) failed: '{createResult.ResponseCode}'.");
        using CreateResponse sealedObject = createResult.Value;

        uint originalHandle;
        using(LoadResponse loaded = await LoadChildAsync(tpm, registry, pool, parentHandle, sealedObject.OutPrivate, sealedObject.OutPublic).ConfigureAwait(false))
        {
            originalHandle = loaded.ObjectHandle.Value;
        }

        byte[] preSaveName;
        byte[] preSaveQualifiedName;
        using(ReadPublicResponse preSavePublic = await ReadPublicAsync(tpm, registry, pool, originalHandle).ConfigureAwait(false))
        {
            preSaveName = preSavePublic.Name.Span.ToArray();
            preSaveQualifiedName = preSavePublic.QualifiedName.Span.ToArray();
        }

        using ContextSaveResponse saveResponse = await SaveContextAsync(tpm, registry, pool, originalHandle).ConfigureAwait(false);
        uint restoredHandle = await LoadContextAsync(tpm, registry, pool, saveResponse.Context).ConfigureAwait(false);

        try
        {
            using(ReadPublicResponse restoredPublic = await ReadPublicAsync(tpm, registry, pool, restoredHandle).ConfigureAwait(false))
            {
                Assert.IsTrue(preSaveName.AsSpan().SequenceEqual(restoredPublic.Name.Span), "Name must survive a context round trip unchanged (Part 1, clause 13, Table 9).");
                Assert.IsTrue(
                    preSaveQualifiedName.AsSpan().SequenceEqual(restoredPublic.QualifiedName.Span),
                    "QualifiedName must survive a context round trip unchanged.");
            }

            using TpmPasswordSession unsealAuth = TpmPasswordSession.CreateEmpty(pool);
            UnsealInput unsealInput = UnsealInput.ForItem(TpmiDhObject.FromValue(restoredHandle));
            TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                tpm, unsealInput, [unsealAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(unsealResult.IsSuccess, $"TPM2_Unseal() at the restored handle must succeed: '{unsealResult.ResponseCode}'.");

            using UnsealResponse unsealed = unsealResult.Value;
            Assert.IsTrue(
                unsealed.OutData.AsReadOnlySpan().SequenceEqual(SealedSecretBytes),
                "The restored sealed object must unseal to the exact secret it was sealed with.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, pool, restoredHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "The encrypted data blob contains the data necessary to reconstruct the full object or session context in
    /// the TPM" (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0
    /// Library Part 1, clause 27.2.1</see>): an HMAC key restored at a new handle HMACs a message to the SAME
    /// tag its pre-save self produced over the identical message — the key bits reconstructed byte-exact.
    /// </summary>
    [TestMethod]
    public async Task HmacKeyRestoredHmacsToTheSameTagTheOriginalProduced()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(HmacKeyRestoredHmacsToTheSameTagTheOriginalProduced), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, HmacKeyBytes, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<HmacResponse> originalResult = await HmacKeyHarness.HmacAsync(
            tpm, registry, pool, key.Handle, HmacMessageBytes, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(originalResult.IsSuccess, $"The pre-save TPM2_HMAC() must succeed: '{originalResult.ResponseCode}'.");
        byte[] originalTag;
        using(HmacResponse originalHmac = originalResult.Value)
        {
            originalTag = originalHmac.OutHmac.AsReadOnlySpan().ToArray();
        }

        using ContextSaveResponse saveResponse = await SaveContextAsync(tpm, registry, pool, key.Handle).ConfigureAwait(false);
        uint restoredHandle = await LoadContextAsync(tpm, registry, pool, saveResponse.Context).ConfigureAwait(false);
        Assert.AreNotEqual(key.Handle, restoredHandle, "An object load draws a NEW transient handle (TPM 2.0 Library Part 1, clause 27.4).");

        try
        {
            TpmResult<HmacResponse> restoredResult = await HmacKeyHarness.HmacAsync(
                tpm, registry, pool, restoredHandle, HmacMessageBytes, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(restoredResult.IsSuccess, $"TPM2_HMAC() at the restored handle must succeed: '{restoredResult.ResponseCode}'.");

            using HmacResponse restoredHmac = restoredResult.Value;
            Assert.IsTrue(
                originalTag.AsSpan().SequenceEqual(restoredHmac.OutHmac.AsReadOnlySpan()),
                "The restored HMAC key must produce the SAME tag over the same message as its pre-save self.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, pool, restoredHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "The context associated with a session is unique... a saved session context may only be loaded once"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1,
    /// clause 27.5</see>): an HMAC session bound to a DA-protected NV Index with a non-empty authValue, over
    /// AES-CFB, saved then loaded at the SAME handle, still authorizes a following <c>TPM2_NV_Read()</c> over
    /// that very Index with the bound-entity fold omitted — recovering the exact octets a password-authorized
    /// write stored, the bound entity's own authValue fold surviving the round trip — and a second command over
    /// the same restored session, an ENCRYPT-attributed <c>TPM2_GetRandom()</c>, has its response HMAC verified
    /// and its encrypt-companion response decrypted by the production executor, proving the nonce roll and the
    /// parameter-encryption key both continue correctly on both sides after the reload.
    /// </summary>
    [TestMethod]
    public async Task BoundHmacSessionOverAnNvIndexRestoredAuthorizesAFollowingCommandAndDecryptsAnEncryptCompanionResponse()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(BoundHmacSessionOverAnNvIndexRestoredAuthorizesAFollowingCommandAndDecryptsAnEncryptCompanionResponse), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await DefineBoundNvIndexAsync(tpm, registry, pool).ConfigureAwait(false);

        using(TpmPasswordSession writeAuth = TpmPasswordSession.Create(NvIndexAuthValueBytes, pool))
        using(Tpm2bMaxNvBuffer writeBuffer = Tpm2bMaxNvBuffer.Create(NvWriteDataBytes, pool))
        {
            var writeInput = new NvWriteInput(BoundNvIndexHandle, BoundNvIndexHandle, writeBuffer, Offset: 0);
            TpmResult<NvWriteResponse> writeResult = await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
                tpm, writeInput, [writeAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(writeResult.IsSuccess, $"The pre-arrangement TPM2_NV_Write() failed: '{writeResult.ResponseCode}'.");
        }

        (uint sessionHandle, TpmSession session) = await HmacKeyHarness.StartBoundHmacSessionAsync(
            tpm, registry, pool, BoundNvIndexHandle, NvIndexAuthValueBytes, TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB),
            isBoundToAuthorizedEntity: true, TestContext.CancellationToken).ConfigureAwait(false);

        try
        {
            using(session)
            {
                using ContextSaveResponse saveResponse = await SaveContextAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
                uint restoredHandle = await LoadContextAsync(tpm, registry, pool, saveResponse.Context).ConfigureAwait(false);
                Assert.AreEqual(sessionHandle, restoredHandle, "A saved session context loads at the SAME handle it was saved from (TPM 2.0 Library Part 1, clause 27.5).");

                TpmResult<NvReadPublicResponse> nameResult = await tpm.NvReadPublicAsync(BoundNvIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(nameResult.IsSuccess, $"TPM2_NV_ReadPublic() failed: '{nameResult.ResponseCode}'.");
                byte[] indexName;
                using(NvReadPublicResponse namePublic = nameResult.Value)
                {
                    indexName = namePublic.NvName.Span.ToArray();
                }

                session.SetAuthValue(ReadOnlySpan<byte>.Empty, pool);
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION;
                var readInput = new NvReadInput(BoundNvIndexHandle, BoundNvIndexHandle, (ushort)NvWriteDataBytes.Length, Offset: 0);
                TpmResult<NvReadResponse> readResult = await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
                    tpm, readInput, [session], [indexName, indexName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(
                    readResult.IsSuccess,
                    $"TPM2_NV_Read() over the restored bound session must succeed — the bound-entity fold and the session key must survive the round trip: '{readResult.ResponseCode}'.");
                using NvReadResponse read = readResult.Value;
                Assert.IsTrue(
                    NvWriteDataBytes.AsSpan().SequenceEqual(read.Data),
                    "The restored bound session must read back exactly what the password-authorized write stored.");

                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;
                var randomInput = new GetRandomInput((ushort)32);
                TpmResult<GetRandomResponse> randomResult = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                    tpm, randomInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(
                    randomResult.IsSuccess,
                    $"A second, ENCRYPT-attributed command over the restored session must have its response HMAC verified and its encrypt companion decrypted: '{randomResult.ResponseCode}'.");
                using GetRandomResponse randomResponse = randomResult.Value;
                Assert.AreEqual(32, randomResponse.RandomBytes.Size, "Parameter encryption must not change the parameter length.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "The context associated with a session is unique... The handle associated with a session does not change
    /// as long as the session is active"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1,
    /// clause 27.5</see>): a policy session that has run <c>TPM2_PolicyCommandCode(TPM_CC_Unseal)</c> then
    /// <c>TPM2_PolicyAuthValue()</c>, saved then loaded at the SAME handle, still satisfies a sealed object's
    /// <c>authPolicy</c> at <c>TPM2_Unseal()</c> — its policyDigest, its cpHash-less kind, and its
    /// isAuthValueNeeded flag all surviving the round trip.
    /// </summary>
    [TestMethod]
    public async Task PolicySessionRestoredAfterPolicyCommandCodeAndPolicyAuthValueSatisfiesTheObjectsAuthPolicy()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(PolicySessionRestoredAfterPolicyCommandCodeAndPolicyAuthValueSatisfiesTheObjectsAuthPolicy), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] unsealPolicyDigest = ComputeUnsealPolicyDigest();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SealedSecretBytes, pool);
        using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(NameAlg, pool, authPolicy: unsealPolicyDigest, noDa: true);
        using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession createParentAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, createInput, [createParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"TPM2_Create() (policy-gated seal) failed: '{createResult.ResponseCode}'.");
        using CreateResponse sealedObject = createResult.Value;

        uint objectHandle;
        byte[] objectName;
        using(LoadResponse loaded = await LoadChildAsync(tpm, registry, pool, parentHandle, sealedObject.OutPrivate, sealedObject.OutPublic).ConfigureAwait(false))
        {
            objectHandle = loaded.ObjectHandle.Value;
            objectName = loaded.Name.Span.ToArray();
        }

        uint sessionHandle = await StartPolicySessionAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            PolicyCommandCodeInput commandCodeInput = PolicyCommandCodeInput.Create(sessionHandle, TpmCcConstants.TPM_CC_Unseal);
            TpmResult<PolicyCommandCodeResponse> commandCodeResult = await TpmCommandExecutor.ExecuteAsync<PolicyCommandCodeResponse>(
                tpm, commandCodeInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(commandCodeResult.IsSuccess, $"TPM2_PolicyCommandCode() failed: '{commandCodeResult.ResponseCode}'.");

            PolicyAuthValueInput authValueInput = PolicyAuthValueInput.ForSession(sessionHandle);
            TpmResult<PolicyAuthValueResponse> authValueResult = await TpmCommandExecutor.ExecuteAsync<PolicyAuthValueResponse>(
                tpm, authValueInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(authValueResult.IsSuccess, $"TPM2_PolicyAuthValue() failed: '{authValueResult.ResponseCode}'.");

            using ContextSaveResponse saveResponse = await SaveContextAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
            uint restoredSessionHandle = await LoadContextAsync(tpm, registry, pool, saveResponse.Context).ConfigureAwait(false);
            Assert.AreEqual(sessionHandle, restoredSessionHandle, "A saved session context loads at the SAME handle it was saved from (TPM 2.0 Library Part 1, clause 27.5).");

            using TpmPolicySession policySession = TpmPolicySession.ForSessionWithPassword(restoredSessionHandle, NameAlg, ReadOnlySpan<byte>.Empty, TestEntropy.NewCounterStream(), pool);
            UnsealInput unsealInput = UnsealInput.ForItem(TpmiDhObject.FromValue(objectHandle));
            TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                tpm, unsealInput, [policySession], [objectName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(
                unsealResult.IsSuccess,
                $"The restored policy session must still satisfy the object's authPolicy at TPM2_Unseal(): '{unsealResult.ResponseCode}'.");

            using UnsealResponse unsealed = unsealResult.Value;
            Assert.IsTrue(
                unsealed.OutData.AsReadOnlySpan().SequenceEqual(SealedSecretBytes),
                "Unseal authorized by the restored policy session must recover the exact sealed secret.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, pool, objectHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "The encrypted data blob contains the data necessary to reconstruct the full object or session context in
    /// the TPM" (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0
    /// Library Part 1, clause 27.2.1</see>), extended to a sequence object: a hash sequence restored at a new
    /// handle, updated with the message's remainder, and completed produces the identical digest a one-shot
    /// <c>TPM2_Hash()</c> gives over the whole message — the running hash state reconstructed byte-exact.
    /// </summary>
    [TestMethod]
    public async Task HashSequenceRestoredCompletesToTheOneShotDigestOfTheWholeMessage()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(HashSequenceRestoredCompletesToTheOneShotDigestOfTheWholeMessage), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] firstHalf = "the first half of a message hashed as a sequence"u8.ToArray();
        byte[] secondHalf = "then restored and completed over the remainder"u8.ToArray();
        byte[] wholeMessage = [.. firstHalf, .. secondHalf];

        using HashSequenceStartInput startInput = HashSequenceStartInput.Create([], TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256), pool);
        TpmResult<HashSequenceStartResponse> startResult = await TpmCommandExecutor.ExecuteAsync<HashSequenceStartResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"TPM2_HashSequenceStart() failed: '{startResult.ResponseCode}'.");
        uint originalHandle = startResult.Value.SequenceHandle.Value;

        using(TpmPasswordSession updateAuth = TpmPasswordSession.CreateEmpty(pool))
        using(SequenceUpdateInput updateInput = SequenceUpdateInput.Create(TpmiDhObject.FromValue(originalHandle), firstHalf, pool))
        {
            TpmResult<SequenceUpdateResponse> updateResult = await TpmCommandExecutor.ExecuteAsync<SequenceUpdateResponse>(
                tpm, updateInput, [updateAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(updateResult.IsSuccess, $"The pre-save TPM2_SequenceUpdate() failed: '{updateResult.ResponseCode}'.");
        }

        using ContextSaveResponse saveResponse = await SaveContextAsync(tpm, registry, pool, originalHandle).ConfigureAwait(false);
        uint restoredHandle = await LoadContextAsync(tpm, registry, pool, saveResponse.Context).ConfigureAwait(false);
        Assert.AreNotEqual(originalHandle, restoredHandle, "An object load draws a NEW transient handle (TPM 2.0 Library Part 1, clause 27.4).");

        try
        {
            using TpmPasswordSession completeAuth = TpmPasswordSession.CreateEmpty(pool);
            using SequenceCompleteInput completeInput = SequenceCompleteInput.Create(TpmiDhObject.FromValue(restoredHandle), secondHalf, TpmiRhHierarchy.Owner, pool);
            TpmResult<SequenceCompleteResponse> completeResult = await TpmCommandExecutor.ExecuteAsync<SequenceCompleteResponse>(
                tpm, completeInput, [completeAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(completeResult.IsSuccess, $"TPM2_SequenceComplete() at the restored handle must succeed: '{completeResult.ResponseCode}'.");
            byte[] sequenceDigest;
            using(SequenceCompleteResponse completed = completeResult.Value)
            {
                sequenceDigest = completed.Result.AsReadOnlySpan().ToArray();
            }

            using HashInput oneShotInput = HashInput.Create(wholeMessage, TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256), TpmiRhHierarchy.Owner, pool);
            TpmResult<HashResponse> oneShotResult = await TpmCommandExecutor.ExecuteAsync<HashResponse>(
                tpm, oneShotInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(oneShotResult.IsSuccess, $"TPM2_Hash() (the oracle) failed: '{oneShotResult.ResponseCode}'.");
            using HashResponse oneShot = oneShotResult.Value;

            Assert.IsTrue(
                sequenceDigest.AsSpan().SequenceEqual(oneShot.OutHash.AsReadOnlySpan()),
                "A hash sequence restored after its first block and completed over the remainder must equal the one-shot TPM2_Hash() of the whole message.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, pool, restoredHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "the sequence counter for sessions increments when a session is created or when it is loaded
    /// (TPM2_ContextLoad())"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2,
    /// clause 14.6.1</see>): this TPM advances its session sequence counter at a <c>TPM2_ContextSave()</c> AND at
    /// a <c>TPM2_ContextLoad()</c> — a session's creation at <c>TPM2_StartAuthSession()</c> does not advance it,
    /// unlike a save-only convention that would advance the counter at a save alone. On a fresh
    /// simulator a session's first save stamps <c>sequence</c> 1; loading that context back advances the counter
    /// to 2 without the load response itself carrying a sequence; saving the reloaded session a second time then
    /// stamps <c>sequence</c> 3 — a value distinguishing the load-time advance from a save-only counter, which
    /// would have stamped 2.
    /// </summary>
    [TestMethod]
    public async Task ContextLoadOfASessionAdvancesTheSessionCounterSoTheNextSaveStampsThree()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ContextLoadOfASessionAdvancesTheSessionCounterSoTheNextSaveStampsThree), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint sessionHandle, TpmSession session) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            using(session)
            {
                using ContextSaveResponse firstSave = await SaveContextAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
                ulong firstSequence = firstSave.Context.Sequence;
                Assert.IsTrue(
                    firstSave.Context.SavedHandle.IsSession,
                    "A session's savedHandle carries the session's own handle value, not a Table 58 fixed constant (Part 2, clause 14.6.2).");
                Assert.AreEqual(
                    1ul, firstSequence,
                    "On a fresh simulator, a session's first save must stamp sequence 1 (Part 2, clause 14.6.1).");

                uint loadedHandle = await LoadContextAsync(tpm, registry, pool, firstSave.Context).ConfigureAwait(false);
                Assert.AreEqual(sessionHandle, loadedHandle, "A saved session context loads at the SAME handle it was saved from.");

                using ContextSaveResponse secondSave = await SaveContextAsync(tpm, registry, pool, loadedHandle).ConfigureAwait(false);
                ulong secondSequence = secondSave.Context.Sequence;

                Assert.AreEqual(
                    3ul, secondSequence,
                    $"The load between the two saves must itself advance the counter, so the second save stamps 3, not 2: first={firstSequence}, second={secondSequence}.");
            }
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "The encrypted data blob contains the data necessary to reconstruct the full object or session context in
    /// the TPM" (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0
    /// Library Part 1, clause 27.2.1</see>): a public-only external RSA key restored at a new handle answers the
    /// SAME <c>TPM_RC_AUTH_UNAVAILABLE</c> at <c>TPM2_RSA_Decrypt()</c>'s USER slot it answered before the save
    /// — the object's own <c>publicOnly</c> attribute (no private key to authorize with) is itself part of the
    /// state a reconstruction must reproduce.
    /// </summary>
    [TestMethod]
    public async Task PublicOnlyExternalRsaKeyRestoredAnswersAuthUnavailableAtRsaDecryptsSlotExactlyAsBeforeTheSave()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(PublicOnlyExternalRsaKeyRestoredAnswersAuthUnavailableAtRsaDecryptsSlotExactlyAsBeforeTheSave), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using RSA framework = RSA.Create(RsaKeyBits);
        byte[] modulus = PadLeft(framework.ExportParameters(false).Modulus!, ModulusOctets);

        TpmaObject attributes = TpmaObject.FIXED_TPM | TpmaObject.FIXED_PARENT | TpmaObject.USER_WITH_AUTH | TpmaObject.NO_DA | TpmaObject.DECRYPT;
        using Tpm2bPublic inPublic = Tpm2bPublic.CreateRsaSigningKey(NameAlg, attributes, RsaKeyBits, TpmtRsaScheme.Null, modulus, pool);
        using var loadExternalInput = new LoadExternalInput(null, inPublic, TpmiRhHierarchy.Owner);
        TpmResult<LoadExternalResponse> loadResult = await TpmCommandExecutor.ExecuteAsync<LoadExternalResponse>(
            tpm, loadExternalInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(loadResult.IsSuccess, $"TPM2_LoadExternal() (public-only) failed: '{loadResult.ResponseCode}'.");
        uint originalHandle;
        using(LoadExternalResponse loaded = loadResult.Value)
        {
            originalHandle = loaded.ObjectHandle.Value;
        }

        TpmResult<RsaDecryptResponse> preSaveDecrypt = await DecryptWithEmptyPasswordAsync(tpm, registry, pool, originalHandle).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, ResponseCodeOrSuccess(preSaveDecrypt),
            "A public-only object has no private key to authorize with, bare TPM_RC_AUTH_UNAVAILABLE, before the save.");

        using ContextSaveResponse saveResponse = await SaveContextAsync(tpm, registry, pool, originalHandle).ConfigureAwait(false);
        uint restoredHandle = await LoadContextAsync(tpm, registry, pool, saveResponse.Context).ConfigureAwait(false);
        Assert.AreNotEqual(originalHandle, restoredHandle, "An object load draws a NEW transient handle (TPM 2.0 Library Part 1, clause 27.4).");

        try
        {
            TpmResult<RsaDecryptResponse> restoredDecrypt = await DecryptWithEmptyPasswordAsync(tpm, registry, pool, restoredHandle).ConfigureAwait(false);
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, ResponseCodeOrSuccess(restoredDecrypt),
                "The restored public-only object must answer the SAME TPM_RC_AUTH_UNAVAILABLE at the restored handle.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, pool, restoredHandle).ConfigureAwait(false);
        }
    }

    /// <summary>Issues <c>TPM2_RSA_Decrypt()</c> at <paramref name="keyHandle"/> over an empty password session, for a case expected to be refused at the authorization slot before any padding is judged.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The public-only key's handle.</param>
    /// <returns>The raw result.</returns>
    private async Task<TpmResult<RsaDecryptResponse>> DecryptWithEmptyPasswordAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint keyHandle)
    {
        using Tpm2bPublicKeyRsa cipherCarrier = Tpm2bPublicKeyRsa.Create(new byte[ModulusOctets], pool);
        using Tpm2bData labelCarrier = Tpm2bData.Create(ReadOnlySpan<byte>.Empty, pool);
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        var input = new RsaDecryptInput(TpmiDhObject.FromValue(keyHandle), cipherCarrier, TpmtRsaDecrypt.Null, labelCarrier);

        return await TpmCommandExecutor.ExecuteAsync<RsaDecryptResponse>(
            tpm, input, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Reads a result's response code without risking <see cref="TpmResult{T}.ResponseCode"/>'s throw on an unexpectedly successful result.</summary>
    /// <typeparam name="T">The result's success-value type.</typeparam>
    /// <param name="result">The result to read.</param>
    /// <returns><see cref="TpmRcConstants.TPM_RC_SUCCESS"/> when successful; otherwise the TPM's own response code.</returns>
    private static TpmRcConstants ResponseCodeOrSuccess<T>(TpmResult<T> result) =>
        result.IsSuccess ? TpmRcConstants.TPM_RC_SUCCESS : result.ResponseCode;

    /// <summary>Left-pads an unsigned big-endian integer to a fixed width.</summary>
    /// <param name="value">The integer's octets.</param>
    /// <param name="width">The target width.</param>
    /// <returns>The padded octets.</returns>
    private static byte[] PadLeft(byte[] value, int width)
    {
        byte[] padded = new byte[width];
        value.CopyTo(padded, width - value.Length);

        return padded;
    }

    /// <summary>Saves a resource's context through <c>TPM2_ContextSave()</c> over the production executor and asserts success.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The handle of the resource to save.</param>
    /// <returns>The response, owning the saved <see cref="TpmsContext"/>; the caller disposes it.</returns>
    private async Task<ContextSaveResponse> SaveContextAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle)
    {
        ContextSaveInput input = ContextSaveInput.ForHandle(handle);
        TpmResult<ContextSaveResponse> result = await TpmCommandExecutor.ExecuteAsync<ContextSaveResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_ContextSave(0x{handle:X8}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Loads a saved context through <c>TPM2_ContextLoad()</c> over the production executor and asserts success.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="context">The context to reload — BORROWED; the caller retains and later disposes it.</param>
    /// <returns>The handle assigned to the reloaded resource.</returns>
    private async Task<uint> LoadContextAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmsContext context)
    {
        var input = new ContextLoadInput(context);
        TpmResult<ContextLoadResponse> result = await TpmCommandExecutor.ExecuteAsync<ContextLoadResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_ContextLoad() failed: '{result.ResponseCode}'.");

        return result.Value.LoadedHandle.Value;
    }

    /// <summary>Issues a sessionless <c>TPM2_ReadPublic()</c> for <paramref name="handle"/> and asserts success.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The object handle to read.</param>
    /// <returns>The response; the caller disposes it.</returns>
    private async Task<ReadPublicResponse> ReadPublicAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle)
    {
        ReadPublicInput input = ReadPublicInput.ForHandle(TpmiDhObject.FromValue(handle));
        TpmResult<ReadPublicResponse> result = await TpmCommandExecutor.ExecuteAsync<ReadPublicResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_ReadPublic(0x{handle:X8}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Loads a Create()'d object under <paramref name="parentHandle"/> from freshly cloned wire copies of its private/public blobs.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentHandle">The loaded parent's handle.</param>
    /// <param name="outPrivate">The object's wrapped private blob — borrowed; the caller retains ownership.</param>
    /// <param name="outPublic">The object's public area — borrowed; the caller retains ownership.</param>
    /// <returns>The load response; the caller disposes it.</returns>
    private async Task<LoadResponse> LoadChildAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle, Tpm2bPrivate outPrivate, Tpm2bPublic outPublic)
    {
        using Tpm2bPrivate inPrivate = Tpm2bPrivate.Create(outPrivate.Span, pool);
        using Tpm2bPublic inPublic = ClonePublic(outPublic, pool);
        using LoadInput loadInput = new(parentHandle, inPrivate, inPublic);
        using TpmPasswordSession loadParentAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<LoadResponse> result = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
            tpm, loadInput, [loadParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_Load(0x{parentHandle:X8}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Reserializes a public area into a fresh, independently owned carrier — <see cref="LoadInput"/> owns and disposes the copy it is given.</summary>
    /// <param name="source">The public area to clone.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>An independent copy of the public area.</returns>
    private static Tpm2bPublic ClonePublic(Tpm2bPublic source, BaseMemoryPool pool)
    {
        int size = source.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(size);
        var writer = new TpmWriter(owner.Memory.Span[..size]);
        source.WriteTo(ref writer);
        var reader = new TpmReader(owner.Memory.Span[..size]);

        return Tpm2bPublic.Parse(ref reader, pool);
    }

    /// <summary>Flushes a transient object or session handle when one is present (non-zero), ignoring the result.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The handle to flush, or 0 for none.</param>
    private async Task FlushIfPresentAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle)
    {
        if(handle == 0)
        {
            return;
        }

        var input = FlushContextInput.ForHandle(handle);
        _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Creates and loads a DA-protected NV Index at <see cref="BoundNvIndexHandle"/> with <see cref="NvIndexAuthValueBytes"/> as its authValue.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task DefineBoundNvIndexAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);
        using Tpm2bAuth auth = Tpm2bAuth.Create(NvIndexAuthValueBytes, pool);
        TpmaNv attributes = TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_OWNERWRITE;
        using var publicInfo = new TpmsNvPublic(BoundNvIndexHandle, TpmAlgIdConstants.TPM_ALG_SHA256, attributes, Tpm2bDigest.Empty, NvIndexDataSize);
        using var input = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, auth, publicInfo);
        TpmResult<NvDefineSpaceResponse> result = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            tpm, input, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_DefineSpace(0x{BoundNvIndexHandle:X8}) failed: '{result.ResponseCode}'.");
    }

    /// <summary>Computes <c>H(H(H(0) || TPM_CC_PolicyCommandCode || TPM_CC_Unseal) || TPM_CC_PolicyAuthValue)</c> — the policyDigest a sealed object's authPolicy must equal for a policy session running those two assertions to authorize <c>TPM2_Unseal()</c>.</summary>
    /// <returns>The SHA-256 policy digest.</returns>
    private static byte[] ComputeUnsealPolicyDigest()
    {
        byte[] afterCommandCode = new byte[32];
        _ = TpmPolicyDigest.ExtendForCommandCode(new byte[32], TpmCcConstants.TPM_CC_Unseal, NameAlg, afterCommandCode, BaseMemoryPool.Shared);

        byte[] afterAuthValue = new byte[32];
        _ = TpmPolicyDigest.ExtendForAuthValue(afterCommandCode, NameAlg, afterAuthValue, BaseMemoryPool.Shared);

        return afterAuthValue;
    }

    /// <summary>Starts an unbound, unsalted policy session and asserts success.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The started session's handle.</returns>
    private async Task<uint> StartPolicySessionAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        StartAuthSessionInput input = StartAuthSessionInputExtensions.CreateUnboundUnsaltedPolicySession(NameAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> result = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"StartAuthSession (policy) failed: '{result.ResponseCode}'.");
        using StartAuthSessionResponse response = result.Value;

        return response.SessionHandle.Value;
    }

    /// <summary>Starts an unbound, unsalted HMAC session and builds the host-side <see cref="TpmSession"/> over it, with an empty authValue.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The session handle and the host session; the caller disposes the session and flushes the handle.</returns>
    private async Task<(uint Handle, TpmSession Session)> StartUnboundHmacSessionAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        StartAuthSessionInput startInput = StartAuthSessionInputExtensions.CreateUnboundUnsaltedHmacSession(NameAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        //nonceTPM ownership transfers to the session below; the response is deliberately not disposed here.
        StartAuthSessionResponse started = startResult.Value;
        var session = new TpmSession(new TpmHandle(started.SessionHandle.Value), started.NonceTPM, NameAlg, TestEntropy.NewCounterStream(), pool);

        return (started.SessionHandle.Value, session);
    }

    /// <summary>Creates a CreatePrimary'd, unrestricted ECC P-256 signing key under the owner hierarchy with an empty password.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The response; the caller disposes it.</returns>
    private async Task<CreatePrimaryResponse> CreateEccSigningKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC signing key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Creates a CreatePrimary'd, unrestricted RSA decrypt key under the owner hierarchy with an OAEP scheme and an empty password.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The response; the caller disposes it.</returns>
    private async Task<CreatePrimaryResponse> CreateRsaDecryptKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForRsaDecryptKey(TpmRh.TPM_RH_OWNER, password: null, RsaKeyBits, TpmtRsaScheme.Oaep(NameAlg), pool, noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (RSA decrypt key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Creates a CreatePrimary'd RSA storage parent under the owner hierarchy with an empty password.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The response; the caller disposes it.</returns>
    private async Task<CreatePrimaryResponse> CreateRsaStorageParentAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForRsaStorageParent(TpmRh.TPM_RH_OWNER, null, RsaKeyBits, pool, noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (RSA storage parent) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Encrypts off-TPM under OAEP-SHA-256 via BouncyCastle's <see cref="OaepEncoding"/> — an independent oracle sharing no code with the simulator's own RSA backend.</summary>
    /// <param name="modulus">The public modulus, unsigned big-endian.</param>
    /// <param name="label">The OAEP label.</param>
    /// <param name="plaintext">The plaintext to encrypt.</param>
    /// <returns>The ciphertext, exactly <see cref="ModulusOctets"/> octets.</returns>
    private static byte[] EncryptOaepOffTpm(ReadOnlySpan<byte> modulus, ReadOnlySpan<byte> label, ReadOnlySpan<byte> plaintext)
    {
        var oaep = new OaepEncoding(new RsaEngine(), new Sha256Digest(), new Sha256Digest(), label.ToArray());
        var publicKey = new RsaKeyParameters(
            isPrivate: false, new Org.BouncyCastle.Math.BigInteger(1, modulus.ToArray()), Org.BouncyCastle.Math.BigInteger.ValueOf(65537));
        oaep.Init(forEncryption: true, publicKey);
        byte[] plaintextBytes = plaintext.ToArray();

        return oaep.ProcessBlock(plaintextBytes, 0, plaintextBytes.Length);
    }

    /// <summary>Computes a SHA-256 digest through the registered digest seam (not a direct framework hash).</summary>
    /// <param name="message">The message to hash.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The 32-byte digest.</returns>
    private static async Task<byte[]> ComputeSha256Async(ReadOnlyMemory<byte> message, BaseMemoryPool pool)
    {
        Tag tag = Tag.Create(HashAlgorithmName.SHA256)
            .With(Purpose.Digest)
            .With(EncodingScheme.Raw)
            .With(MaterialSemantics.Direct);

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            new ReadOnlySequence<byte>(message), outputByteLength: P256ComponentSize, tag: tag, pool: pool).ConfigureAwait(false);

        return digest.AsReadOnlySpan().ToArray();
    }

    /// <summary>Left-pads a big-endian integer to a fixed width, as the IEEE P1363 / ECPoint encodings require.</summary>
    /// <param name="value">The big-endian value.</param>
    /// <param name="length">The fixed width to pad to.</param>
    /// <returns>A new array of exactly <paramref name="length"/> bytes.</returns>
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

    /// <summary>Creates a simulator with both the ECC (BouncyCastle) and RSA (framework) signing backends wired, powers it on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the operational phase.</summary>
    /// <param name="name">The per-test simulator identifier.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(string name, BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator(
            $"tpm-in-house-context-round-trip-{name}",
            signingBackend: BouncyCastleTpmEccSigningBackend.Create(),
            rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator, moving it into the operational phase.</summary>
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
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)responseHeader.Code);
        Assert.AreEqual(TpmLifecyclePhase.Operational, simulator.CurrentPhase);
    }

    /// <summary>Builds the response codec registry covering every command these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_ContextSave, TpmResponseCodec.ContextSave);
        _ = registry.Register(TpmCcConstants.TPM_CC_ContextLoad, TpmResponseCodec.ContextLoad);
        _ = registry.Register(TpmCcConstants.TPM_CC_Sign, TpmResponseCodec.Sign);
        _ = registry.Register(TpmCcConstants.TPM_CC_RSA_Decrypt, TpmResponseCodec.RsaDecrypt);
        _ = registry.Register(TpmCcConstants.TPM_CC_LoadExternal, TpmResponseCodec.LoadExternal);
        _ = registry.Register(TpmCcConstants.TPM_CC_Create, TpmResponseCodec.CreateObject);
        _ = registry.Register(TpmCcConstants.TPM_CC_Load, TpmResponseCodec.Load);
        _ = registry.Register(TpmCcConstants.TPM_CC_Unseal, TpmResponseCodec.Unseal);
        _ = registry.Register(TpmCcConstants.TPM_CC_ReadPublic, TpmResponseCodec.ReadPublic);
        _ = registry.Register(TpmCcConstants.TPM_CC_HMAC, TpmResponseCodec.Hmac);
        _ = registry.Register(TpmCcConstants.TPM_CC_HashSequenceStart, TpmResponseCodec.HashSequenceStart);
        _ = registry.Register(TpmCcConstants.TPM_CC_SequenceUpdate, TpmResponseCodec.SequenceUpdate);
        _ = registry.Register(TpmCcConstants.TPM_CC_SequenceComplete, TpmResponseCodec.SequenceComplete);
        _ = registry.Register(TpmCcConstants.TPM_CC_Hash, TpmResponseCodec.Hash);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyCommandCode, TpmResponseCodec.PolicyCommandCode);
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyAuthValue, TpmResponseCodec.PolicyAuthValue);
        _ = registry.Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Read, TpmResponseCodec.NvRead);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }
}
