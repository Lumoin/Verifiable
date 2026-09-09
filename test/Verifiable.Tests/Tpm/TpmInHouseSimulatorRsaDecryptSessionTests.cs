using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.DictionaryAttack;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives the session-authorized form of <c>TPM2_RSA_Decrypt()</c> against the in-house behavioural
/// <see cref="TpmSimulator"/> — entirely in-process, with no external assets — through the production command
/// path (<see cref="TpmCommandExecutor"/> with the real <see cref="RsaDecryptInput"/> and the real response
/// codec). Table 46's <c>@keyHandle</c> carries Auth Index 1 / Auth Role USER, so its authorization may ride a
/// loaded HMAC session or a policy session, with the handle-less companion positions behind it carrying
/// <c>decrypt</c> (on <c>cipherText</c>) or <c>encrypt</c> (on <c>message</c>) alone
/// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3,
/// clause 14.3</see>, Table 46; Part 1: Architecture, clause 15.6.1, Table 12).
/// </summary>
/// <remarks>
/// <para>
/// Every real session here verifies the response authorization end to end inside the executor
/// (<see cref="TpmSession.VerifyAndUpdateAsync"/>), so a response the simulator framed with the wrong key or the
/// wrong nonce fails the exchange rather than passing silently; the positive cases additionally recover the
/// plaintext byte-exact against an off-TPM oracle that shares no code path with the effect under test — the
/// framework's own <c>RSA.Encrypt(RSAEncryptionPadding.Pkcs1)</c> for RSAES, and, for the OAEP label case, the
/// project's own <see cref="BouncyCastleTpmRsaOaepBackend"/> encrypt delegate driven against the key's exported
/// public modulus alone.
/// </para>
/// <para>
/// The refusals split in two: an authorization-area or credential fault is blamed on the offending slot and
/// carries the session-index modifier (Part 2: Structures, clause 6.6.2), while the command's own rules run only
/// after the authorization has passed and carry the same handle- or parameter-index modifier the password form
/// carries, unaffected by which session type authorized the command (Part 3, clause 5.6 precedes clause 5.7
/// precedes clause 5.8).
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorRsaDecryptSessionTests
{
    /// <summary>The hash algorithm every session in this class negotiates.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The RSA modulus size in bits every key in this class uses.</summary>
    private const ushort RsaKeyBits = 2048;

    /// <summary>The conventional RSA public exponent F4, used to reconstruct an off-TPM public key from an exported modulus.</summary>
    private const uint DefaultRsaExponent = 65537;

    /// <summary>The command header's fixed width: tag (UINT16), commandSize (UINT32), commandCode (UINT32).</summary>
    private const int CommandHeaderSize = 10;

    /// <summary>The SHA-256 digest width the hand-framed cpHash computation produces.</summary>
    private const int CpHashDigestSize = 32;

    /// <summary>The Ordinary Index this class binds a session to for the dictionary-attack charge case, from this task's assigned handle block.</summary>
    private const uint DaProtectedBindIndexHandle = 0x0100_01E0;

    /// <summary>The bind Index's declared data size.</summary>
    private const ushort BindIndexDataSize = 16;

    /// <summary>Dictionary-attack-protected Ordinary Index attributes: <c>TPMA_NV_NO_DA</c> is CLEAR.</summary>
    private const TpmaNv DaProtectedIndexAttributes = TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_OWNERWRITE;

    /// <summary>The attribute word an externally loaded, non-restricted RSA decrypt key carries.</summary>
    private const TpmaObject ExternalDecryptAttributes = TpmaObject.USER_WITH_AUTH | TpmaObject.DECRYPT | TpmaObject.NO_DA;

    /// <summary>
    /// The attribute word a public-only externally loaded RSA decrypt key carries: <c>FIXED_TPM</c> and
    /// <c>FIXED_PARENT</c> are SET when <c>inPrivate</c> is the Empty Buffer (TPM 2.0 Library Part 3, clause
    /// 12.3.1).
    /// </summary>
    private const TpmaObject PublicOnlyDecryptAttributes =
        TpmaObject.FIXED_TPM | TpmaObject.FIXED_PARENT | TpmaObject.USER_WITH_AUTH | TpmaObject.NO_DA | TpmaObject.DECRYPT;

    /// <summary>The password every decrypt key in this class is created or loaded with.</summary>
    private const string KeyPassword = "rsa-decrypt-session-key-auth";

    /// <summary>
    /// <see cref="KeyPassword"/>'s UTF-8 octets, matching the password-to-authValue convention the creation
    /// side applies.
    /// </summary>
    private static byte[] KeyPasswordBytes { get; } = System.Text.Encoding.UTF8.GetBytes(KeyPassword);

    /// <summary>A wrong guess at a key's authorization value, distinct from <see cref="KeyPasswordBytes"/>.</summary>
    private static byte[] WrongKeyPasswordBytes { get; } = [0x51, 0x52, 0x53, 0x54, 0x55];

    /// <summary>The bind Index's authorization value.</summary>
    private static byte[] BindIndexAuthBytes { get; } = [0x01, 0x02, 0x03, 0x04];

    /// <summary>A short plaintext, tied to no published vector, every decrypt round trip in this class recovers.</summary>
    private static byte[] PlaintextBytes { get; } = System.Text.Encoding.UTF8.GetBytes("RSA decrypt session plaintext..");

    /// <summary>An OAEP label with a terminating zero octet — the value the correct-label test encrypts under.</summary>
    private static byte[] CorrectLabelBytes { get; } = System.Text.Encoding.UTF8.GetBytes("TEST\0");

    /// <summary>A different, still properly-formatted OAEP label — the value the wrong-label refusal test presents at decrypt time.</summary>
    private static byte[] WrongLabelBytes { get; } = System.Text.Encoding.UTF8.GetBytes("WRONG\0");

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// An unbound, unsalted HMAC session at <c>@keyHandle</c>'s single USER slot folds the key's own
    /// authorization value into the command HMAC key: "This command uses the private key of keyHandle for this
    /// operation and authorization is required"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3,
    /// clause 14.3.1</see>). The executor verifies the response HMAC end to end before the recovered plaintext —
    /// here a <c>TPM2_LoadExternal()</c>-loaded FULL RSA decrypt key's own — is trusted.
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptOverAnUnboundHmacSessionFoldingTheKeysAuthValueSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptOverAnUnboundHmacSessionFoldingTheKeysAuthValueSucceeds), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using RsaKeyMaterial key = RsaKeyMaterial.Generate();
        byte[] cipherText = key.Key.Encrypt(PlaintextBytes, RSAEncryptionPadding.Pkcs1);

        TpmResult<LoadExternalResponse> loadResult = await LoadRsaDecryptKeyAsync(
            tpm, registry, pool, ExternalDecryptAttributes, TpmtRsaScheme.RsaEs, key.Modulus, key.P, KeyPasswordBytes).ConfigureAwait(false);
        Assert.IsTrue(loadResult.IsSuccess, $"TPM2_LoadExternal() (full RSA decrypt key) failed: '{loadResult.ResponseCode}'.");
        using LoadExternalResponse loaded = loadResult.Value;

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, KeyPasswordBytes).ConfigureAwait(false);
        try
        {
            TpmResult<RsaDecryptResponse> result = await RsaDecryptOverSessionsAsync(
                tpm, registry, pool, [session], loaded.ObjectHandle.Value, loaded.Name.AsReadOnlyMemory(), cipherText, TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"TPM2_RSA_Decrypt() over an unbound HMAC session folding the key's authValue must succeed: '{result.ResponseCode}'.");

            using RsaDecryptResponse response = result.Value;
            Assert.IsTrue(response.Message.Buffer.SequenceEqual(PlaintextBytes), "The recovered message must equal the off-TPM plaintext byte-exact.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A session BOUND to the very key it authorizes decrypts with no per-command authorization value: binding
    /// already folded the key's authValue into the session key, so the command HMAC key omits it — the bind
    /// omission (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0
    /// Library Specification</see>, Part 1: Architecture, clause 16.6.10, equation 22) at <c>TPM2_RSA_Decrypt()</c>'s
    /// single authorized slot (Part 3: Commands, clause 14.3, Table 46).
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptOverASessionBoundToTheKeyOmitsTheAuthValueFromTheCommandHmac()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptOverASessionBoundToTheKeyOmitsTheAuthValueFromTheCommandHmac), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateRsaDecryptPrimaryAsync(tpm, registry, pool, TpmtRsaScheme.RsaEs, isNoDa: true).ConfigureAwait(false);
        byte[] cipherText = EncryptRsaesToPublicModulus(key.OutPublic.PublicArea.Unique.GetRsaModulus(), PlaintextBytes);

        (uint sessionHandle, TpmSession session) = await HmacKeyHarness.StartBoundHmacSessionAsync(
            tpm, registry, pool, key.ObjectHandle.Value, KeyPasswordBytes, TpmtSymDef.Null, isBoundToAuthorizedEntity: true, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            TpmResult<RsaDecryptResponse> result = await RsaDecryptOverSessionsAsync(
                tpm, registry, pool, [session], key.ObjectHandle.Value, key.Name.AsReadOnlyMemory(), cipherText, TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"A session bound to the key it authorizes must succeed with the authValue omitted from the command HMAC key: '{result.ResponseCode}'.");

            using RsaDecryptResponse response = result.Value;
            Assert.IsTrue(response.Message.Buffer.SequenceEqual(PlaintextBytes), "The recovered message must equal the off-TPM plaintext byte-exact.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>cipherText</c> is <c>TPM2_RSA_Decrypt()</c>'s first command parameter and a sized <c>TPM2B_PUBLIC_KEY_RSA</c>
    /// (Table 46), so a session carrying <c>decrypt</c> may protect it — "Any first parameter can be encrypted as
    /// long as the parameter has a size field"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 18.1). Over XOR obfuscation and over AES-128-CFB the
    /// RSA ciphertext crosses the wire transformed and the simulator recovers it under the companion's own
    /// keystream (clause 18.2/18.3), and the decrypted RSA plaintext is byte-exact against the off-TPM oracle.
    /// </summary>
    /// <param name="isAesCfb">Whether the companion negotiates AES-128-CFB (else the XOR obfuscation).</param>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task RsaDecryptWithADecryptCompanionOnCipherTextRecoversThePlaintextByteExact(bool isAesCfb)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(RsaDecryptWithADecryptCompanionOnCipherTextRecoversThePlaintextByteExact)}-{isAesCfb}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using CreatePrimaryResponse key = await CreateRsaDecryptPrimaryAsync(tpm, registry, pool, TpmtRsaScheme.RsaEs, isNoDa: true).ConfigureAwait(false);
        byte[] cipherText = EncryptRsaesToPublicModulus(key.OutPublic.PublicArea.Unique.GetRsaModulus(), PlaintextBytes);

        (uint companionHandle, TpmSession companion) = await HmacKeyHarness.StartBoundHmacSessionAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, Symmetric(isAesCfb), isBoundToAuthorizedEntity: false, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            companion.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

            using TpmPasswordSession keyPassword = TpmPasswordSession.Create(KeyPasswordBytes, pool);
            TpmResult<RsaDecryptResponse> result = await RsaDecryptOverSessionsAsync(
                tpm, registry, pool, [keyPassword, companion], key.ObjectHandle.Value, key.Name.AsReadOnlyMemory(), cipherText, TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"TPM2_RSA_Decrypt() over a '{Symmetric(isAesCfb).Algorithm}' decrypt companion on cipherText must succeed: '{result.ResponseCode}'.");

            using RsaDecryptResponse response = result.Value;
            Assert.IsTrue(response.Message.Buffer.SequenceEqual(PlaintextBytes), "The plaintext recovered through a decrypt-protected cipherText must equal the off-TPM plaintext byte-exact.");
        }
        finally
        {
            companion.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, companionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>message</c> is <c>TPM2_RSA_Decrypt()</c>'s only, sized response parameter (Table 47), so a session
    /// carrying <c>encrypt</c> protects the recovered plaintext on the way back — "The message parameter in the
    /// response may be encrypted using parameter encryption"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 14.3.1). The executor decrypts it client-side to the correct
    /// plaintext, and the raw octets captured on the wire never carry that plaintext in the clear.
    /// </summary>
    /// <param name="isAesCfb">Whether the companion negotiates AES-128-CFB (else the XOR obfuscation).</param>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task RsaDecryptWithAnEncryptCompanionOnMessageKeepsThePlaintextOffTheWire(bool isAesCfb)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(RsaDecryptWithAnEncryptCompanionOnMessageKeepsThePlaintextOffTheWire)}-{isAesCfb}", pool).ConfigureAwait(false);

        byte[]? capturedResponse = null;
        using TpmDevice tpm = CreateRsaDecryptResponseCapturingDevice(simulator, bytes => capturedResponse = bytes);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using CreatePrimaryResponse key = await CreateRsaDecryptPrimaryAsync(tpm, registry, pool, TpmtRsaScheme.RsaEs, isNoDa: true).ConfigureAwait(false);
        byte[] cipherText = EncryptRsaesToPublicModulus(key.OutPublic.PublicArea.Unique.GetRsaModulus(), PlaintextBytes);

        (uint companionHandle, TpmSession companion) = await HmacKeyHarness.StartBoundHmacSessionAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, Symmetric(isAesCfb), isBoundToAuthorizedEntity: false, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            companion.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

            using TpmPasswordSession keyPassword = TpmPasswordSession.Create(KeyPasswordBytes, pool);
            TpmResult<RsaDecryptResponse> result = await RsaDecryptOverSessionsAsync(
                tpm, registry, pool, [keyPassword, companion], key.ObjectHandle.Value, key.Name.AsReadOnlyMemory(), cipherText, TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"TPM2_RSA_Decrypt() over a '{Symmetric(isAesCfb).Algorithm}' encrypt companion on message must succeed: '{result.ResponseCode}'.");

            using RsaDecryptResponse response = result.Value;
            Assert.IsTrue(response.Message.Buffer.SequenceEqual(PlaintextBytes), "The executor's decrypted message must equal the off-TPM plaintext.");

            Assert.IsNotNull(capturedResponse, "The framed TPM2_RSA_Decrypt() response must have been captured on its way back from the simulator.");
            Assert.AreEqual(
                -1, capturedResponse.AsSpan().IndexOf(PlaintextBytes.AsSpan()),
                "An encrypt companion's keystream must actually have transformed the response: the plaintext must never ride the wire in the clear.");
        }
        finally
        {
            companion.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, companionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// An authorization area of <c>[key session, decrypt companion, encrypt companion]</c> is legal — Table 12
    /// admits up to three blocks, the two handle-less ones "for the single purpose of decrypting" and
    /// "encrypting" a command/response parameter respectively
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 15.6.1, Table 12). Both companions apply at once:
    /// <c>cipherText</c> crosses the wire transformed and <c>message</c> comes back transformed, and the
    /// recovered plaintext is still byte-exact against the off-TPM oracle.
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptWithBothADecryptAndAnEncryptCompanionRecoversThePlaintext()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptWithBothADecryptAndAnEncryptCompanionRecoversThePlaintext), pool).ConfigureAwait(false);

        byte[]? capturedResponse = null;
        using TpmDevice tpm = CreateRsaDecryptResponseCapturingDevice(simulator, bytes => capturedResponse = bytes);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using CreatePrimaryResponse key = await CreateRsaDecryptPrimaryAsync(tpm, registry, pool, TpmtRsaScheme.RsaEs, isNoDa: true).ConfigureAwait(false);
        byte[] cipherText = EncryptRsaesToPublicModulus(key.OutPublic.PublicArea.Unique.GetRsaModulus(), PlaintextBytes);

        (uint decryptCompanionHandle, TpmSession decryptCompanion) = await HmacKeyHarness.StartBoundHmacSessionAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmtSymDef.Xor(SessionAlg), isBoundToAuthorizedEntity: false, TestContext.CancellationToken).ConfigureAwait(false);
        (uint encryptCompanionHandle, TpmSession encryptCompanion) = await HmacKeyHarness.StartBoundHmacSessionAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB), isBoundToAuthorizedEntity: false, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            decryptCompanion.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;
            encryptCompanion.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

            using TpmPasswordSession keyPassword = TpmPasswordSession.Create(KeyPasswordBytes, pool);
            TpmResult<RsaDecryptResponse> result = await RsaDecryptOverSessionsAsync(
                tpm, registry, pool, [keyPassword, decryptCompanion, encryptCompanion], key.ObjectHandle.Value, key.Name.AsReadOnlyMemory(), cipherText, TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"TPM2_RSA_Decrypt() with both a decrypt and an encrypt companion must succeed: '{result.ResponseCode}'.");

            using RsaDecryptResponse response = result.Value;
            Assert.IsTrue(response.Message.Buffer.SequenceEqual(PlaintextBytes), "The recovered message must equal the off-TPM plaintext when both companions are present.");

            Assert.IsNotNull(capturedResponse, "The framed response must have been captured.");
            Assert.AreEqual(
                -1, capturedResponse.AsSpan().IndexOf(PlaintextBytes.AsSpan()),
                "The encrypt companion must still keep the plaintext off the wire when a decrypt companion is present too.");
        }
        finally
        {
            encryptCompanion.Dispose();
            decryptCompanion.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, encryptCompanionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, decryptCompanionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A wrong command HMAC over a session bound to a dictionary-attack-PROTECTED NV Index is the
    /// session-index-encoded <c>TPM_RC_AUTH_FAIL</c> at index 0 and charges <c>failedTries</c> once — the failure
    /// counter moves "if either the entity being authorized is subject to DA protection or if the session is
    /// bound to an entity that has DA protection"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 16.8.7), the decrypt key itself being DA-protected here.
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptWithAWrongCommandHmacOverASessionBoundToADaProtectedNvIndexChargesFailedTries()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptWithAWrongCommandHmacOverASessionBoundToADaProtectedNvIndexChargesFailedTries), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateRsaDecryptPrimaryAsync(tpm, registry, pool, TpmtRsaScheme.RsaEs, isNoDa: false).ConfigureAwait(false);
        await DefineDaProtectedIndexAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] cipherText = EncryptRsaesToPublicModulus(key.OutPublic.PublicArea.Unique.GetRsaModulus(), PlaintextBytes);

        (uint sessionHandle, TpmSession session) = await HmacKeyHarness.StartBoundHmacSessionAsync(
            tpm, registry, pool, DaProtectedBindIndexHandle, BindIndexAuthBytes, TpmtSymDef.Null, isBoundToAuthorizedEntity: false, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            session.SetAuthValue(KeyPasswordBytes, pool);
            TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

            byte[] command = await FrameRsaDecryptOverSessionAsync(
                session, key.ObjectHandle.Value, key.Name.AsReadOnlyMemory(), cipherText, TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty, pool).ConfigureAwait(false);
            TamperLastHmacOctet(command);
            TpmRcConstants responseCode = await SubmitRawAsync(simulator, pool, command).ConfigureAwait(false);
            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), responseCode,
                "A wrong command HMAC over a session bound to a DA-protected entity is the session-index-encoded TPM_RC_AUTH_FAIL.");

            TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(before.Value.LockoutCounter + 1, after.Value.LockoutCounter, "The bind to a DA-protected Index must charge failedTries once.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A wrong command HMAC over an UNBOUND session authorizing a <c>noDA</c> decrypt key is the
    /// session-index-encoded <c>TPM_RC_BAD_AUTH</c> at index 0 and charges nothing: neither the entity nor a bind
    /// lends the session dictionary-attack protection
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 16.8.1).
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptWithAWrongCommandHmacOverAnUnboundSessionIsBadAuthUncharged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptWithAWrongCommandHmacOverAnUnboundSessionIsBadAuthUncharged), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateRsaDecryptPrimaryAsync(tpm, registry, pool, TpmtRsaScheme.RsaEs, isNoDa: true).ConfigureAwait(false);
        byte[] cipherText = EncryptRsaesToPublicModulus(key.OutPublic.PublicArea.Unique.GetRsaModulus(), PlaintextBytes);

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, KeyPasswordBytes).ConfigureAwait(false);
        try
        {
            TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

            byte[] command = await FrameRsaDecryptOverSessionAsync(
                session, key.ObjectHandle.Value, key.Name.AsReadOnlyMemory(), cipherText, TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty, pool).ConfigureAwait(false);
            TamperLastHmacOctet(command);
            TpmRcConstants responseCode = await SubmitRawAsync(simulator, pool, command).ConfigureAwait(false);
            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), responseCode,
                "A wrong command HMAC against a noDA key over an unbound session is the session-index-encoded TPM_RC_BAD_AUTH.");

            TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(before.Value.LockoutCounter, after.Value.LockoutCounter, "Nothing lends the session dictionary-attack protection, so nothing must be charged.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_RSA_Decrypt()</c>'s single USER slot (Table 46's Auth Index 1) admits a password or an HMAC
    /// session under the key's authValue; a LOADED policy session presented there is refused the
    /// unimplemented-authorization-kind <c>TPM_RC_AUTH_TYPE</c> marker before any digest is compared against the
    /// key's <c>authPolicy</c> — the
    /// same posture <c>TPM2_Sign()</c>'s own USER slot carries, even when the policy session has already
    /// asserted <c>TPM2_PolicyAuthValue()</c> and would otherwise satisfy that policy. The refusal is decided at
    /// the first authorizing slot, ahead of a decrypt companion queued behind it on <c>cipherText</c>, so the
    /// companion never runs either
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part
    /// 3, clause 5.6</see>; Part 1: Architecture, clause 16.2).
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptRefusesALoadedPolicySessionAtTheUserSlotBareAuthTypeAheadOfADecryptCompanion()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptRefusesALoadedPolicySessionAtTheUserSlotBareAuthTypeAheadOfADecryptCompanion), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using RsaKeyMaterial key = RsaKeyMaterial.Generate();
        byte[] cipherText = key.Key.Encrypt(PlaintextBytes, RSAEncryptionPadding.Pkcs1);
        byte[] authPolicy = PolicyAuthValueDigest();

        TpmResult<LoadExternalResponse> loadResult = await LoadRsaDecryptKeyAsync(
            tpm, registry, pool, ExternalDecryptAttributes, TpmtRsaScheme.RsaEs, key.Modulus, key.P, KeyPasswordBytes, authPolicy).ConfigureAwait(false);
        Assert.IsTrue(loadResult.IsSuccess, $"TPM2_LoadExternal() (full RSA decrypt key with an authPolicy) failed: '{loadResult.ResponseCode}'.");
        using LoadExternalResponse loaded = loadResult.Value;

        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartPolicySession failed: '{startResult.ResponseCode}'.");
        StartAuthSessionResponse started = startResult.Value;
        uint policySessionHandle = started.SessionHandle.Value;

        (uint companionHandle, TpmSession companion) = await HmacKeyHarness.StartBoundHmacSessionAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmtSymDef.Xor(SessionAlg), isBoundToAuthorizedEntity: false, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using TpmSession policySession = new(new TpmHandle(policySessionHandle), started.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), pool);
            TpmResult<PolicyAuthValueResponse> authValueResult = await tpm.PolicyAuthValueAsync(policySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(authValueResult.IsSuccess, $"PolicyAuthValue failed: '{authValueResult.ResponseCode}'.");
            policySession.SetAuthValue(KeyPasswordBytes, pool);

            companion.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

            TpmResult<RsaDecryptResponse> result = await RsaDecryptOverSessionsAsync(
                tpm, registry, pool, [policySession, companion], loaded.ObjectHandle.Value, loaded.Name.AsReadOnlyMemory(), cipherText, TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
            if(result.IsSuccess)
            {
                result.Value.Dispose();
            }

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_AUTH_TYPE, result.ResponseCode,
                "A loaded policy session at TPM2_RSA_Decrypt()'s USER slot is refused the unimplemented-authorization-kind TPM_RC_AUTH_TYPE marker, even when it has already asserted PolicyAuthValue and a decrypt companion is queued behind it.");
        }
        finally
        {
            companion.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, companionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, policySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A restricted decrypt key is refused <c>TPM_RC_ATTRIBUTES</c> naming keyHandle, handle 1 of Table 46 —
    /// "The key referenced by keyHandle shall be an RSA key (TPM_RC_KEY) with restricted CLEAR and decrypt SET
    /// (TPM_RC_ATTRIBUTES)"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 14.3.1) — AFTER the session's command HMAC has verified, and
    /// the refusal rolls no nonce: the SAME session then succeeds on an unrestricted key without a restart.
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptRefusesARestrictedKeyAfterTheHmacWithNoNonceRollThenSucceedsOnAnUnrestrictedKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptRefusesARestrictedKeyAfterTheHmacWithNoNonceRollThenSucceedsOnAnUnrestrictedKey), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse restrictedKey = await CreateRestrictedRsaDecryptPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        using CreatePrimaryResponse unrestrictedKey = await CreateRsaDecryptPrimaryAsync(tpm, registry, pool, TpmtRsaScheme.RsaEs, isNoDa: true).ConfigureAwait(false);
        byte[] cipherText = EncryptRsaesToPublicModulus(unrestrictedKey.OutPublic.PublicArea.Unique.GetRsaModulus(), PlaintextBytes);

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, KeyPasswordBytes).ConfigureAwait(false);
        try
        {
            byte[] beforeRefusal = session.NonceTpm.ToArray();

            TpmResult<RsaDecryptResponse> refused = await RsaDecryptOverSessionsAsync(
                tpm, registry, pool, [session], restrictedKey.ObjectHandle.Value, restrictedKey.Name.AsReadOnlyMemory(), cipherText, TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
            if(refused.IsSuccess)
            {
                refused.Value.Dispose();
            }

            Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 0), refused.ResponseCode, "A restricted decrypt key must be refused handle-encoded TPM_RC_ATTRIBUTES (keyHandle, H1) after the session's command HMAC has verified.");
            Assert.IsTrue(session.NonceTpm.Span.SequenceEqual(beforeRefusal), "A header-only error response carries no authorization area, so the session's nonceTPM must not roll.");

            TpmResult<RsaDecryptResponse> corrected = await RsaDecryptOverSessionsAsync(
                tpm, registry, pool, [session], unrestrictedKey.ObjectHandle.Value, unrestrictedKey.Name.AsReadOnlyMemory(), cipherText, TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
            Assert.IsTrue(corrected.IsSuccess, $"The SAME session must succeed on an unrestricted key without a restart: '{corrected.ResponseCode}'.");
            using RsaDecryptResponse response = corrected.Value;
            Assert.IsTrue(response.Message.Buffer.SequenceEqual(PlaintextBytes), "The corrected retry must recover the off-TPM plaintext.");
            Assert.IsFalse(session.NonceTpm.Span.SequenceEqual(beforeRefusal), "The successful retry, and only it, rolls the session's nonceTPM.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>cipherText.size != k</c> is refused <c>TPM_RC_SIZE</c> naming cipherText, parameter 1 of Table 46 —
    /// "An encrypted RSA data block is the size of the public modulus"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 14.3, Table 46's NOTE) — AFTER the session's command HMAC
    /// has verified, and the refusal rolls no nonce: the SAME session then succeeds on the correct-width
    /// ciphertext without a restart.
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptRefusesAShortCipherTextAfterTheHmacWithNoNonceRollThenSucceedsOnTheCorrectWidth()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptRefusesAShortCipherTextAfterTheHmacWithNoNonceRollThenSucceedsOnTheCorrectWidth), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateRsaDecryptPrimaryAsync(tpm, registry, pool, TpmtRsaScheme.RsaEs, isNoDa: true).ConfigureAwait(false);
        byte[] cipherText = EncryptRsaesToPublicModulus(key.OutPublic.PublicArea.Unique.GetRsaModulus(), PlaintextBytes);
        byte[] shortCipherText = cipherText[1..];

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, KeyPasswordBytes).ConfigureAwait(false);
        try
        {
            byte[] beforeRefusal = session.NonceTpm.ToArray();

            TpmResult<RsaDecryptResponse> refused = await RsaDecryptOverSessionsAsync(
                tpm, registry, pool, [session], key.ObjectHandle.Value, key.Name.AsReadOnlyMemory(), shortCipherText, TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
            if(refused.IsSuccess)
            {
                refused.Value.Dispose();
            }

            Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), refused.ResponseCode, "A k-1 octet cipherText must be refused parameter-encoded TPM_RC_SIZE (cipherText, P1) after the command HMAC has verified.");
            Assert.IsTrue(session.NonceTpm.Span.SequenceEqual(beforeRefusal), "The SIZE refusal must roll no nonce.");

            TpmResult<RsaDecryptResponse> corrected = await RsaDecryptOverSessionsAsync(
                tpm, registry, pool, [session], key.ObjectHandle.Value, key.Name.AsReadOnlyMemory(), cipherText, TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
            Assert.IsTrue(corrected.IsSuccess, $"The SAME session must succeed on the correct-width cipherText without a restart: '{corrected.ResponseCode}'.");
            using RsaDecryptResponse response = corrected.Value;
            Assert.IsTrue(response.Message.Buffer.SequenceEqual(PlaintextBytes), "The corrected retry must recover the off-TPM plaintext.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The generic <c>TPM2B_PUBLIC_KEY_RSA</c> structural bound (<c>MAX_RSA_KEY_BYTES</c>, 512 octets, TPM 2.0
    /// Library Part 2, clause 11.2.4.6, Table 194) is judged on the recovered value before the command reaches
    /// the narrower <c>cipherText.size != k</c> rule <see cref="RsaDecryptRefusesAShortCipherTextAfterTheHmacWithNoNonceRollThenSucceedsOnTheCorrectWidth"/>
    /// proves: a 513-octet <c>cipherText</c> — wider than any RSA public key this TPM can hold — is a failure of
    /// <c>cipherText</c>'s OWN content, never of the decrypt step, so it is parameter-encoded to
    /// <c>cipherText</c> itself, <c>TPM2_RSA_Decrypt()</c>'s first parameter (Table 46, index 0), judged after
    /// the command HMAC has verified.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.3, Table 46; Part 2, clause 6.6.2, Table 15</see>.
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptWithACipherTextWiderThanTheRsaKeyBoundReturnsParameterEncodedSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptWithACipherTextWiderThanTheRsaKeyBoundReturnsParameterEncodedSize), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateRsaDecryptPrimaryAsync(tpm, registry, pool, TpmtRsaScheme.Null, isNoDa: true).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, KeyPasswordBytes).ConfigureAwait(false);
        try
        {
            byte[] overBoundCipherText = new byte[Tpm2bPublicKeyRsa.MaxRsaKeyBytes + 1];
            overBoundCipherText.AsSpan().Fill(0x37);

            byte[] command = await FrameRsaDecryptWithRawCipherTextAsync(
                session, key.ObjectHandle.Value, key.Name.AsReadOnlyMemory(), overBoundCipherText, TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty, pool).ConfigureAwait(false);
            TpmRcConstants responseCode = await SubmitRawAsync(simulator, pool, command).ConfigureAwait(false);

            Assert.AreEqual(
                HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, parameterIndex: 0), responseCode,
                "cipherText is TPM2_RSA_Decrypt()'s first parameter (Table 46, index 0); a declared width past MAX_RSA_KEY_BYTES is that parameter's own content failure, judged ahead of the narrower cipherText.size != k rule.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A label mismatching the OAEP encryption side's is refused, undesignated and IMMEDIATE, with <c>TPM_RC_VALUE</c> — "If
    /// the padding checks fail, TPM_RC_VALUE is returned"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 14.3.1) — AFTER the session's command HMAC has verified, and
    /// the refusal rolls no nonce: the SAME session then succeeds on the correct label without a restart.
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptRefusesAWrongLabelAfterTheHmacWithNoNonceRollThenSucceedsOnTheCorrectLabel()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptRefusesAWrongLabelAfterTheHmacWithNoNonceRollThenSucceedsOnTheCorrectLabel), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateRsaDecryptPrimaryAsync(tpm, registry, pool, TpmtRsaScheme.Oaep(TpmAlgIdConstants.TPM_ALG_SHA256), isNoDa: true).ConfigureAwait(false);
        byte[] modulus = key.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();
        byte[] cipherText = await EncryptOaepToPublicModulusAsync(modulus, PlaintextBytes, CorrectLabelBytes, pool).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, KeyPasswordBytes).ConfigureAwait(false);
        try
        {
            byte[] beforeRefusal = session.NonceTpm.ToArray();

            TpmResult<RsaDecryptResponse> refused = await RsaDecryptOverSessionsAsync(
                tpm, registry, pool, [session], key.ObjectHandle.Value, key.Name.AsReadOnlyMemory(), cipherText, TpmtRsaDecrypt.Null, WrongLabelBytes).ConfigureAwait(false);
            if(refused.IsSuccess)
            {
                refused.Value.Dispose();
            }

            Assert.AreEqual(TpmRcConstants.TPM_RC_VALUE, refused.ResponseCode, "An OAEP label mismatching the encryption side's must be refused with an undesignated TPM_RC_VALUE, immediately, after the command HMAC has verified.");
            Assert.IsTrue(session.NonceTpm.Span.SequenceEqual(beforeRefusal), "The VALUE refusal must roll no nonce.");

            TpmResult<RsaDecryptResponse> corrected = await RsaDecryptOverSessionsAsync(
                tpm, registry, pool, [session], key.ObjectHandle.Value, key.Name.AsReadOnlyMemory(), cipherText, TpmtRsaDecrypt.Null, CorrectLabelBytes).ConfigureAwait(false);
            Assert.IsTrue(corrected.IsSuccess, $"The SAME session must succeed on the correct label without a restart: '{corrected.ResponseCode}'.");
            using RsaDecryptResponse response = corrected.Value;
            Assert.IsTrue(response.Message.Buffer.SequenceEqual(PlaintextBytes), "The corrected retry must recover the off-TPM plaintext.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>@keyHandle</c>'s Name is a cpHash term: <c>cpHash = H(commandCode ‖ Name(keyHandle) ‖ parameters)</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 15.7, equation 15, folded into the command HMAC of
    /// clause 16.6.5, equation 17), so a caller that folds a WRONG Name computes a different cpHash and its
    /// command HMAC no longer matches the TPM's — refused as an authorization failure even though the presented
    /// authorization value was the key's own; the same frame over the TRUE Name succeeds.
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptCpHashFoldsTheKeysNameAndAWrongNameFailsTheCommandHmac()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptCpHashFoldsTheKeysNameAndAWrongNameFailsTheCommandHmac), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateRsaDecryptPrimaryAsync(tpm, registry, pool, TpmtRsaScheme.RsaEs, isNoDa: true).ConfigureAwait(false);
        byte[] cipherText = EncryptRsaesToPublicModulus(key.OutPublic.PublicArea.Unique.GetRsaModulus(), PlaintextBytes);

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, KeyPasswordBytes).ConfigureAwait(false);
        try
        {
            byte[] staleName = key.Name.Span.ToArray();
            staleName[^1] ^= 0xFF;

            byte[] wrongNameCommand = await FrameRsaDecryptOverSessionAsync(
                session, key.ObjectHandle.Value, staleName, cipherText, TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty, pool).ConfigureAwait(false);
            TpmRcConstants wrongNameCode = await SubmitRawAsync(simulator, pool, wrongNameCommand).ConfigureAwait(false);
            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), wrongNameCode,
                "A command HMAC computed over a wrong keyHandle Name cannot match the TPM's own cpHash.");

            byte[] rightNameCommand = await FrameRsaDecryptOverSessionAsync(
                session, key.ObjectHandle.Value, key.Name.AsReadOnlyMemory(), cipherText, TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty, pool).ConfigureAwait(false);
            TpmRcConstants rightNameCode = await SubmitRawAsync(simulator, pool, rightNameCommand).ConfigureAwait(false);
            Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, rightNameCode, "The same frame over the true Name succeeds.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Pool hygiene over a session across four legs: an authorization refusal (a wrong authValue's command-HMAC
    /// mismatch), a post-HMAC transition refusal (a restricted decrypt key at the slot, <c>TPM_RC_ATTRIBUTES</c>
    /// naming keyHandle, handle 1 of Table 46), an effect refusal (a wrong OAEP label, <c>TPM_RC_VALUE</c> naming
    /// no field) and a success
    /// whose response is released — each leaves the pool with exactly the carriers outstanding before it: the
    /// session key, the authorization value, the nonces and the captured parameter area are all returned exactly
    /// once
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 14.3).
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptOverASessionReturnsEveryRentedCarrierToPoolAcrossAnAuthRefusalATransitionRefusalAnEffectRefusalAndASuccess()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptOverASessionReturnsEveryRentedCarrierToPoolAcrossAnAuthRefusalATransitionRefusalAnEffectRefusalAndASuccess), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse restrictedKey = await CreateRestrictedRsaDecryptPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        using CreatePrimaryResponse key = await CreateRsaDecryptPrimaryAsync(tpm, registry, pool, TpmtRsaScheme.RsaEs, isNoDa: true).ConfigureAwait(false);
        using CreatePrimaryResponse oaepKey = await CreateRsaDecryptPrimaryAsync(tpm, registry, pool, TpmtRsaScheme.Oaep(TpmAlgIdConstants.TPM_ALG_SHA256), isNoDa: true).ConfigureAwait(false);
        byte[] cipherText = EncryptRsaesToPublicModulus(key.OutPublic.PublicArea.Unique.GetRsaModulus(), PlaintextBytes);
        byte[] keyName = key.Name.Span.ToArray();
        byte[] restrictedKeyName = restrictedKey.Name.Span.ToArray();
        byte[] oaepKeyName = oaepKey.Name.Span.ToArray();
        byte[] oaepModulus = oaepKey.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();
        byte[] oaepCipherText = await EncryptOaepToPublicModulusAsync(oaepModulus, PlaintextBytes, CorrectLabelBytes, pool).ConfigureAwait(false);

        //The session the three post-authorization legs ride is loaded before the baseline is taken: a loaded
        //session's durable state (its session key and nonceTPM, and the client's own copies) is outstanding
        //by design for as long as the session lives, so the legs are measured against a pool that already
        //holds it. The authorization-refusal leg starts and flushes its own session before its assertion.
        (uint okSessionHandle, TpmSession okSession) = await StartUnboundSessionAsync(tpm, registry, pool, KeyPasswordBytes).ConfigureAwait(false);
        long baseline = trackingPool.OutstandingCount;

        (uint refusedSessionHandle, TpmSession refusedSession) = await StartUnboundSessionAsync(tpm, registry, pool, WrongKeyPasswordBytes).ConfigureAwait(false);
        try
        {
            TpmResult<RsaDecryptResponse> authRefused = await RsaDecryptOverSessionsAsync(
                tpm, registry, pool, [refusedSession], key.ObjectHandle.Value, keyName, cipherText, TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
            Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, authRefused.BaseError, "The authorization-refused round trip must be a genuine wrong-authValue command-HMAC failure.");
        }
        finally
        {
            refusedSession.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, refusedSessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The authorization refusal alone must return every rented carrier to the pool.");

        try
        {
            TpmResult<RsaDecryptResponse> transitionRefused = await RsaDecryptOverSessionsAsync(
                tpm, registry, pool, [okSession], restrictedKey.ObjectHandle.Value, restrictedKeyName, cipherText, TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
            if(transitionRefused.IsSuccess)
            {
                transitionRefused.Value.Dispose();
            }

            Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 0), transitionRefused.ResponseCode, "A restricted decrypt key must be refused handle-encoded TPM_RC_ATTRIBUTES (keyHandle, H1) after the session's command HMAC has verified.");
            Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The post-HMAC transition refusal must return every rented carrier to the pool.");

            TpmResult<RsaDecryptResponse> effectRefused = await RsaDecryptOverSessionsAsync(
                tpm, registry, pool, [okSession], oaepKey.ObjectHandle.Value, oaepKeyName, oaepCipherText, TpmtRsaDecrypt.Null, WrongLabelBytes).ConfigureAwait(false);
            if(effectRefused.IsSuccess)
            {
                effectRefused.Value.Dispose();
            }

            Assert.AreEqual(TpmRcConstants.TPM_RC_VALUE, effectRefused.ResponseCode, "An OAEP label mismatching the encryption side's must be refused with an undesignated TPM_RC_VALUE.");
            Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The effect refusal must return every rented carrier to the pool.");

            TpmResult<RsaDecryptResponse> ok = await RsaDecryptOverSessionsAsync(
                tpm, registry, pool, [okSession], key.ObjectHandle.Value, keyName, cipherText, TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
            Assert.IsTrue(ok.IsSuccess, $"The successful round trip must decrypt with the CORRECT authValue: '{ok.ResponseCode}'.");
            ok.Value.Dispose();
            Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The success leg must return every rented carrier to the pool.");
        }
        finally
        {
            okSession.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, okSessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// An unbound HMAC session at <c>@keyHandle</c> folding an HMAC (KEYEDHASH) object's own authorization value
    /// runs THAT object's own USER ladder first — the correct password passes it — and only then reaches
    /// <c>TPM2_RSA_Decrypt()</c>'s own type gate: "The key referenced by keyHandle shall be an RSA key
    /// (TPM_RC_KEY)"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 14.3.1).
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptOverAnUnboundHmacSessionFoldingAnHmacKeysOwnAuthValueIsBareKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptOverAnUnboundHmacSessionFoldingAnHmacKeysOwnAuthValueIsBareKey), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint hmacKeyHandle, byte[] hmacKeyName) = await CreateAndLoadHmacKeyAsync(tpm, registry, pool, KeyPasswordBytes, isNoDa: true).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, KeyPasswordBytes).ConfigureAwait(false);
        try
        {
            TpmResult<RsaDecryptResponse> result = await RsaDecryptOverSessionsAsync(
                tpm, registry, pool, [session], hmacKeyHandle, hmacKeyName, new byte[RsaKeyBits / 8], TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
            if(result.IsSuccess)
            {
                result.Value.Dispose();
            }

            Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_KEY, 0), result.ResponseCode, "An HMAC object at keyHandle, correctly authorized over the session, is handle-encoded TPM_RC_KEY (keyHandle, H1).");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A WRONG authorization value folded into the session for a <c>noDA</c> HMAC (KEYEDHASH) object at
    /// <c>@keyHandle</c> is refused from THAT object's own KEYEDHASH ladder — the session-index-encoded
    /// <c>TPM_RC_BAD_AUTH</c> — proving the command HMAC key's <c>authValue</c> term is the KEYEDHASH's own,
    /// since the session key concatenates a sessionKey to an authValue: "A sessionKey value is concatenated to
    /// an authValue to create the key that is used in the computation of the HMAC in a command or response"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 16.6.5, equation 17).
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptOverAnUnboundHmacSessionFoldingAnHmacKeysWrongAuthValueIsSessionEncodedBadAuth()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptOverAnUnboundHmacSessionFoldingAnHmacKeysWrongAuthValueIsSessionEncodedBadAuth), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint hmacKeyHandle, byte[] hmacKeyName) = await CreateAndLoadHmacKeyAsync(tpm, registry, pool, KeyPasswordBytes, isNoDa: true).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, WrongKeyPasswordBytes).ConfigureAwait(false);
        try
        {
            TpmResult<RsaDecryptResponse> result = await RsaDecryptOverSessionsAsync(
                tpm, registry, pool, [session], hmacKeyHandle, hmacKeyName, new byte[RsaKeyBits / 8], TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
            if(result.IsSuccess)
            {
                result.Value.Dispose();
            }

            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), result.ResponseCode,
                "A wrong authValue against a noDA HMAC object's own ladder is the session-index-encoded TPM_RC_BAD_AUTH, before TPM2_RSA_Decrypt()'s own type gate is ever reached.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// An unbound HMAC session at <c>@keyHandle</c> folding an open hash sequence context's own authorization
    /// value runs THAT sequence's own USER ladder first — the correct password passes it, folding the
    /// sequence's Name as the Empty Buffer: "If an authorization or audit for a sequence object requires
    /// computation of a cpHash and an rpHash, the Name associated with sequenceHandle will be the Empty
    /// Buffer" — and only then reaches <c>TPM2_RSA_Decrypt()</c>'s own type gate: <c>TPM_RC_KEY</c> naming
    /// keyHandle, handle 1 of Table 46
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 29.4.6).
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptOverAnUnboundHmacSessionFoldingAHashSequencesAuthValueIsBareKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptOverAnUnboundHmacSessionFoldingAHashSequencesAuthValueIsBareKey), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using HashSequenceStartInput startInput = HashSequenceStartInput.CreateFromPassword(KeyPassword, TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256), pool);
        TpmResult<HashSequenceStartResponse> startResult = await TpmCommandExecutor.ExecuteAsync<HashSequenceStartResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"HashSequenceStart failed: '{startResult.ResponseCode}'.");
        uint sequenceHandle = startResult.Value.SequenceHandle.Value;

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, KeyPasswordBytes).ConfigureAwait(false);
        try
        {
            byte[] command = await FrameRsaDecryptOverSessionAsync(
                session, sequenceHandle, ReadOnlyMemory<byte>.Empty, new byte[RsaKeyBits / 8], TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty, pool).ConfigureAwait(false);
            TpmRcConstants responseCode = await SubmitRawAsync(simulator, pool, command).ConfigureAwait(false);

            Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_KEY, 0), responseCode, "A hash sequence context, correctly authorized over the session with its Name folded as the Empty Buffer, is handle-encoded TPM_RC_KEY (keyHandle, H1).");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Check 1 precedes verification of the authorization area itself: a public-only RSA decrypt key loaded
    /// through <c>TPM2_LoadExternal()</c> is refused the format-zero <c>TPM_RC_AUTH_UNAVAILABLE</c> even under an HMAC
    /// session whose command HMAC is deliberately wrong — "The public and sensitive portions of the object
    /// shall be present on the TPM (TPM_RC_AUTH_UNAVAILABLE)" is judged before the session area is ever
    /// verified, so a tampered command HMAC never surfaces as the session-index-encoded TPM_RC_BAD_AUTH
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 5.6).
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptOverAnHmacSessionAgainstAPublicOnlyKeyIsBareAuthUnavailableAheadOfTheSessionGate()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaDecryptOverAnHmacSessionAgainstAPublicOnlyKeyIsBareAuthUnavailableAheadOfTheSessionGate), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using RsaKeyMaterial key = RsaKeyMaterial.Generate();

        TpmResult<LoadExternalResponse> loadResult = await LoadPublicOnlyRsaDecryptKeyAsync(tpm, registry, pool, key, TpmtRsaScheme.Null).ConfigureAwait(false);
        Assert.IsTrue(loadResult.IsSuccess, $"TPM2_LoadExternal() (public-only RSA key) failed: '{loadResult.ResponseCode}'.");
        using LoadExternalResponse loaded = loadResult.Value;
        byte[] loadedName = loaded.Name.Span.ToArray();

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, KeyPasswordBytes).ConfigureAwait(false);
        try
        {
            byte[] command = await FrameRsaDecryptOverSessionAsync(
                session, loaded.ObjectHandle.Value, loadedName, new byte[RsaKeyBits / 8], TpmtRsaDecrypt.Null, ReadOnlyMemory<byte>.Empty, pool).ConfigureAwait(false);
            TamperLastHmacOctet(command);
            TpmRcConstants responseCode = await SubmitRawAsync(simulator, pool, command).ConfigureAwait(false);

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, responseCode,
                "A public-only key has no sensitive portion to authorize against: the format-zero TPM_RC_AUTH_UNAVAILABLE, even under a deliberately tampered command HMAC.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Issues <c>TPM2_RSA_Decrypt()</c> through the production executor over <paramref name="sessions"/> and returns the raw result.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sessions">The authorization area's sessions, in slot order.</param>
    /// <param name="keyHandle">The decrypt key's handle.</param>
    /// <param name="keyName">The key's Name, cpHash's single handle-Name term.</param>
    /// <param name="cipherText">The ciphertext to decrypt.</param>
    /// <param name="inScheme">The padding scheme to use if the key's own scheme is <c>TPM_ALG_NULL</c>.</param>
    /// <param name="label">The label whose association with the message is to be verified, or empty for none.</param>
    /// <returns>The raw result; the caller disposes the value on success.</returns>
    private async Task<TpmResult<RsaDecryptResponse>> RsaDecryptOverSessionsAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmSessionBase[] sessions,
        uint keyHandle, ReadOnlyMemory<byte> keyName, ReadOnlyMemory<byte> cipherText, TpmtRsaDecrypt inScheme, ReadOnlyMemory<byte> label)
    {
        using Tpm2bPublicKeyRsa cipherTextCarrier = Tpm2bPublicKeyRsa.Create(cipherText.Span, pool);
        using Tpm2bData labelCarrier = label.IsEmpty ? Tpm2bData.Empty : Tpm2bData.Create(label.Span, pool);
        var input = new RsaDecryptInput(TpmiDhObject.FromValue(keyHandle), cipherTextCarrier, inScheme, labelCarrier);

        return await TpmCommandExecutor.ExecuteAsync<RsaDecryptResponse>(
            tpm, input, sessions, [keyName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Starts a real, unbound and unsalted HMAC session negotiating no symmetric algorithm and folds
    /// <paramref name="authValue"/> into it, with <c>continueSession</c> SET. The caller disposes the session and
    /// flushes the handle.
    /// </summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="authValue">The authorization value the session's command HMAC folds; empty for none.</param>
    /// <returns>The session handle and the host session.</returns>
    private async Task<(uint SessionHandle, TpmSession Session)> StartUnboundSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, ReadOnlyMemory<byte> authValue)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (unbound, unsalted HMAC) failed: '{startResult.ResponseCode}'.");

        //The response owns nothing but nonceTPM, which the session takes over, so it is deliberately not disposed.
        StartAuthSessionResponse started = startResult.Value;
        var session = new TpmSession(new TpmHandle(started.SessionHandle.Value), started.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), pool);
        if(!authValue.IsEmpty)
        {
            session.SetAuthValue(authValue.Span, pool);
        }

        session.SessionAttributes = TpmaSession.CONTINUE_SESSION;

        return (started.SessionHandle.Value, session);
    }

    /// <summary>Creates a primary, unrestricted RSA decrypt key under the owner hierarchy, authorized by <see cref="KeyPassword"/>.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="scheme">The key's own decryption scheme.</param>
    /// <param name="isNoDa">Whether the template sets <c>noDA</c>, exempting the key from dictionary-attack protection.</param>
    /// <returns>The CreatePrimary response; the caller owns it.</returns>
    private async Task<CreatePrimaryResponse> CreateRsaDecryptPrimaryAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmtRsaScheme scheme, bool isNoDa)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForRsaDecryptKey(TpmRh.TPM_RH_OWNER, KeyPassword, RsaKeyBits, scheme, pool, noDa: isNoDa);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (unrestricted RSA decrypt key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates a primary RSA STORAGE PARENT (restricted, decrypt SET) under the owner hierarchy, authorized by
    /// <see cref="KeyPassword"/> — the restricted key the ATTRIBUTES-refusal test presents at <c>keyHandle</c>.
    /// </summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response; the caller owns it.</returns>
    private async Task<CreatePrimaryResponse> CreateRestrictedRsaDecryptPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForRsaStorageParent(TpmRh.TPM_RH_OWNER, KeyPassword, RsaKeyBits, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (restricted RSA storage parent) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Issues <c>TPM2_LoadExternal()</c> for a FULL RSA decrypt key (a real sensitive area, one prime factor
    /// supplied) under <c>TPM_RH_NULL</c>, carrying <paramref name="authValue"/> as its authorization value — the
    /// known-private-key path a real session can fold a genuine authValue against.
    /// </summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="attributes">The public area's attribute word.</param>
    /// <param name="scheme">The key's own decryption scheme.</param>
    /// <param name="modulus">The public modulus.</param>
    /// <param name="prime">One prime factor.</param>
    /// <param name="authValue">The authorization value to install.</param>
    /// <param name="authPolicy">The authorization policy digest to carry into the public area, or empty for none.</param>
    /// <returns>The raw result; the caller disposes the value on success.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the public and sensitive areas transfers to the load input, disposed here once the command has been issued.")]
    private async Task<TpmResult<LoadExternalResponse>> LoadRsaDecryptKeyAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmaObject attributes, TpmtRsaScheme scheme,
        ReadOnlyMemory<byte> modulus, ReadOnlyMemory<byte> prime, ReadOnlyMemory<byte> authValue, ReadOnlyMemory<byte> authPolicy = default)
    {
        Tpm2bPublic inPublic = Tpm2bPublic.CreateRsaSigningKey(SessionAlg, attributes, RsaKeyBits, scheme, modulus.Span, pool, authPolicy.Span);
        TpmtSensitive inPrivate = new(
            authValue.IsEmpty ? Tpm2bAuth.CreateEmpty(pool) : Tpm2bAuth.Create(authValue.Span, pool),
            Tpm2bDigest.Empty,
            TpmuSensitiveComposite.FromRsa(Tpm2bPrivateKeyRsa.Create(prime.Span, pool)));
        using var input = new LoadExternalInput(inPrivate, inPublic, TpmiRhHierarchy.Null);

        return await TpmCommandExecutor.ExecuteAsync<LoadExternalResponse>(tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Loads a framework RSA key's public area only (no sensitive area) as an unrestricted decrypt key under the
    /// owner hierarchy — the shape Part 3, clause 5.6's check 1 refuses regardless of the session presented.
    /// </summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="key">The framework key material.</param>
    /// <param name="scheme">The key's own decryption scheme.</param>
    /// <returns>The raw result; the caller disposes the value on success.</returns>
    private async Task<TpmResult<LoadExternalResponse>> LoadPublicOnlyRsaDecryptKeyAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, RsaKeyMaterial key, TpmtRsaScheme scheme)
    {
        using Tpm2bPublic inPublic = Tpm2bPublic.CreateRsaSigningKey(SessionAlg, PublicOnlyDecryptAttributes, RsaKeyBits, scheme, key.Modulus, pool);
        using var input = new LoadExternalInput(null, inPublic, TpmiRhHierarchy.Owner);

        return await TpmCommandExecutor.ExecuteAsync<LoadExternalResponse>(tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Creates and loads a password-protected HMAC (KEYEDHASH) key under a fresh RSA storage parent.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="password">The key's authorization value.</param>
    /// <param name="isNoDa">Whether the HMAC key is exempt from dictionary-attack protection.</param>
    /// <returns>The loaded key's transient handle and its Name.</returns>
    private async Task<(uint Handle, byte[] Name)> CreateAndLoadHmacKeyAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, ReadOnlyMemory<byte> password, bool isNoDa)
    {
        using CreatePrimaryInput parentInput = CreatePrimaryInput.ForRsaStorageParent(TpmRh.TPM_RH_OWNER, null, RsaKeyBits, pool, noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> parentResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, parentInput, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(parentResult.IsSuccess, $"CreatePrimary (RSA storage parent) failed: '{parentResult.ResponseCode}'.");
        using CreatePrimaryResponse parent = parentResult.Value;

        using Tpm2bSensitiveCreate hmacSensitive = Tpm2bSensitiveCreate.ForHmacKey(ReadOnlySpan<byte>.Empty, password.Span, pool);
        using Tpm2bPublic hmacTemplate = Tpm2bPublic.CreateHmacKeyTemplate(
            SessionAlg, TpmAlgIdConstants.TPM_ALG_SHA256, pool, authPolicy: default, noDa: isNoDa, userWithAuth: true, isDuplicable: false, isRestricted: false, isSensitiveDataOrigin: true);
        using var createInput = new CreateInput(parent.ObjectHandle.Value, hmacSensitive, hmacTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, createInput, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"Create (HMAC key) failed: '{createResult.ResponseCode}'.");
        using CreateResponse created = createResult.Value;

        using var loadInput = new LoadInput(parent.ObjectHandle.Value, created.OutPrivate, created.OutPublic);
        using TpmPasswordSession loadParentAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<LoadResponse> loadResult = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
            tpm, loadInput, [loadParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(loadResult.IsSuccess, $"Load (HMAC key) failed: '{loadResult.ResponseCode}'.");
        using LoadResponse loaded = loadResult.Value;

        return (loaded.ObjectHandle.Value, loaded.Name.Span.ToArray());
    }

    /// <summary>
    /// Defines the dictionary-attack-protected Ordinary Index at <see cref="DaProtectedBindIndexHandle"/> with
    /// <see cref="BindIndexAuthBytes"/> as its authValue, authorized by the empty owner authValue over a password
    /// session.
    /// </summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task DefineDaProtectedIndexAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);
        using var auth = Tpm2bAuth.Create(BindIndexAuthBytes, pool);
        using var publicInfo = new TpmsNvPublic(DaProtectedBindIndexHandle, SessionAlg, DaProtectedIndexAttributes, Tpm2bDigest.Empty, BindIndexDataSize);
        using var input = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, auth, publicInfo);

        TpmResult<NvDefineSpaceResponse> result = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            tpm, input, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_DefineSpace(0x{DaProtectedBindIndexHandle:X8}) failed: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// Hand-frames a <c>TPM2_RSA_Decrypt()</c> over <paramref name="session"/> with a genuine command HMAC over
    /// cpHash — the command code, <paramref name="keyNameForCpHash"/>, and the raw <c>cipherText ‖ inScheme ‖
    /// label</c> parameter area (TPM 2.0 Library Part 1, clause 15.7, equation 15) — so the Name a caller folds
    /// can be chosen independently of the handle it presents.
    /// </summary>
    /// <param name="session">The authorizing session, whose caller nonce this rolls.</param>
    /// <param name="keyHandle">The handle presented at <c>keyHandle</c>.</param>
    /// <param name="keyNameForCpHash">The Name folded into cpHash.</param>
    /// <param name="cipherText">The ciphertext to decrypt.</param>
    /// <param name="inScheme">The padding scheme to use if the key's own scheme is <c>TPM_ALG_NULL</c>.</param>
    /// <param name="label">The label, or empty for none.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The exact octets to submit.</returns>
    private async Task<byte[]> FrameRsaDecryptOverSessionAsync(
        TpmSession session, uint keyHandle, ReadOnlyMemory<byte> keyNameForCpHash, ReadOnlyMemory<byte> cipherText,
        TpmtRsaDecrypt inScheme, ReadOnlyMemory<byte> label, BaseMemoryPool pool)
    {
        using Tpm2bPublicKeyRsa cipherTextCarrier = Tpm2bPublicKeyRsa.Create(cipherText.Span, pool);
        using Tpm2bData labelCarrier = label.IsEmpty ? Tpm2bData.Empty : Tpm2bData.Create(label.Span, pool);

        int parametersLength = cipherTextCarrier.SerializedSize + inScheme.SerializedSize + labelCarrier.SerializedSize;
        using IMemoryOwner<byte> parametersOwner = pool.Rent(parametersLength);
        Memory<byte> parameters = parametersOwner.Memory[..parametersLength];
        {
            var parameterWriter = new TpmWriter(parameters.Span);
            cipherTextCarrier.WriteTo(ref parameterWriter);
            inScheme.WriteTo(ref parameterWriter);
            labelCarrier.WriteTo(ref parameterWriter);
        }

        session.RollNonceCaller(pool);

        int cpHashInputLength = sizeof(uint) + keyNameForCpHash.Length + parametersLength;
        using IMemoryOwner<byte> cpHashInputOwner = pool.Rent(cpHashInputLength);
        Memory<byte> cpHashInput = cpHashInputOwner.Memory[..cpHashInputLength];
        {
            var cpHashWriter = new TpmWriter(cpHashInput.Span);
            cpHashWriter.WriteUInt32((uint)TpmCcConstants.TPM_CC_RSA_Decrypt);
            cpHashWriter.WriteBytes(keyNameForCpHash.Span);
            cpHashWriter.WriteBytes(parameters.Span);
        }

        using DigestValue cpHash = await CryptographicKeyEvents.ComputeDigestAsync(
            cpHashInput, outputByteLength: CpHashDigestSize, tag: DigestTag(), pool: pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        using Tpm2bAuth? hmac = await session.PrepareAuthHmacAsync(cpHash.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);

        int authAreaSize = sizeof(uint) + session.GetAuthCommandSize();
        int totalSize = TpmHeader.HeaderSize + sizeof(uint) + authAreaSize + parametersLength;
        using IMemoryOwner<byte> commandOwner = pool.Rent(totalSize);
        Memory<byte> command = commandOwner.Memory[..totalSize];
        var writer = new TpmWriter(command.Span);
        writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_SESSIONS);
        writer.WriteUInt32((uint)totalSize);
        writer.WriteUInt32((uint)TpmCcConstants.TPM_CC_RSA_Decrypt);
        writer.WriteUInt32(keyHandle);
        writer.WriteUInt32((uint)session.GetAuthCommandSize());
        session.WriteAuthCommand(ref writer, hmac);
        writer.WriteBytes(parameters.Span);

        return command.Span.ToArray();
    }

    /// <summary>
    /// Hand-frames a <c>TPM2_RSA_Decrypt()</c> exactly as <see cref="FrameRsaDecryptOverSessionAsync"/> does,
    /// except <paramref name="cipherText"/> is written directly as a raw <c>TPM2B</c> (a 2-octet size then the
    /// octets themselves) rather than through <see cref="Tpm2bPublicKeyRsa.Create"/>, whose own bound check
    /// would otherwise refuse a width past <see cref="Tpm2bPublicKeyRsa.MaxRsaKeyBytes"/> before the frame ever
    /// reaches the wire — the shape needed to prove the TPM's OWN post-HMAC bound check rather than a
    /// client-side one.
    /// </summary>
    /// <param name="session">The authorizing session, whose caller nonce this rolls.</param>
    /// <param name="keyHandle">The handle presented at <c>keyHandle</c>.</param>
    /// <param name="keyNameForCpHash">The Name folded into cpHash.</param>
    /// <param name="cipherText">The raw ciphertext octets, of any length.</param>
    /// <param name="inScheme">The padding scheme to use if the key's own scheme is <c>TPM_ALG_NULL</c>.</param>
    /// <param name="label">The label, or empty for none.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The exact octets to submit.</returns>
    private async Task<byte[]> FrameRsaDecryptWithRawCipherTextAsync(
        TpmSession session, uint keyHandle, ReadOnlyMemory<byte> keyNameForCpHash, ReadOnlyMemory<byte> cipherText,
        TpmtRsaDecrypt inScheme, ReadOnlyMemory<byte> label, BaseMemoryPool pool)
    {
        using Tpm2bData labelCarrier = label.IsEmpty ? Tpm2bData.Empty : Tpm2bData.Create(label.Span, pool);

        int cipherTextFieldSize = sizeof(ushort) + cipherText.Length;
        int parametersLength = cipherTextFieldSize + inScheme.SerializedSize + labelCarrier.SerializedSize;
        using IMemoryOwner<byte> parametersOwner = pool.Rent(parametersLength);
        Memory<byte> parameters = parametersOwner.Memory[..parametersLength];
        {
            var parameterWriter = new TpmWriter(parameters.Span);
            parameterWriter.WriteTpm2b(cipherText.Span);
            inScheme.WriteTo(ref parameterWriter);
            labelCarrier.WriteTo(ref parameterWriter);
        }

        session.RollNonceCaller(pool);

        int cpHashInputLength = sizeof(uint) + keyNameForCpHash.Length + parametersLength;
        using IMemoryOwner<byte> cpHashInputOwner = pool.Rent(cpHashInputLength);
        Memory<byte> cpHashInput = cpHashInputOwner.Memory[..cpHashInputLength];
        {
            var cpHashWriter = new TpmWriter(cpHashInput.Span);
            cpHashWriter.WriteUInt32((uint)TpmCcConstants.TPM_CC_RSA_Decrypt);
            cpHashWriter.WriteBytes(keyNameForCpHash.Span);
            cpHashWriter.WriteBytes(parameters.Span);
        }

        using DigestValue cpHash = await CryptographicKeyEvents.ComputeDigestAsync(
            cpHashInput, outputByteLength: CpHashDigestSize, tag: DigestTag(), pool: pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        using Tpm2bAuth? hmac = await session.PrepareAuthHmacAsync(cpHash.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);

        int authAreaSize = sizeof(uint) + session.GetAuthCommandSize();
        int totalSize = TpmHeader.HeaderSize + sizeof(uint) + authAreaSize + parametersLength;
        using IMemoryOwner<byte> commandOwner = pool.Rent(totalSize);
        Memory<byte> command = commandOwner.Memory[..totalSize];
        var writer = new TpmWriter(command.Span);
        writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_SESSIONS);
        writer.WriteUInt32((uint)totalSize);
        writer.WriteUInt32((uint)TpmCcConstants.TPM_CC_RSA_Decrypt);
        writer.WriteUInt32(keyHandle);
        writer.WriteUInt32((uint)session.GetAuthCommandSize());
        session.WriteAuthCommand(ref writer, hmac);
        writer.WriteBytes(parameters.Span);

        return command.Span.ToArray();
    }

    /// <summary>
    /// Flips every bit of the LAST octet of the authorization slot's <c>hmac</c> field, navigating to it from the
    /// front of the frame past the one handle so the offset follows the actual nonce and hmac widths.
    /// </summary>
    /// <param name="command">The framed command, mutated in place.</param>
    private static void TamperLastHmacOctet(byte[] command)
    {
        var reader = new TpmReader(command);
        _ = TpmHeader.Parse(ref reader);
        _ = reader.ReadUInt32();
        _ = reader.ReadUInt32();
        _ = reader.ReadUInt32();

        ushort nonceSize = reader.ReadUInt16();
        reader.Skip(nonceSize);
        _ = reader.ReadByte();

        ushort hmacSize = reader.ReadUInt16();
        Assert.IsGreaterThan(0, hmacSize, "The arrangement must carry a non-empty hmac for the tamper to change one.");

        int lastHmacOctet = reader.Consumed + hmacSize - 1;
        command[lastHmacOctet] ^= 0xFF;
    }

    /// <summary>Submits raw, hand-framed octets straight to the simulator and returns the response code.</summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="command">The exact octets to submit.</param>
    /// <returns>The response code, still carrying any session-index encoding.</returns>
    private async Task<TpmRcConstants> SubmitRawAsync(TpmSimulator simulator, BaseMemoryPool pool, byte[] command)
    {
        TpmResult<TpmResponse> result = await simulator.SubmitAsync(command, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The transport itself must succeed even when the TPM refuses the command.");

        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());

        return (TpmRcConstants)TpmHeader.Parse(ref reader).Code;
    }

    /// <summary>The <c>TPM2_PolicyAuthValue()</c> policyDigest for <see cref="SessionAlg"/> — H(0 ‖ TPM_CC_PolicyAuthValue).</summary>
    /// <returns>The predicted digest.</returns>
    private static byte[] PolicyAuthValueDigest()
    {
        int size = TpmPolicyDigest.Size(SessionAlg);
        byte[] digest = new byte[size];
        Span<byte> zero = stackalloc byte[size];
        zero.Clear();
        _ = TpmPolicyDigest.ExtendForAuthValue(zero, SessionAlg, digest, BaseMemoryPool.Shared);

        return digest;
    }

    /// <summary>The tag describing a raw SHA-256 digest for the cpHash computation.</summary>
    /// <returns>The tag.</returns>
    private static Tag DigestTag() =>
        Tag.Create(HashAlgorithmName.SHA256).With(Purpose.Digest).With(EncodingScheme.Raw).With(MaterialSemantics.Direct);

    /// <summary>The symmetric definition a companion session negotiates for parameter encryption.</summary>
    /// <param name="isAesCfb">Whether to negotiate AES-128-CFB (else the XOR obfuscation).</param>
    /// <returns>The symmetric definition.</returns>
    private static TpmtSymDef Symmetric(bool isAesCfb) =>
        isAesCfb ? TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB) : TpmtSymDef.Xor(SessionAlg);

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> under RFC 8017 EME-PKCS1-v1_5 (RSAES) to a public-only RSA key
    /// reconstructed from an exported modulus and the conventional public exponent F4 — the off-TPM oracle for
    /// a CreatePrimary'd key, whose private material never leaves the simulator.
    /// </summary>
    /// <param name="modulus">The exported public modulus.</param>
    /// <param name="plaintext">The plaintext to encrypt.</param>
    /// <returns>The RSAES ciphertext, exactly the modulus width.</returns>
    private static byte[] EncryptRsaesToPublicModulus(ReadOnlySpan<byte> modulus, ReadOnlySpan<byte> plaintext)
    {
        var parameters = new RSAParameters { Modulus = modulus.ToArray(), Exponent = [0x01, 0x00, 0x01] };
        using RSA rsa = RSA.Create(parameters);

        return rsa.Encrypt(plaintext, RSAEncryptionPadding.Pkcs1);
    }

    /// <summary>
    /// OAEP-encrypts <paramref name="plaintext"/> under <paramref name="label"/> to a public-only RSA key,
    /// through the project's own <see cref="BouncyCastleTpmRsaOaepBackend"/> encrypt delegate — the only surface
    /// in this codebase that can carry TPM 2.0's custom OAEP label (the framework's own OAEP API has none).
    /// </summary>
    /// <param name="modulus">The exported public modulus.</param>
    /// <param name="plaintext">The plaintext to encrypt.</param>
    /// <param name="label">The OAEP label, including its terminating zero octet.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The OAEP ciphertext, exactly the modulus width.</returns>
    private async Task<byte[]> EncryptOaepToPublicModulusAsync(ReadOnlyMemory<byte> modulus, ReadOnlyMemory<byte> plaintext, ReadOnlyMemory<byte> label, BaseMemoryPool pool)
    {
        using IMemoryOwner<byte> ciphertext = await BouncyCastleTpmRsaOaepBackend.EncryptOaep(
            modulus, DefaultRsaExponent, plaintext, label, TpmAlgIdConstants.TPM_ALG_SHA256, TpmAlgIdConstants.TPM_ALG_SHA256, pool, TestContext.CancellationToken).ConfigureAwait(false);

        return ciphertext.Memory.Span.ToArray();
    }

    /// <summary>
    /// Wraps the simulator in a device that captures every <c>TPM2_RSA_Decrypt()</c> response's raw octets on
    /// their way back to the caller, without consuming or altering the result, so a confidentiality claim about
    /// the response can be checked against what actually crossed the wire.
    /// </summary>
    /// <param name="simulator">The simulator the command is submitted to.</param>
    /// <param name="capture">Receives the framed response's bytes on a successful <c>TPM2_RSA_Decrypt()</c> exchange.</param>
    /// <returns>The capturing device; the caller owns it.</returns>
    private static TpmDevice CreateRsaDecryptResponseCapturingDevice(TpmSimulator simulator, Action<byte[]> capture)
    {
        return TpmDevice.Create(async (command, commandPool, cancellationToken) =>
        {
            byte[] commandBytes = command.ToArray();
            TpmResult<TpmResponse> result = await simulator.SubmitAsync(command, commandPool, cancellationToken).ConfigureAwait(false);
            if(ReadCommandCode(commandBytes) == TpmCcConstants.TPM_CC_RSA_Decrypt && result.IsSuccess)
            {
                capture(result.Value.AsReadOnlySpan().ToArray());
            }

            return result;
        }, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
    }

    /// <summary>Reads a framed command's <c>commandCode</c> field (TPM 2.0 Library Part 1, clause 15.2.3's commandCode header field).</summary>
    /// <param name="command">The framed command.</param>
    /// <returns>The command code.</returns>
    private static TpmCcConstants ReadCommandCode(ReadOnlySpan<byte> command) =>
        (TpmCcConstants)BinaryPrimitives.ReadUInt32BigEndian(command[6..CommandHeaderSize]);

    /// <summary>Builds the response codec registry covering every command these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry() =>
        HmacKeyHarness.CreateRegistry()
            .Register(TpmCcConstants.TPM_CC_RSA_Decrypt, TpmResponseCodec.RsaDecrypt)
            .Register(TpmCcConstants.TPM_CC_LoadExternal, TpmResponseCodec.LoadExternal)
            .Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace)
            .Register(TpmCcConstants.TPM_CC_HashSequenceStart, TpmResponseCodec.HashSequenceStart);

    /// <summary>
    /// Creates a simulator with both the ECC (BouncyCastle, for the companion sessions' storage parent) and RSA
    /// (framework key generation, BouncyCastle RSAES/OAEP/raw) backends wired, powers it on, and brings it
    /// through <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// </summary>
    /// <param name="name">A per-test simulator identifier.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator; the caller owns it.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(string name, BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator(
            $"tpm-in-house-rsa-decrypt-session-{name}",
            signingBackend: BouncyCastleTpmEccSigningBackend.Create(),
            rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>
    /// Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator, mirroring how the executor frames an
    /// unauthorized command on the wire, to move it into <see cref="TpmLifecyclePhase.Operational"/>.
    /// </summary>
    /// <param name="simulator">The simulator to bring operational.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task BringOperationalAsync(TpmSimulator simulator, BaseMemoryPool pool)
    {
        var input = new StartupInput(TpmSuConstants.TPM_SU_CLEAR);
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);

        var writer = new TpmWriter(owner.Memory.Span[..length]);
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

    /// <summary>
    /// A framework-generated RSA-2048 key pair, the "known private key" material a <c>TPM2_LoadExternal()</c> FULL
    /// load carries into the simulator: the modulus and one prime factor go over the wire, and the framework
    /// object itself is the independent off-TPM encryption oracle.
    /// </summary>
    private sealed class RsaKeyMaterial: IDisposable
    {
        /// <summary>Gets the framework key, the off-TPM encryption oracle.</summary>
        public RSA Key { get; }

        /// <summary>Gets the public modulus, 256 octets.</summary>
        public byte[] Modulus { get; }

        /// <summary>Gets the first prime factor, 128 octets.</summary>
        public byte[] P { get; }

        /// <summary>Initializes the material from the framework key.</summary>
        /// <param name="key">The framework key; owned.</param>
        private RsaKeyMaterial(RSA key)
        {
            Key = key;
            RSAParameters parameters = key.ExportParameters(includePrivateParameters: true);
            Modulus = PadLeft(parameters.Modulus!, RsaKeyBits / 8);
            P = PadLeft(parameters.P!, RsaKeyBits / 16);
        }

        /// <summary>Mints a fresh RSA-2048 key pair.</summary>
        /// <returns>The material; the caller disposes it.</returns>
        public static RsaKeyMaterial Generate() => new(RSA.Create(RsaKeyBits));

        /// <summary>Releases the framework key and clears the prime.</summary>
        public void Dispose()
        {
            Array.Clear(P);
            Key.Dispose();
        }
    }

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
}
