using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.DictionaryAttack;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives the session-authorized form of <c>TPM2_Sign()</c> against the in-house behavioural
/// <see cref="TpmSimulator"/> — entirely in-process, with no external assets — through the production command
/// path (<see cref="TpmCommandExecutor"/> with the real <see cref="SignInput"/> and the real response codec).
/// Table 122's <c>@keyHandle</c> carries Auth Index 1 / Auth Role USER, so its authorization may ride a
/// <c>TPM_RS_PW</c> password slot or a loaded HMAC session, with the handle-less companion positions behind it
/// carrying <c>decrypt</c> or <c>encrypt</c> alone
/// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
/// Specification</see>, Part 3: Commands, clause 20.5; Part 1: Architecture, clause 15.6.1, Table 12).
/// </summary>
/// <remarks>
/// <para>
/// Every real session here verifies the response authorization end to end inside the executor
/// (<see cref="TpmSession.VerifyAndUpdateAsync"/>), so a response entry the simulator framed with the wrong key
/// or the wrong nonce fails the exchange rather than passing silently; the positive cases additionally verify
/// the produced signature <b>off-TPM</b> against a public key reconstructed solely from the exported public
/// area, or against the framework's own HMAC over the RFC 4231 key bytes.
/// </para>
/// <para>
/// The refusals split in two: an authorization-area or credential fault is blamed on the offending slot and
/// carries the session-index modifier (Part 2: Structures, clause 6.6.2), while the command's own rules run
/// only after the authorization has passed and the first parameter has been recovered, and carry Table 122's
/// own handle- or parameter-designated form (keyHandle, handle 1; digest, inScheme and validation, parameters
/// 1 through 3) — the same designated codes the password form answers (Part 3, clause 5.6 precedes clause 5.7
/// precedes clause 5.8).
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorSignSessionTests
{
    /// <summary>The hash algorithm every HMAC session in this class negotiates.</summary>
    private const TpmAlgIdConstants HmacSessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The number of bytes in a NIST P-256 coordinate or in an ECDSA r/s component.</summary>
    private const int P256ComponentSize = 32;

    /// <summary>The RSA modulus size in bits the RSA signing case uses.</summary>
    private const ushort Rsa2048KeyBits = 2048;

    /// <summary>The conventional RSA public exponent F4, used to reconstruct an exported modulus off-TPM.</summary>
    private const uint DefaultRsaExponent = 65537;

    /// <summary>The command header's fixed width: tag (UINT16), commandSize (UINT32), commandCode (UINT32).</summary>
    private const int CommandHeaderSize = 10;

    /// <summary>The lowered <c>maxTries</c> the Lockout case uses to reach Lockout mode in one wrong guess.</summary>
    private const uint LockoutTestMaxTries = 1;

    /// <summary>The password the signing keys of this class are created with.</summary>
    private const string SigningKeyPassword = "sign-over-session-key-auth";

    /// <summary>
    /// <see cref="SigningKeyPassword"/>'s UTF-8 octets, matching the password-to-authValue convention the
    /// creation side applies; the password carries no trailing zeros, so no trimming is in play.
    /// </summary>
    private static byte[] SigningKeyPasswordBytes { get; } = System.Text.Encoding.UTF8.GetBytes(SigningKeyPassword);

    /// <summary>A wrong guess at the signing key's authorization value, distinct from <see cref="SigningKeyPasswordBytes"/>.</summary>
    private static byte[] WrongSigningKeyPasswordBytes { get; } = [0x51, 0x52, 0x53, 0x54, 0x55];

    /// <summary>A fixed SHA-256-width digest to sign; arbitrary octets, tied to no published vector.</summary>
    private static byte[] Sha256WidthDigest { get; } = Convert.FromHexString("00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f");

    /// <summary>A SHA-1-width digest — the wrong width for a SHA-256-scheme HMAC key, which is what makes it a probe.</summary>
    private static byte[] Sha1WidthDigest { get; } = Convert.FromHexString("00112233445566778899aabbccddeeff10213243");

    /// <summary>The RFC 4231 test case 3 key: twenty octets of <c>0xaa</c>.</summary>
    private static byte[] Rfc4231Case3Key { get; } = Convert.FromHexString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    /// <summary>A short secret the sealed-object fixture seals; arbitrary octets tied to no published vector.</summary>
    private static byte[] SealedSecretBytes { get; } = [0x11, 0x22, 0x33, 0x44];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// A real, unbound and unsalted HMAC session at <c>TPM2_Sign()</c>'s single authorization slot, carrying the
    /// ECC signing key's own authorization value, signs: the key's authValue is folded into the command HMAC key
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 16.6.5, equation 17), the response authorization
    /// verifies end to end, and the ECDSA signature the simulator framed verifies off-TPM against a public key
    /// reconstructed solely from the exported public area — the session form producing exactly what the password
    /// form of Part 3: Commands, clause 20.5 produces.
    /// </summary>
    [TestMethod]
    public async Task SignOverAnUnboundHmacSessionProducesAVerifiableEcdsaSignature()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignOverAnUnboundHmacSessionProducesAVerifiableEcdsaSignature), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, SigningKeyPassword, isNoDa: true).ConfigureAwait(false);
        (uint sessionHandle, TpmSession session) = await StartUnboundHmacSessionAsync(tpm, registry, pool, SigningKeyPasswordBytes).ConfigureAwait(false);

        try
        {
            TpmResult<SignResponse> result = await SignOverSessionAsync(
                tpm, registry, pool, session, key.ObjectHandle.Value, key.Name.Span.ToArray(), Sha256WidthDigest,
                TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"TPM2_Sign() over an unbound HMAC session carrying the key's authValue must succeed: '{result.ResponseCode}'.");

            using SignResponse signature = result.Value;
            Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_ECDSA, signature.SignatureAlgorithm, "The framed TPMT_SIGNATURE must select the ECDSA member.");
            AssertEcdsaSignatureVerifies(key, signature, Sha256WidthDigest, "A signature produced over a session must verify against the key's exported public area exactly as the password form's does.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The same authorization over an RSA signing key: an unbound HMAC session carrying the key's authValue
    /// signs, and the RSASSA signature verifies off-TPM against the exported modulus — clause 20.5's key gate
    /// admits every signing key type identically once the session has proved the authValue
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.5, Table 122).
    /// </summary>
    [TestMethod]
    public async Task SignOverAnUnboundHmacSessionProducesAVerifiableRsassaSignature()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignOverAnUnboundHmacSessionProducesAVerifiableRsassaSignature), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForRsaSigningKey(
            TpmRh.TPM_RH_OWNER, SigningKeyPassword, keyBits: Rsa2048KeyBits, TpmtRsaScheme.Null, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (RSA 2048 signing key) failed: '{primaryResult.ResponseCode}'.");

        using CreatePrimaryResponse key = primaryResult.Value;
        (uint sessionHandle, TpmSession session) = await StartUnboundHmacSessionAsync(tpm, registry, pool, SigningKeyPasswordBytes).ConfigureAwait(false);

        try
        {
            TpmResult<SignResponse> result = await SignOverSessionAsync(
                tpm, registry, pool, session, key.ObjectHandle.Value, key.Name.Span.ToArray(), Sha256WidthDigest,
                TpmAlgIdConstants.TPM_ALG_RSASSA, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"TPM2_Sign() (RSASSA) over an unbound HMAC session must succeed: '{result.ResponseCode}'.");

            using SignResponse signature = result.Value;
            Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_RSASSA, signature.SignatureAlgorithm, "The framed TPMT_SIGNATURE must select the RSASSA member.");

            //Independent-oracle carve-out: the framework's RSA verifies wire-exported simulator output, sharing
            //no code path with the signer.
            var rsaParameters = new RSAParameters
            {
                Modulus = key.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray(),
                Exponent = [0x01, 0x00, 0x01]
            };

            using RSA rsa = RSA.Create(rsaParameters);
            Assert.IsTrue(
                rsa.VerifyHash(Sha256WidthDigest, signature.Signature.RsaSignature.Buffer.ToArray(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
                "An RSASSA signature produced over a session must verify against the key's exported modulus.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The KEYEDHASH row of Table 115 over a session: an unbound HMAC session carrying a loaded HMAC key's
    /// authorization value signs, and the framed <c>TPMT_HA</c> equals the framework's HMAC-SHA-256 over the RFC
    /// 4231 case 3 key bytes and the same digest — clause 20.5's <c>HMAC_h(bits, digest)</c>, unchanged by the
    /// authorization shape (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
    /// 2.0 Library Specification</see>, Part 3: Commands, clauses 20.1 (Table 115) and 20.5; the key bytes and
    /// the oracle are <see href="https://www.rfc-editor.org/rfc/rfc4231">RFC 4231</see>'s test case 3 key).
    /// </summary>
    [TestMethod]
    public async Task SignOverAnUnboundHmacSessionOverAnHmacKeyEqualsTheHmacOfTheDigest()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignOverAnUnboundHmacSessionOverAnHmacKeyEqualsTheHmacOfTheDigest), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256,
            userAuth: SigningKeyPasswordBytes, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartUnboundHmacSessionAsync(tpm, registry, pool, SigningKeyPasswordBytes).ConfigureAwait(false);

        try
        {
            TpmResult<SignResponse> result = await SignOverSessionAsync(
                tpm, registry, pool, session, key.Handle, key.Name.AsReadOnlyMemory(), Sha256WidthDigest,
                TpmAlgIdConstants.TPM_ALG_HMAC, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"TPM2_Sign() over an HMAC key authorized by a session must succeed: '{result.ResponseCode}'.");

            using SignResponse signature = result.Value;
            Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_HMAC, signature.SignatureAlgorithm, "The framed TPMT_SIGNATURE must select the HMAC member.");
            Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, signature.HashAlgorithm, "The TPMT_HA member must carry the key's own scheme hash.");

            byte[] expected = HMACSHA256.HashData(Rfc4231Case3Key, Sha256WidthDigest);
            Assert.IsTrue(
                signature.Signature.HmacSignature!.AsReadOnlyMemory().Span.SequenceEqual(expected),
                "The signature must be HMAC-SHA-256 of the digest under the key's bits, whatever authorized the key slot.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A session BOUND to the very key it authorizes signs with no per-command authorization value: binding
    /// already folded the key's authValue into the session key, so the command HMAC key omits it — the bind
    /// omission (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0
    /// Library Specification</see>, Part 1: Architecture, clause 16.6.10, equation 22) at
    /// <c>TPM2_Sign()</c>'s single authorized slot (Part 3: Commands, clause 20.5).
    /// </summary>
    [TestMethod]
    public async Task SignOverASessionBoundToTheSigningKeyItselfNeedsNoPerCommandAuthValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignOverASessionBoundToTheSigningKeyItselfNeedsNoPerCommandAuthValue), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, SigningKeyPassword, isNoDa: true).ConfigureAwait(false);

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession(key.ObjectHandle.Value, HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (bound to the signing key) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession session = await TpmSession.CreateBoundAsync(
                new TpmHandle(sessionHandle), SigningKeyPasswordBytes, startInput.NonceCaller, started.NonceTPM,
                HmacSessionAlg, TestEntropy.NewCounterStream(), pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION;

            TpmResult<SignResponse> result = await SignOverSessionAsync(
                tpm, registry, pool, session, key.ObjectHandle.Value, key.Name.Span.ToArray(), Sha256WidthDigest,
                TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
            Assert.IsTrue(
                result.IsSuccess,
                $"A session bound to the signing key itself must sign with the authValue folded into the bind alone: '{result.ResponseCode}'.");

            using SignResponse signature = result.Value;
            AssertEcdsaSignatureVerifies(key, signature, Sha256WidthDigest, "The bind-omission path must produce the same verifiable signature the folded-authValue path does.");
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A SALTED and BOUND session — bound to the signing key itself — signs: the salt folds in after the bind
    /// authorization value in the session-key KDFa
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 16.6.12, equation 25), so salting composes with the
    /// same bind omission of equation 22 at <c>TPM2_Sign()</c>'s key slot (Part 3: Commands, clause 20.5).
    /// </summary>
    [TestMethod]
    public async Task SignOverASaltedAndBoundSessionSignsTheDigest()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignOverASaltedAndBoundSessionSignsTheDigest), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, SigningKeyPassword, isNoDa: true).ConfigureAwait(false);

        using CreatePrimaryInput saltKeyInput = CreatePrimaryInput.ForRsaEndorsementKey(TpmRh.TPM_RH_OWNER, pool);
        using TpmPasswordSession saltOwnerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> saltKeyResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, saltKeyInput, [saltOwnerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(saltKeyResult.IsSuccess, $"CreatePrimary (RSA decrypt key for salting) failed: '{saltKeyResult.ResponseCode}'.");

        using CreatePrimaryResponse saltKey = saltKeyResult.Value;
        ReadOnlyMemory<byte> modulus = saltKey.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();
        TpmRsaSigningBackend rsaBackend = MicrosoftTpmRsaSigningBackend.Create();

        (StartAuthSessionInput startInput, IMemoryOwner<byte> salt, int saltLength) = await StartAuthSessionInputExtensions.CreateBoundAndSaltedHmacSession(
            saltKey.ObjectHandle.Value, key.ObjectHandle.Value, modulus, DefaultRsaExponent, HmacSessionAlg, HmacSessionAlg,
            rsaBackend.EncryptOaep, TestEntropy.NewCounterStream(), pool, TestContext.CancellationToken).ConfigureAwait(false);

        using(salt)
        {
            TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
                tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (salted and bound) failed: '{startResult.ResponseCode}'.");

            StartAuthSessionResponse started = startResult.Value;
            uint sessionHandle = started.SessionHandle.Value;

            try
            {
                using TpmSession session = await TpmSession.CreateBoundAsync(
                    new TpmHandle(sessionHandle), SigningKeyPasswordBytes, startInput.NonceCaller, started.NonceTPM,
                    HmacSessionAlg, TestEntropy.NewCounterStream(), pool, symmetric: TpmtSymDef.Null, salt: salt.Memory[..saltLength],
                    cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION;

                TpmResult<SignResponse> result = await SignOverSessionAsync(
                    tpm, registry, pool, session, key.ObjectHandle.Value, key.Name.Span.ToArray(), Sha256WidthDigest,
                    TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"A salted-and-bound session must sign: '{result.ResponseCode}'.");

                using SignResponse signature = result.Value;
                AssertEcdsaSignatureVerifies(key, signature, Sha256WidthDigest, "A salted-and-bound session must produce the same verifiable signature an unsalted one does.");
            }
            finally
            {
                await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            }
        }
    }

    /// <summary>
    /// Two consecutive <c>TPM2_Sign()</c> commands over ONE session each succeed, each adopting a genuinely
    /// rolled <c>nonceTPM</c> from its own response entry: a session's <c>nonceTPM</c> changes on every use
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 16.6.3), and the host adopts the new value only once
    /// the response HMAC of equation 17 (clause 16.6.5) has verified against that entry.
    /// </summary>
    [TestMethod]
    public async Task TwoConsecutiveSignsOverOneSessionSucceedAndRollTheNonce()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(TwoConsecutiveSignsOverOneSessionSucceedAndRollTheNonce), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, SigningKeyPassword, isNoDa: true).ConfigureAwait(false);
        (uint sessionHandle, TpmSession session) = await StartUnboundHmacSessionAsync(tpm, registry, pool, SigningKeyPasswordBytes).ConfigureAwait(false);

        try
        {
            byte[] keyName = key.Name.Span.ToArray();

            byte[] beforeFirst = session.NonceTpm.ToArray();
            TpmResult<SignResponse> first = await SignOverSessionAsync(
                tpm, registry, pool, session, key.ObjectHandle.Value, keyName, Sha256WidthDigest,
                TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
            Assert.IsTrue(first.IsSuccess, $"The first Sign over the session must succeed: '{first.ResponseCode}'.");
            first.Value.Dispose();

            Assert.IsFalse(
                session.NonceTpm.Span.SequenceEqual(beforeFirst),
                "The session must adopt a genuinely rolled nonceTPM from its own response entry, which it does only once that entry's response HMAC has verified.");

            byte[] beforeSecond = session.NonceTpm.ToArray();
            TpmResult<SignResponse> second = await SignOverSessionAsync(
                tpm, registry, pool, session, key.ObjectHandle.Value, keyName, Sha256WidthDigest,
                TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
            Assert.IsTrue(second.IsSuccess, $"A SECOND Sign over the SAME session must likewise succeed: '{second.ResponseCode}'.");
            second.Value.Dispose();

            Assert.IsFalse(
                session.NonceTpm.Span.SequenceEqual(beforeSecond),
                "The second command must again roll the session's nonceTPM from its own response entry.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A WRONG authorization value folded into a real session against a DA-protected signing key fails the key
    /// slot's command HMAC with the session-index-encoded <c>TPM_RC_AUTH_FAIL</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 6.6.2) and charges <c>failedTries</c> exactly once (Part
    /// 1: Architecture, clause 16.8.7) — the session form of the same check clause 20.5's password form applies.
    /// </summary>
    [TestMethod]
    public async Task SignOverASessionWithAWrongAuthValueOnADaProtectedKeyChargesFailedTries()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignOverASessionWithAWrongAuthValueOnADaProtectedKeyChargesFailedTries), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, SigningKeyPassword, isNoDa: false).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(before.IsSuccess, $"GetDictionaryAttackParameters failed: '{before.ResponseCode}'.");

        (uint sessionHandle, TpmSession session) = await StartUnboundHmacSessionAsync(tpm, registry, pool, WrongSigningKeyPasswordBytes).ConfigureAwait(false);

        try
        {
            TpmResult<SignResponse> result = await SignOverSessionAsync(
                tpm, registry, pool, session, key.ObjectHandle.Value, key.Name.Span.ToArray(), Sha256WidthDigest,
                TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
            if(result.IsSuccess)
            {
                result.Value.Dispose();
            }

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_AUTH_FAIL, result.BaseError,
                "A wrong authValue folded into a real key session against a DA-protected key must fail command-HMAC verification with TPM_RC_AUTH_FAIL.");
            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), result.ResponseCode,
                "The mismatch names the key slot (index 0), so the wire code carries its session-index modifier.");

            TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                before.Value.LockoutCounter + 1, after.Value.LockoutCounter,
                "A wrong authValue against a DA-protected signing key must charge failedTries exactly once.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The <c>noDA</c> contrast: a WRONG authorization value folded into a real session against a
    /// dictionary-attack-exempt signing key answers the UNCHARGED <c>TPM_RC_BAD_AUTH</c> rather than
    /// <c>TPM_RC_AUTH_FAIL</c>, still session-index-encoded to the key slot
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 16.8.1; Part 2: Structures, clause 6.6.2).
    /// </summary>
    [TestMethod]
    public async Task SignOverASessionWithAWrongAuthValueOnANoDaKeyReturnsBadAuthUncharged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignOverASessionWithAWrongAuthValueOnANoDaKeyReturnsBadAuthUncharged), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, SigningKeyPassword, isNoDa: true).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(before.IsSuccess, $"GetDictionaryAttackParameters failed: '{before.ResponseCode}'.");

        (uint sessionHandle, TpmSession session) = await StartUnboundHmacSessionAsync(tpm, registry, pool, WrongSigningKeyPasswordBytes).ConfigureAwait(false);

        try
        {
            TpmResult<SignResponse> result = await SignOverSessionAsync(
                tpm, registry, pool, session, key.ObjectHandle.Value, key.Name.Span.ToArray(), Sha256WidthDigest,
                TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
            if(result.IsSuccess)
            {
                result.Value.Dispose();
            }

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_BAD_AUTH, result.BaseError,
                "A wrong authValue against a noDA signing key must fail command-HMAC verification with the uncharged TPM_RC_BAD_AUTH.");
            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), result.ResponseCode,
                "The mismatch names the key slot (index 0), so the wire code carries its session-index modifier.");

            TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                before.Value.LockoutCounter, after.Value.LockoutCounter,
                "A noDA key's mismatch must move no dictionary-attack counter.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A signing key whose <c>TPMA_OBJECT.userWithAuth</c> is CLEAR refuses an HMAC session before any command
    /// HMAC is queued: "the authValue cannot be used for USER role authorization, meaning that authorization
    /// cannot be done using an HMAC session or a password"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 16.6.17; Part 3: Commands, clause 5.6, check 7.1). The
    /// answer is the BARE <c>TPM_RC_POLICY_FAIL</c> — never a session-index-encoded auth failure — and the key
    /// is DA-protected, so a reached credential comparison would have charged <c>failedTries</c>; it does not.
    /// </summary>
    [TestMethod]
    public async Task SignOverASessionWithAUserWithAuthClearKeyReturnsPolicyFailUncharged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignOverASessionWithAUserWithAuthClearKeyReturnsPolicyFailUncharged), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput primaryInput = CreateUserWithAuthClearEccSigningKeyInput(SigningKeyPassword);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (userWithAuth-CLEAR ECC signing key) failed: '{primaryResult.ResponseCode}'.");

        using CreatePrimaryResponse key = primaryResult.Value;

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(before.IsSuccess, $"GetDictionaryAttackParameters failed: '{before.ResponseCode}'.");

        (uint sessionHandle, TpmSession session) = await StartUnboundHmacSessionAsync(tpm, registry, pool, SigningKeyPasswordBytes).ConfigureAwait(false);

        try
        {
            TpmResult<SignResponse> result = await SignOverSessionAsync(
                tpm, registry, pool, session, key.ObjectHandle.Value, key.Name.Span.ToArray(), Sha256WidthDigest,
                TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
            if(result.IsSuccess)
            {
                result.Value.Dispose();
            }

            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_POLICY_FAIL, 0), result.ResponseCode,
                $"A userWithAuth-CLEAR signing key must refuse an HMAC session at keyHandle, session 1 of Table 122, even carrying the key's CORRECT authValue (got '{result.ResponseCode}').");

            TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                before.Value.LockoutCounter, after.Value.LockoutCounter,
                "TPM_RC_POLICY_FAIL is not TPM_RC_AUTH_FAIL, so the USER-role gate must move no dictionary-attack counter.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// With the TPM in Lockout mode a DA-protected signing key answers the bare <c>TPM_RC_LOCKOUT</c> even
    /// though the session carries the CORRECT authorization value: the dictionary-attack gate
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 5.6, check 3) precedes checks 7.1 and 9/10, so no
    /// credential is ever evaluated.
    /// </summary>
    [TestMethod]
    public async Task SignOverASessionWithADaProtectedKeyInLockoutReturnsLockout()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignOverASessionWithADaProtectedKeyInLockoutReturnsLockout), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, SigningKeyPassword, isNoDa: false).ConfigureAwait(false);

        TpmResult<DictionaryAttackParametersResponse> lowered = await tpm.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, LockoutTestMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds,
            TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lowered.IsSuccess, $"Lowering maxTries failed: '{lowered.ResponseCode}'.");

        //A single wrong password over the all-password form charges the DA-protected key and, with maxTries at
        //one, enters Lockout mode as a side effect.
        using(SignInput seedingInput = SignInput.ForEcdsa(key.ObjectHandle, Sha256WidthDigest, TpmAlgIdConstants.TPM_ALG_SHA256, pool))
        using(TpmPasswordSession wrongPassword = TpmPasswordSession.Create(WrongSigningKeyPasswordBytes, pool))
        {
            TpmResult<SignResponse> seeding = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
                tpm, seedingInput, [wrongPassword], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), seeding.ResponseCode,
                "The seeding mismatch must be a charged key-slot auth failure at session index 0.");
        }

        TpmResult<TpmDictionaryAttackParameters> lockedOut = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lockedOut.Value.IsLockedOut, "The TPM must be in Lockout mode before the session-form case runs.");

        (uint sessionHandle, TpmSession session) = await StartUnboundHmacSessionAsync(tpm, registry, pool, SigningKeyPasswordBytes).ConfigureAwait(false);

        try
        {
            TpmResult<SignResponse> result = await SignOverSessionAsync(
                tpm, registry, pool, session, key.ObjectHandle.Value, key.Name.Span.ToArray(), Sha256WidthDigest,
                TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
            if(result.IsSuccess)
            {
                result.Value.Dispose();
            }

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_LOCKOUT, result.ResponseCode,
                "A DA-protected signing key in Lockout mode must be refused bare before the session's credential is evaluated, correct or not.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The signing key's Name is a cpHash term: <c>cpHash = H(commandCode ‖ Name(keyHandle) ‖ parameters)</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 15.7, equation 15, folded into the command HMAC of
    /// clause 16.6.5, equation 17), so a caller that folds a STALE or WRONG Name computes a different cpHash and
    /// its command HMAC no longer matches the TPM's — refused as an authorization failure at the key slot even
    /// though the authorization value presented was the key's own. The key is <c>noDA</c>, so the refusal is the
    /// uncharged <c>TPM_RC_BAD_AUTH</c>; the DA standing alone decides between that and <c>TPM_RC_AUTH_FAIL</c>.
    /// </summary>
    [TestMethod]
    public async Task SignOverASessionWithAWrongKeyNameInTheCallersCpHashFailsTheCommandHmac()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignOverASessionWithAWrongKeyNameInTheCallersCpHashFailsTheCommandHmac), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, SigningKeyPassword, isNoDa: true).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(before.IsSuccess, $"GetDictionaryAttackParameters failed: '{before.ResponseCode}'.");

        (uint sessionHandle, TpmSession session) = await StartUnboundHmacSessionAsync(tpm, registry, pool, SigningKeyPasswordBytes).ConfigureAwait(false);

        try
        {
            //The genuine Name with one octet of its digest flipped: the same width and the same nameAlg, so
            //nothing but the cpHash term differs.
            byte[] staleName = key.Name.Span.ToArray();
            staleName[^1] ^= 0xFF;

            TpmResult<SignResponse> result = await SignOverSessionAsync(
                tpm, registry, pool, session, key.ObjectHandle.Value, staleName, Sha256WidthDigest,
                TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
            if(result.IsSuccess)
            {
                result.Value.Dispose();
            }

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_BAD_AUTH, result.BaseError,
                "A wrong keyName in the caller's cpHash must fail the key slot's command HMAC, proving the Name is a cpHash term rather than decoration.");
            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), result.ResponseCode,
                "The mismatch names the key slot (index 0), so the wire code carries its session-index modifier.");

            TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                before.Value.LockoutCounter, after.Value.LockoutCounter,
                "The key is noDA, so its command-HMAC mismatch moves no dictionary-attack counter.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>digest</c> is <c>TPM2_Sign()</c>'s first command parameter and a sized <c>TPM2B_DIGEST</c> (Table
    /// 122), so a session carrying <c>decrypt</c> may protect it — "Any first parameter can be encrypted as long
    /// as the parameter has a size field"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 18.1). Over XOR obfuscation the digest crosses the wire
    /// transformed and the simulator recovers it under the same <c>sessionKey ‖ authValue</c> keystream the host
    /// derived (clause 18.2): the command bytes carry no octet of the digest in the clear, and the signature the
    /// TPM produced nevertheless verifies against the CALLER's plaintext digest off-TPM.
    /// </summary>
    [TestMethod]
    public async Task SignWithTheDigestDecryptProtectedOverXorVerifiesOverTheRecoveredPlaintext() =>
        await RunDecryptProtectedSignAsync(
            nameof(SignWithTheDigestDecryptProtectedOverXorVerifiesOverTheRecoveredPlaintext), TpmtSymDef.Xor(HmacSessionAlg)).ConfigureAwait(false);

    /// <summary>
    /// The same first-parameter protection over AES-128-CFB, the platform-specific cipher mode keyed and
    /// initialized from the session's KDFa
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 18.3): the digest crosses the wire carrying none of its
    /// own octets, and the recovered value is what <c>TPM2_Sign()</c> signs, so the signature verifies against
    /// the caller's plaintext (Part 3: Commands, clause 20.5).
    /// </summary>
    [TestMethod]
    public async Task SignWithTheDigestDecryptProtectedOverAesCfbVerifiesOverTheRecoveredPlaintext() =>
        await RunDecryptProtectedSignAsync(
            nameof(SignWithTheDigestDecryptProtectedOverAesCfbVerifiesOverTheRecoveredPlaintext), TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB)).ConfigureAwait(false);

    /// <summary>
    /// An authorization area of exactly <c>[TPM_RS_PW, decrypt companion]</c> is legal — the password slot
    /// authorizes <c>@keyHandle</c> and the handle-less slot behind it is carried "for the single purpose of
    /// decrypting a command parameter"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 15.6.1, Table 12) — and a companion authorizes no
    /// entity, so its cipher key is its <c>sessionKey</c> ALONE, with no authValue folded (clause 18.1). The
    /// digest leaves the host transformed, and the signature verifying over the caller's plaintext is what
    /// proves the simulator recovered it under exactly that key.
    /// </summary>
    [TestMethod]
    public async Task SignWithADecryptCompanionBesideAPasswordKeySlotVerifiesOverTheRecoveredPlaintext()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignWithADecryptCompanionBesideAPasswordKeySlotVerifiesOverTheRecoveredPlaintext), pool).ConfigureAwait(false);

        byte[]? signCommand = null;
        using TpmDevice tpm = CreateSignCapturingDevice(simulator, bytes => signCommand = bytes);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, SigningKeyPassword, isNoDa: true).ConfigureAwait(false);

        (uint companionHandle, TpmSession companion) = await HmacKeyHarness.StartBoundHmacSessionAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmtSymDef.Xor(HmacSessionAlg),
            isBoundToAuthorizedEntity: false, TestContext.CancellationToken).ConfigureAwait(false);

        try
        {
            companion.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

            using TpmPasswordSession keyPassword = TpmPasswordSession.Create(SigningKeyPasswordBytes, pool);
            using SignInput input = SignInput.ForEcdsa(key.ObjectHandle, Sha256WidthDigest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            ReadOnlyMemory<byte>[] handleNames = [key.Name.Span.ToArray()];

            TpmResult<SignResponse> result = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
                tpm, input, [keyPassword, companion], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"A password key slot beside a decrypt companion must sign: '{result.ResponseCode}'.");

            Assert.IsNotNull(signCommand, "The framed TPM2_Sign() command must have been captured on its way to the simulator.");
            Assert.IsLessThan(
                0, signCommand.AsSpan().IndexOf(Sha256WidthDigest.AsSpan()),
                "The companion's keystream must actually have transformed the digest: a command carrying it in the clear proves nothing was protected.");

            using SignResponse signature = result.Value;
            AssertEcdsaSignatureVerifies(key, signature, Sha256WidthDigest, "A companion's keystream folds its sessionKey alone, so the recovered digest — and thus the signature — must match the caller's plaintext.");
        }
        finally
        {
            companion.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, companionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// An HMAC session genuinely authorizing <c>@keyHandle</c> at index 0 and a LOADED policy session claiming
    /// <c>decrypt</c> at index 1 together sign: the policy companion is admitted exactly like an
    /// HMAC companion would be (TPM 2.0 Library Part 1, clause 15.6.1, Table 12, footnote [2]: "a policy
    /// authorization session can also be used for encryption and decryption"), its OWN AES-CFB keystream recovers
    /// <c>digest</c> before cpHash is computed, and the signature the simulator produced verifies off-TPM against
    /// the caller's plaintext, proving the policy companion's decrypt claim was genuinely honored beside a
    /// genuinely authorizing HMAC session at index 0.
    /// </summary>
    /// <remarks>
    /// Hand-framed. <see cref="TpmPolicySession"/> — the production client-side type for a policy session — has
    /// no <see cref="TpmSessionBase.Symmetric"/> constructor parameter and never overrides
    /// <see cref="TpmSessionBase.EncryptFirstParameterAsync"/> or <see cref="TpmSessionBase.DecryptFirstParameterAsync"/>,
    /// so it cannot serve as a decrypt or encrypt companion through <see cref="TpmCommandExecutor"/>: a production
    /// caller has no way to compose this shape today (a host gap, not a spec gap). The generic
    /// <see cref="TpmSession"/> wrapper used here is the test-only stand-in the sibling classes already use for a
    /// policy companion — its wire math is driven solely by the raw session handle value and negotiated
    /// <see cref="TpmSessionBase.Symmetric"/>, never by the handle's type octet, so it is byte-identical on the
    /// wire to a genuine policy session's own companion behavior.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1,
    /// clause 15.6.1, Table 12, footnote [2]; clause 18.3</see>.
    /// </remarks>
    [TestMethod]
    public async Task SignWithAnHmacAuthorizingSessionAndAPolicyDecryptCompanionRecoversTheDigestUnderThePolicySessionsOwnKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignWithAnHmacAuthorizingSessionAndAPolicyDecryptCompanionRecoversTheDigestUnderThePolicySessionsOwnKey), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, SigningKeyPassword, isNoDa: true).ConfigureAwait(false);
        byte[] keyName = key.Name.Span.ToArray();

        (uint keySessionHandle, TpmSession keySession) = await StartUnboundHmacSessionAsync(tpm, registry, pool, SigningKeyPasswordBytes).ConfigureAwait(false);

        TpmtSymDef aesCfb = TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB);
        uint policySessionHandle = 0;
        try
        {
            using(keySession)
            {
                var policyInput = new StartAuthSessionInput
                {
                    TpmKey = (uint)TpmRh.TPM_RH_NULL,
                    Bind = (uint)TpmRh.TPM_RH_NULL,
                    NonceCaller = RandomNumberGenerator.GetBytes(32),
                    EncryptedSalt = ReadOnlyMemory<byte>.Empty,
                    SessionType = TpmSeConstants.TPM_SE_POLICY,
                    AuthHash = HmacSessionAlg,
                    Symmetric = aesCfb
                };
                TpmResult<StartAuthSessionResponse> policyResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
                    tpm, policyInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(policyResult.IsSuccess, $"StartAuthSession (policy) failed: '{policyResult.ResponseCode}'.");
                StartAuthSessionResponse policyStarted = policyResult.Value;
                policySessionHandle = policyStarted.SessionHandle.Value;
                using var policySession = new TpmSession(new TpmHandle(policySessionHandle), policyStarted.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), pool, aesCfb);

                keySession.SessionAttributes = TpmaSession.CONTINUE_SESSION;
                policySession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                using SignInput signInput = SignInput.ForEcdsa(key.ObjectHandle, Sha256WidthDigest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
                byte[] parameters = SerializeCommandParameters(signInput, handleCount: 1);

                keySession.RollNonceCaller(pool);
                policySession.RollNonceCaller(pool);
                await policySession.EncryptFirstParameterAsync(parameters.AsMemory(sizeof(ushort), Sha256WidthDigest.Length), pool, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsFalse(
                    parameters.AsSpan(sizeof(ushort), Sha256WidthDigest.Length).SequenceEqual(Sha256WidthDigest),
                    "The policy companion's keystream must actually have transformed the digest before cpHash is computed: unchanged octets would prove nothing was protected.");

                ReadOnlyMemory<byte>[] handleNames = [keyName];
                byte[] cpHash = await ComputeCpHashAsync(TpmCcConstants.TPM_CC_Sign, handleNames, parameters, pool).ConfigureAwait(false);

                //keySession is the FIRST session and genuinely authorizes @keyHandle, so its own command HMAC
                //folds the companion's nonceTPM (TPM 2.0 Library Part 1, clause 16.6.3.4) — the same fold
                //TpmNoAuthSessionExecutorTests.SignOverItsKeysHmacSessionAndADecryptCompanionFoldsTheCompanionsNonceIntoSessionZerosHmac
                //proves through the production executor for an HMAC companion; the policy companion folds
                //identically since the fold reads only NonceTpm, never the companion's own kind.
                using Tpm2bAuth? keyHmac = await keySession.PrepareAuthHmacAsync(
                    cpHash, pool, TestContext.CancellationToken, foldedSessionNonces: policySession.NonceTpm).ConfigureAwait(false);
                byte[] keyBlock = new byte[keySession.GetAuthCommandSize()];
                var keyWriter = new TpmWriter(keyBlock);
                keySession.WriteAuthCommand(ref keyWriter, keyHmac);

                using Tpm2bAuth? policyHmac = await policySession.PrepareAuthHmacAsync(cpHash, pool, TestContext.CancellationToken).ConfigureAwait(false);
                byte[] policyBlock = new byte[policySession.GetAuthCommandSize()];
                var policyWriter = new TpmWriter(policyBlock);
                policySession.WriteAuthCommand(ref policyWriter, policyHmac);

                byte[] authArea = [.. keyBlock, .. policyBlock];

                int length = TpmHeader.HeaderSize + sizeof(uint) + sizeof(uint) + authArea.Length + parameters.Length;
                byte[] command = new byte[length];
                var writer = new TpmWriter(command);
                var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)length, (uint)TpmCcConstants.TPM_CC_Sign);
                header.WriteTo(ref writer);
                writer.WriteUInt32(key.ObjectHandle.Value);
                writer.WriteUInt32((uint)authArea.Length);
                writer.WriteBytes(authArea);
                writer.WriteBytes(parameters);

                TpmResult<TpmResponse> submitResult = await simulator.SubmitAsync(command, pool, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(submitResult.IsSuccess, "The simulator must answer a refused command rather than fault.");
                using TpmResponse rawResponse = submitResult.Value;
                byte[] response = rawResponse.AsReadOnlySpan().ToArray();
                var codeReader = new TpmReader(response);
                TpmRcConstants code = (TpmRcConstants)TpmHeader.Parse(ref codeReader).Code;

                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, $"An HMAC-authorized TPM2_Sign() beside a policy decrypt companion must succeed: '{code}'.");

                byte[] responseParameters = ReadResponseParameters(response, outHandleCount: 0);
                var signatureReader = new TpmReader(responseParameters);
                using SignResponse signature = SignResponse.Parse(ref signatureReader, pool);

                AssertEcdsaSignatureVerifies(
                    key, signature, Sha256WidthDigest,
                    "The policy companion's keystream folds its sessionKey alone, so the recovered digest — and thus the signature — must match the caller's plaintext.");
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, keySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, policySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The TRIAL counterpart of
    /// <see cref="SignWithAnHmacAuthorizingSessionAndAPolicyDecryptCompanionRecoversTheDigestUnderThePolicySessionsOwnKey"/>:
    /// beside a genuinely authorizing HMAC session at index 0, a TRIAL policy session (<c>TPM_SE_TRIAL</c>) at
    /// index 1 claiming <c>decrypt</c> is refused session-encoded <c>TPM_RC_ATTRIBUTES</c> at its own index —
    /// "a trial session is not allowed to be used for authorization. … the sessionKey of the session will never
    /// be used" (TPM 2.0 Library Part 1, clause 16.6.9) — and the authorizing session's own command HMAC is
    /// never reached, since Part 3, clause 5.5's per-slot attribute checks precede the HMAC comparisons.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1,
    /// clause 16.6.9; Part 3, clause 5.5, step 4.4.2; clause 11.1.1</see>.
    /// </summary>
    [TestMethod]
    public async Task SignWithAnHmacAuthorizingSessionAndATrialPolicyCompanionClaimingDecryptReturnsSessionEncodedAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignWithAnHmacAuthorizingSessionAndATrialPolicyCompanionClaimingDecryptReturnsSessionEncodedAttributes), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, SigningKeyPassword, isNoDa: true).ConfigureAwait(false);
        byte[] keyName = key.Name.Span.ToArray();

        (uint keySessionHandle, TpmSession keySession) = await StartUnboundHmacSessionAsync(tpm, registry, pool, SigningKeyPasswordBytes).ConfigureAwait(false);

        TpmtSymDef aesCfb = TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB);
        uint trialSessionHandle = 0;
        try
        {
            using(keySession)
            {
                var trialInput = new StartAuthSessionInput
                {
                    TpmKey = (uint)TpmRh.TPM_RH_NULL,
                    Bind = (uint)TpmRh.TPM_RH_NULL,
                    NonceCaller = RandomNumberGenerator.GetBytes(32),
                    EncryptedSalt = ReadOnlyMemory<byte>.Empty,
                    SessionType = TpmSeConstants.TPM_SE_TRIAL,
                    AuthHash = HmacSessionAlg,
                    Symmetric = aesCfb
                };
                TpmResult<StartAuthSessionResponse> trialResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
                    tpm, trialInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(trialResult.IsSuccess, $"StartAuthSession (trial) failed: '{trialResult.ResponseCode}'.");
                StartAuthSessionResponse trialStarted = trialResult.Value;
                trialSessionHandle = trialStarted.SessionHandle.Value;
                using var trialSession = new TpmSession(new TpmHandle(trialSessionHandle), trialStarted.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), pool, aesCfb);

                keySession.SessionAttributes = TpmaSession.CONTINUE_SESSION;
                trialSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                using SignInput signInput = SignInput.ForEcdsa(key.ObjectHandle, Sha256WidthDigest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
                byte[] parameters = SerializeCommandParameters(signInput, handleCount: 1);

                keySession.RollNonceCaller(pool);
                trialSession.RollNonceCaller(pool);
                await trialSession.EncryptFirstParameterAsync(parameters.AsMemory(sizeof(ushort), Sha256WidthDigest.Length), pool, TestContext.CancellationToken).ConfigureAwait(false);

                ReadOnlyMemory<byte>[] handleNames = [keyName];
                byte[] cpHash = await ComputeCpHashAsync(TpmCcConstants.TPM_CC_Sign, handleNames, parameters, pool).ConfigureAwait(false);

                using Tpm2bAuth? keyHmac = await keySession.PrepareAuthHmacAsync(
                    cpHash, pool, TestContext.CancellationToken, foldedSessionNonces: trialSession.NonceTpm).ConfigureAwait(false);
                byte[] keyBlock = new byte[keySession.GetAuthCommandSize()];
                var keyWriter = new TpmWriter(keyBlock);
                keySession.WriteAuthCommand(ref keyWriter, keyHmac);

                using Tpm2bAuth? trialHmac = await trialSession.PrepareAuthHmacAsync(cpHash, pool, TestContext.CancellationToken).ConfigureAwait(false);
                byte[] trialBlock = new byte[trialSession.GetAuthCommandSize()];
                var trialWriter = new TpmWriter(trialBlock);
                trialSession.WriteAuthCommand(ref trialWriter, trialHmac);

                byte[] authArea = [.. keyBlock, .. trialBlock];

                int length = TpmHeader.HeaderSize + sizeof(uint) + sizeof(uint) + authArea.Length + parameters.Length;
                byte[] command = new byte[length];
                var writer = new TpmWriter(command);
                var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)length, (uint)TpmCcConstants.TPM_CC_Sign);
                header.WriteTo(ref writer);
                writer.WriteUInt32(key.ObjectHandle.Value);
                writer.WriteUInt32((uint)authArea.Length);
                writer.WriteBytes(authArea);
                writer.WriteBytes(parameters);

                TpmResult<TpmResponse> submitResult = await simulator.SubmitAsync(command, pool, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(submitResult.IsSuccess, "The simulator must answer a refused command rather than fault.");
                using TpmResponse rawResponse = submitResult.Value;
                byte[] response = rawResponse.AsReadOnlySpan().ToArray();
                var codeReader = new TpmReader(response);
                TpmRcConstants code = (TpmRcConstants)TpmHeader.Parse(ref codeReader).Code;

                Assert.AreEqual(
                    HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 1), code,
                    "A TRIAL session at index 1 claiming decrypt beside a genuinely authorizing HMAC session at index 0 is refused session-encoded TPM_RC_ATTRIBUTES.");
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, keySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, trialSessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The bound on <c>digest</c> belongs to the PLAINTEXT, and it is the decryption step that judges it: a
    /// <c>TPM2B_DIGEST</c> is at most <c>sizeof(TPMU_HA)</c> octets
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.3.2, Table 90), so a wider recovered value is a
    /// failure of <c>digest</c>'s OWN content, never of the decrypt step — parameter-encoded to <c>digest</c>
    /// itself, <c>TPM2_Sign()</c>'s first parameter (Part 3, clause 20.5, Table 122, index 0) — the session
    /// form's parse can only step over the field's framing, since a decrypt session may have left those octets
    /// ciphertext (Part 1: Architecture, clause 18.1; Part 3: Commands, clause 5.7 precedes clause 5.8).
    /// </summary>
    [TestMethod]
    public async Task SignWithAnOverBoundPlaintextDigestReturnsParameterEncodedSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignWithAnOverBoundPlaintextDigestReturnsParameterEncodedSize), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, SigningKeyPassword, isNoDa: true).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await HmacKeyHarness.StartBoundHmacSessionAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmtSymDef.Xor(HmacSessionAlg),
            isBoundToAuthorizedEntity: false, TestContext.CancellationToken).ConfigureAwait(false);

        try
        {
            session.SetAuthValue(SigningKeyPasswordBytes, pool);
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

            //One octet past sizeof(TPMU_HA): the typed carrier refuses to build such a digest, so the frame is
            //composed by hand while every other octet of the command stays exactly what SignInput writes.
            byte[] overBoundDigest = new byte[Tpm2bDigest.MaxSize + 1];
            var input = new OversizedDigestSignInput(key.ObjectHandle.Value, overBoundDigest);
            ReadOnlyMemory<byte>[] handleNames = [key.Name.Span.ToArray()];

            TpmResult<SignResponse> result = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
                tpm, input, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            if(result.IsSuccess)
            {
                result.Value.Dispose();
            }

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_SIZE, result.BaseError,
                "A recovered digest wider than sizeof(TPMU_HA) must be refused with TPM_RC_SIZE.");
            Assert.AreEqual(
                HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, parameterIndex: 0), result.ResponseCode,
                "digest is TPM2_Sign()'s first parameter (Table 122, index 0); an over-bound recovered value is that parameter's own content failure, not the decrypt slot's, so the wire code carries the parameter-index modifier.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_Sign()</c>'s response carries a <c>TPMT_SIGNATURE</c> (Table 123), which has no size field, so no
    /// response parameter of this command can be encrypted: a slot claiming <c>encrypt</c> is refused with
    /// <c>TPM_RC_ATTRIBUTES</c> session-index-encoded to the claiming slot
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 18.1: "only the first parameter ... can be encrypted.
    /// That parameter must have an explicit size field"; Part 2: Structures, clause 6.6.2). The claim is planted
    /// on the WIRE because the area's structural checks (Part 3: Commands, clause 5.5) precede the
    /// authorization of clause 5.6, so the slot is refused for its attributes long before its <c>hmac</c> —
    /// computed over the un-planted octet — is ever looked at.
    /// </summary>
    [TestMethod]
    public async Task SignOverASessionClaimingEncryptIsRefusedWithAttributesAtItsSlot()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignOverASessionClaimingEncryptIsRefusedWithAttributesAtItsSlot), pool).ConfigureAwait(false);
        TpmResponseRegistry registry = CreateRegistry();

        using TpmDevice plainDevice = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(plainDevice, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(plainDevice, registry, pool, SigningKeyPassword, isNoDa: true).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await HmacKeyHarness.StartBoundHmacSessionAsync(
            plainDevice, registry, pool, parent.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmtSymDef.Xor(HmacSessionAlg),
            isBoundToAuthorizedEntity: false, TestContext.CancellationToken).ConfigureAwait(false);

        try
        {
            session.SetAuthValue(SigningKeyPasswordBytes, pool);

            static byte[] Rewrite(byte[] command)
            {
                SetSessionAttributeBit(command, handleCount: 1, sessionIndex: 0, TpmaSession.ENCRYPT);

                return command;
            }

            using TpmDevice rewritingDevice = CreateRewritingDevice(simulator, TpmCcConstants.TPM_CC_Sign, Rewrite);

            TpmResult<SignResponse> result = await SignOverSessionAsync(
                rewritingDevice, registry, pool, session, key.ObjectHandle.Value, key.Name.Span.ToArray(), Sha256WidthDigest,
                TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
            if(result.IsSuccess)
            {
                result.Value.Dispose();
            }

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_ATTRIBUTES, result.BaseError,
                "No TPM2_Sign() response parameter has a size field, so an encrypt claim must be refused with TPM_RC_ATTRIBUTES.");
            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0), result.ResponseCode,
                "The refusal names the claiming slot (index 0), so the wire code carries its session-index modifier.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(plainDevice, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A session claiming the <c>audit</c> attribute at <c>TPM2_Sign()</c>'s key slot is admitted (TPM 2.0
    /// Library Part 1, clause 17.1) and the command succeeds, extending the session's audit digest to
    /// <c>H(0…0 ‖ cpHash ‖ rpHash)</c> on its first use (equation 30) with the response echoing <c>audit</c> SET,
    /// <c>auditExclusive</c> SET and <c>auditReset</c> CLEAR (Part 2, clause 8.4, Table 38) — proved by chaining
    /// cpHash/rpHash from the octets this test itself sent and read, then reading the session's digest back
    /// through <c>TPM2_GetSessionAuditDigest()</c> with the NULL signer.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.1; Part 2, clause 8.4, Table 38</see>.
    /// </summary>
    [TestMethod]
    public async Task SignOverASessionClaimingAuditSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignOverASessionClaimingAuditSucceeds), pool).ConfigureAwait(false);
        List<(TpmCcConstants Code, byte[] Command, byte[] Response)> wire = [];
        using TpmDevice tpm = CreateRecordingDevice(simulator, wire);
        TpmResponseRegistry registry = CreateRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_GetSessionAuditDigest, TpmResponseCodec.GetSessionAuditDigest);

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, SigningKeyPassword, isNoDa: true).ConfigureAwait(false);
        (uint sessionHandle, TpmSession session) = await StartUnboundHmacSessionAsync(tpm, registry, pool, SigningKeyPasswordBytes).ConfigureAwait(false);

        try
        {
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

            using SignInput signInput = SignInput.Create(key.ObjectHandle, Sha256WidthDigest, TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            ReadOnlyMemory<byte>[] handleNames = [key.Name.Span.ToArray()];

            TpmResult<SignResponse> result = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
                tpm, signInput, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            if(result.IsSuccess)
            {
                result.Value.Dispose();
            }

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_SUCCESS, result.IsSuccess ? TpmRcConstants.TPM_RC_SUCCESS : result.ResponseCode,
                "An audit-claiming session over an audited command succeeds (TPM 2.0 Library Part 1, clause 17.1).");

            (TpmCcConstants Code, byte[] Command, byte[] Response) audited = wire[^1];
            byte auditedAttributes = ReadResponseSessionAttributes(audited.Response, outHandleCount: 0, sessionIndex: 0);
            Assert.AreEqual(
                (byte)(TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT | TpmaSession.AUDIT_EXCLUSIVE), auditedAttributes,
                "The response echoes audit SET and auditExclusive SET (the session's first use as an audit session), with auditReset CLEAR (TPM 2.0 Library Part 2, clause 8.4, Table 38).");

            byte[] responseParameters = ReadResponseParameters(audited.Response, outHandleCount: 0);
            byte[] cpHash = await ComputeCpHashAsync(TpmCcConstants.TPM_CC_Sign, handleNames, SerializeCommandParameters(signInput, handleCount: 1), pool).ConfigureAwait(false);
            byte[] rpHash = await ComputeRpHashAsync(TpmCcConstants.TPM_CC_Sign, responseParameters, pool).ConfigureAwait(false);
            byte[] expectedDigest = await ExtendAuditDigestAsync(priorDigest: null, cpHash, rpHash, pool).ConfigureAwait(false);

            using GetSessionAuditDigestInput auditDigestInput = GetSessionAuditDigestInput.ForNullSigner(TpmiShHmac.FromValue(sessionHandle), ReadOnlySpan<byte>.Empty, pool);
            using TpmPasswordSession endorsementForDigest = TpmPasswordSession.CreateEmpty(pool);
            using TpmPasswordSession nullSignerSlot = TpmPasswordSession.CreateEmpty(pool);

            TpmResult<GetSessionAuditDigestResponse> digestResult = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                tpm, auditDigestInput, [endorsementForDigest, nullSignerSlot], handleNames: null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            using GetSessionAuditDigestResponse? auditDigestResponse = digestResult.IsSuccess ? digestResult.Value : null;

            Assert.IsTrue(digestResult.IsSuccess, $"TPM2_GetSessionAuditDigest() over the freshly audited session must succeed: '{digestResult.ResponseCode}'.");
            Assert.IsTrue(auditDigestResponse!.SessionAudit.ExclusiveSession.IsYes, "The session became the exclusive audit session on its first use (TPM 2.0 Library Part 1, clause 17.2).");
            Assert.IsTrue(
                expectedDigest.AsSpan().SequenceEqual(auditDigestResponse.SessionAudit.SessionDigest.AsReadOnlySpan()),
                "The session's audit digest must equal H(0…0 ‖ cpHash ‖ rpHash) chained from the sign exchange's own wire octets (TPM 2.0 Library Part 1, clause 17.1, equation 30).");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A companion slot that authorizes nothing must claim at least one of <c>decrypt</c>, <c>encrypt</c>, or
    /// <c>audit</c>; one claiming NONE of them is refused with <c>TPM_RC_ATTRIBUTES</c> encoded to its own index
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 15.6.4; Part 2: Structures, clause 6.6.2) — the rule
    /// that keeps an area from carrying a session that does nothing but consume a slot.
    /// </summary>
    [TestMethod]
    public async Task SignWithACompanionClaimingNoAttributeIsRefusedWithAttributesAtIndexOne()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignWithACompanionClaimingNoAttributeIsRefusedWithAttributesAtIndexOne), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, SigningKeyPassword, isNoDa: true).ConfigureAwait(false);

        (uint keySessionHandle, TpmSession keySession) = await StartUnboundHmacSessionAsync(tpm, registry, pool, SigningKeyPasswordBytes).ConfigureAwait(false);
        (uint companionHandle, TpmSession companion) = await HmacKeyHarness.StartBoundHmacSessionAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, TestContext.CancellationToken).ConfigureAwait(false);

        try
        {
            companion.SessionAttributes = TpmaSession.CONTINUE_SESSION;

            using SignInput input = SignInput.ForEcdsa(key.ObjectHandle, Sha256WidthDigest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            ReadOnlyMemory<byte>[] handleNames = [key.Name.Span.ToArray()];

            TpmResult<SignResponse> result = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
                tpm, input, [keySession, companion], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            if(result.IsSuccess)
            {
                result.Value.Dispose();
            }

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_ATTRIBUTES, result.BaseError,
                "A session authorizing no entity must claim at least one of decrypt, encrypt, or audit.");
            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 1), result.ResponseCode,
                "The refusal names the companion slot (index 1), so the wire code carries its session-index modifier.");
        }
        finally
        {
            companion.Dispose();
            keySession.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, companionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, keySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A LOADED policy session at <c>TPM2_Sign()</c>'s key slot is a kind of authorization this arm does not
    /// model, answered with the BARE <c>TPM_RC_AUTH_TYPE</c> at slot resolution — before any command HMAC is
    /// queued (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0
    /// Library Specification</see>, Part 3: Commands, clause 5.6's entry ladder; Part 2: Structures, clause 9.8,
    /// Table 54 admits HMAC sessions, policy sessions, and <c>TPM_RS_PW</c> at an authorization slot).
    /// </summary>
    [TestMethod]
    public async Task SignWithALoadedPolicySessionAtTheKeySlotReturnsAuthType()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignWithALoadedPolicySessionAtTheKeySlotReturnsAuthType), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, SigningKeyPassword, isNoDa: true).ConfigureAwait(false);

        TpmResult<StartAuthSessionResponse> policyStartResult = await tpm.StartPolicySessionAsync(
            HmacSessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(policyStartResult.IsSuccess, $"StartPolicySession failed: '{policyStartResult.ResponseCode}'.");

        StartAuthSessionResponse policyStarted = policyStartResult.Value;
        uint policySessionHandle = policyStarted.SessionHandle.Value;

        try
        {
            using TpmSession policySlotSession = new(new TpmHandle(policySessionHandle), policyStarted.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), pool);

            TpmResult<SignResponse> result = await SignOverSessionAsync(
                tpm, registry, pool, policySlotSession, key.ObjectHandle.Value, key.Name.Span.ToArray(), Sha256WidthDigest,
                TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
            if(result.IsSuccess)
            {
                result.Value.Dispose();
            }

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_AUTH_TYPE, result.ResponseCode,
                "A policy-session handle at the key slot is a kind of authorization this arm does not model, answered bare.");
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, policySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A session handle at the key slot that resolves to NO loaded session at all is blamed on the offending
    /// slot index with <c>TPM_RC_REFERENCE_S0</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 5.5, step 4.2; Part 2: Structures, clause 6.6.3, Table 18) — distinct from
    /// the bare <c>TPM_RC_AUTH_TYPE</c> a LOADED policy session earns.
    /// </summary>
    [TestMethod]
    public async Task SignWithAnUnloadedSessionHandleAtTheKeySlotReturnsSessionReferenceMiss()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignWithAnUnloadedSessionHandleAtTheKeySlotReturnsSessionReferenceMiss), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, SigningKeyPassword, isNoDa: true).ConfigureAwait(false);
        (uint sessionHandle, TpmSession session) = await StartUnboundHmacSessionAsync(tpm, registry, pool, SigningKeyPasswordBytes).ConfigureAwait(false);

        using(session)
        {
            //Flushed BEFORE it ever authorizes a command, so the handle the Sign below names is genuinely
            //unloaded rather than a policy session or a password slot.
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);

            TpmResult<SignResponse> result = await SignOverSessionAsync(
                tpm, registry, pool, session, key.ObjectHandle.Value, key.Name.Span.ToArray(), Sha256WidthDigest,
                TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
            if(result.IsSuccess)
            {
                result.Value.Dispose();
            }

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_REFERENCE_S0, result.ResponseCode,
                "A key-slot handle that resolves to no loaded session at all is blamed on the offending slot index.");
        }
    }

    /// <summary>
    /// The command's own rules run only AFTER the session has proved the authorization value: "If the sign
    /// attribute is not SET in the key referenced by handle, then the TPM shall return TPM_RC_KEY"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.5.1), so a sealed data object authorized by a genuine
    /// HMAC session draws <c>TPM_RC_KEY</c> handle-encoded at keyHandle, handle 1 of Table 122 — never
    /// session-index-encoded, because the fault is the command's, not any slot's (clause 5.6 precedes clause 5.8).
    /// </summary>
    [TestMethod]
    public async Task SignOverASessionAgainstASealedDataObjectIsRefusedWithKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignOverASessionAgainstASealedDataObjectIsRefusedWithKey), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        (uint sealedHandle, byte[] sealedName) = await PolicySweepHarness.SealAndLoadAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, SealedSecretBytes, ReadOnlyMemory<byte>.Empty,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartUnboundHmacSessionAsync(tpm, registry, pool, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        try
        {
            TpmResult<SignResponse> result = await SignOverSessionAsync(
                tpm, registry, pool, session, sealedHandle, sealedName, Sha256WidthDigest,
                TpmAlgIdConstants.TPM_ALG_NULL, TpmAlgIdConstants.TPM_ALG_NULL).ConfigureAwait(false);
            if(result.IsSuccess)
            {
                result.Value.Dispose();
            }

            Assert.AreEqual(
                HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_KEY, 0), result.ResponseCode,
                "A sealed data object (sign CLEAR) authorized over a session is refused at keyHandle, handle 1 of Table 122.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "If inScheme is not a valid signing scheme for the type of keyHandle (or TPM_ALG_NULL), then the TPM
    /// shall return TPM_RC_SCHEME"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.5): an RSASSA <c>inScheme</c> against an ECC signing key
    /// authorized over a genuine HMAC session answers <c>TPM_RC_SCHEME</c> parameter-encoded at inScheme,
    /// parameter 2 of Table 122 — the same designation the password form answers, once the session has proved
    /// the authorization value.
    /// </summary>
    [TestMethod]
    public async Task SignOverASessionWithASchemeIncompatibleWithTheKeyIsRefusedWithScheme()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignOverASessionWithASchemeIncompatibleWithTheKeyIsRefusedWithScheme), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, SigningKeyPassword, isNoDa: true).ConfigureAwait(false);
        (uint sessionHandle, TpmSession session) = await StartUnboundHmacSessionAsync(tpm, registry, pool, SigningKeyPasswordBytes).ConfigureAwait(false);

        try
        {
            TpmResult<SignResponse> result = await SignOverSessionAsync(
                tpm, registry, pool, session, key.ObjectHandle.Value, key.Name.Span.ToArray(), Sha256WidthDigest,
                TpmAlgIdConstants.TPM_ALG_RSASSA, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
            if(result.IsSuccess)
            {
                result.Value.Dispose();
            }

            Assert.AreEqual(
                HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SCHEME, 1), result.ResponseCode,
                "An RSASSA inScheme against an ECC key is refused at inScheme, parameter 2 of Table 122, after the session has authorized the key.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "If keyHandle references a restricted signing key, then validation shall be provided"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.5.1): a restricted HMAC signing key with the modelled
    /// NULL validation ticket is refused with <c>TPM_RC_TICKET</c> parameter-encoded at validation, parameter 3
    /// of Table 122 — again after, not before, the session's authorization has passed.
    /// </summary>
    [TestMethod]
    public async Task SignOverASessionAgainstARestrictedHmacKeyIsRefusedWithTicket()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignOverASessionAgainstARestrictedHmacKeyIsRefusedWithTicket), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        (uint restrictedHandle, byte[] restrictedName) = await CreateAndLoadRestrictedHmacKeyAsync(tpm, registry, pool, parent.ObjectHandle.Value).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartUnboundHmacSessionAsync(tpm, registry, pool, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        try
        {
            TpmResult<SignResponse> result = await SignOverSessionAsync(
                tpm, registry, pool, session, restrictedHandle, restrictedName, Sha256WidthDigest,
                TpmAlgIdConstants.TPM_ALG_NULL, TpmAlgIdConstants.TPM_ALG_NULL).ConfigureAwait(false);
            if(result.IsSuccess)
            {
                result.Value.Dispose();
            }

            Assert.AreEqual(
                HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_TICKET, 2), result.ResponseCode,
                "A restricted HMAC signing key with the modelled NULL validation ticket is refused at validation, parameter 3 of Table 122.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The digest a KEYEDHASH signing key is asked to sign must be exactly its scheme hash's width, or the TPM
    /// answers <c>TPM_RC_SIZE</c> parameter-encoded at digest, parameter 1 of Table 122 — the last of clause
    /// 20.5's own rules, run after the session's authorization
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
    /// 2.0 Library Specification</see>, Part 3: Commands, clause 20.5.1; Part 2: Structures, clause 10.3.2, Table 90's
    /// <c>TPM2B_DIGEST</c>, whose bound the width check is narrower than).
    /// </summary>
    [TestMethod]
    public async Task SignOverASessionWithAWrongWidthDigestIsRefusedWithSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignOverASessionWithAWrongWidthDigestIsRefusedWithSize), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256,
            userAuth: SigningKeyPasswordBytes, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartUnboundHmacSessionAsync(tpm, registry, pool, SigningKeyPasswordBytes).ConfigureAwait(false);

        try
        {
            TpmResult<SignResponse> result = await SignOverSessionAsync(
                tpm, registry, pool, session, key.Handle, key.Name.AsReadOnlyMemory(), Sha1WidthDigest,
                TpmAlgIdConstants.TPM_ALG_HMAC, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
            if(result.IsSuccess)
            {
                result.Value.Dispose();
            }

            Assert.AreEqual(
                HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), result.ResponseCode,
                "A digest whose width differs from the key's scheme hash is refused at digest, parameter 1 of Table 122.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// An error response is header-only and carries no authorization area, so the TPM rolls no
    /// <c>nonceTPM</c> for it (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
    /// 2.0 Library Specification</see>, Part 3: Commands, clause 6.2; Part 1: Architecture, clause 15.8): a
    /// <c>TPM2_Sign()</c> refused by the command's own rules leaves the session exactly where it was, which a
    /// CORRECTED retry over the SAME session succeeding — and only then rolling the nonce — is what proves.
    /// </summary>
    [TestMethod]
    public async Task ASignRefusedByACommandRuleLeavesTheSessionUsableForACorrectedRetry()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ASignRefusedByACommandRuleLeavesTheSessionUsableForACorrectedRetry), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256,
            userAuth: SigningKeyPasswordBytes, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartUnboundHmacSessionAsync(tpm, registry, pool, SigningKeyPasswordBytes).ConfigureAwait(false);

        try
        {
            ReadOnlyMemory<byte> keyName = key.Name.AsReadOnlyMemory();
            byte[] beforeRefusal = session.NonceTpm.ToArray();

            TpmResult<SignResponse> refused = await SignOverSessionAsync(
                tpm, registry, pool, session, key.Handle, keyName, Sha1WidthDigest,
                TpmAlgIdConstants.TPM_ALG_HMAC, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
            if(refused.IsSuccess)
            {
                refused.Value.Dispose();
            }

            Assert.AreEqual(
                HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), refused.ResponseCode,
                "The refusal under test must be the command rule's TPM_RC_SIZE, or the retry proves nothing about a refused exchange.");
            Assert.IsTrue(
                session.NonceTpm.Span.SequenceEqual(beforeRefusal),
                "A header-only error response carries no authorization area, so the session's nonceTPM must not roll.");

            TpmResult<SignResponse> corrected = await SignOverSessionAsync(
                tpm, registry, pool, session, key.Handle, keyName, Sha256WidthDigest,
                TpmAlgIdConstants.TPM_ALG_HMAC, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
            Assert.IsTrue(corrected.IsSuccess, $"A corrected retry over the SAME session must succeed: '{corrected.ResponseCode}'.");
            corrected.Value.Dispose();

            Assert.IsFalse(
                session.NonceTpm.Span.SequenceEqual(beforeRefusal),
                "The successful retry, and only it, rolls the session's nonceTPM.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A real HMAC session's carrier rentals around <c>TPM2_Sign()</c> (the session key, the authorization
    /// value, the nonce buffers, the captured parameter area) are returned to the pool exactly, whether the
    /// round trip is REFUSED (a wrong authorization value) or SUCCESSFUL (the correct one) — real pool telemetry
    /// over a genuine <see cref="BaseMemoryPool"/>, with no test hook in production code, for the command of
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.5.
    /// </summary>
    [TestMethod]
    public async Task SignOverASessionReturnsEveryRentedCarrierToPoolAcrossARefusalAndASuccess()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignOverASessionReturnsEveryRentedCarrierToPoolAcrossARefusalAndASuccess), trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, trackingPool.Pool, SigningKeyPassword, isNoDa: true).ConfigureAwait(false);
        byte[] keyName = key.Name.Span.ToArray();

        long baseline = trackingPool.OutstandingCount;

        (uint refusedSessionHandle, TpmSession refusedSession) = await StartUnboundHmacSessionAsync(
            tpm, registry, trackingPool.Pool, WrongSigningKeyPasswordBytes).ConfigureAwait(false);

        try
        {
            TpmResult<SignResponse> refused = await SignOverSessionAsync(
                tpm, registry, trackingPool.Pool, refusedSession, key.ObjectHandle.Value, keyName, Sha256WidthDigest,
                TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_BAD_AUTH, refused.BaseError,
                "The refused round trip must be a genuine wrong-authValue command-HMAC failure, or its carrier accounting proves nothing about a refusal.");
        }
        finally
        {
            refusedSession.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, trackingPool.Pool, refusedSessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The refused Sign alone must return every rented carrier — the session key, the authorization value, the nonces and the captured parameter area — to the pool.");

        (uint okSessionHandle, TpmSession okSession) = await StartUnboundHmacSessionAsync(
            tpm, registry, trackingPool.Pool, SigningKeyPasswordBytes).ConfigureAwait(false);

        try
        {
            TpmResult<SignResponse> ok = await SignOverSessionAsync(
                tpm, registry, trackingPool.Pool, okSession, key.ObjectHandle.Value, keyName, Sha256WidthDigest,
                TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
            Assert.IsTrue(ok.IsSuccess, $"The successful round trip must sign with the CORRECT authValue: '{ok.ResponseCode}'.");
            ok.Value.Dispose();
        }
        finally
        {
            okSession.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, trackingPool.Pool, okSessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "Both a refused and a successful Sign-over-session round trip must return every rented carrier to the pool.");
    }

    /// <summary>
    /// Signs a digest that crosses the wire under <paramref name="symmetric"/> on the AUTHORIZING slot, and
    /// verifies the produced signature off-TPM against the caller's plaintext digest — the observable that pins
    /// the recovered value.
    /// </summary>
    /// <param name="testName">The calling test's name, naming the simulator instance.</param>
    /// <param name="symmetric">The symmetric definition the session negotiates for parameter encryption.</param>
    private async Task RunDecryptProtectedSignAsync(string testName, TpmtSymDef symmetric)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(testName, pool).ConfigureAwait(false);

        byte[]? signCommand = null;
        using TpmDevice tpm = CreateSignCapturingDevice(simulator, bytes => signCommand = bytes);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, SigningKeyPassword, isNoDa: true).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await HmacKeyHarness.StartBoundHmacSessionAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, symmetric,
            isBoundToAuthorizedEntity: false, TestContext.CancellationToken).ConfigureAwait(false);

        try
        {
            session.SetAuthValue(SigningKeyPasswordBytes, pool);
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

            TpmResult<SignResponse> result = await SignOverSessionAsync(
                tpm, registry, pool, session, key.ObjectHandle.Value, key.Name.Span.ToArray(), Sha256WidthDigest,
                TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"TPM2_Sign() over a '{symmetric.Algorithm}' decrypt session must succeed: '{result.ResponseCode}'.");

            Assert.IsNotNull(signCommand, "The framed TPM2_Sign() command must have been captured on its way to the simulator.");
            Assert.IsLessThan(
                0, signCommand.AsSpan().IndexOf(Sha256WidthDigest.AsSpan()),
                "A decrypt-protected command must not carry the digest in the clear: only the data portion of the first parameter is transformed, and it must be.");

            using SignResponse signature = result.Value;
            AssertEcdsaSignatureVerifies(key, signature, Sha256WidthDigest, "The signature must verify against the CALLER's plaintext digest, which it does only if the simulator recovered exactly that value.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Issues <c>TPM2_Sign()</c> over one authorization session and returns the raw result.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="session">The session at the key slot.</param>
    /// <param name="keyHandle">The signing key's handle.</param>
    /// <param name="keyName">The signing key's Name, the command's single cpHash handle-area term.</param>
    /// <param name="digest">The digest to sign.</param>
    /// <param name="scheme">The <c>inScheme</c> selector, or <c>TPM_ALG_NULL</c> for the key's own default.</param>
    /// <param name="schemeHashAlg">The scheme hash, absent on the wire for a NULL scheme.</param>
    /// <returns>The command result.</returns>
    private async Task<TpmResult<SignResponse>> SignOverSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmSessionBase session,
        uint keyHandle, ReadOnlyMemory<byte> keyName, ReadOnlyMemory<byte> digest,
        TpmAlgIdConstants scheme, TpmAlgIdConstants schemeHashAlg)
    {
        using SignInput input = SignInput.Create(TpmiDhObject.FromValue(keyHandle), digest.Span, scheme, schemeHashAlg, pool);
        ReadOnlyMemory<byte>[] handleNames = [keyName];

        return await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, input, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>The digest width, in octets, of <see cref="HmacSessionAlg"/> (SHA-256) — the Zero Digest width an audit session's first extend starts from (TPM 2.0 Library Part 1, clause 17.1, equation 30).</summary>
    private const int AuditDigestSize = 32;

    /// <summary>
    /// Wraps a device whose transport records every submitted command's raw octets alongside the raw response
    /// octets the simulator returned, in submission order — the wire archaeology an audit digest's independent
    /// chain needs, firewalled to the wire with no back-channel into <see cref="TpmSession"/> or simulator
    /// internals.
    /// </summary>
    /// <param name="simulator">The simulator the recording transport forwards to.</param>
    /// <param name="pairs">The list each observed triple is appended to, in submission order.</param>
    /// <returns>A device the caller disposes; its transport records as a side effect of forwarding.</returns>
    private static TpmDevice CreateRecordingDevice(TpmSimulator simulator, List<(TpmCcConstants Code, byte[] Command, byte[] Response)> pairs)
    {
        async ValueTask<TpmResult<TpmResponse>> RecordAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, CancellationToken ct)
        {
            byte[] commandBytes = command.ToArray();
            TpmResult<TpmResponse> result = await simulator.SubmitAsync(command, commandPool, ct).ConfigureAwait(false);
            byte[] responseBytes = result.IsSuccess ? result.Value.AsReadOnlySpan().ToArray() : [];
            var commandReader = new TpmReader(commandBytes);
            TpmHeader commandHeader = TpmHeader.Parse(ref commandReader);
            pairs.Add(((TpmCcConstants)commandHeader.Code, commandBytes, responseBytes));

            return result;
        }

        return TpmDevice.Create(RecordAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
    }

    /// <summary>
    /// Serializes an input's parameter area alone — the octets a command sends after its handle area — by
    /// invoking the same <see cref="ITpmCommandInput.WriteParameters"/> the executor calls, a second time, over a
    /// freshly rented buffer: a pure marshal of the input's own immutable fields, not a read of any computed or
    /// cached wire state.
    /// </summary>
    /// <param name="input">The command input.</param>
    /// <param name="handleCount">The command's handle count, so the parameter area can be sized apart from the handle area.</param>
    /// <returns>The parameter octets, in the order <see cref="ITpmCommandInput.WriteParameters"/> writes them.</returns>
    private static byte[] SerializeCommandParameters(SignInput input, int handleCount)
    {
        int parametersSize = input.GetSerializedSize() - (handleCount * sizeof(uint));
        byte[] buffer = new byte[parametersSize];
        var writer = new TpmWriter(buffer);
        input.WriteParameters(ref writer);

        return buffer;
    }

    /// <summary>
    /// Reads the response parameter area out of a captured raw response's octets — the bytes rpHash (TPM 2.0
    /// Library Part 1, clause 15.8, equation 16) is computed over, as actually returned on the wire, independent
    /// of whatever the codec parsed them into.
    /// </summary>
    /// <param name="responseBytes">The raw response octets, tagged <c>TPM_ST_SESSIONS</c>.</param>
    /// <param name="outHandleCount">The number of output handles the response carries before its parameter area.</param>
    /// <returns>The response parameter octets.</returns>
    private static byte[] ReadResponseParameters(byte[] responseBytes, int outHandleCount)
    {
        var reader = new TpmReader(responseBytes);
        _ = TpmHeader.Parse(ref reader);
        for(int i = 0; i < outHandleCount; i++)
        {
            _ = reader.ReadUInt32();
        }

        uint parameterSize = reader.ReadUInt32();

        return reader.ReadBytes((int)parameterSize).ToArray();
    }

    /// <summary>
    /// Reads one entry's <c>sessionAttributes</c> octet out of a captured raw response's authorization area — the
    /// octet Table 38's <c>audit</c>/<c>auditExclusive</c>/<c>auditReset</c> echo lands in and the response HMAC
    /// is computed over, walked directly off the wire rather than through any parsed session state.
    /// </summary>
    /// <param name="responseBytes">The raw response octets.</param>
    /// <param name="outHandleCount">The number of output handles preceding the parameter area.</param>
    /// <param name="sessionIndex">The zero-based position, in request order, of the session entry to read.</param>
    /// <returns>The entry's raw <c>sessionAttributes</c> octet.</returns>
    private static byte ReadResponseSessionAttributes(byte[] responseBytes, int outHandleCount, int sessionIndex)
    {
        var reader = new TpmReader(responseBytes);
        _ = TpmHeader.Parse(ref reader);
        for(int i = 0; i < outHandleCount; i++)
        {
            _ = reader.ReadUInt32();
        }

        uint parameterSize = reader.ReadUInt32();
        _ = reader.ReadBytes((int)parameterSize);

        byte attributes = 0;
        for(int i = 0; i <= sessionIndex; i++)
        {
            ushort nonceLength = reader.ReadUInt16();
            _ = reader.ReadBytes(nonceLength);
            attributes = reader.ReadByte();
            ushort hmacLength = reader.ReadUInt16();
            _ = reader.ReadBytes(hmacLength);
        }

        return attributes;
    }

    /// <summary>
    /// Computes <c>cpHash = H_sessionAlg(commandCode ‖ Name1 ‖ Name2 ‖ … ‖ parameters)</c> (TPM 2.0 Library Part
    /// 1, clause 15.7, equation 15) over octets this test assembled itself from the command it sent.
    /// </summary>
    /// <param name="commandCode">The command code.</param>
    /// <param name="handleNames">The handle Names, in handle order.</param>
    /// <param name="parameters">The parameter area as sent.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The cpHash octets.</returns>
    private async Task<byte[]> ComputeCpHashAsync(TpmCcConstants commandCode, ReadOnlyMemory<byte>[] handleNames, ReadOnlyMemory<byte> parameters, BaseMemoryPool pool)
    {
        int namesLength = 0;
        foreach(ReadOnlyMemory<byte> name in handleNames)
        {
            namesLength += name.Length;
        }

        byte[] input = new byte[sizeof(uint) + namesLength + parameters.Length];
        BinaryPrimitives.WriteUInt32BigEndian(input, (uint)commandCode);
        int offset = sizeof(uint);
        foreach(ReadOnlyMemory<byte> name in handleNames)
        {
            name.Span.CopyTo(input.AsSpan(offset));
            offset += name.Length;
        }
        parameters.Span.CopyTo(input.AsSpan(offset));

        return await HashSha256Async(input, pool).ConfigureAwait(false);
    }

    /// <summary>
    /// Computes <c>rpHash = H_sessionAlg(TPM_RC_SUCCESS ‖ commandCode ‖ parameters)</c> (TPM 2.0 Library Part 1,
    /// clause 15.8, equation 16) over the response parameter octets as actually read off the wire.
    /// </summary>
    /// <param name="commandCode">The command code.</param>
    /// <param name="responseParameters">The response parameter area as read.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The rpHash octets.</returns>
    private async Task<byte[]> ComputeRpHashAsync(TpmCcConstants commandCode, ReadOnlyMemory<byte> responseParameters, BaseMemoryPool pool)
    {
        byte[] input = new byte[sizeof(uint) + sizeof(uint) + responseParameters.Length];
        BinaryPrimitives.WriteUInt32BigEndian(input, (uint)TpmRcConstants.TPM_RC_SUCCESS);
        BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(sizeof(uint)), (uint)commandCode);
        responseParameters.Span.CopyTo(input.AsSpan(2 * sizeof(uint)));

        return await HashSha256Async(input, pool).ConfigureAwait(false);
    }

    /// <summary>
    /// Extends an audit session digest by one round: <c>H(old ‖ cpHash ‖ rpHash)</c>, with the Zero Digest of the
    /// session's hash width standing in for <paramref name="priorDigest"/> on the session's first use as an audit
    /// session (TPM 2.0 Library Part 1, clause 17.1, equation 30).
    /// </summary>
    /// <param name="priorDigest">The digest before this extend, or <see langword="null"/> on first use.</param>
    /// <param name="cpHash">The audited command's cpHash.</param>
    /// <param name="rpHash">The audited command's rpHash.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The extended digest.</returns>
    private async Task<byte[]> ExtendAuditDigestAsync(byte[]? priorDigest, byte[] cpHash, byte[] rpHash, BaseMemoryPool pool)
    {
        byte[] old = priorDigest ?? new byte[AuditDigestSize];
        byte[] input = new byte[old.Length + cpHash.Length + rpHash.Length];
        old.CopyTo(input, 0);
        cpHash.CopyTo(input, old.Length);
        rpHash.CopyTo(input, old.Length + cpHash.Length);

        return await HashSha256Async(input, pool).ConfigureAwait(false);
    }

    /// <summary>Computes a raw SHA-256 digest over <paramref name="input"/> through the project's own digest primitive.</summary>
    /// <param name="input">The octets to hash.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The digest octets.</returns>
    private async Task<byte[]> HashSha256Async(ReadOnlyMemory<byte> input, BaseMemoryPool pool)
    {
        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            input, AuditDigestSize, CryptoTags.Sha256Digest, pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        return digest.AsReadOnlySpan().ToArray();
    }

    /// <summary>
    /// Starts a real, unbound and unsalted HMAC session negotiating no symmetric algorithm and folds
    /// <paramref name="authValue"/> into it, with <c>continueSession</c> SET. The caller disposes the session
    /// and flushes the handle.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="authValue">The authorization value the session's command HMAC folds; empty for none.</param>
    /// <returns>The session handle and the host session.</returns>
    private async Task<(uint SessionHandle, TpmSession Session)> StartUnboundHmacSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, ReadOnlyMemory<byte> authValue)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (unbound, unsalted HMAC) failed: '{startResult.ResponseCode}'.");

        //The response owns nothing but nonceTPM, which the session takes over, so it is deliberately not disposed.
        StartAuthSessionResponse started = startResult.Value;
        TpmSession session = new(new TpmHandle(started.SessionHandle.Value), started.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
        if(!authValue.IsEmpty)
        {
            session.SetAuthValue(authValue.Span, pool);
        }

        session.SessionAttributes = TpmaSession.CONTINUE_SESSION;

        return (started.SessionHandle.Value, session);
    }

    /// <summary>Creates a primary ECC P-256 signing key under the owner hierarchy with the given password.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="password">The password bound to the key's retained authorization value.</param>
    /// <param name="isNoDa">Whether the template sets <c>TPMA_OBJECT.noDA</c>, exempting the key from dictionary-attack protection.</param>
    /// <returns>The CreatePrimary response; the caller owns it.</returns>
    private async Task<CreatePrimaryResponse> CreateEccSigningPrimaryAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, string? password, bool isNoDa)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password, TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: isNoDa);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC P-256 signing key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Composes a CreatePrimary input for a DA-protected ECC signing key whose <c>TPMA_OBJECT.userWithAuth</c>
    /// bit is CLEAR — no production factory omits it, so the public template is built directly, mirroring
    /// <see cref="CreatePrimaryInput.ForEccSigningKey"/> with that one attribute bit withheld and
    /// <c>TPMA_OBJECT.noDA</c> never set. Creation itself is authorized by the owner hierarchy, which "operates
    /// as if userWithAuth is SET" (TPM 2.0 Library Part 3, clause 5.6).
    /// </summary>
    /// <param name="password">The real password bound to the key's retained authorization value.</param>
    /// <returns>The command input; the caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the composed sensitive area and public template transfers to the returned CreatePrimaryInput, whose Dispose releases them.")]
    private static CreatePrimaryInput CreateUserWithAuthClearEccSigningKeyInput(string password)
    {
        Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.WithPassword(password, BaseMemoryPool.Shared);

        var attributes =
            TpmaObject.FIXED_TPM |
            TpmaObject.FIXED_PARENT |
            TpmaObject.SENSITIVE_DATA_ORIGIN |
            TpmaObject.SIGN_ENCRYPT;

        Tpm2bPublic inPublic = Tpm2bPublic.CreateEccSigningTemplate(
            TpmAlgIdConstants.TPM_ALG_SHA256,
            attributes,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256));

        return new CreatePrimaryInput(TpmRh.TPM_RH_OWNER, inSensitive, inPublic, Tpm2bData.Empty, TpmlPcrSelection.Empty);
    }

    /// <summary>
    /// Creates and loads a RESTRICTED HMAC signing key: the create gates require <c>sensitiveDataOrigin</c> SET
    /// for a restricted KEYEDHASH key, so its bits are TPM-generated and unknown to the caller.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentHandle">The storage parent handle.</param>
    /// <returns>The loaded key's transient handle and its Name.</returns>
    private async Task<(uint Handle, byte[] Name)> CreateAndLoadRestrictedHmacKeyAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle)
    {
        TpmResult<CreateResponse> createResult = await HmacKeyHarness.CreateHmacKeyAsync(
            tpm, registry, pool, parentHandle, ReadOnlyMemory<byte>.Empty, TpmAlgIdConstants.TPM_ALG_SHA256,
            isRestricted: true, isSensitiveDataOrigin: true, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"Create (restricted HMAC key) failed: '{createResult.ResponseCode}'.");
        using CreateResponse created = createResult.Value;

        TpmResult<LoadResponse> loadResult = await HmacKeyHarness.LoadAsync(
            tpm, registry, pool, parentHandle, created.OutPrivate, created.OutPublic, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(loadResult.IsSuccess, $"Load (restricted HMAC key) failed: '{loadResult.ResponseCode}'.");
        using LoadResponse loaded = loadResult.Value;

        return (loaded.ObjectHandle.Value, loaded.Name.Span.ToArray());
    }

    /// <summary>
    /// Verifies a framed ECDSA signature off-TPM against a P-256 public key reconstructed solely from the
    /// simulator's exported public area — an independent-oracle carve-out: the framework's ECDsa shares no code
    /// path with the signer, so a divergence in either implementation fails here.
    /// </summary>
    /// <param name="key">The CreatePrimary response whose exported public area supplies the point.</param>
    /// <param name="signature">The framed signature response.</param>
    /// <param name="digest">The digest the signature is claimed to be over.</param>
    /// <param name="because">The assertion message describing what the verification proves.</param>
    private static void AssertEcdsaSignatureVerifies(CreatePrimaryResponse key, SignResponse signature, ReadOnlySpan<byte> digest, string because)
    {
        Assert.IsNotNull(signature.Signature.SignatureR, "An ECDSA signature must frame its r component.");
        Assert.IsNotNull(signature.Signature.SignatureS, "An ECDSA signature must frame its s component.");

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

        //The framework's VerifyHash expects the raw IEEE P1363 r || s concatenation, each component fixed-width.
        byte[] p1363Signature = new byte[2 * P256ComponentSize];
        ToFixed(signature.Signature.SignatureR!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(0));
        ToFixed(signature.Signature.SignatureS!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(P256ComponentSize));

        using ECDsa ecdsa = ECDsa.Create(ecParameters);
        Assert.IsTrue(ecdsa.VerifyHash(digest, p1363Signature), because);
    }

    /// <summary>
    /// Left-pads a big-endian integer to a fixed width, as the IEEE P1363 and <c>ECPoint</c> encodings require;
    /// the simulator returns TPM2B integers that may omit leading zero octets.
    /// </summary>
    /// <param name="value">The big-endian value.</param>
    /// <param name="length">The fixed width to pad to.</param>
    /// <returns>A new array of exactly <paramref name="length"/> octets.</returns>
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

    /// <summary>
    /// Wraps the simulator in a device that rewrites the wire bytes of exactly one command code on their way in,
    /// leaving every other command untouched.
    /// </summary>
    /// <param name="simulator">The simulator the rewritten command is submitted to.</param>
    /// <param name="commandCode">The command whose bytes are rewritten.</param>
    /// <param name="rewrite">The rewrite to apply.</param>
    /// <returns>The rewriting device; the caller owns it.</returns>
    private static TpmDevice CreateRewritingDevice(TpmSimulator simulator, TpmCcConstants commandCode, Func<byte[], byte[]> rewrite)
    {
        return TpmDevice.Create(async (command, commandPool, cancellationToken) =>
        {
            byte[] bytes = command.ToArray();
            if(ReadCommandCode(bytes) == commandCode)
            {
                bytes = rewrite(bytes);
            }

            return await simulator.SubmitAsync(bytes, commandPool, cancellationToken).ConfigureAwait(false);
        }, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
    }

    /// <summary>
    /// Wraps the simulator in a device that hands every framed <c>TPM2_Sign()</c> command's bytes to
    /// <paramref name="capture"/> on their way in and forwards them unchanged, so a confidentiality claim can be
    /// checked against what actually crossed the wire.
    /// </summary>
    /// <param name="simulator">The simulator the command is submitted to.</param>
    /// <param name="capture">Receives the framed command's bytes.</param>
    /// <returns>The capturing device; the caller owns it.</returns>
    private static TpmDevice CreateSignCapturingDevice(TpmSimulator simulator, Action<byte[]> capture)
    {
        return TpmDevice.Create(async (command, commandPool, cancellationToken) =>
        {
            byte[] bytes = command.ToArray();
            if(ReadCommandCode(bytes) == TpmCcConstants.TPM_CC_Sign)
            {
                capture(bytes);
            }

            return await simulator.SubmitAsync(bytes, commandPool, cancellationToken).ConfigureAwait(false);
        }, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
    }

    /// <summary>Reads a framed command's <c>commandCode</c> field (TPM 2.0 Library Part 1, clause 15.2.3's commandCode header field).</summary>
    /// <param name="command">The framed command.</param>
    /// <returns>The command code.</returns>
    private static TpmCcConstants ReadCommandCode(ReadOnlySpan<byte> command) =>
        (TpmCcConstants)BinaryPrimitives.ReadUInt32BigEndian(command[6..CommandHeaderSize]);

    /// <summary>Sets one attribute bit in an existing authorization slot's attributes octet, in place.</summary>
    /// <param name="command">The framed command to rewrite.</param>
    /// <param name="handleCount">The command's handle count, which fixes where its authorization area starts.</param>
    /// <param name="sessionIndex">The zero-based slot whose attributes octet is rewritten.</param>
    /// <param name="sessionAttributes">The attribute bits to set.</param>
    private static void SetSessionAttributeBit(byte[] command, int handleCount, int sessionIndex, TpmaSession sessionAttributes)
    {
        int offset = CommandHeaderSize + (handleCount * sizeof(uint)) + sizeof(uint);
        for(int slot = 0; slot < sessionIndex; slot++)
        {
            offset += sizeof(uint);
            offset += sizeof(ushort) + BinaryPrimitives.ReadUInt16BigEndian(command.AsSpan(offset, sizeof(ushort)));
            offset += sizeof(byte);
            offset += sizeof(ushort) + BinaryPrimitives.ReadUInt16BigEndian(command.AsSpan(offset, sizeof(ushort)));
        }

        offset += sizeof(uint);
        offset += sizeof(ushort) + BinaryPrimitives.ReadUInt16BigEndian(command.AsSpan(offset, sizeof(ushort)));
        command[offset] |= (byte)sessionAttributes;
    }

    /// <summary>Builds the response codec registry covering every command these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_Sign, TpmResponseCodec.Sign);

        return registry;
    }

    /// <summary>
    /// Creates a simulator with both the ECC (BouncyCastle) and RSA (framework) signing backends wired, powers
    /// it on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// </summary>
    /// <param name="name">A per-test simulator identifier.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator; the caller owns it.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(string name, BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator(
            name,
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

    /// <summary>
    /// A <c>TPM2_Sign()</c> input that marshals a <c>digest</c> of any width by hand, so a value wider than
    /// <see cref="Tpm2bDigest.MaxSize"/> — which the typed carrier refuses to build — can still ride the
    /// production executor under a real session and be judged where the specification judges it: in the
    /// decryption step, over the plaintext. Every other octet is what <see cref="SignInput"/> writes: a
    /// <c>TPM_ALG_NULL</c> <c>inScheme</c> with no trailing detail and a NULL <c>TPMT_TK_HASHCHECK</c>. It owns
    /// nothing; the digest memory is the caller's.
    /// </summary>
    /// <param name="keyHandle">The signing key's handle.</param>
    /// <param name="digest">The <c>digest</c> octets to marshal, unbounded.</param>
    private sealed class OversizedDigestSignInput(uint keyHandle, ReadOnlyMemory<byte> digest): ITpmCommandInput
    {
        /// <summary>The <c>TPM2_Sign()</c> command code.</summary>
        public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_Sign;

        /// <summary>
        /// <c>digest</c> is a sized <c>TPM2B_DIGEST</c>, so a decrypt session may protect it (TPM 2.0 Library
        /// Part 1, clause 18.1) — the very declaration that routes this frame through the decryption step.
        /// </summary>
        public bool FirstCommandParameterIsEncryptable => true;

        /// <summary>The handle area plus <c>digest ‖ inScheme ‖ validation</c>.</summary>
        /// <returns>The serialized size.</returns>
        public int GetSerializedSize() =>
            sizeof(uint) + sizeof(ushort) + digest.Length + sizeof(ushort) + sizeof(ushort) + sizeof(uint) + sizeof(ushort);

        /// <summary>Writes <c>@keyHandle</c>.</summary>
        /// <param name="writer">The writer.</param>
        public void WriteHandles(ref TpmWriter writer) => writer.WriteUInt32(keyHandle);

        /// <summary>Marshals the unbounded <c>digest</c>, a bare <c>TPM_ALG_NULL</c> <c>inScheme</c>, and a NULL validation ticket.</summary>
        /// <param name="writer">The writer.</param>
        public void WriteParameters(ref TpmWriter writer)
        {
            writer.WriteTpm2b(digest.Span);
            writer.WriteUInt16((ushort)TpmAlgIdConstants.TPM_ALG_NULL);
            writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_HASHCHECK);
            writer.WriteUInt32((uint)TpmRh.TPM_RH_NULL);
            writer.WriteUInt16(0);
        }
    }

    /// <summary>
    /// An authorization area holds "at least one but no more than three" blocks, and with one authorizing slot
    /// Table 12's positions 2 and 3 are both open to a session used only for encryption, decryption, or audit:
    /// a three-block area — the key's session, a decrypt companion at index 1, and a companion at index 2
    /// claiming nothing — is read to its third block and refused for THAT block's attributes, encoded to index 2
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 15.6.1, Table 12, and clause 15.6.4; Part 2: Structures,
    /// clause 6.6.2). The refusal's index is what proves the third position was admitted and read at all.
    /// </summary>
    [TestMethod]
    public async Task SignWithAThreeBlockAreaRefusesTheThirdCompanionClaimingNothingAtIndexTwo()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignWithAThreeBlockAreaRefusesTheThirdCompanionClaimingNothingAtIndexTwo), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, SigningKeyPassword, isNoDa: true).ConfigureAwait(false);

        (uint keySessionHandle, TpmSession keySession) = await StartUnboundHmacSessionAsync(tpm, registry, pool, SigningKeyPasswordBytes).ConfigureAwait(false);
        (uint decryptCompanionHandle, TpmSession decryptCompanion) = await HmacKeyHarness.StartBoundHmacSessionAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmtSymDef.Xor(HmacSessionAlg),
            isBoundToAuthorizedEntity: false, TestContext.CancellationToken).ConfigureAwait(false);
        (uint idleCompanionHandle, TpmSession idleCompanion) = await HmacKeyHarness.StartBoundHmacSessionAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, TestContext.CancellationToken).ConfigureAwait(false);

        try
        {
            decryptCompanion.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;
            idleCompanion.SessionAttributes = TpmaSession.CONTINUE_SESSION;

            using SignInput input = SignInput.ForEcdsa(key.ObjectHandle, Sha256WidthDigest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            ReadOnlyMemory<byte>[] handleNames = [key.Name.Span.ToArray()];

            TpmResult<SignResponse> result = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
                tpm, input, [keySession, decryptCompanion, idleCompanion], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            if(result.IsSuccess)
            {
                result.Value.Dispose();
            }

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_ATTRIBUTES, result.BaseError,
                "A third block authorizing no entity must claim at least one of decrypt, encrypt, or audit.");
            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 2), result.ResponseCode,
                "The refusal names the third block (index 2): Table 12's third position was admitted and read.");
        }
        finally
        {
            idleCompanion.Dispose();
            decryptCompanion.Dispose();
            keySession.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, idleCompanionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, decryptCompanionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, keySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }
}
