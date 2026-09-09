using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Nv;
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
/// Drives the audit session's bind loss (TPM 2.0 Library Part 1, clause 17.1), the ciphertext cpHash a decrypt
/// companion leaves for a co-present audit session to fold (clause 17.1, NOTE), the policy-session refusal at a
/// generic authorizing slot and at a policy-admitting arm (clause 15.6.4, Table 15), and a refused parameter over
/// an already-established audit session (clause 17.1, "when a command fails, the audit session digest is not
/// changed") — against the in-house behavioural <see cref="TpmSimulator"/>, entirely in-process, through the
/// production command path (<see cref="TpmCommandExecutor"/>, the real command inputs, and the real response
/// codecs). Every audit digest a test asserts is chained by the test itself from the command's own wire octets —
/// cpHash per <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
/// Part 1, clause 15.7</see> equation 15, rpHash per clause 15.8 equation 16, and the fold per clause 17.1
/// equation 30 — using the project's own digest primitive, never <see cref="TpmSession"/>'s internal computation;
/// every read-back runs through the production <see cref="TpmCommandExecutor"/> with <c>TPM2_GetSessionAuditDigest()</c>'s
/// NULL signer.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorAuditSessionBindingTests
{
    /// <summary>The hash algorithm every session in this class negotiates.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The SHA-256 digest width, in octets — the audit digest width and the cpHash/rpHash width throughout.</summary>
    private const int Sha256DigestSize = 32;

    /// <summary>The Zero Digest an audit session's first use extends from (TPM 2.0 Library Part 1, clause 17.1).</summary>
    private static byte[] ZeroDigestSha256 { get; } = new byte[Sha256DigestSize];

    /// <summary>The DA-protected, non-empty-authValue NV Index this class binds a session to, from the assigned handle block.</summary>
    private const uint BoundNvIndexHandle = 0x0100_0280;

    /// <summary>The declared data size of <see cref="BoundNvIndexHandle"/>.</summary>
    private const ushort BoundNvIndexDataSize = 16;

    /// <summary>The non-empty authValue <see cref="BoundNvIndexHandle"/> is defined with — the bind target's own secret.</summary>
    private static byte[] BoundIndexAuth { get; } = [0x71, 0x62, 0x53, 0x44, 0x35, 0x26, 0x17, 0x08];

    /// <summary>The sixteen octets written to <see cref="BoundNvIndexHandle"/> before it is read; an Index must be written before <c>TPM2_NV_Read()</c> admits it.</summary>
    private static byte[] BoundIndexData { get; } =
        [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F];

    /// <summary>Ordinary Index attributes leaving dictionary-attack protection SET, so the bind entity lends real DA protection to the session it binds (TPM 2.0 Library Part 1, clause 16.8.1).</summary>
    private const TpmaNv DaProtectedIndexAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_OWNERWRITE;

    /// <summary>A second bind-target Index for the pool-balance test, kept distinct so the two tests never share simulator-independent state.</summary>
    private const uint PoolTestNvIndexHandle = 0x0100_0281;

    /// <summary>The plaintext octets a <c>TPM2_StirRandom()</c> case sends as <c>inData</c> — arbitrary, tied to no published vector.</summary>
    private static byte[] StirPlaintext { get; } = [0x5A, 0xA5, 0x3C, 0xC3, 0x18, 0x81, 0x66, 0x99];

    /// <summary>A digest of ECDSA/SHA-256's own width to sign in the audit-session Sign cases.</summary>
    private static byte[] Sha256WidthDigest { get; } = Convert.FromHexString("00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f");

    /// <summary>A digest one hash family narrower than <see cref="Sha256WidthDigest"/> — the wrong width for the SHA-256 ECDSA scheme, which is what makes it a probe.</summary>
    private static byte[] Sha1WidthDigest { get; } = Convert.FromHexString("00112233445566778899aabbccddeeff10213243");

    /// <summary>The password an ECC signing key in this class is created with.</summary>
    private const string SigningKeyPassword = "audit-binding-sign-key";

    /// <summary><see cref="SigningKeyPassword"/>'s UTF-8 octets.</summary>
    private static byte[] SigningKeyPasswordBytes { get; } = System.Text.Encoding.UTF8.GetBytes(SigningKeyPassword);

    /// <summary>The HMAC key seed the wrong-width-digest Sign case's KEYEDHASH key is created from — arbitrary octets, tied to no published vector.</summary>
    private static byte[] HmacKeySeed { get; } = [0x2A, 0x3B, 0x4C, 0x5D, 0x6E, 0x7F, 0x80, 0x91, 0xA2, 0xB3, 0xC4, 0xD5, 0xE6, 0xF7, 0x08, 0x19];

    /// <summary>A short secret the sealed-object fixture in the policy-admitting-arm case seals; arbitrary octets tied to no published vector.</summary>
    private static byte[] SealedSecretBytes { get; } = [0x11, 0x22, 0x33, 0x44];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// A session bound to an NV Index whose authValue is non-empty, used FIRST as an audit-claiming session
    /// authorizing that same Index at <c>TPM2_NV_Read()</c>: the omitted-authValue HMAC key still matches (the
    /// bind is intact) and the command's own response authorization verifies under that pre-loss key. From the
    /// next command on, the same omitted-authValue key is refused — "the bind value is lost and any further use
    /// of the session for authorization will require that the authValue be used in the HMAC" — answered
    /// session-encoded <c>TPM_RC_AUTH_FAIL</c> because the Index is dictionary-attack protected (a DA-protected
    /// bound entity's mismatch is <c>RejectSessionAuthFailure</c>'s charging arm, not the exempt entity's
    /// non-charging <c>TPM_RC_BAD_AUTH</c>) — while folding the authValue succeeds.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.1</see>.
    /// </summary>
    [TestMethod]
    public async Task BoundAuditSessionLosesItsBindOnFirstAuditUse()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(BoundAuditSessionLosesItsBindOnFirstAuditUse), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await DefineAndWriteBoundIndexAsync(tpm, registry, pool, BoundNvIndexHandle, BoundIndexAuth, BoundIndexData).ConfigureAwait(false);
        byte[] indexName = await ReadIndexNameAsync(tpm, BoundNvIndexHandle).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await HmacKeyHarness.StartBoundHmacSessionAsync(
            tpm, registry, pool, BoundNvIndexHandle, BoundIndexAuth, TpmtSymDef.Null, isBoundToAuthorizedEntity: false, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            session.SetAuthValue(ReadOnlyMemory<byte>.Empty.Span, pool);
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

            TpmResult<NvReadResponse> firstUse = await ReadBoundIndexAsync(tpm, registry, pool, BoundNvIndexHandle, session, indexName).ConfigureAwait(false);
            Assert.IsTrue(
                firstUse.IsSuccess,
                $"The bind is still intact on the session's first audit use, so the omitted-authValue key must authorize and the response must verify under it: '{firstUse.ResponseCode}'.");
            firstUse.Value.Dispose();

            session.SessionAttributes = TpmaSession.CONTINUE_SESSION;
            TpmResult<NvReadResponse> afterLoss = await ReadBoundIndexAsync(tpm, registry, pool, BoundNvIndexHandle, session, indexName).ConfigureAwait(false);
            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), afterLoss.ResponseCode,
                "authHandle's authorizing session, session 1 of Table 265, is refused with session-encoded TPM_RC_AUTH_FAIL once the bind is lost: the omitted-authValue key no longer matches the DA-protected Index's own HMAC key.");

            session.SetAuthValue(BoundIndexAuth, pool);
            TpmResult<NvReadResponse> folded = await ReadBoundIndexAsync(tpm, registry, pool, BoundNvIndexHandle, session, indexName).ConfigureAwait(false);
            Assert.IsTrue(
                folded.IsSuccess,
                $"Folding the entity's authValue into the HMAC key, as the bind loss now requires, must authorize: '{folded.ResponseCode}'.");
            folded.Value.Dispose();
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A single session claiming BOTH <c>decrypt</c> and <c>audit</c> together over <c>TPM2_StirRandom()</c> —
    /// admissible since "this attribute can be used in combination with any other session attributes" and this
    /// simulator's <c>TPM2_StirRandom()</c> over-session form parses exactly one authorization slot, so a decrypt
    /// companion and an audit companion can only coincide on the SAME session: the octets the session's own
    /// command HMAC covered — and that its audit digest folds — are the CIPHERTEXT parameter area as sent on the
    /// wire, not the plaintext the caller composed. The test independently chains both the plaintext-keyed and
    /// the ciphertext-keyed cpHash and asserts the read-back digest matches the ciphertext one alone.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.1, NOTE; Part 2, clause 8.4, Table 38</see>.
    /// </summary>
    [TestMethod]
    public async Task AuditCompanionOverADecryptProtectedStirRandomChainsTheCiphertextCpHash()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(AuditCompanionOverADecryptProtectedStirRandomChainsTheCiphertextCpHash), pool).ConfigureAwait(false);
        List<(TpmCcConstants Code, byte[] Command, byte[] Response)> wire = [];
        using TpmDevice tpm = CreateRecordingDevice(simulator, wire);
        TpmResponseRegistry registry = CreateRegistry();

        (uint sessionHandle, TpmSession session) = await HmacKeyHarness.StartBoundHmacSessionAsync(
            tpm, registry, pool, (uint)TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, TpmtSymDef.Xor(SessionAlg), isBoundToAuthorizedEntity: false, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT | TpmaSession.AUDIT;

            using Tpm2bSensitiveData inData = Tpm2bSensitiveData.Create(StirPlaintext, pool);
            var input = new StirRandomInput(inData);
            TpmResult<StirRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<StirRandomResponse>(
                tpm, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"A session claiming decrypt and audit together over TPM2_StirRandom() must succeed: '{result.ResponseCode}'.");

            (TpmCcConstants Code, byte[] Command, byte[] Response) audited = wire[^1];
            ReadOnlyMemory<byte> ciphertextParameters = ExtractZeroHandleCommandParameters(audited.Command, session.GetAuthCommandSize());

            byte[] plaintextParameters = new byte[sizeof(ushort) + StirPlaintext.Length];
            BinaryPrimitives.WriteUInt16BigEndian(plaintextParameters, (ushort)StirPlaintext.Length);
            StirPlaintext.CopyTo(plaintextParameters.AsSpan(sizeof(ushort)));

            Assert.IsFalse(
                ciphertextParameters.Span.SequenceEqual(plaintextParameters),
                "A decrypt-protected first parameter must ride the wire transformed; an unchanged parameter area would mean nothing was actually encrypted.");

            byte[] plaintextCpHash = await ComputeCpHashAsync(TpmCcConstants.TPM_CC_StirRandom, [], plaintextParameters, pool).ConfigureAwait(false);
            byte[] ciphertextCpHash = await ComputeCpHashAsync(TpmCcConstants.TPM_CC_StirRandom, [], ciphertextParameters, pool).ConfigureAwait(false);
            byte[] rpHash = await ComputeRpHashAsync(TpmCcConstants.TPM_CC_StirRandom, ReadOnlyMemory<byte>.Empty, pool).ConfigureAwait(false);

            byte[] plaintextDigest = await ExtendAuditDigestAsync(priorDigest: null, plaintextCpHash, rpHash, pool).ConfigureAwait(false);
            byte[] ciphertextDigest = await ExtendAuditDigestAsync(priorDigest: null, ciphertextCpHash, rpHash, pool).ConfigureAwait(false);

            (TpmiYesNo _, byte[] readBack) = await ReadAuditDigestAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);

            Assert.IsTrue(
                readBack.AsSpan().SequenceEqual(ciphertextDigest),
                "The audit digest must chain the CIPHERTEXT cpHash — the octets the command HMAC actually covered on the wire.");
            Assert.IsFalse(
                readBack.AsSpan().SequenceEqual(plaintextDigest),
                "The audit digest must NOT chain the plaintext cpHash: audit within an encrypted session records the encrypted cpHash.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A loaded POLICY session at <c>TPM2_Sign()</c>'s generic key slot claiming <c>audit</c> is refused
    /// session-encoded <c>TPM_RC_ATTRIBUTES</c> — "This attribute is not allowed to be SET in a policy or trial
    /// policy session" — pinned alongside the SAME session, without the claim, still answering the standing bare
    /// <c>TPM_RC_AUTH_TYPE</c> a policy session earns at a generic slot regardless of audit.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 15.6.4, Table 15</see>.
    /// </summary>
    [TestMethod]
    public async Task PolicySessionAtSignsGenericSlotClaimingAuditIsRefusedWithAttributesWhileWithoutAuditItIsAuthType()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(PolicySessionAtSignsGenericSlotClaimingAuditIsRefusedWithAttributesWhileWithoutAuditItIsAuthType), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<StartAuthSessionResponse> policyStartResult = await tpm.StartPolicySessionAsync(SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(policyStartResult.IsSuccess, $"StartAuthSession (policy) failed: '{policyStartResult.ResponseCode}'.");

        StartAuthSessionResponse policyStarted = policyStartResult.Value;
        uint policySessionHandle = policyStarted.SessionHandle.Value;
        try
        {
            using TpmSession policySlotSession = new(new TpmHandle(policySessionHandle), policyStarted.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), pool);
            ReadOnlyMemory<byte>[] handleNames = [key.Name.Span.ToArray()];

            policySlotSession.SessionAttributes = TpmaSession.CONTINUE_SESSION;
            using SignInput withoutAudit = SignInput.Create(key.ObjectHandle, Sha256WidthDigest, TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            TpmResult<SignResponse> withoutAuditResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
                tpm, withoutAudit, [policySlotSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_AUTH_TYPE, withoutAuditResult.ResponseCode,
                "A policy session at a generic authorizing slot, without an audit claim, answers the standing bare TPM_RC_AUTH_TYPE.");

            policySlotSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
            using SignInput withAudit = SignInput.Create(key.ObjectHandle, Sha256WidthDigest, TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            TpmResult<SignResponse> withAuditResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
                tpm, withAudit, [policySlotSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0), withAuditResult.ResponseCode,
                "keyHandle's authorizing session, session 1 of Table 122, claiming audit at a policy session's generic authorizing slot must be refused session-encoded TPM_RC_ATTRIBUTES, ahead of the standing AUTH_TYPE refusal.");
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, policySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_Unseal()</c>'s policy arm: a sealed object whose <c>authPolicy</c> is satisfied by
    /// <c>TPM2_PolicyCommandCode(TPM_CC_Unseal)</c> then <c>TPM2_PolicyAuthValue()</c>, presented at the sole
    /// authorizing slot with <c>audit</c> SET is refused session-encoded <c>TPM_RC_ATTRIBUTES</c> — the
    /// policy-admitting arm's own gate, distinct from the generic-slot AUTH_TYPE refusal since this arm otherwise
    /// admits the policy session — while the same satisfied session, without the claim, still unseals.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 15.6.4, Table 15</see>.
    /// </summary>
    [TestMethod]
    public async Task PolicySessionSatisfyingUnsealsAuthPolicyClaimingAuditIsRefusedWithAttributesWhileWithoutAuditItSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(PolicySessionSatisfyingUnsealsAuthPolicyClaimingAuditIsRefusedWithAttributesWhileWithoutAuditItSucceeds), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] unsealPolicyDigest = ComputeUnsealPolicyDigest();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SealedSecretBytes, pool);
        using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy: unsealPolicyDigest, noDa: true);
        using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession createParentAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, createInput, [createParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"TPM2_Create() (policy-gated seal) failed: '{createResult.ResponseCode}'.");
        using CreateResponse sealedObject = createResult.Value;

        using LoadResponse loaded = await LoadChildAsync(tpm, registry, pool, parentHandle, sealedObject.OutPrivate, sealedObject.OutPublic).ConfigureAwait(false);
        uint objectHandle = loaded.ObjectHandle.Value;
        byte[] objectName = loaded.Name.Span.ToArray();

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

            using TpmPolicySession auditingSession = TpmPolicySession.ForSessionWithPassword(sessionHandle, SessionAlg, ReadOnlySpan<byte>.Empty, TestEntropy.NewCounterStream(), pool);
            auditingSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
            UnsealInput auditedUnsealInput = UnsealInput.ForItem(TpmiDhObject.FromValue(objectHandle));
            TpmResult<UnsealResponse> auditedResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                tpm, auditedUnsealInput, [auditingSession], [objectName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0), auditedResult.ResponseCode,
                "itemHandle's authorizing session, session 1 of Table 30, satisfying the object's authPolicy while claiming audit at Unseal's authorizing slot, must be refused session-encoded TPM_RC_ATTRIBUTES.");

            using TpmPolicySession plainSession = TpmPolicySession.ForSessionWithPassword(sessionHandle, SessionAlg, ReadOnlySpan<byte>.Empty, TestEntropy.NewCounterStream(), pool);
            UnsealInput plainUnsealInput = UnsealInput.ForItem(TpmiDhObject.FromValue(objectHandle));
            TpmResult<UnsealResponse> plainResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                tpm, plainUnsealInput, [plainSession], [objectName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(
                plainResult.IsSuccess,
                $"The refusal above must not have consumed the satisfied policy: the same session, without the audit claim, must still unseal: '{plainResult.ResponseCode}'.");
            plainResult.Value.Dispose();
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, objectHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, parentHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A refused PARAMETER (a digest of the wrong width for the key's scheme) over an ESTABLISHED audit session,
    /// with a genuinely good command HMAC, leaves the audit digest exactly where the first, successful command
    /// left it — "when a command fails, the audit session digest is not changed" — and, since no intervening
    /// session-admitting command ran between the two Sign calls, the session's exclusivity (granted on the first,
    /// successful use) is unaffected by the failure either (clause 17.5: "if a session was exclusive before the
    /// command failure, it is exclusive after the command failure").
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.1; clause 17.5</see>.
    /// </summary>
    [TestMethod]
    public async Task SignOverAnEstablishedAuditSessionRefusedByAWrongWidthDigestLeavesTheDigestUnchangedAndExclusive()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(SignOverAnEstablishedAuditSessionRefusedByAWrongWidthDigestLeavesTheDigestUnchangedAndExclusive), pool).ConfigureAwait(false);
        List<(TpmCcConstants Code, byte[] Command, byte[] Response)> wire = [];
        using TpmDevice tpm = CreateRecordingDevice(simulator, wire);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, HmacKeySeed, TpmAlgIdConstants.TPM_ALG_SHA256,
            userAuth: SigningKeyPasswordBytes, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        ReadOnlyMemory<byte>[] handleNames = [key.Name.AsReadOnlyMemory()];

        (uint sessionHandle, TpmSession session) = await StartUnboundHmacSessionAsync(tpm, registry, pool, SigningKeyPasswordBytes).ConfigureAwait(false);
        try
        {
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

            using SignInput firstInput = SignInput.Create(TpmiDhObject.FromValue(key.Handle), Sha256WidthDigest, TpmAlgIdConstants.TPM_ALG_HMAC, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            TpmResult<SignResponse> first = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
                tpm, firstInput, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(first.IsSuccess, $"The first, correctly-widthed Sign over the audit-claiming session must succeed: '{first.ResponseCode}'.");
            first.Value.Dispose();

            byte[] firstParameters = ReadResponseParameters(wire[^1].Response, outHandleCount: 0);
            byte[] firstParametersWritten = SerializeSignParameters(firstInput);
            byte[] cpHash1 = await ComputeCpHashAsync(TpmCcConstants.TPM_CC_Sign, handleNames, firstParametersWritten, pool).ConfigureAwait(false);
            byte[] rpHash1 = await ComputeRpHashAsync(TpmCcConstants.TPM_CC_Sign, firstParameters, pool).ConfigureAwait(false);
            byte[] establishedDigest = await ExtendAuditDigestAsync(priorDigest: null, cpHash1, rpHash1, pool).ConfigureAwait(false);

            using SignInput secondInput = SignInput.Create(TpmiDhObject.FromValue(key.Handle), Sha1WidthDigest, TpmAlgIdConstants.TPM_ALG_HMAC, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            TpmResult<SignResponse> second = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
                tpm, secondInput, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            if(second.IsSuccess)
            {
                second.Value.Dispose();
            }
            Assert.AreEqual(
                HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), second.ResponseCode,
                "digest, parameter 1 of Table 122, whose width differs from the key's scheme hash must be refused parameter-encoded TPM_RC_SIZE — the command rule runs after authorization, so the good HMAC does not save it.");

            (TpmiYesNo exclusive, byte[] readBack) = await ReadAuditDigestAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
            Assert.IsTrue(
                readBack.AsSpan().SequenceEqual(establishedDigest),
                "The failed second command must not extend the digest: the read-back must equal the chain of the first command alone.");
            Assert.IsTrue(
                exclusive.IsYes,
                "No session-admitting command intervened between the two Sign calls, so the exclusivity the first, successful use granted must still hold after the failure.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The house pool balances across the bound session's two successful authorizations (the bind-omitted first
    /// use, then the authValue-folded use after the bind is lost) and a decrypt-plus-audit companion session over
    /// <c>TPM2_StirRandom()</c>: every carrier the exchanges rent — cpHash inputs, the fold input, the HMAC
    /// buffers, the ciphertext parameter area — comes back. The balance is measured against a BASELINE taken
    /// once setup (defining the bound Index; priming the RNG's own one-time-per-simulator reseed carrier, "the
    /// reseed state the RNG keeps for the life of the TPM") is complete, since those carriers are simulator
    /// state legitimately outstanding for the simulator's whole life, not rentals the tested exchanges owe back.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17</see>.
    /// </summary>
    [TestMethod]
    public async Task TheMeteredPoolBalancesAcrossTheBoundSessionsTwoAuthorizationsAndTheDecryptAuditPair()
    {
        using var metered = new MeteredHousePool();
        BaseMemoryPool pool = metered.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(TheMeteredPoolBalancesAcrossTheBoundSessionsTwoAuthorizationsAndTheDecryptAuditPair), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await DefineAndWriteBoundIndexAsync(tpm, registry, pool, PoolTestNvIndexHandle, BoundIndexAuth, BoundIndexData).ConfigureAwait(false);
        byte[] indexName = await ReadIndexNameAsync(tpm, PoolTestNvIndexHandle).ConfigureAwait(false);

        using Tpm2bSensitiveData primingData = Tpm2bSensitiveData.Create(StirPlaintext, pool);
        TpmResult<StirRandomResponse> primed = await TpmCommandExecutor.ExecuteAsync<StirRandomResponse>(
            tpm, new StirRandomInput(primingData), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primed.IsSuccess, $"Priming the RNG's one-time reseed carrier must succeed: '{primed.ResponseCode}'.");

        long baseline = metered.OutstandingCount;

        (uint boundHandle, TpmSession boundSession) = await HmacKeyHarness.StartBoundHmacSessionAsync(
            tpm, registry, pool, PoolTestNvIndexHandle, BoundIndexAuth, TpmtSymDef.Null, isBoundToAuthorizedEntity: false, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            boundSession.SetAuthValue(ReadOnlyMemory<byte>.Empty.Span, pool);
            boundSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
            TpmResult<NvReadResponse> firstUse = await ReadBoundIndexAsync(tpm, registry, pool, PoolTestNvIndexHandle, boundSession, indexName).ConfigureAwait(false);
            Assert.IsTrue(firstUse.IsSuccess, $"The bound session's first (bind-omitted) authorization must succeed: '{firstUse.ResponseCode}'.");
            firstUse.Value.Dispose();

            boundSession.SetAuthValue(BoundIndexAuth, pool);
            boundSession.SessionAttributes = TpmaSession.CONTINUE_SESSION;
            TpmResult<NvReadResponse> secondUse = await ReadBoundIndexAsync(tpm, registry, pool, PoolTestNvIndexHandle, boundSession, indexName).ConfigureAwait(false);
            Assert.IsTrue(secondUse.IsSuccess, $"The bound session's second (authValue-folded) authorization must succeed: '{secondUse.ResponseCode}'.");
            secondUse.Value.Dispose();
        }
        finally
        {
            boundSession.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, boundHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }

        (uint pairHandle, TpmSession pairSession) = await HmacKeyHarness.StartBoundHmacSessionAsync(
            tpm, registry, pool, (uint)TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, TpmtSymDef.Xor(SessionAlg), isBoundToAuthorizedEntity: false, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            pairSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT | TpmaSession.AUDIT;

            using Tpm2bSensitiveData inData = Tpm2bSensitiveData.Create(StirPlaintext, pool);
            var input = new StirRandomInput(inData);
            TpmResult<StirRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<StirRandomResponse>(
                tpm, input, [pairSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"The decrypt-plus-audit companion session over TPM2_StirRandom() must succeed: '{result.ResponseCode}'.");
        }
        finally
        {
            pairSession.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, pairHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }

        Assert.AreEqual(
            baseline, metered.OutstandingCount,
            "Every carrier the bound session's two authorizations and the decrypt/audit companion session rented, beyond the simulator's own already-outstanding setup state, must have been returned.");
    }

    /// <summary>Defines an Ordinary Index with a non-empty, dictionary-attack-protected authValue and writes it, so a subsequent <c>TPM2_NV_Read()</c> is admitted.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    /// <param name="authValue">The Index's own authValue.</param>
    /// <param name="data">The octets written to the Index.</param>
    private async Task DefineAndWriteBoundIndexAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint nvIndex, ReadOnlyMemory<byte> authValue, ReadOnlyMemory<byte> data)
    {
        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);
        using var auth = Tpm2bAuth.Create(authValue.Span, pool);
        using var publicInfo = new TpmsNvPublic(nvIndex, TpmAlgIdConstants.TPM_ALG_SHA256, DaProtectedIndexAttributes, Tpm2bDigest.Empty, BoundNvIndexDataSize);
        using var defineInput = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, auth, publicInfo);
        TpmResult<NvDefineSpaceResponse> defineResult = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            tpm, defineInput, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"TPM2_NV_DefineSpace(0x{nvIndex:X8}) failed: '{defineResult.ResponseCode}'.");

        using TpmPasswordSession writeAuth = TpmPasswordSession.Create(authValue.Span, pool);
        using Tpm2bMaxNvBuffer buffer = Tpm2bMaxNvBuffer.Create(data.Span, pool);
        var writeInput = new NvWriteInput(nvIndex, nvIndex, buffer, Offset: 0);
        TpmResult<NvWriteResponse> writeResult = await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
            tpm, writeInput, [writeAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(writeResult.IsSuccess, $"TPM2_NV_Write(0x{nvIndex:X8}) failed: '{writeResult.ResponseCode}'.");
    }

    /// <summary>Reads an Index's Name through <c>TPM2_NV_ReadPublic()</c>, the cpHash Name term an Index-arm authorization folds.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="nvIndex">The Index whose Name is wanted.</param>
    /// <returns>The Index's Name.</returns>
    private async Task<byte[]> ReadIndexNameAsync(TpmDevice tpm, uint nvIndex)
    {
        TpmResult<NvReadPublicResponse> nameResult = await tpm.NvReadPublicAsync(nvIndex, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(nameResult.IsSuccess, $"NvReadPublicAsync(0x{nvIndex:X8}) failed: '{nameResult.ResponseCode}'.");

        using NvReadPublicResponse namePublic = nameResult.Value;

        return namePublic.NvName.Span.ToArray();
    }

    /// <summary>Issues an Index-arm <c>TPM2_NV_Read()</c> over <paramref name="session"/>, both handles the same bound Index.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The bound Index's handle.</param>
    /// <param name="session">The authorizing session.</param>
    /// <param name="indexName">The Index's own Name, folded as both cpHash Name terms.</param>
    /// <returns>The read result.</returns>
    private async Task<TpmResult<NvReadResponse>> ReadBoundIndexAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint nvIndex, TpmSession session, ReadOnlyMemory<byte> indexName)
    {
        var input = new NvReadInput(AuthHandle: nvIndex, NvIndex: nvIndex, Size: (ushort)BoundIndexData.Length, Offset: 0);
        ReadOnlyMemory<byte>[] handleNames = [indexName, indexName];

        return await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
            tpm, input, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Starts an unbound, unsalted HMAC session negotiating no symmetric algorithm, with <paramref name="authValue"/> folded and <c>continueSession</c> SET.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="authValue">The authorization value the session's command HMAC folds.</param>
    /// <returns>The session handle and the host session.</returns>
    private async Task<(uint Handle, TpmSession Session)> StartUnboundHmacSessionAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, ReadOnlyMemory<byte> authValue)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (unbound HMAC) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        var session = new TpmSession(new TpmHandle(started.SessionHandle.Value), started.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), pool);
        session.SetAuthValue(authValue.Span, pool);
        session.SessionAttributes = TpmaSession.CONTINUE_SESSION;

        return (started.SessionHandle.Value, session);
    }

    /// <summary>Starts an unbound, unsalted HMAC session with an empty authorization value — an unauthorizing audit companion.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The session handle and the host session.</returns>
    private async Task<(uint Handle, TpmSession Session)> StartUnboundAuditSessionAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (unbound HMAC) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        var session = new TpmSession(new TpmHandle(started.SessionHandle.Value), started.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), pool);

        return (started.SessionHandle.Value, session);
    }

    /// <summary>Creates a primary ECC P-256 signing key under the owner hierarchy with <see cref="SigningKeyPassword"/>, exempt from dictionary-attack protection.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response; the caller owns it.</returns>
    private async Task<CreatePrimaryResponse> CreateEccSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, SigningKeyPassword, TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC P-256 signing key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Loads a child under <paramref name="parentHandle"/> from its create-time output blobs, authorized by the parent's empty password.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentHandle">The loaded parent's handle.</param>
    /// <param name="outPrivate">The child's private area, as returned by <c>TPM2_Create()</c>.</param>
    /// <param name="outPublic">The child's public area, as returned by <c>TPM2_Create()</c>.</param>
    /// <returns>The load response; the caller owns it.</returns>
    private async Task<LoadResponse> LoadChildAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle, Tpm2bPrivate outPrivate, Tpm2bPublic outPublic)
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

    /// <summary>Reserializes a public area into a fresh, independently owned carrier, since <see cref="LoadInput"/> owns and disposes the copy it is given.</summary>
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

    /// <summary>Predicts the policyDigest a fresh session must accumulate to satisfy Unseal's authPolicy: <c>H(0...0 ‖ TPM_CC_PolicyCommandCode ‖ TPM_CC_Unseal)</c> then extended for PolicyAuthValue.</summary>
    /// <returns>The predicted authPolicy.</returns>
    private static byte[] ComputeUnsealPolicyDigest()
    {
        byte[] afterCommandCode = new byte[Sha256DigestSize];
        _ = TpmPolicyDigest.ExtendForCommandCode(new byte[Sha256DigestSize], TpmCcConstants.TPM_CC_Unseal, SessionAlg, afterCommandCode, BaseMemoryPool.Shared);

        byte[] afterAuthValue = new byte[Sha256DigestSize];
        _ = TpmPolicyDigest.ExtendForAuthValue(afterCommandCode, SessionAlg, afterAuthValue, BaseMemoryPool.Shared);

        return afterAuthValue;
    }

    /// <summary>Starts an unbound, unsalted policy session.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The started session's handle.</returns>
    private async Task<uint> StartPolicySessionAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        StartAuthSessionInput input = StartAuthSessionInputExtensions.CreateUnboundUnsaltedPolicySession(SessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> result = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"StartAuthSession (policy) failed: '{result.ResponseCode}'.");
        using StartAuthSessionResponse response = result.Value;

        return response.SessionHandle.Value;
    }

    /// <summary>Serializes a <c>TPM2_Sign()</c> input's parameter area alone — the octets sent after its one handle — by invoking <see cref="ITpmCommandInput.WriteParameters"/> a second time over a freshly rented buffer.</summary>
    /// <param name="input">The command input.</param>
    /// <returns>The parameter octets, in the order <see cref="ITpmCommandInput.WriteParameters"/> writes them.</returns>
    private static byte[] SerializeSignParameters(SignInput input)
    {
        const int HandleCount = 1;
        int parametersSize = input.GetSerializedSize() - (HandleCount * sizeof(uint));
        byte[] buffer = new byte[parametersSize];
        var writer = new TpmWriter(buffer);
        input.WriteParameters(ref writer);

        return buffer;
    }

    /// <summary>Reads the response parameter area out of a captured raw response's octets, independent of whatever the codec parsed them into.</summary>
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
    /// Extracts a zero-handle command's parameter area from its captured wire octets by subtraction: header
    /// (tag ‖ commandSize ‖ commandCode), the authorizationSize field, then <paramref name="authAreaSize"/>
    /// octets of authorization area — the remainder is the parameter area exactly as sent, ciphertext included
    /// when a decrypt session protected it.
    /// </summary>
    /// <param name="commandBytes">The raw command octets.</param>
    /// <param name="authAreaSize">The total size, in octets, of every <c>TPMS_AUTH_COMMAND</c> entry in submission order.</param>
    /// <returns>The parameter area as sent.</returns>
    private static ReadOnlyMemory<byte> ExtractZeroHandleCommandParameters(byte[] commandBytes, int authAreaSize)
    {
        int offset = TpmHeader.HeaderSize + sizeof(uint) + authAreaSize;

        return commandBytes.AsMemory(offset);
    }

    /// <summary>
    /// Computes <c>cpHash = H_sessionAlg(commandCode ‖ Name1 ‖ Name2 ‖ … ‖ parameters)</c> (TPM 2.0 Library Part
    /// 1, clause 15.7, equation 15) over octets this test assembled or captured itself.
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
    /// session's hash width standing in for <paramref name="priorDigest"/> on a first use (TPM 2.0 Library Part
    /// 1, clause 17.1, equation 30).
    /// </summary>
    /// <param name="priorDigest">The digest before this extend, or <see langword="null"/> on first use.</param>
    /// <param name="cpHash">The audited command's cpHash.</param>
    /// <param name="rpHash">The audited command's rpHash.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The extended digest.</returns>
    private async Task<byte[]> ExtendAuditDigestAsync(byte[]? priorDigest, byte[] cpHash, byte[] rpHash, BaseMemoryPool pool)
    {
        byte[] old = priorDigest ?? ZeroDigestSha256;
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
            input, Sha256DigestSize, CryptoTags.Sha256Digest, pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        return digest.AsReadOnlySpan().ToArray();
    }

    /// <summary>
    /// Reads back an audit session's status through <c>TPM2_GetSessionAuditDigest()</c>'s NULL signer (Part 3,
    /// clause 18.1: "the attestation block is 'signed' with the NULL Signature"), authorized against the Empty
    /// Buffer at both slots.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sessionHandle">The audit session's handle.</param>
    /// <returns>Whether the session is currently exclusive, and its attested digest.</returns>
    private async Task<(TpmiYesNo Exclusive, byte[] Digest)> ReadAuditDigestAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint sessionHandle)
    {
        using GetSessionAuditDigestInput input = GetSessionAuditDigestInput.ForNullSigner(TpmiShHmac.FromValue(sessionHandle), ReadOnlySpan<byte>.Empty, pool);
        using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<GetSessionAuditDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
            tpm, input, [privacyAdminAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_GetSessionAuditDigest(NULL signer) failed: '{result.ResponseCode}'.");

        using GetSessionAuditDigestResponse response = result.Value;
        TpmsSessionAuditInfo info = response.SessionAudit;

        return (info.ExclusiveSession, info.SessionDigest.AsReadOnlySpan().ToArray());
    }

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

    /// <summary>Builds the response codec registry covering every command this class issues.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_Create, TpmResponseCodec.CreateObject);
        _ = registry.Register(TpmCcConstants.TPM_CC_Load, TpmResponseCodec.Load);
        _ = registry.Register(TpmCcConstants.TPM_CC_Unseal, TpmResponseCodec.Unseal);
        _ = registry.Register(TpmCcConstants.TPM_CC_Sign, TpmResponseCodec.Sign);
        _ = registry.Register(TpmCcConstants.TPM_CC_StirRandom, TpmResponseCodec.StirRandom);
        _ = registry.Register(TpmCcConstants.TPM_CC_GetSessionAuditDigest, TpmResponseCodec.GetSessionAuditDigest);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Read, TpmResponseCodec.NvRead);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_ReadPublic, TpmResponseCodec.NvReadPublic);
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyCommandCode, TpmResponseCodec.PolicyCommandCode);
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyAuthValue, TpmResponseCodec.PolicyAuthValue);

        return registry;
    }

    /// <summary>
    /// Creates a simulator with the ECC (BouncyCastle) signing backend wired, powers it on, and brings it through
    /// <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// </summary>
    /// <param name="name">A per-test simulator identifier.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator; the caller owns it.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(string name, BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator(name, signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator, mirroring how the executor frames an unauthorized command on the wire, to move it into <see cref="TpmLifecyclePhase.Operational"/>.</summary>
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
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)responseHeader.Code, "TPM2_Startup(CLEAR) must succeed.");
        Assert.AreEqual(TpmLifecyclePhase.Operational, simulator.CurrentPhase, "TPM2_Startup(CLEAR) must move the simulator into the operational phase.");
    }
}
