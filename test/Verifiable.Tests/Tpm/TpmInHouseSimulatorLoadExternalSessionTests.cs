using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.DictionaryAttack;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives the <c>TPM_ST_SESSIONS</c> form of <c>TPM2_LoadExternal()</c> against the in-house behavioural
/// <see cref="TpmSimulator"/>: the zero-handle session table's cells for a command whose first parameter
/// (<c>inPrivate</c>) a <c>decrypt</c> session may protect and whose response's first parameter (<c>name</c>) an
/// <c>encrypt</c> session may protect (TPM 2.0 Library Part 3, clause 12.3, Table 22; Part 1, clause 18.1), the
/// XOR and AES-CFB round trips through the production <see cref="TpmCommandExecutor"/> and <see cref="TpmSession"/>,
/// and the refusals — over the raw wire where the executor's own client-side guards would refuse the
/// composition first (Part 3, clauses 5.5, 5.6 and 5.7; Part 1, clauses 15.6.4, 16.8.1 and 18).
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorLoadExternalSessionTests
{
    /// <summary>The Name and session hash algorithm used throughout.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The digest width of <see cref="SessionAlg"/>, the cpHash and nonce width.</summary>
    private const int DigestSize = 32;

    /// <summary>The width of a P-256 coordinate or scalar.</summary>
    private const int P256ComponentSize = 32;

    /// <summary>The dictionary-attack-protected Ordinary Index a session is bound to for the Lockout case.</summary>
    private const uint DaProtectedBindIndexHandle = 0x0100_0160;

    /// <summary>The bind Index's declared data size.</summary>
    private const ushort BindIndexDataSize = 16;

    /// <summary>Dictionary-attack-protected Ordinary Index attributes: <c>TPMA_NV_NO_DA</c> is CLEAR.</summary>
    private const TpmaNv DaProtectedIndexAttributes = TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_OWNERWRITE;

    /// <summary>A transient-object handle value, never a session handle by its kind alone.</summary>
    private const uint TransientRangeHandle = 0x8000_0000;

    /// <summary>The bind Index's authorization value.</summary>
    private static byte[] BindIndexAuth { get; } = [0x01, 0x02, 0x03, 0x04];

    /// <summary>A wrong authorization value for the bind Index.</summary>
    private static byte[] WrongIndexAuth { get; } = [0x09, 0x09, 0x09, 0x09];

    /// <summary>The octets written into the Index that drives the TPM into Lockout mode.</summary>
    private static byte[] PrimingWriteData { get; } = [0x2A];

    /// <summary>The message the loaded key signs.</summary>
    private static byte[] MessageBytes { get; } = "Load me over a session."u8.ToArray();

    /// <summary>The attribute word of an external signing key: unbound, caller-supplied, USER-role by password, dictionary-attack exempt.</summary>
    private const TpmaObject ExternalSigningAttributes = TpmaObject.USER_WITH_AUTH | TpmaObject.SIGN_ENCRYPT | TpmaObject.NO_DA;

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// "If present, a password authorization is always associated with a command handle that requires
    /// authorization as there is no session context associated with a password that would allow it to be used
    /// for encryption or command audit." — <c>TPM2_LoadExternal()</c> has no command handle, so a <c>TPM_RS_PW</c>
    /// slot is refused with the session-index-encoded <c>TPM_RC_ATTRIBUTES</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clauses 16.4 and 15.6.4, Table 15; Part 3, clause 12.3, Table 22</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalOverAPasswordSlotReturnsSessionEncodedAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalOverAPasswordSlotReturnsSessionEncodedAttributes), pool).ConfigureAwait(false);
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        byte[] parameters = PublicOnlyParameterArea(pool, key);
        TpmRcConstants code = await SubmitZeroHandleAsync(simulator, pool, BuildPasswordAuthArea(), parameters).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0), code,
            "TPM2_LoadExternal() has no command handle for a TPM_RS_PW authorization to attach to (Part 1, clause 16.4).");
    }

    /// <summary>
    /// "If a session is not being used for authorization, at least one of decrypt, encrypt, or audit must be SET.
    /// (TPM_RC_ATTRIBUTES)." — a loaded HMAC session at <c>TPM2_LoadExternal()</c>'s lone slot authorizes nothing,
    /// so claiming none of the three is refused, session-index-encoded to the slot.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.5, step 4.4.2; Part 2, clause 6.6.2</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalOverAnAttributelessSessionReturnsSessionEncodedAttributes()
    {
        await AssertSessionClaimAnswerAsync(
            nameof(LoadExternalOverAnAttributelessSessionReturnsSessionEncodedAttributes), TpmaSession.CONTINUE_SESSION, TpmtSymDef.Xor(SessionAlg),
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0),
            "a session authorizing nothing must claim at least one of decrypt, encrypt or audit (Part 3, clause 5.5, step 4.4.2)").ConfigureAwait(false);
    }

    /// <summary>
    /// "This attribute indicates that the session is being used for audit." — an <c>audit</c> claim over the
    /// zero-handle session table is admitted and the load succeeds, extending the session's audit digest to
    /// <c>H(0…0 ‖ cpHash ‖ rpHash)</c> on its first use (TPM 2.0 Library Part 1, clause 17.1, equation 30) with
    /// the response echoing <c>audit</c> SET, <c>auditExclusive</c> SET and <c>auditReset</c> CLEAR (Part 2,
    /// clause 8.4, Table 38) — proved by chaining cpHash/rpHash from the octets this test itself sent and read,
    /// then reading the session's digest back through <c>TPM2_GetSessionAuditDigest()</c> with the NULL signer.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.1; Part 2, clause 8.4, Table 38</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalOverAnAuditClaimingSessionSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalOverAnAuditClaimingSessionSucceeds), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_GetSessionAuditDigest, TpmResponseCodec.GetSessionAuditDigest);
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        byte[] parameters = PublicOnlyParameterArea(pool, key);
        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(tpm, registry, pool, TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                byte[] authArea = await BuildSessionAuthAreaAsync(session, parameters, pool).ConfigureAwait(false);

                (TpmRcConstants code, byte[] response) = await SubmitZeroHandleForAuditAsync(simulator, pool, authArea, parameters).ConfigureAwait(false);
                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "TPM2_LoadExternal() over a session claiming audit alone succeeds (Part 1, clause 17.1).");

                byte auditedAttributes = ReadResponseSessionAttributes(response, outHandleCount: 1, sessionIndex: 0);
                Assert.AreEqual(
                    (byte)(TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT | TpmaSession.AUDIT_EXCLUSIVE), auditedAttributes,
                    "The response echoes audit SET and auditExclusive SET (the session's first use as an audit session), with auditReset CLEAR (TPM 2.0 Library Part 2, clause 8.4, Table 38).");

                byte[] responseParameters = ReadResponseParameters(response, outHandleCount: 1);
                using DigestValue cpHash = await ComputeCpHashAsync(parameters, pool).ConfigureAwait(false);
                byte[] rpHash = await ComputeRpHashAsync(TpmCcConstants.TPM_CC_LoadExternal, responseParameters, pool).ConfigureAwait(false);
                byte[] expectedDigest = await ExtendAuditDigestAsync(priorDigest: null, cpHash.AsReadOnlySpan().ToArray(), rpHash, pool).ConfigureAwait(false);

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
                    "The session's audit digest must equal H(0…0 ‖ cpHash ‖ rpHash) chained from the load's own wire octets (TPM 2.0 Library Part 1, clause 17.1, equation 30).");
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "If the symmetric algorithm is TPM_ALG_NULL and encryption or decryption is specified, the TPM returns
    /// TPM_RC_SYMMETRIC." — <c>inPrivate</c> is a sized first parameter, so a <c>decrypt</c> claim is admissible
    /// and the session's own symmetric definition decides; the parameter area is judged only afterwards, so a body
    /// the load itself would refuse still answers <c>TPM_RC_SYMMETRIC</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 18.1; Part 3, clause 5.7</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalOverADecryptClaimingNullSymmetricSessionReturnsSessionEncodedSymmetric()
    {
        await AssertSessionClaimAnswerAsync(
            nameof(LoadExternalOverADecryptClaimingNullSymmetricSessionReturnsSessionEncodedSymmetric), TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT, TpmtSymDef.Null,
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_SYMMETRIC, sessionIndex: 0),
            "a decrypt claim over a session that negotiated no symmetric algorithm is TPM_RC_SYMMETRIC, judged before the parameters (Part 1, clause 18.1)",
            isBodyRefusable: true).ConfigureAwait(false);
    }

    /// <summary>
    /// "If the session is not loaded, the TPM will return the warning TPM_RC_REFERENCE_S0 + N where N is the
    /// number of the session." — a well-typed session handle whose session has been flushed.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.5, step 4.2; Part 2, clause 6.6.2</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalOverAnUnloadedSessionHandleReturnsReferenceMiss()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalOverAnUnloadedSessionHandleReturnsReferenceMiss), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        byte[] parameters = PublicOnlyParameterArea(pool, key);
        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(tpm, registry, pool, TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);
        byte[] authArea;
        using(session)
        {
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;
            authArea = await BuildSessionAuthAreaAsync(session, parameters, pool).ConfigureAwait(false);
        }

        await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);

        TpmRcConstants code = await SubmitZeroHandleAsync(simulator, pool, authArea, parameters).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_REFERENCE_S0, code, "A session handle naming no loaded session is blamed on the offending slot (Part 3, clause 5.5, step 4.2).");
    }

    /// <summary>
    /// A LOADED policy session at the lone slot of a command that authorizes no entity, claiming <c>encrypt</c>,
    /// is admitted exactly like an HMAC companion — TPM 2.0 Library Part 1, clause 15.6.1, Table 12, footnote
    /// [2] — since <c>TPM2_LoadExternal()</c>'s <c>name</c> is a sized response parameter an encrypt session may
    /// protect. This test's wire block is built with a BOUND HMAC session's own real, KDFa-derived key, then its
    /// handle field alone is overwritten with an unrelated, UNBOUND policy session's handle: the resolved policy
    /// session's own <c>sessionKey</c> (the Empty Buffer, since it is neither bound nor salted, Part 1, clause
    /// 18) cannot reproduce a command HMAC built under the other session's key, so the mismatch is refused
    /// session-encoded <c>TPM_RC_BAD_AUTH</c>, uncharged (the policy session is unbound, so no dictionary-attack
    /// accounting applies, Part 1, clause 16.8.1), the inner action never run.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 15.6.1, Table 12, footnote [2]; clause 18; clause 16.8.1</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalOverALoadedPolicySessionClaimingEncryptWithAMismatchedKeyReturnsBadAuth()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalOverALoadedPolicySessionClaimingEncryptWithAMismatchedKeyReturnsBadAuth), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        //A real (non-null) symmetric definition, negotiated exactly as the wire block's own HMAC session
        //negotiates one, so this proves the mismatched-key case rather than tripping the unrelated NULL-symmetric
        //gate (Part 1, clause 18) first.
        var policyInput = new StartAuthSessionInput
        {
            TpmKey = (uint)TpmRh.TPM_RH_NULL,
            Bind = (uint)TpmRh.TPM_RH_NULL,
            NonceCaller = RandomNumberGenerator.GetBytes(DigestSize),
            EncryptedSalt = ReadOnlyMemory<byte>.Empty,
            SessionType = TpmSeConstants.TPM_SE_POLICY,
            AuthHash = SessionAlg,
            Symmetric = TpmtSymDef.Xor(SessionAlg)
        };
        TpmResult<StartAuthSessionResponse> policyResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, policyInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(policyResult.IsSuccess, $"StartAuthSession (policy) failed: '{policyResult.ResponseCode}'.");
        uint policySessionHandle;
        using(StartAuthSessionResponse policyStarted = policyResult.Value)
        {
            policySessionHandle = policyStarted.SessionHandle.Value;
        }

        try
        {
            TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(before.IsSuccess, $"Reading the dictionary-attack parameters failed: '{before.ResponseCode}'.");

            TpmRcConstants code = await SubmitOverPatchedSlotAsync(simulator, tpm, registry, pool, key, policySessionHandle).ConfigureAwait(false);
            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), code,
                "A POLICY session admitted at the sole slot is refused session-encoded BAD_AUTH once its own (Empty Buffer) key fails to reproduce a command HMAC built under a different session's key.");

            TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(after.IsSuccess, $"Reading the dictionary-attack parameters failed: '{after.ResponseCode}'.");
            Assert.AreEqual(
                before.Value.LockoutCounter, after.Value.LockoutCounter,
                "An unbound policy session's wrong HMAC is uncharged (Part 1, clause 16.8.1): failedTries must not move.");
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, policySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "If the session handle is not a handle for an HMAC session, a handle for a policy session, or, TPM_RS_PW
    /// then the TPM shall return TPM_RC_HANDLE." — a transient-object handle in the slot is refused on its KIND
    /// alone, session-index-encoded to the slot.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.5, step 4.1; Part 2, clauses 7.2 and 6.6.2</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalOverANonSessionSlotHandleReturnsSessionEncodedHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalOverANonSessionSlotHandleReturnsSessionEncodedHandle), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        TpmRcConstants code = await SubmitOverPatchedSlotAsync(simulator, tpm, registry, pool, key, TransientRangeHandle).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_HANDLE, sessionIndex: 0), code,
            "A non-session handle at the authorization slot is refused on the handle's kind, ahead of any credential evaluation (Part 3, clause 5.5, step 4.1).");
    }

    /// <summary>
    /// <c>inPrivate</c> is the command's first sized parameter, so a <c>decrypt</c> session protects it (TPM 2.0
    /// Library Part 1, clause 18.1): the executor encrypts the sensitive area client-side under the session's XOR
    /// or AES-CFB keystream, the TPM recovers the plaintext before the load, and the loaded ECC key then signs a
    /// digest the framework's own ECDSA verifies against the public point — the scalar arrived intact.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3, Table 22</see>.
    /// </summary>
    /// <param name="isAesCfb">Whether the session negotiates AES-128-CFB (else the XOR obfuscation).</param>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task LoadExternalOverADecryptSessionDeliversThePlaintextSensitiveArea(bool isAesCfb)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(LoadExternalOverADecryptSessionDeliversThePlaintextSensitiveArea)}-{isAesCfb}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(tpm, registry, pool, Symmetric(isAesCfb)).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                TpmResult<LoadExternalResponse> result = await LoadFullEccAsync(tpm, registry, pool, key, session, ExternalSigningAttributes).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"TPM2_LoadExternal() over a {Symmetric(isAesCfb).Algorithm} decrypt session must succeed (Part 1, clause 18.1), but failed: '{result.ResponseCode}'.");
                using LoadExternalResponse loaded = result.Value;

                await AssertLoadedKeySignsForTheFrameworkAsync(tpm, registry, pool, loaded.ObjectHandle, key).ConfigureAwait(false);
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The recovered <c>inPrivate</c> is judged by the plain form's own rules once decrypted: a
    /// <c>TPM2B_SENSITIVE</c> whose declared size exceeds what its <c>TPMT_SENSITIVE</c> consumes is a
    /// structural failure of <c>inPrivate</c> itself, <c>TPM2_LoadExternal()</c>'s first parameter (Table 22,
    /// index 0), so it is parameter-encoded — passed through the decrypt continuation unchanged rather than
    /// blamed on the decrypt slot (Part 2, clause 6.6.2, Table 15's closing sentence: a code is designated once).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.7; Part 2, clause 6.6.2, Table 15</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalOverADecryptSessionRefusesAnOverDeclaredSensitiveAreaParameterEncoded()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalOverADecryptSessionRefusesAnOverDeclaredSensitiveAreaParameterEncoded), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(tpm, registry, pool, TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                byte[] parameters = OverDeclaredFullEccParameterArea(pool, key);
                byte[] command = await FrameEncryptedOverSessionAsync(session, parameters, pool).ConfigureAwait(false);
                TpmRcConstants code = await SubmitRawAsync(simulator, pool, command).ConfigureAwait(false);
                Assert.AreEqual(
                    HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, parameterIndex: 0), code,
                    "A decrypted inPrivate declaring more than its TPMT_SENSITIVE consumes is the plain form's TPM_RC_SIZE, designated to inPrivate (Table 22, index 0), not blamed on the decrypt slot (Part 2, clause 6.6.2).");
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>name</c> is the response's first sized parameter, so an <c>encrypt</c> session protects it (TPM 2.0
    /// Library Part 1, clause 18.1): the executor decrypts the returned Name under the session's keystream, and
    /// it equals the Name the plain form answers for the same public area and an independent
    /// <c>nameAlg ‖ H_nameAlg(TPMT_PUBLIC)</c> transcription.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3, Table 23</see>.
    /// </summary>
    /// <param name="isAesCfb">Whether the session negotiates AES-128-CFB (else the XOR obfuscation).</param>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task LoadExternalOverAnEncryptSessionReturnsANameTheExecutorDecrypts(bool isAesCfb)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(LoadExternalOverAnEncryptSessionReturnsANameTheExecutorDecrypts)}-{isAesCfb}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        byte[] expectedName = TranscribeEccName(pool, key, ExternalSigningAttributes);
        TpmResult<LoadExternalResponse> plainResult = await LoadPublicOnlyEccAsync(tpm, registry, pool, key, null, ExternalSigningAttributes).ConfigureAwait(false);
        Assert.IsTrue(plainResult.IsSuccess, $"The plain-form load failed: '{plainResult.ResponseCode}'.");
        byte[] plainName;
        using(LoadExternalResponse plainLoaded = plainResult.Value)
        {
            plainName = plainLoaded.Name.Span.ToArray();
        }

        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(tpm, registry, pool, Symmetric(isAesCfb)).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                TpmResult<LoadExternalResponse> result = await LoadPublicOnlyEccAsync(tpm, registry, pool, key, session, ExternalSigningAttributes).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"TPM2_LoadExternal() over a {Symmetric(isAesCfb).Algorithm} encrypt session must succeed (Part 1, clause 18.1), but failed: '{result.ResponseCode}'.");
                using LoadExternalResponse loaded = result.Value;

                Assert.IsTrue(loaded.Name.Span.SequenceEqual(plainName), "The decrypted name equals the plain form's for the same public area.");
                Assert.IsTrue(loaded.Name.Span.SequenceEqual(expectedName), "The decrypted name is nameAlg ‖ H_nameAlg(TPMT_PUBLIC), transcribed independently (Part 3, clause 12.3.1).");
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// One session may claim both directions (TPM 2.0 Library Part 1, clause 18.1): a full ECC load with
    /// <c>decrypt</c> over <c>inPrivate</c> and <c>encrypt</c> over <c>name</c> succeeds, the decrypted Name matches
    /// the independent transcription, and the loaded key signs.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3, Table 22</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalOverADecryptAndEncryptSessionProtectsBothDirections()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalOverADecryptAndEncryptSessionProtectsBothDirections), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        byte[] expectedName = TranscribeEccName(pool, key, ExternalSigningAttributes);
        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(tpm, registry, pool, TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB)).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT | TpmaSession.ENCRYPT;

                TpmResult<LoadExternalResponse> result = await LoadFullEccAsync(tpm, registry, pool, key, session, ExternalSigningAttributes).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"TPM2_LoadExternal() over a decrypt+encrypt session must succeed (Part 1, clause 18.1), but failed: '{result.ResponseCode}'.");
                using LoadExternalResponse loaded = result.Value;

                Assert.IsTrue(loaded.Name.Span.SequenceEqual(expectedName), "The decrypted name is the independent transcription.");
                await AssertLoadedKeySignsForTheFrameworkAsync(tpm, registry, pool, loaded.ObjectHandle, key).ConfigureAwait(false);
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A wrong command HMAC over a session bound to <c>TPM_RH_OWNER</c> — a permanent entity lending no
    /// dictionary-attack protection, on a command authorizing no entity — is the session-index-encoded
    /// <c>TPM_RC_BAD_AUTH</c> at index 0 and charges nothing.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.8.1; Part 3, clause 5.6</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalWithAWrongHmacOverAnOwnerBoundSessionIsBadAuthUncharged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalWithAWrongHmacOverAnOwnerBoundSessionIsBadAuthUncharged), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(tpm, registry, pool, TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;
                TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

                byte[] parameters = PublicOnlyParameterArea(pool, key);
                byte[] authArea = await BuildSessionAuthAreaAsync(session, parameters, pool).ConfigureAwait(false);
                TamperLastHmacOctet(authArea);
                TpmRcConstants code = await SubmitZeroHandleAsync(simulator, pool, authArea, parameters).ConfigureAwait(false);
                Assert.AreEqual(
                    HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), code,
                    "A wrong command HMAC on a session lent no dictionary-attack protection is the session-index-encoded TPM_RC_BAD_AUTH (Part 1, clause 16.8.1).");

                TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(before.Value.LockoutCounter, after.Value.LockoutCounter, "Nothing lends the session dictionary-attack protection, so nothing is charged.");
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A session bound to a dictionary-attack-protected NV Index while the TPM is in Lockout mode is refused
    /// with the bare <c>TPM_RC_LOCKOUT</c> before its command HMAC is judged: the bind-side gate applies "For all
    /// session types" (TPM 2.0 Library Part 3, clause 11.1.1), whatever the command authorizes.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 11.1.1; Part 1, clause 16.8.3</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalOverASessionBoundToADaProtectedIndexInLockoutIsRefusedWithLockout()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalOverASessionBoundToADaProtectedIndexInLockoutIsRefusedWithLockout), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        await DriveIntoLockoutAsync(tpm, registry, pool).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await HmacKeyHarness.StartBoundHmacSessionAsync(
            tpm, registry, pool, DaProtectedBindIndexHandle, BindIndexAuth, TpmtSymDef.Xor(SessionAlg), isBoundToAuthorizedEntity: false, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                TpmResult<LoadExternalResponse> result = await LoadPublicOnlyEccAsync(tpm, registry, pool, key, session, ExternalSigningAttributes).ConfigureAwait(false);
                Assert.AreEqual(TpmRcConstants.TPM_RC_LOCKOUT, result.ResponseCode, "A session bound to a DA-protected entity is unusable in Lockout mode (Part 3, clause 11.1.1).");
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The session's nonceTPM rolls on success only: a load the attribute rules refuse after the command HMAC
    /// verified (<c>fixedTPM</c> SET with a sensitive area, <c>TPM_RC_ATTRIBUTES</c>) leaves the session where it
    /// stood, and the SAME session — with no restart and the executor's nonceTPM untouched — then loads a
    /// well-formed key, which it could not if the refusal had advanced the session.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.6.3; Part 3, clause 12.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalRefusalRollsNoNonceAndTheSessionLoadsAfterwards()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalRefusalRollsNoNonceAndTheSessionLoadsAfterwards), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(tpm, registry, pool, TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                TpmResult<LoadExternalResponse> refused = await LoadFullEccAsync(tpm, registry, pool, key, session, ExternalSigningAttributes | TpmaObject.FIXED_TPM).ConfigureAwait(false);
                Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 1), refused.ResponseCode, "fixedTPM SET with a sensitive area is TPM_RC_ATTRIBUTES after the HMAC verified (Part 3, clause 12.3.1).");

                TpmResult<LoadExternalResponse> accepted = await LoadFullEccAsync(tpm, registry, pool, key, session, ExternalSigningAttributes).ConfigureAwait(false);
                Assert.IsTrue(accepted.IsSuccess, $"The same session must load a well-formed key without a restart — the refusal rolled no nonce — but failed: '{accepted.ResponseCode}'.");
                accepted.Value.Dispose();
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Pool hygiene over a session across four legs: a parse-time refusal (an over-declared <c>inPrivate</c>,
    /// the parameter-encoded <c>TPM_RC_SIZE</c>), a transition refusal (<c>fixedTPM</c> SET with a sensitive
    /// area, <c>TPM_RC_ATTRIBUTES</c>), an effect refusal (a public point off the curve, <c>TPM_RC_ECC_POINT</c>)
    /// and a success whose object is flushed and whose response is released — each leaves the pool with exactly
    /// the carriers outstanding before it.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalOverASessionLeavesThePoolBalancedAcrossARefusalAndASuccess()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalOverASessionLeavesThePoolBalancedAcrossARefusalAndASuccess), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(tpm, registry, pool, TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT | TpmaSession.ENCRYPT;
                long baseline = trackingPool.OutstandingCount;

                byte[] overDeclaredParameters = OverDeclaredFullEccParameterArea(pool, key);
                byte[] overDeclaredCommand = await FrameEncryptedOverSessionAsync(session, overDeclaredParameters, pool).ConfigureAwait(false);
                TpmRcConstants parseRefusalCode = await SubmitRawAsync(simulator, pool, overDeclaredCommand).ConfigureAwait(false);
                Assert.AreEqual(
                    HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, parameterIndex: 0), parseRefusalCode,
                    "An over-declared inPrivate recovered under the decrypt claim is the plain form's TPM_RC_SIZE, designated to inPrivate (Table 22, index 0), not blamed on the decrypt slot.");
                Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A parse-time refusal returns every carrier it rented.");

                TpmResult<LoadExternalResponse> transitionRefused = await LoadFullEccAsync(tpm, registry, pool, key, session, ExternalSigningAttributes | TpmaObject.FIXED_TPM).ConfigureAwait(false);
                Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 1), transitionRefused.ResponseCode, "The bound-attribute load is refused with TPM_RC_ATTRIBUTES.");
                Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A transition refusal returns every carrier it rented.");

                byte[] offCurveY = (byte[])key.Y.Clone();
                offCurveY[^1] ^= 0x01;
                TpmResult<LoadExternalResponse> effectRefused = await LoadFullEccAsync(tpm, registry, pool, key, session, ExternalSigningAttributes, offCurveY).ConfigureAwait(false);
                Assert.AreEqual(TpmRcConstants.TPM_RC_ECC_POINT, effectRefused.ResponseCode, "The off-curve load is refused with TPM_RC_ECC_POINT.");
                Assert.AreEqual(baseline, trackingPool.OutstandingCount, "An effect refusal returns every carrier it rented, the sensitive area's included.");

                TpmResult<LoadExternalResponse> accepted = await LoadFullEccAsync(tpm, registry, pool, key, session, ExternalSigningAttributes).ConfigureAwait(false);
                Assert.IsTrue(accepted.IsSuccess, $"The load must succeed, but failed: '{accepted.ResponseCode}'.");
                uint handle;
                using(LoadExternalResponse loaded = accepted.Value)
                {
                    handle = loaded.ObjectHandle.Value;
                }

                TpmResult<FlushContextResponse> flushed = await HmacKeyHarness.FlushAsync(tpm, registry, pool, handle, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(flushed.IsSuccess, $"Flushing the loaded object failed: '{flushed.ResponseCode}'.");
                Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A successful session-authorized load returns every carrier once the object is flushed and the response released.");
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>A P-256 key pair minted by the framework, its coordinates and scalar padded to the field width.</summary>
    private sealed class EccKeyMaterial: IDisposable
    {
        /// <summary>Gets the framework key, the off-TPM verifying oracle.</summary>
        public ECDsa Key { get; }

        /// <summary>Gets the public point's X coordinate, 32 octets.</summary>
        public byte[] X { get; }

        /// <summary>Gets the public point's Y coordinate, 32 octets.</summary>
        public byte[] Y { get; }

        /// <summary>Gets the private scalar, 32 octets.</summary>
        public byte[] D { get; }

        /// <summary>Initializes the material from the framework key.</summary>
        /// <param name="key">The framework key; owned.</param>
        private EccKeyMaterial(ECDsa key)
        {
            Key = key;
            ECParameters parameters = key.ExportParameters(includePrivateParameters: true);
            X = PadLeft(parameters.Q.X!, P256ComponentSize);
            Y = PadLeft(parameters.Q.Y!, P256ComponentSize);
            D = PadLeft(parameters.D!, P256ComponentSize);
        }

        /// <summary>Mints a fresh P-256 key pair.</summary>
        /// <returns>The material; the caller disposes it.</returns>
        public static EccKeyMaterial Generate() => new(ECDsa.Create(ECCurve.NamedCurves.nistP256));

        /// <summary>Releases the framework key and clears the scalar.</summary>
        public void Dispose()
        {
            Array.Clear(D);
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

    /// <summary>Creates an operational simulator with the elliptic-curve backend.</summary>
    /// <param name="name">The per-test simulator identifier.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private Task<TpmSimulator> CreateOperationalAsync(string name, BaseMemoryPool pool) =>
        HmacKeyHarness.CreateOperationalAsync($"tpm-in-house-load-external-session-{name}", pool, TestContext.CancellationToken);

    /// <summary>Builds the codec registry covering every command these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry() =>
        HmacKeyHarness.CreateRegistry()
            .Register(TpmCcConstants.TPM_CC_LoadExternal, TpmResponseCodec.LoadExternal)
            .Register(TpmCcConstants.TPM_CC_Sign, TpmResponseCodec.Sign)
            .Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace)
            .Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite);

    /// <summary>The symmetric definition a parameter-encryption session negotiates.</summary>
    /// <param name="isAesCfb">Whether to negotiate AES-128-CFB (else the XOR obfuscation).</param>
    /// <returns>The symmetric definition.</returns>
    private static TpmtSymDef Symmetric(bool isAesCfb) =>
        isAesCfb ? TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB) : TpmtSymDef.Xor(SessionAlg);

    /// <summary>Builds an ECC P-256 ECDSA-SHA-256 signing public area carrying the key's point.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="key">The key material.</param>
    /// <param name="attributes">The attribute word.</param>
    /// <returns>The public area; the caller owns it.</returns>
    private static Tpm2bPublic BuildEccPublic(BaseMemoryPool pool, EccKeyMaterial key, TpmaObject attributes) =>
        BuildEccPublic(pool, key, attributes, key.Y);

    /// <summary>Builds an ECC P-256 ECDSA-SHA-256 signing public area carrying the key's X coordinate and the given Y coordinate.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="key">The key material.</param>
    /// <param name="attributes">The attribute word.</param>
    /// <param name="y">The public point's Y coordinate, the key's own or an off-curve substitute.</param>
    /// <returns>The public area; the caller owns it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the point transfers to the returned public area, which its owner disposes.")]
    private static Tpm2bPublic BuildEccPublic(BaseMemoryPool pool, EccKeyMaterial key, TpmaObject attributes, ReadOnlySpan<byte> y) =>
        Tpm2bPublic.CreateEccSigningKey(SessionAlg, attributes, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(SessionAlg), TpmsEccPoint.Create(key.X, y, pool), pool);

    /// <summary>Builds an ECC sensitive area (TPM 2.0 Library Part 2, clause 12.3.2, Table 240) around the key's scalar with an empty authValue.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="key">The key material.</param>
    /// <returns>The sensitive area; the caller owns it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the carriers transfers to the returned sensitive area, which its owner disposes.")]
    private static TpmtSensitive BuildEccSensitive(BaseMemoryPool pool, EccKeyMaterial key) =>
        new(Tpm2bAuth.CreateEmpty(pool), Tpm2bDigest.Empty, TpmuSensitiveComposite.FromEcc(Tpm2bEccParameter.Create(key.D, pool)));

    /// <summary>Transcribes the Name the TPM must compute for the key's public area: <c>nameAlg ‖ H_nameAlg(TPMT_PUBLIC)</c> (TPM 2.0 Library Part 1, clause 13, Table 9).</summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="key">The key material.</param>
    /// <param name="attributes">The attribute word.</param>
    /// <returns>The Name octets.</returns>
    private static byte[] TranscribeEccName(BaseMemoryPool pool, EccKeyMaterial key, TpmaObject attributes)
    {
        using Tpm2bPublic publicArea = BuildEccPublic(pool, key, attributes);
        byte[] marshaled = new byte[publicArea.GetSerializedSize()];
        var writer = new TpmWriter(marshaled);
        publicArea.WriteTo(ref writer);
        byte[] digest = SHA256.HashData(marshaled.AsSpan(sizeof(ushort)));
        byte[] name = new byte[sizeof(ushort) + digest.Length];
        BinaryPrimitives.WriteUInt16BigEndian(name, (ushort)SessionAlg);
        digest.CopyTo(name, sizeof(ushort));

        return name;
    }

    /// <summary>Serializes the parameter area of a public-only ECC load under the owner hierarchy through the production input type.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="key">The key material.</param>
    /// <returns>The parameter area's octets.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the public area transfers to the load input, disposed here once serialized.")]
    private static byte[] PublicOnlyParameterArea(BaseMemoryPool pool, EccKeyMaterial key)
    {
        using LoadExternalInput input = LoadExternalInput.PublicOnly(BuildEccPublic(pool, key, ExternalSigningAttributes), TpmiRhHierarchy.Owner);

        return SerializeParameters(input);
    }

    /// <summary>Serializes the parameter area of a load whose ECC public area sits over a KEYEDHASH sensitive area — a body the load itself refuses with <c>TPM_RC_TYPE</c>.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="key">The key material.</param>
    /// <returns>The parameter area's octets.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the public and sensitive areas transfers to the load input, disposed here once serialized.")]
    private static byte[] MismatchedTypeParameterArea(BaseMemoryPool pool, EccKeyMaterial key)
    {
        TpmtSensitive keyedHash = TpmtSensitive.ForKeyedHash(Tpm2bAuth.CreateEmpty(pool), Tpm2bDigest.Empty, Tpm2bSensitiveData.Create(key.D, pool));
        using var input = new LoadExternalInput(keyedHash, BuildEccPublic(pool, key, ExternalSigningAttributes), TpmiRhHierarchy.Null);

        return SerializeParameters(input);
    }

    /// <summary>
    /// Serializes the parameter area of a full ECC load under <c>TPM_RH_NULL</c> whose <c>inPrivate</c> declares
    /// one octet more than its <c>TPMT_SENSITIVE</c> consumes, a zero octet padding the declared window.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="key">The key material.</param>
    /// <returns>The parameter area's octets.</returns>
    private static byte[] OverDeclaredFullEccParameterArea(BaseMemoryPool pool, EccKeyMaterial key)
    {
        byte[] marshaledSensitive;
        using(TpmtSensitive sensitive = BuildEccSensitive(pool, key))
        {
            marshaledSensitive = new byte[sensitive.SerializedSize];
            var sensitiveWriter = new TpmWriter(marshaledSensitive);
            sensitive.WriteTo(ref sensitiveWriter);
        }

        byte[] marshaledPublic;
        using(Tpm2bPublic publicArea = BuildEccPublic(pool, key, ExternalSigningAttributes))
        {
            marshaledPublic = new byte[publicArea.GetSerializedSize()];
            var publicWriter = new TpmWriter(marshaledPublic);
            publicArea.WriteTo(ref publicWriter);
        }

        byte[] parameters = new byte[sizeof(ushort) + marshaledSensitive.Length + 1 + marshaledPublic.Length + sizeof(uint)];
        var writer = new TpmWriter(parameters);
        writer.WriteUInt16((ushort)(marshaledSensitive.Length + 1));
        writer.WriteBytes(marshaledSensitive);
        writer.WriteByte(0);
        writer.WriteBytes(marshaledPublic);
        writer.WriteUInt32((uint)TpmRh.TPM_RH_NULL);

        return parameters;
    }

    /// <summary>Serializes a command input's parameter area.</summary>
    /// <param name="input">The input.</param>
    /// <returns>The parameter area's octets.</returns>
    private static byte[] SerializeParameters(LoadExternalInput input)
    {
        byte[] parameters = new byte[input.GetSerializedSize()];
        var writer = new TpmWriter(parameters);
        input.WriteParameters(ref writer);

        return parameters;
    }

    /// <summary>Issues a public-only ECC load under the owner hierarchy through the executor, over <paramref name="session"/> or sessionless, and returns the raw result.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="key">The key material.</param>
    /// <param name="session">The companion session, or <see langword="null"/> for the plain form.</param>
    /// <param name="attributes">The attribute word.</param>
    /// <returns>The raw result; the caller disposes the value on success.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the public area transfers to the load input, disposed here once the command has been issued.")]
    private async Task<TpmResult<LoadExternalResponse>> LoadPublicOnlyEccAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, EccKeyMaterial key, TpmSession? session, TpmaObject attributes)
    {
        using LoadExternalInput input = LoadExternalInput.PublicOnly(BuildEccPublic(pool, key, attributes), TpmiRhHierarchy.Owner);

        return await TpmCommandExecutor.ExecuteAsync<LoadExternalResponse>(
            tpm, input, session is null ? [] : [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Issues a full ECC load under <c>TPM_RH_NULL</c> through the executor over <paramref name="session"/> and returns the raw result.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="key">The key material.</param>
    /// <param name="session">The companion session.</param>
    /// <param name="attributes">The attribute word.</param>
    /// <param name="y">The public point's Y coordinate, or empty for the key's own.</param>
    /// <returns>The raw result; the caller disposes the value on success.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the public and sensitive areas transfers to the load input, disposed here once the command has been issued.")]
    private async Task<TpmResult<LoadExternalResponse>> LoadFullEccAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, EccKeyMaterial key, TpmSession session, TpmaObject attributes, ReadOnlyMemory<byte> y = default)
    {
        using var input = new LoadExternalInput(BuildEccSensitive(pool, key), BuildEccPublic(pool, key, attributes, y.IsEmpty ? key.Y : y.Span), TpmiRhHierarchy.Null);

        return await TpmCommandExecutor.ExecuteAsync<LoadExternalResponse>(tpm, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Signs a digest with the loaded key over a password session and asserts the framework's ECDSA accepts the signature against the key's public point.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The loaded key.</param>
    /// <param name="key">The key material.</param>
    private async Task AssertLoadedKeySignsForTheFrameworkAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject handle, EccKeyMaterial key)
    {
        byte[] digest = SHA256.HashData(MessageBytes);
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignInput signInput = SignInput.ForEcdsa(handle, digest, SessionAlg, pool);
        TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signResult.IsSuccess, $"The loaded key must sign, but failed: '{signResult.ResponseCode}'.");
        using SignResponse signed = signResult.Value;

        byte[] p1363 = new byte[2 * P256ComponentSize];
        ReadOnlySpan<byte> r = signed.Signature.SignatureR!.AsReadOnlySpan();
        ReadOnlySpan<byte> s = signed.Signature.SignatureS!.AsReadOnlySpan();
        r.CopyTo(p1363.AsSpan(P256ComponentSize - r.Length));
        s.CopyTo(p1363.AsSpan((2 * P256ComponentSize) - s.Length));
        Assert.IsTrue(key.Key.VerifyHash(digest, p1363, DSASignatureFormat.IeeeP1363FixedFieldConcatenation), "The framework's ECDSA accepts the TPM's signature: the plaintext scalar reached the object.");
    }

    /// <summary>
    /// Frames a public-only load over a live, owner-bound HMAC session negotiating <paramref name="symmetric"/>
    /// and claiming <paramref name="attributes"/>, and asserts the answer the session table earns.
    /// </summary>
    /// <param name="name">The per-test simulator identifier.</param>
    /// <param name="attributes">The <c>TPMA_SESSION</c> octet the slot carries.</param>
    /// <param name="symmetric">The symmetric definition the session negotiates.</param>
    /// <param name="expected">The expected response code.</param>
    /// <param name="rule">The rule under proof, quoted into the assertion message.</param>
    /// <param name="isBodyRefusable">Whether to frame a body the load itself would refuse, proving the session rule is judged first.</param>
    private async Task AssertSessionClaimAnswerAsync(string name, TpmaSession attributes, TpmtSymDef symmetric, TpmRcConstants expected, string rule, bool isBodyRefusable = false)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(name, pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        byte[] parameters = isBodyRefusable ? MismatchedTypeParameterArea(pool, key) : PublicOnlyParameterArea(pool, key);
        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(tpm, registry, pool, symmetric).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = attributes;
                byte[] authArea = await BuildSessionAuthAreaAsync(session, parameters, pool).ConfigureAwait(false);
                TpmRcConstants code = await SubmitZeroHandleAsync(simulator, pool, authArea, parameters).ConfigureAwait(false);
                Assert.AreEqual(expected, code, $"TPM2_LoadExternal() over a session claiming '{attributes}': {rule}.");
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Frames a public-only load over a genuine HMAC authorization block whose slot handle field is then
    /// overwritten with <paramref name="slotHandle"/>, so only the handle under test differs from a real session's.
    /// </summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="key">The key material.</param>
    /// <param name="slotHandle">The wire-only substitute for the slot's session handle field.</param>
    /// <returns>The response code, still carrying any session-index encoding.</returns>
    private async Task<TpmRcConstants> SubmitOverPatchedSlotAsync(TpmSimulator simulator, TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, EccKeyMaterial key, uint slotHandle)
    {
        byte[] parameters = PublicOnlyParameterArea(pool, key);
        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(tpm, registry, pool, TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;
                byte[] authArea = await BuildSessionAuthAreaAsync(session, parameters, pool).ConfigureAwait(false);
                BinaryPrimitives.WriteUInt32BigEndian(authArea.AsSpan(0, sizeof(uint)), slotHandle);

                return await SubmitZeroHandleAsync(simulator, pool, authArea, parameters).ConfigureAwait(false);
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Builds one <c>TPMS_AUTH_COMMAND</c> block over <paramref name="session"/>, its command HMAC computed on the
    /// cpHash a zero-handle command owns: the command code folded with the parameter area and NO Name term (TPM 2.0
    /// Library Part 1, clause 15.7, equation 15).
    /// </summary>
    /// <param name="session">The session, whose caller nonce this rolls.</param>
    /// <param name="parameters">The parameter area the HMAC commits to.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The block's octets, without the authorizationSize field that precedes them.</returns>
    private async Task<byte[]> BuildSessionAuthAreaAsync(TpmSession session, byte[] parameters, BaseMemoryPool pool)
    {
        using DigestValue cpHash = await ComputeCpHashAsync(parameters, pool).ConfigureAwait(false);
        session.RollNonceCaller(pool);
        using Tpm2bAuth? hmac = await session.PrepareAuthHmacAsync(cpHash.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] block = new byte[session.GetAuthCommandSize()];
        var writer = new TpmWriter(block);
        session.WriteAuthCommand(ref writer, hmac);

        return block;
    }

    /// <summary>
    /// Hand-frames a <c>decrypt</c>-attributed load whose <c>inPrivate</c> data portion is encrypted under the
    /// session's own keystream through the production <see cref="TpmSessionBase.EncryptFirstParameterAsync"/>,
    /// the command HMAC computed over the CIPHERTEXT parameter area (TPM 2.0 Library Part 1, clause 18.1:
    /// "Parameters in commands are encrypted before any cpHash is computed").
    /// </summary>
    /// <param name="session">The decrypt session, whose caller nonce this rolls.</param>
    /// <param name="parameters">The plaintext parameter area, mutated in place to its ciphertext form.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The exact octets to submit.</returns>
    private async Task<byte[]> FrameEncryptedOverSessionAsync(TpmSession session, byte[] parameters, BaseMemoryPool pool)
    {
        int declaredSize = BinaryPrimitives.ReadUInt16BigEndian(parameters.AsSpan(0, sizeof(ushort)));
        session.RollNonceCaller(pool);
        await session.EncryptFirstParameterAsync(parameters.AsMemory(sizeof(ushort), declaredSize), pool, TestContext.CancellationToken).ConfigureAwait(false);

        using DigestValue cpHash = await ComputeCpHashAsync(parameters, pool).ConfigureAwait(false);
        using Tpm2bAuth? hmac = await session.PrepareAuthHmacAsync(cpHash.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);

        int authAreaSize = sizeof(uint) + session.GetAuthCommandSize();
        byte[] command = new byte[TpmHeader.HeaderSize + authAreaSize + parameters.Length];
        var writer = new TpmWriter(command);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)command.Length, (uint)TpmCcConstants.TPM_CC_LoadExternal);
        header.WriteTo(ref writer);
        writer.WriteUInt32((uint)session.GetAuthCommandSize());
        session.WriteAuthCommand(ref writer, hmac);
        writer.WriteBytes(parameters);

        return command;
    }

    /// <summary>Computes cpHash for a zero-handle <c>TPM2_LoadExternal()</c>: <c>H(commandCode ‖ parameters)</c> (TPM 2.0 Library Part 1, clause 15.7, equation 15).</summary>
    /// <param name="parameters">The parameter area as it rides the wire.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The digest; the caller disposes it.</returns>
    private async Task<DigestValue> ComputeCpHashAsync(byte[] parameters, BaseMemoryPool pool)
    {
        byte[] cpHashInput = new byte[sizeof(uint) + parameters.Length];
        var writer = new TpmWriter(cpHashInput);
        writer.WriteUInt32((uint)TpmCcConstants.TPM_CC_LoadExternal);
        writer.WriteBytes(parameters);

        return await CryptographicKeyEvents.ComputeDigestAsync(
            cpHashInput, outputByteLength: DigestSize, tag: DigestTag(), pool: pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Builds a one-slot authorization block naming <c>TPM_RS_PW</c> with an empty nonce and an empty password (TPM 2.0 Library Part 1, clause 16.6.4.1).</summary>
    /// <returns>The block's octets, without the authorizationSize field that precedes them.</returns>
    private static byte[] BuildPasswordAuthArea()
    {
        byte[] block = new byte[sizeof(uint) + sizeof(ushort) + sizeof(byte) + sizeof(ushort)];
        BinaryPrimitives.WriteUInt32BigEndian(block.AsSpan(0, sizeof(uint)), (uint)TpmRh.TPM_RH_PW);
        BinaryPrimitives.WriteUInt16BigEndian(block.AsSpan(sizeof(uint), sizeof(ushort)), 0);
        block[sizeof(uint) + sizeof(ushort)] = (byte)TpmaSession.CONTINUE_SESSION;
        BinaryPrimitives.WriteUInt16BigEndian(block.AsSpan(sizeof(uint) + sizeof(ushort) + sizeof(byte), sizeof(ushort)), 0);

        return block;
    }

    /// <summary>Flips every bit of the LAST octet of a one-slot authorization block's <c>hmac</c> field, navigating past the handle, nonce and attributes so the offset follows the actual widths.</summary>
    /// <param name="authArea">The authorization block, mutated in place.</param>
    private static void TamperLastHmacOctet(byte[] authArea)
    {
        var reader = new TpmReader(authArea);
        _ = reader.ReadUInt32();
        ushort nonceSize = reader.ReadUInt16();
        reader.Skip(nonceSize);
        _ = reader.ReadByte();
        ushort hmacSize = reader.ReadUInt16();
        Assert.IsGreaterThan(0, hmacSize, "The arrangement must carry a non-empty hmac for the tamper to change one.");

        authArea[reader.Consumed + hmacSize - 1] ^= 0xFF;
    }

    /// <summary>Frames a <c>TPM_ST_SESSIONS</c> <c>TPM2_LoadExternal()</c> with no handle area — the authorization block preceded by its size, then the parameters — and submits it straight to the simulator.</summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="authArea">The authorization block.</param>
    /// <param name="parameters">The parameter area.</param>
    /// <returns>The response code, still carrying any session-index encoding.</returns>
    private async Task<TpmRcConstants> SubmitZeroHandleAsync(TpmSimulator simulator, BaseMemoryPool pool, byte[] authArea, byte[] parameters)
    {
        byte[] command = new byte[TpmHeader.HeaderSize + sizeof(uint) + authArea.Length + parameters.Length];
        var writer = new TpmWriter(command);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)command.Length, (uint)TpmCcConstants.TPM_CC_LoadExternal);
        header.WriteTo(ref writer);
        writer.WriteUInt32((uint)authArea.Length);
        writer.WriteBytes(authArea);
        writer.WriteBytes(parameters);

        return await SubmitRawAsync(simulator, pool, command).ConfigureAwait(false);
    }

    /// <summary>Submits raw, hand-framed octets straight to the simulator and returns the response code.</summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="command">The exact octets to submit.</param>
    /// <returns>The response code, still carrying any session-index encoding.</returns>
    private async Task<TpmRcConstants> SubmitRawAsync(TpmSimulator simulator, BaseMemoryPool pool, byte[] command)
    {
        TpmResult<TpmResponse> result = await simulator.SubmitAsync(command, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The simulator must answer a refused command rather than fault.");

        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());

        return (TpmRcConstants)TpmHeader.Parse(ref reader).Code;
    }

    /// <summary>
    /// Frames a <c>TPM_ST_SESSIONS</c> <c>TPM2_LoadExternal()</c> with no handle area — the same wire shape as
    /// <see cref="SubmitZeroHandleAsync"/> — but also returns the raw response octets alongside the code so an
    /// audit digest can be chained from them independently of the codec.
    /// </summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="authArea">The authorization block.</param>
    /// <param name="parameters">The parameter area.</param>
    /// <returns>The response code, still carrying any session-index encoding, and the full raw response.</returns>
    private async Task<(TpmRcConstants Code, byte[] Response)> SubmitZeroHandleForAuditAsync(TpmSimulator simulator, BaseMemoryPool pool, byte[] authArea, byte[] parameters)
    {
        byte[] command = new byte[TpmHeader.HeaderSize + sizeof(uint) + authArea.Length + parameters.Length];
        var writer = new TpmWriter(command);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)command.Length, (uint)TpmCcConstants.TPM_CC_LoadExternal);
        header.WriteTo(ref writer);
        writer.WriteUInt32((uint)authArea.Length);
        writer.WriteBytes(authArea);
        writer.WriteBytes(parameters);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(command, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The simulator must answer a refused command rather than fault.");

        using TpmResponse response = result.Value;
        byte[] responseBytes = response.AsReadOnlySpan().ToArray();
        var reader = new TpmReader(response.AsReadOnlySpan());

        return ((TpmRcConstants)TpmHeader.Parse(ref reader).Code, responseBytes);
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
        byte[] old = priorDigest ?? new byte[DigestSize];
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
            input, DigestSize, CryptoTags.Sha256Digest, pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        return digest.AsReadOnlySpan().ToArray();
    }

    /// <summary>Starts an HMAC session bound to <c>TPM_RH_OWNER</c> — a permanent entity whose empty authValue lends no dictionary-attack protection — negotiating <paramref name="symmetric"/>.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="symmetric">The symmetric definition to negotiate.</param>
    /// <returns>The session handle and the host session.</returns>
    private Task<(uint Handle, TpmSession Session)> StartOwnerBoundSessionAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmtSymDef symmetric) =>
        HmacKeyHarness.StartBoundHmacSessionAsync(tpm, registry, pool, (uint)TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, symmetric, isBoundToAuthorizedEntity: false, TestContext.CancellationToken);

    /// <summary>
    /// Lowers <c>maxTries</c> to one, defines the dictionary-attack-protected Index at
    /// <see cref="DaProtectedBindIndexHandle"/> and drives the TPM into Lockout mode with one wrong-password write
    /// against it (TPM 2.0 Library Part 1, clause 16.8).
    /// </summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task DriveIntoLockoutAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        const uint LoweredMaxTries = 1;
        TpmResult<DictionaryAttackParametersResponse> lowerResult = await tpm.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, LoweredMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds, TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lowerResult.IsSuccess, $"Lowering maxTries failed: '{lowerResult.ResponseCode}'.");

        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);
        using var auth = Tpm2bAuth.Create(BindIndexAuth, pool);
        using var publicInfo = new TpmsNvPublic(DaProtectedBindIndexHandle, SessionAlg, DaProtectedIndexAttributes, Tpm2bDigest.Empty, BindIndexDataSize);
        using var defineInput = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, auth, publicInfo);
        TpmResult<NvDefineSpaceResponse> defineResult = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            tpm, defineInput, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"TPM2_NV_DefineSpace(0x{DaProtectedBindIndexHandle:X8}) failed: '{defineResult.ResponseCode}'.");

        using TpmPasswordSession wrongSession = TpmPasswordSession.Create(WrongIndexAuth, pool);
        using Tpm2bMaxNvBuffer buffer = Tpm2bMaxNvBuffer.Create(PrimingWriteData, pool);
        var writeInput = new NvWriteInput(DaProtectedBindIndexHandle, DaProtectedBindIndexHandle, buffer, Offset: 0);
        TpmResult<NvWriteResponse> wrongResult = await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
            tpm, writeInput, [wrongSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, 0), wrongResult.ResponseCode, "The priming write must fail and count, taking the TPM into Lockout mode.");

        TpmResult<TpmDictionaryAttackParameters> state = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(state.Value.IsLockedOut, "The TPM must be in Lockout mode before the case under proof runs.");
    }

    /// <summary>The tag describing a raw SHA-256 digest for the cpHash computation.</summary>
    /// <returns>The tag.</returns>
    private static Tag DigestTag() =>
        Tag.Create(HashAlgorithmName.SHA256).With(Purpose.Digest).With(EncodingScheme.Raw).With(MaterialSemantics.Direct);
}
