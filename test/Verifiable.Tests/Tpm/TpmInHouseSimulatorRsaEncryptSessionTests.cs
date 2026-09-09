using System;
using System.Buffers.Binary;
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
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives the <c>TPM_ST_SESSIONS</c> form of <c>TPM2_RSA_Encrypt()</c> against the in-house behavioural
/// <see cref="TpmSimulator"/>: the zero-authorizing-slot session table's cells (<c>keyHandle</c> carries Auth
/// Index None, so the one command session is a companion only, never an authorizing slot — the identical shape
/// <c>TPM2_LoadExternal()</c>'s own session table carries), the XOR and AES-CFB round trips through the
/// production <see cref="TpmCommandExecutor"/> and <see cref="TpmSession"/>, and the wire-shape refusals framed
/// by hand where the executor's own client-side guards would refuse the composition first (TPM 2.0 Library Part
/// 3, clauses 5.5, 5.6, 5.7 and 14.2; Part 1, clauses 15.7, 16.8.1 and 18).
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorRsaEncryptSessionTests
{
    /// <summary>The hash algorithm used throughout: the session's, the Name algorithm, and the OAEP scheme's.</summary>
    private const TpmAlgIdConstants Alg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The digest width of <see cref="Alg"/>, the cpHash width.</summary>
    private const int DigestSize = 32;

    /// <summary>The RSA key width the loaded keys use throughout.</summary>
    private const ushort RsaKeyBits = 2048;

    /// <summary>The message-size bound an OAEP-SHA-256 scheme admits at 2048 bits: <c>k - 2·hLen - 2 = 256 - 64 - 2</c>.</summary>
    private const int OaepMessageBound = 190;

    /// <summary>A message wider than <see cref="OaepMessageBound"/>, so the effect refuses it (Table 43).</summary>
    private const int OversizedOaepMessageLength = OaepMessageBound + 10;

    /// <summary>The dictionary-attack-protected Ordinary Index a session is bound to for the Lockout case.</summary>
    private const uint DaProtectedBindIndexHandle = 0x0100_01C0;

    /// <summary>The bind Index's declared data size.</summary>
    private const ushort BindIndexDataSize = 16;

    /// <summary>Dictionary-attack-protected Ordinary Index attributes: <c>TPMA_NV_NO_DA</c> is CLEAR.</summary>
    private const TpmaNv DaProtectedIndexAttributes = TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_OWNERWRITE;

    /// <summary>A transient-object handle value, never a session handle by its kind alone.</summary>
    private const uint TransientRangeHandle = 0x8000_0000;

    /// <summary>The attribute word of an externally loaded RSA key: unbound, caller-supplied, USER-role by password.</summary>
    private const TpmaObject ExternalKeyAttributes = TpmaObject.USER_WITH_AUTH | TpmaObject.DECRYPT | TpmaObject.NO_DA;

    /// <summary>The bind Index's authorization value.</summary>
    private static byte[] BindIndexAuth { get; } = [0x01, 0x02, 0x03, 0x04];

    /// <summary>A wrong authorization value for the bind Index.</summary>
    private static byte[] WrongIndexAuth { get; } = [0x09, 0x09, 0x09, 0x09];

    /// <summary>The octets written into the Index that drives the TPM into Lockout mode.</summary>
    private static byte[] PrimingWriteData { get; } = [0x2A];

    /// <summary>The plaintext message RSA-encrypted throughout, OAEP-eligible at 2048 bits.</summary>
    private static byte[] MessageBytes { get; } = "RSA session message!"u8.ToArray();

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>A fresh <see cref="TpmInHouseSimulatorNoAuthSessionTests"/> instance carrying this class's own <see cref="TestContext"/>, reached for its NULL-signer audit-digest helper rather than re-minting a second copy here.</summary>
    private TpmInHouseSimulatorNoAuthSessionTests Shared => new() { TestContext = TestContext };

    /// <summary>
    /// "If present, a password authorization is always associated with a command handle that requires
    /// authorization as there is no session context associated with a password that would allow it to be used
    /// for encryption or command audit." — <c>keyHandle</c> carries Auth Index None (Table 44), so no command
    /// handle requires authorization here either, and a <c>TPM_RS_PW</c> slot is refused with the
    /// session-index-encoded <c>TPM_RC_ATTRIBUTES</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clauses 16.4 and 15.6.4, Table 15; TPM 2.0 Library Part 3, clause 14.2, Table 44</see>.
    /// </summary>
    [TestMethod]
    public async Task RsaEncryptOverAPasswordSlotReturnsSessionEncodedAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaEncryptOverAPasswordSlotReturnsSessionEncodedAttributes), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using RsaKeyMaterial key = RsaKeyMaterial.Generate();
        LoadedRsaKey loaded = await LoadPublicOnlyRsaKeyAsync(tpm, registry, pool, key).ConfigureAwait(false);

        byte[] parameters = SerializeParameters(pool);
        TpmRcConstants code = await SubmitOneHandleAsync(simulator, pool, loaded.Handle, BuildPasswordAuthArea(), parameters).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0), code,
            "TPM2_RSA_Encrypt() has no authorizing command handle for a TPM_RS_PW authorization to attach to (Part 1, clause 16.4).");
    }

    /// <summary>
    /// "If a session is not being used for authorization, at least one of decrypt, encrypt, or audit must be
    /// SET. (TPM_RC_ATTRIBUTES)." — a loaded HMAC session at the command's lone companion slot authorizes
    /// nothing, so claiming none of the three is refused, session-index-encoded to the slot.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.5, step 4.4.2; Part 2, clause 6.6.2</see>.
    /// </summary>
    [TestMethod]
    public async Task RsaEncryptOverAnAttributelessSessionReturnsSessionEncodedAttributes()
    {
        await AssertSessionClaimAnswerAsync(
            nameof(RsaEncryptOverAnAttributelessSessionReturnsSessionEncodedAttributes), TpmaSession.CONTINUE_SESSION, TpmtSymDef.Xor(Alg),
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0),
            "a session authorizing nothing must claim at least one of decrypt, encrypt or audit (Part 3, clause 5.5, step 4.4.2)").ConfigureAwait(false);
    }

    /// <summary>
    /// "This attribute indicates that the session is being used for audit." — an <c>audit</c> claim at
    /// <c>TPM2_RSA_Encrypt()</c>'s lone slot is admitted and the command succeeds, extending the session's audit
    /// digest to <c>H(0…0 ‖ cpHash ‖ rpHash)</c> on its first use (TPM 2.0 Library Part 1, clause 17.1, equation
    /// 30) with the response echoing <c>audit</c> SET, <c>auditExclusive</c> SET and <c>auditReset</c> CLEAR
    /// (Part 2, clause 8.4, Table 38) — proved by chaining cpHash/rpHash from the octets this test itself sent
    /// and read, then reading the session's digest back through <c>TPM2_GetSessionAuditDigest()</c> with the NULL
    /// signer.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.1; Part 2, clause 8.4, Table 38</see>.
    /// </summary>
    [TestMethod]
    public async Task RsaEncryptOverAnAuditClaimingSessionSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaEncryptOverAnAuditClaimingSessionSucceeds), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_GetSessionAuditDigest, TpmResponseCodec.GetSessionAuditDigest);
        using RsaKeyMaterial key = RsaKeyMaterial.Generate();
        LoadedRsaKey loaded = await LoadPublicOnlyRsaKeyAsync(tpm, registry, pool, key).ConfigureAwait(false);

        byte[] parameters = SerializeParameters(pool);
        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(tpm, registry, pool, TpmtSymDef.Xor(Alg)).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                byte[] authArea = await BuildSessionAuthAreaAsync(session, loaded.Name, parameters, pool).ConfigureAwait(false);

                (TpmRcConstants code, byte[] response) = await SubmitOneHandleForAuditAsync(simulator, pool, loaded.Handle, authArea, parameters).ConfigureAwait(false);
                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "TPM2_RSA_Encrypt() over a session claiming audit alone succeeds (Part 1, clause 17.1).");

                byte auditedAttributes = ReadResponseSessionAttributes(response, outHandleCount: 0, sessionIndex: 0);
                Assert.AreEqual(
                    (byte)(TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT | TpmaSession.AUDIT_EXCLUSIVE), auditedAttributes,
                    "The response echoes audit SET and auditExclusive SET (the session's first use as an audit session), with auditReset CLEAR (TPM 2.0 Library Part 2, clause 8.4, Table 38).");

                byte[] responseParameters = ReadResponseParameters(response, outHandleCount: 0);
                using DigestValue cpHash = await ComputeCpHashAsync(loaded.Name, parameters, pool).ConfigureAwait(false);
                byte[] rpHash = await ComputeRpHashAsync(TpmCcConstants.TPM_CC_RSA_Encrypt, responseParameters, pool).ConfigureAwait(false);
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
                    "The session's audit digest must equal H(0…0 ‖ cpHash ‖ rpHash) chained from the encrypt exchange's own wire octets (TPM 2.0 Library Part 1, clause 17.1, equation 30).");
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "If the symmetric algorithm is TPM_ALG_NULL and encryption or decryption is specified, the TPM returns
    /// TPM_RC_SYMMETRIC." — <c>message</c> is a sized first parameter (Table 44), so a <c>decrypt</c> claim is
    /// admissible and the session's own symmetric definition decides, judged before the parameters.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 18.1; Part 3, clause 5.7</see>.
    /// </summary>
    [TestMethod]
    public async Task RsaEncryptOverADecryptClaimingNullSymmetricSessionReturnsSessionEncodedSymmetric()
    {
        await AssertSessionClaimAnswerAsync(
            nameof(RsaEncryptOverADecryptClaimingNullSymmetricSessionReturnsSessionEncodedSymmetric), TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT, TpmtSymDef.Null,
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_SYMMETRIC, sessionIndex: 0),
            "a decrypt claim over a session that negotiated no symmetric algorithm is TPM_RC_SYMMETRIC (Part 1, clause 18.1)").ConfigureAwait(false);
    }

    /// <summary>
    /// "The TPM shall successfully unmarshal the number of handles required by the command and validate that the
    /// value of the handle is consistent with the command syntax. If not, the TPM shall return TPM_RC_VALUE." — a
    /// <c>keyHandle</c> whose type octet is neither <c>TPM_HT_TRANSIENT</c> nor <c>TPM_HT_PERSISTENT</c> is a
    /// handle-area syntax failure, judged at parse before the authorization area is ever read, so a genuine,
    /// loaded encrypt companion at the sole slot is never reached at all — its nonceTPM stays usable for a later,
    /// well-typed call over the same session. This request is framed <c>TPM_ST_SESSIONS</c>, so the shared
    /// no-authorization wrapper reads <c>keyHandle</c> knowing <c>TPM2_RSA_Encrypt()</c> (Table 44) declares
    /// exactly one handle at index 0, and designates the failure to it (Part 2, clause 6.6.2, Table 15/16 — H1).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3,
    /// clause 5.4, step 1; Part 2, clause 9.3, Table 49</see>.
    /// </summary>
    [TestMethod]
    [DataRow(0x0100_0001u, DisplayName = "NV Index")]
    [DataRow(0x0000_0001u, DisplayName = "PCR")]
    [DataRow(0x0200_0001u, DisplayName = "HMAC session")]
    [DataRow(0x4000_0001u, DisplayName = "Permanent/hierarchy")]
    public async Task RsaEncryptOverAnEncryptSlotWithAMistypedHandleAnswersHandleEncodedValueAheadOfTheSession(uint mistypedHandle)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaEncryptOverAnEncryptSlotWithAMistypedHandleAnswersHandleEncodedValueAheadOfTheSession), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using RsaKeyMaterial key = RsaKeyMaterial.Generate();
        LoadedRsaKey loaded = await LoadPublicOnlyRsaKeyAsync(tpm, registry, pool, key).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(tpm, registry, pool, TpmtSymDef.Xor(Alg)).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                //The range check runs ahead of the authorization area (clause 5.4 precedes clause 5.5), so an
                //empty area suffices — the octets that would follow the mistyped handle are never inspected.
                (TpmRcConstants code, byte[] response) = await SubmitOneHandleForAuditAsync(simulator, pool, mistypedHandle, authArea: [], parameters: []).ConfigureAwait(false);

                //keyHandle is TPM2_RSA_Encrypt()'s sole handle, Table 44, index 0 (this test's own doc comment).
                Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), code, $"A handle of type 0x{(mistypedHandle >> 24):X2} is TPM_RC_VALUE designated to handle 1, ahead of the authorization area.");

                var responseReader = new TpmReader(response);
                TpmHeader responseHeader = TpmHeader.Parse(ref responseReader);
                Assert.AreEqual((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, responseHeader.Tag, "A failed command frames TPM_ST_NO_SESSIONS regardless of the request's own tag.");
                Assert.HasCount(10, response, "A failed command's response is exactly the 10-octet header (Part 3, clause 5.9).");

                byte[] parameters = SerializeParameters(pool);
                byte[] followUpAuthArea = await BuildSessionAuthAreaAsync(session, loaded.Name, parameters, pool).ConfigureAwait(false);
                TpmRcConstants followUpCode = await SubmitOneHandleAsync(simulator, pool, loaded.Handle, followUpAuthArea, parameters).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, followUpCode, "The session's nonceTPM was never touched by the parse-time refusal, so a genuine, well-typed follow-up over it still verifies.");
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A sequence handle's Name term is the Empty Buffer ("the Name associated with sequenceHandle will be the
    /// Empty Buffer"), so the audit companion is verified over it exactly like any other slot BEFORE
    /// <c>TPM2_RSA_Encrypt()</c>'s own sequence-slot gate answers <c>TPM_RC_KEY</c>, handle-encoded to the same index — the resolved kind is
    /// neither a key nor a KEYEDHASH object: the response is still bare, framed <c>TPM_ST_NO_SESSIONS</c> in
    /// exactly 10 octets, and the session never becomes an audit session at all (only a command that claims
    /// <c>audit</c> AND succeeds starts its digest chain).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1,
    /// Table 9 footnote (1) and clause 29.4.6; Part 3, clauses 5.4, 5.9 and 14.2</see>.
    /// </summary>
    [TestMethod]
    public async Task RsaEncryptWithASequenceHandleAtTheKeySlotAnswersTheInnersHandleEncodedKeyAfterTheSessionsVerified()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaEncryptWithASequenceHandleAtTheKeySlotAnswersTheInnersHandleEncodedKeyAfterTheSessionsVerified), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry()
            .Register(TpmCcConstants.TPM_CC_HashSequenceStart, TpmResponseCodec.HashSequenceStart)
            .Register(TpmCcConstants.TPM_CC_GetSessionAuditDigest, TpmResponseCodec.GetSessionAuditDigest);
        using RsaKeyMaterial key = RsaKeyMaterial.Generate();
        LoadedRsaKey loaded = await LoadPublicOnlyRsaKeyAsync(tpm, registry, pool, key).ConfigureAwait(false);

        using HashSequenceStartInput openInput = HashSequenceStartInput.CreateFromPassword(string.Empty, TpmiAlgHash.FromValue(Alg), pool);
        TpmResult<HashSequenceStartResponse> openResult = await TpmCommandExecutor.ExecuteAsync<HashSequenceStartResponse>(
            tpm, openInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(openResult.IsSuccess, $"TPM2_HashSequenceStart() must succeed: '{openResult.ResponseCode}'.");
        uint sequenceHandle = openResult.Value.SequenceHandle.Value;

        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(tpm, registry, pool, TpmtSymDef.Xor(Alg)).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                //The sequence handle's Name term is the Empty Buffer, the SAME term the session's own command
                //HMAC commits to, so the HMAC is verified before the command's own handle-role check runs.
                byte[] parameters = SerializeParameters(pool);
                byte[] authArea = await BuildSessionAuthAreaAsync(session, [], parameters, pool).ConfigureAwait(false);

                (TpmRcConstants code, byte[] response) = await SubmitOneHandleForAuditAsync(simulator, pool, sequenceHandle, authArea, parameters).ConfigureAwait(false);
                Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_KEY, 0), code, "A sequence handle refuses at keyHandle, handle 1 of Table 44, after the authorization area verifies.");

                var responseReader = new TpmReader(response);
                TpmHeader responseHeader = TpmHeader.Parse(ref responseReader);
                Assert.AreEqual((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, responseHeader.Tag, "A failed command frames TPM_ST_NO_SESSIONS regardless of the request's own tag.");
                Assert.HasCount(10, response, "A failed command's response is exactly the 10-octet header (Part 3, clause 5.9).");

                (TpmRcConstants digestCodeAfterRefusal, _) = await Shared.TryReadNullSignedAuditDigestAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
                Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_TYPE, 2), digestCodeAfterRefusal, "The refused command never used the session as an audit session — TPM2_GetSessionAuditDigest() still refuses TPM_RC_TYPE, exactly as a session that has never audited anything (Part 3, clause 5.9).");

                byte[] followUpAuthArea = await BuildSessionAuthAreaAsync(session, loaded.Name, parameters, pool).ConfigureAwait(false);
                TpmRcConstants followUpCode = await SubmitOneHandleAsync(simulator, pool, loaded.Handle, followUpAuthArea, parameters).ConfigureAwait(false);
                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, followUpCode, "The session's nonceTPM was never touched by the refusal, so a genuine, well-typed follow-up over it still verifies.");
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "If the session is not loaded, the TPM will return the warning TPM_RC_REFERENCE_S0 + N where N is the
    /// number of the session." — a well-typed session handle whose session has been flushed.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.5, step 4.2; Part 2, clause 6.6.2</see>.
    /// </summary>
    [TestMethod]
    public async Task RsaEncryptOverAnUnloadedSessionHandleReturnsReferenceMiss()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaEncryptOverAnUnloadedSessionHandleReturnsReferenceMiss), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using RsaKeyMaterial key = RsaKeyMaterial.Generate();
        LoadedRsaKey loaded = await LoadPublicOnlyRsaKeyAsync(tpm, registry, pool, key).ConfigureAwait(false);

        byte[] parameters = SerializeParameters(pool);
        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(tpm, registry, pool, TpmtSymDef.Xor(Alg)).ConfigureAwait(false);
        byte[] authArea;
        using(session)
        {
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;
            authArea = await BuildSessionAuthAreaAsync(session, loaded.Name, parameters, pool).ConfigureAwait(false);
        }

        await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);

        TpmRcConstants code = await SubmitOneHandleAsync(simulator, pool, loaded.Handle, authArea, parameters).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_REFERENCE_S0, code, "A session handle naming no loaded session is blamed on the offending slot (Part 3, clause 5.5, step 4.2).");
    }

    /// <summary>
    /// A LOADED policy session at the command's lone companion slot, claiming <c>encrypt</c>, is admitted
    /// exactly like an HMAC companion — TPM 2.0 Library Part 1, clause 15.6.1, Table 12, footnote [2] — since
    /// <c>TPM2_RSA_Encrypt()</c>'s <c>outData</c> is a sized response parameter an encrypt session may protect.
    /// This test's wire block is built with a BOUND HMAC session's own real, KDFa-derived key, then its handle
    /// field alone is overwritten with an unrelated, UNBOUND policy session's handle: the resolved policy
    /// session's own <c>sessionKey</c> (the Empty Buffer, since it is neither bound nor salted, Part 1, clause
    /// 18) is generic to the command HMAC verification step, so this proves the DIFFERENT-key case rather than
    /// the type gate — the command HMAC recomputed under the policy session's own key cannot match the one built
    /// under the other session's, and the mismatch is refused session-encoded <c>TPM_RC_BAD_AUTH</c>, uncharged
    /// (the policy session is unbound, so no dictionary-attack accounting applies, Part 1, clause 16.8.1), the
    /// inner action never run.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 15.6.1, Table 12, footnote [2]; clause 18; clause 16.8.1</see>.
    /// </summary>
    [TestMethod]
    public async Task RsaEncryptOverALoadedPolicySessionClaimingEncryptWithAMismatchedKeyReturnsBadAuth()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaEncryptOverALoadedPolicySessionClaimingEncryptWithAMismatchedKeyReturnsBadAuth), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using RsaKeyMaterial key = RsaKeyMaterial.Generate();
        LoadedRsaKey loaded = await LoadPublicOnlyRsaKeyAsync(tpm, registry, pool, key).ConfigureAwait(false);

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
            AuthHash = Alg,
            Symmetric = TpmtSymDef.Xor(Alg)
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

            TpmRcConstants code = await SubmitOverPatchedSlotAsync(simulator, tpm, registry, pool, loaded, policySessionHandle).ConfigureAwait(false);
            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), code,
                "A POLICY session admitted at the companion slot is refused session-encoded BAD_AUTH once its own (Empty Buffer) key fails to reproduce a command HMAC built under a different session's key.");

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
    /// A single LOADED policy session may claim BOTH <c>decrypt</c> and <c>encrypt</c> at
    /// <c>TPM2_RSA_Encrypt()</c>'s one companion slot, exactly like an HMAC session (TPM 2.0 Library Part 1,
    /// clause 15.6.1, Table 12, footnote [2]): the policy companion's own AES-CFB key recovers <c>message</c> and
    /// protects <c>outData</c> at once, and the off-TPM twin recovers the exact plaintext from the
    /// doubly-protected round trip.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3,
    /// clause 14.2, Tables 44 and 45; Part 1, clause 15.6.1, Table 12, footnote [2]</see>.
    /// </summary>
    [TestMethod]
    public async Task RsaEncryptOverASinglePolicySessionClaimingBothDecryptAndEncryptProtectsBothDirections()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaEncryptOverASinglePolicySessionClaimingBothDecryptAndEncryptProtectsBothDirections), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using RsaKeyMaterial key = RsaKeyMaterial.Generate();
        LoadedRsaKey loaded = await LoadPublicOnlyRsaKeyAsync(tpm, registry, pool, key).ConfigureAwait(false);

        var policyInput = new StartAuthSessionInput
        {
            TpmKey = (uint)TpmRh.TPM_RH_NULL,
            Bind = (uint)TpmRh.TPM_RH_NULL,
            NonceCaller = RandomNumberGenerator.GetBytes(DigestSize),
            EncryptedSalt = ReadOnlyMemory<byte>.Empty,
            SessionType = TpmSeConstants.TPM_SE_POLICY,
            AuthHash = Alg,
            Symmetric = TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB)
        };
        TpmResult<StartAuthSessionResponse> policyResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, policyInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(policyResult.IsSuccess, $"StartAuthSession (policy) failed: '{policyResult.ResponseCode}'.");
        StartAuthSessionResponse policyStarted = policyResult.Value;
        uint policySessionHandle = policyStarted.SessionHandle.Value;
        var policySession = new TpmSession(new TpmHandle(policySessionHandle), policyStarted.NonceTPM, Alg, TestEntropy.NewCounterStream(), pool, policyInput.Symmetric);

        try
        {
            using(policySession)
            {
                policySession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT | TpmaSession.ENCRYPT;

                byte[] parameters = SerializeParameters(pool);
                policySession.RollNonceCaller(pool);
                await policySession.EncryptFirstParameterAsync(parameters.AsMemory(sizeof(ushort), MessageBytes.Length), pool, TestContext.CancellationToken).ConfigureAwait(false);

                using DigestValue cpHash = await ComputeCpHashAsync(loaded.Name, parameters, pool).ConfigureAwait(false);
                using Tpm2bAuth? hmac = await policySession.PrepareAuthHmacAsync(cpHash.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);
                byte[] authArea = new byte[policySession.GetAuthCommandSize()];
                var authWriter = new TpmWriter(authArea);
                policySession.WriteAuthCommand(ref authWriter, hmac);

                (TpmRcConstants code, byte[] response) = await SubmitOneHandleForAuditAsync(simulator, pool, loaded.Handle, authArea, parameters).ConfigureAwait(false);
                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, $"TPM2_RSA_Encrypt() over a policy session claiming both decrypt and encrypt must succeed: '{code}'.");

                byte[] cipherResponseParameters = ReadResponseParameters(response, outHandleCount: 0);
                byte[] rpHash = await ComputeRpHashAsync(TpmCcConstants.TPM_CC_RSA_Encrypt, cipherResponseParameters, pool).ConfigureAwait(false);
                using TpmsAuthResponse entry = ReadResponseSessionEntry(response, outHandleCount: 0, sessionIndex: 0, pool);
                bool verified = await policySession.VerifyAndUpdateAsync(entry, rpHash, pool, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(verified, "The policy companion's own response HMAC must verify under its session key before outData is decrypted.");

                ushort outDataLength = BinaryPrimitives.ReadUInt16BigEndian(cipherResponseParameters);
                await policySession.DecryptFirstParameterAsync(cipherResponseParameters.AsMemory(sizeof(ushort), outDataLength), pool, TestContext.CancellationToken).ConfigureAwait(false);

                byte[] recovered = key.Key.Decrypt(cipherResponseParameters.AsSpan(sizeof(ushort), outDataLength).ToArray(), RSAEncryptionPadding.OaepSHA256);
                Assert.IsTrue(recovered.AsSpan().SequenceEqual(MessageBytes), "The off-TPM decrypt recovers the exact plaintext through both protected directions at once, over a single POLICY companion.");
            }
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
    public async Task RsaEncryptOverANonSessionSlotHandleReturnsSessionEncodedHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaEncryptOverANonSessionSlotHandleReturnsSessionEncodedHandle), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using RsaKeyMaterial key = RsaKeyMaterial.Generate();
        LoadedRsaKey loaded = await LoadPublicOnlyRsaKeyAsync(tpm, registry, pool, key).ConfigureAwait(false);

        TpmRcConstants code = await SubmitOverPatchedSlotAsync(simulator, tpm, registry, pool, loaded, TransientRangeHandle).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_HANDLE, sessionIndex: 0), code,
            "A non-session handle at the companion slot is refused on the handle's kind, ahead of any credential evaluation (Part 3, clause 5.5, step 4.1).");
    }

    /// <summary>
    /// "If a session is not being used for authorization, at least one of decrypt, encrypt, or audit must be
    /// SET. (TPM_RC_ATTRIBUTES)" — <c>keyHandle</c> carries no Auth Index (Table 44), so a <c>TPM_RS_PW</c> slot
    /// here authorizes nothing and "a password authorization cannot be used for anything but authorization and
    /// the TPM will return an error (TPM_RC_ATTRIBUTES) if encrypt, decrypt, or audit is SET in a password
    /// authorization" leaves it no admissible attribute octet at all. This refusal is judged over the
    /// authorization area alone (TPM 2.0 Library Part 3, clause 5.5), strictly before <c>message</c>'s own
    /// declared size is ever read (clause 5.8) — so a <c>message</c> declared past Table 194's
    /// <c>MAX_RSA_KEY_BYTES</c> bound in the SAME command never reaches the size check at all: the password
    /// slot's session-encoded <c>TPM_RC_ATTRIBUTES</c> wins.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.5, step 4.4.2; TPM 2.0 Library Part 1, clause 15.6.1</see>.
    /// </summary>
    [TestMethod]
    public async Task RsaEncryptWithAnOverBoundMessageOverAPasswordSlotReturnsSessionEncodedAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaEncryptWithAnOverBoundMessageOverAPasswordSlotReturnsSessionEncodedAttributes), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using RsaKeyMaterial key = RsaKeyMaterial.Generate();
        LoadedRsaKey loaded = await LoadPublicOnlyRsaKeyAsync(tpm, registry, pool, key).ConfigureAwait(false);

        byte[] parameters = SerializeOverBoundParameters();
        TpmRcConstants code = await SubmitOneHandleAsync(simulator, pool, loaded.Handle, BuildPasswordAuthArea(), parameters).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0), code,
            "The password slot's authorization-area refusal is judged before message's own size field is ever read (Part 3, clause 5.5 precedes clause 5.8), so the over-bound message never reaches its own size check.");
    }

    /// <summary>
    /// An <c>audit</c>-only claim admits no decrypt transform, so the parameter core runs on the raw wire octets
    /// exactly as an unauthenticated peer would send them: <c>message</c>'s declared size past Table 194's
    /// <c>MAX_RSA_KEY_BYTES</c> bound is a structural failure of <c>message</c> itself, <c>TPM2_RSA_Encrypt()</c>'s
    /// first parameter (Table 44, index 0), so it is parameter-encoded — and the response is the 10-octet
    /// <c>TPM_ST_NO_SESSIONS</c> failure shape, the session's nonces and audit status untouched, so it verifies a
    /// well-formed command afterward with no restart.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.5 precedes clause 5.8; clause 5.9; TPM 2.0 Library Part 2, clause 11.2.4.6, Table 194; clause 6.6.2, Table 15</see>.
    /// </summary>
    [TestMethod]
    public async Task RsaEncryptWithAnOverBoundMessageOverAnAuditOnlySessionReturnsParameterEncodedSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaEncryptWithAnOverBoundMessageOverAnAuditOnlySessionReturnsParameterEncodedSize), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using RsaKeyMaterial key = RsaKeyMaterial.Generate();
        LoadedRsaKey loaded = await LoadPublicOnlyRsaKeyAsync(tpm, registry, pool, key).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(tpm, registry, pool, TpmtSymDef.Xor(Alg)).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                byte[] overBoundParameters = SerializeOverBoundParameters();
                byte[] overBoundAuthArea = await BuildSessionAuthAreaAsync(session, loaded.Name, overBoundParameters, pool).ConfigureAwait(false);
                (TpmRcConstants code, byte[] response) = await SubmitOneHandleForAuditAsync(simulator, pool, loaded.Handle, overBoundAuthArea, overBoundParameters).ConfigureAwait(false);
                Assert.AreEqual(
                    HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, parameterIndex: 0), code,
                    "message is TPM2_RSA_Encrypt()'s first parameter (Table 44, index 0); its own declared size is read only once the audit-only area has verified, and the structural over-bound is parameter-encoded (Part 2, clause 6.6.2, Table 15).");

                var reader = new TpmReader(response);
                TpmHeader header = TpmHeader.Parse(ref reader);
                Assert.AreEqual((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, header.Tag, "A failed command's response is tagged TPM_ST_NO_SESSIONS regardless of the request's own tag (Part 3, clause 5.9).");
                Assert.AreEqual((uint)TpmHeader.HeaderSize, header.Size, "A failed command's response is exactly the 10-octet header, no session area appended (Part 3, clause 5.9).");
                Assert.HasCount(TpmHeader.HeaderSize, response, "The raw response carries no octets beyond the 10-octet header.");

                byte[] parameters = SerializeParameters(pool);
                byte[] authArea = await BuildSessionAuthAreaAsync(session, loaded.Name, parameters, pool).ConfigureAwait(false);
                TpmRcConstants recovered = await SubmitOneHandleAsync(simulator, pool, loaded.Handle, authArea, parameters).ConfigureAwait(false);
                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, recovered, "The same session must verify a well-formed command afterward — the bare refusal rolled no nonce (Part 3, clause 5.9).");
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A <c>decrypt</c> claim over a session with a real (non-NULL) symmetric definition recovers <c>message</c>
    /// in plaintext before the parameter core ever runs (TPM 2.0 Library Part 3, clause 5.7 precedes clause
    /// 5.8): the declared size the core then judges against Table 194's <c>MAX_RSA_KEY_BYTES</c> bound belongs to
    /// the RECOVERED plaintext, not the wire's ciphertext octets, and is a structural failure of <c>message</c>
    /// itself — the SAME parameter-encoded answer the audit-only form gives, since a code the parameter core
    /// already designated is never re-designated to the decrypt slot (TPM 2.0 Library Part 2, clause 6.6.2,
    /// Table 15's closing sentence).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.7; clause 14.2, Table 44; TPM 2.0 Library Part 2, clause 11.2.4.6, Table 194; clause 6.6.2, Table 15</see>.
    /// </summary>
    [TestMethod]
    public async Task RsaEncryptWithAnOverBoundMessageOverADecryptSessionReturnsParameterEncodedSize()
    {
        await AssertSessionClaimAnswerAsync(
            nameof(RsaEncryptWithAnOverBoundMessageOverADecryptSessionReturnsParameterEncodedSize), TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT, TpmtSymDef.Xor(Alg),
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, parameterIndex: 0),
            "an over-bound message is judged against the recovered plaintext once the decrypt transform has run, but the answer is message's own designation (Table 44, index 0), passed through the decrypt continuation unchanged rather than blamed on the claiming slot",
            SerializeOverBoundParameters()).ConfigureAwait(false);
    }

    /// <summary>
    /// The <c>decrypt</c> claim over <c>message</c> (TPM 2.0 Library Part 1, clause 18.1): the executor encrypts
    /// the message client-side under the session's XOR or AES-CFB keystream, the TPM recovers the plaintext
    /// before RSA-encrypting it, and the off-TPM twin OAEP-decrypts <c>outData</c> back to the original
    /// plaintext — proving the plaintext, not the ciphertext, reached the RSA engine.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.2, Table 44</see>.
    /// </summary>
    /// <param name="isAesCfb">Whether the session negotiates AES-128-CFB (else the XOR obfuscation).</param>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task RsaEncryptOverADecryptSessionDeliversThePlaintextMessage(bool isAesCfb)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(RsaEncryptOverADecryptSessionDeliversThePlaintextMessage)}-{isAesCfb}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using RsaKeyMaterial key = RsaKeyMaterial.Generate();
        LoadedRsaKey loaded = await LoadPublicOnlyRsaKeyAsync(tpm, registry, pool, key).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(tpm, registry, pool, Symmetric(isAesCfb)).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                TpmResult<RsaEncryptResponse> result = await IssueEncryptAsync(tpm, registry, pool, session, loaded, MessageBytes, TpmtRsaDecrypt.Oaep(Alg)).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"TPM2_RSA_Encrypt() over a {Symmetric(isAesCfb).Algorithm} decrypt session must succeed, but failed: '{result.ResponseCode}'.");
                using RsaEncryptResponse response = result.Value;

                byte[] recovered = key.Key.Decrypt(response.OutData.Buffer.ToArray(), RSAEncryptionPadding.OaepSHA256);
                Assert.IsTrue(recovered.AsSpan().SequenceEqual(MessageBytes), "The off-TPM decrypt of outData recovers the exact plaintext, proving it reached the RSA engine intact.");
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The <c>encrypt</c> claim over <c>outData</c> (TPM 2.0 Library Part 1, clause 18.1): the executor decrypts
    /// the response under the session's keystream before returning it, and the off-TPM twin OAEP-decrypts the
    /// recovered <c>outData</c> back to the plaintext, proving the executor's own decrypt is correct.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.2, Table 45</see>.
    /// </summary>
    [TestMethod]
    public async Task RsaEncryptOverAnEncryptSessionProtectsOutData()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaEncryptOverAnEncryptSessionProtectsOutData), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using RsaKeyMaterial key = RsaKeyMaterial.Generate();
        LoadedRsaKey loaded = await LoadPublicOnlyRsaKeyAsync(tpm, registry, pool, key).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(tpm, registry, pool, TpmtSymDef.Xor(Alg)).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                TpmResult<RsaEncryptResponse> result = await IssueEncryptAsync(tpm, registry, pool, session, loaded, MessageBytes, TpmtRsaDecrypt.Oaep(Alg)).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"TPM2_RSA_Encrypt() over an encrypt session must succeed, but failed: '{result.ResponseCode}'.");
                using RsaEncryptResponse response = result.Value;

                byte[] recovered = key.Key.Decrypt(response.OutData.Buffer.ToArray(), RSAEncryptionPadding.OaepSHA256);
                Assert.IsTrue(recovered.AsSpan().SequenceEqual(MessageBytes), "The off-TPM decrypt of the executor-decrypted outData recovers the exact plaintext.");
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// One session may claim both directions (TPM 2.0 Library Part 1, clause 18.1): a <c>decrypt</c> claim over
    /// <c>message</c> and an <c>encrypt</c> claim over <c>outData</c> at once, both admissible independently per
    /// Table 44's session table, and the off-TPM twin recovers the exact plaintext from the doubly-protected
    /// round trip.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.2, Tables 44 and 45</see>.
    /// </summary>
    [TestMethod]
    public async Task RsaEncryptOverADecryptAndEncryptSessionProtectsBothDirections()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaEncryptOverADecryptAndEncryptSessionProtectsBothDirections), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using RsaKeyMaterial key = RsaKeyMaterial.Generate();
        LoadedRsaKey loaded = await LoadPublicOnlyRsaKeyAsync(tpm, registry, pool, key).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(tpm, registry, pool, TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB)).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT | TpmaSession.ENCRYPT;

                TpmResult<RsaEncryptResponse> result = await IssueEncryptAsync(tpm, registry, pool, session, loaded, MessageBytes, TpmtRsaDecrypt.Oaep(Alg)).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"TPM2_RSA_Encrypt() over a decrypt+encrypt session must succeed, but failed: '{result.ResponseCode}'.");
                using RsaEncryptResponse response = result.Value;

                byte[] recovered = key.Key.Decrypt(response.OutData.Buffer.ToArray(), RSAEncryptionPadding.OaepSHA256);
                Assert.IsTrue(recovered.AsSpan().SequenceEqual(MessageBytes), "The off-TPM decrypt recovers the exact plaintext through both protected directions at once.");
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
    public async Task RsaEncryptWithAWrongCommandHmacIsBadAuthUnchargedAndLockoutCounterUnchanged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaEncryptWithAWrongCommandHmacIsBadAuthUnchargedAndLockoutCounterUnchanged), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using RsaKeyMaterial key = RsaKeyMaterial.Generate();
        LoadedRsaKey loaded = await LoadPublicOnlyRsaKeyAsync(tpm, registry, pool, key).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(tpm, registry, pool, TpmtSymDef.Xor(Alg)).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;
                TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

                byte[] parameters = SerializeParameters(pool);
                byte[] authArea = await BuildSessionAuthAreaAsync(session, loaded.Name, parameters, pool).ConfigureAwait(false);
                TamperLastHmacOctet(authArea);
                TpmRcConstants code = await SubmitOneHandleAsync(simulator, pool, loaded.Handle, authArea, parameters).ConfigureAwait(false);
                Assert.AreEqual(
                    HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), code,
                    "A wrong command HMAC on a session lent no dictionary-attack protection is the session-index-encoded TPM_RC_BAD_AUTH (Part 1, clause 16.8.1).");

                TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(before.Value.LockoutCounter, after.Value.LockoutCounter, "Nothing lends the session dictionary-attack protection, so TPM_PT_LOCKOUT_COUNTER is unchanged.");
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A session bound to a dictionary-attack-protected NV Index while the TPM is in Lockout mode is refused
    /// with the bare <c>TPM_RC_LOCKOUT</c> before its command HMAC is judged: the bind-side gate applies "For
    /// all session types" (TPM 2.0 Library Part 3, clause 11.1.1), whatever the command authorizes.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 11.1.1; Part 1, clause 16.8.3</see>.
    /// </summary>
    [TestMethod]
    public async Task RsaEncryptOverASessionBoundToADaProtectedIndexInLockoutIsRefusedWithLockout()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaEncryptOverASessionBoundToADaProtectedIndexInLockoutIsRefusedWithLockout), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using RsaKeyMaterial key = RsaKeyMaterial.Generate();
        LoadedRsaKey loaded = await LoadPublicOnlyRsaKeyAsync(tpm, registry, pool, key).ConfigureAwait(false);

        await DriveIntoLockoutAsync(tpm, registry, pool).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await HmacKeyHarness.StartBoundHmacSessionAsync(
            tpm, registry, pool, DaProtectedBindIndexHandle, BindIndexAuth, TpmtSymDef.Xor(Alg), isBoundToAuthorizedEntity: false, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                TpmResult<RsaEncryptResponse> result = await IssueEncryptAsync(tpm, registry, pool, session, loaded, MessageBytes, TpmtRsaDecrypt.Oaep(Alg)).ConfigureAwait(false);
                Assert.AreEqual(TpmRcConstants.TPM_RC_LOCKOUT, result.ResponseCode, "A session bound to a DA-protected entity is unusable in Lockout mode (Part 3, clause 11.1.1).");
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The session's nonceTPM rolls on success only: an encrypt the effect refuses after the command HMAC
    /// verified (an OAEP message wider than Table 43's <c>k - 2hLen - 2</c> bound, <c>TPM_RC_VALUE</c>) leaves
    /// the session where it stood, and the SAME session — with no restart — then encrypts a well-formed
    /// message, which it could not if the refusal had advanced the session.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.6.3; Part 3, clause 14.2, Table 43</see>.
    /// </summary>
    [TestMethod]
    public async Task RsaEncryptRefusalRollsNoNonceAndTheSessionEncryptsAfterwards()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaEncryptRefusalRollsNoNonceAndTheSessionEncryptsAfterwards), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using RsaKeyMaterial key = RsaKeyMaterial.Generate();
        LoadedRsaKey loaded = await LoadPublicOnlyRsaKeyAsync(tpm, registry, pool, key).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(tpm, registry, pool, TpmtSymDef.Xor(Alg)).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                TpmResult<RsaEncryptResponse> refused = await IssueEncryptAsync(
                    tpm, registry, pool, session, loaded, new byte[OversizedOaepMessageLength], TpmtRsaDecrypt.Oaep(Alg)).ConfigureAwait(false);
                Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), refused.ResponseCode, "message is TPM2_RSA_Encrypt()'s first parameter (Table 44, index 0); an oversized OAEP message is parameter-encoded TPM_RC_VALUE at the effect (Table 43).");

                TpmResult<RsaEncryptResponse> accepted = await IssueEncryptAsync(tpm, registry, pool, session, loaded, MessageBytes, TpmtRsaDecrypt.Oaep(Alg)).ConfigureAwait(false);
                Assert.IsTrue(accepted.IsSuccess, $"The same session must encrypt without a restart — the refusal rolled no nonce — but failed: '{accepted.ResponseCode}'.");
                accepted.Value.Dispose();
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The hand-framed command HMAC, keyed on a cpHash computed exactly as <c>H(commandCode ‖ Name(keyHandle) ‖
    /// parameters)</c> — the ONE handle's Name folded into cpHash even though <c>keyHandle</c> carries Auth
    /// Index None (TPM 2.0 Library Part 1, clause 15.7, equation 15) — verifies against the simulator's own
    /// computation and the command succeeds.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 15.7, equation 15; TPM 2.0 Library Part 3, clause 14.2</see>.
    /// </summary>
    [TestMethod]
    public async Task RsaEncryptHandFramedCpHashOverTheKeysNameSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaEncryptHandFramedCpHashOverTheKeysNameSucceeds), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using RsaKeyMaterial key = RsaKeyMaterial.Generate();
        LoadedRsaKey loaded = await LoadPublicOnlyRsaKeyAsync(tpm, registry, pool, key).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(tpm, registry, pool, TpmtSymDef.Xor(Alg)).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;
                byte[] parameters = SerializeParameters(pool);
                byte[] authArea = await BuildSessionAuthAreaAsync(session, loaded.Name, parameters, pool).ConfigureAwait(false);

                TpmRcConstants code = await SubmitOneHandleAsync(simulator, pool, loaded.Handle, authArea, parameters).ConfigureAwait(false);
                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "A cpHash folding exactly the key's own Name verifies against the simulator's own equation-15 computation.");
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The hand-framed cpHash's twin under a WRONG Name term (a second key's Name, in place of the addressed
    /// key's own): the simulator resolves the wire's <c>keyHandle</c> to the REAL key and computes cpHash over
    /// ITS Name, so the mismatched HMAC is refused, session-index-encoded, proving the Name term is actually
    /// checked and not merely carried.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 15.7, equation 15; clause 16.8.1</see>.
    /// </summary>
    [TestMethod]
    public async Task RsaEncryptHandFramedCpHashWithTheWrongKeysNameIsBadAuth()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaEncryptHandFramedCpHashWithTheWrongKeysNameIsBadAuth), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using RsaKeyMaterial key = RsaKeyMaterial.Generate();
        using RsaKeyMaterial otherKey = RsaKeyMaterial.Generate();
        LoadedRsaKey loaded = await LoadPublicOnlyRsaKeyAsync(tpm, registry, pool, key).ConfigureAwait(false);
        LoadedRsaKey otherLoaded = await LoadPublicOnlyRsaKeyAsync(tpm, registry, pool, otherKey).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(tpm, registry, pool, TpmtSymDef.Xor(Alg)).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;
                byte[] parameters = SerializeParameters(pool);

                //Wire addresses the REAL key (loaded.Handle) but the HMAC is keyed on a cpHash folding a
                //DIFFERENT key's Name — the simulator resolves keyHandle first and computes cpHash over the
                //real key's own Name, so the two disagree.
                byte[] authArea = await BuildSessionAuthAreaAsync(session, otherLoaded.Name, parameters, pool).ConfigureAwait(false);

                TpmRcConstants code = await SubmitOneHandleAsync(simulator, pool, loaded.Handle, authArea, parameters).ConfigureAwait(false);
                Assert.AreEqual(
                    HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), code,
                    "A cpHash folding the wrong key's Name mismatches the simulator's own computation over the addressed key's real Name.");
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Pool hygiene over a session across three legs: a transition refusal (an attribute-less session,
    /// <c>TPM_RC_ATTRIBUTES</c>), an effect refusal (an oversized OAEP message, <c>TPM_RC_VALUE</c>) and a
    /// success whose response is released — each leaves the pool with exactly the carriers outstanding before
    /// it.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.2</see>.
    /// </summary>
    [TestMethod]
    public async Task RsaEncryptOverASessionLeavesThePoolBalancedAcrossATransitionRefusalAnEffectRefusalAndASuccess()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaEncryptOverASessionLeavesThePoolBalancedAcrossATransitionRefusalAnEffectRefusalAndASuccess), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using RsaKeyMaterial key = RsaKeyMaterial.Generate();
        LoadedRsaKey loaded = await LoadPublicOnlyRsaKeyAsync(tpm, registry, pool, key).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(tpm, registry, pool, TpmtSymDef.Xor(Alg)).ConfigureAwait(false);
        try
        {
            using(session)
            {
                long baseline = trackingPool.OutstandingCount;

                session.SessionAttributes = TpmaSession.CONTINUE_SESSION;
                TpmResult<RsaEncryptResponse> transitionRefused = await IssueEncryptAsync(tpm, registry, pool, session, loaded, MessageBytes, TpmtRsaDecrypt.Oaep(Alg)).ConfigureAwait(false);
                Assert.AreEqual(
                    HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0), transitionRefused.ResponseCode,
                    "The attribute-less session is refused with TPM_RC_ATTRIBUTES.");
                Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A transition refusal returns every carrier it rented.");

                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;
                TpmResult<RsaEncryptResponse> effectRefused = await IssueEncryptAsync(
                    tpm, registry, pool, session, loaded, new byte[OversizedOaepMessageLength], TpmtRsaDecrypt.Oaep(Alg)).ConfigureAwait(false);
                Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), effectRefused.ResponseCode, "message is TPM2_RSA_Encrypt()'s first parameter (Table 44, index 0); the oversized OAEP message is refused with parameter-encoded TPM_RC_VALUE.");
                Assert.AreEqual(baseline, trackingPool.OutstandingCount, "An effect refusal returns every carrier it rented.");

                TpmResult<RsaEncryptResponse> accepted = await IssueEncryptAsync(tpm, registry, pool, session, loaded, MessageBytes, TpmtRsaDecrypt.Oaep(Alg)).ConfigureAwait(false);
                Assert.IsTrue(accepted.IsSuccess, $"The encrypt must succeed, but failed: '{accepted.ResponseCode}'.");
                accepted.Value.Dispose();
                Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A successful session-authorized encrypt returns every carrier once the response is released.");
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>An RSA-2048 key pair minted by the framework, its modulus exported for a public-only load and the key kept for the off-TPM oracle.</summary>
    private sealed class RsaKeyMaterial: IDisposable
    {
        /// <summary>Gets the framework key, the off-TPM decrypting oracle.</summary>
        public RSA Key { get; }

        /// <summary>Gets the public modulus, 256 octets.</summary>
        public byte[] Modulus { get; }

        /// <summary>Initializes the material from the framework key.</summary>
        /// <param name="key">The framework key; owned.</param>
        private RsaKeyMaterial(RSA key)
        {
            Key = key;
            Modulus = PadLeft(key.ExportParameters(includePrivateParameters: false).Modulus!, RsaKeyBits / 8);
        }

        /// <summary>Mints a fresh RSA-2048 key pair.</summary>
        /// <returns>The material; the caller disposes it.</returns>
        public static RsaKeyMaterial Generate() => new(RSA.Create(RsaKeyBits));

        /// <summary>Releases the framework key.</summary>
        public void Dispose() => Key.Dispose();
    }

    /// <summary>A loaded RSA key's transient handle and its Name, independent of the LoadExternal response that produced them.</summary>
    /// <param name="Handle">The loaded transient object handle.</param>
    /// <param name="Name">The key's Name (<c>nameAlg ‖ H_nameAlg(TPMT_PUBLIC)</c>), copied out of the load response.</param>
    private readonly record struct LoadedRsaKey(uint Handle, byte[] Name);

    /// <summary>Left-pads an unsigned big-endian integer to a fixed width.</summary>
    /// <param name="value">The integer's octets.</param>
    /// <param name="width">The target width.</param>
    /// <returns>The padded octets.</returns>
    private static byte[] PadLeft(byte[] value, int width)
    {
        if(value.Length == width)
        {
            return value;
        }

        byte[] padded = new byte[width];
        value.CopyTo(padded, width - value.Length);

        return padded;
    }

    /// <summary>Creates an RSA-only operational simulator (no ECC backend, matching the RSA-only dispatch recipe).</summary>
    /// <param name="name">The per-test simulator identifier.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(string name, BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator($"tpm-in-house-rsa-encrypt-session-{name}", signingBackend: null, rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var startup = new StartupInput(TpmSuConstants.TPM_SU_CLEAR);
        int length = TpmHeader.HeaderSize + startup.GetSerializedSize();
        using System.Buffers.IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)startup.CommandCode);
        header.WriteTo(ref writer);
        startup.WriteHandles(ref writer);
        startup.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "TPM2_Startup(CLEAR) must succeed at the transport level.");
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)TpmHeader.Parse(ref reader).Code, "TPM2_Startup(CLEAR) must succeed.");

        return simulator;
    }

    /// <summary>Builds the codec registry covering every command these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry() =>
        new TpmResponseRegistry()
            .Register(TpmCcConstants.TPM_CC_LoadExternal, TpmResponseCodec.LoadExternal)
            .Register(TpmCcConstants.TPM_CC_RSA_Encrypt, TpmResponseCodec.RsaEncrypt)
            .Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession)
            .Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext)
            .Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace)
            .Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite);

    /// <summary>Issues a public-only <c>TPM2_LoadExternal()</c> under the owner hierarchy through the executor and returns the loaded handle and Name.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="key">The key material.</param>
    /// <returns>The loaded key's handle and Name.</returns>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the public area transfers to the load input, disposed here once the command has been issued.")]
    private async Task<LoadedRsaKey> LoadPublicOnlyRsaKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, RsaKeyMaterial key)
    {
        using LoadExternalInput input = LoadExternalInput.PublicOnly(
            Tpm2bPublic.CreateRsaSigningKey(Alg, ExternalKeyAttributes, RsaKeyBits, TpmtRsaScheme.Null, key.Modulus, pool), TpmiRhHierarchy.Owner);

        TpmResult<LoadExternalResponse> result = await TpmCommandExecutor.ExecuteAsync<LoadExternalResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_LoadExternal() (public-only RSA key) failed: '{result.ResponseCode}'.");
        using LoadExternalResponse loaded = result.Value;

        return new LoadedRsaKey(loaded.ObjectHandle.Value, loaded.Name.Span.ToArray());
    }

    /// <summary>Issues <c>TPM2_RSA_Encrypt()</c> over <paramref name="session"/> through the production executor and returns the raw result.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="session">The companion session.</param>
    /// <param name="loaded">The key to encrypt under.</param>
    /// <param name="message">The plaintext message.</param>
    /// <param name="inScheme">The padding scheme.</param>
    /// <returns>The raw result; the caller disposes the value on success.</returns>
    private async Task<TpmResult<RsaEncryptResponse>> IssueEncryptAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmSession session, LoadedRsaKey loaded, byte[] message, TpmtRsaDecrypt inScheme)
    {
        using Tpm2bPublicKeyRsa messageCarrier = Tpm2bPublicKeyRsa.Create(message, pool);
        using Tpm2bData label = Tpm2bData.Empty;
        var input = new RsaEncryptInput(TpmiDhObject.FromValue(loaded.Handle), messageCarrier, inScheme, label);

        return await TpmCommandExecutor.ExecuteAsync<RsaEncryptResponse>(
            tpm, input, [session], [loaded.Name], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Serializes the standard OAEP-SHA-256, empty-label parameter area (<c>message ‖ inScheme ‖ label</c>) through the production carriers.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The parameter area's octets.</returns>
    private static byte[] SerializeParameters(BaseMemoryPool pool)
    {
        using Tpm2bPublicKeyRsa message = Tpm2bPublicKeyRsa.Create(MessageBytes, pool);
        using Tpm2bData label = Tpm2bData.Empty;
        TpmtRsaDecrypt inScheme = TpmtRsaDecrypt.Oaep(Alg);

        byte[] parameters = new byte[message.SerializedSize + inScheme.SerializedSize + label.SerializedSize];
        var writer = new TpmWriter(parameters);
        message.WriteTo(ref writer);
        inScheme.WriteTo(ref writer);
        label.WriteTo(ref writer);

        return parameters;
    }

    /// <summary>Serializes a parameter area whose <c>message</c> declares one octet more than Table 194's <c>MAX_RSA_KEY_BYTES</c> bound.</summary>
    /// <returns>The parameter area's octets.</returns>
    private static byte[] SerializeOverBoundParameters()
    {
        const int OverBoundSize = Tpm2bPublicKeyRsa.MaxRsaKeyBytes + 1;
        TpmtRsaDecrypt inScheme = TpmtRsaDecrypt.Null;

        byte[] parameters = new byte[sizeof(ushort) + OverBoundSize + inScheme.SerializedSize + sizeof(ushort)];
        var writer = new TpmWriter(parameters);
        writer.WriteUInt16(OverBoundSize);
        writer.WriteBytes(new byte[OverBoundSize]);
        inScheme.WriteTo(ref writer);
        writer.WriteUInt16(0);

        return parameters;
    }

    /// <summary>
    /// Builds one <c>TPMS_AUTH_COMMAND</c> block over <paramref name="session"/>, its command HMAC computed on
    /// the cpHash <c>H(commandCode ‖ Name(keyHandle) ‖ parameters)</c> (TPM 2.0 Library Part 1, clause 15.7,
    /// equation 15).
    /// </summary>
    /// <param name="session">The session, whose caller nonce this rolls.</param>
    /// <param name="keyName">The Name term cpHash folds.</param>
    /// <param name="parameters">The parameter area the HMAC commits to.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The block's octets, without the authorizationSize field that precedes them.</returns>
    private async Task<byte[]> BuildSessionAuthAreaAsync(TpmSession session, byte[] keyName, byte[] parameters, BaseMemoryPool pool)
    {
        using DigestValue cpHash = await ComputeCpHashAsync(keyName, parameters, pool).ConfigureAwait(false);
        session.RollNonceCaller(pool);
        using Tpm2bAuth? hmac = await session.PrepareAuthHmacAsync(cpHash.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] block = new byte[session.GetAuthCommandSize()];
        var writer = new TpmWriter(block);
        session.WriteAuthCommand(ref writer, hmac);

        return block;
    }

    /// <summary>Computes cpHash for <c>TPM2_RSA_Encrypt()</c>: <c>H(commandCode ‖ Name(keyHandle) ‖ parameters)</c> (TPM 2.0 Library Part 1, clause 15.7, equation 15).</summary>
    /// <param name="keyName">The Name term.</param>
    /// <param name="parameters">The parameter area as it rides the wire.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The digest; the caller disposes it.</returns>
    private async Task<DigestValue> ComputeCpHashAsync(byte[] keyName, byte[] parameters, BaseMemoryPool pool)
    {
        byte[] cpHashInput = new byte[sizeof(uint) + keyName.Length + parameters.Length];
        var writer = new TpmWriter(cpHashInput);
        writer.WriteUInt32((uint)TpmCcConstants.TPM_CC_RSA_Encrypt);
        writer.WriteBytes(keyName);
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

    /// <summary>Frames a <c>TPM_ST_SESSIONS</c> <c>TPM2_RSA_Encrypt()</c> with ONE handle (<c>keyHandle</c>) — the handle, then the authorization block preceded by its size, then the parameters — and submits it straight to the simulator.</summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The key handle written into the handle area.</param>
    /// <param name="authArea">The authorization block.</param>
    /// <param name="parameters">The parameter area.</param>
    /// <returns>The response code, still carrying any session-index encoding.</returns>
    private async Task<TpmRcConstants> SubmitOneHandleAsync(TpmSimulator simulator, BaseMemoryPool pool, uint keyHandle, byte[] authArea, byte[] parameters)
    {
        byte[] command = new byte[TpmHeader.HeaderSize + sizeof(uint) + sizeof(uint) + authArea.Length + parameters.Length];
        var writer = new TpmWriter(command);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)command.Length, (uint)TpmCcConstants.TPM_CC_RSA_Encrypt);
        header.WriteTo(ref writer);
        writer.WriteUInt32(keyHandle);
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
    /// Frames a <c>TPM_ST_SESSIONS</c> <c>TPM2_RSA_Encrypt()</c> with ONE handle — the same wire shape as
    /// <see cref="SubmitOneHandleAsync"/> — but also returns the raw response octets alongside the code so an
    /// audit digest can be chained from them independently of the codec.
    /// </summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The key handle written into the handle area.</param>
    /// <param name="authArea">The authorization block.</param>
    /// <param name="parameters">The parameter area.</param>
    /// <returns>The response code, still carrying any session-index encoding, and the full raw response.</returns>
    private async Task<(TpmRcConstants Code, byte[] Response)> SubmitOneHandleForAuditAsync(TpmSimulator simulator, BaseMemoryPool pool, uint keyHandle, byte[] authArea, byte[] parameters)
    {
        byte[] command = new byte[TpmHeader.HeaderSize + sizeof(uint) + sizeof(uint) + authArea.Length + parameters.Length];
        var writer = new TpmWriter(command);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)command.Length, (uint)TpmCcConstants.TPM_CC_RSA_Encrypt);
        header.WriteTo(ref writer);
        writer.WriteUInt32(keyHandle);
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
    /// Reads one response-session entry out of a captured raw response's authorization area by index, disposing
    /// every entry read before it — the parsed <c>TPMS_AUTH_RESPONSE</c> a companion's own
    /// <see cref="TpmSessionBase.VerifyAndUpdateAsync"/> call needs to verify the response HMAC and adopt the
    /// freshly rolled nonceTPM.
    /// </summary>
    /// <param name="responseBytes">The raw response octets.</param>
    /// <param name="outHandleCount">The number of output handles preceding the parameter area.</param>
    /// <param name="sessionIndex">The zero-based slot index to read.</param>
    /// <param name="pool">The memory pool the entry's owned carriers are allocated from.</param>
    /// <returns>The requested entry; the caller disposes it.</returns>
    private static TpmsAuthResponse ReadResponseSessionEntry(byte[] responseBytes, int outHandleCount, int sessionIndex, BaseMemoryPool pool)
    {
        var reader = new TpmReader(responseBytes);
        _ = TpmHeader.Parse(ref reader);
        for(int i = 0; i < outHandleCount; i++)
        {
            _ = reader.ReadUInt32();
        }

        uint parameterSize = reader.ReadUInt32();
        _ = reader.ReadBytes((int)parameterSize);

        for(int i = 0; i < sessionIndex; i++)
        {
            using TpmsAuthResponse skip = TpmsAuthResponse.Parse(ref reader, pool);
        }

        return TpmsAuthResponse.Parse(ref reader, pool);
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

    /// <summary>
    /// Frames a genuine encrypt-claiming HMAC authorization block whose slot handle field is then overwritten
    /// with <paramref name="slotHandle"/>, so only the handle under test differs from a real session's.
    /// </summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="loaded">The key addressed on the wire.</param>
    /// <param name="slotHandle">The wire-only substitute for the slot's session handle field.</param>
    /// <returns>The response code, still carrying any session-index encoding.</returns>
    private async Task<TpmRcConstants> SubmitOverPatchedSlotAsync(TpmSimulator simulator, TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, LoadedRsaKey loaded, uint slotHandle)
    {
        byte[] parameters = SerializeParameters(pool);
        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(tpm, registry, pool, TpmtSymDef.Xor(Alg)).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;
                byte[] authArea = await BuildSessionAuthAreaAsync(session, loaded.Name, parameters, pool).ConfigureAwait(false);
                BinaryPrimitives.WriteUInt32BigEndian(authArea.AsSpan(0, sizeof(uint)), slotHandle);

                return await SubmitOneHandleAsync(simulator, pool, loaded.Handle, authArea, parameters).ConfigureAwait(false);
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Frames a public-only-key encrypt over a live, owner-bound HMAC session negotiating
    /// <paramref name="symmetric"/> and claiming <paramref name="attributes"/>, and asserts the answer the
    /// session table earns.
    /// </summary>
    /// <param name="name">The per-test simulator identifier.</param>
    /// <param name="attributes">The <c>TPMA_SESSION</c> octet the slot carries.</param>
    /// <param name="symmetric">The symmetric definition the session negotiates.</param>
    /// <param name="expected">The expected response code.</param>
    /// <param name="rule">The rule under proof, quoted into the assertion message.</param>
    /// <param name="parameters">The parameter area to submit, or <see langword="null"/> for the standard OAEP-SHA-256, empty-label area.</param>
    private async Task AssertSessionClaimAnswerAsync(string name, TpmaSession attributes, TpmtSymDef symmetric, TpmRcConstants expected, string rule, byte[]? parameters = null)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(name, pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using RsaKeyMaterial key = RsaKeyMaterial.Generate();
        LoadedRsaKey loaded = await LoadPublicOnlyRsaKeyAsync(tpm, registry, pool, key).ConfigureAwait(false);

        parameters ??= SerializeParameters(pool);
        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(tpm, registry, pool, symmetric).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = attributes;
                byte[] authArea = await BuildSessionAuthAreaAsync(session, loaded.Name, parameters, pool).ConfigureAwait(false);
                TpmRcConstants code = await SubmitOneHandleAsync(simulator, pool, loaded.Handle, authArea, parameters).ConfigureAwait(false);
                Assert.AreEqual(expected, code, $"TPM2_RSA_Encrypt() over a session claiming '{attributes}': {rule}.");
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>The symmetric definition a parameter-encryption session negotiates.</summary>
    /// <param name="isAesCfb">Whether to negotiate AES-128-CFB (else the XOR obfuscation).</param>
    /// <returns>The symmetric definition.</returns>
    private static TpmtSymDef Symmetric(bool isAesCfb) =>
        isAesCfb ? TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB) : TpmtSymDef.Xor(Alg);

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
        using var publicInfo = new TpmsNvPublic(DaProtectedBindIndexHandle, Alg, DaProtectedIndexAttributes, Tpm2bDigest.Empty, BindIndexDataSize);
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

    /// <summary>
    /// "A TPM is required to perform the handle area validation before the authorization checks because an
    /// authorization cannot be performed unless the authorization values and attributes for the referenced
    /// entity are known by the TPM" — an unresolved, well-typed transient <c>keyHandle</c> is refused
    /// <c>TPM_RC_REFERENCE_H0</c> (clause 5.4, step 2.1) ahead of a genuine, loaded encrypt companion at the sole
    /// slot, which is never reached at all: its nonceTPM stays usable for a later, well-typed call over the same
    /// session.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3,
    /// clause 5.4, step 2.1; clause 5.9</see>.
    /// </summary>
    [TestMethod]
    public async Task RsaEncryptOverAnEncryptSlotWithAnUnresolvedHandleAnswersReferenceH0AheadOfTheSession()
    {
        const uint UnknownTransientHandle = 0x8000_9999u;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaEncryptOverAnEncryptSlotWithAnUnresolvedHandleAnswersReferenceH0AheadOfTheSession), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using RsaKeyMaterial key = RsaKeyMaterial.Generate();
        LoadedRsaKey loaded = await LoadPublicOnlyRsaKeyAsync(tpm, registry, pool, key).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(tpm, registry, pool, TpmtSymDef.Xor(Alg)).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                //Resolution fails after the wire-framed authorization area is validated but before the
                //companion's own command HMAC is ever checked, so a genuinely framed area is required here (an
                //empty area is refused TPM_RC_AUTHSIZE at the framing step, ahead of resolution) — its Name term
                //is irrelevant, since the HMAC comparison it would feed is never reached.
                byte[] parameters = SerializeParameters(pool);
                byte[] authArea = await BuildSessionAuthAreaAsync(session, [], parameters, pool).ConfigureAwait(false);
                (TpmRcConstants code, byte[] response) = await SubmitOneHandleForAuditAsync(simulator, pool, UnknownTransientHandle, authArea, parameters).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_REFERENCE_H0, code, "An unresolved transient keyHandle answers TPM_RC_REFERENCE_H0 ahead of the companion's own HMAC verification.");

                var responseReader = new TpmReader(response);
                TpmHeader responseHeader = TpmHeader.Parse(ref responseReader);
                Assert.AreEqual((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, responseHeader.Tag, "A failed command frames TPM_ST_NO_SESSIONS regardless of the request's own tag.");
                Assert.HasCount(10, response, "A failed command's response is exactly the 10-octet header (Part 3, clause 5.9).");

                byte[] followUpAuthArea = await BuildSessionAuthAreaAsync(session, loaded.Name, parameters, pool).ConfigureAwait(false);
                TpmRcConstants followUpCode = await SubmitOneHandleAsync(simulator, pool, loaded.Handle, followUpAuthArea, parameters).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, followUpCode, "The session's nonceTPM was never touched by the resolution refusal, so a genuine, well-typed follow-up over it still verifies.");
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A companion whose command HMAC does not verify is refused at its own index BEFORE
    /// <c>TPM2_RSA_Encrypt()</c>'s own sequence-handle resolution is ever reached: the session-encoded
    /// <c>TPM_RC_BAD_AUTH</c> this test asserts — not the inner's bare <c>TPM_RC_KEY</c> — is the discriminating
    /// proof that the authorization area is judged first. The session's nonceTPM is left untouched by the
    /// refusal.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3,
    /// clause 5.5; clause 5.9; clause 14.2</see>.
    /// </summary>
    [TestMethod]
    public async Task RsaEncryptOverASequenceHandleWithAWrongCompanionHmacReturnsBadAuthAndLeavesTheSessionUsable()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(RsaEncryptOverASequenceHandleWithAWrongCompanionHmacReturnsBadAuthAndLeavesTheSessionUsable), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry()
            .Register(TpmCcConstants.TPM_CC_HashSequenceStart, TpmResponseCodec.HashSequenceStart);
        using RsaKeyMaterial key = RsaKeyMaterial.Generate();
        LoadedRsaKey loaded = await LoadPublicOnlyRsaKeyAsync(tpm, registry, pool, key).ConfigureAwait(false);

        using HashSequenceStartInput openInput = HashSequenceStartInput.CreateFromPassword(string.Empty, TpmiAlgHash.FromValue(Alg), pool);
        TpmResult<HashSequenceStartResponse> openResult = await TpmCommandExecutor.ExecuteAsync<HashSequenceStartResponse>(
            tpm, openInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(openResult.IsSuccess, $"TPM2_HashSequenceStart() must succeed: '{openResult.ResponseCode}'.");
        uint sequenceHandle = openResult.Value.SequenceHandle.Value;

        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(tpm, registry, pool, TpmtSymDef.Xor(Alg)).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                byte[] parameters = SerializeParameters(pool);
                byte[] authArea = await BuildSessionAuthAreaAsync(session, [], parameters, pool).ConfigureAwait(false);
                authArea[^1] ^= 0xFF;

                (TpmRcConstants code, byte[] response) = await SubmitOneHandleForAuditAsync(simulator, pool, sequenceHandle, authArea, parameters).ConfigureAwait(false);
                Assert.AreEqual(
                    HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), code,
                    "The companion's own HMAC is refused before the sequence handle is ever resolved — not the inner's TPM_RC_KEY.");

                var responseReader = new TpmReader(response);
                TpmHeader responseHeader = TpmHeader.Parse(ref responseReader);
                Assert.AreEqual((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, responseHeader.Tag, "A failed command frames TPM_ST_NO_SESSIONS regardless of the request's own tag.");
                Assert.HasCount(10, response, "A failed command's response is exactly the 10-octet header (Part 3, clause 5.9).");

                byte[] followUpAuthArea = await BuildSessionAuthAreaAsync(session, loaded.Name, parameters, pool).ConfigureAwait(false);
                TpmRcConstants followUpCode = await SubmitOneHandleAsync(simulator, pool, loaded.Handle, followUpAuthArea, parameters).ConfigureAwait(false);
                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, followUpCode, "The session's nonceTPM was never touched by the refusal, so a genuine, well-typed follow-up over it still verifies.");
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }
}
