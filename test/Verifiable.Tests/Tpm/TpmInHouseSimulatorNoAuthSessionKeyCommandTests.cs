using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives the eight commands whose Part 3 tag cell admits an audit, decrypt or encrypt companion beside a key
/// or hierarchy operation — six of them over a no-authorization handle, <c>TPM2_Hash()</c> and
/// <c>TPM2_HashSequenceStart()</c> with no handle area at all — <c>TPM2_Hash()</c>,
/// <c>TPM2_HashSequenceStart()</c>, <c>TPM2_SignSequenceStart()</c>, <c>TPM2_VerifySequenceStart()</c>,
/// <c>TPM2_VerifySignature()</c>, <c>TPM2_VerifyDigestSignature()</c>, <c>TPM2_Encapsulate()</c> and
/// <c>TPM2_MakeCredential()</c> — over multi-slot and less-common authorization areas, against the in-house
/// behavioural <see cref="TpmSimulator"/>, entirely in-process with no external assets. It deepens
/// <see cref="TpmInHouseSimulatorNoAuthSessionTests"/>'s single-companion coverage of the same eight commands: the
/// hand-framed three-slot and dual-claim shapes on <c>TPM2_Hash()</c> (TPM 2.0 Library Part 3, clause 5.5, step
/// 4.4.1), a companion's own digest chain with a handle's Name folded into cpHash, the two remaining decrypt
/// companions no sibling test exercises, the handle judged before the authorization area (TPM 2.0 Library Part 3,
/// clause 5.4 before clause 5.5), and the <see cref="MeteredHousePool"/> balance across a three-entry success, an
/// encrypt success, a companion refusal and an inner refusal. Every audit digest a test asserts is chained by the
/// test itself from the command's own wire octets — cpHash per
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1,
/// clause 15.7</see>, equation 15, rpHash per clause 15.8, equation 16, and the fold per clause 17.1, equation 30 —
/// never trusted from any codec's own parse.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorNoAuthSessionKeyCommandTests
{
    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The session hash algorithm every session in this class negotiates.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The real (non-NULL) symmetric definition a decrypt or encrypt companion negotiates in this class.</summary>
    private static TpmtSymDef SessionSymmetric { get; } = TpmtSymDef.Xor(TpmAlgIdConstants.TPM_ALG_SHA256);

    /// <summary>A persistent handle assigned to a genuine ECC signing key, from this class's own range.</summary>
    private const uint PersistentSigningKeyHandle = 0x8100_0315;

    /// <summary>A persistent handle assigned to a genuine ECC KEM key, from this class's own range.</summary>
    private const uint PersistentKemKeyHandle = 0x8100_0318;

    /// <summary>
    /// A throwaway instance of the sibling class whose <c>internal</c> single-handle hand-framing and digest
    /// helpers this class reuses rather than re-minting — its own <see cref="TestContext"/> carries this class's
    /// cancellation token to every call.
    /// </summary>
    private TpmInHouseSimulatorNoAuthSessionTests Shared => new() { TestContext = TestContext };

    /// <summary>
    /// <c>TPM2_Hash()</c> over three companion slots — audit at index 0, decrypt (a real symmetric definition) at
    /// index 1, encrypt (another real symmetric definition) at index 2 — succeeds with a
    /// <c>TPM_ST_SESSIONS</c>-tagged response carrying exactly three response-session entries: the recovered
    /// plaintext <c>data</c> hashes to the decrypted <c>outHash</c>, and the audit session's digest extends over
    /// the CIPHERTEXT <c>data</c> and the ENCRYPTED <c>outHash</c> — "Parameters in commands are encrypted before
    /// any cpHash is computed. Parameters in responses are encrypted before any rpHash is computed" — proving Part
    /// 1, clause 15.6.1's "at least one but no more than three" authorization blocks admits every companion kind
    /// on the SAME call, beyond the one-companion-at-a-time shape the sibling class's own tests exercise.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3,
    /// clause 15.4, Table 69; Part 1, clauses 15.6.1 and 18</see>.
    /// </summary>
    [TestMethod]
    public async Task HashOverAnAuditDecryptAndEncryptSlotSucceedsWithThreeResponseEntriesAndTheAuditDigestChainedOverTheCiphertext()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_GetSessionAuditDigest, TpmResponseCodec.GetSessionAuditDigest);

        byte[] data = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60];
        byte[] expectedHash = SHA256.HashData(data);
        TpmiAlgHash hashAlg = TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256);

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        (uint decryptHandle, TpmSession decryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        (uint encryptHandle, TpmSession encryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        try
        {
            using(auditSession)
            using(decryptSession)
            using(encryptSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                decryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;
                encryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                using HashInput hashInput = HashInput.Create(data, hashAlg, TpmiRhHierarchy.Null, pool);
                byte[] parameters = SerializeParameters(hashInput, pool);
                byte[] decryptBlock = await BuildDecryptCompanionBlockAsync(
                    decryptSession, TpmCcConstants.TPM_CC_Hash, parameters, firstParameterOffset: sizeof(ushort), firstParameterLength: data.Length, pool).ConfigureAwait(false);

                byte[] auditBlock = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_Hash, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                byte[] encryptBlock = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(encryptSession, TpmCcConstants.TPM_CC_Hash, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                byte[] authArea = [.. auditBlock, .. decryptBlock, .. encryptBlock];

                (TpmRcConstants code, byte[] response) = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleForAuditAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_Hash, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "Audit, decrypt and encrypt together over TPM2_Hash() must succeed.");
                Assert.AreEqual((ushort)TpmStConstants.TPM_ST_SESSIONS, TpmInHouseSimulatorNoAuthSessionTests.ReadResponseTag(response), "A successful over-session response is TPM_ST_SESSIONS-tagged.");
                Assert.HasCount(3, TpmInHouseSimulatorNoAuthSessionTests.ReadResponseSessionEntries(response, outHandleCount: 0), "All three companion slots must frame their own response-session entry.");

                byte[] cipherResponseParameters = TpmInHouseSimulatorZeroHandleSessionTests.ReadResponseParameters(response, outHandleCount: 0);
                byte[] rpHash = await TpmInHouseSimulatorZeroHandleSessionTests.ComputeRpHashAsync(TpmCcConstants.TPM_CC_Hash, cipherResponseParameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                byte[] cpHash = await TpmInHouseSimulatorZeroHandleSessionTests.ComputeZeroHandleCpHashAsync(TpmCcConstants.TPM_CC_Hash, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                byte[] expectedDigest = await TpmInHouseSimulatorZeroHandleSessionTests.ExtendAuditDigestAsync(priorDigest: null, cpHash, rpHash, pool, TestContext.CancellationToken).ConfigureAwait(false);

                byte[] plaintextOutHashArea = await DecryptResponseFirstParameterAsync(encryptSession, response, outHandleCount: 0, sessionIndex: 2, TpmCcConstants.TPM_CC_Hash, pool).ConfigureAwait(false);
                ushort outHashLength = BinaryPrimitives.ReadUInt16BigEndian(plaintextOutHashArea);
                Assert.IsTrue(
                    expectedHash.AsSpan().SequenceEqual(plaintextOutHashArea.AsSpan(sizeof(ushort), outHashLength)),
                    "The decrypted outHash must equal SHA-256 of the plaintext data recovered from the decrypt slot's own ciphertext.");

                using GetSessionAuditDigestInput auditDigestInput = GetSessionAuditDigestInput.ForNullSigner(TpmiShHmac.FromValue(auditHandle), ReadOnlySpan<byte>.Empty, pool);
                using TpmPasswordSession endorsementForDigest = TpmPasswordSession.CreateEmpty(pool);
                using TpmPasswordSession nullSignerSlot = TpmPasswordSession.CreateEmpty(pool);
                TpmResult<GetSessionAuditDigestResponse> digestResult = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                    device, auditDigestInput, [endorsementForDigest, nullSignerSlot], handleNames: null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(digestResult.IsSuccess, $"TPM2_GetSessionAuditDigest() must succeed: '{digestResult.ResponseCode}'.");
                using GetSessionAuditDigestResponse auditDigestResponse = digestResult.Value;

                Assert.IsTrue(
                    expectedDigest.AsSpan().SequenceEqual(auditDigestResponse.SessionAudit.SessionDigest.AsReadOnlySpan()),
                    "The audit digest must equal H(0…0 ‖ cpHash ‖ rpHash) with cpHash chained over the CIPHERTEXT data and rpHash chained over the ENCRYPTED outHash (TPM 2.0 Library Part 1, clause 18).");

                byte auditedAttributes = TpmInHouseSimulatorZeroHandleSessionTests.ReadResponseSessionAttributes(response, outHandleCount: 0, sessionIndex: 0);
                Assert.AreEqual(
                    (byte)(TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT | TpmaSession.AUDIT_EXCLUSIVE), auditedAttributes,
                    "The audit slot's response echoes audit SET and auditExclusive SET on its first use.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, decryptHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, encryptHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_Hash()</c> over an audit companion at index 0 and ONE companion at index 1 claiming BOTH
    /// <c>decrypt</c> and <c>encrypt</c> succeeds with exactly two response-session entries — "A session used for
    /// decrypting a command parameter can also be used for encrypting a response parameter" — the decrypted
    /// <c>outHash</c> equals SHA-256 of the plaintext <c>data</c> the SAME session recovered.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3,
    /// clause 5.5, step 4.4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task HashOverAnAuditSlotAndASingleSessionClaimingBothDecryptAndEncryptSucceedsWithTwoResponseEntries()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        byte[] data = [0x01, 0x02, 0x03];
        byte[] expectedHash = SHA256.HashData(data);
        TpmiAlgHash hashAlg = TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256);

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        (uint dualHandle, TpmSession dualSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        try
        {
            using(auditSession)
            using(dualSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                dualSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT | TpmaSession.ENCRYPT;

                using HashInput hashInput = HashInput.Create(data, hashAlg, TpmiRhHierarchy.Null, pool);
                byte[] parameters = SerializeParameters(hashInput, pool);
                byte[] dualBlock = await BuildDecryptCompanionBlockAsync(
                    dualSession, TpmCcConstants.TPM_CC_Hash, parameters, firstParameterOffset: sizeof(ushort), firstParameterLength: data.Length, pool).ConfigureAwait(false);
                byte[] auditBlock = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_Hash, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                byte[] authArea = [.. auditBlock, .. dualBlock];

                (TpmRcConstants code, byte[] response) = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleForAuditAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_Hash, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "A single session claiming both decrypt and encrypt over TPM2_Hash() must succeed.");
                Assert.HasCount(2, TpmInHouseSimulatorNoAuthSessionTests.ReadResponseSessionEntries(response, outHandleCount: 0), "Two companion slots must frame their own response-session entry.");

                byte[] plaintextOutHashArea = await DecryptResponseFirstParameterAsync(dualSession, response, outHandleCount: 0, sessionIndex: 1, TpmCcConstants.TPM_CC_Hash, pool).ConfigureAwait(false);
                ushort outHashLength = BinaryPrimitives.ReadUInt16BigEndian(plaintextOutHashArea);
                Assert.IsTrue(
                    expectedHash.AsSpan().SequenceEqual(plaintextOutHashArea.AsSpan(sizeof(ushort), outHashLength)),
                    "The SAME session's decrypted outHash must equal SHA-256 of the plaintext data it also recovered.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, dualHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "If the maximum allowed number of sessions have been unmarshaled and fewer octets than indicated in
    /// authorizationSize were unmarshaled... the TPM shall return TPM_RC_AUTHSIZE" — a fourth well-formed block
    /// over <c>TPM2_Hash()</c> is refused bare, before any slot's HMAC is judged.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3,
    /// clause 5.5, step 4.3; Part 1, clause 15.6.1</see>.
    /// </summary>
    [TestMethod]
    public async Task HashOverAFourBlockAreaReturnsBareAuthsize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        using HashInput fourBlockInput = HashInput.Create([0x01], TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256), TpmiRhHierarchy.Null, pool);
        byte[] parameters = SerializeParameters(fourBlockInput, pool);

        (uint sessionHandle, TpmSession session) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                var authArea = new List<byte>();
                for(int i = 0; i < 4; i++)
                {
                    authArea.AddRange(await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(session, TpmCcConstants.TPM_CC_Hash, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false));
                }

                TpmRcConstants code = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_Hash, authArea.ToArray(), parameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_AUTHSIZE, code, "A fourth authorization block beyond the three-slot maximum is bare TPM_RC_AUTHSIZE.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A LOADED policy session at <c>TPM2_Hash()</c>'s sole authorization slot, claiming <c>audit</c>, is refused
    /// session-encoded <c>TPM_RC_ATTRIBUTES</c> at its own index: "use of audit is restricted to HMAC sessions" —
    /// a policy session may ride a decrypt or encrypt companion slot, but never an audit one, which is checked
    /// distinctly from — and ahead of — the generic loaded-policy-session type gate a companion claiming no audit
    /// would otherwise reach.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1,
    /// clause 15.6.4; Part 3, clause 5.5, step 4</see>.
    /// </summary>
    [TestMethod]
    public async Task HashOverAPolicySessionClaimingAuditAtIndexZeroReturnsSessionEncodedAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        using HashInput policyGateInput = HashInput.Create([0x02], TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256), TpmiRhHierarchy.Null, pool);
        byte[] parameters = SerializeParameters(policyGateInput, pool);

        TpmResult<StartAuthSessionResponse> policyStartResult = await device.StartPolicySessionAsync(SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(policyStartResult.IsSuccess, $"StartAuthSession (policy) failed: '{policyStartResult.ResponseCode}'.");
        using StartAuthSessionResponse policyStarted = policyStartResult.Value;
        uint policySessionHandle = policyStarted.SessionHandle.Value;

        (uint sessionHandle, TpmSession session) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                byte[] authArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(session, TpmCcConstants.TPM_CC_Hash, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                BinaryPrimitives.WriteUInt32BigEndian(authArea.AsSpan(0, sizeof(uint)), policySessionHandle);

                TpmRcConstants code = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_Hash, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmInHouseSimulatorZeroHandleSessionTests.SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0), code,
                    "TPM2_Hash() over a genuine POLICY session claiming audit at its sole slot must be refused session-encoded TPM_RC_ATTRIBUTES.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, policySessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A LOADED policy session at <c>TPM2_Hash()</c>'s sole authorization slot, claiming <c>decrypt</c> alone, is
    /// admitted exactly like an HMAC companion — TPM 2.0 Library Part 1, clause 15.6.1, Table 12, footnote [2]:
    /// "a policy authorization session can also be used for encryption and decryption." The command's own
    /// <c>data</c> parameter, encrypted here under the policy session's own AES-CFB keystream (Part 1, clause
    /// 18.3, equation 32; the session's key is the Empty Buffer, since it is neither bound nor salted, Part 3,
    /// clause 11.1.1), recovers to the correct plaintext by the command succeeding: the returned <c>outHash</c>
    /// equals SHA-256 of the plaintext the simulator decrypted before hashing, never the ciphertext, proving the
    /// policy companion's decrypt claim was genuinely honored.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 15.6.1, Table 12, footnote [2]; clause 18.3</see>.
    /// </summary>
    [TestMethod]
    public async Task HashOverAPolicyDecryptCompanionRecoversThePlaintextByTheCommandSucceeding()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        byte[] data = [0x71, 0x72, 0x73, 0x74, 0x75, 0x76];
        byte[] expectedHash = SHA256.HashData(data);
        TpmiAlgHash hashAlg = TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256);
        TpmtSymDef aesCfb = TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB);

        (uint policyHandle, TpmSession policySession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(
            device, registry, pool, TestContext.CancellationToken, aesCfb, TpmSeConstants.TPM_SE_POLICY).ConfigureAwait(false);
        try
        {
            using(policySession)
            {
                policySession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                using HashInput hashInput = HashInput.Create(data, hashAlg, TpmiRhHierarchy.Null, pool);
                byte[] parameters = SerializeParameters(hashInput, pool);
                byte[] authArea = await BuildDecryptCompanionBlockAsync(
                    policySession, TpmCcConstants.TPM_CC_Hash, parameters, firstParameterOffset: sizeof(ushort), firstParameterLength: data.Length, pool).ConfigureAwait(false);

                (TpmRcConstants code, byte[] response) = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleForAuditAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_Hash, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, $"TPM2_Hash() over a policy decrypt companion must succeed: '{code}'.");

                //No slot claims encrypt here, so the response itself is plaintext — outHash is read directly.
                byte[] responseParameters = TpmInHouseSimulatorZeroHandleSessionTests.ReadResponseParameters(response, outHandleCount: 0);
                ushort outHashLength = BinaryPrimitives.ReadUInt16BigEndian(responseParameters);
                Assert.IsTrue(
                    expectedHash.AsSpan().SequenceEqual(responseParameters.AsSpan(sizeof(ushort), outHashLength)),
                    "outHash must equal SHA-256 of the plaintext data the policy companion's decrypt claim recovered.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, policyHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A TRIAL policy session (<c>TPM_SE_TRIAL</c>) at <c>TPM2_Hash()</c>'s sole companion slot, claiming
    /// <c>decrypt</c>, is refused session-encoded <c>TPM_RC_ATTRIBUTES</c> before the command's own <c>data</c>
    /// parameter is ever decrypted: "a trial session is not allowed to be used for authorization. … the
    /// sessionKey of the session will never be used" (TPM 2.0 Library Part 1, clause 16.6.9) — the same
    /// posture the reference implementation's session parser applies at every slot, trial or not. Unlike
    /// <see cref="HashOverAPolicyDecryptCompanionRecoversThePlaintextByTheCommandSucceeding"/>'s genuine POLICY
    /// session, this one never reaches the decrypt step at all.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1,
    /// clause 16.6.9; Part 3, clause 11.1.1</see>.
    /// </summary>
    [TestMethod]
    public async Task HashOverATrialPolicyCompanionClaimingDecryptReturnsSessionEncodedAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        byte[] data = [0x81, 0x82, 0x83, 0x84, 0x85, 0x86];
        TpmiAlgHash hashAlg = TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256);
        TpmtSymDef aesCfb = TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB);

        (uint trialHandle, TpmSession trialSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(
            device, registry, pool, TestContext.CancellationToken, aesCfb, TpmSeConstants.TPM_SE_TRIAL).ConfigureAwait(false);
        try
        {
            using(trialSession)
            {
                trialSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                using HashInput hashInput = HashInput.Create(data, hashAlg, TpmiRhHierarchy.Null, pool);
                byte[] parameters = SerializeParameters(hashInput, pool);
                byte[] authArea = await BuildDecryptCompanionBlockAsync(
                    trialSession, TpmCcConstants.TPM_CC_Hash, parameters, firstParameterOffset: sizeof(ushort), firstParameterLength: data.Length, pool).ConfigureAwait(false);

                TpmRcConstants code = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_Hash, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmInHouseSimulatorZeroHandleSessionTests.SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0), code,
                    "A TRIAL session claiming decrypt at a companion slot is refused session-encoded TPM_RC_ATTRIBUTES, never reaching the decrypt step.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, trialHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The <see cref="MeteredHousePool"/> balance across a policy decrypt-companion <c>TPM2_Hash()</c> success and
    /// a policy-companion command-HMAC refusal — every rented carrier the policy path touches (the resolved
    /// <see cref="PolicySessionState"/>'s own key/nonce borrows, the verification queue's entry, the framed
    /// response) comes back on both the success and the refusal.
    /// </summary>
    [TestMethod]
    public async Task PolicyCompanionPathsReturnTheirCarriersAcrossADecryptSuccessAndABadAuthRefusal()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;

        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        long baseline = trackingPool.OutstandingCount;
        TpmiAlgHash hashAlg = TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256);

        //A policy decrypt-companion TPM2_Hash() success.
        {
            byte[] data = [0x31, 0x32, 0x33];
            byte[] parameters;
            using(HashInput hashInput = HashInput.Create(data, hashAlg, TpmiRhHierarchy.Null, pool))
            {
                parameters = SerializeParameters(hashInput, pool);
            }

            (uint policyHandle, TpmSession policySession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(
                device, registry, pool, TestContext.CancellationToken, SessionSymmetric, TpmSeConstants.TPM_SE_POLICY).ConfigureAwait(false);
            try
            {
                using(policySession)
                {
                    policySession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;
                    byte[] authArea = await BuildDecryptCompanionBlockAsync(
                        policySession, TpmCcConstants.TPM_CC_Hash, parameters, firstParameterOffset: sizeof(ushort), firstParameterLength: data.Length, pool).ConfigureAwait(false);

                    TpmRcConstants code = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                        simulator, pool, TpmCcConstants.TPM_CC_Hash, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "The policy decrypt-companion success must actually succeed for its balance to prove anything.");
                }
            }
            finally
            {
                await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, policyHandle).ConfigureAwait(false);
            }

            Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The policy decrypt-companion success must return every carrier it rented.");
        }

        //A policy-companion command-HMAC refusal.
        {
            byte[] data = [0x41];
            byte[] parameters;
            using(HashInput hashInput = HashInput.Create(data, hashAlg, TpmiRhHierarchy.Null, pool))
            {
                parameters = SerializeParameters(hashInput, pool);
            }

            (uint policyHandle, TpmSession policySession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(
                device, registry, pool, TestContext.CancellationToken, SessionSymmetric, TpmSeConstants.TPM_SE_POLICY).ConfigureAwait(false);
            try
            {
                using(policySession)
                {
                    policySession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;
                    byte[] authArea = await BuildDecryptCompanionBlockAsync(
                        policySession, TpmCcConstants.TPM_CC_Hash, parameters, firstParameterOffset: sizeof(ushort), firstParameterLength: data.Length, pool).ConfigureAwait(false);
                    authArea[^1] ^= 0xFF;

                    TpmRcConstants code = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                        simulator, pool, TpmCcConstants.TPM_CC_Hash, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.AreEqual(
                        TpmInHouseSimulatorZeroHandleSessionTests.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), code,
                        "The policy-companion HMAC refusal must actually refuse for its balance to prove anything.");
                }
            }
            finally
            {
                await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, policyHandle).ConfigureAwait(false);
            }

            Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The policy-companion BAD_AUTH refusal must return every carrier it rented.");
        }
    }

    /// <summary>
    /// <c>TPM2_Hash()</c> over an audit companion at index 0 and ONE POLICY session at index 1 claiming BOTH
    /// <c>decrypt</c> and <c>encrypt</c> succeeds with exactly two response-session entries — TPM 2.0 Library
    /// Part 1, Table 12, footnote [2]: "a policy authorization session can also be used for encryption and
    /// decryption" — the decrypted <c>outHash</c> equals SHA-256 of the plaintext <c>data</c> the SAME policy
    /// companion recovered, proving a policy session may claim both directions on one slot exactly like an HMAC
    /// companion (TPM 2.0 Library Part 3, clause 5.5, step 4.4.1).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3,
    /// clause 15.4, Table 69; Part 1, clause 15.6.1, Table 12, footnote [2], and clause 18</see>.
    /// </summary>
    [TestMethod]
    public async Task HashOverAnAuditSlotAndASinglePolicySessionClaimingBothDecryptAndEncryptSucceedsWithTwoResponseEntries()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        byte[] data = [0x04, 0x05, 0x06];
        byte[] expectedHash = SHA256.HashData(data);
        TpmiAlgHash hashAlg = TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256);

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        (uint dualHandle, TpmSession dualSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(
            device, registry, pool, TestContext.CancellationToken, SessionSymmetric, TpmSeConstants.TPM_SE_POLICY).ConfigureAwait(false);
        try
        {
            using(auditSession)
            using(dualSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                dualSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT | TpmaSession.ENCRYPT;

                using HashInput hashInput = HashInput.Create(data, hashAlg, TpmiRhHierarchy.Null, pool);
                byte[] parameters = SerializeParameters(hashInput, pool);
                byte[] dualBlock = await BuildDecryptCompanionBlockAsync(
                    dualSession, TpmCcConstants.TPM_CC_Hash, parameters, firstParameterOffset: sizeof(ushort), firstParameterLength: data.Length, pool).ConfigureAwait(false);
                byte[] auditBlock = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_Hash, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                byte[] authArea = [.. auditBlock, .. dualBlock];

                (TpmRcConstants code, byte[] response) = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleForAuditAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_Hash, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "A single POLICY session claiming both decrypt and encrypt over TPM2_Hash() must succeed.");
                Assert.HasCount(2, TpmInHouseSimulatorNoAuthSessionTests.ReadResponseSessionEntries(response, outHandleCount: 0), "Two companion slots must frame their own response-session entry.");

                byte[] plaintextOutHashArea = await DecryptResponseFirstParameterAsync(dualSession, response, outHandleCount: 0, sessionIndex: 1, TpmCcConstants.TPM_CC_Hash, pool).ConfigureAwait(false);
                ushort outHashLength = BinaryPrimitives.ReadUInt16BigEndian(plaintextOutHashArea);
                Assert.IsTrue(
                    expectedHash.AsSpan().SequenceEqual(plaintextOutHashArea.AsSpan(sizeof(ushort), outHashLength)),
                    "The SAME policy session's decrypted outHash must equal SHA-256 of the plaintext data it also recovered.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, dualHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_Hash()</c> over an audit-only companion, with <c>hierarchy</c> carrying a value outside
    /// <c>TPMI_RH_HIERARCHY</c>'s own table, answers the inner's own <c>TPM_RC_VALUE</c>, parameter-encoded to the same index — judged only AFTER
    /// the audit companion verifies, since the authorization area is judged (clause 5.5) before parameter decoding
    /// (clause 5.8) — framed <c>TPM_ST_NO_SESSIONS</c> in exactly 10 octets; the session's nonceTPM is left untouched, so
    /// a genuine follow-up command over it still verifies.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2,
    /// clause 9.13, Table 59; Part 3, clauses 5.5 and 5.9</see>.
    /// </summary>
    [TestMethod]
    public async Task HashWithAHierarchyOutsideTableFiftyNineAnswersTheInnersParameterEncodedValueAfterTheAuditCompanionVerifies()
    {
        const uint OutOfTableHierarchy = 0x0000_0010;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        byte[] data = [0x0A, 0x0B];
        byte[] parameters = new byte[sizeof(ushort) + data.Length + sizeof(ushort) + sizeof(uint)];
        var writer = new TpmWriter(parameters);
        writer.WriteUInt16((ushort)data.Length);
        writer.WriteBytes(data);
        writer.WriteUInt16((ushort)TpmAlgIdConstants.TPM_ALG_SHA256);
        writer.WriteUInt32(OutOfTableHierarchy);

        (uint sessionHandle, TpmSession session) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                byte[] authArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(session, TpmCcConstants.TPM_CC_Hash, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);

                (TpmRcConstants code, byte[] response) = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleForAuditAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_Hash, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 2), code, "hierarchy is TPM2_Hash()'s third parameter (Table 69, index 2); a value outside TPMI_RH_HIERARCHY's own table is the inner's own parameter-encoded TPM_RC_VALUE, judged only after the audit companion verifies.");
                Assert.AreEqual((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, TpmInHouseSimulatorNoAuthSessionTests.ReadResponseTag(response), "A failed command frames TPM_ST_NO_SESSIONS regardless of the request's own tag.");
                Assert.HasCount(10, response, "A failed command's response is exactly the 10-octet header (Part 3, clause 5.9).");

                byte[] followUpParameters = TpmInHouseSimulatorZeroHandleSessionTests.ParameterAreaFor(TpmCcConstants.TPM_CC_TestParms, pool);
                byte[] followUpAuthArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(session, TpmCcConstants.TPM_CC_TestParms, followUpParameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                TpmRcConstants followUpCode = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_TestParms, followUpAuthArea, followUpParameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, followUpCode, "The session's nonceTPM was left untouched by the refusal, so a genuine follow-up command over it still verifies.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_HashSequenceStart()</c> over an audit-only companion chains its digest to
    /// <c>H(0…0 ‖ cpHash ‖ rpHash)</c> with rpHash computed over the EMPTY parameter area that follows the
    /// response's own handle — "The contents of the handles area of the response are not included in the rpHash"
    /// — read back through <c>TPM2_GetSessionAuditDigest()</c>'s NULL signer.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3,
    /// clause 17.4, Table 85 and Table 86; Part 1, clauses 15.8 and 17.1</see>.
    /// </summary>
    [TestMethod]
    public async Task HashSequenceStartOverAnAuditSlotChainsTheDigestExcludingTheResponseHandleFromRpHash()
    {
        const string SequenceAuthPassword = "hash-sequence-audit-digest-auth";

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_GetSessionAuditDigest, TpmResponseCodec.GetSessionAuditDigest);

        using HashSequenceStartInput startInput = HashSequenceStartInput.CreateFromPassword(SequenceAuthPassword, TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256), pool);
        byte[] parameters = SerializeParameters(startInput, pool);

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        uint sequenceHandle = 0;
        try
        {
            using(auditSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                byte[] authArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_HashSequenceStart, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);

                (TpmRcConstants code, byte[] response) = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleForAuditAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_HashSequenceStart, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "TPM2_HashSequenceStart() over an audit-only companion must succeed (Table 85's tag rule).");
                sequenceHandle = ReadResponseHandle(response);

                byte[] responseParameters = TpmInHouseSimulatorZeroHandleSessionTests.ReadResponseParameters(response, outHandleCount: 1);
                Assert.IsEmpty(responseParameters, "Table 86's response carries the handle alone; the parameter area is empty.");

                byte[] cpHash = await TpmInHouseSimulatorZeroHandleSessionTests.ComputeZeroHandleCpHashAsync(TpmCcConstants.TPM_CC_HashSequenceStart, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                byte[] rpHash = await TpmInHouseSimulatorZeroHandleSessionTests.ComputeRpHashAsync(TpmCcConstants.TPM_CC_HashSequenceStart, responseParameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                byte[] expectedDigest = await TpmInHouseSimulatorZeroHandleSessionTests.ExtendAuditDigestAsync(priorDigest: null, cpHash, rpHash, pool, TestContext.CancellationToken).ConfigureAwait(false);

                using GetSessionAuditDigestInput auditDigestInput = GetSessionAuditDigestInput.ForNullSigner(TpmiShHmac.FromValue(auditHandle), ReadOnlySpan<byte>.Empty, pool);
                using TpmPasswordSession endorsementForDigest = TpmPasswordSession.CreateEmpty(pool);
                using TpmPasswordSession nullSignerSlot = TpmPasswordSession.CreateEmpty(pool);
                TpmResult<GetSessionAuditDigestResponse> digestResult = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                    device, auditDigestInput, [endorsementForDigest, nullSignerSlot], handleNames: null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(digestResult.IsSuccess, $"TPM2_GetSessionAuditDigest() must succeed: '{digestResult.ResponseCode}'.");
                using GetSessionAuditDigestResponse auditDigestResponse = digestResult.Value;

                Assert.IsTrue(
                    expectedDigest.AsSpan().SequenceEqual(auditDigestResponse.SessionAudit.SessionDigest.AsReadOnlySpan()),
                    "The audit digest must equal H(0…0 ‖ cpHash ‖ rpHash) with rpHash computed over the empty parameter area, the response handle excluded.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, sequenceHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A companion whose HMAC does not verify is refused <c>TPM_RC_BAD_AUTH</c> at its own index and the command
    /// is NOT run: <c>TPM2_HashSequenceStart()</c> opens no sequence, the session's nonceTPM is left untouched,
    /// and a genuine follow-up <c>TPM2_HashSequenceStart()</c> over the SAME session succeeds afterward.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3,
    /// clause 5.5; Part 1, clause 17.1</see>.
    /// </summary>
    [TestMethod]
    public async Task HashSequenceStartOverAWrongCompanionHmacReturnsBadAuthAndLeavesTheSessionUsable()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        using HashSequenceStartInput startInput = HashSequenceStartInput.CreateFromPassword("wrong-hmac-auth", TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256), pool);
        byte[] parameters = SerializeParameters(startInput, pool);

        (uint sessionHandle, TpmSession session) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                byte[] authArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(session, TpmCcConstants.TPM_CC_HashSequenceStart, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                authArea[^1] ^= 0xFF;

                (TpmRcConstants code, byte[] response) = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleForAuditAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_HashSequenceStart, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmInHouseSimulatorZeroHandleSessionTests.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), code,
                    "A companion whose HMAC does not verify is refused TPM_RC_BAD_AUTH at its own index, uncharged.");
                Assert.AreEqual((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, TpmInHouseSimulatorNoAuthSessionTests.ReadResponseTag(response), "A failed command frames TPM_ST_NO_SESSIONS.");
                Assert.HasCount(10, response, "A failed command's response is exactly the 10-octet header.");

                byte[] followUpAuthArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(session, TpmCcConstants.TPM_CC_HashSequenceStart, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                (TpmRcConstants followUpCode, byte[] followUpResponse) = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleForAuditAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_HashSequenceStart, followUpAuthArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, followUpCode, "The rejected attempt opened no sequence and left the session usable, so a genuine follow-up over it now succeeds.");
                await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, ReadResponseHandle(followUpResponse)).ConfigureAwait(false);
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_SignSequenceStart()</c> over an audit-only companion, the addressed key's own Name folded into
    /// cpHash BEFORE the authorization area is judged (TPM 2.0 Library Part 3, clause 5.4 precedes clause 5.5),
    /// succeeds with the audit digest chained from this exchange's own wire octets and read back through
    /// <c>TPM2_GetSessionAuditDigest()</c>'s NULL signer.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3,
    /// clause 17.5, Table 87 and Table 88; Part 1, clauses 15.7 and 17.1</see>.
    /// </summary>
    [TestMethod]
    public async Task SignSequenceStartOverAnAuditSlotSucceedsWithTheKeyNameChainedIntoTheAuditDigest()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await Shared.CreateOperationalWithEccBackendAsync(pool).ConfigureAwait(false);
        List<byte[]> responses = [];
        using TpmDevice device = CreateResponseCapturingDevice(simulator, responses);
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary)
            .Register(TpmCcConstants.TPM_CC_SignSequenceStart, TpmResponseCodec.SignSequenceStart)
            .Register(TpmCcConstants.TPM_CC_GetSessionAuditDigest, TpmResponseCodec.GetSessionAuditDigest);

        using CreatePrimaryInput createInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            device, createInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"TPM2_CreatePrimary() must succeed: '{createResult.ResponseCode}'.");
        using CreatePrimaryResponse primary = createResult.Value;

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        uint sequenceHandle = 0;
        try
        {
            using(auditSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                using SignSequenceStartInput startInput = SignSequenceStartInput.CreateFromPassword(primary.ObjectHandle, "sign-sequence-audit-auth", pool);
                byte[] parameters = SerializeParameters(startInput, pool);

                TpmResult<SignSequenceStartResponse> startResult = await TpmCommandExecutor.ExecuteAsync<SignSequenceStartResponse>(
                    device, startInput, [auditSession], handleNames: [primary.Name.AsReadOnlyMemory()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(startResult.IsSuccess, $"TPM2_SignSequenceStart() over an audit companion, with the key's Name folded into cpHash, must succeed: '{startResult.ResponseCode}'.");
                SignSequenceStartResponse started = startResult.Value;
                sequenceHandle = started.SequenceHandle.Value;

                byte[] expectedDigest = await ComputeExpectedDigestWithNameAsync(
                    null, TpmCcConstants.TPM_CC_SignSequenceStart, primary.Name.AsReadOnlyMemory(), parameters, responses[^1], outHandleCount: 1, pool).ConfigureAwait(false);

                using GetSessionAuditDigestInput auditDigestInput = GetSessionAuditDigestInput.ForNullSigner(TpmiShHmac.FromValue(auditHandle), ReadOnlySpan<byte>.Empty, pool);
                using TpmPasswordSession endorsementForDigest = TpmPasswordSession.CreateEmpty(pool);
                using TpmPasswordSession nullSignerSlot = TpmPasswordSession.CreateEmpty(pool);
                TpmResult<GetSessionAuditDigestResponse> digestResult = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                    device, auditDigestInput, [endorsementForDigest, nullSignerSlot], handleNames: null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(digestResult.IsSuccess, $"TPM2_GetSessionAuditDigest() must succeed: '{digestResult.ResponseCode}'.");
                using GetSessionAuditDigestResponse auditDigestResponse = digestResult.Value;

                Assert.IsTrue(
                    expectedDigest.AsSpan().SequenceEqual(auditDigestResponse.SessionAudit.SessionDigest.AsReadOnlySpan()),
                    "The audit digest must equal H(0…0 ‖ cpHash ‖ rpHash), with the signing key's own Name folded into cpHash, chained from this exchange's own wire octets.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, sequenceHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, primary.ObjectHandle.Value).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A sequence handle's Name term is the Empty Buffer ("the Name associated with sequenceHandle will be the
    /// Empty Buffer"), so the audit companion is verified over it exactly like any other slot BEFORE
    /// <c>TPM2_SignSequenceStart()</c>'s own "If keyHandle does not refer to a signing key, the TPM shall return
    /// TPM_RC_KEY" gate (clause 17.5.1) answers: the response is still <c>TPM_RC_KEY</c>, handle-encoded to the same index, framed
    /// <c>TPM_ST_NO_SESSIONS</c> in exactly 10 octets, the audit session's nonceTPM is that of a session that
    /// verified and then hit a dropped pending frame (never becoming an audit session, since only a command that
    /// claims <c>audit</c> AND succeeds starts its digest chain), and the hash sequence itself is untouched.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1,
    /// Table 9 footnote (1) and clause 29.4.6; Part 3, clauses 5.4, 5.9 and 17.5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task SignSequenceStartWithASequenceHandleAtTheKeySlotAnswersTheInnersHandleEncodedKeyAfterTheSessionsVerified()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await Shared.CreateOperationalWithEccBackendAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_HashSequenceStart, TpmResponseCodec.HashSequenceStart)
            .Register(TpmCcConstants.TPM_CC_SignSequenceStart, TpmResponseCodec.SignSequenceStart)
            .Register(TpmCcConstants.TPM_CC_SequenceComplete, TpmResponseCodec.SequenceComplete)
            .Register(TpmCcConstants.TPM_CC_GetSessionAuditDigest, TpmResponseCodec.GetSessionAuditDigest);

        using HashSequenceStartInput openInput = HashSequenceStartInput.CreateFromPassword(string.Empty, TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256), pool);
        TpmResult<HashSequenceStartResponse> openResult = await TpmCommandExecutor.ExecuteAsync<HashSequenceStartResponse>(
            device, openInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(openResult.IsSuccess, $"TPM2_HashSequenceStart() must succeed: '{openResult.ResponseCode}'.");
        TpmiDhObject sequenceHandle = openResult.Value.SequenceHandle;

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(auditSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                //An empty auth (TPM2B_AUTH) and an empty context (TPM2B_SIGNATURE_CTX) — two zero-size TPM2B
                //fields — parse cleanly so the wrapper reaches the inner's own resolution step once the session
                //verifies, where the sequence handle answers TPM_RC_KEY. The Name term is the Empty Buffer, the
                //SAME term the session's own command HMAC commits to.
                byte[] parameters = [0x00, 0x00, 0x00, 0x00];
                byte[] authArea = await Shared.BuildSessionAuthAreaOverHandleAsync(auditSession, TpmCcConstants.TPM_CC_SignSequenceStart, ReadOnlyMemory<byte>.Empty, parameters, pool).ConfigureAwait(false);

                (TpmRcConstants code, byte[] response) = await Shared.SubmitOverHandleAsync(simulator, pool, TpmCcConstants.TPM_CC_SignSequenceStart, sequenceHandle.Value, authArea, parameters).ConfigureAwait(false);

                Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_KEY, 0), code, "A sequence handle refuses at keyHandle, handle 1 of Table 87, after the authorization area verifies.");
                Assert.AreEqual((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, TpmInHouseSimulatorNoAuthSessionTests.ReadResponseTag(response), "A failed command frames TPM_ST_NO_SESSIONS regardless of the request's own tag.");
                Assert.HasCount(10, response, "A failed command's response is exactly the 10-octet header (Part 3, clause 5.9).");

                (TpmRcConstants digestCodeAfterRefusal, _) = await Shared.TryReadNullSignedAuditDigestAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
                Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_TYPE, 2), digestCodeAfterRefusal, "The refused command never used the session as an audit session — TPM2_GetSessionAuditDigest() still refuses TPM_RC_TYPE, exactly as a session that has never audited anything (Part 3, clause 5.9).");

                byte[] followUpParameters = TpmInHouseSimulatorZeroHandleSessionTests.ParameterAreaFor(TpmCcConstants.TPM_CC_TestParms, pool);
                byte[] followUpAuthArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_TestParms, followUpParameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                TpmRcConstants followUpCode = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_TestParms, followUpAuthArea, followUpParameters, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, followUpCode, "The session's nonceTPM was left untouched by the dropped pending frame, so a genuine follow-up over it still verifies.");

                using SequenceCompleteInput probeInput = SequenceCompleteInput.Create(sequenceHandle, [], TpmiRhHierarchy.Null, pool);
                using TpmPasswordSession sequencePassword = TpmPasswordSession.CreateEmpty(pool);
                TpmResult<SequenceCompleteResponse> stillOpenResult = await TpmCommandExecutor.ExecuteAsync<SequenceCompleteResponse>(
                    device, probeInput, [sequencePassword], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(stillOpenResult.IsSuccess, "The hash sequence itself was never touched by the refused TPM2_SignSequenceStart() and can still be completed.");
                stillOpenResult.Value.Dispose();
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A sequence handle's Name term is the Empty Buffer ("the Name associated with sequenceHandle will be the
    /// Empty Buffer"), so the audit companion is verified over it exactly like any other slot BEFORE
    /// <c>TPM2_VerifySequenceStart()</c>'s own "If keyHandle does not refer to a signing key, the TPM shall
    /// return TPM_RC_KEY" gate (clause 17.6.1) answers: the response is still <c>TPM_RC_KEY</c>, handle-encoded to the same index, framed
    /// <c>TPM_ST_NO_SESSIONS</c> in exactly 10 octets, the session never becomes an audit session at all (only a
    /// command that claims <c>audit</c> AND succeeds starts its digest chain), and the hash sequence itself is
    /// untouched.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1,
    /// Table 9 footnote (1) and clause 29.4.6; Part 3, clauses 5.4, 5.9 and 17.6.1</see>.
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceStartWithASequenceHandleAtTheKeySlotAnswersTheInnersHandleEncodedKeyAfterTheSessionsVerified()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await Shared.CreateOperationalWithEccBackendAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_HashSequenceStart, TpmResponseCodec.HashSequenceStart)
            .Register(TpmCcConstants.TPM_CC_VerifySequenceStart, TpmResponseCodec.VerifySequenceStart)
            .Register(TpmCcConstants.TPM_CC_SequenceComplete, TpmResponseCodec.SequenceComplete)
            .Register(TpmCcConstants.TPM_CC_GetSessionAuditDigest, TpmResponseCodec.GetSessionAuditDigest);

        using HashSequenceStartInput openInput = HashSequenceStartInput.CreateFromPassword(string.Empty, TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256), pool);
        TpmResult<HashSequenceStartResponse> openResult = await TpmCommandExecutor.ExecuteAsync<HashSequenceStartResponse>(
            device, openInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(openResult.IsSuccess, $"TPM2_HashSequenceStart() must succeed: '{openResult.ResponseCode}'.");
        TpmiDhObject sequenceHandle = openResult.Value.SequenceHandle;

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(auditSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                //The executor's own client-side guard refuses an empty handleNames entry for an object-range
                //handle it cannot itself know is a sequence, so this frames the request by hand instead: the
                //Name term is the Empty Buffer, the SAME term the session's own command HMAC commits to.
                using VerifySequenceStartInput verifyInput = VerifySequenceStartInput.Create(sequenceHandle, [], pool);
                byte[] parameters = SerializeParameters(verifyInput, pool);
                byte[] authArea = await Shared.BuildSessionAuthAreaOverHandleAsync(auditSession, TpmCcConstants.TPM_CC_VerifySequenceStart, ReadOnlyMemory<byte>.Empty, parameters, pool).ConfigureAwait(false);

                (TpmRcConstants code, byte[] response) = await Shared.SubmitOverHandleAsync(simulator, pool, TpmCcConstants.TPM_CC_VerifySequenceStart, sequenceHandle.Value, authArea, parameters).ConfigureAwait(false);

                Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_KEY, 0), code, "A sequence handle refuses at keyHandle, handle 1 of Table 89, after the authorization area verifies.");
                Assert.AreEqual((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, TpmInHouseSimulatorNoAuthSessionTests.ReadResponseTag(response), "A failed command frames TPM_ST_NO_SESSIONS regardless of the request's own tag.");
                Assert.HasCount(10, response, "A failed command's response is exactly the 10-octet header (Part 3, clause 5.9).");

                (TpmRcConstants digestCodeAfterRefusal, _) = await Shared.TryReadNullSignedAuditDigestAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
                Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_TYPE, 2), digestCodeAfterRefusal, "The refused command never used the session as an audit session — TPM2_GetSessionAuditDigest() still refuses TPM_RC_TYPE, exactly as a session that has never audited anything (Part 3, clause 5.9).");

                byte[] followUpParameters = TpmInHouseSimulatorZeroHandleSessionTests.ParameterAreaFor(TpmCcConstants.TPM_CC_TestParms, pool);
                byte[] followUpAuthArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_TestParms, followUpParameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                TpmRcConstants followUpCode = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_TestParms, followUpAuthArea, followUpParameters, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, followUpCode, "The session's nonceTPM was left untouched by the dropped pending frame, so a genuine follow-up over it still verifies.");

                using SequenceCompleteInput probeInput = SequenceCompleteInput.Create(sequenceHandle, [], TpmiRhHierarchy.Null, pool);
                using TpmPasswordSession sequencePassword = TpmPasswordSession.CreateEmpty(pool);
                TpmResult<SequenceCompleteResponse> stillOpenResult = await TpmCommandExecutor.ExecuteAsync<SequenceCompleteResponse>(
                    device, probeInput, [sequencePassword], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(stillOpenResult.IsSuccess, "The hash sequence itself was never touched by the refused TPM2_VerifySequenceStart() and can still be completed.");
                stillOpenResult.Value.Dispose();
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_VerifySequenceStart()</c> over a decrypt-only companion recovers <c>auth</c> before the sequence
    /// opens; a follow-up <c>TPM2_SequenceUpdate()</c> authorized by that SAME plaintext password succeeds,
    /// proving the decrypted octets — not the ciphertext that rode the wire — were installed as the sequence's
    /// authValue.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3,
    /// clause 17.6, Table 89 and Table 90</see>.
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceStartOverADecryptSlotSucceedsAndTheDecryptedAuthAuthorizesASequenceUpdate()
    {
        const string SequenceAuthPassword = "verify-sequence-decrypt-auth";

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await Shared.CreateOperationalWithEccBackendAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary)
            .Register(TpmCcConstants.TPM_CC_VerifySequenceStart, TpmResponseCodec.VerifySequenceStart)
            .Register(TpmCcConstants.TPM_CC_SequenceUpdate, TpmResponseCodec.SequenceUpdate);

        using CreatePrimaryInput createInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            device, createInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"TPM2_CreatePrimary() must succeed: '{createResult.ResponseCode}'.");
        using CreatePrimaryResponse primary = createResult.Value;

        (uint decryptHandle, TpmSession decryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        uint sequenceHandle = 0;
        try
        {
            using(decryptSession)
            {
                decryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                using VerifySequenceStartInput startInput = VerifySequenceStartInput.Create(primary.ObjectHandle, System.Text.Encoding.ASCII.GetBytes(SequenceAuthPassword), pool);
                TpmResult<VerifySequenceStartResponse> startResult = await TpmCommandExecutor.ExecuteAsync<VerifySequenceStartResponse>(
                    device, startInput, [decryptSession], handleNames: [primary.Name.AsReadOnlyMemory()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(startResult.IsSuccess, $"TPM2_VerifySequenceStart() over a decrypt companion must succeed: '{startResult.ResponseCode}'.");
                VerifySequenceStartResponse started = startResult.Value;
                sequenceHandle = started.SequenceHandle.Value;

                using SequenceUpdateInput updateInput = SequenceUpdateInput.Create(started.SequenceHandle, [0x01, 0x02], pool);
                using TpmPasswordSession sequencePassword = TpmPasswordSession.Create(SequenceAuthPassword, pool);
                TpmResult<SequenceUpdateResponse> updateResult = await TpmCommandExecutor.ExecuteAsync<SequenceUpdateResponse>(
                    device, updateInput, [sequencePassword], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(
                    updateResult.IsSuccess,
                    $"TPM2_SequenceUpdate() over the sequence's own plaintext password must succeed, proving the decrypted (not ciphertext) auth was installed: '{updateResult.ResponseCode}'.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, sequenceHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, decryptHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, primary.ObjectHandle.Value).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_VerifySequenceStart()</c> over an audit-only companion, the addressed key's own Name folded into
    /// cpHash BEFORE the authorization area is judged (TPM 2.0 Library Part 3, clause 5.4 precedes clause 5.5),
    /// succeeds with the audit digest chained to <c>H(0…0 ‖ cpHash ‖ rpHash)</c> with rpHash computed over the
    /// parameter area that follows the response's own handle — "The contents of the handles area of the response
    /// are not included in the rpHash" — read back through <c>TPM2_GetSessionAuditDigest()</c>'s NULL signer.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3,
    /// clause 17.6, Table 89 and Table 90; Part 1, clauses 15.7, 15.8 and 17.1</see>.
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceStartOverAnAuditSlotChainsTheDigestExcludingTheResponseHandleFromRpHash()
    {
        const string SequenceAuthPassword = "verify-sequence-audit-auth";

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await Shared.CreateOperationalWithEccBackendAsync(pool).ConfigureAwait(false);
        List<byte[]> responses = [];
        using TpmDevice device = CreateResponseCapturingDevice(simulator, responses);
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary)
            .Register(TpmCcConstants.TPM_CC_VerifySequenceStart, TpmResponseCodec.VerifySequenceStart)
            .Register(TpmCcConstants.TPM_CC_GetSessionAuditDigest, TpmResponseCodec.GetSessionAuditDigest);

        using CreatePrimaryInput createInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            device, createInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"TPM2_CreatePrimary() must succeed: '{createResult.ResponseCode}'.");
        using CreatePrimaryResponse primary = createResult.Value;

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        uint sequenceHandle = 0;
        try
        {
            using(auditSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                using VerifySequenceStartInput startInput = VerifySequenceStartInput.Create(primary.ObjectHandle, System.Text.Encoding.ASCII.GetBytes(SequenceAuthPassword), pool);
                byte[] parameters = SerializeParameters(startInput, pool);

                TpmResult<VerifySequenceStartResponse> startResult = await TpmCommandExecutor.ExecuteAsync<VerifySequenceStartResponse>(
                    device, startInput, [auditSession], handleNames: [primary.Name.AsReadOnlyMemory()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(startResult.IsSuccess, $"TPM2_VerifySequenceStart() over an audit companion, with the key's Name folded into cpHash, must succeed: '{startResult.ResponseCode}'.");
                VerifySequenceStartResponse started = startResult.Value;
                sequenceHandle = started.SequenceHandle.Value;

                byte[] expectedDigest = await ComputeExpectedDigestWithNameAsync(
                    null, TpmCcConstants.TPM_CC_VerifySequenceStart, primary.Name.AsReadOnlyMemory(), parameters, responses[^1], outHandleCount: 1, pool).ConfigureAwait(false);

                using GetSessionAuditDigestInput auditDigestInput = GetSessionAuditDigestInput.ForNullSigner(TpmiShHmac.FromValue(auditHandle), ReadOnlySpan<byte>.Empty, pool);
                using TpmPasswordSession endorsementForDigest = TpmPasswordSession.CreateEmpty(pool);
                using TpmPasswordSession nullSignerSlot = TpmPasswordSession.CreateEmpty(pool);
                TpmResult<GetSessionAuditDigestResponse> digestResult = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                    device, auditDigestInput, [endorsementForDigest, nullSignerSlot], handleNames: null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(digestResult.IsSuccess, $"TPM2_GetSessionAuditDigest() must succeed: '{digestResult.ResponseCode}'.");
                using GetSessionAuditDigestResponse auditDigestResponse = digestResult.Value;

                Assert.IsTrue(
                    expectedDigest.AsSpan().SequenceEqual(auditDigestResponse.SessionAudit.SessionDigest.AsReadOnlySpan()),
                    "The audit digest must equal H(0…0 ‖ cpHash ‖ rpHash), with the key's own Name folded into cpHash and rpHash computed over the parameter area after the response handle, chained from this exchange's own wire octets.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, sequenceHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, primary.ObjectHandle.Value).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_VerifySignature()</c> over a PERSISTENT key and an audit-only companion succeeds, the persistent
    /// object's own Name — identical to its transient Name, since a Name is a hash of the public area alone —
    /// chained into cpHash and read back through the extended audit digest.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3,
    /// clause 20.2, Table 116; Part 1, clauses 15.7 and 17.1</see>.
    /// </summary>
    [TestMethod]
    public async Task VerifySignatureOverAPersistentKeyAndAnAuditSlotSucceedsWithThePersistentNameChainedIntoTheAuditDigest()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await Shared.CreateOperationalWithEccBackendAsync(pool).ConfigureAwait(false);
        List<byte[]> responses = [];
        using TpmDevice device = CreateResponseCapturingDevice(simulator, responses);
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary)
            .Register(TpmCcConstants.TPM_CC_Sign, TpmResponseCodec.Sign)
            .Register(TpmCcConstants.TPM_CC_EvictControl, TpmResponseCodec.EvictControl)
            .Register(TpmCcConstants.TPM_CC_VerifySignature, TpmResponseCodec.VerifySignature)
            .Register(TpmCcConstants.TPM_CC_GetSessionAuditDigest, TpmResponseCodec.GetSessionAuditDigest);

        using CreatePrimaryInput createInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            device, createInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"TPM2_CreatePrimary() must succeed: '{createResult.ResponseCode}'.");
        using CreatePrimaryResponse primary = createResult.Value;

        byte[] digest = SHA256.HashData([0x07, 0x08, 0x09]);
        using TpmPasswordSession signKeyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignInput signInput = SignInput.ForEcdsa(primary.ObjectHandle, digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            device, signInput, [signKeyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signResult.IsSuccess, $"TPM2_Sign() must succeed: '{signResult.ResponseCode}'.");
        using SignResponse signature = signResult.Value;
        byte[] signatureOctets = [.. signature.Signature.SignatureR!.AsReadOnlySpan(), .. signature.Signature.SignatureS!.AsReadOnlySpan()];

        TpmResult<EvictControlResponse> persistResult = await TpmEvictControlHarness.EvictControlAsync(
            device, registry, pool, primary.ObjectHandle.Value, PersistentSigningKeyHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(persistResult.IsSuccess, $"EvictControl (persist) failed: '{persistResult.ResponseCode}'.");

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(auditSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                using VerifySignatureInput verifyInput = VerifySignatureInput.ForEcdsa(TpmiDhObject.FromValue(PersistentSigningKeyHandle), digest, signatureOctets, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
                byte[] parameters = SerializeParameters(verifyInput, pool);

                TpmResult<VerifySignatureResponse> verifyResult = await TpmCommandExecutor.ExecuteAsync<VerifySignatureResponse>(
                    device, verifyInput, [auditSession], handleNames: [primary.Name.AsReadOnlyMemory()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(verifyResult.IsSuccess, $"TPM2_VerifySignature() over the PERSISTENT key and an audit companion must succeed: '{verifyResult.ResponseCode}'.");
                using VerifySignatureResponse validated = verifyResult.Value;
                Assert.AreEqual(TpmiRhHierarchy.Owner, validated.Validation.Hierarchy, "The validation ticket names the signing key's hierarchy.");

                byte[] expectedDigest = await ComputeExpectedDigestWithNameAsync(
                    null, TpmCcConstants.TPM_CC_VerifySignature, primary.Name.AsReadOnlyMemory(), parameters, responses[^1], outHandleCount: 0, pool).ConfigureAwait(false);

                using GetSessionAuditDigestInput auditDigestInput = GetSessionAuditDigestInput.ForNullSigner(TpmiShHmac.FromValue(auditHandle), ReadOnlySpan<byte>.Empty, pool);
                using TpmPasswordSession endorsementForDigest = TpmPasswordSession.CreateEmpty(pool);
                using TpmPasswordSession nullSignerSlot = TpmPasswordSession.CreateEmpty(pool);
                TpmResult<GetSessionAuditDigestResponse> digestResult = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                    device, auditDigestInput, [endorsementForDigest, nullSignerSlot], handleNames: null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(digestResult.IsSuccess, $"TPM2_GetSessionAuditDigest() must succeed: '{digestResult.ResponseCode}'.");
                using GetSessionAuditDigestResponse auditDigestResponse = digestResult.Value;

                Assert.IsTrue(
                    expectedDigest.AsSpan().SequenceEqual(auditDigestResponse.SessionAudit.SessionDigest.AsReadOnlySpan()),
                    "The audit digest must equal H(0…0 ‖ cpHash ‖ rpHash) with the PERSISTENT key's own Name folded into cpHash.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A sequence handle's Name term is the Empty Buffer ("the Name associated with sequenceHandle will be the
    /// Empty Buffer"), so the audit companion is verified over it exactly like any other slot BEFORE
    /// <c>TPM2_VerifyDigestSignature()</c>'s own sequence-slot gate answers <c>TPM_RC_KEY</c>, handle-encoded to the same index — the code
    /// Part 0's version-185 change history states for the case ("All signing commands, including attestation
    /// commands, return TPM_RC_KEY for a non-signing key"; Part 3, clause 20.4.1 itself names only <c>TPM_RC_SCHEME</c>):
    /// the response is still bare, framed <c>TPM_ST_NO_SESSIONS</c> in exactly 10 octets, and the session never
    /// becomes an audit session at all (only a command that claims <c>audit</c> AND succeeds starts its digest
    /// chain).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 0
    /// (version-185 change history); Part 1, Table 9 footnote (1) and clause 29.4.6; Part 3, clauses 5.4, 5.9 and
    /// 20.4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task VerifyDigestSignatureWithASequenceHandleAtTheKeySlotAnswersTheInnersHandleEncodedKeyAfterTheSessionsVerified()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await Shared.CreateOperationalWithEccBackendAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_HashSequenceStart, TpmResponseCodec.HashSequenceStart)
            .Register(TpmCcConstants.TPM_CC_VerifyDigestSignature, TpmResponseCodec.VerifyDigestSignature)
            .Register(TpmCcConstants.TPM_CC_SequenceComplete, TpmResponseCodec.SequenceComplete)
            .Register(TpmCcConstants.TPM_CC_GetSessionAuditDigest, TpmResponseCodec.GetSessionAuditDigest);

        using HashSequenceStartInput openInput = HashSequenceStartInput.CreateFromPassword(string.Empty, TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256), pool);
        TpmResult<HashSequenceStartResponse> openResult = await TpmCommandExecutor.ExecuteAsync<HashSequenceStartResponse>(
            device, openInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(openResult.IsSuccess, $"TPM2_HashSequenceStart() must succeed: '{openResult.ResponseCode}'.");
        TpmiDhObject sequenceHandle = openResult.Value.SequenceHandle;

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(auditSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                //The digest/signature octets are placeholders: the sequence handle resolves to TPM_RC_KEY before
                //any signature-content check ever runs, so only their WIRE SHAPE (an admitted sigAlg, a
                //well-formed TPMT_SIGNATURE body) needs to parse. The executor's own client-side guard refuses
                //an empty handleNames entry for an object-range handle it cannot itself know is a sequence, so
                //this frames the request by hand instead: the Name term is the Empty Buffer, the SAME term the
                //session's own command HMAC commits to.
                using VerifyDigestSignatureInput verifyInput = VerifyDigestSignatureInput.ForEcdsa(sequenceHandle, new byte[32], new byte[64], TpmAlgIdConstants.TPM_ALG_SHA256, pool);
                byte[] parameters = SerializeParameters(verifyInput, pool);
                byte[] authArea = await Shared.BuildSessionAuthAreaOverHandleAsync(auditSession, TpmCcConstants.TPM_CC_VerifyDigestSignature, ReadOnlyMemory<byte>.Empty, parameters, pool).ConfigureAwait(false);

                (TpmRcConstants code, byte[] response) = await Shared.SubmitOverHandleAsync(simulator, pool, TpmCcConstants.TPM_CC_VerifyDigestSignature, sequenceHandle.Value, authArea, parameters).ConfigureAwait(false);

                Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_KEY, 0), code, "A sequence handle refuses at keyHandle, handle 1 of Table 120, after the authorization area verifies.");
                Assert.AreEqual((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, TpmInHouseSimulatorNoAuthSessionTests.ReadResponseTag(response), "A failed command frames TPM_ST_NO_SESSIONS regardless of the request's own tag.");
                Assert.HasCount(10, response, "A failed command's response is exactly the 10-octet header (Part 3, clause 5.9).");

                (TpmRcConstants digestCodeAfterRefusal, _) = await Shared.TryReadNullSignedAuditDigestAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
                Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_TYPE, 2), digestCodeAfterRefusal, "The refused command never used the session as an audit session — TPM2_GetSessionAuditDigest() still refuses TPM_RC_TYPE, exactly as a session that has never audited anything (Part 3, clause 5.9).");

                byte[] followUpParameters = TpmInHouseSimulatorZeroHandleSessionTests.ParameterAreaFor(TpmCcConstants.TPM_CC_TestParms, pool);
                byte[] followUpAuthArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_TestParms, followUpParameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                TpmRcConstants followUpCode = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_TestParms, followUpAuthArea, followUpParameters, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, followUpCode, "The session's nonceTPM was left untouched by the dropped pending frame, so a genuine follow-up over it still verifies.");

                using SequenceCompleteInput probeInput = SequenceCompleteInput.Create(sequenceHandle, [], TpmiRhHierarchy.Null, pool);
                using TpmPasswordSession sequencePassword = TpmPasswordSession.CreateEmpty(pool);
                TpmResult<SequenceCompleteResponse> stillOpenResult = await TpmCommandExecutor.ExecuteAsync<SequenceCompleteResponse>(
                    device, probeInput, [sequencePassword], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(stillOpenResult.IsSuccess, "The hash sequence itself was never touched by the refused TPM2_VerifyDigestSignature() and can still be completed.");
                stillOpenResult.Value.Dispose();
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_VerifyDigestSignature()</c> over an audit-only companion, the key's own Name folded into cpHash,
    /// succeeds with the audit digest chained from this exchange's own wire octets.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3,
    /// clause 20.4, Table 120; Part 1, clauses 15.7 and 17.1</see>.
    /// </summary>
    [TestMethod]
    public async Task VerifyDigestSignatureOverAnAuditSlotSucceedsWithTheKeyNameChainedIntoTheAuditDigest()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await Shared.CreateOperationalWithEccBackendAsync(pool).ConfigureAwait(false);
        List<byte[]> responses = [];
        using TpmDevice device = CreateResponseCapturingDevice(simulator, responses);
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary)
            .Register(TpmCcConstants.TPM_CC_Sign, TpmResponseCodec.Sign)
            .Register(TpmCcConstants.TPM_CC_VerifyDigestSignature, TpmResponseCodec.VerifyDigestSignature)
            .Register(TpmCcConstants.TPM_CC_GetSessionAuditDigest, TpmResponseCodec.GetSessionAuditDigest);

        using CreatePrimaryInput createInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            device, createInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"TPM2_CreatePrimary() must succeed: '{createResult.ResponseCode}'.");
        using CreatePrimaryResponse primary = createResult.Value;

        byte[] digest = SHA256.HashData([0x0C, 0x0D, 0x0E]);
        using TpmPasswordSession signKeyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignInput signInput = SignInput.ForEcdsa(primary.ObjectHandle, digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            device, signInput, [signKeyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signResult.IsSuccess, $"TPM2_Sign() must succeed: '{signResult.ResponseCode}'.");
        using SignResponse signature = signResult.Value;
        byte[] signatureOctets = [.. signature.Signature.SignatureR!.AsReadOnlySpan(), .. signature.Signature.SignatureS!.AsReadOnlySpan()];

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(auditSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                using VerifyDigestSignatureInput verifyInput = VerifyDigestSignatureInput.ForEcdsa(primary.ObjectHandle, digest, signatureOctets, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
                byte[] parameters = SerializeParameters(verifyInput, pool);

                TpmResult<VerifyDigestSignatureResponse> verifyResult = await TpmCommandExecutor.ExecuteAsync<VerifyDigestSignatureResponse>(
                    device, verifyInput, [auditSession], handleNames: [primary.Name.AsReadOnlyMemory()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(verifyResult.IsSuccess, $"TPM2_VerifyDigestSignature() over an audit companion must succeed: '{verifyResult.ResponseCode}'.");
                using VerifyDigestSignatureResponse validated = verifyResult.Value;
                Assert.AreEqual(TpmiRhHierarchy.Owner, validated.Validation.Hierarchy, "The validation ticket names the signing key's hierarchy.");

                byte[] expectedDigest = await ComputeExpectedDigestWithNameAsync(
                    null, TpmCcConstants.TPM_CC_VerifyDigestSignature, primary.Name.AsReadOnlyMemory(), parameters, responses[^1], outHandleCount: 0, pool).ConfigureAwait(false);

                using GetSessionAuditDigestInput auditDigestInput = GetSessionAuditDigestInput.ForNullSigner(TpmiShHmac.FromValue(auditHandle), ReadOnlySpan<byte>.Empty, pool);
                using TpmPasswordSession endorsementForDigest = TpmPasswordSession.CreateEmpty(pool);
                using TpmPasswordSession nullSignerSlot = TpmPasswordSession.CreateEmpty(pool);
                TpmResult<GetSessionAuditDigestResponse> digestResult = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                    device, auditDigestInput, [endorsementForDigest, nullSignerSlot], handleNames: null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(digestResult.IsSuccess, $"TPM2_GetSessionAuditDigest() must succeed: '{digestResult.ResponseCode}'.");
                using GetSessionAuditDigestResponse auditDigestResponse = digestResult.Value;

                Assert.IsTrue(
                    expectedDigest.AsSpan().SequenceEqual(auditDigestResponse.SessionAudit.SessionDigest.AsReadOnlySpan()),
                    "The audit digest must equal H(0…0 ‖ cpHash ‖ rpHash) with the signing key's own Name folded into cpHash.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, primary.ObjectHandle.Value).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_VerifyDigestSignature()</c> over a claiming XOR decrypt companion, addressed at a genuine,
    /// resolvable key: <c>digest</c>'s own declared size past <c>TPM2B_DIGEST</c>'s <c>MaxSize</c> — the
    /// SECOND parameter (Table 120, index 1), never the decrypt-eligible FIRST parameter <c>context</c> — is
    /// the parameter core's own designation, already carrying the P bit and N = 2 before this arm's decrypt
    /// continuation ever sees it, and TPM 2.0 Library Part 2, clause 6.6.2, Table 15's closing sentence (a code
    /// is designated once) keeps it from picking up a second, session designation: the answer passes through
    /// unchanged rather than stacking to N = 11.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 20.4, Table 120; Part 2, clause 6.6.2, Table 15; Part 1, clause 18.1</see>.
    /// </summary>
    [TestMethod]
    public async Task VerifyDigestSignatureOverAXorDecryptCompanionWithAnOverBoundDigestAnswersTheParameterEncodedSizeUnchanged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await Shared.CreateOperationalWithEccBackendAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);

        //A resolvable signing-capable object at a real handle: TPM2_VerifyDigestSignature()'s companion-session
        //wire form resolves keyHandle before any parameter is decoded, so a placeholder handle number is not
        //enough here.
        using CreatePrimaryResponse primary = await HmacKeyHarness.CreateEccSigningPrimaryAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        //context: well-formed empty TPM2B_SIGNATURE_CTX (the decrypt-eligible first parameter, untouched by the
        //malformation); digest: declared one octet past Tpm2bDigest.MaxSize (Table 120, index 1) — the bound
        //check fires on the declared size alone, so no content octets are needed after it.
        byte[] parameters = new byte[sizeof(ushort) + sizeof(ushort)];
        BinaryPrimitives.WriteUInt16BigEndian(parameters.AsSpan(0, sizeof(ushort)), 0);
        BinaryPrimitives.WriteUInt16BigEndian(parameters.AsSpan(sizeof(ushort), sizeof(ushort)), (ushort)(Tpm2bDigest.MaxSize + 1));

        (uint decryptHandle, TpmSession decryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(
            device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        try
        {
            using(decryptSession)
            {
                decryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                byte[] authArea = await Shared.BuildSessionAuthAreaOverHandleAsync(
                    decryptSession, TpmCcConstants.TPM_CC_VerifyDigestSignature, primary.Name.AsReadOnlyMemory(), parameters, pool).ConfigureAwait(false);

                (TpmRcConstants code, _) = await Shared.SubmitOverHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_VerifyDigestSignature, primary.ObjectHandle.Value, authArea, parameters).ConfigureAwait(false);

                Assert.AreEqual(
                    HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 1), code,
                    "digest is TPM2_VerifyDigestSignature()'s second parameter (Table 120, index 1); its own declared over-bound size is the parameter core's designation, passed through the decrypt continuation unchanged rather than session-encoded.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, decryptHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, primary.ObjectHandle.Value).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_Quote()</c>'s sole authorizing slot claiming <c>decrypt</c> alongside its own authorization of
    /// <c>signHandle</c>, with <c>qualifyingData</c> declared one octet past <c>Tpm2bData.MaxSize</c>
    /// (<c>sizeof(TPMT_HA)</c>): this is qualifyingData's OWN content failure, not the decrypt step's — the
    /// step's own two size failures are the size field unreadable or the declared cipher size wider than the
    /// captured area, neither of which this is — so it answers parameter-encoded, passed through the decrypt
    /// continuation unchanged rather than session-encoded to the claiming slot. TPM 2.0 Library Part 3, clause
    /// 18.4, Table 101: qualifyingData is <c>TPM2_Quote()</c>'s first parameter, index 0.
    /// </summary>
    [TestMethod]
    public async Task QuoteOverAXorDecryptCompanionWithAnOverBoundQualifyingDataAnswersTheParameterEncodedSizeUnchanged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await Shared.CreateOperationalWithEccBackendAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);

        using CreatePrimaryResponse primary = await HmacKeyHarness.CreateEccSigningPrimaryAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        //TPM2_Quote()'s session-authorized wire parser walks all three parameters at parse time (qualifyingData
        //captured opaque for the decrypt step, then inScheme and PCRselect decoded for real), so every one of
        //them must be genuinely present and well-formed for the request to reach HMAC verification at all:
        //qualifyingData declared AND actually carrying one octet past Tpm2bData.MaxSize (Table 101, index 0) —
        //the content octets must genuinely be present so the wire-level capture is not itself truncated, which
        //would answer a different, unrelated INSUFFICIENT — followed by a well-formed NULL inScheme
        //(TPMT_SIG_SCHEME, two octets, no scheme-specific data) and an empty PCRselect (TPML_PCR_SELECTION,
        //count zero), so the semantic width bound on qualifyingData is the only thing this row proves.
        const int OverBoundLength = Tpm2bData.MaxSize + 1;
        byte[] parameters = new byte[sizeof(ushort) + OverBoundLength + sizeof(ushort) + sizeof(uint)];
        var parameterWriter = new TpmWriter(parameters);
        parameterWriter.WriteUInt16((ushort)OverBoundLength);
        parameterWriter.WriteBytes(new byte[OverBoundLength]);
        parameterWriter.WriteUInt16((ushort)TpmAlgIdConstants.TPM_ALG_NULL);
        parameterWriter.WriteUInt32(0);

        (uint decryptHandle, TpmSession decryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(
            device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        try
        {
            using(decryptSession)
            {
                decryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                byte[] authArea = await Shared.BuildSessionAuthAreaOverHandleAsync(
                    decryptSession, TpmCcConstants.TPM_CC_Quote, primary.Name.AsReadOnlyMemory(), parameters, pool).ConfigureAwait(false);

                (TpmRcConstants code, _) = await Shared.SubmitOverHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_Quote, primary.ObjectHandle.Value, authArea, parameters).ConfigureAwait(false);

                Assert.AreEqual(
                    HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), code,
                    "Table 101: qualifyingData is TPM2_Quote()'s first parameter (index 0); its own declared over-bound size is parameter-encoded there, passed through the decrypt continuation unchanged rather than session-encoded, exactly as every other decrypt-eligible first parameter's own content failure is.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, decryptHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, primary.ObjectHandle.Value).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_Hash()</c> over a claiming XOR decrypt companion whose declared first-parameter (<c>data</c>)
    /// size exceeds the octets actually captured in the parameter area: this is the DECRYPT STEP'S OWN failure
    /// (the reference's <c>CryptParameterDecryption</c> answers the identical shape <c>TPM_RC_SIZE</c>, session-encoded to the same index
    /// before ever reaching the command's parameter core), so — unlike a failure of the decrypted content — it
    /// is session-index-encoded to the slot that claimed <c>decrypt</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 6.6.2; Part 1, clause 18.1</see>.
    /// </summary>
    [TestMethod]
    public async Task HashOverADecryptCompanionWithACipherSizeWiderThanTheParameterAreaAnswersSessionEncodedSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        //A declared first-parameter size (200) far wider than the five octets actually captured: the decrypt
        //step's own generic size-field preamble refuses this before any command-specific parsing runs.
        byte[] parameters = new byte[sizeof(ushort) + 5];
        BinaryPrimitives.WriteUInt16BigEndian(parameters.AsSpan(0, sizeof(ushort)), 200);

        (uint decryptHandle, TpmSession decryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(
            device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        try
        {
            using(decryptSession)
            {
                decryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                byte[] authArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(
                    decryptSession, TpmCcConstants.TPM_CC_Hash, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                TpmRcConstants code = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_Hash, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmInHouseSimulatorZeroHandleSessionTests.SessionEncodedRc(TpmRcConstants.TPM_RC_SIZE, sessionIndex: 0), code,
                    "A declared cipher size wider than the captured parameter area is the decrypt step's OWN failure, session-encoded to the claiming slot, never a property of the command's own parameter.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, decryptHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_Hash()</c> over a claiming XOR decrypt companion, framed with one octet beyond its own
    /// well-formed parameter area: the whole-area trailing-octets check (the reference's own generic
    /// <c>CommandDispatcher</c> rule — once every declared parameter has unmarshaled, a non-zero remainder is a
    /// property of the whole area, not of the last field read) runs AFTER the decrypted content has re-parsed
    /// cleanly, so it stays bare rather than being blamed on the decrypt slot.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 6.6.2, Table 15; Part 3, clause 5.8.2</see>.
    /// </summary>
    [TestMethod]
    public async Task HashOverADecryptCompanionWithATrailingOctetAfterTheDecryptedFirstParameterStaysBareSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        byte[] data = [0x01, 0x02, 0x03];
        using HashInput hashInput = HashInput.Create(data, TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256), TpmiRhHierarchy.Null, pool);
        byte[] wellFormedParameters = SerializeParameters(hashInput, pool);
        byte[] parameters = [.. wellFormedParameters, 0x00]; //One octet beyond the last declared field.

        (uint decryptHandle, TpmSession decryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(
            device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        try
        {
            using(decryptSession)
            {
                decryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                byte[] authArea = await BuildDecryptCompanionBlockAsync(
                    decryptSession, TpmCcConstants.TPM_CC_Hash, parameters, firstParameterOffset: sizeof(ushort), firstParameterLength: data.Length, pool).ConfigureAwait(false);
                TpmRcConstants code = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_Hash, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_SIZE, code,
                    "A trailing octet after every declared parameter has unmarshaled is a property of the whole area, not of the decrypt step nor of one field, so it stays bare (Table 15's closing sentence).");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, decryptHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_Hash()</c> over a claiming XOR decrypt companion whose <c>data</c> — the decrypt-eligible FIRST
    /// parameter itself (Table 69, index 0) — declares a size past <c>TPM2B_MAX_BUFFER</c>'s own
    /// <c>MaxSize</c>: the parameter core's own re-parse of the recovered plaintext designates this exactly as
    /// the plain <c>TPM_ST_NO_SESSIONS</c> form would, and the decrypt continuation's already-designated guard
    /// passes it through unchanged rather than adding a session designation on top.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 15.4, Table 69; Part 2, clause 6.6.2, Table 15</see>.
    /// </summary>
    [TestMethod]
    public async Task HashOverADecryptCompanionWithAnOverBoundDataAnswersTheParameterEncodedSizeUnchanged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        //data declares one octet past Tpm2bMaxBuffer.MaxSize, its full declared content present — the decrypt
        //step's own generic size-field preamble must see a parameter area at least as wide as the declared
        //size, or it refuses first with its OWN (session-encoded) failure instead of ever reaching the
        //parameter core's re-parse.
        int dataSize = Tpm2bMaxBuffer.MaxSize + 1;
        byte[] parameters = new byte[sizeof(ushort) + dataSize];
        BinaryPrimitives.WriteUInt16BigEndian(parameters.AsSpan(0, sizeof(ushort)), (ushort)dataSize);

        (uint decryptHandle, TpmSession decryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(
            device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        try
        {
            using(decryptSession)
            {
                decryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                byte[] authArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(
                    decryptSession, TpmCcConstants.TPM_CC_Hash, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                TpmRcConstants code = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_Hash, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(
                    HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), code,
                    "data is TPM2_Hash()'s first parameter (Table 69, index 0); its own declared over-bound size is the parameter core's designation, passed through the decrypt continuation unchanged rather than session-encoded.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, decryptHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_VerifySignature()</c> over a claiming XOR decrypt companion, addressed at a genuine, resolvable
    /// key, whose <c>digest</c> — the decrypt-eligible FIRST parameter itself (Table 116, index 0) — declares a
    /// size past <c>TPM2B_DIGEST</c>'s own <c>MaxSize</c>: the same already-designated passthrough
    /// <see cref="HashOverADecryptCompanionWithAnOverBoundDataAnswersTheParameterEncodedSizeUnchanged"/> proves,
    /// for a command whose handle DOES need resolving before the parameter core ever runs.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 20.2, Table 116; Part 2, clause 6.6.2, Table 15</see>.
    /// </summary>
    [TestMethod]
    public async Task VerifySignatureOverADecryptCompanionWithAnOverBoundDigestAnswersTheParameterEncodedSizeUnchanged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await Shared.CreateOperationalWithEccBackendAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);

        using CreatePrimaryInput createInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            device, createInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"TPM2_CreatePrimary() must succeed: '{createResult.ResponseCode}'.");
        using CreatePrimaryResponse primary = createResult.Value;

        //digest declares one octet past Tpm2bDigest.MaxSize, its full declared content present — for the same
        //reason the sibling Hash row needs it: the decrypt step's own generic size-field preamble must see a
        //parameter area at least as wide as the declared size.
        int digestSize = Tpm2bDigest.MaxSize + 1;
        byte[] parameters = new byte[sizeof(ushort) + digestSize];
        BinaryPrimitives.WriteUInt16BigEndian(parameters.AsSpan(0, sizeof(ushort)), (ushort)digestSize);

        (uint decryptHandle, TpmSession decryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(
            device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        try
        {
            using(decryptSession)
            {
                decryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                byte[] authArea = await Shared.BuildSessionAuthAreaOverHandleAsync(
                    decryptSession, TpmCcConstants.TPM_CC_VerifySignature, primary.Name.AsReadOnlyMemory(), parameters, pool).ConfigureAwait(false);

                (TpmRcConstants code, _) = await Shared.SubmitOverHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_VerifySignature, primary.ObjectHandle.Value, authArea, parameters).ConfigureAwait(false);

                Assert.AreEqual(
                    HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), code,
                    "digest is TPM2_VerifySignature()'s first parameter (Table 116, index 0); its own declared over-bound size is the parameter core's designation, passed through the decrypt continuation unchanged rather than session-encoded.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, decryptHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, primary.ObjectHandle.Value).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_MakeCredential()</c> over a claiming XOR decrypt companion, addressed at a genuine, resolvable
    /// key, whose <c>credential</c> — the decrypt-eligible FIRST parameter itself (Table 28, index 0) —
    /// declares a size past <c>TPM2B_DIGEST</c>'s own <c>MaxSize</c>: the same already-designated passthrough
    /// the sibling rows prove, for a command whose bound check runs AFTER a full, in-bound <c>TPM2B</c> read
    /// (unlike the bounded-reader shape the other rows exercise).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.6, Table 28; Part 2, clause 6.6.2, Table 15</see>.
    /// </summary>
    [TestMethod]
    public async Task MakeCredentialOverADecryptCompanionWithAnOverBoundCredentialAnswersTheParameterEncodedSizeUnchanged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await Shared.CreateOperationalWithEccBackendAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);

        using CreatePrimaryInput createInput = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            device, createInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"TPM2_CreatePrimary() must succeed: '{createResult.ResponseCode}'.");
        using CreatePrimaryResponse primary = createResult.Value;

        //credential declares one octet past Tpm2bDigest.MaxSize; its full declared content must still be
        //present in the frame for the read to reach that bound check.
        int credentialSize = Tpm2bDigest.MaxSize + 1;
        byte[] parameters = new byte[sizeof(ushort) + credentialSize];
        BinaryPrimitives.WriteUInt16BigEndian(parameters.AsSpan(0, sizeof(ushort)), (ushort)credentialSize);

        (uint decryptHandle, TpmSession decryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(
            device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        try
        {
            using(decryptSession)
            {
                decryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                byte[] authArea = await Shared.BuildSessionAuthAreaOverHandleAsync(
                    decryptSession, TpmCcConstants.TPM_CC_MakeCredential, primary.Name.AsReadOnlyMemory(), parameters, pool).ConfigureAwait(false);

                (TpmRcConstants code, _) = await Shared.SubmitOverHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_MakeCredential, primary.ObjectHandle.Value, authArea, parameters).ConfigureAwait(false);

                Assert.AreEqual(
                    HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), code,
                    "credential is TPM2_MakeCredential()'s first parameter (Table 28, index 0); its own declared over-bound size is the parameter core's designation, passed through the decrypt continuation unchanged rather than session-encoded.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, decryptHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, primary.ObjectHandle.Value).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_Encapsulate()</c> over a PERSISTENT KEM key and an audit-only companion succeeds, the persistent
    /// object's own Name chained into cpHash and read back through the extended audit digest.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3,
    /// clause 14.10, Table 60 and Table 61; Part 1, clauses 15.7 and 17.1</see>.
    /// </summary>
    [TestMethod]
    public async Task EncapsulateOverAPersistentKeyAndAnAuditSlotSucceedsWithThePersistentNameChainedIntoTheAuditDigest()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await Shared.CreateOperationalWithEccBackendAsync(pool).ConfigureAwait(false);
        List<byte[]> responses = [];
        using TpmDevice device = CreateResponseCapturingDevice(simulator, responses);
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary)
            .Register(TpmCcConstants.TPM_CC_EvictControl, TpmResponseCodec.EvictControl)
            .Register(TpmCcConstants.TPM_CC_Encapsulate, TpmResponseCodec.Encapsulate)
            .Register(TpmCcConstants.TPM_CC_GetSessionAuditDigest, TpmResponseCodec.GetSessionAuditDigest);

        using CreatePrimaryInput kemInput = CreatePrimaryInput.ForEccKemKey(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmAlgIdConstants.TPM_ALG_SHA256, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> kemResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            device, kemInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(kemResult.IsSuccess, $"CreatePrimary (ECC KEM key) must succeed: '{kemResult.ResponseCode}'.");
        using CreatePrimaryResponse primary = kemResult.Value;

        TpmResult<EvictControlResponse> persistResult = await TpmEvictControlHarness.EvictControlAsync(
            device, registry, pool, primary.ObjectHandle.Value, PersistentKemKeyHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(persistResult.IsSuccess, $"EvictControl (persist) failed: '{persistResult.ResponseCode}'.");

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(auditSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                EncapsulateInput encapsulateInput = EncapsulateInput.ForHandle(TpmiDhObject.FromValue(PersistentKemKeyHandle));
                TpmResult<EncapsulateResponse> encapsulateResult = await TpmCommandExecutor.ExecuteAsync<EncapsulateResponse>(
                    device, encapsulateInput, [auditSession], handleNames: [primary.Name.AsReadOnlyMemory()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(encapsulateResult.IsSuccess, $"TPM2_Encapsulate() over the PERSISTENT key and an audit companion must succeed: '{encapsulateResult.ResponseCode}'.");
                encapsulateResult.Value.Dispose();

                byte[] expectedDigest = await ComputeExpectedDigestWithNameAsync(
                    null, TpmCcConstants.TPM_CC_Encapsulate, primary.Name.AsReadOnlyMemory(), ReadOnlyMemory<byte>.Empty, responses[^1], outHandleCount: 0, pool).ConfigureAwait(false);

                using GetSessionAuditDigestInput auditDigestInput = GetSessionAuditDigestInput.ForNullSigner(TpmiShHmac.FromValue(auditHandle), ReadOnlySpan<byte>.Empty, pool);
                using TpmPasswordSession endorsementForDigest = TpmPasswordSession.CreateEmpty(pool);
                using TpmPasswordSession nullSignerSlot = TpmPasswordSession.CreateEmpty(pool);
                TpmResult<GetSessionAuditDigestResponse> digestResult = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                    device, auditDigestInput, [endorsementForDigest, nullSignerSlot], handleNames: null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(digestResult.IsSuccess, $"TPM2_GetSessionAuditDigest() must succeed: '{digestResult.ResponseCode}'.");
                using GetSessionAuditDigestResponse auditDigestResponse = digestResult.Value;

                Assert.IsTrue(
                    expectedDigest.AsSpan().SequenceEqual(auditDigestResponse.SessionAudit.SessionDigest.AsReadOnlySpan()),
                    "The audit digest must equal H(0…0 ‖ cpHash ‖ rpHash) with the PERSISTENT KEM key's own Name folded into cpHash.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_MakeCredential()</c> over a decrypt-only companion recovers <c>credential</c> before wrapping it;
    /// the resulting <c>credentialBlob</c>/<c>secret</c> pair activates through <c>TPM2_ActivateCredential()</c>
    /// and recovers the SAME secret the test wrapped, proving the recovered plaintext — not the ciphertext that
    /// rode the wire — was the value actually protected.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3,
    /// clause 12.6, Table 28</see>.
    /// </summary>
    [TestMethod]
    public async Task MakeCredentialOverADecryptSlotSucceedsAndTheDecryptedCredentialActivates()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await Shared.CreateOperationalWithEccBackendAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary)
            .Register(TpmCcConstants.TPM_CC_MakeCredential, TpmResponseCodec.MakeCredential)
            .Register(TpmCcConstants.TPM_CC_ActivateCredential, TpmResponseCodec.ActivateCredential);

        using CreatePrimaryInput storageInput = CreatePrimaryInput.ForEccStorageParent(TpmRh.TPM_RH_ENDORSEMENT, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession endorsementAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> storageResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            device, storageInput, [endorsementAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(storageResult.IsSuccess, $"CreatePrimary (storage key, EK stand-in) must succeed: '{storageResult.ResponseCode}'.");
        using CreatePrimaryResponse ek = storageResult.Value;

        using CreatePrimaryInput signingInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> akResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            device, signingInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(akResult.IsSuccess, $"CreatePrimary (attestation key) must succeed: '{akResult.ResponseCode}'.");
        using CreatePrimaryResponse ak = akResult.Value;

        byte[] credentialSecret = [0x50, 0x51, 0x52, 0x53];

        (uint decryptHandle, TpmSession decryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        byte[] credentialBlob;
        byte[] secret;
        try
        {
            using(decryptSession)
            {
                decryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                using MakeCredentialInput makeInput = MakeCredentialInput.Create(ek.ObjectHandle, credentialSecret, ak.Name.Span.ToArray(), pool);
                TpmResult<MakeCredentialResponse> makeResult = await TpmCommandExecutor.ExecuteAsync<MakeCredentialResponse>(
                    device, makeInput, [decryptSession], handleNames: [ek.Name.AsReadOnlyMemory()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(makeResult.IsSuccess, $"TPM2_MakeCredential() over a decrypt companion must succeed: '{makeResult.ResponseCode}'.");
                using MakeCredentialResponse made = makeResult.Value;
                credentialBlob = made.CredentialBlob.Span.ToArray();
                secret = made.Secret.Span.ToArray();
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, decryptHandle).ConfigureAwait(false);
        }

        using ActivateCredentialInput activateInput = ActivateCredentialInput.Create(ak.ObjectHandle, ek.ObjectHandle, credentialBlob, secret, pool);
        using TpmPasswordSession activateAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<ActivateCredentialResponse> activateResult = await TpmCommandExecutor.ExecuteAsync<ActivateCredentialResponse>(
            device, activateInput, [activateAuth, keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(activateResult.IsSuccess, $"TPM2_ActivateCredential() must succeed, proving the decrypted credential equals the plain form's own wrap: '{activateResult.ResponseCode}'.");
        using ActivateCredentialResponse activated = activateResult.Value;
        Assert.AreSequenceEqual(credentialSecret, activated.CertInfo.AsReadOnlySpan().ToArray(), "The recovered credential must equal the secret TPM2_MakeCredential() wrapped over the decrypt companion.");

        await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, ak.ObjectHandle.Value).ConfigureAwait(false);
        await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, ek.ObjectHandle.Value).ConfigureAwait(false);
    }

    /// <summary>
    /// A LOADED policy session at <c>TPM2_MakeCredential()</c>'s sole companion slot, claiming BOTH
    /// <c>decrypt</c> and <c>encrypt</c>, is admitted exactly like an HMAC companion — TPM 2.0 Library Part 1,
    /// Table 12, footnote [2]: "a policy authorization session can also be used for encryption and decryption."
    /// <c>credential</c> is decrypted before it is wrapped and <c>credentialBlob</c> is returned encrypted
    /// (Part 3, clause 12.6, Table 28): both directions run under the SAME session's key, and
    /// <c>TPM2_ActivateCredential()</c> recovering the exact secret the test wrapped is the only outcome
    /// consistent with the simulator having genuinely decrypted the command parameter and encrypted the response
    /// one, rather than passing either through unchanged.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1,
    /// clause 15.6.1, Table 12, footnote [2], and clause 18.1; Part 3, clause 12.6, Table 28</see>.
    /// </summary>
    [TestMethod]
    public async Task MakeCredentialOverAPolicyCompanionClaimingBothDecryptAndEncryptActivates()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await Shared.CreateOperationalWithEccBackendAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary)
            .Register(TpmCcConstants.TPM_CC_MakeCredential, TpmResponseCodec.MakeCredential)
            .Register(TpmCcConstants.TPM_CC_ActivateCredential, TpmResponseCodec.ActivateCredential);

        using CreatePrimaryInput storageInput = CreatePrimaryInput.ForEccStorageParent(TpmRh.TPM_RH_ENDORSEMENT, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession endorsementAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> storageResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            device, storageInput, [endorsementAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(storageResult.IsSuccess, $"CreatePrimary (storage key, EK stand-in) must succeed: '{storageResult.ResponseCode}'.");
        using CreatePrimaryResponse ek = storageResult.Value;

        using CreatePrimaryInput signingInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> akResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            device, signingInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(akResult.IsSuccess, $"CreatePrimary (attestation key) must succeed: '{akResult.ResponseCode}'.");
        using CreatePrimaryResponse ak = akResult.Value;

        byte[] credentialSecret = [0x60, 0x61, 0x62, 0x63];

        (uint policyHandle, TpmSession policySession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(
            device, registry, pool, TestContext.CancellationToken, SessionSymmetric, TpmSeConstants.TPM_SE_POLICY).ConfigureAwait(false);
        byte[] credentialBlob;
        byte[] secret;
        try
        {
            using(policySession)
            {
                policySession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT | TpmaSession.ENCRYPT;

                using MakeCredentialInput makeInput = MakeCredentialInput.Create(ek.ObjectHandle, credentialSecret, ak.Name.Span.ToArray(), pool);
                TpmResult<MakeCredentialResponse> makeResult = await TpmCommandExecutor.ExecuteAsync<MakeCredentialResponse>(
                    device, makeInput, [policySession], handleNames: [ek.Name.AsReadOnlyMemory()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(makeResult.IsSuccess, $"TPM2_MakeCredential() over a policy companion claiming both decrypt and encrypt must succeed: '{makeResult.ResponseCode}'.");
                using MakeCredentialResponse made = makeResult.Value;
                credentialBlob = made.CredentialBlob.Span.ToArray();
                secret = made.Secret.Span.ToArray();
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, policyHandle).ConfigureAwait(false);
        }

        using ActivateCredentialInput activateInput = ActivateCredentialInput.Create(ak.ObjectHandle, ek.ObjectHandle, credentialBlob, secret, pool);
        using TpmPasswordSession activateAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<ActivateCredentialResponse> activateResult = await TpmCommandExecutor.ExecuteAsync<ActivateCredentialResponse>(
            device, activateInput, [activateAuth, keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(activateResult.IsSuccess, $"TPM2_ActivateCredential() must succeed, proving the decrypted credential equals the plain form's own wrap: '{activateResult.ResponseCode}'.");
        using ActivateCredentialResponse activated = activateResult.Value;
        Assert.AreSequenceEqual(credentialSecret, activated.CertInfo.AsReadOnlySpan().ToArray(), "The recovered credential must equal the secret TPM2_MakeCredential() wrapped over the policy companion claiming both directions.");

        await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, ak.ObjectHandle.Value).ConfigureAwait(false);
        await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, ek.ObjectHandle.Value).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>TPM2_MakeCredential()</c> over an audit-claiming companion, addressed at a genuine object that is NOT a
    /// storage parent, answers the inner's own <c>TPM_RC_TYPE</c>, handle-encoded to the same index — judged only AFTER the audit companion
    /// verifies, since the handle's Name still resolves and the storage-parent check is the inner transition's
    /// own gate, not the resolve step's; the session's nonceTPM is left untouched afterward.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3,
    /// clauses 5.4, 5.5 and 12.6</see>.
    /// </summary>
    [TestMethod]
    public async Task MakeCredentialOverAnAuditSlotWithANonStorageKeyHandleAnswersTheInnersBareTypeAfterTheAuditCompanionVerifies()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await Shared.CreateOperationalWithEccBackendAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary)
            .Register(TpmCcConstants.TPM_CC_MakeCredential, TpmResponseCodec.MakeCredential);

        using CreatePrimaryInput signingInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> signingResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            device, signingInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signingResult.IsSuccess, $"CreatePrimary (signing key) must succeed: '{signingResult.ResponseCode}'.");
        using CreatePrimaryResponse nonStorageKey = signingResult.Value;

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(auditSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                using MakeCredentialInput makeInput = MakeCredentialInput.Create(nonStorageKey.ObjectHandle, [0x01], nonStorageKey.Name.Span.ToArray(), pool);
                TpmResult<MakeCredentialResponse> makeResult = await TpmCommandExecutor.ExecuteAsync<MakeCredentialResponse>(
                    device, makeInput, [auditSession], handleNames: [nonStorageKey.Name.AsReadOnlyMemory()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_TYPE, 0), makeResult.ResponseCode, "A non-storage-parent handle is refused at handle, handle 1 of Table 28, judged only after the audit companion verifies.");

                byte[] followUpParameters = TpmInHouseSimulatorZeroHandleSessionTests.ParameterAreaFor(TpmCcConstants.TPM_CC_TestParms, pool);
                byte[] followUpAuthArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_TestParms, followUpParameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                TpmRcConstants followUpCode = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_TestParms, followUpAuthArea, followUpParameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, followUpCode, "The session's nonceTPM was left untouched by the refusal, so a genuine follow-up command over it still verifies.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, nonStorageKey.ObjectHandle.Value).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The <see cref="MeteredHousePool"/> balance across a three-entry <c>TPM2_Hash()</c> success, an
    /// <c>TPM2_Encapsulate()</c> encrypt-companion success, a <c>TPM2_HashSequenceStart()</c> companion HMAC
    /// refusal, and a <c>TPM2_MakeCredential()</c> inner-core refusal — every rented carrier across all four
    /// paths comes back.
    /// </summary>
    [TestMethod]
    public async Task NoAuthorizationKeyCommandsReturnTheirCarriersAcrossAThreeEntrySuccessAnEncryptSuccessABadAuthRefusalAndAnInnerRefusal()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;

        using TpmSimulator simulator = await Shared.CreateOperationalWithEccBackendAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary)
            .Register(TpmCcConstants.TPM_CC_Encapsulate, TpmResponseCodec.Encapsulate)
            .Register(TpmCcConstants.TPM_CC_HashSequenceStart, TpmResponseCodec.HashSequenceStart)
            .Register(TpmCcConstants.TPM_CC_MakeCredential, TpmResponseCodec.MakeCredential);

        long baseline = trackingPool.OutstandingCount;

        //A three-entry TPM2_Hash() success: audit, decrypt and encrypt together.
        {
            byte[] data = [0x21, 0x22];
            TpmiAlgHash hashAlg = TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256);
            byte[] parameters;
            using(HashInput hashInput = HashInput.Create(data, hashAlg, TpmiRhHierarchy.Null, pool))
            {
                parameters = SerializeParameters(hashInput, pool);
            }

            (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
            (uint decryptHandle, TpmSession decryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
            (uint encryptHandle, TpmSession encryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
            try
            {
                using(auditSession)
                using(decryptSession)
                using(encryptSession)
                {
                    auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                    decryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;
                    encryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                    byte[] decryptBlock = await BuildDecryptCompanionBlockAsync(decryptSession, TpmCcConstants.TPM_CC_Hash, parameters, sizeof(ushort), data.Length, pool).ConfigureAwait(false);
                    byte[] auditBlock = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_Hash, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                    byte[] encryptBlock = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(encryptSession, TpmCcConstants.TPM_CC_Hash, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                    byte[] authArea = [.. auditBlock, .. decryptBlock, .. encryptBlock];

                    (TpmRcConstants code, byte[] response) = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleForAuditAsync(
                        simulator, pool, TpmCcConstants.TPM_CC_Hash, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "The three-entry Hash round trip must actually succeed for its balance to prove anything.");

                    byte[] decryptedOutHashArea = await DecryptResponseFirstParameterAsync(encryptSession, response, 0, 2, TpmCcConstants.TPM_CC_Hash, pool).ConfigureAwait(false);
                    _ = decryptedOutHashArea;
                }
            }
            finally
            {
                await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
                await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, decryptHandle).ConfigureAwait(false);
                await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, encryptHandle).ConfigureAwait(false);
            }

            Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The three-entry Hash success must return every carrier it rented.");
        }

        //An Encapsulate encrypt-companion success.
        {
            uint encryptHandle;
            uint kemPrimaryHandle;
            using(CreatePrimaryInput kemInput = CreatePrimaryInput.ForEccKemKey(
                TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmAlgIdConstants.TPM_ALG_SHA256, pool, noDa: true))
            using(TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool))
            {
                TpmResult<CreatePrimaryResponse> kemResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
                    device, kemInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(kemResult.IsSuccess, $"CreatePrimary (ECC KEM key) must succeed: '{kemResult.ResponseCode}'.");
                using CreatePrimaryResponse kemPrimary = kemResult.Value;
                kemPrimaryHandle = kemPrimary.ObjectHandle.Value;

                (encryptHandle, TpmSession encryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
                try
                {
                    using(encryptSession)
                    {
                        encryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                        EncapsulateInput encapsulateInput = EncapsulateInput.ForHandle(kemPrimary.ObjectHandle);
                        TpmResult<EncapsulateResponse> encapsulateResult = await TpmCommandExecutor.ExecuteAsync<EncapsulateResponse>(
                            device, encapsulateInput, [encryptSession], handleNames: [kemPrimary.Name.AsReadOnlyMemory()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                        Assert.IsTrue(encapsulateResult.IsSuccess, $"TPM2_Encapsulate() over an encrypt companion must actually succeed for its balance to prove anything: '{encapsulateResult.ResponseCode}'.");
                        encapsulateResult.Value.Dispose();
                    }
                }
                finally
                {
                    await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, encryptHandle).ConfigureAwait(false);
                    await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, kemPrimaryHandle).ConfigureAwait(false);
                }
            }

            Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The Encapsulate encrypt success must return every carrier it rented.");
        }

        //A HashSequenceStart companion HMAC refusal.
        {
            uint sessionHandle;
            using(HashSequenceStartInput startInput = HashSequenceStartInput.CreateFromPassword("pool-balance-bad-auth", TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256), pool))
            {
                byte[] parameters = SerializeParameters(startInput, pool);

                (sessionHandle, TpmSession session) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
                try
                {
                    using(session)
                    {
                        session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                        byte[] authArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(session, TpmCcConstants.TPM_CC_HashSequenceStart, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                        authArea[^1] ^= 0xFF;

                        TpmRcConstants code = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                            simulator, pool, TpmCcConstants.TPM_CC_HashSequenceStart, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);
                        Assert.AreEqual(
                            TpmInHouseSimulatorZeroHandleSessionTests.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), code,
                            "The companion HMAC refusal must actually refuse for its balance to prove anything.");
                    }
                }
                finally
                {
                    await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
                }
            }

            Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The BAD_AUTH refusal must return every carrier it rented.");
        }

        //A MakeCredential inner-core (non-storage-key) refusal.
        {
            uint auditHandle;
            uint nonStorageKeyHandle;
            using(CreatePrimaryInput signingInput = CreatePrimaryInput.ForEccSigningKey(
                TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true))
            using(TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool))
            {
                TpmResult<CreatePrimaryResponse> signingResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
                    device, signingInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(signingResult.IsSuccess, $"CreatePrimary (signing key) must succeed: '{signingResult.ResponseCode}'.");
                using CreatePrimaryResponse nonStorageKey = signingResult.Value;
                nonStorageKeyHandle = nonStorageKey.ObjectHandle.Value;

                (auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
                try
                {
                    using(auditSession)
                    {
                        auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                        using MakeCredentialInput makeInput = MakeCredentialInput.Create(nonStorageKey.ObjectHandle, [0x02], nonStorageKey.Name.Span.ToArray(), pool);
                        TpmResult<MakeCredentialResponse> makeResult = await TpmCommandExecutor.ExecuteAsync<MakeCredentialResponse>(
                            device, makeInput, [auditSession], handleNames: [nonStorageKey.Name.AsReadOnlyMemory()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_TYPE, 0), makeResult.ResponseCode, "The inner-core refusal must actually refuse for its balance to prove anything.");
                    }
                }
                finally
                {
                    await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
                    await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, nonStorageKeyHandle).ConfigureAwait(false);
                }
            }

            Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The MakeCredential inner-core refusal must return every carrier it rented, including the request's own inner value.");
        }
    }

    /// <summary>
    /// Rolls <paramref name="session"/>'s own nonceCaller ONCE, encrypts the first parameter octets in place
    /// under its key — the client-side keystream a decrypt companion applies before cpHash is computed
    /// (<paramref name="parameters"/> is mutated in place, becoming the wire's own ciphertext) — then builds this
    /// session's own <c>TPMS_AUTH_COMMAND</c> block over the resulting cpHash, its HMAC keyed on the SAME
    /// nonceCaller the encryption used.
    /// </summary>
    /// <param name="session">The decrypt-claiming companion session.</param>
    /// <param name="commandCode">The command code the HMAC commits to.</param>
    /// <param name="parameters">The plaintext parameter area, mutated in place to ciphertext.</param>
    /// <param name="firstParameterOffset">The octet offset of the first TPM2B's data, past its own size field.</param>
    /// <param name="firstParameterLength">The first TPM2B's data length.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The block's octets, without the authorizationSize field that precedes them.</returns>
    private async Task<byte[]> BuildDecryptCompanionBlockAsync(
        TpmSession session, TpmCcConstants commandCode, byte[] parameters, int firstParameterOffset, int firstParameterLength, BaseMemoryPool pool)
    {
        session.RollNonceCaller(pool);
        await session.EncryptFirstParameterAsync(parameters.AsMemory(firstParameterOffset, firstParameterLength), pool, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] cpHash = await TpmInHouseSimulatorZeroHandleSessionTests.ComputeZeroHandleCpHashAsync(commandCode, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using Tpm2bAuth? hmac = await session.PrepareAuthHmacAsync(cpHash, pool, TestContext.CancellationToken).ConfigureAwait(false);

        int blockSize = session.GetAuthCommandSize();
        using IMemoryOwner<byte> blockOwner = pool.Rent(blockSize);
        Memory<byte> block = blockOwner.Memory[..blockSize];
        var writer = new TpmWriter(block.Span);
        session.WriteAuthCommand(ref writer, hmac);

        return block.Span.ToArray();
    }

    /// <summary>
    /// Verifies <paramref name="session"/>'s own response-session entry at <paramref name="sessionIndex"/> — which
    /// adopts the response's freshly rolled nonceTPM (TPM 2.0 Library Part 1, clause 16.6.3.1) — then decrypts the
    /// captured response's first parameter under that session's key. rpHash is computed BEFORE decrypting, over
    /// the octets exactly as the wire carried them: "Parameters in responses are encrypted before any rpHash is
    /// computed."
    /// </summary>
    /// <param name="session">The encrypt-claiming companion session.</param>
    /// <param name="rawResponse">The captured raw response octets.</param>
    /// <param name="outHandleCount">The number of response handles preceding the parameter area.</param>
    /// <param name="sessionIndex">This session's own zero-based position in the authorization area.</param>
    /// <param name="commandCode">The command code rpHash commits to.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The response parameter octets with the first TPM2B's data decrypted in place.</returns>
    private async Task<byte[]> DecryptResponseFirstParameterAsync(
        TpmSession session, byte[] rawResponse, int outHandleCount, int sessionIndex, TpmCcConstants commandCode, BaseMemoryPool pool)
    {
        byte[] responseParameters = TpmInHouseSimulatorZeroHandleSessionTests.ReadResponseParameters(rawResponse, outHandleCount);
        byte[] rpHash = await TpmInHouseSimulatorZeroHandleSessionTests.ComputeRpHashAsync(commandCode, responseParameters, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmsAuthResponse entry = ReadResponseSessionEntry(rawResponse, outHandleCount, sessionIndex, pool);
        bool verified = await session.VerifyAndUpdateAsync(entry, rpHash, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(verified, "The encrypt companion's own response HMAC must verify under its session key before its first parameter is decrypted.");

        ushort firstParameterLength = BinaryPrimitives.ReadUInt16BigEndian(responseParameters);
        await session.DecryptFirstParameterAsync(responseParameters.AsMemory(sizeof(ushort), firstParameterLength), pool, TestContext.CancellationToken).ConfigureAwait(false);

        return responseParameters;
    }

    /// <summary>
    /// Chains the audit digest fold the test itself computes from the octets it sent and read, with the addressed
    /// handle's own Name folded into cpHash ahead of the parameters (TPM 2.0 Library Part 1, clause 15.7,
    /// equation 15) — the one-handle no-authorization commands' own cpHash shape.
    /// </summary>
    /// <param name="oldDigest">The digest before this command, or <see langword="null"/> for the Zero Digest.</param>
    /// <param name="commandCode">The audited command's own code.</param>
    /// <param name="nameOctets">The addressed handle's Name term.</param>
    /// <param name="commandParameters">The command's parameter area exactly as sent.</param>
    /// <param name="capturedResponse">The raw response octets the simulator returned.</param>
    /// <param name="outHandleCount">The number of response handles preceding the parameter area.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The expected post-command audit digest.</returns>
    private async Task<byte[]> ComputeExpectedDigestWithNameAsync(
        byte[]? oldDigest, TpmCcConstants commandCode, ReadOnlyMemory<byte> nameOctets, ReadOnlyMemory<byte> commandParameters, byte[] capturedResponse, int outHandleCount, BaseMemoryPool pool)
    {
        byte[] responseParameters = TpmInHouseSimulatorZeroHandleSessionTests.ReadResponseParameters(capturedResponse, outHandleCount);
        byte[] cpHash = await Shared.ComputeCpHashWithNameAsync(commandCode, nameOctets, commandParameters, pool).ConfigureAwait(false);
        byte[] rpHash = await TpmInHouseSimulatorZeroHandleSessionTests.ComputeRpHashAsync(commandCode, responseParameters, pool, TestContext.CancellationToken).ConfigureAwait(false);

        return await TpmInHouseSimulatorZeroHandleSessionTests.ExtendAuditDigestAsync(oldDigest, cpHash, rpHash, pool, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Reads one response-session entry out of a captured raw response's authorization area by index, disposing
    /// every entry read before it.
    /// </summary>
    /// <param name="responseBytes">The raw response octets.</param>
    /// <param name="outHandleCount">The number of response handles preceding the parameter area.</param>
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

    /// <summary>Reads a captured raw response's own single response handle, ahead of its (possibly empty) parameter area.</summary>
    /// <param name="responseBytes">The raw response octets.</param>
    /// <returns>The response handle's value.</returns>
    private static uint ReadResponseHandle(byte[] responseBytes)
    {
        var reader = new TpmReader(responseBytes);
        _ = TpmHeader.Parse(ref reader);

        return reader.ReadUInt32();
    }

    /// <summary>Serializes one command input's parameter area (excluding any handle area) into a standalone array.</summary>
    /// <param name="input">The command input.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The parameter octets.</returns>
    private static byte[] SerializeParameters(ITpmCommandInput input, BaseMemoryPool pool)
    {
        int upperBound = input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(Math.Max(upperBound, 1));
        Memory<byte> scratch = owner.Memory[..upperBound];
        var writer = new TpmWriter(scratch.Span);
        input.WriteParameters(ref writer);

        return scratch.Span[..writer.Written].ToArray();
    }

    /// <summary>
    /// Wraps the simulator in a device that records every response's raw octets, in submission order, so a test
    /// can independently re-derive cpHash/rpHash from what the wire actually carried while still driving the
    /// command through the production <see cref="TpmCommandExecutor"/>.
    /// </summary>
    /// <param name="simulator">The simulator under test.</param>
    /// <param name="responses">The list every response's octets are appended to (empty on a refusal).</param>
    /// <returns>The capturing device; the caller owns it.</returns>
    private static TpmDevice CreateResponseCapturingDevice(TpmSimulator simulator, List<byte[]> responses) =>
        TpmDevice.Create(async (command, pool, cancellationToken) =>
        {
            TpmResult<TpmResponse> result = await simulator.SubmitAsync(command, pool, cancellationToken).ConfigureAwait(false);
            responses.Add(result.IsSuccess ? result.Value.AsReadOnlySpan().ToArray() : []);

            return result;
        }, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

    /// <summary>
    /// Each of the six key commands whose handle slot is typed <c>TPMI_DH_OBJECT</c> with no authorization
    /// (<c>TPM2_SignSequenceStart()</c> Table 87, <c>TPM2_VerifySequenceStart()</c> Table 89,
    /// <c>TPM2_VerifySignature()</c> Table 116, <c>TPM2_VerifyDigestSignature()</c> Table 120,
    /// <c>TPM2_Encapsulate()</c> Table 60, <c>TPM2_MakeCredential()</c> Table 28 — <c>TPM2_RSA_Encrypt()</c>,
    /// Table 44, is pinned separately in <c>TpmInHouseSimulatorRsaEncryptTests</c> and
    /// <c>TpmInHouseSimulatorRsaEncryptSessionTests</c> since it needs its own RSA-backed simulator) refuses an
    /// NV-index, PCR, session or hierarchy-range handle with <c>TPM_RC_VALUE</c> at parse, before any
    /// authorization area is ever read: "The TPM shall successfully unmarshal the number of handles required by
    /// the command and validate that the value of the handle is consistent with the command syntax. If not, the
    /// TPM shall return TPM_RC_VALUE." Table 15/16's designation is unconditional on the command's own framing,
    /// so both the plain form's dedicated per-command parser and the over-sessions form's shared
    /// no-authorization wrapper designate the refusal to this sole handle's own index 0 (H1) alike. Over the
    /// sessions form, a genuine, loaded audit companion is never
    /// reached at all — its nonceTPM stays usable for a genuine follow-up. A well-typed but unresolved transient
    /// handle answers the plain form's own resolution code,
    /// <c>TPM_RC_REFERENCE_H0</c> (clause 5.4, step 2.1) — already pinned per-command elsewhere for
    /// <c>TPM2_VerifySequenceStart()</c> (<c>TpmInHouseSimulatorVerifySequenceTests.VerifySequenceStartOnAnUnknownHandleReturnsReferenceH0</c>),
    /// <c>TPM2_VerifySignature()</c> (<c>TpmInHouseSimulatorVerifySignatureTests</c>'s own unknown-keyHandle
    /// case) and <c>TPM2_SignSequenceStart()</c> (<c>TpmInHouseSimulatorSignSequenceHardeningTests</c>'s
    /// post-flush handle cases) — proved directly here instead for <c>TPM2_VerifyDigestSignature()</c>,
    /// <c>TPM2_Encapsulate()</c> and <c>TPM2_MakeCredential()</c>, which carry no such pin elsewhere. The same
    /// three also prove the persistent-range complement (clause 5.4 step 2.2): an unallocated persistent handle
    /// answers <c>TPM_RC_HANDLE</c> designated to the same sole handle's index 0, not the transient-only step
    /// 2.1 code.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3,
    /// clause 5.4, steps 1, 2.1 and 2.2; Part 2, clause 9.3, Table 49</see>.
    /// </summary>
    [TestMethod]
    [DataRow(TpmCcConstants.TPM_CC_SignSequenceStart, DisplayName = "TPM2_SignSequenceStart()")]
    [DataRow(TpmCcConstants.TPM_CC_VerifySequenceStart, DisplayName = "TPM2_VerifySequenceStart()")]
    [DataRow(TpmCcConstants.TPM_CC_VerifySignature, DisplayName = "TPM2_VerifySignature()")]
    [DataRow(TpmCcConstants.TPM_CC_VerifyDigestSignature, DisplayName = "TPM2_VerifyDigestSignature()")]
    [DataRow(TpmCcConstants.TPM_CC_Encapsulate, DisplayName = "TPM2_Encapsulate()")]
    [DataRow(TpmCcConstants.TPM_CC_MakeCredential, DisplayName = "TPM2_MakeCredential()")]
    public async Task MistypedHandleAnswersHandleEncodedValueOnBothThePlainAndSessionsForm(TpmCcConstants commandCode)
    {
        const uint NvIndexHandle = 0x0100_0001u;
        const uint PcrHandle = 0x0000_0001u;
        const uint SessionHandle = 0x0200_0001u;
        const uint HierarchyHandle = 0x4000_0001u;
        const uint UnknownTransientHandle = 0x8000_9999u;
        const uint UnallocatedPersistentHandle = 0x8100_9999u;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await Shared.CreateOperationalWithEccBackendAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        foreach(uint mistypedHandle in (uint[])[NvIndexHandle, PcrHandle, SessionHandle, HierarchyHandle])
        {
            //Neither form ever reads a parameter octet before the range check fires, so an empty parameter area
            //suffices for both.
            (TpmRcConstants plainCode, byte[] plainResponse) = await Shared.SubmitPlainOverHandleAsync(simulator, pool, commandCode, mistypedHandle, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
            Assert.AreEqual(
                HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), plainCode,
                $"'{commandCode}': a handle of type 0x{(mistypedHandle >> 24):X2} is TPM_RC_VALUE designated to handle 1 (Table 15/16, H1) on the plain form too — the designation is unconditional on framing.");
            Assert.AreEqual((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, TpmInHouseSimulatorNoAuthSessionTests.ReadResponseTag(plainResponse), "A failed command frames TPM_ST_NO_SESSIONS regardless of the request's own tag.");
            Assert.HasCount(10, plainResponse, "A failed command's response is exactly the 10-octet header (Part 3, clause 5.9).");

            (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
            try
            {
                using(auditSession)
                {
                    auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                    //The range check runs before any authorization area is read (clause 5.4 precedes clause
                    //5.5), so an empty area suffices — the octets that would follow the mistyped handle are
                    //never inspected.
                    (TpmRcConstants sessionCode, byte[] sessionResponse) = await Shared.SubmitOverHandleAsync(simulator, pool, commandCode, mistypedHandle, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

                    //keyHandle (or equivalent) is this command's sole handle, Auth Index None, index 0 (its own
                    //Part 3 table, cited in this test's own doc comment) — the over-sessions form routes
                    //through the shared no-authorization wrapper, which designates it H1 (Table 15/16).
                    Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), sessionCode, $"'{commandCode}': a handle of type 0x{(mistypedHandle >> 24):X2} is TPM_RC_VALUE designated to handle 1 on the over-sessions form, ahead of the authorization area.");
                    Assert.AreEqual((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, TpmInHouseSimulatorNoAuthSessionTests.ReadResponseTag(sessionResponse), "A failed command frames TPM_ST_NO_SESSIONS regardless of the request's own tag.");
                    Assert.HasCount(10, sessionResponse, "A failed command's response is exactly the 10-octet header (Part 3, clause 5.9).");

                    byte[] followUpParameters = TpmInHouseSimulatorZeroHandleSessionTests.ParameterAreaFor(TpmCcConstants.TPM_CC_TestParms, pool);
                    byte[] followUpAuthArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_TestParms, followUpParameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                    TpmRcConstants followUpCode = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                        simulator, pool, TpmCcConstants.TPM_CC_TestParms, followUpAuthArea, followUpParameters, TestContext.CancellationToken).ConfigureAwait(false);

                    Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, followUpCode, $"'{commandCode}': the session's nonceTPM was never touched by the parse-time refusal, so a genuine follow-up over it still verifies.");
                }
            }
            finally
            {
                await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
            }
        }

        if(commandCode is TpmCcConstants.TPM_CC_VerifyDigestSignature or TpmCcConstants.TPM_CC_Encapsulate or TpmCcConstants.TPM_CC_MakeCredential)
        {
            byte[] unresolvedParameters = CanonicalKeyCommandParameters(commandCode, UnknownTransientHandle, pool);
            (TpmRcConstants unresolvedCode, byte[] unresolvedResponse) = await Shared.SubmitPlainOverHandleAsync(simulator, pool, commandCode, UnknownTransientHandle, unresolvedParameters).ConfigureAwait(false);
            Assert.AreEqual(TpmRcConstants.TPM_RC_REFERENCE_H0, unresolvedCode, $"'{commandCode}': a well-typed but unresolved transient handle answers the plain form's own TPM_RC_REFERENCE_H0 — the range check judges the type octet only.");
            Assert.AreEqual((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, TpmInHouseSimulatorNoAuthSessionTests.ReadResponseTag(unresolvedResponse), "A failed command frames TPM_ST_NO_SESSIONS regardless of the request's own tag.");
            Assert.HasCount(10, unresolvedResponse, "A failed command's response is exactly the 10-octet header (Part 3, clause 5.9).");

            //The persistent-range complement (clause 5.4 step 2.2): an unallocated persistent handle answers
            //TPM_RC_HANDLE designated to the same sole handle's index 0, not the transient-only step 2.1 code.
            byte[] unallocatedParameters = CanonicalKeyCommandParameters(commandCode, UnallocatedPersistentHandle, pool);
            (TpmRcConstants unallocatedCode, byte[] unallocatedResponse) = await Shared.SubmitPlainOverHandleAsync(simulator, pool, commandCode, UnallocatedPersistentHandle, unallocatedParameters).ConfigureAwait(false);

            //The sole handle of each command's own table (keyHandle, handle 1 of Table 120 for
            //VerifyDigestSignature and of Table 60 for Encapsulate; handle, handle 1 of Table 28 for
            //MakeCredential) carries the same persistent-range-miss designation (clause 5.4 step 2.2).
            TpmRcConstants expectedUnallocatedCode = HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0);
            Assert.AreEqual(expectedUnallocatedCode, unallocatedCode, $"'{commandCode}': a well-typed but unallocated persistent handle is refused with the command's own attribution.");
            Assert.AreEqual((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, TpmInHouseSimulatorNoAuthSessionTests.ReadResponseTag(unallocatedResponse), "A failed command frames TPM_ST_NO_SESSIONS regardless of the request's own tag.");
            Assert.HasCount(10, unallocatedResponse, "A failed command's response is exactly the 10-octet header (Part 3, clause 5.9).");
        }
    }

    /// <summary>
    /// Builds a well-formed, minimal parameter area for one of the three key commands
    /// <see cref="MistypedHandleAnswersHandleEncodedValueOnBothThePlainAndSessionsForm"/> proves the unresolved-handle
    /// invariance for — enough to parse past the parameter core so the addressed handle reaches its own
    /// resolution step; content is otherwise irrelevant, since an unresolved handle always answers before any
    /// parameter content is inspected.
    /// </summary>
    /// <param name="commandCode">The command whose parameters to build.</param>
    /// <param name="handle">The handle value threaded into the input purely to satisfy its constructor — never
    /// itself serialized, since the parameter area excludes the handle (TPM 2.0 Library Part 3, clause 4.3).</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The parameter octets.</returns>
    private static byte[] CanonicalKeyCommandParameters(TpmCcConstants commandCode, uint handle, BaseMemoryPool pool)
    {
        var typedHandle = TpmiDhObject.FromValue(handle);

        return commandCode switch
        {
            TpmCcConstants.TPM_CC_VerifyDigestSignature => VerifyDigestSignatureParameters(typedHandle, pool),
            TpmCcConstants.TPM_CC_Encapsulate => SerializeParameters(EncapsulateInput.ForHandle(typedHandle), pool),
            TpmCcConstants.TPM_CC_MakeCredential => MakeCredentialParameters(typedHandle, pool),
            _ => throw new ArgumentOutOfRangeException(nameof(commandCode), commandCode, "Only the three commands the unresolved-handle case covers are framed here.")
        };
    }

    /// <summary>Builds a well-formed <c>TPM2_VerifyDigestSignature()</c> parameter area addressed at <paramref name="handle"/>.</summary>
    /// <param name="handle">The key handle threaded into the input purely to satisfy its constructor.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The parameter octets.</returns>
    private static byte[] VerifyDigestSignatureParameters(TpmiDhObject handle, BaseMemoryPool pool)
    {
        using VerifyDigestSignatureInput input = VerifyDigestSignatureInput.ForEcdsa(handle, new byte[32], new byte[64], TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        return SerializeParameters(input, pool);
    }

    /// <summary>Builds a well-formed <c>TPM2_MakeCredential()</c> parameter area addressed at <paramref name="handle"/>.</summary>
    /// <param name="handle">The key handle threaded into the input purely to satisfy its constructor.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The parameter octets.</returns>
    private static byte[] MakeCredentialParameters(TpmiDhObject handle, BaseMemoryPool pool)
    {
        using MakeCredentialInput input = MakeCredentialInput.Create(handle, new byte[4], new byte[4], pool);

        return SerializeParameters(input, pool);
    }

    /// <summary>
    /// Each of the six key commands whose handle slot is typed <c>TPMI_DH_OBJECT</c> refuses a WELL-TYPED but
    /// unresolved transient handle with <c>TPM_RC_REFERENCE_H0</c> (clause 5.4, step 2.1) on the over-sessions
    /// form too, ahead of a genuine, loaded audit companion: "A TPM is required to perform the handle area
    /// validation before the authorization checks because an authorization cannot be performed unless the
    /// authorization values and attributes for the referenced entity are known by the TPM" — the wire octets that
    /// would follow the handle are never inspected, so an empty parameter area suffices, and the companion's own
    /// nonceTPM stays usable for a genuine follow-up. <c>TPM2_RSA_Encrypt()</c> is pinned separately in
    /// <c>TpmInHouseSimulatorRsaEncryptSessionTests</c> since it needs its own RSA-backed simulator.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3,
    /// clause 5.4, step 2.1; clause 5.9</see>.
    /// </summary>
    [TestMethod]
    [DataRow(TpmCcConstants.TPM_CC_SignSequenceStart, DisplayName = "TPM2_SignSequenceStart()")]
    [DataRow(TpmCcConstants.TPM_CC_VerifySequenceStart, DisplayName = "TPM2_VerifySequenceStart()")]
    [DataRow(TpmCcConstants.TPM_CC_VerifySignature, DisplayName = "TPM2_VerifySignature()")]
    [DataRow(TpmCcConstants.TPM_CC_VerifyDigestSignature, DisplayName = "TPM2_VerifyDigestSignature()")]
    [DataRow(TpmCcConstants.TPM_CC_Encapsulate, DisplayName = "TPM2_Encapsulate()")]
    [DataRow(TpmCcConstants.TPM_CC_MakeCredential, DisplayName = "TPM2_MakeCredential()")]
    public async Task UnresolvedTransientHandleAnswersReferenceH0OverTheSessionsFormAheadOfTheAuditCompanion(TpmCcConstants commandCode)
    {
        const uint UnknownTransientHandle = 0x8000_9999u;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await Shared.CreateOperationalWithEccBackendAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(auditSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                //The handle fails to resolve before the session area is ever judged (clause 5.4 precedes clause
                //5.5), so an empty parameter area suffices — the auth area's own Name term is irrelevant since
                //the session's HMAC is never checked once resolution has already failed.
                byte[] authArea = await Shared.BuildSessionAuthAreaOverHandleAsync(auditSession, commandCode, ReadOnlyMemory<byte>.Empty, [], pool).ConfigureAwait(false);
                (TpmRcConstants code, byte[] response) = await Shared.SubmitOverHandleAsync(simulator, pool, commandCode, UnknownTransientHandle, authArea, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_REFERENCE_H0, code, $"'{commandCode}': an unresolved transient handle answers TPM_RC_REFERENCE_H0 ahead of any session judgment.");
                Assert.AreEqual((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, TpmInHouseSimulatorNoAuthSessionTests.ReadResponseTag(response), "A failed command frames TPM_ST_NO_SESSIONS regardless of the request's own tag.");
                Assert.HasCount(10, response, "A failed command's response is exactly the 10-octet header (Part 3, clause 5.9).");

                byte[] followUpParameters = TpmInHouseSimulatorZeroHandleSessionTests.ParameterAreaFor(TpmCcConstants.TPM_CC_TestParms, pool);
                byte[] followUpAuthArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_TestParms, followUpParameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                TpmRcConstants followUpCode = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_TestParms, followUpAuthArea, followUpParameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, followUpCode, $"'{commandCode}': the session's nonceTPM was never touched by the resolution refusal, so a genuine follow-up over it still verifies.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The persistent-range complement of
    /// <see cref="UnresolvedTransientHandleAnswersReferenceH0OverTheSessionsFormAheadOfTheAuditCompanion"/>: a
    /// well-typed but unallocated PERSISTENT handle answers <c>TPM_RC_HANDLE</c> designated to the command's own
    /// sole handle (clause 5.4, step 2.2 — the implementation can and does attribute the field, so N is not left
    /// zero per Table 15's last sentence), ahead of a genuine, loaded audit companion: <c>keyHandle</c>, handle 1
    /// of Table 87 (SignSequenceStart) / Table 89 (VerifySequenceStart) / Table 116 (VerifySignature) / Table 120
    /// (VerifyDigestSignature) / Table 60 (Encapsulate); <c>handle</c>, handle 1 of Table 28 (MakeCredential).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3,
    /// clause 5.4, step 2.2; clause 5.9</see>.
    /// </summary>
    [TestMethod]
    [DataRow(TpmCcConstants.TPM_CC_SignSequenceStart, DisplayName = "TPM2_SignSequenceStart()")]
    [DataRow(TpmCcConstants.TPM_CC_VerifySequenceStart, DisplayName = "TPM2_VerifySequenceStart()")]
    [DataRow(TpmCcConstants.TPM_CC_VerifySignature, DisplayName = "TPM2_VerifySignature()")]
    [DataRow(TpmCcConstants.TPM_CC_VerifyDigestSignature, DisplayName = "TPM2_VerifyDigestSignature()")]
    [DataRow(TpmCcConstants.TPM_CC_Encapsulate, DisplayName = "TPM2_Encapsulate()")]
    [DataRow(TpmCcConstants.TPM_CC_MakeCredential, DisplayName = "TPM2_MakeCredential()")]
    public async Task UnallocatedPersistentHandleAnswersHandleOverTheSessionsFormAheadOfTheAuditCompanion(TpmCcConstants commandCode)
    {
        const uint UnallocatedPersistentHandle = 0x8100_9999u;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await Shared.CreateOperationalWithEccBackendAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(auditSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                //The handle fails to resolve before the session area is ever judged (clause 5.4 precedes clause
                //5.5), so an empty parameter area suffices — the auth area's own Name term is irrelevant since
                //the session's HMAC is never checked once resolution has already failed.
                byte[] authArea = await Shared.BuildSessionAuthAreaOverHandleAsync(auditSession, commandCode, ReadOnlyMemory<byte>.Empty, [], pool).ConfigureAwait(false);
                (TpmRcConstants code, byte[] response) = await Shared.SubmitOverHandleAsync(simulator, pool, commandCode, UnallocatedPersistentHandle, authArea, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

                Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), code, $"'{commandCode}': an unallocated persistent handle answers TPM_RC_HANDLE designated to the command's sole handle, handle 1, ahead of any session judgment.");
                Assert.AreEqual((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, TpmInHouseSimulatorNoAuthSessionTests.ReadResponseTag(response), "A failed command frames TPM_ST_NO_SESSIONS regardless of the request's own tag.");
                Assert.HasCount(10, response, "A failed command's response is exactly the 10-octet header (Part 3, clause 5.9).");

                byte[] followUpParameters = TpmInHouseSimulatorZeroHandleSessionTests.ParameterAreaFor(TpmCcConstants.TPM_CC_TestParms, pool);
                byte[] followUpAuthArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_TestParms, followUpParameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                TpmRcConstants followUpCode = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_TestParms, followUpAuthArea, followUpParameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, followUpCode, $"'{commandCode}': the session's nonceTPM was never touched by the resolution refusal, so a genuine follow-up over it still verifies.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A companion whose command HMAC does not verify is refused at its own index BEFORE
    /// <c>TPM2_SignSequenceStart()</c>'s own sequence-handle resolution is ever reached: the session-encoded
    /// <c>TPM_RC_BAD_AUTH</c> this test asserts — not the inner's bare <c>TPM_RC_KEY</c> — is the discriminating
    /// proof that the authorization area is judged first. The session's nonceTPM is left untouched by the
    /// refusal, and the hash sequence itself is never disturbed.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3,
    /// clause 5.5; clause 5.9</see>.
    /// </summary>
    [TestMethod]
    public async Task SignSequenceStartOverASequenceHandleWithAWrongCompanionHmacReturnsBadAuthAndLeavesTheSessionUsable()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await Shared.CreateOperationalWithEccBackendAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_HashSequenceStart, TpmResponseCodec.HashSequenceStart)
            .Register(TpmCcConstants.TPM_CC_SignSequenceStart, TpmResponseCodec.SignSequenceStart)
            .Register(TpmCcConstants.TPM_CC_SequenceComplete, TpmResponseCodec.SequenceComplete);

        using HashSequenceStartInput openInput = HashSequenceStartInput.CreateFromPassword(string.Empty, TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256), pool);
        TpmResult<HashSequenceStartResponse> openResult = await TpmCommandExecutor.ExecuteAsync<HashSequenceStartResponse>(
            device, openInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(openResult.IsSuccess, $"TPM2_HashSequenceStart() must succeed: '{openResult.ResponseCode}'.");
        TpmiDhObject sequenceHandle = openResult.Value.SequenceHandle;

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(auditSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                byte[] parameters = [0x00, 0x00, 0x00, 0x00];
                byte[] authArea = await Shared.BuildSessionAuthAreaOverHandleAsync(auditSession, TpmCcConstants.TPM_CC_SignSequenceStart, ReadOnlyMemory<byte>.Empty, parameters, pool).ConfigureAwait(false);
                authArea[^1] ^= 0xFF;

                (TpmRcConstants code, byte[] response) = await Shared.SubmitOverHandleAsync(simulator, pool, TpmCcConstants.TPM_CC_SignSequenceStart, sequenceHandle.Value, authArea, parameters).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmInHouseSimulatorZeroHandleSessionTests.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), code,
                    "The companion's own HMAC is refused before the sequence handle is ever resolved — not the inner's TPM_RC_KEY.");
                Assert.AreEqual((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, TpmInHouseSimulatorNoAuthSessionTests.ReadResponseTag(response), "A failed command frames TPM_ST_NO_SESSIONS regardless of the request's own tag.");
                Assert.HasCount(10, response, "A failed command's response is exactly the 10-octet header (Part 3, clause 5.9).");

                byte[] followUpParameters = TpmInHouseSimulatorZeroHandleSessionTests.ParameterAreaFor(TpmCcConstants.TPM_CC_TestParms, pool);
                byte[] followUpAuthArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_TestParms, followUpParameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                TpmRcConstants followUpCode = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_TestParms, followUpAuthArea, followUpParameters, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, followUpCode, "The session's nonceTPM was never touched by the refusal, so a genuine follow-up over it still verifies.");

                using SequenceCompleteInput probeInput = SequenceCompleteInput.Create(sequenceHandle, [], TpmiRhHierarchy.Null, pool);
                using TpmPasswordSession sequencePassword = TpmPasswordSession.CreateEmpty(pool);
                TpmResult<SequenceCompleteResponse> stillOpenResult = await TpmCommandExecutor.ExecuteAsync<SequenceCompleteResponse>(
                    device, probeInput, [sequencePassword], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(stillOpenResult.IsSuccess, "The hash sequence itself was never reached by the refused companion and can still be completed.");
                stillOpenResult.Value.Dispose();
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A companion whose command HMAC does not verify is refused at its own index BEFORE
    /// <c>TPM2_VerifySequenceStart()</c>'s own sequence-handle resolution is ever reached: the session-encoded
    /// <c>TPM_RC_BAD_AUTH</c> this test asserts — not the inner's bare <c>TPM_RC_KEY</c> — is the discriminating
    /// proof that the authorization area is judged first. The session's nonceTPM is left untouched by the
    /// refusal, and the hash sequence itself is never disturbed.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3,
    /// clause 5.5; clause 5.9</see>.
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceStartOverASequenceHandleWithAWrongCompanionHmacReturnsBadAuthAndLeavesTheSessionUsable()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await Shared.CreateOperationalWithEccBackendAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_HashSequenceStart, TpmResponseCodec.HashSequenceStart)
            .Register(TpmCcConstants.TPM_CC_VerifySequenceStart, TpmResponseCodec.VerifySequenceStart)
            .Register(TpmCcConstants.TPM_CC_SequenceComplete, TpmResponseCodec.SequenceComplete);

        using HashSequenceStartInput openInput = HashSequenceStartInput.CreateFromPassword(string.Empty, TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256), pool);
        TpmResult<HashSequenceStartResponse> openResult = await TpmCommandExecutor.ExecuteAsync<HashSequenceStartResponse>(
            device, openInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(openResult.IsSuccess, $"TPM2_HashSequenceStart() must succeed: '{openResult.ResponseCode}'.");
        TpmiDhObject sequenceHandle = openResult.Value.SequenceHandle;

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(auditSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                using VerifySequenceStartInput verifyInput = VerifySequenceStartInput.Create(sequenceHandle, [], pool);
                byte[] parameters = SerializeParameters(verifyInput, pool);
                byte[] authArea = await Shared.BuildSessionAuthAreaOverHandleAsync(auditSession, TpmCcConstants.TPM_CC_VerifySequenceStart, ReadOnlyMemory<byte>.Empty, parameters, pool).ConfigureAwait(false);
                authArea[^1] ^= 0xFF;

                (TpmRcConstants code, byte[] response) = await Shared.SubmitOverHandleAsync(simulator, pool, TpmCcConstants.TPM_CC_VerifySequenceStart, sequenceHandle.Value, authArea, parameters).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmInHouseSimulatorZeroHandleSessionTests.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), code,
                    "The companion's own HMAC is refused before the sequence handle is ever resolved — not the inner's TPM_RC_KEY.");
                Assert.AreEqual((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, TpmInHouseSimulatorNoAuthSessionTests.ReadResponseTag(response), "A failed command frames TPM_ST_NO_SESSIONS regardless of the request's own tag.");
                Assert.HasCount(10, response, "A failed command's response is exactly the 10-octet header (Part 3, clause 5.9).");

                byte[] followUpParameters = TpmInHouseSimulatorZeroHandleSessionTests.ParameterAreaFor(TpmCcConstants.TPM_CC_TestParms, pool);
                byte[] followUpAuthArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_TestParms, followUpParameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                TpmRcConstants followUpCode = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_TestParms, followUpAuthArea, followUpParameters, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, followUpCode, "The session's nonceTPM was never touched by the refusal, so a genuine follow-up over it still verifies.");

                using SequenceCompleteInput probeInput = SequenceCompleteInput.Create(sequenceHandle, [], TpmiRhHierarchy.Null, pool);
                using TpmPasswordSession sequencePassword = TpmPasswordSession.CreateEmpty(pool);
                TpmResult<SequenceCompleteResponse> stillOpenResult = await TpmCommandExecutor.ExecuteAsync<SequenceCompleteResponse>(
                    device, probeInput, [sequencePassword], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(stillOpenResult.IsSuccess, "The hash sequence itself was never reached by the refused companion and can still be completed.");
                stillOpenResult.Value.Dispose();
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A companion whose command HMAC does not verify is refused at its own index BEFORE
    /// <c>TPM2_VerifyDigestSignature()</c>'s own sequence-handle resolution is ever reached: the session-encoded
    /// <c>TPM_RC_BAD_AUTH</c> this test asserts — not the inner's bare <c>TPM_RC_KEY</c> — is the discriminating
    /// proof that the authorization area is judged first. The session's nonceTPM is left untouched by the
    /// refusal, and the hash sequence itself is never disturbed.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3,
    /// clause 5.5; clause 5.9</see>.
    /// </summary>
    [TestMethod]
    public async Task VerifyDigestSignatureOverASequenceHandleWithAWrongCompanionHmacReturnsBadAuthAndLeavesTheSessionUsable()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await Shared.CreateOperationalWithEccBackendAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_HashSequenceStart, TpmResponseCodec.HashSequenceStart)
            .Register(TpmCcConstants.TPM_CC_VerifyDigestSignature, TpmResponseCodec.VerifyDigestSignature)
            .Register(TpmCcConstants.TPM_CC_SequenceComplete, TpmResponseCodec.SequenceComplete);

        using HashSequenceStartInput openInput = HashSequenceStartInput.CreateFromPassword(string.Empty, TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256), pool);
        TpmResult<HashSequenceStartResponse> openResult = await TpmCommandExecutor.ExecuteAsync<HashSequenceStartResponse>(
            device, openInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(openResult.IsSuccess, $"TPM2_HashSequenceStart() must succeed: '{openResult.ResponseCode}'.");
        TpmiDhObject sequenceHandle = openResult.Value.SequenceHandle;

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(auditSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                using VerifyDigestSignatureInput verifyInput = VerifyDigestSignatureInput.ForEcdsa(sequenceHandle, new byte[32], new byte[64], TpmAlgIdConstants.TPM_ALG_SHA256, pool);
                byte[] parameters = SerializeParameters(verifyInput, pool);
                byte[] authArea = await Shared.BuildSessionAuthAreaOverHandleAsync(auditSession, TpmCcConstants.TPM_CC_VerifyDigestSignature, ReadOnlyMemory<byte>.Empty, parameters, pool).ConfigureAwait(false);
                authArea[^1] ^= 0xFF;

                (TpmRcConstants code, byte[] response) = await Shared.SubmitOverHandleAsync(simulator, pool, TpmCcConstants.TPM_CC_VerifyDigestSignature, sequenceHandle.Value, authArea, parameters).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmInHouseSimulatorZeroHandleSessionTests.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), code,
                    "The companion's own HMAC is refused before the sequence handle is ever resolved — not the inner's TPM_RC_KEY.");
                Assert.AreEqual((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, TpmInHouseSimulatorNoAuthSessionTests.ReadResponseTag(response), "A failed command frames TPM_ST_NO_SESSIONS regardless of the request's own tag.");
                Assert.HasCount(10, response, "A failed command's response is exactly the 10-octet header (Part 3, clause 5.9).");

                byte[] followUpParameters = TpmInHouseSimulatorZeroHandleSessionTests.ParameterAreaFor(TpmCcConstants.TPM_CC_TestParms, pool);
                byte[] followUpAuthArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_TestParms, followUpParameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                TpmRcConstants followUpCode = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_TestParms, followUpAuthArea, followUpParameters, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, followUpCode, "The session's nonceTPM was never touched by the refusal, so a genuine follow-up over it still verifies.");

                using SequenceCompleteInput probeInput = SequenceCompleteInput.Create(sequenceHandle, [], TpmiRhHierarchy.Null, pool);
                using TpmPasswordSession sequencePassword = TpmPasswordSession.CreateEmpty(pool);
                TpmResult<SequenceCompleteResponse> stillOpenResult = await TpmCommandExecutor.ExecuteAsync<SequenceCompleteResponse>(
                    device, probeInput, [sequencePassword], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(stillOpenResult.IsSuccess, "The hash sequence itself was never reached by the refused companion and can still be completed.");
                stillOpenResult.Value.Dispose();
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
        }
    }
}
