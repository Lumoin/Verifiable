using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
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
/// Deepens <see cref="TpmInHouseSimulatorNoAuthSessionTests"/>'s coverage of the six handle-less commands whose
/// Part 3 tag cell admits an audit (and, for <c>TPM2_GetTestResult()</c>, an encrypt) companion
/// (<c>TPM2_ReadClock()</c>, <c>TPM2_Shutdown()</c>, <c>TPM2_SelfTest()</c>, <c>TPM2_GetTestResult()</c>,
/// <c>TPM2_GetCapability()</c>, <c>TPM2_PCR_Read()</c>) and the two handle-bearing read commands whose tag cell
/// admits an audit or encrypt companion (<c>TPM2_ReadPublic()</c>, <c>TPM2_NV_ReadPublic()</c>): the cases that
/// class's own pins do not already prove — the encrypt-not-admitted refusal, the decrypt refusal (none of the eight has an
/// encryptable command parameter), the session-form trailing-octet refusal, a persistent and a sequence handle at
/// <c>TPM2_ReadPublic()</c>'s slot, an undefined Index at <c>TPM2_NV_ReadPublic()</c>'s, Failure Mode's admission
/// of <c>TPM2_GetCapability()</c> and <c>TPM2_SelfTest()</c>, <c>TPM2_Shutdown(TPM_SU_CLEAR)</c>'s session lifecycle,
/// and the exclusive-session wire pin — extending that class's own hand-framing fixture and
/// <see cref="TpmInHouseSimulatorZeroHandleSessionTests"/>'s shared recipe rather than re-minting either.
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 4.3, 5.4, 5.5, 5.7 and 5.9; Part 1, clauses 15.6.1, 15.6.4, 17.1, 17.3 and 18</see>.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorNoAuthSessionReadCommandTests
{
    /// <summary>The symmetric definition a slot claiming <c>decrypt</c> or <c>encrypt</c> negotiates in these tests.</summary>
    private static TpmtSymDef SessionSymmetric { get; } = TpmtSymDef.Xor(TpmAlgIdConstants.TPM_ALG_SHA256);

    /// <summary>The persistent handle <see cref="ReadPublicOverAnAuditSlotOnAPersistentHandleSucceedsWithThePersistentNameFoldedIntoCpHash"/> evicts a primary to, inside this class's assigned persistent range.</summary>
    private const uint PersistentHandle = 0x8100_0301u;

    /// <summary>An NV Index inside this class's assigned block that is never defined by any test here.</summary>
    private const uint UndefinedNvIndex = 0x0100_02E5u;

    /// <summary>An NV Index inside this class's assigned block, defined only by the pool-balance test.</summary>
    private const uint MeteredNvIndex = 0x0100_02E1u;

    /// <summary>A transient-range handle nothing is ever loaded at in this class's simulators.</summary>
    private const uint UnknownObjectHandle = 0x8000_1235u;

    /// <summary>An HMAC-session-range handle no test here ever starts a real session at (TPM 2.0 Library Part 2, clause 6.6.3's <c>TPM_HT_HMAC_SESSION</c>).</summary>
    private const uint UnloadedHmacSessionHandle = 0x0200_0000u;

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>A fresh <see cref="TpmInHouseSimulatorNoAuthSessionTests"/> instance carrying this class's own <see cref="TestContext"/>, reached for the instance helpers that class promoted to <c>internal</c> rather than re-minting a second copy here.</summary>
    private TpmInHouseSimulatorNoAuthSessionTests Shared => new() { TestContext = TestContext };

    /// <summary>
    /// <c>TPM2_PCR_Read()</c> over an audit-only companion succeeds and answers the SAME <c>pcrUpdateCounter</c>,
    /// <c>pcrSelectionOut</c> and <c>pcrValues</c> octets the plain, sessionless form answers — the audit
    /// companion changes only the framing, never the command's own answer ("TPM_ST_SESSIONS if an audit session
    /// is present; otherwise, TPM_ST_NO_SESSIONS").
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 22.4, Table 134; Part 1, clause 15.6.1</see>.
    /// </summary>
    [TestMethod]
    public async Task PcrReadOverAnAuditSlotSucceedsWithTheSameCounterSelectionAndValuesAsThePlainForm()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        byte[] parameters;
        using(PcrReadInput plainInput = PcrReadInput.ForAllPcrs(TpmAlgIdConstants.TPM_ALG_SHA256, pool))
        {
            parameters = TpmInHouseSimulatorNoAuthSessionTests.SerializeParameters(plainInput, pool);
        }

        byte[] plainResponse = await Shared.SubmitBareAsync(simulator, pool, TpmCcConstants.TPM_CC_PCR_Read, parameters).ConfigureAwait(false);
        byte[] plainParameters = plainResponse[TpmHeader.HeaderSize..];

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(auditSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                byte[] authArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_PCR_Read, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);

                (TpmRcConstants code, byte[] response) = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleForAuditAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_PCR_Read, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "TPM2_PCR_Read() over an audit-only companion must succeed (Table 134's tag rule).");
                byte[] sessionParameters = TpmInHouseSimulatorZeroHandleSessionTests.ReadResponseParameters(response, outHandleCount: 0);
                Assert.AreSequenceEqual(plainParameters, sessionParameters, "The audited answer must equal the plain form's own pcrUpdateCounter/pcrSelectionOut/pcrValues octets exactly.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_SelfTest()</c> over an audit-only companion, run while the self-test itself passes, succeeds and
    /// extends the session's audit digest to <c>H(0…0 ‖ cpHash ‖ rpHash)</c> chained from this exchange's own
    /// wire octets and read back through <c>TPM2_GetSessionAuditDigest()</c>'s NULL signer.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 10.2, Table 8; Part 1, clause 17.1</see>.
    /// </summary>
    [TestMethod]
    public async Task SelfTestOverAnAuditSlotSucceedsWithTheDigestChained()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_GetSessionAuditDigest, TpmResponseCodec.GetSessionAuditDigest);

        byte[] parameters = TpmInHouseSimulatorNoAuthSessionTests.SerializeParameters(new SelfTestInput(IsFullTest: true), pool);

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(auditSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                byte[] authArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_SelfTest, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);

                (TpmRcConstants code, byte[] response) = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleForAuditAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_SelfTest, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "TPM2_SelfTest() over an audit-only companion, when the self-test itself passes, must succeed (Table 8's tag rule).");
                Assert.AreEqual((ushort)TpmStConstants.TPM_ST_SESSIONS, TpmInHouseSimulatorNoAuthSessionTests.ReadResponseTag(response), "A successful over-session response is TPM_ST_SESSIONS-tagged.");

                byte[] responseParameters = TpmInHouseSimulatorZeroHandleSessionTests.ReadResponseParameters(response, outHandleCount: 0);
                byte[] cpHash = await TpmInHouseSimulatorZeroHandleSessionTests.ComputeZeroHandleCpHashAsync(TpmCcConstants.TPM_CC_SelfTest, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                byte[] rpHash = await TpmInHouseSimulatorZeroHandleSessionTests.ComputeRpHashAsync(TpmCcConstants.TPM_CC_SelfTest, responseParameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                byte[] expectedDigest = await TpmInHouseSimulatorZeroHandleSessionTests.ExtendAuditDigestAsync(priorDigest: null, cpHash, rpHash, pool, TestContext.CancellationToken).ConfigureAwait(false);

                using GetSessionAuditDigestInput auditDigestInput = GetSessionAuditDigestInput.ForNullSigner(TpmiShHmac.FromValue(auditHandle), ReadOnlySpan<byte>.Empty, pool);
                using TpmPasswordSession endorsementForDigest = TpmPasswordSession.CreateEmpty(pool);
                using TpmPasswordSession nullSignerSlot = TpmPasswordSession.CreateEmpty(pool);

                TpmResult<GetSessionAuditDigestResponse> digestResult = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                    device, auditDigestInput, [endorsementForDigest, nullSignerSlot], handleNames: null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                using GetSessionAuditDigestResponse? auditDigestResponse = digestResult.IsSuccess ? digestResult.Value : null;

                Assert.IsTrue(digestResult.IsSuccess, $"TPM2_GetSessionAuditDigest() over the freshly audited session must succeed: '{digestResult.ResponseCode}'.");
                Assert.IsTrue(
                    expectedDigest.AsSpan().SequenceEqual(auditDigestResponse!.SessionAudit.SessionDigest.AsReadOnlySpan()),
                    "The audit session's digest must equal H(0…0 ‖ cpHash ‖ rpHash) chained from this exchange's own wire octets (TPM 2.0 Library Part 1, clause 17.1, equation 30).");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// None of <c>TPM2_ReadClock()</c>, <c>TPM2_Shutdown()</c>, <c>TPM2_SelfTest()</c>, <c>TPM2_GetCapability()</c>
    /// or <c>TPM2_PCR_Read()</c> has a sized first response parameter, so an <c>encrypt</c> claim over any of
    /// them is refused session-index-encoded, blamed on the offending slot.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 15.6.4, Table 15; Part 3, clause 5.5, step 4.4.2</see>.
    /// </summary>
    /// <param name="commandCode">The command under test.</param>
    [TestMethod]
    [DataRow(TpmCcConstants.TPM_CC_ReadClock, DisplayName = "TPM2_ReadClock()")]
    [DataRow(TpmCcConstants.TPM_CC_Shutdown, DisplayName = "TPM2_Shutdown()")]
    [DataRow(TpmCcConstants.TPM_CC_SelfTest, DisplayName = "TPM2_SelfTest()")]
    [DataRow(TpmCcConstants.TPM_CC_GetCapability, DisplayName = "TPM2_GetCapability()")]
    [DataRow(TpmCcConstants.TPM_CC_PCR_Read, DisplayName = "TPM2_PCR_Read()")]
    public async Task EncryptCompanionIsRefusedOnCommandsWithNoEncryptableResponseParameter(TpmCcConstants commandCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        byte[] parameters = TpmInHouseSimulatorNoAuthSessionTests.CanonicalParametersFor(commandCode, pool);

        (uint sessionHandle, TpmSession session) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;
                byte[] authArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(session, commandCode, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);

                TpmRcConstants code = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(simulator, pool, commandCode, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmInHouseSimulatorZeroHandleSessionTests.SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0), code,
                    $"'{commandCode}' has no sized first response parameter, so an encrypt claim is refused session-encoded TPM_RC_ATTRIBUTES.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// None of the six handle-less commands has a sized first command parameter, so a <c>decrypt</c> claim over
    /// any of them is refused session-index-encoded, blamed on the offending slot — never
    /// <c>TPM_RC_SYMMETRIC</c>, since the attribute is judged against the command's own parameter shape before
    /// the session's negotiated algorithm is ever consulted.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 15.6.4, Table 15; Part 3, clause 5.5, step 4.4.2</see>.
    /// </summary>
    /// <param name="commandCode">The command under test.</param>
    [TestMethod]
    [DataRow(TpmCcConstants.TPM_CC_ReadClock, DisplayName = "TPM2_ReadClock()")]
    [DataRow(TpmCcConstants.TPM_CC_Shutdown, DisplayName = "TPM2_Shutdown()")]
    [DataRow(TpmCcConstants.TPM_CC_SelfTest, DisplayName = "TPM2_SelfTest()")]
    [DataRow(TpmCcConstants.TPM_CC_GetTestResult, DisplayName = "TPM2_GetTestResult()")]
    [DataRow(TpmCcConstants.TPM_CC_GetCapability, DisplayName = "TPM2_GetCapability()")]
    [DataRow(TpmCcConstants.TPM_CC_PCR_Read, DisplayName = "TPM2_PCR_Read()")]
    public async Task DecryptCompanionIsRefusedOnTheSixHandlelessCommands(TpmCcConstants commandCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        byte[] parameters = TpmInHouseSimulatorNoAuthSessionTests.CanonicalParametersFor(commandCode, pool);

        (uint sessionHandle, TpmSession session) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;
                byte[] authArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(session, commandCode, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);

                TpmRcConstants code = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(simulator, pool, commandCode, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmInHouseSimulatorZeroHandleSessionTests.SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0), code,
                    $"'{commandCode}' has no sized first command parameter, so a decrypt claim is refused session-encoded TPM_RC_ATTRIBUTES, never TPM_RC_SYMMETRIC.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A LOADED policy session claiming <c>decrypt</c> is admitted exactly like an HMAC companion
    /// (TPM 2.0 Library Part 1, clause 15.6.1, Table 12, footnote [2]: "a policy authorization session can also
    /// be used for encryption and decryption"), but none of the six handle-less commands has a sized first
    /// command parameter, so the claim is refused session-index-encoded <c>TPM_RC_ATTRIBUTES</c> by the area's
    /// own attribute rule — never <c>TPM_RC_SYMMETRIC</c>, since the attribute is judged against the command's
    /// own parameter shape before the session's negotiated algorithm is ever consulted.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1,
    /// clause 15.6.1, Table 12, footnote [2]; clause 15.6.4, Table 15; Part 3, clause 5.5, step 4.4.2</see>.
    /// </summary>
    /// <param name="commandCode">The command under test.</param>
    [TestMethod]
    [DataRow(TpmCcConstants.TPM_CC_ReadClock, DisplayName = "TPM2_ReadClock()")]
    [DataRow(TpmCcConstants.TPM_CC_Shutdown, DisplayName = "TPM2_Shutdown()")]
    [DataRow(TpmCcConstants.TPM_CC_SelfTest, DisplayName = "TPM2_SelfTest()")]
    [DataRow(TpmCcConstants.TPM_CC_GetTestResult, DisplayName = "TPM2_GetTestResult()")]
    [DataRow(TpmCcConstants.TPM_CC_GetCapability, DisplayName = "TPM2_GetCapability()")]
    [DataRow(TpmCcConstants.TPM_CC_PCR_Read, DisplayName = "TPM2_PCR_Read()")]
    public async Task PolicyCompanionClaimingDecryptIsRefusedOnTheSixHandlelessCommands(TpmCcConstants commandCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        byte[] parameters = TpmInHouseSimulatorNoAuthSessionTests.CanonicalParametersFor(commandCode, pool);

        (uint policyHandle, TpmSession policySession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(
            device, registry, pool, TestContext.CancellationToken, SessionSymmetric, TpmSeConstants.TPM_SE_POLICY).ConfigureAwait(false);
        try
        {
            using(policySession)
            {
                policySession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;
                byte[] authArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(policySession, commandCode, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);

                TpmRcConstants code = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(simulator, pool, commandCode, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmInHouseSimulatorZeroHandleSessionTests.SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0), code,
                    $"'{commandCode}' has no sized first command parameter, so a POLICY companion's decrypt claim is refused session-encoded TPM_RC_ATTRIBUTES, never TPM_RC_SYMMETRIC.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, policyHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Neither <c>TPM2_ReadPublic()</c>'s <c>objectHandle</c> nor <c>TPM2_NV_ReadPublic()</c>'s <c>nvIndex</c> is a
    /// sized command parameter, so a <c>decrypt</c> claim over either is refused session-encoded
    /// <c>TPM_RC_ATTRIBUTES</c> once the addressed handle resolves — the same rule the six handle-less commands
    /// answer, proved here on the two commands whose <c>@</c>-free handle precedes their own session area.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.4, Table 24; clause 31.6, Table 251; Part 1, clause 15.6.4, Table 15</see>.
    /// </summary>
    [TestMethod]
    public async Task ReadPublicAndNvReadPublicDecryptCompanionsAreRefusedWithAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        //TPM2_ReadPublic() over a loaded primary.
        {
            using TpmSimulator simulator = await CreateOperationalWithEccBackendAsync(pool).ConfigureAwait(false);
            using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
            TpmResponseRegistry registry = CreateFullRegistry();

            using CreatePrimaryResponse primary = await CreateEccPrimaryAsync(device, registry, pool).ConfigureAwait(false);

            (uint sessionHandle, TpmSession session) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
            try
            {
                using(session)
                {
                    session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;
                    byte[] authArea = await Shared.BuildSessionAuthAreaOverHandleAsync(session, TpmCcConstants.TPM_CC_ReadPublic, primary.Name.AsReadOnlyMemory(), [], pool).ConfigureAwait(false);

                    (TpmRcConstants code, _) = await Shared.SubmitOverHandleAsync(simulator, pool, TpmCcConstants.TPM_CC_ReadPublic, primary.ObjectHandle.Value, authArea, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

                    Assert.AreEqual(
                        TpmInHouseSimulatorZeroHandleSessionTests.SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0), code,
                        "TPM2_ReadPublic() has no sized command parameter of its own, so a decrypt claim is refused session-encoded TPM_RC_ATTRIBUTES.");
                }
            }
            finally
            {
                await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
            }
        }

        //TPM2_NV_ReadPublic() over a defined Index.
        {
            using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
            using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
            TpmResponseRegistry registry = CreateFullRegistry();

            byte[] indexName = await DefineOrdinaryIndexAsync(device, registry, pool, MeteredNvIndex).ConfigureAwait(false);

            (uint sessionHandle, TpmSession session) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
            try
            {
                using(session)
                {
                    session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;
                    byte[] authArea = await Shared.BuildSessionAuthAreaOverHandleAsync(session, TpmCcConstants.TPM_CC_NV_ReadPublic, indexName, [], pool).ConfigureAwait(false);

                    (TpmRcConstants code, _) = await Shared.SubmitOverHandleAsync(simulator, pool, TpmCcConstants.TPM_CC_NV_ReadPublic, MeteredNvIndex, authArea, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

                    Assert.AreEqual(
                        TpmInHouseSimulatorZeroHandleSessionTests.SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0), code,
                        "TPM2_NV_ReadPublic() has no sized command parameter of its own, so a decrypt claim is refused session-encoded TPM_RC_ATTRIBUTES.");
                }
            }
            finally
            {
                await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
            }
        }
    }

    /// <summary>
    /// A trailing octet beyond the last parameter is discovered only once the session area verifies (clause 5.5
    /// precedes clause 5.8's parameter unmarshaling), so the answer is the inner's own bare <c>TPM_RC_SIZE</c>,
    /// framed <c>TPM_ST_NO_SESSIONS</c> in exactly 10 octets — never a session-encoded code, since the failure is
    /// discovered strictly after every entry in the area has already been individually verified.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.5; clause 5.9</see>.
    /// </summary>
    /// <param name="commandCode">The command under test.</param>
    [TestMethod]
    [DataRow(TpmCcConstants.TPM_CC_ReadClock, DisplayName = "TPM2_ReadClock()")]
    [DataRow(TpmCcConstants.TPM_CC_Shutdown, DisplayName = "TPM2_Shutdown()")]
    [DataRow(TpmCcConstants.TPM_CC_SelfTest, DisplayName = "TPM2_SelfTest()")]
    [DataRow(TpmCcConstants.TPM_CC_GetTestResult, DisplayName = "TPM2_GetTestResult()")]
    [DataRow(TpmCcConstants.TPM_CC_GetCapability, DisplayName = "TPM2_GetCapability()")]
    [DataRow(TpmCcConstants.TPM_CC_PCR_Read, DisplayName = "TPM2_PCR_Read()")]
    public async Task SessionFormRefusesATrailingOctetWithBareSizeAfterTheSessionVerifies(TpmCcConstants commandCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        byte[] withTrailingOctet = [.. TpmInHouseSimulatorNoAuthSessionTests.CanonicalParametersFor(commandCode, pool), 0x00];

        (uint sessionHandle, TpmSession session) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                byte[] authArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(session, commandCode, withTrailingOctet, pool, TestContext.CancellationToken).ConfigureAwait(false);

                (TpmRcConstants code, byte[] response) = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleForAuditAsync(
                    simulator, pool, commandCode, authArea, withTrailingOctet, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, code, $"'{commandCode}': a trailing octet discovered only after the session verifies is bare TPM_RC_SIZE.");
                Assert.AreEqual((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, TpmInHouseSimulatorNoAuthSessionTests.ReadResponseTag(response), "A failed command frames TPM_ST_NO_SESSIONS regardless of the request's own tag.");
                Assert.HasCount(10, response, "A failed command's response is exactly the 10-octet header (Part 3, clause 5.9).");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A persistent object is a loaded object at <c>TPM2_ReadPublic()</c>'s slot exactly as a transient one is:
    /// an audit-only companion succeeds, and the persistent record's OWN Name — unchanged by persisting, which
    /// changes only the handle — is what the folded cpHash carries, chained into the read-back audit digest.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.4, Table 24; Part 2, clause 9.3, Table 49; Part 1, clause 17.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ReadPublicOverAnAuditSlotOnAPersistentHandleSucceedsWithThePersistentNameFoldedIntoCpHash()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalWithEccBackendAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateFullRegistry();

        using CreatePrimaryResponse primary = await CreateEccPrimaryAsync(device, registry, pool).ConfigureAwait(false);
        byte[] persistentName = primary.Name.Span.ToArray();

        TpmResult<EvictControlResponse> persistResult = await TpmEvictControlHarness.EvictControlAsync(
            device, registry, pool, primary.ObjectHandle.Value, PersistentHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(persistResult.IsSuccess, $"TPM2_EvictControl() (persist) must succeed: '{persistResult.ResponseCode}'.");

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(auditSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                byte[] authArea = await Shared.BuildSessionAuthAreaOverHandleAsync(auditSession, TpmCcConstants.TPM_CC_ReadPublic, persistentName, [], pool).ConfigureAwait(false);

                (TpmRcConstants code, byte[] response) = await Shared.SubmitOverHandleAsync(simulator, pool, TpmCcConstants.TPM_CC_ReadPublic, PersistentHandle, authArea, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "TPM2_ReadPublic() over an audit-only companion, addressed at the persistent handle, must succeed.");
                Assert.AreEqual((ushort)TpmStConstants.TPM_ST_SESSIONS, TpmInHouseSimulatorNoAuthSessionTests.ReadResponseTag(response), "A successful over-session response is TPM_ST_SESSIONS-tagged.");

                byte[] responseParameters = TpmInHouseSimulatorZeroHandleSessionTests.ReadResponseParameters(response, outHandleCount: 0);
                byte[] cpHash = await Shared.ComputeCpHashWithNameAsync(TpmCcConstants.TPM_CC_ReadPublic, persistentName, ReadOnlyMemory<byte>.Empty, pool).ConfigureAwait(false);
                byte[] rpHash = await TpmInHouseSimulatorZeroHandleSessionTests.ComputeRpHashAsync(TpmCcConstants.TPM_CC_ReadPublic, responseParameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                byte[] expectedDigest = await TpmInHouseSimulatorZeroHandleSessionTests.ExtendAuditDigestAsync(priorDigest: null, cpHash, rpHash, pool, TestContext.CancellationToken).ConfigureAwait(false);

                using GetSessionAuditDigestInput auditDigestInput = GetSessionAuditDigestInput.ForNullSigner(TpmiShHmac.FromValue(auditHandle), ReadOnlySpan<byte>.Empty, pool);
                using TpmPasswordSession endorsementForDigest = TpmPasswordSession.CreateEmpty(pool);
                using TpmPasswordSession nullSignerSlot = TpmPasswordSession.CreateEmpty(pool);

                TpmResult<GetSessionAuditDigestResponse> digestResult = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                    device, auditDigestInput, [endorsementForDigest, nullSignerSlot], handleNames: null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                using GetSessionAuditDigestResponse? auditDigestResponse = digestResult.IsSuccess ? digestResult.Value : null;

                Assert.IsTrue(digestResult.IsSuccess, $"TPM2_GetSessionAuditDigest() must succeed: '{digestResult.ResponseCode}'.");
                Assert.IsTrue(
                    expectedDigest.AsSpan().SequenceEqual(auditDigestResponse!.SessionAudit.SessionDigest.AsReadOnlySpan()),
                    "The audit digest must equal H(0…0 ‖ cpHash ‖ rpHash) with the PERSISTENT record's own Name folded into cpHash.");
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
    /// <c>TPM2_ReadPublic()</c>'s own "If objectHandle references a sequence object, the TPM shall return
    /// TPM_RC_SEQUENCE" gate runs: the response is still bare, framed <c>TPM_ST_NO_SESSIONS</c> in exactly 10
    /// octets, but the companion's nonceTPM is that of a session that verified and then hit a dropped pending
    /// frame, not of one turned away pre-verification — a genuine follow-up command over the same session still
    /// verifies. The session never becomes an audit session at all (only a command that claims <c>audit</c> AND
    /// succeeds starts its digest chain), so <c>TPM2_GetSessionAuditDigest()</c> still refuses <c>TPM_RC_TYPE</c>
    /// afterward — the refused command's cpHash/rpHash are never extended into any digest.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1,
    /// Table 9 footnote (1) and clause 29.4.6; Part 3, clauses 5.4, 5.9 and 12.4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ReadPublicOverAnAuditSlotOnASequenceHandleAnswersBareSequenceAfterTheSessionsVerified()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_GetSessionAuditDigest, TpmResponseCodec.GetSessionAuditDigest);

        uint sequenceHandle = await StartHashSequenceAsync(simulator, pool, "no-auth-read-command-sequence-auth").ConfigureAwait(false);

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(auditSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                //The sequence handle's Name term is the Empty Buffer, the SAME term the session is verified
                //against, so the command HMAC this block commits to must actually verify before the inner's own
                //TPM_RC_SEQUENCE gate is ever reached.
                byte[] authArea = await Shared.BuildSessionAuthAreaOverHandleAsync(auditSession, TpmCcConstants.TPM_CC_ReadPublic, ReadOnlyMemory<byte>.Empty, [], pool).ConfigureAwait(false);

                (TpmRcConstants code, byte[] response) = await Shared.SubmitOverHandleAsync(simulator, pool, TpmCcConstants.TPM_CC_ReadPublic, sequenceHandle, authArea, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_SEQUENCE, code, "A sequence handle at TPM2_ReadPublic()'s slot answers the inner's own bare TPM_RC_SEQUENCE, after the session area verifies.");
                Assert.AreEqual((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, TpmInHouseSimulatorNoAuthSessionTests.ReadResponseTag(response), "A failed command frames TPM_ST_NO_SESSIONS regardless of the request's own tag.");
                Assert.HasCount(10, response, "A failed command's response is exactly the 10-octet header (Part 3, clause 5.9).");

                (TpmRcConstants digestCodeAfterRefusal, _) = await Shared.TryReadNullSignedAuditDigestAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
                Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_TYPE, 2), digestCodeAfterRefusal, "The refused command never used the session as an audit session — TPM2_GetSessionAuditDigest() still refuses TPM_RC_TYPE, exactly as a session that has never audited anything (Part 3, clause 5.9).");

                byte[] followUpParameters = TpmInHouseSimulatorZeroHandleSessionTests.ParameterAreaFor(TpmCcConstants.TPM_CC_TestParms, pool);
                byte[] followUpAuthArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_TestParms, followUpParameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                TpmRcConstants followUpCode = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_TestParms, followUpAuthArea, followUpParameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, followUpCode, "The session's nonceTPM was left untouched by the dropped pending frame, so a genuine follow-up command over it still verifies.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "A TPM is required to perform the handle area validation before the authorization checks because an
    /// authorization cannot be performed unless the authorization values and attributes for the referenced entity
    /// are known by the TPM" — an unloaded transient-range <c>objectHandle</c> answers <c>TPM_RC_REFERENCE_H0</c>
    /// even when the authorization slot itself is malformed (an HMAC-session-range handle naming no loaded
    /// session), proving the handle resolves, and the command refuses, before the slot is ever inspected at all.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.4, step 2.1; clause 5.9</see>.
    /// </summary>
    [TestMethod]
    public async Task ReadPublicOverAnUnknownHandleAndAMalformedSlotAnswersReferenceH0AheadOfTheSlot()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);

        byte[] authArea = BuildMalformedSessionSlot();

        (TpmRcConstants code, byte[] response) = await Shared.SubmitOverHandleAsync(simulator, pool, TpmCcConstants.TPM_CC_ReadPublic, UnknownObjectHandle, authArea, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_REFERENCE_H0, code, "An unloaded transient-range objectHandle answers TPM_RC_REFERENCE_H0 even when the slot names no loaded session at all.");
        Assert.AreEqual((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, TpmInHouseSimulatorNoAuthSessionTests.ReadResponseTag(response), "A failed command frames TPM_ST_NO_SESSIONS regardless of the request's own tag.");
        Assert.HasCount(10, response, "A failed command's response is exactly the 10-octet header (Part 3, clause 5.9).");
    }

    /// <summary>
    /// An unloaded transient-range <c>objectHandle</c> answers <c>TPM_RC_REFERENCE_H0</c> ahead of the session
    /// area even over a genuine, LOADED policy companion claiming <c>encrypt</c> — clause 5.4 precedes clause
    /// 5.5, so the policy companion's own credential is never inspected at all — and leaves that companion's
    /// nonceTPM untouched, so a genuine follow-up command over it still verifies ("If that code is not
    /// TPM_RC_SUCCESS, the post processing code will not update any session or audit data").
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3,
    /// clause 5.4, step 2.1; clause 5.9</see>.
    /// </summary>
    [TestMethod]
    public async Task ReadPublicOverAnUnknownHandleAndALoadedPolicyCompanionAnswersReferenceH0AndLeavesTheCompanionUsable()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        (uint policyHandle, TpmSession policySession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(
            device, registry, pool, TestContext.CancellationToken, SessionSymmetric, TpmSeConstants.TPM_SE_POLICY).ConfigureAwait(false);
        try
        {
            using(policySession)
            {
                policySession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;
                byte[] authArea = await Shared.BuildSessionAuthAreaOverHandleAsync(policySession, TpmCcConstants.TPM_CC_ReadPublic, ReadOnlyMemory<byte>.Empty, [], pool).ConfigureAwait(false);

                (TpmRcConstants code, byte[] response) = await Shared.SubmitOverHandleAsync(simulator, pool, TpmCcConstants.TPM_CC_ReadPublic, UnknownObjectHandle, authArea, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_REFERENCE_H0, code, "An unloaded transient-range objectHandle answers TPM_RC_REFERENCE_H0 even when a genuine, loaded POLICY companion is attached.");
                Assert.AreEqual((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, TpmInHouseSimulatorNoAuthSessionTests.ReadResponseTag(response), "A failed command frames TPM_ST_NO_SESSIONS regardless of the request's own tag.");
                Assert.HasCount(10, response, "A failed command's response is exactly the 10-octet header (Part 3, clause 5.9).");

                byte[] followUpParameters = TpmInHouseSimulatorZeroHandleSessionTests.ParameterAreaFor(TpmCcConstants.TPM_CC_GetRandom, pool);
                byte[] followUpAuthArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(policySession, TpmCcConstants.TPM_CC_GetRandom, followUpParameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                TpmRcConstants followUpCode = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_GetRandom, followUpAuthArea, followUpParameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, followUpCode, "The policy companion's nonceTPM was left untouched by the handle-area refusal, so a genuine follow-up command over it still verifies.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, policyHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// An undefined Index answers <c>TPM_RC_HANDLE</c> at nvIndex, handle 1 of Table 251, ahead of the session area, even over a genuine,
    /// loaded audit companion — clause 5.4 precedes clause 5.5 — and leaves that companion's nonceTPM untouched,
    /// so a genuine follow-up command over it still verifies.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.6, Table 251; clause 5.4; clause 5.9</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadPublicOverAnAuditSlotOnAnUndefinedIndexAnswersHandleAndLeavesTheSessionUsable()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        (uint sessionHandle, TpmSession session) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                byte[] authArea = await Shared.BuildSessionAuthAreaOverHandleAsync(session, TpmCcConstants.TPM_CC_NV_ReadPublic, ReadOnlyMemory<byte>.Empty, [], pool).ConfigureAwait(false);

                (TpmRcConstants code, byte[] response) = await Shared.SubmitOverHandleAsync(simulator, pool, TpmCcConstants.TPM_CC_NV_ReadPublic, UndefinedNvIndex, authArea, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

                Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), code, "An undefined Index answers TPM_RC_HANDLE at nvIndex, handle 1 of Table 251, ahead of any session judgment.");
                Assert.AreEqual((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, TpmInHouseSimulatorNoAuthSessionTests.ReadResponseTag(response), "A failed command frames TPM_ST_NO_SESSIONS regardless of the request's own tag.");
                Assert.HasCount(10, response, "A failed command's response is exactly the 10-octet header (Part 3, clause 5.9).");

                byte[] followUpParameters = TpmInHouseSimulatorNoAuthSessionTests.CanonicalParametersFor(TpmCcConstants.TPM_CC_GetCapability, pool);
                byte[] followUpAuthArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(session, TpmCcConstants.TPM_CC_GetCapability, followUpParameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                TpmRcConstants followUpCode = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_GetCapability, followUpAuthArea, followUpParameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, followUpCode, "The session's nonceTPM was left untouched by the refusal, so a genuine follow-up command over it still verifies.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "If the TPM is in Failure mode, then the commandCode is TPM_CC_GetTestResult or TPM_CC_GetCapability
    /// (TPM_RC_FAILURE) and the command tag is TPM_ST_NO_SESSIONS (TPM_RC_FAILURE). In Failure mode, the TPM has
    /// no cryptographic capability and processing of sessions is not supported" — a companion that verified while
    /// the TPM was still operational is refused the same bare <c>TPM_RC_FAILURE</c>, framed <c>TPM_ST_NO_SESSIONS</c>
    /// in exactly 10 octets, once the TPM has entered Failure Mode: the session's own nonceTPM is left byte-identical,
    /// since Failure Mode processes no session at all.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.3, step 1; clause 10.4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task GetCapabilityOverAnAuditSlotInFailureModeAnswersBareFailureWithTheSessionsNonceUntouched()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(TpmSelfTestBehavior.Fails).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(auditSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                byte[] selfTestParameters = TpmInHouseSimulatorNoAuthSessionTests.SerializeParameters(new SelfTestInput(IsFullTest: false), pool);
                TpmRcConstants selfTestCode = ReadResponseCode(await Shared.SubmitBareAsync(simulator, pool, TpmCcConstants.TPM_CC_SelfTest, selfTestParameters).ConfigureAwait(false));
                Assert.AreEqual(TpmRcConstants.TPM_RC_FAILURE, selfTestCode, "The scripted Fails self-test behaviour must enter Failure Mode.");
                Assert.AreEqual(TpmLifecyclePhase.FailureMode, simulator.CurrentPhase, "The simulator must be in Failure Mode for this test to prove anything.");

                byte[] parameters = TpmInHouseSimulatorNoAuthSessionTests.SerializeParameters(GetCapabilityInput.ForFixedProperties(), pool);
                byte[] plainResponse = await Shared.SubmitBareAsync(simulator, pool, TpmCcConstants.TPM_CC_GetCapability, parameters).ConfigureAwait(false);
                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, ReadResponseCode(plainResponse), "The plain, TPM_ST_NO_SESSIONS form of TPM2_GetCapability() is the one form clause 5.3 step 1 still admits in Failure Mode.");

                byte[] nonceBeforeRefusal = auditSession.NonceTpm.ToArray();
                byte[] authArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_GetCapability, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                (TpmRcConstants code, byte[] response) = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleForAuditAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_GetCapability, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_FAILURE, code, "A TPM_ST_SESSIONS-tagged TPM2_GetCapability() is refused bare TPM_RC_FAILURE in Failure Mode, per clause 5.3 step 1, even though the plain form just succeeded.");
                Assert.AreEqual((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, TpmInHouseSimulatorNoAuthSessionTests.ReadResponseTag(response), "Clause 5.3 step 1's refusal is framed TPM_ST_NO_SESSIONS regardless of the request's own tag.");
                Assert.HasCount(10, response, "Clause 5.3 step 1's refusal is exactly the 10-octet header; no session is processed at all.");
                Assert.AreSequenceEqual(nonceBeforeRefusal, auditSession.NonceTpm.ToArray(), "Failure Mode processes no session, so the companion's nonceTPM is the literal same octets before and after the refusal.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_SelfTest()</c> run with the scripted Fails behaviour, over an audit-only companion established
    /// before the failure, answers the inner's own bare <c>TPM_RC_FAILURE</c> framed <c>TPM_ST_NO_SESSIONS</c> in
    /// exactly 10 octets — a failing command frames nothing session-related — and, once the Failure Mode the
    /// self-test itself just entered is in effect, the plain, <c>TPM_ST_NO_SESSIONS</c> form of
    /// <c>TPM2_GetCapability()</c> still succeeds, since clause 5.3 step 1 admits only that tag for it there.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 10.2, Table 8; clause 5.3, step 1; clause 5.9</see>.
    /// </summary>
    [TestMethod]
    public async Task SelfTestOverAnAuditSlotWithTheFailsBehaviourAnswersTheInnersBareFailureCode()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(TpmSelfTestBehavior.Fails).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(auditSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                byte[] selfTestParameters = TpmInHouseSimulatorNoAuthSessionTests.SerializeParameters(new SelfTestInput(IsFullTest: false), pool);
                byte[] authArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_SelfTest, selfTestParameters, pool, TestContext.CancellationToken).ConfigureAwait(false);

                (TpmRcConstants code, byte[] response) = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleForAuditAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_SelfTest, authArea, selfTestParameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_FAILURE, code, "TPM2_SelfTest() with the scripted Fails behaviour answers the inner's own bare TPM_RC_FAILURE.");
                Assert.AreEqual((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, TpmInHouseSimulatorNoAuthSessionTests.ReadResponseTag(response), "A failed command frames TPM_ST_NO_SESSIONS regardless of the request's own tag.");
                Assert.HasCount(10, response, "A failed command's response is exactly the 10-octet header (Part 3, clause 5.9).");
                Assert.AreEqual(TpmLifecyclePhase.FailureMode, simulator.CurrentPhase, "The Fails behaviour must have entered Failure Mode.");

                byte[] followUpParameters = TpmInHouseSimulatorNoAuthSessionTests.SerializeParameters(GetCapabilityInput.ForFixedProperties(), pool);
                byte[] followUpResponse = await Shared.SubmitBareAsync(simulator, pool, TpmCcConstants.TPM_CC_GetCapability, followUpParameters).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, ReadResponseCode(followUpResponse), "Clause 5.3 step 1 admits the plain, TPM_ST_NO_SESSIONS form of TPM2_GetCapability() in Failure Mode; a TPM_ST_SESSIONS form over the same companion would instead be refused bare TPM_RC_FAILURE.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "If the TPM is in Failure mode, then the commandCode is TPM_CC_GetTestResult or TPM_CC_GetCapability
    /// (TPM_RC_FAILURE) and the command tag is TPM_ST_NO_SESSIONS (TPM_RC_FAILURE)" governs
    /// <c>TPM2_GetTestResult()</c> exactly as it governs <c>TPM2_GetCapability()</c>: a companion that verified
    /// while the TPM was still operational is refused bare <c>TPM_RC_FAILURE</c>, framed <c>TPM_ST_NO_SESSIONS</c>
    /// in exactly 10 octets, once the TPM has entered Failure Mode, while the plain, <c>TPM_ST_NO_SESSIONS</c> form
    /// still answers — "This command will operate when the TPM is in Failure mode so that software can determine
    /// the test status of the TPM".
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.3, step 1; clause 10.4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task GetTestResultOverAnAuditSlotInFailureModeAnswersBareFailureWhileThePlainFormStillSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(TpmSelfTestBehavior.Fails).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(auditSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                byte[] selfTestParameters = TpmInHouseSimulatorNoAuthSessionTests.SerializeParameters(new SelfTestInput(IsFullTest: false), pool);
                TpmRcConstants selfTestCode = ReadResponseCode(await Shared.SubmitBareAsync(simulator, pool, TpmCcConstants.TPM_CC_SelfTest, selfTestParameters).ConfigureAwait(false));
                Assert.AreEqual(TpmRcConstants.TPM_RC_FAILURE, selfTestCode, "The scripted Fails self-test behaviour must enter Failure Mode.");
                Assert.AreEqual(TpmLifecyclePhase.FailureMode, simulator.CurrentPhase, "The simulator must be in Failure Mode for this test to prove anything.");

                byte[] parameters = TpmInHouseSimulatorNoAuthSessionTests.SerializeParameters(new GetTestResultInput(), pool);
                byte[] plainResponse = await Shared.SubmitBareAsync(simulator, pool, TpmCcConstants.TPM_CC_GetTestResult, parameters).ConfigureAwait(false);
                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, ReadResponseCode(plainResponse), "The plain, TPM_ST_NO_SESSIONS form of TPM2_GetTestResult() is the one form clause 5.3 step 1 still admits in Failure Mode.");

                byte[] nonceBeforeRefusal = auditSession.NonceTpm.ToArray();
                byte[] authArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_GetTestResult, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                (TpmRcConstants code, byte[] response) = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleForAuditAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_GetTestResult, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_FAILURE, code, "A TPM_ST_SESSIONS-tagged TPM2_GetTestResult() is refused bare TPM_RC_FAILURE in Failure Mode, per clause 5.3 step 1, even though the plain form just succeeded.");
                Assert.AreEqual((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, TpmInHouseSimulatorNoAuthSessionTests.ReadResponseTag(response), "Clause 5.3 step 1's refusal is framed TPM_ST_NO_SESSIONS regardless of the request's own tag.");
                Assert.HasCount(10, response, "Clause 5.3 step 1's refusal is exactly the 10-octet header; no session is processed at all.");
                Assert.AreSequenceEqual(nonceBeforeRefusal, auditSession.NonceTpm.ToArray(), "Failure Mode processes no session, so the SAME companion, started before the failure, is refused the same way and its nonceTPM is the literal same octets before and after the refusal.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// An audited <c>TPM2_Shutdown(TPM_SU_CLEAR)</c> succeeds and frames normally, since the command body never
    /// touches session state; at the next <c>TPM2_Startup(TPM_SU_CLEAR)</c>, every loaded session — including the
    /// one that just audited the Shutdown call itself — is unconditionally discarded, so the same handle now
    /// answers session-encoded <c>TPM_RC_REFERENCE_S0</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 9.4, Table 6</see>.
    /// </summary>
    [TestMethod]
    public async Task ShutdownClearOverAnAuditSlotSucceedsAndTheSessionIsGoneAfterStartup()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        byte[] shutdownParameters = TpmInHouseSimulatorNoAuthSessionTests.SerializeParameters(new ShutdownInput(TpmSuConstants.TPM_SU_CLEAR), pool);

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
        byte[] authArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_Shutdown, shutdownParameters, pool, TestContext.CancellationToken).ConfigureAwait(false);

        (TpmRcConstants code, byte[] response) = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleForAuditAsync(
            simulator, pool, TpmCcConstants.TPM_CC_Shutdown, authArea, shutdownParameters, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "TPM2_Shutdown(CLEAR) over an audit-only companion must succeed (Table 6's tag rule).");
        Assert.AreEqual((ushort)TpmStConstants.TPM_ST_SESSIONS, TpmInHouseSimulatorNoAuthSessionTests.ReadResponseTag(response), "A successful over-session response is TPM_ST_SESSIONS-tagged.");

        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS,
            await SubmitStartupAsync(simulator, pool, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false),
            "TPM2_Startup(CLEAR) must succeed after a _TPM_Init indication.");

        byte[] followUpParameters = TpmInHouseSimulatorNoAuthSessionTests.CanonicalParametersFor(TpmCcConstants.TPM_CC_ReadClock, pool);
        byte[] followUpAuthArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_ReadClock, followUpParameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
        TpmRcConstants followUpCode = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
            simulator, pool, TpmCcConstants.TPM_CC_ReadClock, followUpAuthArea, followUpParameters, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_REFERENCE_S0, followUpCode,
            "Every loaded session is unconditionally discarded at the next TPM2_Startup(), so the same handle now answers session-encoded TPM_RC_REFERENCE_S0.");

        auditSession.Dispose();
    }

    /// <summary>
    /// "A command that is not allowed to have any sessions will not change the current exclusive audit session"
    /// implies the converse the model follows: a command that IS allowed sessions clears exclusivity whenever it
    /// runs WITHOUT an audit session — an audited <c>TPM2_ReadClock()</c> sets the exclusive session, and a
    /// following PLAIN (<c>TPM_ST_NO_SESSIONS</c>) <c>TPM2_ReadClock()</c> clears it, read back through
    /// <c>TPM2_GetSessionAuditDigest()</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, Table 232; Part 1, clause 17.2</see>.
    /// </summary>
    [TestMethod]
    public async Task TheExclusiveSessionIsSetByAnAuditedReadClockAndClearedByThePlainForm()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_GetSessionAuditDigest, TpmResponseCodec.GetSessionAuditDigest);

        byte[] parameters = TpmInHouseSimulatorNoAuthSessionTests.CanonicalParametersFor(TpmCcConstants.TPM_CC_ReadClock, pool);

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(auditSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                byte[] authArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_ReadClock, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);

                TpmRcConstants auditedCode = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_ReadClock, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, auditedCode, "The audited TPM2_ReadClock() must succeed for its exclusivity effect to be checked.");

                using(GetSessionAuditDigestInput firstDigestInput = GetSessionAuditDigestInput.ForNullSigner(TpmiShHmac.FromValue(auditHandle), ReadOnlySpan<byte>.Empty, pool))
                using(TpmPasswordSession firstEndorsement = TpmPasswordSession.CreateEmpty(pool))
                using(TpmPasswordSession firstNullSigner = TpmPasswordSession.CreateEmpty(pool))
                {
                    TpmResult<GetSessionAuditDigestResponse> firstDigestResult = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                        device, firstDigestInput, [firstEndorsement, firstNullSigner], handleNames: null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.IsTrue(firstDigestResult.IsSuccess, $"TPM2_GetSessionAuditDigest() must succeed: '{firstDigestResult.ResponseCode}'.");
                    using GetSessionAuditDigestResponse firstDigestResponse = firstDigestResult.Value;
                    Assert.IsTrue(firstDigestResponse.SessionAudit.ExclusiveSession.IsYes, "The audited TPM2_ReadClock() must set the session as exclusive on its first use.");
                }

                byte[] plainResponse = await Shared.SubmitBareAsync(simulator, pool, TpmCcConstants.TPM_CC_ReadClock, parameters).ConfigureAwait(false);
                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, ReadResponseCode(plainResponse), "The plain TPM2_ReadClock() must succeed for its exclusivity-clearing effect to be checked.");

                using GetSessionAuditDigestInput secondDigestInput = GetSessionAuditDigestInput.ForNullSigner(TpmiShHmac.FromValue(auditHandle), ReadOnlySpan<byte>.Empty, pool);
                using TpmPasswordSession secondEndorsement = TpmPasswordSession.CreateEmpty(pool);
                using TpmPasswordSession secondNullSigner = TpmPasswordSession.CreateEmpty(pool);

                TpmResult<GetSessionAuditDigestResponse> secondDigestResult = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                    device, secondDigestInput, [secondEndorsement, secondNullSigner], handleNames: null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(secondDigestResult.IsSuccess, $"TPM2_GetSessionAuditDigest() must succeed: '{secondDigestResult.ResponseCode}'.");
                using GetSessionAuditDigestResponse secondDigestResponse = secondDigestResult.Value;
                Assert.IsFalse(secondDigestResponse.SessionAudit.ExclusiveSession.IsYes, "A following PLAIN TPM2_ReadClock() must clear the exclusive session, since it ran with no audit session at all.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The <see cref="MeteredHousePool"/> balance across a successful encrypt-companion <c>TPM2_ReadPublic()</c>,
    /// a successful audit-companion <c>TPM2_NV_ReadPublic()</c> (its Index Name resolved through the asynchronous
    /// hop), an unknown-handle refusal, and a session-area slot refusal — every rented carrier comes back on
    /// every one of the four paths.
    /// </summary>
    [TestMethod]
    public async Task MeteredHousePoolIsBalancedAcrossAnEncryptSuccessAnAuditSuccessAnUnknownHandleRefusalAndASlotRefusal()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;

        using TpmSimulator simulator = await CreateOperationalWithEccBackendAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateFullRegistry();

        //Defining the Index reserves its data area for the Index's whole durable life (TPM 2.0 Library Part 3,
        //clause 31.7.1) — a genuine retained rental, not a leak — so it is set up BEFORE the baseline this test
        //tracks, which asks only whether the READ round trips below return every carrier THEY rent.
        byte[] indexName = await DefineOrdinaryIndexAsync(device, registry, pool, MeteredNvIndex).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        //(a) TPM2_ReadPublic() over an encrypt companion, driven through the production executor.
        {
            using CreatePrimaryResponse primary = await CreateEccPrimaryAsync(device, registry, pool).ConfigureAwait(false);

            (uint encryptHandle, TpmSession encryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
            try
            {
                using(encryptSession)
                {
                    encryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;
                    TpmResult<ReadPublicResponse> result = await TpmCommandExecutor.ExecuteAsync<ReadPublicResponse>(
                        device, ReadPublicInput.ForHandle(primary.ObjectHandle), [encryptSession], [primary.Name.AsReadOnlyMemory()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.IsTrue(result.IsSuccess, $"(a) must actually succeed for its balance to prove anything: '{result.ResponseCode}'.");
                    result.Value.Dispose();
                }
            }
            finally
            {
                await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, encryptHandle).ConfigureAwait(false);
                await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, primary.ObjectHandle.Value).ConfigureAwait(false);
            }
        }
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "(a) A successful encrypt-companion TPM2_ReadPublic() must return every carrier it rented.");

        //(b) TPM2_NV_ReadPublic() over an audit companion.
        {
            (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
            try
            {
                using(auditSession)
                {
                    auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                    TpmResult<NvReadPublicResponse> sessionResult = await TpmCommandExecutor.ExecuteAsync<NvReadPublicResponse>(
                        device, new NvReadPublicInput(MeteredNvIndex), [auditSession], [indexName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.IsTrue(sessionResult.IsSuccess, $"(b) must actually succeed for its balance to prove anything: '{sessionResult.ResponseCode}'.");
                    sessionResult.Value.Dispose();
                }
            }
            finally
            {
                await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
            }
        }
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "(b) A successful audit-companion TPM2_NV_ReadPublic() must return every carrier it rented.");

        //(c) TPM2_ReadPublic() addressed at an unloaded transient-range handle, refused ahead of any session
        //judgment (TPM_RC_REFERENCE_H0, TPM 2.0 Library Part 3, clause 5.4, step 2.1).
        {
            (uint sessionHandle, TpmSession session) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
            try
            {
                using(session)
                {
                    session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                    byte[] authArea = await Shared.BuildSessionAuthAreaOverHandleAsync(session, TpmCcConstants.TPM_CC_ReadPublic, ReadOnlyMemory<byte>.Empty, [], pool).ConfigureAwait(false);
                    (TpmRcConstants code, _) = await Shared.SubmitOverHandleAsync(simulator, pool, TpmCcConstants.TPM_CC_ReadPublic, UnknownObjectHandle, authArea, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
                    Assert.AreEqual(TpmRcConstants.TPM_RC_REFERENCE_H0, code, "(c) must actually refuse on the unloaded transient handle for its balance to prove anything.");
                }
            }
            finally
            {
                await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
            }
        }
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "(c) An unloaded-transient-handle refusal must return every carrier it rented.");

        //(d) TPM2_GetCapability() over a decrypt-claiming companion, refused at the session-area check.
        {
            byte[] parameters = TpmInHouseSimulatorNoAuthSessionTests.SerializeParameters(GetCapabilityInput.ForFixedProperties(), pool);
            (uint sessionHandle, TpmSession session) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
            try
            {
                using(session)
                {
                    session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;
                    byte[] authArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(session, TpmCcConstants.TPM_CC_GetCapability, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                    TpmRcConstants code = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(simulator, pool, TpmCcConstants.TPM_CC_GetCapability, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.AreEqual(
                        TpmInHouseSimulatorZeroHandleSessionTests.SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0), code,
                        "(d) must actually refuse at the slot for its balance to prove anything.");
                }
            }
            finally
            {
                await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
            }
        }
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "(d) A session-area slot refusal must return every carrier it rented.");
    }

    /// <summary>Reads a captured raw response's header response code.</summary>
    /// <param name="responseBytes">The raw response octets.</param>
    /// <returns>The response code.</returns>
    private static TpmRcConstants ReadResponseCode(byte[] responseBytes)
    {
        var reader = new TpmReader(responseBytes);

        return (TpmRcConstants)TpmHeader.Parse(ref reader).Code;
    }

    /// <summary>Frames <c>TPM2_Startup()</c> directly to the simulator, sessionless, and returns its response code.</summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="suType">The startup type.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitStartupAsync(TpmSimulator simulator, BaseMemoryPool pool, TpmSuConstants suType)
    {
        var input = new StartupInput(suType);
        byte[] response = await Shared.SubmitBareAsync(simulator, pool, (TpmCcConstants)input.CommandCode, TpmInHouseSimulatorNoAuthSessionTests.SerializeParameters(input, pool)).ConfigureAwait(false);

        return ReadResponseCode(response);
    }

    /// <summary>
    /// Builds a one-slot authorization block naming an HMAC-session-range handle no test in this class ever
    /// starts a real session at, an empty nonce, <c>audit</c> SET, and an empty hmac — a slot that resolves to
    /// nothing before its own attribute or HMAC could ever matter.
    /// </summary>
    /// <returns>The block's octets, without the authorizationSize field that precedes them.</returns>
    private static byte[] BuildMalformedSessionSlot()
    {
        byte[] block = new byte[sizeof(uint) + sizeof(ushort) + sizeof(byte) + sizeof(ushort)];
        BinaryPrimitives.WriteUInt32BigEndian(block.AsSpan(0, sizeof(uint)), UnloadedHmacSessionHandle);
        BinaryPrimitives.WriteUInt16BigEndian(block.AsSpan(sizeof(uint), sizeof(ushort)), 0);
        block[sizeof(uint) + sizeof(ushort)] = (byte)TpmaSession.AUDIT;
        BinaryPrimitives.WriteUInt16BigEndian(block.AsSpan(sizeof(uint) + sizeof(ushort) + sizeof(byte), sizeof(ushort)), 0);

        return block;
    }

    /// <summary>
    /// Starts a hash sequence with <c>TPM2_HashSequenceStart()</c>, plain and sessionless — no handle, no backend
    /// needed — and returns the new sequence handle straight off the wire.
    /// </summary>
    /// <param name="simulator">The simulator under test.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="password">The sequence's own authorization value.</param>
    /// <returns>The sequence handle.</returns>
    private async Task<uint> StartHashSequenceAsync(TpmSimulator simulator, BaseMemoryPool pool, string password)
    {
        byte[] parameters;
        using(HashSequenceStartInput startInput = HashSequenceStartInput.CreateFromPassword(password, TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256), pool))
        {
            parameters = TpmInHouseSimulatorNoAuthSessionTests.SerializeParameters(startInput, pool);
        }

        byte[] response = await Shared.SubmitBareAsync(simulator, pool, TpmCcConstants.TPM_CC_HashSequenceStart, parameters).ConfigureAwait(false);
        var reader = new TpmReader(response);
        TpmHeader header = TpmHeader.Parse(ref reader);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)header.Code, "TPM2_HashSequenceStart() must succeed to set up the sequence-handle fixture.");

        return reader.ReadUInt32();
    }

    /// <summary>Creates an unrestricted ECC P-256 signing primary under the owner hierarchy with an empty password, asserting success.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateEccPrimaryAsync(TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            device, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_CreatePrimary() (ECC P-256) must succeed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Defines an ordinary NV Index with a small data area under owner authorization, asserting success.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    /// <returns>The defined Index's own Name.</returns>
    private async Task<byte[]> DefineOrdinaryIndexAsync(TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool, uint nvIndex)
    {
        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);
        using Tpm2bAuth indexAuth = Tpm2bAuth.Create([0x05, 0x06], pool);
        using var publicInfo = new TpmsNvPublic(nvIndex, TpmAlgIdConstants.TPM_ALG_SHA256, TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE, Tpm2bDigest.Empty, dataSize: 8);
        using var defineInput = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, indexAuth, publicInfo);
        TpmResult<NvDefineSpaceResponse> defineResult = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            device, defineInput, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"TPM2_NV_DefineSpace() must succeed: '{defineResult.ResponseCode}'.");

        TpmResult<NvReadPublicResponse> plainResult = await TpmCommandExecutor.ExecuteAsync<NvReadPublicResponse>(
            device, new NvReadPublicInput(nvIndex), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(plainResult.IsSuccess, $"The plain TPM2_NV_ReadPublic() form must succeed to read back the defined Index's Name: '{plainResult.ResponseCode}'.");
        using NvReadPublicResponse plainResponse = plainResult.Value;

        return plainResponse.NvName.Span.ToArray();
    }

    /// <summary>Creates a response codec registry covering every command this class issues through the production executor.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateFullRegistry() =>
        new TpmResponseRegistry()
            .Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary)
            .Register(TpmCcConstants.TPM_CC_ReadPublic, TpmResponseCodec.ReadPublic)
            .Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace)
            .Register(TpmCcConstants.TPM_CC_NV_ReadPublic, TpmResponseCodec.NvReadPublic)
            .Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession)
            .Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext)
            .Register(TpmCcConstants.TPM_CC_EvictControl, TpmResponseCodec.EvictControl)
            .Register(TpmCcConstants.TPM_CC_GetSessionAuditDigest, TpmResponseCodec.GetSessionAuditDigest);

    /// <summary>
    /// Creates a simulator, powers it on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the operational
    /// phase — no signing backend, matching every test in this class that never creates an asymmetric key.
    /// </summary>
    /// <param name="selfTest">The scripted self-test behaviour; <see cref="TpmSelfTestBehavior.Passes"/> by default.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(TpmSelfTestBehavior selfTest = TpmSelfTestBehavior.Passes)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var simulator = new TpmSimulator("tpm-in-house-no-auth-read-command",selfTest: selfTest, rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS,
            await SubmitStartupAsync(simulator, pool, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false),
            "TPM2_Startup(CLEAR) must succeed.");

        return simulator;
    }

    /// <summary>
    /// Creates a simulator with the ECC (BouncyCastle) signing backend wired, powers it on, and brings it through
    /// <c>TPM2_Startup(CLEAR)</c> into the operational phase — <c>TPM2_CreatePrimary()</c> needs a signing
    /// backend to answer anything but <c>TPM_RC_COMMAND_CODE</c>.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalWithEccBackendAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator("tpm-in-house-no-auth-read-command-ecc", signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS,
            await SubmitStartupAsync(simulator, pool, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false),
            "TPM2_Startup(CLEAR) must succeed.");

        return simulator;
    }

    /// <summary>
    /// A companion whose command HMAC does not verify is refused at its own index BEFORE
    /// <c>TPM2_ReadPublic()</c>'s own sequence-handle resolution is ever reached: the session-encoded
    /// <c>TPM_RC_BAD_AUTH</c> this test asserts — not the inner's bare <c>TPM_RC_SEQUENCE</c> — is the
    /// discriminating proof that the authorization area is judged first. The session's nonceTPM is left untouched
    /// by the refusal, and the hash sequence itself is never disturbed.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3,
    /// clause 5.5; clause 5.9; clause 12.4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ReadPublicOverASequenceHandleWithAWrongCompanionHmacReturnsBadAuthAndLeavesTheSessionUsable()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_SequenceComplete, TpmResponseCodec.SequenceComplete);

        uint sequenceHandle = await StartHashSequenceAsync(simulator, pool, string.Empty).ConfigureAwait(false);

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(auditSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                byte[] authArea = await Shared.BuildSessionAuthAreaOverHandleAsync(auditSession, TpmCcConstants.TPM_CC_ReadPublic, ReadOnlyMemory<byte>.Empty, [], pool).ConfigureAwait(false);
                authArea[^1] ^= 0xFF;

                (TpmRcConstants code, byte[] response) = await Shared.SubmitOverHandleAsync(simulator, pool, TpmCcConstants.TPM_CC_ReadPublic, sequenceHandle, authArea, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmInHouseSimulatorZeroHandleSessionTests.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), code,
                    "The companion's own HMAC is refused before the sequence handle is ever resolved — not the inner's TPM_RC_SEQUENCE.");
                Assert.AreEqual((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, TpmInHouseSimulatorNoAuthSessionTests.ReadResponseTag(response), "A failed command frames TPM_ST_NO_SESSIONS regardless of the request's own tag.");
                Assert.HasCount(10, response, "A failed command's response is exactly the 10-octet header (Part 3, clause 5.9).");

                byte[] followUpParameters = TpmInHouseSimulatorZeroHandleSessionTests.ParameterAreaFor(TpmCcConstants.TPM_CC_TestParms, pool);
                byte[] followUpAuthArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_TestParms, followUpParameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                TpmRcConstants followUpCode = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_TestParms, followUpAuthArea, followUpParameters, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, followUpCode, "The session's nonceTPM was never touched by the refusal, so a genuine follow-up command over it still verifies.");

                using SequenceCompleteInput probeInput = SequenceCompleteInput.Create(TpmiDhObject.FromValue(sequenceHandle), [], TpmiRhHierarchy.Null, pool);
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
    /// A <c>decrypt</c>-claiming companion at <c>TPM2_ReadPublic()</c>'s sole slot is refused session-encoded
    /// <c>TPM_RC_ATTRIBUTES</c> regardless of what the handle resolves to — a sequence handle included: the
    /// refusal is judged from the command's own static shape (no sized first command parameter,
    /// <see cref="ReadPublicAndNvReadPublicDecryptCompanionsAreRefusedWithAttributes"/> proves it on a loaded
    /// primary), not from the handle's kind, so the sequence-slot gate's own <c>TPM_RC_SEQUENCE</c> is never
    /// reached at all.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3,
    /// clause 5.5, step 4.4.2; clause 12.4.1; Part 1, clause 15.6.4, Table 15</see>.
    /// </summary>
    [TestMethod]
    public async Task ReadPublicOverADecryptSlotOnASequenceHandleIsRefusedWithAttributesRegardlessOfTheHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        uint sequenceHandle = await StartHashSequenceAsync(simulator, pool, "no-auth-read-command-decrypt-sequence-auth").ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                byte[] authArea = await Shared.BuildSessionAuthAreaOverHandleAsync(session, TpmCcConstants.TPM_CC_ReadPublic, ReadOnlyMemory<byte>.Empty, [], pool).ConfigureAwait(false);

                (TpmRcConstants code, _) = await Shared.SubmitOverHandleAsync(simulator, pool, TpmCcConstants.TPM_CC_ReadPublic, sequenceHandle, authArea, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmInHouseSimulatorZeroHandleSessionTests.SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0), code,
                    "TPM2_ReadPublic() has no sized command parameter of its own, so a decrypt claim is refused session-encoded TPM_RC_ATTRIBUTES even over a sequence handle — the inner's TPM_RC_SEQUENCE is never reached.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A sequence handle's Name term is the Empty Buffer ("the Name associated with sequenceHandle will be the
    /// Empty Buffer"), so an <c>encrypt</c>-claiming companion — the one non-audit attribute claim
    /// <c>TPM2_ReadPublic()</c> actually admits, since its <c>outPublic</c> is a sized first response parameter
    /// while its request carries none (a <c>decrypt</c> claim is always refused
    /// <c>TPM_RC_ATTRIBUTES</c>, proved by
    /// <see cref="ReadPublicOverADecryptSlotOnASequenceHandleIsRefusedWithAttributesRegardlessOfTheHandle"/>) — is
    /// verified over it exactly like the audit case BEFORE the inner's own sequence-slot gate answers bare
    /// <c>TPM_RC_SEQUENCE</c>: the response is still bare, framed <c>TPM_ST_NO_SESSIONS</c> in exactly 10 octets
    /// (no response parameter exists for the companion to protect, since the command failed), and the
    /// companion's nonceTPM is that of a session that verified and then hit a dropped pending frame, not one
    /// turned away pre-verification.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1,
    /// Table 9 footnote (1) and clause 29.4.6; Part 3, clauses 5.4, 5.9 and 12.4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ReadPublicOverAnEncryptSlotOnASequenceHandleAnswersBareSequenceAfterTheSessionsVerified()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        uint sequenceHandle = await StartHashSequenceAsync(simulator, pool, "no-auth-read-command-encrypt-sequence-auth").ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                byte[] authArea = await Shared.BuildSessionAuthAreaOverHandleAsync(session, TpmCcConstants.TPM_CC_ReadPublic, ReadOnlyMemory<byte>.Empty, [], pool).ConfigureAwait(false);

                (TpmRcConstants code, byte[] response) = await Shared.SubmitOverHandleAsync(simulator, pool, TpmCcConstants.TPM_CC_ReadPublic, sequenceHandle, authArea, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_SEQUENCE, code, "A sequence handle at TPM2_ReadPublic()'s slot answers the inner's own bare TPM_RC_SEQUENCE, after the encrypt companion's session area verifies.");
                Assert.AreEqual((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, TpmInHouseSimulatorNoAuthSessionTests.ReadResponseTag(response), "A failed command frames TPM_ST_NO_SESSIONS regardless of the request's own tag.");
                Assert.HasCount(10, response, "A failed command's response is exactly the 10-octet header (Part 3, clause 5.9).");

                //TPM2_TestParms() has no sized first response parameter of its own (an encrypt claim over a
                //shapeless response is itself refused TPM_RC_ATTRIBUTES) and, being a no-authorization command,
                //still needs at least one of decrypt/encrypt/audit SET (clause 5.5, step 4.4.2) — so the
                //follow-up switches the claim to audit, proving nonce liveness the same way the sibling
                //audit-companion pin's own follow-up does.
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                byte[] followUpParameters = TpmInHouseSimulatorZeroHandleSessionTests.ParameterAreaFor(TpmCcConstants.TPM_CC_TestParms, pool);
                byte[] followUpAuthArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(session, TpmCcConstants.TPM_CC_TestParms, followUpParameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                TpmRcConstants followUpCode = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_TestParms, followUpAuthArea, followUpParameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, followUpCode, "The session's nonceTPM was left untouched by the dropped pending frame, so a genuine follow-up command over it still verifies.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The <c>encrypt</c>-claiming twin of
    /// <see cref="ReadPublicOverASequenceHandleWithAWrongCompanionHmacReturnsBadAuthAndLeavesTheSessionUsable"/>:
    /// a companion whose command HMAC does not verify is refused at its own index BEFORE
    /// <c>TPM2_ReadPublic()</c>'s own sequence-handle resolution is ever reached, regardless of which admitted
    /// attribute the companion claims — the session-encoded <c>TPM_RC_BAD_AUTH</c> this test asserts, not the
    /// inner's bare <c>TPM_RC_SEQUENCE</c>, is the discriminating proof that the authorization area is judged
    /// first. The session's nonceTPM is left untouched by the refusal, and the hash sequence itself is never
    /// disturbed.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3,
    /// clause 5.5; clause 5.9; clause 12.4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ReadPublicOverASequenceHandleWithAWrongEncryptCompanionHmacReturnsBadAuthAndLeavesTheSessionUsable()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_SequenceComplete, TpmResponseCodec.SequenceComplete);

        uint sequenceHandle = await StartHashSequenceAsync(simulator, pool, string.Empty).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                byte[] authArea = await Shared.BuildSessionAuthAreaOverHandleAsync(session, TpmCcConstants.TPM_CC_ReadPublic, ReadOnlyMemory<byte>.Empty, [], pool).ConfigureAwait(false);
                authArea[^1] ^= 0xFF;

                (TpmRcConstants code, byte[] response) = await Shared.SubmitOverHandleAsync(simulator, pool, TpmCcConstants.TPM_CC_ReadPublic, sequenceHandle, authArea, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmInHouseSimulatorZeroHandleSessionTests.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), code,
                    "The encrypt companion's own HMAC is refused before the sequence handle is ever resolved — not the inner's TPM_RC_SEQUENCE.");
                Assert.AreEqual((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, TpmInHouseSimulatorNoAuthSessionTests.ReadResponseTag(response), "A failed command frames TPM_ST_NO_SESSIONS regardless of the request's own tag.");
                Assert.HasCount(10, response, "A failed command's response is exactly the 10-octet header (Part 3, clause 5.9).");

                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                byte[] followUpParameters = TpmInHouseSimulatorZeroHandleSessionTests.ParameterAreaFor(TpmCcConstants.TPM_CC_TestParms, pool);
                byte[] followUpAuthArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(session, TpmCcConstants.TPM_CC_TestParms, followUpParameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                TpmRcConstants followUpCode = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_TestParms, followUpAuthArea, followUpParameters, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, followUpCode, "The session's nonceTPM was never touched by the refusal, so a genuine follow-up command over it still verifies.");

                using SequenceCompleteInput probeInput = SequenceCompleteInput.Create(TpmiDhObject.FromValue(sequenceHandle), [], TpmiRhHierarchy.Null, pool);
                using TpmPasswordSession sequencePassword = TpmPasswordSession.CreateEmpty(pool);
                TpmResult<SequenceCompleteResponse> stillOpenResult = await TpmCommandExecutor.ExecuteAsync<SequenceCompleteResponse>(
                    device, probeInput, [sequencePassword], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(stillOpenResult.IsSuccess, "The hash sequence itself was never reached by the refused companion and can still be completed.");
                stillOpenResult.Value.Dispose();
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }
}
