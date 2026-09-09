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
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives the no-authorization commands over 2- and 3-slot authorization areas — the shape beyond the ONE
/// companion slot <see cref="TpmInHouseSimulatorZeroHandleSessionTests"/> already proves — against
/// the in-house behavioural <see cref="TpmSimulator"/>, entirely in-process with no external assets. Every case
/// is hand-framed over that class's own fixture, extended here rather than re-minted: multiple
/// <c>TPMS_AUTH_COMMAND</c> blocks concatenate freely, since cpHash is the SAME term regardless of how many
/// sessions verify it (TPM 2.0 Library Part 1, clause 15.7, equation 15) and each block's own command HMAC is
/// computed independently over it.
/// TPM 2.0 Library Part 3, clauses 4.3, 5.5, 5.9, 16.1, 16.2 and 30.3; Part 1, clauses 15.6.1, 15.6.4, 17.1 and 18.
/// </summary>
/// <remarks>
/// <c>TPM2_GetRandom()</c>'s own inner (post-session) refusal is unreachable over this table: every <c>UINT16</c>
/// value is a well-formed <c>bytesRequested</c>, and an over-large request is clamped rather than refused, so no
/// case here exercises that path for <c>TPM2_GetRandom()</c> specifically — <c>TPM2_TestParms()</c>'s own
/// refused-profile cases carry the inner-refusal proof for this table instead.
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorNoAuthSessionTests
{
    /// <summary>The octet count the framed <c>TPM2_GetRandom()</c> parameter area asks for.</summary>
    private const ushort RandomDrawLength = 16;

    /// <summary>The symmetric definition a slot claiming <c>decrypt</c> or <c>encrypt</c> negotiates in these tests.</summary>
    private static TpmtSymDef SessionSymmetric { get; } = TpmtSymDef.Xor(TpmAlgIdConstants.TPM_ALG_SHA256);

    /// <summary>
    /// The <c>TPMT_PUBLIC_PARMS</c> a profile-refusing <c>TPM2_TestParms()</c> composes: a raw algorithm ID this
    /// model implements no <c>TPMU_PUBLIC_PARMS</c> selector for, answering the interface type's own bare code
    /// before any session-index encoding could apply (TPM 2.0 Library Part 3, clause 5.8.2).
    /// </summary>
    private static byte[] UnimplementedAlgorithmParms { get; } = [0x00, 0x25];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// <c>TPM2_GetRandom()</c> over TWO companion slots — an unbound session claiming <c>audit</c> at index 0, a
    /// second unbound session claiming <c>encrypt</c> at index 1 — succeeds with a <c>TPM_ST_SESSIONS</c>-tagged
    /// response carrying exactly two response-session entries: the framed <c>randomBytes</c> TPM2B is exactly as
    /// wide as requested, since parameter encryption never changes a TPM2B's declared size ("the encrypted data
    /// size and the plain-text data size is the same", TPM 2.0 Library Part 1, clause 18.1), and the audit
    /// session's digest extends to <c>H(0…0 ‖ cpHash ‖ rpHash)</c> chained from this exchange's own wire octets
    /// and read back through <c>TPM2_GetSessionAuditDigest()</c>'s NULL signer — proving Part 1, clause 15.6.1's
    /// "at least one but no more than three" authorization blocks admits more than the ONE companion slot the
    /// zero-handle table's own fixture already covers.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 16.1; Part 1, clauses 15.6.1, 17.1 and 18.1</see>.
    /// </summary>
    [TestMethod]
    public async Task GetRandomOverAnAuditSlotAndAnEncryptSlotSucceedsWithTwoResponseEntriesAndTheAuditDigestChained()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_GetSessionAuditDigest, TpmResponseCodec.GetSessionAuditDigest);

        byte[] parameters = TpmInHouseSimulatorZeroHandleSessionTests.ParameterAreaFor(TpmCcConstants.TPM_CC_GetRandom, pool);

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        (uint encryptHandle, TpmSession encryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        try
        {
            using(auditSession)
            using(encryptSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                encryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                byte[] authArea =
                [
                    .. await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_GetRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false),
                    .. await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(encryptSession, TpmCcConstants.TPM_CC_GetRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false),
                ];

                (TpmRcConstants code, byte[] response) = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleForAuditAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_GetRandom, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "Two admissible companion claims over GetRandom must succeed.");
                Assert.AreEqual((ushort)TpmStConstants.TPM_ST_SESSIONS, ReadResponseTag(response), "A successful over-session response is TPM_ST_SESSIONS-tagged.");
                Assert.HasCount(2, ReadResponseSessionEntries(response, outHandleCount: 0), "Both companion slots must frame their own response-session entry.");

                byte[] responseParameters = TpmInHouseSimulatorZeroHandleSessionTests.ReadResponseParameters(response, outHandleCount: 0);
                ushort framedRandomLength = BinaryPrimitives.ReadUInt16BigEndian(responseParameters);
                Assert.AreEqual(RandomDrawLength, framedRandomLength, "The framed randomBytes TPM2B is exactly as wide as requested, encrypted or not.");

                byte auditedAttributes = TpmInHouseSimulatorZeroHandleSessionTests.ReadResponseSessionAttributes(response, outHandleCount: 0, sessionIndex: 0);
                Assert.AreEqual(
                    (byte)(TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT | TpmaSession.AUDIT_EXCLUSIVE), auditedAttributes,
                    "The audit slot's response echoes audit SET and auditExclusive SET on its first use, auditReset CLEAR.");

                byte[] cpHash = await TpmInHouseSimulatorZeroHandleSessionTests.ComputeZeroHandleCpHashAsync(TpmCcConstants.TPM_CC_GetRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                byte[] rpHash = await TpmInHouseSimulatorZeroHandleSessionTests.ComputeRpHashAsync(TpmCcConstants.TPM_CC_GetRandom, responseParameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
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
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, encryptHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_StirRandom()</c> over TWO companion slots — an unbound session claiming <c>audit</c>, a second
    /// claiming <c>decrypt</c> over a real (non-NULL) symmetric definition — succeeds and genuinely folds the
    /// caller's <c>inData</c> into the RNG reseed state: the next draw over a fresh, otherwise-identical
    /// simulator (which never issued the stir) differs from the stirred instance's own next draw, proving the
    /// two-slot area's decrypt claim recovered the caller's octets before the reseed folded them.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 16.2; Part 1, clauses 15.6.1 and 18.1</see>.
    /// </summary>
    [TestMethod]
    public async Task StirRandomOverAnAuditSlotAndADecryptSlotSucceedsAndFoldsTheRecoveredInData()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        byte[] stirredDraw;
        using(TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false))
        {
            using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
            TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

            byte[] parameters = TpmInHouseSimulatorZeroHandleSessionTests.ParameterAreaFor(TpmCcConstants.TPM_CC_StirRandom, pool);

            (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
            (uint decryptHandle, TpmSession decryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
            try
            {
                using(auditSession)
                using(decryptSession)
                {
                    auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                    decryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                    byte[] authArea =
                    [
                        .. await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_StirRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false),
                        .. await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(decryptSession, TpmCcConstants.TPM_CC_StirRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false),
                    ];

                    TpmRcConstants code = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                        simulator, pool, TpmCcConstants.TPM_CC_StirRandom, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

                    Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "An audit claim plus a real (non-NULL) decrypt claim over StirRandom must succeed.");
                }
            }
            finally
            {
                await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
                await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, decryptHandle).ConfigureAwait(false);
            }

            stirredDraw = await DrawRandomBareAsync(simulator, pool).ConfigureAwait(false);
        }

        using TpmSimulator unstirredTwin = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] unstirredDraw = await DrawRandomBareAsync(unstirredTwin, pool).ConfigureAwait(false);

        Assert.AreNotSequenceEqual(unstirredDraw, stirredDraw, "The recovered inData must genuinely fold into the RNG state, so the stirred twin's draw diverges from an otherwise-identical, unstirred instance's.");
    }

    /// <summary>
    /// "Only one session is allowed for... session auditing (TPM_RC_ATTRIBUTES)" — a second slot claiming
    /// <c>audit</c> is refused, blamed on the SECOND occurrence's own index, not the first.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.5, step 4.4.1; Part 2, clause 6.6.2</see>.
    /// </summary>
    [TestMethod]
    public async Task GetRandomOverTwoAuditClaimingSlotsReturnsSessionEncodedAttributesAtTheSecondIndex()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        byte[] parameters = TpmInHouseSimulatorZeroHandleSessionTests.ParameterAreaFor(TpmCcConstants.TPM_CC_GetRandom, pool);

        (uint firstHandle, TpmSession firstSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        (uint secondHandle, TpmSession secondSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(firstSession)
            using(secondSession)
            {
                firstSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                secondSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                byte[] authArea =
                [
                    .. await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(firstSession, TpmCcConstants.TPM_CC_GetRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false),
                    .. await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(secondSession, TpmCcConstants.TPM_CC_GetRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false),
                ];

                TpmRcConstants code = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_GetRandom, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmInHouseSimulatorZeroHandleSessionTests.SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 1), code,
                    "A second slot claiming audit is refused, blamed on its own (second) index, once the first slot has already verified.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, firstHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, secondHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "If the maximum allowed number of sessions have been unmarshaled and fewer octets than indicated in
    /// authorizationSize were unmarshaled (that is, authorizationSize is too large), the TPM shall return
    /// TPM_RC_AUTHSIZE." — a fourth well-formed block beyond the three-slot maximum leaves octets the frame's own
    /// declared <c>authorizationSize</c> cannot account for, refused bare, before any slot's HMAC is judged.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.5, step 4.3; Part 1, clause 15.6.1</see>.
    /// </summary>
    [TestMethod]
    public async Task TestParmsOverAFourBlockAreaReturnsBareAuthsize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        byte[] parameters = TpmInHouseSimulatorZeroHandleSessionTests.ParameterAreaFor(TpmCcConstants.TPM_CC_TestParms, pool);

        (uint sessionHandle, TpmSession session) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                var authArea = new List<byte>();
                for(int i = 0; i < 4; i++)
                {
                    authArea.AddRange(await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(session, TpmCcConstants.TPM_CC_TestParms, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false));
                }

                TpmRcConstants code = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_TestParms, authArea.ToArray(), parameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_AUTHSIZE, code, "A fourth authorization block beyond the three-slot maximum is bare TPM_RC_AUTHSIZE.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_TestParms()</c> over an audit-claiming companion succeeds at the session area, so its own
    /// parameters are finally judged (TPM 2.0 Library Part 3, clause 5.5 precedes clause 5.8) — and, for a
    /// combination this model implements no <c>TPMU_PUBLIC_PARMS</c> selector for, answers that judgment's own
    /// bare refusal, framed as a <c>TPM_ST_NO_SESSIONS</c>, exactly 10-octet response ("the post processing code will
    /// not update any session or audit data and will return a 10-octet response packet", clause 5.9): the
    /// session's nonceTPM is left exactly where it stood, so a genuine follow-up command over the SAME session
    /// still verifies.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 5.5, 5.9 and 30.3; Part 2, clause 12.2.3.10, Table 234</see>.
    /// </summary>
    [TestMethod]
    public async Task TestParmsOverAnAuditSlotWithARefusedProfileAnswersTheInnersBareCodeAndLeavesTheSessionUsable()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        (uint sessionHandle, TpmSession session) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                byte[] authArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(session, TpmCcConstants.TPM_CC_TestParms, UnimplementedAlgorithmParms, pool, TestContext.CancellationToken).ConfigureAwait(false);

                (TpmRcConstants code, byte[] response) = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleForAuditAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_TestParms, authArea, UnimplementedAlgorithmParms, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(
                    HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_TYPE, parameterIndex: 0), code,
                    "Table 240: parameters is TPM2_TestParms()'s sole parameter (index 0); an unimplemented TPMU_PUBLIC_PARMS selector answers that parameter's own TPM_RC_TYPE, never session-encoded (TestParms admits no decrypt companion).");
                Assert.AreEqual((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, ReadResponseTag(response), "A failed command frames TPM_ST_NO_SESSIONS regardless of the request's own tag.");
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
    /// The <see cref="MeteredHousePool"/> balance across a successful two-slot round trip, a session-area
    /// refusal, and an inner-core refusal — every rented carrier (both slots' nonce and hmac, the parameter
    /// area, the framed response's own buffers) comes back on every one of the three paths.
    /// </summary>
    [TestMethod]
    public async Task NoAuthorizationCommandsReturnTheirCarriersAcrossSuccessAnAreaRefusalAndAnInnerRefusal()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;

        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_GetSessionAuditDigest, TpmResponseCodec.GetSessionAuditDigest);

        long baseline = trackingPool.OutstandingCount;

        //(a) The successful two-slot GetRandom round trip.
        {
            byte[] parameters = TpmInHouseSimulatorZeroHandleSessionTests.ParameterAreaFor(TpmCcConstants.TPM_CC_GetRandom, pool);
            (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
            (uint encryptHandle, TpmSession encryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
            try
            {
                using(auditSession)
                using(encryptSession)
                {
                    auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                    encryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                    byte[] authArea =
                    [
                        .. await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_GetRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false),
                        .. await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(encryptSession, TpmCcConstants.TPM_CC_GetRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false),
                    ];

                    TpmRcConstants code = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                        simulator, pool, TpmCcConstants.TPM_CC_GetRandom, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "(a) must actually succeed for its balance to prove anything.");
                }
            }
            finally
            {
                await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
                await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, encryptHandle).ConfigureAwait(false);
            }

            Assert.AreEqual(baseline, trackingPool.OutstandingCount, "(a) A successful two-slot round trip must return every carrier it rented.");
        }

        //(c) The second-audit-claim area refusal.
        {
            byte[] parameters = TpmInHouseSimulatorZeroHandleSessionTests.ParameterAreaFor(TpmCcConstants.TPM_CC_GetRandom, pool);
            (uint firstHandle, TpmSession firstSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
            (uint secondHandle, TpmSession secondSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
            try
            {
                using(firstSession)
                using(secondSession)
                {
                    firstSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                    secondSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                    byte[] authArea =
                    [
                        .. await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(firstSession, TpmCcConstants.TPM_CC_GetRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false),
                        .. await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(secondSession, TpmCcConstants.TPM_CC_GetRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false),
                    ];

                    TpmRcConstants code = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                        simulator, pool, TpmCcConstants.TPM_CC_GetRandom, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.AreEqual(
                        TpmInHouseSimulatorZeroHandleSessionTests.SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 1), code,
                        "(c) must actually refuse at the second slot for its balance to prove anything.");
                }
            }
            finally
            {
                await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, firstHandle).ConfigureAwait(false);
                await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, secondHandle).ConfigureAwait(false);
            }

            Assert.AreEqual(baseline, trackingPool.OutstandingCount, "(c) A session-area refusal must return every carrier it rented.");
        }

        //(e) The inner-core (profile) refusal.
        {
            (uint sessionHandle, TpmSession session) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
            try
            {
                using(session)
                {
                    session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                    byte[] authArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(session, TpmCcConstants.TPM_CC_TestParms, UnimplementedAlgorithmParms, pool, TestContext.CancellationToken).ConfigureAwait(false);

                    TpmRcConstants code = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                        simulator, pool, TpmCcConstants.TPM_CC_TestParms, authArea, UnimplementedAlgorithmParms, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.AreEqual(
                        HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_TYPE, parameterIndex: 0), code,
                        "Table 240: parameters is TPM2_TestParms()'s sole parameter (index 0); (e) must actually refuse at the inner core for its balance to prove anything.");
                }
            }
            finally
            {
                await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
            }

            Assert.AreEqual(baseline, trackingPool.OutstandingCount, "(e) An inner-core refusal must return every carrier it rented, including the request's own inner value.");
        }
    }

    /// <summary>
    /// <c>TPM2_ReadClock()</c> over an audit-only companion succeeds with a <c>TPM_ST_SESSIONS</c>-tagged
    /// response, and the audit session's digest extends to <c>H(0…0 ‖ cpHash ‖ rpHash)</c> chained from this
    /// exchange's own wire octets and read back through <c>TPM2_GetSessionAuditDigest()</c>'s NULL signer —
    /// proving <c>TPM2_ReadClock()</c>'s <c>TPM_ST_SESSIONS</c> form has the TPM read the authorization area
    /// rather than dropping it.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 29.1, Table 232; Part 1, clauses 15.6.1, 17.1 and 18.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ReadClockOverAnAuditSlotSucceedsWithTheAuditDigestChained()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_GetSessionAuditDigest, TpmResponseCodec.GetSessionAuditDigest);

        byte[] parameters = SerializeParameters(new ReadClockInput(), pool);

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(auditSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                byte[] authArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_ReadClock, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);

                (TpmRcConstants code, byte[] response) = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleForAuditAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_ReadClock, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "TPM2_ReadClock() over an audit-only companion must succeed (Table 232's tag rule).");
                Assert.AreEqual((ushort)TpmStConstants.TPM_ST_SESSIONS, ReadResponseTag(response), "A successful over-session response is TPM_ST_SESSIONS-tagged.");

                byte[] responseParameters = TpmInHouseSimulatorZeroHandleSessionTests.ReadResponseParameters(response, outHandleCount: 0);
                byte[] cpHash = await TpmInHouseSimulatorZeroHandleSessionTests.ComputeZeroHandleCpHashAsync(TpmCcConstants.TPM_CC_ReadClock, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                byte[] rpHash = await TpmInHouseSimulatorZeroHandleSessionTests.ComputeRpHashAsync(TpmCcConstants.TPM_CC_ReadClock, responseParameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
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
    /// <c>TPM2_GetCapability()</c> over an audit-only companion succeeds and answers the SAME
    /// <c>TPM_CAP_TPM_PROPERTIES</c> parameter octets the plain, sessionless form answers — the audit companion
    /// changes only the framing, never the command's own answer.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, Table 238; Part 1, clause 15.6.1</see>.
    /// </summary>
    [TestMethod]
    public async Task GetCapabilityOverAnAuditSlotSucceedsWithTheSamePropertiesAsThePlainForm()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        byte[] parameters = SerializeParameters(GetCapabilityInput.ForFixedProperties(), pool);

        byte[] plainResponse = await SubmitBareAsync(simulator, pool, TpmCcConstants.TPM_CC_GetCapability, parameters).ConfigureAwait(false);
        byte[] plainParameters = plainResponse[TpmHeader.HeaderSize..];

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(auditSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                byte[] authArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_GetCapability, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);

                (TpmRcConstants code, byte[] response) = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleForAuditAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_GetCapability, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "TPM2_GetCapability() over an audit-only companion must succeed (Table 238's tag rule).");

                byte[] sessionParameters = TpmInHouseSimulatorZeroHandleSessionTests.ReadResponseParameters(response, outHandleCount: 0);
                Assert.AreSequenceEqual(plainParameters, sessionParameters, "The audited answer must equal the plain form's own TPM_CAP_TPM_PROPERTIES answer, octet for octet.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_ReadPublic()</c> over an audit-only companion, the addressed key's own Name folded into cpHash
    /// BEFORE the authorization area is judged (TPM 2.0 Library Part 3, clause 5.4 precedes clause 5.5), succeeds with a
    /// <c>TPM_ST_SESSIONS</c>-tagged response; the audit digest extends to <c>H(0…0 ‖ cpHash ‖ rpHash)</c>
    /// chained from this exchange's own wire octets and read back through <c>TPM2_GetSessionAuditDigest()</c>'s
    /// NULL signer, proving the resolved Name genuinely enters the folded cpHash the response HMAC and audit
    /// extend both key on.
    /// </summary>
    /// <remarks>
    /// Hand-framed rather than driven through <see cref="TpmCommandExecutor"/>: proving the audit digest formula
    /// needs cpHash and rpHash chained by hand from this exchange's own raw wire octets — the exact bytes sent
    /// and received — rather than from any value a codec parsed, so the test frames the command itself and reads
    /// the response's raw octets directly.
    /// </remarks>
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.4, Table 24; Part 1, clauses 15.7, 17.1 and 18.1</see>.
    [TestMethod]
    public async Task ReadPublicOverAnAuditSlotSucceedsWithTheKeyNameChainedIntoTheAuditDigest()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalWithEccBackendAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary)
            .Register(TpmCcConstants.TPM_CC_GetSessionAuditDigest, TpmResponseCodec.GetSessionAuditDigest);

        using CreatePrimaryInput createInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            device, createInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"TPM2_CreatePrimary() must succeed: '{createResult.ResponseCode}'.");
        using CreatePrimaryResponse primary = createResult.Value;
        byte[] keyName = primary.Name.Span.ToArray();

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(auditSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                byte[] authArea = await BuildSessionAuthAreaOverHandleAsync(auditSession, TpmCcConstants.TPM_CC_ReadPublic, keyName, [], pool).ConfigureAwait(false);

                (TpmRcConstants code, byte[] response) = await SubmitOverHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_ReadPublic, primary.ObjectHandle.Value, authArea, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "TPM2_ReadPublic() over an audit-only companion, with the key's own Name folded into cpHash, must succeed.");
                Assert.AreEqual((ushort)TpmStConstants.TPM_ST_SESSIONS, ReadResponseTag(response), "A successful over-session response is TPM_ST_SESSIONS-tagged.");

                byte[] responseParameters = TpmInHouseSimulatorZeroHandleSessionTests.ReadResponseParameters(response, outHandleCount: 0);
                byte[] cpHash = await ComputeCpHashWithNameAsync(TpmCcConstants.TPM_CC_ReadPublic, keyName, ReadOnlyMemory<byte>.Empty, pool).ConfigureAwait(false);
                byte[] rpHash = await TpmInHouseSimulatorZeroHandleSessionTests.ComputeRpHashAsync(TpmCcConstants.TPM_CC_ReadPublic, responseParameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
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
                    "The audit session's digest must equal H(0…0 ‖ cpHash ‖ rpHash), with the key's own Name folded into cpHash, chained from this exchange's own wire octets.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_ReadPublic()</c> over an encrypt-only companion succeeds; the production executor decrypts
    /// <c>outPublic</c> before parsing it once the response HMAC verifies, so the typed response equals the
    /// plain form's own octets exactly.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.4, Table 24; Part 1, clauses 15.7 and 18.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ReadPublicOverAnEncryptSlotSucceedsWithTheDecryptedOutPublicMatchingThePlainForm()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalWithEccBackendAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary)
            .Register(TpmCcConstants.TPM_CC_ReadPublic, TpmResponseCodec.ReadPublic);

        using CreatePrimaryInput createInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            device, createInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"TPM2_CreatePrimary() must succeed: '{createResult.ResponseCode}'.");
        using CreatePrimaryResponse primary = createResult.Value;

        TpmResult<ReadPublicResponse> plainResult = await TpmCommandExecutor.ExecuteAsync<ReadPublicResponse>(
            device, ReadPublicInput.ForHandle(primary.ObjectHandle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(plainResult.IsSuccess, $"The plain TPM2_ReadPublic() form must succeed: '{plainResult.ResponseCode}'.");
        using ReadPublicResponse plainResponse = plainResult.Value;
        byte[] plainOutPublicOctets = plainResponse.PublicArea.GetRawBytes().ToArray();

        (uint encryptHandle, TpmSession encryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        try
        {
            using(encryptSession)
            {
                encryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                TpmResult<ReadPublicResponse> sessionResult = await TpmCommandExecutor.ExecuteAsync<ReadPublicResponse>(
                    device, ReadPublicInput.ForHandle(primary.ObjectHandle), [encryptSession], [primary.Name.AsReadOnlyMemory()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(sessionResult.IsSuccess, $"TPM2_ReadPublic() over an encrypt-only companion, with the key's own Name folded into cpHash, must succeed: '{sessionResult.ResponseCode}'.");
                using ReadPublicResponse sessionResponse = sessionResult.Value;
                Assert.AreSequenceEqual(plainResponse.Name.Span.ToArray(), sessionResponse.Name.Span.ToArray(), "The Name must equal the plain form's.");
                Assert.AreSequenceEqual(plainOutPublicOctets, sessionResponse.PublicArea.GetRawBytes().ToArray(), "The decrypted outPublic must equal the plain form's own octets exactly.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, encryptHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_ReadPublic()</c> over an audit companion at session index 0 — unassociated with <c>objectHandle</c>
    /// (Auth Index None, Table 24) — alongside an encrypt companion at index 1 succeeds through the production
    /// <see cref="TpmCommandExecutor"/>: session 0 authorizes nothing, so the encrypt slot's own <c>nonceTPM</c>
    /// must NOT fold into session 0's command HMAC (TPM 2.0 Library Part 1, clause 16.6.5;
    /// <see cref="ITpmCommandInput.IsFirstHandleAuthorized"/>) — a companion pair the executor's own fold
    /// desynchronized before that declaration existed. The decrypted <c>outPublic</c> still equals the plain
    /// form's own octets.
    /// </summary>
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.4, Table 24; Part 1, clauses 15.7, 16.6.5 and 18.1</see>.
    [TestMethod]
    public async Task ReadPublicOverAnAuditAndEncryptCompanionPairSucceedsThroughTheExecutor()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalWithEccBackendAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary)
            .Register(TpmCcConstants.TPM_CC_ReadPublic, TpmResponseCodec.ReadPublic);

        using CreatePrimaryInput createInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            device, createInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"TPM2_CreatePrimary() must succeed: '{createResult.ResponseCode}'.");
        using CreatePrimaryResponse primary = createResult.Value;

        TpmResult<ReadPublicResponse> plainResult = await TpmCommandExecutor.ExecuteAsync<ReadPublicResponse>(
            device, ReadPublicInput.ForHandle(primary.ObjectHandle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(plainResult.IsSuccess, $"The plain TPM2_ReadPublic() form must succeed: '{plainResult.ResponseCode}'.");
        using ReadPublicResponse plainResponse = plainResult.Value;
        byte[] plainOutPublicOctets = plainResponse.PublicArea.GetRawBytes().ToArray();

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        (uint encryptHandle, TpmSession encryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        try
        {
            using(auditSession)
            using(encryptSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                encryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                TpmResult<ReadPublicResponse> sessionResult = await TpmCommandExecutor.ExecuteAsync<ReadPublicResponse>(
                    device, ReadPublicInput.ForHandle(primary.ObjectHandle), [auditSession, encryptSession], [primary.Name.AsReadOnlyMemory()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(sessionResult.IsSuccess, $"TPM2_ReadPublic() over an audit companion at index 0 and an encrypt companion at index 1 must succeed: '{sessionResult.ResponseCode}'.");
                using ReadPublicResponse sessionResponse = sessionResult.Value;
                Assert.AreSequenceEqual(
                    plainOutPublicOctets, sessionResponse.PublicArea.GetRawBytes().ToArray(),
                    "The decrypted outPublic must equal the plain form's own octets exactly, proving session 0's command HMAC was computed without folding the encrypt companion's nonceTPM into it.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, encryptHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_NV_ReadPublic()</c> over an audit-only companion, a defined Index's own Name folded into cpHash
    /// BEFORE the authorization area is judged (TPM 2.0 Library Part 3, clause 5.4 precedes clause 5.5),
    /// succeeds with the same Name the plain form answers.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.6, Table 251; Part 1, clause 15.7</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadPublicOverAnAuditSlotSucceedsWithTheIndexNameFoldedIntoCpHash()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace)
            .Register(TpmCcConstants.TPM_CC_NV_ReadPublic, TpmResponseCodec.NvReadPublic);

        const uint NvIndex = 0x0100_00A5;
        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);
        using Tpm2bAuth indexAuth = Tpm2bAuth.Create([0x01, 0x02], pool);
        using var publicInfo = new TpmsNvPublic(NvIndex, TpmAlgIdConstants.TPM_ALG_SHA256, TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE, Tpm2bDigest.Empty, dataSize: 16);
        using var defineInput = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, indexAuth, publicInfo);
        TpmResult<NvDefineSpaceResponse> defineResult = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            device, defineInput, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"TPM2_NV_DefineSpace() must succeed: '{defineResult.ResponseCode}'.");

        TpmResult<NvReadPublicResponse> plainResult = await TpmCommandExecutor.ExecuteAsync<NvReadPublicResponse>(
            device, new NvReadPublicInput(NvIndex), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(plainResult.IsSuccess, $"The plain TPM2_NV_ReadPublic() form must succeed: '{plainResult.ResponseCode}'.");
        using NvReadPublicResponse plainResponse = plainResult.Value;
        byte[] indexName = plainResponse.NvName.Span.ToArray();

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(auditSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                TpmResult<NvReadPublicResponse> sessionResult = await TpmCommandExecutor.ExecuteAsync<NvReadPublicResponse>(
                    device, new NvReadPublicInput(NvIndex), [auditSession], [indexName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(sessionResult.IsSuccess, $"TPM2_NV_ReadPublic() over an audit companion, with the Index's own Name folded into cpHash, must succeed: '{sessionResult.ResponseCode}'.");
                using NvReadPublicResponse sessionResponse = sessionResult.Value;
                Assert.AreSequenceEqual(indexName, sessionResponse.NvName.Span.ToArray(), "The Name must equal the plain form's.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_ReadPublic()</c> over an audit-claiming companion, addressed at an unloaded transient-range
    /// handle, answers <c>TPM_RC_REFERENCE_H0</c> — ahead of any session judgment, since clause 5.4 (handle
    /// validation) precedes clause 5.5 (session validation) — framed <c>TPM_ST_NO_SESSIONS</c> in exactly 10
    /// octets (clause 5.9); the session's nonceTPM is left untouched, so a genuine follow-up command over it
    /// still verifies.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.4, step 2.1; clause 5.9</see>.
    /// </summary>
    [TestMethod]
    public async Task ReadPublicOverAnAuditSlotWithAnUnknownHandleAnswersReferenceH0AndLeavesTheSessionUsable()
    {
        const uint UnknownTransientHandle = 0x8000_1234;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        (uint sessionHandle, TpmSession session) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                //The Name term is irrelevant to this path — the handle resolves to nothing before any session is
                //judged — so an empty value keeps the block structurally well-formed regardless of what the
                //(never-verified) command HMAC actually covers.
                byte[] authArea = await BuildSessionAuthAreaOverHandleAsync(session, TpmCcConstants.TPM_CC_ReadPublic, ReadOnlyMemory<byte>.Empty, [], pool).ConfigureAwait(false);

                (TpmRcConstants code, byte[] response) = await SubmitOverHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_ReadPublic, UnknownTransientHandle, authArea, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_REFERENCE_H0, code, "An unloaded transient-range handle answers TPM_RC_REFERENCE_H0 ahead of any session judgment.");
                Assert.AreEqual((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, ReadResponseTag(response), "A failed command frames TPM_ST_NO_SESSIONS regardless of the request's own tag.");
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
    /// An audited <c>TPM2_Shutdown(TPM_SU_STATE)</c> succeeds and frames normally, since the command body itself
    /// never touches session state: the audit digest is readable afterward through
    /// <c>TPM2_GetSessionAuditDigest()</c>. At the next <c>TPM2_Startup()</c>, every loaded session — including
    /// the one that just audited the Shutdown call itself — is unconditionally discarded (Part 4
    /// <c>SessionStartup</c>'s unconditional sweep, distinct from a <c>TPM2_ContextSave()</c>d session, which
    /// alone survives), so the same handle now answers session-encoded <c>TPM_RC_REFERENCE_S0</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 9.4, Table 6</see>.
    /// </summary>
    [TestMethod]
    public async Task ShutdownStateOverAnAuditSlotSucceedsAndTheSessionIsGoneAfterStartup()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_GetSessionAuditDigest, TpmResponseCodec.GetSessionAuditDigest);

        byte[] shutdownParameters = SerializeParameters(new ShutdownInput(TpmSuConstants.TPM_SU_STATE), pool);

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

        byte[] authArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_Shutdown, shutdownParameters, pool, TestContext.CancellationToken).ConfigureAwait(false);

        (TpmRcConstants code, byte[] response) = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleForAuditAsync(
            simulator, pool, TpmCcConstants.TPM_CC_Shutdown, authArea, shutdownParameters, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "TPM2_Shutdown(STATE) over an audit-only companion must succeed (Table 6's tag rule).");
        Assert.AreEqual((ushort)TpmStConstants.TPM_ST_SESSIONS, ReadResponseTag(response), "A successful over-session response is TPM_ST_SESSIONS-tagged.");

        byte[] responseParameters = TpmInHouseSimulatorZeroHandleSessionTests.ReadResponseParameters(response, outHandleCount: 0);
        byte[] cpHash = await TpmInHouseSimulatorZeroHandleSessionTests.ComputeZeroHandleCpHashAsync(TpmCcConstants.TPM_CC_Shutdown, shutdownParameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] rpHash = await TpmInHouseSimulatorZeroHandleSessionTests.ComputeRpHashAsync(TpmCcConstants.TPM_CC_Shutdown, responseParameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] expectedDigest = await TpmInHouseSimulatorZeroHandleSessionTests.ExtendAuditDigestAsync(priorDigest: null, cpHash, rpHash, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using(GetSessionAuditDigestInput auditDigestInput = GetSessionAuditDigestInput.ForNullSigner(TpmiShHmac.FromValue(auditHandle), ReadOnlySpan<byte>.Empty, pool))
        using(TpmPasswordSession endorsementForDigest = TpmPasswordSession.CreateEmpty(pool))
        using(TpmPasswordSession nullSignerSlot = TpmPasswordSession.CreateEmpty(pool))
        {
            TpmResult<GetSessionAuditDigestResponse> digestResult = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                device, auditDigestInput, [endorsementForDigest, nullSignerSlot], handleNames: null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            using GetSessionAuditDigestResponse? auditDigestResponse = digestResult.IsSuccess ? digestResult.Value : null;

            Assert.IsTrue(digestResult.IsSuccess, $"TPM2_GetSessionAuditDigest() must still succeed after an audited Shutdown(STATE), since the TPM stays operational until the next _TPM_Init: '{digestResult.ResponseCode}'.");
            Assert.IsTrue(
                expectedDigest.AsSpan().SequenceEqual(auditDigestResponse!.SessionAudit.SessionDigest.AsReadOnlySpan()),
                "The audit session's digest must equal H(0…0 ‖ cpHash ‖ rpHash) chained from this exchange's own wire octets, proving Shutdown itself never touches session state.");
        }

        //TPM2_Startup() is admitted only after a platform _TPM_Init indication (TPM 2.0 Library Part 1, clause
        //9.2.2); the orderly Shutdown(STATE) above changed no lifecycle phase of its own, so the power-cycle
        //signal is sent explicitly here before the Startup(STATE) that resumes from it.
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS,
            await SubmitStartupStateAsync(simulator, pool).ConfigureAwait(false),
            "TPM2_Startup(STATE) must succeed after an orderly TPM2_Shutdown(STATE) and a _TPM_Init indication.");

        byte[] followUpParameters = SerializeParameters(new ReadClockInput(), pool);
        byte[] followUpAuthArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_ReadClock, followUpParameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
        TpmRcConstants followUpCode = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
            simulator, pool, TpmCcConstants.TPM_CC_ReadClock, followUpAuthArea, followUpParameters, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_REFERENCE_S0, followUpCode,
            "Every loaded session is unconditionally discarded at the next TPM2_Startup() (Part 4 SessionStartup's unconditional sweep), so the same handle now answers TPM_RC_REFERENCE_S0 + N (Part 2, clause 6.6.2) — N is 0 for the first (and only) slot here, so the warning's own base value stands unwrapped.");

        auditSession.Dispose();
    }

    /// <summary>
    /// <c>TPM2_GetTestResult()</c> over an encrypt-only companion succeeds, its response HMAC verifying under the
    /// session's own key (the production executor answers <c>TPM_RC_AUTH_FAIL</c> rather than success on a
    /// mismatch): the framed <c>outData</c> is a zero-length <c>TPM2B_MAX_BUFFER</c>, since this simulator emits
    /// <c>outData</c> empty on every success and the ciphertext of an empty buffer is itself empty (TPM 2.0
    /// Library Part 1, clause 18.1).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 10.4, Table 12</see>.
    /// </summary>
    [TestMethod]
    public async Task GetTestResultOverAnEncryptSlotSucceedsWithAnEmptyFramedOutData()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_GetTestResult, TpmResponseCodec.GetTestResult);

        (uint encryptHandle, TpmSession encryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        try
        {
            using(encryptSession)
            {
                encryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                TpmResult<GetTestResultResponse> result = await TpmCommandExecutor.ExecuteAsync<GetTestResultResponse>(
                    device, new GetTestResultInput(), [encryptSession], handleNames: null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(result.IsSuccess, $"TPM2_GetTestResult() over an encrypt companion must succeed, its response HMAC verifying under the session's own key: '{result.ResponseCode}'.");
                using GetTestResultResponse response = result.Value;
                Assert.AreEqual(0, response.OutData.Length, "outData is framed empty on this simulator, so the ciphertext of an empty buffer is itself empty.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, encryptHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_Hash()</c> is the widest of the eight key-family commands whose Part 3 tag cell admits an audit,
    /// decrypt or encrypt companion, exercising all three companion kinds (Table 69's tag
    /// rule: "TPM_ST_SESSIONS if an audit, encrypt, or decrypt session is present"): a decrypt companion recovers
    /// <c>data</c> before hashing, an encrypt companion protects the
    /// response's <c>outHash</c>, and an audit companion chains <c>H(0…0 ‖ cpHash ‖ rpHash)</c> over the
    /// exchange's own wire octets.
    /// </summary>
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 15.4, Table 69; Part 1, clauses 15.6.1, 17.1 and 18.1</see>.
    [TestMethod]
    public async Task HashOverADecryptSlotAnEncryptSlotAndAnAuditSlotEachSucceedsWithTheExpectedDigest()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_Hash, TpmResponseCodec.Hash)
            .Register(TpmCcConstants.TPM_CC_GetSessionAuditDigest, TpmResponseCodec.GetSessionAuditDigest);

        byte[] data = [0x01, 0x02, 0x03, 0x04, 0x05];
        byte[] expectedHash = SHA256.HashData(data);
        TpmiAlgHash hashAlg = TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256);

        //A decrypt companion recovers the plaintext data before hashing.
        {
            (uint decryptHandle, TpmSession decryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
            try
            {
                using(decryptSession)
                {
                    decryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                    using HashInput input = HashInput.Create(data, hashAlg, TpmiRhHierarchy.Null, pool);
                    TpmResult<HashResponse> result = await TpmCommandExecutor.ExecuteAsync<HashResponse>(
                        device, input, [decryptSession], handleNames: null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                    Assert.IsTrue(result.IsSuccess, $"TPM2_Hash() over a decrypt companion must succeed: '{result.ResponseCode}'.");
                    using HashResponse response = result.Value;
                    Assert.AreSequenceEqual(expectedHash, response.OutHash.AsReadOnlySpan().ToArray(), "The recovered plaintext data must hash to the SHA-256 of the octets the test encrypted under the decrypt session's own key.");
                }
            }
            finally
            {
                await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, decryptHandle).ConfigureAwait(false);
            }
        }

        //An encrypt companion protects outHash; the executor decrypts it under the session's own key before
        //parsing, so the typed response already carries the plaintext digest.
        {
            (uint encryptHandle, TpmSession encryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
            try
            {
                using(encryptSession)
                {
                    encryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                    using HashInput input = HashInput.Create(data, hashAlg, TpmiRhHierarchy.Null, pool);
                    TpmResult<HashResponse> result = await TpmCommandExecutor.ExecuteAsync<HashResponse>(
                        device, input, [encryptSession], handleNames: null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                    Assert.IsTrue(result.IsSuccess, $"TPM2_Hash() over an encrypt companion must succeed, its response HMAC verifying under the session's own key: '{result.ResponseCode}'.");
                    using HashResponse response = result.Value;
                    Assert.AreSequenceEqual(expectedHash, response.OutHash.AsReadOnlySpan().ToArray(), "The decrypted outHash must equal SHA-256 of the plaintext data.");
                }
            }
            finally
            {
                await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, encryptHandle).ConfigureAwait(false);
            }
        }

        //An audit companion chains H(0…0 ‖ cpHash ‖ rpHash) over the plaintext parameter octets it saw (no
        //decrypt claim here, so cpHash's parameter term is the data as sent).
        {
            byte[] parameters;
            using(HashInput auditedInput = HashInput.Create(data, hashAlg, TpmiRhHierarchy.Null, pool))
            {
                parameters = SerializeParameters(auditedInput, pool);
            }

            (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
            try
            {
                using(auditSession)
                {
                    auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                    byte[] authArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_Hash, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);

                    (TpmRcConstants code, byte[] response) = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleForAuditAsync(
                        simulator, pool, TpmCcConstants.TPM_CC_Hash, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

                    Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "TPM2_Hash() over an audit-only companion must succeed (Table 69's tag rule).");
                    Assert.AreEqual((ushort)TpmStConstants.TPM_ST_SESSIONS, ReadResponseTag(response), "A successful over-session response is TPM_ST_SESSIONS-tagged.");

                    byte[] responseParameters = TpmInHouseSimulatorZeroHandleSessionTests.ReadResponseParameters(response, outHandleCount: 0);
                    byte[] cpHash = await TpmInHouseSimulatorZeroHandleSessionTests.ComputeZeroHandleCpHashAsync(TpmCcConstants.TPM_CC_Hash, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                    byte[] rpHash = await TpmInHouseSimulatorZeroHandleSessionTests.ComputeRpHashAsync(TpmCcConstants.TPM_CC_Hash, responseParameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
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
    }

    /// <summary>
    /// <c>TPM2_HashSequenceStart()</c> over an audit-only companion succeeds with a <c>TPM_ST_SESSIONS</c>-tagged
    /// response whose parameter area is empty and whose response handle area carries the new sequence handle
    /// alone (Table 86: no response parameters at all); <c>TPM2_SequenceUpdate()</c> and
    /// <c>TPM2_SequenceComplete()</c> over that handle, authorized by the sequence's own password, both succeed
    /// afterward.
    /// </summary>
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 17.4, Table 85 and Table 86</see>.
    [TestMethod]
    public async Task HashSequenceStartOverAnAuditSlotSucceedsWithTheHandleAheadOfAnEmptyParameterAreaThenTheSequenceCompletes()
    {
        const string SequenceAuthPassword = "hash-sequence-audit-auth";

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_SequenceUpdate, TpmResponseCodec.SequenceUpdate)
            .Register(TpmCcConstants.TPM_CC_SequenceComplete, TpmResponseCodec.SequenceComplete);

        byte[] parameters;
        using(HashSequenceStartInput startInput = HashSequenceStartInput.CreateFromPassword(SequenceAuthPassword, TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256), pool))
        {
            parameters = SerializeParameters(startInput, pool);
        }

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(auditSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                byte[] authArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_HashSequenceStart, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);

                (TpmRcConstants code, byte[] response) = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleForAuditAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_HashSequenceStart, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "TPM2_HashSequenceStart() over an audit-only companion must succeed (Table 85's tag rule).");
                Assert.AreEqual((ushort)TpmStConstants.TPM_ST_SESSIONS, ReadResponseTag(response), "A successful over-session response is TPM_ST_SESSIONS-tagged.");

                var reader = new TpmReader(response);
                _ = TpmHeader.Parse(ref reader);
                uint sequenceHandleValue = reader.ReadUInt32();
                uint parameterSize = reader.ReadUInt32();
                Assert.AreEqual(0u, parameterSize, "TPM2_HashSequenceStart()'s response over sessions carries the new handle alone; the parameter area is empty (Table 86).");

                var sequenceHandle = TpmiDhObject.FromValue(sequenceHandleValue);

                using SequenceUpdateInput updateInput = SequenceUpdateInput.Create(sequenceHandle, [0xAA, 0xBB], pool);
                using TpmPasswordSession sequencePasswordForUpdate = TpmPasswordSession.Create(SequenceAuthPassword, pool);
                TpmResult<SequenceUpdateResponse> updateResult = await TpmCommandExecutor.ExecuteAsync<SequenceUpdateResponse>(
                    device, updateInput, [sequencePasswordForUpdate], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(updateResult.IsSuccess, $"TPM2_SequenceUpdate() over the sequence the over-session TPM2_HashSequenceStart() opened must succeed: '{updateResult.ResponseCode}'.");

                using SequenceCompleteInput completeInput = SequenceCompleteInput.Create(sequenceHandle, [0xCC], TpmiRhHierarchy.Null, pool);
                using TpmPasswordSession sequencePasswordForComplete = TpmPasswordSession.Create(SequenceAuthPassword, pool);
                TpmResult<SequenceCompleteResponse> completeResult = await TpmCommandExecutor.ExecuteAsync<SequenceCompleteResponse>(
                    device, completeInput, [sequencePasswordForComplete], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(completeResult.IsSuccess, $"TPM2_SequenceComplete() must succeed: '{completeResult.ResponseCode}'.");
                completeResult.Value.Dispose();
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_SignSequenceStart()</c> over a decrypt-only companion, its <c>auth</c> recovered before the
    /// sequence opens, succeeds; a follow-up <c>TPM2_SignSequenceComplete()</c> authorized by that SAME plaintext
    /// password succeeds too, proving the decrypted octets — not the ciphertext that rode the wire — were
    /// installed as the sequence's authValue.
    /// </summary>
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 17.5, Table 87 and Table 88</see>.
    [TestMethod]
    public async Task SignSequenceStartOverADecryptSlotSucceedsAndTheDecryptedAuthCompletesTheSequence()
    {
        const string SequenceAuthPassword = "sign-sequence-decrypt-auth";

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalWithEccBackendAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary)
            .Register(TpmCcConstants.TPM_CC_SignSequenceStart, TpmResponseCodec.SignSequenceStart)
            .Register(TpmCcConstants.TPM_CC_SignSequenceComplete, TpmResponseCodec.SignSequenceComplete);

        using CreatePrimaryInput createInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            device, createInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"TPM2_CreatePrimary() must succeed: '{createResult.ResponseCode}'.");
        using CreatePrimaryResponse primary = createResult.Value;

        (uint decryptHandle, TpmSession decryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        try
        {
            using(decryptSession)
            {
                decryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                using SignSequenceStartInput startInput = SignSequenceStartInput.CreateFromPassword(primary.ObjectHandle, SequenceAuthPassword, pool);
                TpmResult<SignSequenceStartResponse> startResult = await TpmCommandExecutor.ExecuteAsync<SignSequenceStartResponse>(
                    device, startInput, [decryptSession], handleNames: [primary.Name.AsReadOnlyMemory()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(startResult.IsSuccess, $"TPM2_SignSequenceStart() over a decrypt companion must succeed: '{startResult.ResponseCode}'.");
                SignSequenceStartResponse started = startResult.Value;

                using SignSequenceCompleteInput completeInput = SignSequenceCompleteInput.Create(started.SequenceHandle, primary.ObjectHandle, [0x01, 0x02, 0x03], pool);
                using TpmPasswordSession sequencePassword = TpmPasswordSession.Create(SequenceAuthPassword, pool);
                using TpmPasswordSession keyPassword = TpmPasswordSession.CreateEmpty(pool);
                TpmResult<SignSequenceCompleteResponse> completeResult = await TpmCommandExecutor.ExecuteAsync<SignSequenceCompleteResponse>(
                    device, completeInput, [sequencePassword, keyPassword], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(
                    completeResult.IsSuccess,
                    $"TPM2_SignSequenceComplete() over the sequence's own plaintext password must succeed, proving the decrypted auth (not the ciphertext) was installed as authValue: '{completeResult.ResponseCode}'.");
                completeResult.Value.Dispose();
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, decryptHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, primary.ObjectHandle.Value).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_VerifySignature()</c> over a decrypt-only companion, its <c>digest</c> recovered before
    /// verification, succeeds with a genuine validation ticket over the plaintext digest a real ECDSA signature
    /// verifies against.
    /// </summary>
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 20.2, Table 116</see>.
    [TestMethod]
    public async Task VerifySignatureOverADecryptSlotSucceedsWithThePlaintextDigestVerified()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalWithEccBackendAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary)
            .Register(TpmCcConstants.TPM_CC_Sign, TpmResponseCodec.Sign)
            .Register(TpmCcConstants.TPM_CC_VerifySignature, TpmResponseCodec.VerifySignature);

        using CreatePrimaryInput createInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            device, createInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"TPM2_CreatePrimary() must succeed: '{createResult.ResponseCode}'.");
        using CreatePrimaryResponse primary = createResult.Value;

        byte[] digest = SHA256.HashData([0x01, 0x02, 0x03]);
        using TpmPasswordSession signKeyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignInput signInput = SignInput.ForEcdsa(primary.ObjectHandle, digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            device, signInput, [signKeyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signResult.IsSuccess, $"TPM2_Sign() must succeed: '{signResult.ResponseCode}'.");
        using SignResponse signature = signResult.Value;
        byte[] signatureOctets = [.. signature.Signature.SignatureR!.AsReadOnlySpan(), .. signature.Signature.SignatureS!.AsReadOnlySpan()];

        (uint decryptHandle, TpmSession decryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        try
        {
            using(decryptSession)
            {
                decryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                using VerifySignatureInput verifyInput = VerifySignatureInput.ForEcdsa(primary.ObjectHandle, digest, signatureOctets, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
                TpmResult<VerifySignatureResponse> verifyResult = await TpmCommandExecutor.ExecuteAsync<VerifySignatureResponse>(
                    device, verifyInput, [decryptSession], handleNames: [primary.Name.AsReadOnlyMemory()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(verifyResult.IsSuccess, $"TPM2_VerifySignature() over a decrypt companion, with the plaintext digest recovered, must succeed: '{verifyResult.ResponseCode}'.");
                using VerifySignatureResponse validated = verifyResult.Value;
                Assert.AreEqual(TpmiRhHierarchy.Owner, validated.Validation.Hierarchy, "The validation ticket names the signing key's hierarchy, proving the recovered plaintext digest — not the ciphertext — verified.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, decryptHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, primary.ObjectHandle.Value).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_VerifyDigestSignature()</c> over a decrypt-only companion: <c>context</c> — always the Empty
    /// Buffer, TPM 2.0 Library Table 220's <c>empty[0]</c> arm — is the encrypted first command parameter, so
    /// encrypting it changes nothing observable, while <c>digest</c> stays in the clear (it is NOT the first
    /// parameter); the command still succeeds with a genuine validation ticket.
    /// </summary>
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 20.4, Table 120</see>.
    [TestMethod]
    public async Task VerifyDigestSignatureOverADecryptSlotSucceedsWithTheEncryptedEmptyContextAndThePlaintextDigest()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalWithEccBackendAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary)
            .Register(TpmCcConstants.TPM_CC_Sign, TpmResponseCodec.Sign)
            .Register(TpmCcConstants.TPM_CC_VerifyDigestSignature, TpmResponseCodec.VerifyDigestSignature);

        using CreatePrimaryInput createInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            device, createInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"TPM2_CreatePrimary() must succeed: '{createResult.ResponseCode}'.");
        using CreatePrimaryResponse primary = createResult.Value;

        byte[] digest = SHA256.HashData([0x04, 0x05, 0x06]);
        using TpmPasswordSession signKeyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignInput signInput = SignInput.ForEcdsa(primary.ObjectHandle, digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            device, signInput, [signKeyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signResult.IsSuccess, $"TPM2_Sign() must succeed: '{signResult.ResponseCode}'.");
        using SignResponse signature = signResult.Value;
        byte[] signatureOctets = [.. signature.Signature.SignatureR!.AsReadOnlySpan(), .. signature.Signature.SignatureS!.AsReadOnlySpan()];

        (uint decryptHandle, TpmSession decryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        try
        {
            using(decryptSession)
            {
                decryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                using VerifyDigestSignatureInput verifyInput = VerifyDigestSignatureInput.ForEcdsa(primary.ObjectHandle, digest, signatureOctets, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
                TpmResult<VerifyDigestSignatureResponse> verifyResult = await TpmCommandExecutor.ExecuteAsync<VerifyDigestSignatureResponse>(
                    device, verifyInput, [decryptSession], handleNames: [primary.Name.AsReadOnlyMemory()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(verifyResult.IsSuccess, $"TPM2_VerifyDigestSignature() over a decrypt companion, with the empty context encrypted and the digest read in the clear, must succeed: '{verifyResult.ResponseCode}'.");
                using VerifyDigestSignatureResponse validated = verifyResult.Value;
                Assert.AreEqual(TpmiRhHierarchy.Owner, validated.Validation.Hierarchy, "The validation ticket names the signing key's hierarchy.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, decryptHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, primary.ObjectHandle.Value).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_Encapsulate()</c> over an encrypt-only companion succeeds; the decrypted <c>sharedSecret</c>
    /// equals what <c>TPM2_Decapsulate()</c> of the returned ciphertext yields on the SAME key — the plain
    /// path's own oracle, proving the decryption recovered the genuine DHKEM output rather than garbage that
    /// merely parsed.
    /// </summary>
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.10, Table 60 and Table 61</see>.
    [TestMethod]
    public async Task EncapsulateOverAnEncryptSlotSucceedsWithTheDecryptedSharedSecretMatchingDecapsulate()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalWithEccBackendAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary)
            .Register(TpmCcConstants.TPM_CC_Encapsulate, TpmResponseCodec.Encapsulate)
            .Register(TpmCcConstants.TPM_CC_Decapsulate, TpmResponseCodec.Decapsulate);

        using CreatePrimaryInput createInput = CreatePrimaryInput.ForEccKemKey(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmAlgIdConstants.TPM_ALG_SHA256, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            device, createInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"CreatePrimary (ECC KEM key) must succeed: '{createResult.ResponseCode}'.");
        using CreatePrimaryResponse primary = createResult.Value;

        (uint encryptHandle, TpmSession encryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        byte[] decryptedSharedSecret;
        byte[] ciphertextBytes;
        try
        {
            using(encryptSession)
            {
                encryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                EncapsulateInput encapsulateInput = EncapsulateInput.ForHandle(primary.ObjectHandle);
                TpmResult<EncapsulateResponse> encapsulateResult = await TpmCommandExecutor.ExecuteAsync<EncapsulateResponse>(
                    device, encapsulateInput, [encryptSession], handleNames: [primary.Name.AsReadOnlyMemory()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(encapsulateResult.IsSuccess, $"TPM2_Encapsulate() over an encrypt companion must succeed: '{encapsulateResult.ResponseCode}'.");
                using EncapsulateResponse encapsulated = encapsulateResult.Value;
                decryptedSharedSecret = encapsulated.SharedSecret.AsReadOnlySpan().ToArray();
                ciphertextBytes = encapsulated.Ciphertext.Ciphertext.ToArray();
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, encryptHandle).ConfigureAwait(false);
        }

        using DecapsulateInput decapsulateInput = DecapsulateInput.Create(primary.ObjectHandle, ciphertextBytes, pool);
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<DecapsulateResponse> decapsulateResult = await TpmCommandExecutor.ExecuteAsync<DecapsulateResponse>(
            device, decapsulateInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(decapsulateResult.IsSuccess, $"TPM2_Decapsulate() must succeed: '{decapsulateResult.ResponseCode}'.");
        using DecapsulateResponse decapsulated = decapsulateResult.Value;

        Assert.AreSequenceEqual(
            decapsulated.SharedSecret.AsReadOnlySpan().ToArray(), decryptedSharedSecret,
            "The encrypt companion's decrypted sharedSecret must equal what TPM2_Decapsulate() of the returned ciphertext yields on the same key.");

        await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, primary.ObjectHandle.Value).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>TPM2_Encapsulate()</c> over an audit companion at session index 0 — unassociated with <c>keyHandle</c>
    /// (Auth Index None, Table 60) — alongside an encrypt companion at index 1 succeeds through the production
    /// <see cref="TpmCommandExecutor"/>: session 0 authorizes nothing, so the encrypt slot's own <c>nonceTPM</c>
    /// must NOT fold into session 0's command HMAC (TPM 2.0 Library Part 1, clause 16.6.5;
    /// <see cref="ITpmCommandInput.IsFirstHandleAuthorized"/>). The decrypted <c>sharedSecret</c> still equals
    /// what <c>TPM2_Decapsulate()</c> of the returned ciphertext yields on the same key.
    /// </summary>
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.10, Table 60 and Table 61; Part 1, clause 16.6.5</see>.
    [TestMethod]
    public async Task EncapsulateOverAnAuditAndEncryptCompanionPairSucceedsWithTheDecryptedSharedSecretMatchingDecapsulate()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalWithEccBackendAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary)
            .Register(TpmCcConstants.TPM_CC_Encapsulate, TpmResponseCodec.Encapsulate)
            .Register(TpmCcConstants.TPM_CC_Decapsulate, TpmResponseCodec.Decapsulate);

        using CreatePrimaryInput createInput = CreatePrimaryInput.ForEccKemKey(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmAlgIdConstants.TPM_ALG_SHA256, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            device, createInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"CreatePrimary (ECC KEM key) must succeed: '{createResult.ResponseCode}'.");
        using CreatePrimaryResponse primary = createResult.Value;

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        (uint encryptHandle, TpmSession encryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        byte[] decryptedSharedSecretWithAudit;
        byte[] ciphertextBytesWithAudit;
        try
        {
            using(auditSession)
            using(encryptSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                encryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                EncapsulateInput encapsulateInput = EncapsulateInput.ForHandle(primary.ObjectHandle);
                TpmResult<EncapsulateResponse> encapsulateResult = await TpmCommandExecutor.ExecuteAsync<EncapsulateResponse>(
                    device, encapsulateInput, [auditSession, encryptSession], handleNames: [primary.Name.AsReadOnlyMemory()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(encapsulateResult.IsSuccess, $"TPM2_Encapsulate() over an audit companion at index 0 and an encrypt companion at index 1 must succeed: '{encapsulateResult.ResponseCode}'.");
                using EncapsulateResponse encapsulated = encapsulateResult.Value;
                decryptedSharedSecretWithAudit = encapsulated.SharedSecret.AsReadOnlySpan().ToArray();
                ciphertextBytesWithAudit = encapsulated.Ciphertext.Ciphertext.ToArray();
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, encryptHandle).ConfigureAwait(false);
        }

        using DecapsulateInput decapsulateInput = DecapsulateInput.Create(primary.ObjectHandle, ciphertextBytesWithAudit, pool);
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<DecapsulateResponse> decapsulateResult = await TpmCommandExecutor.ExecuteAsync<DecapsulateResponse>(
            device, decapsulateInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(decapsulateResult.IsSuccess, $"TPM2_Decapsulate() must succeed: '{decapsulateResult.ResponseCode}'.");
        using DecapsulateResponse decapsulated = decapsulateResult.Value;

        Assert.AreSequenceEqual(
            decapsulated.SharedSecret.AsReadOnlySpan().ToArray(), decryptedSharedSecretWithAudit,
            "The encrypt companion's decrypted sharedSecret must equal what TPM2_Decapsulate() of the returned ciphertext yields on the same key, proving session 0's command HMAC was computed without folding the encrypt companion's nonceTPM into it.");

        await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, primary.ObjectHandle.Value).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>TPM2_MakeCredential()</c> over an encrypt-only companion succeeds; the decrypted <c>credentialBlob</c>
    /// activates through <c>TPM2_ActivateCredential()</c> and recovers the SAME secret the test wrapped, proving
    /// the decryption recovered the genuine wrap rather than garbage that merely parsed.
    /// </summary>
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.6, Table 28</see>.
    [TestMethod]
    public async Task MakeCredentialOverAnEncryptSlotSucceedsAndTheDecryptedCredentialBlobActivates()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalWithEccBackendAsync(pool).ConfigureAwait(false);
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

        byte[] credentialSecret = [0x10, 0x20, 0x30, 0x40];

        (uint encryptHandle, TpmSession encryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        byte[] credentialBlob;
        byte[] secret;
        try
        {
            using(encryptSession)
            {
                encryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                using MakeCredentialInput makeInput = MakeCredentialInput.Create(ek.ObjectHandle, credentialSecret, ak.Name.Span.ToArray(), pool);
                TpmResult<MakeCredentialResponse> makeResult = await TpmCommandExecutor.ExecuteAsync<MakeCredentialResponse>(
                    device, makeInput, [encryptSession], handleNames: [ek.Name.AsReadOnlyMemory()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(makeResult.IsSuccess, $"TPM2_MakeCredential() over an encrypt companion must succeed: '{makeResult.ResponseCode}'.");
                using MakeCredentialResponse made = makeResult.Value;
                credentialBlob = made.CredentialBlob.Span.ToArray();
                secret = made.Secret.Span.ToArray();
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, encryptHandle).ConfigureAwait(false);
        }

        using ActivateCredentialInput activateInput = ActivateCredentialInput.Create(ak.ObjectHandle, ek.ObjectHandle, credentialBlob, secret, pool);
        using TpmPasswordSession activateAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<ActivateCredentialResponse> activateResult = await TpmCommandExecutor.ExecuteAsync<ActivateCredentialResponse>(
            device, activateInput, [activateAuth, keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(activateResult.IsSuccess, $"TPM2_ActivateCredential() must succeed, proving the decrypted credentialBlob equals the plain form's own wrap: '{activateResult.ResponseCode}'.");
        using ActivateCredentialResponse activated = activateResult.Value;
        Assert.AreSequenceEqual(credentialSecret, activated.CertInfo.AsReadOnlySpan().ToArray(), "The recovered credential must equal the secret TPM2_MakeCredential() wrapped over the encrypt companion.");

        await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, ak.ObjectHandle.Value).ConfigureAwait(false);
        await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, ek.ObjectHandle.Value).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>TPM2_MakeCredential()</c> over an audit companion at session index 0 — unassociated with <c>handle</c>
    /// (Auth Index None, Table 28) — alongside an encrypt companion at index 1 succeeds through the production
    /// <see cref="TpmCommandExecutor"/>: session 0 authorizes nothing, so the encrypt slot's own <c>nonceTPM</c>
    /// must NOT fold into session 0's command HMAC (TPM 2.0 Library Part 1, clause 16.6.5;
    /// <see cref="ITpmCommandInput.IsFirstHandleAuthorized"/>). The decrypted <c>credentialBlob</c> still
    /// activates through <c>TPM2_ActivateCredential()</c> and recovers the same secret the test wrapped.
    /// </summary>
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.6, Table 28; Part 1, clause 16.6.5</see>.
    [TestMethod]
    public async Task MakeCredentialOverAnAuditAndEncryptCompanionPairSucceedsAndTheDecryptedCredentialBlobActivates()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalWithEccBackendAsync(pool).ConfigureAwait(false);
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

        byte[] credentialSecret = [0x11, 0x21, 0x31, 0x41];

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        (uint encryptHandle, TpmSession encryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        byte[] credentialBlob;
        byte[] secret;
        try
        {
            using(auditSession)
            using(encryptSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                encryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                using MakeCredentialInput makeInput = MakeCredentialInput.Create(ek.ObjectHandle, credentialSecret, ak.Name.Span.ToArray(), pool);
                TpmResult<MakeCredentialResponse> makeResult = await TpmCommandExecutor.ExecuteAsync<MakeCredentialResponse>(
                    device, makeInput, [auditSession, encryptSession], handleNames: [ek.Name.AsReadOnlyMemory()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(makeResult.IsSuccess, $"TPM2_MakeCredential() over an audit companion at index 0 and an encrypt companion at index 1 must succeed: '{makeResult.ResponseCode}'.");
                using MakeCredentialResponse made = makeResult.Value;
                credentialBlob = made.CredentialBlob.Span.ToArray();
                secret = made.Secret.Span.ToArray();
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, encryptHandle).ConfigureAwait(false);
        }

        using ActivateCredentialInput activateInput = ActivateCredentialInput.Create(ak.ObjectHandle, ek.ObjectHandle, credentialBlob, secret, pool);
        using TpmPasswordSession activateAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<ActivateCredentialResponse> activateResult = await TpmCommandExecutor.ExecuteAsync<ActivateCredentialResponse>(
            device, activateInput, [activateAuth, keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(activateResult.IsSuccess, $"TPM2_ActivateCredential() must succeed, proving the decrypted credentialBlob equals the plain form's own wrap: '{activateResult.ResponseCode}'.");
        using ActivateCredentialResponse activated = activateResult.Value;
        Assert.AreSequenceEqual(
            credentialSecret, activated.CertInfo.AsReadOnlySpan().ToArray(),
            "The recovered credential must equal the secret TPM2_MakeCredential() wrapped over the encrypt companion, proving session 0's command HMAC was computed without folding the encrypt companion's nonceTPM into it.");

        await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, ak.ObjectHandle.Value).ConfigureAwait(false);
        await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, ek.ObjectHandle.Value).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>TPM2_VerifySignature()</c> over an audit-claiming companion, addressed at a genuine, resolvable key,
    /// answers the inner's own <c>TPM_RC_SIZE</c>, parameter-encoded to the same index for a digest wider than <c>TPM2B_DIGEST</c>'s own
    /// <c>MaxSize</c> — judged only AFTER the authorization area verifies (clause 5.5 precedes clause 5.8) — framed
    /// <c>TPM_ST_NO_SESSIONS</c> in exactly 10 octets (clause 5.9); the session's nonceTPM is left untouched, so
    /// a genuine follow-up command over it still verifies.
    /// </summary>
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 5.5, 5.9 and 20.2; Part 2, clause 10.3.2, Table 90</see>.
    [TestMethod]
    public async Task VerifySignatureOverAnAuditSlotWithAWrongWidthDigestAnswersTheInnersParameterEncodedSizeAndLeavesTheSessionUsable()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalWithEccBackendAsync(pool).ConfigureAwait(false);
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
        byte[] keyName = primary.Name.Span.ToArray();

        //A TPM2B_DIGEST whose declared size (65) exceeds Tpm2bDigest.MaxSize (64, sizeof(TPMU_HA)) — the parse's
        //own bound check answers TPM_RC_SIZE before reading sigAlg, so the content octets are never examined.
        byte[] oversizedDigestParams = new byte[sizeof(ushort) + 65];
        BinaryPrimitives.WriteUInt16BigEndian(oversizedDigestParams, 65);

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(auditSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                byte[] authArea = await BuildSessionAuthAreaOverHandleAsync(auditSession, TpmCcConstants.TPM_CC_VerifySignature, keyName, oversizedDigestParams, pool).ConfigureAwait(false);

                (TpmRcConstants code, byte[] response) = await SubmitOverHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_VerifySignature, primary.ObjectHandle.Value, authArea, oversizedDigestParams).ConfigureAwait(false);

                Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), code, "digest is TPM2_VerifySignature()'s first parameter (Table 116, index 0); one wider than TPM2B_DIGEST's own MaxSize is the inner's own parameter-encoded TPM_RC_SIZE, judged only after the sessions verify.");
                Assert.AreEqual((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, ReadResponseTag(response), "A failed command frames TPM_ST_NO_SESSIONS regardless of the request's own tag.");
                Assert.HasCount(10, response, "A failed command's response is exactly the 10-octet header (Part 3, clause 5.9).");

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
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, primary.ObjectHandle.Value).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// An encrypt claim against <c>TPM2_VerifySignature()</c> — whose response is a <c>TPMT_TK_VERIFIED</c>, not
    /// a TPM2B (clause 5.5, step 4.4.2's "the parameter has an explicit size field" test) — and a decrypt claim
    /// against <c>TPM2_Encapsulate()</c> — which carries no command parameter at all (Table 60) — are each
    /// refused session-encoded <c>TPM_RC_ATTRIBUTES</c> at the claiming slot.
    /// </summary>
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 5.5, 14.10 and 20.2; Part 1, clause 18.1</see>.
    [TestMethod]
    public async Task AnEncryptClaimOnVerifySignatureAndADecryptClaimOnEncapsulateAreBothSessionEncodedAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalWithEccBackendAsync(pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);

        //VerifySignature's response is a TPMT_TK_VERIFIED, not a TPM2B, so an encrypt claim is session-encoded ATTRIBUTES.
        {
            using CreatePrimaryInput createInput = CreatePrimaryInput.ForEccSigningKey(
                TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
            using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
            TpmResult<CreatePrimaryResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
                device, createInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(createResult.IsSuccess, $"TPM2_CreatePrimary() must succeed: '{createResult.ResponseCode}'.");
            using CreatePrimaryResponse primary = createResult.Value;
            byte[] keyName = primary.Name.Span.ToArray();

            byte[] digestParams = new byte[sizeof(ushort) + 32];
            BinaryPrimitives.WriteUInt16BigEndian(digestParams, 32);

            (uint encryptHandle, TpmSession encryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
            try
            {
                using(encryptSession)
                {
                    encryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                    byte[] authArea = await BuildSessionAuthAreaOverHandleAsync(encryptSession, TpmCcConstants.TPM_CC_VerifySignature, keyName, digestParams, pool).ConfigureAwait(false);

                    (TpmRcConstants code, _) = await SubmitOverHandleAsync(
                        simulator, pool, TpmCcConstants.TPM_CC_VerifySignature, primary.ObjectHandle.Value, authArea, digestParams).ConfigureAwait(false);

                    Assert.AreEqual(
                        TpmInHouseSimulatorZeroHandleSessionTests.SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0), code,
                        "TPM2_VerifySignature()'s response is a TPMT_TK_VERIFIED, not a TPM2B, so an encrypt claim is refused session-encoded TPM_RC_ATTRIBUTES.");
                }
            }
            finally
            {
                await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, encryptHandle).ConfigureAwait(false);
                await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, primary.ObjectHandle.Value).ConfigureAwait(false);
            }
        }

        //TPM2_Encapsulate() carries no command parameter at all (Table 60), so a decrypt claim is session-encoded ATTRIBUTES.
        {
            using CreatePrimaryInput kemInput = CreatePrimaryInput.ForEccKemKey(
                TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmAlgIdConstants.TPM_ALG_SHA256, pool, noDa: true);
            using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
            TpmResult<CreatePrimaryResponse> kemResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
                device, kemInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(kemResult.IsSuccess, $"CreatePrimary (ECC KEM key) must succeed: '{kemResult.ResponseCode}'.");
            using CreatePrimaryResponse kemPrimary = kemResult.Value;
            byte[] keyName = kemPrimary.Name.Span.ToArray();

            (uint decryptHandle, TpmSession decryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
            try
            {
                using(decryptSession)
                {
                    decryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                    byte[] authArea = await BuildSessionAuthAreaOverHandleAsync(decryptSession, TpmCcConstants.TPM_CC_Encapsulate, keyName, [], pool).ConfigureAwait(false);

                    (TpmRcConstants code, _) = await SubmitOverHandleAsync(
                        simulator, pool, TpmCcConstants.TPM_CC_Encapsulate, kemPrimary.ObjectHandle.Value, authArea, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

                    Assert.AreEqual(
                        TpmInHouseSimulatorZeroHandleSessionTests.SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0), code,
                        "TPM2_Encapsulate() carries no command parameter at all, so a decrypt claim is refused session-encoded TPM_RC_ATTRIBUTES.");
                }
            }
            finally
            {
                await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, decryptHandle).ConfigureAwait(false);
                await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, kemPrimary.ObjectHandle.Value).ConfigureAwait(false);
            }
        }
    }

    /// <summary>
    /// Each of <c>TPM2_ReadClock()</c>, <c>TPM2_Shutdown()</c>, <c>TPM2_SelfTest()</c>,
    /// <c>TPM2_GetTestResult()</c>, <c>TPM2_GetCapability()</c> and <c>TPM2_PCR_Read()</c>'s plain
    /// <c>TPM_ST_NO_SESSIONS</c> form refuses a trailing octet beyond its own last parameter with
    /// <c>TPM_RC_SIZE</c> — the generic "no leftover octets" rule the plain form applies
    /// (Part 3, clause 5.8.2, Table 2; Part 4 <c>CommandDispatcher</c>).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.8.2, Table 2</see>.
    /// </summary>
    [TestMethod]
    [DataRow(TpmCcConstants.TPM_CC_ReadClock, DisplayName = "TPM2_ReadClock()")]
    [DataRow(TpmCcConstants.TPM_CC_Shutdown, DisplayName = "TPM2_Shutdown()")]
    [DataRow(TpmCcConstants.TPM_CC_SelfTest, DisplayName = "TPM2_SelfTest()")]
    [DataRow(TpmCcConstants.TPM_CC_GetTestResult, DisplayName = "TPM2_GetTestResult()")]
    [DataRow(TpmCcConstants.TPM_CC_GetCapability, DisplayName = "TPM2_GetCapability()")]
    [DataRow(TpmCcConstants.TPM_CC_PCR_Read, DisplayName = "TPM2_PCR_Read()")]
    public async Task SilentParserPlainFormRefusesATrailingOctetWithSize(TpmCcConstants commandCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] parameters = CanonicalParametersFor(commandCode, pool);
        byte[] withTrailingOctet = [.. parameters, 0x00];

        int length = TpmHeader.HeaderSize + withTrailingOctet.Length;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        Memory<byte> command = owner.Memory[..length];
        var writer = new TpmWriter(command.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)commandCode);
        header.WriteTo(ref writer);
        writer.WriteBytes(withTrailingOctet);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(command, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The transport itself must succeed.");
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, (TpmRcConstants)responseHeader.Code, $"'{commandCode}' must refuse a trailing octet with TPM_RC_SIZE.");
    }

    /// <summary>
    /// <c>TPM2_GetRandom()</c> over a single encrypt-claiming companion succeeds, and the response's
    /// <c>randomBytes</c> TPM2B genuinely decrypts under the SESSION'S OWN parameter-encryption key — verified
    /// through <see cref="TpmSession.VerifyAndUpdateAsync"/> and recovered through
    /// <see cref="TpmSession.DecryptFirstParameterAsync"/>, not merely a declared-width check — for both admitted
    /// transforms ("This attribute may only be SET in a response that has a sized buffer as its first
    /// parameter... the encrypted data size and the plain-text data size is the same").
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clauses 15.6.4, Table 15, and 18.1 and 18.2</see>.
    /// </summary>
    /// <param name="useAesCfb"><see langword="true"/> to negotiate AES-CFB; <see langword="false"/> for TPM_ALG_XOR.</param>
    [TestMethod]
    [DataRow(false, DisplayName = "TPM_ALG_XOR")]
    [DataRow(true, DisplayName = "AES-CFB")]
    public async Task GetRandomOverAnEncryptSlotSucceedsWithTheRandomBytesGenuinelyDecryptedUnderTheSessionsOwnKey(bool useAesCfb)
    {
        TpmtSymDef symmetric = useAesCfb ? TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB) : SessionSymmetric;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        byte[] parameters = TpmInHouseSimulatorZeroHandleSessionTests.ParameterAreaFor(TpmCcConstants.TPM_CC_GetRandom, pool);

        (uint encryptHandle, TpmSession encryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, symmetric).ConfigureAwait(false);
        try
        {
            using(encryptSession)
            {
                encryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;
                byte[] authArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(encryptSession, TpmCcConstants.TPM_CC_GetRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);

                (TpmRcConstants code, byte[] response) = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleForAuditAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_GetRandom, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "GetRandom over an encrypt companion must succeed.");

                (byte[] responseParameters, TpmsAuthResponse entry) = ReadResponseParametersAndEntry(response, outHandleCount: 0, entryIndex: 0, pool);
                using(entry)
                {
                    ushort declaredLength = BinaryPrimitives.ReadUInt16BigEndian(responseParameters);
                    Assert.AreEqual(RandomDrawLength, declaredLength, "The declared randomBytes width equals the request; parameter encryption never changes it.");

                    byte[] rpHash = await TpmInHouseSimulatorZeroHandleSessionTests.ComputeRpHashAsync(TpmCcConstants.TPM_CC_GetRandom, responseParameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                    bool verified = await encryptSession.VerifyAndUpdateAsync(entry, rpHash, pool, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.IsTrue(verified, "The response HMAC must verify under the session's own key before its parameter is trusted decrypted.");

                    byte[] payload = responseParameters[sizeof(ushort)..];
                    await encryptSession.DecryptFirstParameterAsync(payload, pool, TestContext.CancellationToken).ConfigureAwait(false);

                    Assert.AreEqual(RandomDrawLength, payload.Length, "The genuinely decrypted payload's own length is unchanged by the stream transform.");
                }
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, encryptHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_GetRandom()</c> over a THREE-entry area — audit at index 0, encrypt at index 1, and a third slot
    /// claiming an attribute the third position cannot carry — is refused session-encoded <c>TPM_RC_ATTRIBUTES</c>
    /// at the THIRD index once the first two have already verified: a decrypt claim, because GetRandom's only
    /// command parameter (<c>bytesRequested</c>) is a bare UINT16 with no sized-buffer form to decrypt into
    /// ("This attribute can only be SET in a command that has a sized buffer as its first parameter"); a second
    /// audit claim, because "Only one session is allowed for... session auditing".
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.5, steps 4.4.1 and 4.4.2; Part 1, clauses 15.6.1 and 15.6.4</see>.
    /// </summary>
    /// <param name="thirdSlotClaimsDecrypt"><see langword="true"/> for a decrypt claim at index 2; <see langword="false"/> for a second audit claim.</param>
    [TestMethod]
    [DataRow(true, DisplayName = "third slot claims decrypt")]
    [DataRow(false, DisplayName = "third slot claims a second audit")]
    public async Task GetRandomOverThreeEntriesReturnsSessionEncodedAttributesAtTheThirdIndex(bool thirdSlotClaimsDecrypt)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        byte[] parameters = TpmInHouseSimulatorZeroHandleSessionTests.ParameterAreaFor(TpmCcConstants.TPM_CC_GetRandom, pool);

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        (uint encryptHandle, TpmSession encryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        (uint thirdHandle, TpmSession thirdSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        try
        {
            using(auditSession)
            using(encryptSession)
            using(thirdSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                encryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;
                thirdSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | (thirdSlotClaimsDecrypt ? TpmaSession.DECRYPT : TpmaSession.AUDIT);

                byte[] authArea =
                [
                    .. await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_GetRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false),
                    .. await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(encryptSession, TpmCcConstants.TPM_CC_GetRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false),
                    .. await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(thirdSession, TpmCcConstants.TPM_CC_GetRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false),
                ];

                TpmRcConstants code = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_GetRandom, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmInHouseSimulatorZeroHandleSessionTests.SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 2), code,
                    "The third slot's inadmissible claim is refused at its own index once the first two slots have already verified.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, encryptHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, thirdHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_StirRandom()</c> over an audit-claiming companion and a decrypt-claiming companion negotiating
    /// AES-CFB (rather than TPM_ALG_XOR) succeeds and genuinely folds the recovered <c>inData</c> into the RNG
    /// reseed state: the next draw over a fresh, otherwise-identical simulator differs from the stirred instance's
    /// own next draw.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 16.2; Part 1, clauses 15.6.1 and 18.3</see>.
    /// </summary>
    [TestMethod]
    public async Task StirRandomOverAnAuditSlotAndAnAesCfbDecryptSlotSucceedsAndFoldsTheRecoveredInData()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmtSymDef aesCfb = TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB);

        byte[] stirredDraw;
        using(TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false))
        {
            using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
            TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

            byte[] parameters = TpmInHouseSimulatorZeroHandleSessionTests.ParameterAreaFor(TpmCcConstants.TPM_CC_StirRandom, pool);

            (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
            (uint decryptHandle, TpmSession decryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, aesCfb).ConfigureAwait(false);
            try
            {
                using(auditSession)
                using(decryptSession)
                {
                    auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                    decryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                    byte[] authArea =
                    [
                        .. await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_StirRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false),
                        .. await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(decryptSession, TpmCcConstants.TPM_CC_StirRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false),
                    ];

                    TpmRcConstants code = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                        simulator, pool, TpmCcConstants.TPM_CC_StirRandom, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

                    Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "An audit claim plus a real AES-CFB decrypt claim over StirRandom must succeed.");
                }
            }
            finally
            {
                await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
                await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, decryptHandle).ConfigureAwait(false);
            }

            stirredDraw = await DrawRandomBareAsync(simulator, pool).ConfigureAwait(false);
        }

        using TpmSimulator unstirredTwin = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] unstirredDraw = await DrawRandomBareAsync(unstirredTwin, pool).ConfigureAwait(false);

        Assert.AreNotSequenceEqual(unstirredDraw, stirredDraw, "The AES-CFB-recovered inData must genuinely fold into the RNG state, so the stirred twin's draw diverges from an unstirred instance's.");
    }

    /// <summary>
    /// <c>TPM2_StirRandom()</c> over an audit-claiming companion at index 0 and an encrypt-claiming companion at
    /// index 1 is refused session-encoded <c>TPM_RC_ATTRIBUTES</c> at the SECOND index: StirRandom answers a
    /// header-only response with no sized first parameter for an encrypt claim to protect, regardless of how many
    /// OTHER companions the area also carries.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clauses 15.6.4, Table 15, and 18.1; Part 3, clause 16.2.2, Table 78</see>.
    /// </summary>
    [TestMethod]
    public async Task StirRandomOverAnAuditSlotAndAnEncryptSlotReturnsSessionEncodedAttributesAtTheSecondIndex()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        byte[] parameters = TpmInHouseSimulatorZeroHandleSessionTests.ParameterAreaFor(TpmCcConstants.TPM_CC_StirRandom, pool);

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        (uint encryptHandle, TpmSession encryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        try
        {
            using(auditSession)
            using(encryptSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                encryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                byte[] authArea =
                [
                    .. await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_StirRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false),
                    .. await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(encryptSession, TpmCcConstants.TPM_CC_StirRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false),
                ];

                TpmRcConstants code = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_StirRandom, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmInHouseSimulatorZeroHandleSessionTests.SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 1), code,
                    "StirRandom's response carries no sized parameter, so an encrypt claim beside a verified audit companion is refused at its own (second) index.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, encryptHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_StirRandom()</c> over an audit-claiming companion at index 0 and a decrypt-claiming companion
    /// negotiating <c>TPM_ALG_NULL</c> at index 1 is refused session-encoded <c>TPM_RC_SYMMETRIC</c> at the SECOND
    /// index: <c>inData</c> IS a sized command parameter, so the claim reaches the symmetric-algorithm gate rather
    /// than the attribute gate — the single-slot rule the sibling zero-handle class pins, holding unchanged when a
    /// verified audit companion precedes it.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 18.1; Part 3, clause 5.7</see>.
    /// </summary>
    [TestMethod]
    public async Task StirRandomOverAnAuditSlotAndANullSymmetricDecryptSlotReturnsSessionEncodedSymmetricAtTheSecondIndex()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        byte[] parameters = TpmInHouseSimulatorZeroHandleSessionTests.ParameterAreaFor(TpmCcConstants.TPM_CC_StirRandom, pool);

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        (uint decryptHandle, TpmSession decryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(auditSession)
            using(decryptSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                decryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                byte[] authArea =
                [
                    .. await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_StirRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false),
                    .. await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(decryptSession, TpmCcConstants.TPM_CC_StirRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false),
                ];

                TpmRcConstants code = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_StirRandom, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmInHouseSimulatorZeroHandleSessionTests.SessionEncodedRc(TpmRcConstants.TPM_RC_SYMMETRIC, sessionIndex: 1), code,
                    "inData is a sized command parameter, so a TPM_ALG_NULL decrypt claim beside a verified audit companion is refused TPM_RC_SYMMETRIC at its own (second) index.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, decryptHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_TestParms()</c> over an audit-claiming companion at index 0 and a decrypt-claiming companion at
    /// index 1 is refused session-encoded <c>TPM_RC_ATTRIBUTES</c> at the SECOND index: its <c>TPMT_PUBLIC_PARMS</c>
    /// carries no sized first parameter in either direction, so a decrypt claim has nothing to attach to,
    /// regardless of the audit companion that already verified beside it.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clauses 15.6.4, Table 15, and 18.1; Part 3, clause 30.3.2, Table 241</see>.
    /// </summary>
    [TestMethod]
    public async Task TestParmsOverAnAuditSlotAndADecryptSlotReturnsSessionEncodedAttributesAtTheSecondIndex()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        byte[] parameters = TpmInHouseSimulatorZeroHandleSessionTests.ParameterAreaFor(TpmCcConstants.TPM_CC_TestParms, pool);

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        (uint decryptHandle, TpmSession decryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        try
        {
            using(auditSession)
            using(decryptSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                decryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                byte[] authArea =
                [
                    .. await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_TestParms, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false),
                    .. await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(decryptSession, TpmCcConstants.TPM_CC_TestParms, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false),
                ];

                TpmRcConstants code = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_TestParms, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmInHouseSimulatorZeroHandleSessionTests.SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 1), code,
                    "TestParms has no sized first parameter in either direction, so a decrypt claim beside a verified audit companion is refused at its own (second) index.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, decryptHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_GetRandom()</c> over an audit-claiming companion at index 0 and a SECOND companion at index 1 whose
    /// own command HMAC does not verify is refused session-encoded <c>TPM_RC_BAD_AUTH</c> at the SECOND index,
    /// uncharged, with the command itself NOT run: the next bare draw over this same simulator equals a fresh,
    /// never-touched twin's own first draw, proving no randomness was consumed.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.5, step 4; Part 1, clause 17.1</see>.
    /// </summary>
    [TestMethod]
    public async Task GetRandomOverAnAuditSlotAndACorruptedEncryptSlotHmacReturnsBadAuthAndTheDrawIsNotTaken()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        byte[] parameters = TpmInHouseSimulatorZeroHandleSessionTests.ParameterAreaFor(TpmCcConstants.TPM_CC_GetRandom, pool);

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        (uint encryptHandle, TpmSession encryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        try
        {
            using(auditSession)
            using(encryptSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                encryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                byte[] auditBlock = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_GetRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                byte[] corruptedBlock = WithCorruptedHmac(
                    await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(encryptSession, TpmCcConstants.TPM_CC_GetRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false));

                byte[] authArea = [.. auditBlock, .. corruptedBlock];

                TpmRcConstants code = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_GetRandom, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmInHouseSimulatorZeroHandleSessionTests.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 1), code,
                    "A companion whose own HMAC does not verify is refused TPM_RC_BAD_AUTH at its own index, uncharged.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, encryptHandle).ConfigureAwait(false);
        }

        byte[] thisDraw = await DrawRandomBareAsync(simulator, pool).ConfigureAwait(false);
        byte[] twinDraw = await DrawRandomAfterMatchingSessionStartsAsync(pool).ConfigureAwait(false);

        Assert.AreSequenceEqual(twinDraw, thisDraw, "A refused companion HMAC must leave TPM2_GetRandom() un-run, so this simulator's next bare draw equals a twin's own first draw after the SAME two session starts (which themselves consume the deterministic RNG the draw reads from).");
    }

    /// <summary>
    /// <c>TPM2_StirRandom()</c> over an audit-claiming companion at index 0 and a SECOND (decrypt-claiming)
    /// companion at index 1 whose own command HMAC does not verify is refused session-encoded
    /// <c>TPM_RC_BAD_AUTH</c> at the SECOND index, uncharged, with the command NOT run: the RNG is left exactly as
    /// an otherwise-identical, never-stirred twin's — no fold occurred.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.5, step 4; Part 1, clause 17.1</see>.
    /// </summary>
    [TestMethod]
    public async Task StirRandomOverAnAuditSlotAndACorruptedDecryptSlotHmacReturnsBadAuthAndNoStirIsApplied()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        byte[] parameters = TpmInHouseSimulatorZeroHandleSessionTests.ParameterAreaFor(TpmCcConstants.TPM_CC_StirRandom, pool);

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        (uint decryptHandle, TpmSession decryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        try
        {
            using(auditSession)
            using(decryptSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                decryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                byte[] auditBlock = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_StirRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                byte[] corruptedBlock = WithCorruptedHmac(
                    await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(decryptSession, TpmCcConstants.TPM_CC_StirRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false));

                byte[] authArea = [.. auditBlock, .. corruptedBlock];

                TpmRcConstants code = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_StirRandom, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmInHouseSimulatorZeroHandleSessionTests.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 1), code,
                    "A companion whose own HMAC does not verify is refused TPM_RC_BAD_AUTH at its own index, uncharged.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, decryptHandle).ConfigureAwait(false);
        }

        byte[] thisDraw = await DrawRandomBareAsync(simulator, pool).ConfigureAwait(false);
        byte[] twinDraw = await DrawRandomAfterMatchingSessionStartsAsync(pool).ConfigureAwait(false);

        Assert.AreSequenceEqual(twinDraw, thisDraw, "A refused companion HMAC must leave TPM2_StirRandom() un-run, so this simulator's RNG state matches a twin's own first draw after the SAME two session starts (which themselves consume the deterministic RNG the draw reads from).");
    }

    /// <summary>
    /// <c>TPM2_GetRandom()</c> has no command handle for a <c>TPM_RS_PW</c> authorization to attach to, so a
    /// password slot at index 1, beside an audit companion that already verified at index 0, is refused
    /// session-encoded <c>TPM_RC_ATTRIBUTES</c> at its own (second) index — the single-slot rule the sibling
    /// zero-handle class pins, holding unchanged beside another, already-admissible companion.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.4 and clause 15.6.4, Table 15; Part 3, clause 5.5, step 4.4.2</see>.
    /// </summary>
    [TestMethod]
    public async Task GetRandomOverAnAuditSlotAndAPasswordSlotReturnsSessionEncodedAttributesAtTheSecondIndex()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        byte[] parameters = TpmInHouseSimulatorZeroHandleSessionTests.ParameterAreaFor(TpmCcConstants.TPM_CC_GetRandom, pool);

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(auditSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                byte[] authArea =
                [
                    .. await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_GetRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false),
                    .. BuildPasswordAuthArea(),
                ];

                TpmRcConstants code = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_GetRandom, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmInHouseSimulatorZeroHandleSessionTests.SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 1), code,
                    "A TPM_RS_PW slot beside a verified audit companion is refused at its own (second) index.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A well-typed session handle at index 1, naming no loaded session, beside an audit companion that already
    /// verified at index 0, is blamed on the offending slot's own warning value: session-encoded
    /// <c>TPM_RC_REFERENCE_S0 + N</c> becomes the distinct constant <c>TPM_RC_REFERENCE_S1</c> at N = 1.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.5, step 4.2; Part 2, clause 6.6.2</see>.
    /// </summary>
    [TestMethod]
    public async Task GetRandomOverAnAuditSlotAndAnUnloadedSessionHandleAtTheSecondIndexReturnsReferenceS1()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        byte[] parameters = TpmInHouseSimulatorZeroHandleSessionTests.ParameterAreaFor(TpmCcConstants.TPM_CC_GetRandom, pool);

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        (uint unloadedHandle, TpmSession unloadedSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        byte[] unloadedBlock;
        using(unloadedSession)
        {
            unloadedSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;
            unloadedBlock = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(unloadedSession, TpmCcConstants.TPM_CC_GetRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
        }

        await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, unloadedHandle).ConfigureAwait(false);

        try
        {
            using(auditSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                byte[] authArea =
                [
                    .. await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_GetRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false),
                    .. unloadedBlock,
                ];

                TpmRcConstants code = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_GetRandom, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_REFERENCE_S1, code,
                    "A well-typed session handle naming no loaded session at index 1, beside a verified audit companion, answers TPM_RC_REFERENCE_S1.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A LOADED policy session at index 1, beside an audit companion that already verified at index 0, claiming
    /// <c>decrypt</c> and authorizing no entity, is admitted exactly like an HMAC companion — TPM 2.0 Library
    /// Part 1, Table 12, footnote [2]: "a policy authorization session can also be used for encryption and
    /// decryption." <c>TPM2_GetRandom()</c>'s own command parameter is a plain <c>UINT16</c>, not a sized buffer
    /// a decrypt session can protect, so the claim is refused by the area's own attribute rule, session-encoded
    /// <c>TPM_RC_ATTRIBUTES</c> at index 1 — the same refusal an HMAC companion claiming <c>decrypt</c> here
    /// would draw.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 15.6.1, Table 12, footnote [2]; clause 18.1</see>.
    /// </summary>
    [TestMethod]
    public async Task GetRandomOverAnAuditSlotAndALoadedPolicySessionClaimingDecryptAtTheSecondIndexReturnsSessionEncodedAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        byte[] parameters = TpmInHouseSimulatorZeroHandleSessionTests.ParameterAreaFor(TpmCcConstants.TPM_CC_GetRandom, pool);

        TpmResult<StartAuthSessionResponse> policyStartResult = await device.StartPolicySessionAsync(TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(policyStartResult.IsSuccess, $"StartAuthSession (policy) failed: '{policyStartResult.ResponseCode}'.");
        using StartAuthSessionResponse policyStarted = policyStartResult.Value;
        uint policySessionHandle = policyStarted.SessionHandle.Value;

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        (uint placeholderHandle, TpmSession placeholderSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        try
        {
            using(auditSession)
            using(placeholderSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                placeholderSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                byte[] auditBlock = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_GetRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                byte[] placeholderBlock = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(placeholderSession, TpmCcConstants.TPM_CC_GetRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);

                //The nonce, attributes and hmac stay exactly as the placeholder companion negotiated them; only
                //the handle field is overwritten with the loaded policy session's own handle, so the slot's type
                //and loadedness resolve to a genuine POLICY session ahead of any HMAC judgment.
                BinaryPrimitives.WriteUInt32BigEndian(placeholderBlock.AsSpan(0, sizeof(uint)), policySessionHandle);

                byte[] authArea = [.. auditBlock, .. placeholderBlock];

                TpmRcConstants code = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_GetRandom, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmInHouseSimulatorZeroHandleSessionTests.SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 1), code,
                    "A loaded POLICY session at index 1 claiming decrypt is admitted like an HMAC companion, then refused session-encoded ATTRIBUTES because GetRandom's own command parameter is not a sized buffer a decrypt session can protect.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, placeholderHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, policySessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A non-session handle at index 1, beside an audit companion that already verified at index 0, is refused
    /// on the handle's KIND alone, ahead of any credential evaluation: session-encoded <c>TPM_RC_HANDLE</c> at
    /// the offending (second) index.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.5, step 4.1; Part 2, clauses 7.2 and 6.6.2</see>.
    /// </summary>
    [TestMethod]
    public async Task GetRandomOverAnAuditSlotAndANonSessionHandleAtTheSecondIndexReturnsSessionEncodedHandle()
    {
        const uint TransientRangeHandle = 0x8000_0000;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        byte[] parameters = TpmInHouseSimulatorZeroHandleSessionTests.ParameterAreaFor(TpmCcConstants.TPM_CC_GetRandom, pool);

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        (uint placeholderHandle, TpmSession placeholderSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        try
        {
            using(auditSession)
            using(placeholderSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                placeholderSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                byte[] auditBlock = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_GetRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                byte[] placeholderBlock = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(placeholderSession, TpmCcConstants.TPM_CC_GetRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                BinaryPrimitives.WriteUInt32BigEndian(placeholderBlock.AsSpan(0, sizeof(uint)), TransientRangeHandle);

                byte[] authArea = [.. auditBlock, .. placeholderBlock];

                TpmRcConstants code = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_GetRandom, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmInHouseSimulatorZeroHandleSessionTests.SessionEncodedRc(TpmRcConstants.TPM_RC_HANDLE, sessionIndex: 1), code,
                    "A non-session handle at index 1, beside an already-verified audit companion, is refused on the handle's kind alone, session-encoded to its own index.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, placeholderHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A companion claiming ONLY audit becomes the exclusive audit session on its first use, and its response
    /// echoes <c>auditExclusive</c> SET; a plain, sessionless <c>TPM_ST_NO_SESSIONS</c> <c>TPM2_GetRandom()</c> run
    /// afterward clears that exclusivity ("A command that is not allowed to have any sessions will not change the
    /// current exclusive audit session" implies every OTHER command does), so the SAME session's next audited use
    /// — still claiming only audit — now echoes <c>auditExclusive</c> CLEAR, read directly off the wire.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.2; Part 2, clause 8.4, Table 38</see>.
    /// </summary>
    [TestMethod]
    public async Task GetRandomOverAnAuditSlotLosesTheEchoedExclusiveBitAfterAnInterveningPlainGetRandom()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        byte[] parameters = TpmInHouseSimulatorZeroHandleSessionTests.ParameterAreaFor(TpmCcConstants.TPM_CC_GetRandom, pool);

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(auditSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                byte[] firstAuthArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_GetRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                (TpmRcConstants firstCode, byte[] firstResponse) = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleForAuditAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_GetRandom, firstAuthArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, firstCode, "The first audited draw must succeed.");

                byte firstAttributes = TpmInHouseSimulatorZeroHandleSessionTests.ReadResponseSessionAttributes(firstResponse, outHandleCount: 0, sessionIndex: 0);
                Assert.AreEqual(
                    (byte)(TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT | TpmaSession.AUDIT_EXCLUSIVE), firstAttributes,
                    "The session's first audit use always grants it the exclusive status.");

                //Hand-framing bypasses the production executor, so the session's own nonceTPM is adopted here,
                //exactly as TpmSession.VerifyAndUpdateAsync would on a genuine round trip — without it the
                //SECOND audited call below would compute its command HMAC over a stale nonceTPM and fail BAD_AUTH.
                (byte[] firstResponseParameters, TpmsAuthResponse firstEntry) = ReadResponseParametersAndEntry(firstResponse, outHandleCount: 0, entryIndex: 0, pool);
                using(firstEntry)
                {
                    byte[] firstRpHash = await TpmInHouseSimulatorZeroHandleSessionTests.ComputeRpHashAsync(TpmCcConstants.TPM_CC_GetRandom, firstResponseParameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                    bool firstVerified = await auditSession.VerifyAndUpdateAsync(firstEntry, firstRpHash, pool, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.IsTrue(firstVerified, "The first audited response's own HMAC must verify under the session's key before its nonceTPM is trusted.");
                }

                byte[] plainResponse = await SubmitBareAsync(simulator, pool, TpmCcConstants.TPM_CC_GetRandom, parameters).ConfigureAwait(false);
                var plainReader = new TpmReader(plainResponse);
                TpmHeader plainHeader = TpmHeader.Parse(ref plainReader);
                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)plainHeader.Code, "The intervening plain, sessionless TPM2_GetRandom() must itself succeed.");

                byte[] secondAuthArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_GetRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                (TpmRcConstants secondCode, byte[] secondResponse) = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleForAuditAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_GetRandom, secondAuthArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, secondCode, "The session's second audited use, still claiming only audit, must succeed.");

                byte secondAttributes = TpmInHouseSimulatorZeroHandleSessionTests.ReadResponseSessionAttributes(secondResponse, outHandleCount: 0, sessionIndex: 0);
                Assert.AreEqual(
                    (byte)(TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT), secondAttributes,
                    "auditExclusive is echoed CLEAR: the intervening plain command cleared the exclusive status, and merely claiming audit again does not reclaim it.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_TestParms()</c> over a SINGLE audit-claiming companion succeeds at the session area, so its own
    /// <c>TPMT_PUBLIC_PARMS</c> is finally judged — and for <c>TPM_ALG_MLDSA</c> (a Table 225 member no creatable
    /// type in this simulator implements, distinct from the SYMCIPHER selector this class's own single-slot
    /// refused-profile case already exercises) answers that judgment's own <c>TPM_RC_TYPE</c>, parameter-encoded to the same index; the session's own nonceTPM —
    /// read directly off the client-side session, not merely inferred from a follow-up's success — is the SAME
    /// octets before and after the refusal, since a failed command "will not update any session or audit data".
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 5.5, 5.8.2 and 5.9; Part 2, clause 12.2.2, Table 225</see>.
    /// </summary>
    [TestMethod]
    public async Task TestParmsOverAnAuditSlotWithADifferentUnimplementedTypeLeavesTheSessionsNonceTpmUnchanged()
    {
        byte[] mldsaParms = [0x00, 0xA1];

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        (uint sessionHandle, TpmSession session) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                byte[] authArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(session, TpmCcConstants.TPM_CC_TestParms, mldsaParms, pool, TestContext.CancellationToken).ConfigureAwait(false);
                byte[] nonceBeforeRefusal = session.NonceTpm.ToArray();

                TpmRcConstants code = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_TestParms, authArea, mldsaParms, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(
                    HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_TYPE, parameterIndex: 0), code,
                    "Table 240: parameters is TPM2_TestParms()'s sole parameter (index 0); TPM_ALG_MLDSA is a registered-but-unimplemented object type, answering that parameter's own TPM_RC_TYPE.");
                Assert.AreSequenceEqual(nonceBeforeRefusal, session.NonceTpm.ToArray(), "A failed command updates no session data at all, so nonceTPM is the literal same octets after the refusal.");

                byte[] followUpParameters = TpmInHouseSimulatorZeroHandleSessionTests.ParameterAreaFor(TpmCcConstants.TPM_CC_TestParms, pool);
                byte[] followUpAuthArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(session, TpmCcConstants.TPM_CC_TestParms, followUpParameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                TpmRcConstants followUpCode = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_TestParms, followUpAuthArea, followUpParameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, followUpCode, "The unchanged nonceTPM, re-used by this follow-up's own HMAC, still verifies.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The <see cref="MeteredHousePool"/> balance across a successful single-slot encrypt round trip whose
    /// <c>randomBytes</c> is genuinely decrypted (not merely width-checked), a corrupted-companion-HMAC refusal,
    /// and a three-entry area's third-slot <c>TPM_RC_ATTRIBUTES</c> refusal — every rented carrier comes back on
    /// each of the three paths.
    /// </summary>
    [TestMethod]
    public async Task TheMeteredPoolBalancesAcrossAnEncryptSuccessWithPlaintextRecoveryABadAuthRefusalAndAThreeEntryAttributesRefusal()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;

        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        long baseline = trackingPool.OutstandingCount;

        //(a) The successful single-slot encrypt round trip, its randomBytes genuinely decrypted.
        {
            byte[] parameters = TpmInHouseSimulatorZeroHandleSessionTests.ParameterAreaFor(TpmCcConstants.TPM_CC_GetRandom, pool);
            (uint encryptHandle, TpmSession encryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
            try
            {
                using(encryptSession)
                {
                    encryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;
                    byte[] authArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(encryptSession, TpmCcConstants.TPM_CC_GetRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);

                    (TpmRcConstants code, byte[] response) = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleForAuditAsync(
                        simulator, pool, TpmCcConstants.TPM_CC_GetRandom, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "(a) must actually succeed for its balance to prove anything.");

                    (byte[] responseParameters, TpmsAuthResponse entry) = ReadResponseParametersAndEntry(response, outHandleCount: 0, entryIndex: 0, pool);
                    using(entry)
                    {
                        byte[] rpHash = await TpmInHouseSimulatorZeroHandleSessionTests.ComputeRpHashAsync(TpmCcConstants.TPM_CC_GetRandom, responseParameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                        bool verified = await encryptSession.VerifyAndUpdateAsync(entry, rpHash, pool, TestContext.CancellationToken).ConfigureAwait(false);
                        Assert.IsTrue(verified, "(a)'s response HMAC must verify for its balance to prove anything.");

                        byte[] payload = responseParameters[sizeof(ushort)..];
                        await encryptSession.DecryptFirstParameterAsync(payload, pool, TestContext.CancellationToken).ConfigureAwait(false);
                    }
                }
            }
            finally
            {
                await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, encryptHandle).ConfigureAwait(false);
            }

            Assert.AreEqual(baseline, trackingPool.OutstandingCount, "(a) A successful encrypt round trip with a genuine plaintext recovery must return every carrier it rented.");
        }

        //(b) The corrupted second-slot HMAC refusal.
        {
            byte[] parameters = TpmInHouseSimulatorZeroHandleSessionTests.ParameterAreaFor(TpmCcConstants.TPM_CC_GetRandom, pool);
            (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
            (uint encryptHandle, TpmSession encryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
            try
            {
                using(auditSession)
                using(encryptSession)
                {
                    auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                    encryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                    byte[] auditBlock = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_GetRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                    byte[] corruptedBlock = WithCorruptedHmac(
                        await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(encryptSession, TpmCcConstants.TPM_CC_GetRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false));

                    byte[] authArea = [.. auditBlock, .. corruptedBlock];

                    TpmRcConstants code = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                        simulator, pool, TpmCcConstants.TPM_CC_GetRandom, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.AreEqual(
                        TpmInHouseSimulatorZeroHandleSessionTests.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 1), code,
                        "(b) must actually refuse at the second slot's HMAC for its balance to prove anything.");
                }
            }
            finally
            {
                await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
                await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, encryptHandle).ConfigureAwait(false);
            }

            Assert.AreEqual(baseline, trackingPool.OutstandingCount, "(b) A corrupted companion HMAC refusal must return every carrier it rented.");
        }

        //(c) The three-entry area's third-index ATTRIBUTES refusal.
        {
            byte[] parameters = TpmInHouseSimulatorZeroHandleSessionTests.ParameterAreaFor(TpmCcConstants.TPM_CC_GetRandom, pool);
            (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
            (uint encryptHandle, TpmSession encryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
            (uint thirdHandle, TpmSession thirdSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
            try
            {
                using(auditSession)
                using(encryptSession)
                using(thirdSession)
                {
                    auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                    encryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;
                    thirdSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                    byte[] authArea =
                    [
                        .. await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(auditSession, TpmCcConstants.TPM_CC_GetRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false),
                        .. await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(encryptSession, TpmCcConstants.TPM_CC_GetRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false),
                        .. await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(thirdSession, TpmCcConstants.TPM_CC_GetRandom, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false),
                    ];

                    TpmRcConstants code = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleAsync(
                        simulator, pool, TpmCcConstants.TPM_CC_GetRandom, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.AreEqual(
                        TpmInHouseSimulatorZeroHandleSessionTests.SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 2), code,
                        "(c) must actually refuse at the third slot for its balance to prove anything.");
                }
            }
            finally
            {
                await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
                await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, encryptHandle).ConfigureAwait(false);
                await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, thirdHandle).ConfigureAwait(false);
            }

            Assert.AreEqual(baseline, trackingPool.OutstandingCount, "(c) A three-entry area's third-index refusal must return every carrier it rented.");
        }
    }

    /// <summary>
    /// Serializes one command's canonical, well-formed parameter area through its own production input type, so
    /// a refusal in a test is never a malformed body's doing. Shared with
    /// <see cref="Verifiable.Tests.Tpm.TpmInHouseSimulatorNoAuthSessionReadCommandTests"/>, which drives the same
    /// six handle-less commands rather than re-minting a second copy.
    /// </summary>
    /// <param name="commandCode">One of the six zero-handle commands <see cref="SilentParserPlainFormRefusesATrailingOctetWithSize"/> covers.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The parameter area's octets.</returns>
    internal static byte[] CanonicalParametersFor(TpmCcConstants commandCode, BaseMemoryPool pool)
    {
        switch(commandCode)
        {
            case TpmCcConstants.TPM_CC_ReadClock:
            {
                return SerializeParameters(new ReadClockInput(), pool);
            }
            case TpmCcConstants.TPM_CC_Shutdown:
            {
                return SerializeParameters(new ShutdownInput(TpmSuConstants.TPM_SU_CLEAR), pool);
            }
            case TpmCcConstants.TPM_CC_SelfTest:
            {
                return SerializeParameters(new SelfTestInput(IsFullTest: false), pool);
            }
            case TpmCcConstants.TPM_CC_GetTestResult:
            {
                return SerializeParameters(new GetTestResultInput(), pool);
            }
            case TpmCcConstants.TPM_CC_GetCapability:
            {
                return SerializeParameters(GetCapabilityInput.ForFixedProperties(), pool);
            }
            case TpmCcConstants.TPM_CC_PCR_Read:
            {
                using(PcrReadInput input = PcrReadInput.ForAllPcrs(TpmAlgIdConstants.TPM_ALG_SHA256, pool))
                {
                    return SerializeParameters(input, pool);
                }
            }

            default:
            {
                throw new ArgumentOutOfRangeException(nameof(commandCode), commandCode, "Only the six zero-handle commands this test class covers are framed here.");
            }
        }
    }

    /// <summary>
    /// Serializes one command input's parameter area (excluding any handle area) into a standalone array. Shared
    /// with <see cref="Verifiable.Tests.Tpm.TpmInHouseSimulatorNoAuthSessionReadCommandTests"/>, which extends
    /// this class's own hand-framing fixture rather than re-minting a second copy.
    /// </summary>
    /// <param name="input">The command input.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The parameter octets.</returns>
    internal static byte[] SerializeParameters(ITpmCommandInput input, BaseMemoryPool pool)
    {
        int length = input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(Math.Max(length, 1));
        Memory<byte> parameters = owner.Memory[..length];
        var writer = new TpmWriter(parameters.Span);
        input.WriteParameters(ref writer);

        return parameters.Span.ToArray();
    }

    /// <summary>
    /// Frames a <c>TPM_ST_NO_SESSIONS</c> command directly and returns the raw response octets, independent of
    /// any registry or codec. Shared with
    /// <see cref="Verifiable.Tests.Tpm.TpmInHouseSimulatorNoAuthSessionReadCommandTests"/> through its own
    /// <c>Shared</c> instance, rather than re-minting a second copy.
    /// </summary>
    /// <param name="simulator">The simulator under test.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="commandCode">The command code written into the header.</param>
    /// <param name="parameters">The parameter area.</param>
    /// <returns>The raw response octets.</returns>
    internal async Task<byte[]> SubmitBareAsync(TpmSimulator simulator, BaseMemoryPool pool, TpmCcConstants commandCode, ReadOnlyMemory<byte> parameters)
    {
        int length = TpmHeader.HeaderSize + parameters.Length;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        Memory<byte> command = owner.Memory[..length];
        var writer = new TpmWriter(command.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)commandCode);
        header.WriteTo(ref writer);
        writer.WriteBytes(parameters.Span);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(command, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The transport itself must succeed.");
        using TpmResponse response = result.Value;

        return response.AsReadOnlySpan().ToArray();
    }

    /// <summary>Frames <c>TPM2_Startup(TPM_SU_STATE)</c> directly to the simulator, sessionless, and returns its response code.</summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitStartupStateAsync(TpmSimulator simulator, BaseMemoryPool pool)
    {
        var input = new StartupInput(TpmSuConstants.TPM_SU_STATE);
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);
        Memory<byte> command = owner.Memory[..length];
        var writer = new TpmWriter(command.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(command, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The transport itself must succeed.");
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());

        return (TpmRcConstants)TpmHeader.Parse(ref reader).Code;
    }

    /// <summary>
    /// Computes <c>cpHash = H_sessionAlg(commandCode ‖ Name ‖ parameters)</c> (TPM 2.0 Library Part 1, clause
    /// 15.7, equation 15) for a ONE-handle no-authorization command, over octets this test assembled itself.
    /// </summary>
    /// <param name="commandCode">The command code.</param>
    /// <param name="nameOctets">The addressed handle's Name term.</param>
    /// <param name="parameters">The parameter area as sent.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The cpHash octets.</returns>
    internal async Task<byte[]> ComputeCpHashWithNameAsync(TpmCcConstants commandCode, ReadOnlyMemory<byte> nameOctets, ReadOnlyMemory<byte> parameters, BaseMemoryPool pool)
    {
        byte[] input = new byte[sizeof(uint) + nameOctets.Length + parameters.Length];
        BinaryPrimitives.WriteUInt32BigEndian(input, (uint)commandCode);
        nameOctets.Span.CopyTo(input.AsSpan(sizeof(uint)));
        parameters.Span.CopyTo(input.AsSpan(sizeof(uint) + nameOctets.Length));

        return await TpmInHouseSimulatorZeroHandleSessionTests.HashSha256Async(input, pool, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Builds one <c>TPMS_AUTH_COMMAND</c> block over <paramref name="session"/>, its command HMAC computed on
    /// the cpHash a ONE-handle no-authorization command owns: the command code folded with the handle's Name
    /// term and the parameter area (TPM 2.0 Library Part 1, clause 15.7, equation 15).
    /// </summary>
    /// <param name="session">The authorizing session, whose caller nonce this rolls.</param>
    /// <param name="commandCode">The command the HMAC commits to.</param>
    /// <param name="nameOctets">The addressed handle's Name term, empty when it contributes nothing (e.g. an unresolved handle, whose refusal never reaches HMAC verification at all).</param>
    /// <param name="parameters">The parameter area the HMAC commits to.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The block's octets, without the authorizationSize field that precedes them.</returns>
    internal async Task<byte[]> BuildSessionAuthAreaOverHandleAsync(TpmSession session, TpmCcConstants commandCode, ReadOnlyMemory<byte> nameOctets, byte[] parameters, BaseMemoryPool pool)
    {
        byte[] cpHashInput = new byte[sizeof(uint) + nameOctets.Length + parameters.Length];
        BinaryPrimitives.WriteUInt32BigEndian(cpHashInput, (uint)commandCode);
        nameOctets.Span.CopyTo(cpHashInput.AsSpan(sizeof(uint)));
        parameters.CopyTo(cpHashInput.AsSpan(sizeof(uint) + nameOctets.Length));

        byte[] cpHash = await TpmInHouseSimulatorZeroHandleSessionTests.HashSha256Async(cpHashInput, pool, TestContext.CancellationToken).ConfigureAwait(false);

        session.RollNonceCaller(pool);
        using Tpm2bAuth? hmac = await session.PrepareAuthHmacAsync(cpHash, pool, TestContext.CancellationToken).ConfigureAwait(false);

        int blockSize = session.GetAuthCommandSize();
        using IMemoryOwner<byte> blockOwner = pool.Rent(blockSize);
        Memory<byte> block = blockOwner.Memory[..blockSize];
        var writer = new TpmWriter(block.Span);
        session.WriteAuthCommand(ref writer, hmac);

        return block.Span.ToArray();
    }

    /// <summary>
    /// Frames a <c>TPM_ST_SESSIONS</c> command carrying ONE handle ahead of its authorization area — the shape
    /// every handle-bearing no-authorization command wants (TPM 2.0 Library Part 3, clause 4.3) — and submits it
    /// straight to the simulator.
    /// </summary>
    /// <param name="simulator">The simulator under test.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="commandCode">The command code written into the header.</param>
    /// <param name="handle">The single handle value.</param>
    /// <param name="authArea">The authorization block, preceded here by its own authorizationSize.</param>
    /// <param name="parameters">The parameter area.</param>
    /// <returns>The response code, still carrying any session-index encoding, and the full raw response.</returns>
    internal async Task<(TpmRcConstants Code, byte[] Response)> SubmitOverHandleAsync(
        TpmSimulator simulator, BaseMemoryPool pool, TpmCcConstants commandCode, uint handle, ReadOnlyMemory<byte> authArea, ReadOnlyMemory<byte> parameters)
    {
        int length = TpmHeader.HeaderSize + sizeof(uint) + sizeof(uint) + authArea.Length + parameters.Length;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        Memory<byte> command = owner.Memory[..length];

        var writer = new TpmWriter(command.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)length, (uint)commandCode);
        header.WriteTo(ref writer);
        writer.WriteUInt32(handle);
        writer.WriteUInt32((uint)authArea.Length);
        writer.WriteBytes(authArea.Span);
        writer.WriteBytes(parameters.Span);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(command, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The simulator must answer a refused command rather than fault.");

        using TpmResponse response = result.Value;
        byte[] responseBytes = response.AsReadOnlySpan().ToArray();
        var reader = new TpmReader(response.AsReadOnlySpan());

        return ((TpmRcConstants)TpmHeader.Parse(ref reader).Code, responseBytes);
    }

    /// <summary>
    /// Frames a <c>TPM_ST_NO_SESSIONS</c> command carrying ONE handle and no authorization area — the plain form
    /// of every handle-bearing no-authorization command (TPM 2.0 Library Part 3, clause 4.3) — and submits it
    /// straight to the simulator.
    /// </summary>
    /// <param name="simulator">The simulator under test.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="commandCode">The command code written into the header.</param>
    /// <param name="handle">The single handle value.</param>
    /// <param name="parameters">The parameter area.</param>
    /// <returns>The response code and the full raw response.</returns>
    internal async Task<(TpmRcConstants Code, byte[] Response)> SubmitPlainOverHandleAsync(
        TpmSimulator simulator, BaseMemoryPool pool, TpmCcConstants commandCode, uint handle, ReadOnlyMemory<byte> parameters)
    {
        int length = TpmHeader.HeaderSize + sizeof(uint) + parameters.Length;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        Memory<byte> command = owner.Memory[..length];

        var writer = new TpmWriter(command.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)commandCode);
        header.WriteTo(ref writer);
        writer.WriteUInt32(handle);
        writer.WriteBytes(parameters.Span);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(command, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The simulator must answer a refused command rather than fault.");

        using TpmResponse response = result.Value;
        byte[] responseBytes = response.AsReadOnlySpan().ToArray();
        var reader = new TpmReader(response.AsReadOnlySpan());

        return ((TpmRcConstants)TpmHeader.Parse(ref reader).Code, responseBytes);
    }

    /// <summary>
    /// Reads back a session's digest through <c>TPM2_GetSessionAuditDigest()</c>'s NULL-signer form, without
    /// asserting success: a session that has never yet completed a command claiming <c>audit</c> is not an audit
    /// session at all and answers <c>TPM_RC_TYPE</c> ("If sessionHandle is not an audit session, the TPM shall
    /// return TPM_RC_TYPE") — the shape a refused first attempt at claiming audit leaves it in, proving the
    /// refusal never established the session as an audit session in the first place.
    /// </summary>
    /// <param name="device">The device to submit through.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="auditHandle">The session's handle.</param>
    /// <returns>The response code, and the session digest octets on success (empty otherwise).</returns>
    internal async Task<(TpmRcConstants Code, byte[] Digest)> TryReadNullSignedAuditDigestAsync(TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool, uint auditHandle)
    {
        using GetSessionAuditDigestInput auditDigestInput = GetSessionAuditDigestInput.ForNullSigner(TpmiShHmac.FromValue(auditHandle), ReadOnlySpan<byte>.Empty, pool);
        using TpmPasswordSession endorsementForDigest = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession nullSignerSlot = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<GetSessionAuditDigestResponse> digestResult = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
            device, auditDigestInput, [endorsementForDigest, nullSignerSlot], handleNames: null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        if(!digestResult.IsSuccess)
        {
            return (digestResult.ResponseCode, []);
        }

        using GetSessionAuditDigestResponse response = digestResult.Value;

        return (TpmRcConstants.TPM_RC_SUCCESS, response.SessionAudit.SessionDigest.AsReadOnlySpan().ToArray());
    }

    /// <summary>
    /// Issues a bare, sessionless <c>TPM2_GetRandom()</c> and returns the drawn octets — used only to compare two
    /// simulator instances' RNG streams, never to prove anything about the no-authorization commands' session
    /// form itself.
    /// </summary>
    /// <param name="simulator">The simulator to draw from.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The drawn octets.</returns>
    private async Task<byte[]> DrawRandomBareAsync(TpmSimulator simulator, BaseMemoryPool pool)
    {
        int length = TpmHeader.HeaderSize + sizeof(ushort);
        using IMemoryOwner<byte> owner = pool.Rent(length);
        Memory<byte> command = owner.Memory[..length];

        var writer = new TpmWriter(command.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)TpmCcConstants.TPM_CC_GetRandom);
        header.WriteTo(ref writer);
        writer.WriteUInt16(RandomDrawLength);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(command, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The transport itself must succeed.");

        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        _ = TpmHeader.Parse(ref reader);
        ushort declaredSize = reader.ReadUInt16();

        return reader.ReadBytes(declaredSize).ToArray();
    }

    /// <summary>
    /// Creates a simulator with the ECC (BouncyCastle) signing backend wired, powers it on, and brings it through
    /// <c>TPM2_Startup(CLEAR)</c> into the operational phase — <c>TPM2_CreatePrimary()</c> needs a signing
    /// backend to answer anything but <c>TPM_RC_COMMAND_CODE</c>, unlike the no-authorization commands' session
    /// form's own fixture, which needs none.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    internal async Task<TpmSimulator> CreateOperationalWithEccBackendAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator("tpm-in-house-no-auth-session-ecc", signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var input = new StartupInput(TpmSuConstants.TPM_SU_CLEAR);
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "TPM2_Startup(CLEAR) must succeed at the transport level.");
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)responseHeader.Code, "TPM2_Startup(CLEAR) must succeed.");

        return simulator;
    }

    /// <summary>
    /// Reads a captured raw response's header tag, independent of whatever the codec parsed it into. Shared with
    /// <see cref="Verifiable.Tests.Tpm.TpmInHouseSimulatorNoAuthSessionReadCommandTests"/>, which extends this
    /// class's own hand-framing fixture rather than re-minting a second copy.
    /// </summary>
    /// <param name="responseBytes">The raw response octets.</param>
    /// <returns>The response tag.</returns>
    internal static ushort ReadResponseTag(byte[] responseBytes)
    {
        var reader = new TpmReader(responseBytes);

        return TpmHeader.Parse(ref reader).Tag;
    }

    /// <summary>
    /// Reads every response-session entry's own <c>sessionAttributes</c> octet out of a captured raw response's
    /// authorization area, walking entry by entry (<c>nonceTPM</c>/<c>sessionAttributes</c>/<c>hmac</c>) until
    /// the buffer is exhausted — independent of whatever the codec parsed the area into. The count of the
    /// returned list is itself the number of response-session entries the wire carries.
    /// </summary>
    /// <param name="responseBytes">The raw response octets.</param>
    /// <param name="outHandleCount">The number of output handles preceding the parameter area.</param>
    /// <returns>Every entry's raw <c>sessionAttributes</c> octet, in wire order.</returns>
    internal static List<byte> ReadResponseSessionEntries(byte[] responseBytes, int outHandleCount)
    {
        var reader = new TpmReader(responseBytes);
        _ = TpmHeader.Parse(ref reader);
        for(int i = 0; i < outHandleCount; i++)
        {
            _ = reader.ReadUInt32();
        }

        uint parameterSize = reader.ReadUInt32();
        _ = reader.ReadBytes((int)parameterSize);

        var entries = new List<byte>();
        while(reader.Remaining > 0)
        {
            ushort nonceLength = reader.ReadUInt16();
            _ = reader.ReadBytes(nonceLength);
            entries.Add(reader.ReadByte());
            ushort hmacLength = reader.ReadUInt16();
            _ = reader.ReadBytes(hmacLength);
        }

        return entries;
    }

    /// <summary>
    /// Draws a bare, sessionless <c>TPM2_GetRandom()</c> from a FRESH, otherwise-identical simulator that first
    /// starts, and then flushes, two unbound HMAC sessions — the same two <c>TPM2_StartAuthSession()</c> calls a
    /// two-companion test issues before its own draw — so the comparison isolates whether the companion-bearing
    /// command itself ran, rather than conflating that with the deterministic RNG octets session establishment
    /// alone already consumes.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The drawn octets.</returns>
    private async Task<byte[]> DrawRandomAfterMatchingSessionStartsAsync(BaseMemoryPool pool)
    {
        using TpmSimulator twin = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice twinDevice = TpmDevice.Create(twin.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry twinRegistry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry();

        (uint firstHandle, TpmSession firstSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(twinDevice, twinRegistry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        (uint secondHandle, TpmSession secondSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(twinDevice, twinRegistry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        firstSession.Dispose();
        secondSession.Dispose();
        await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(twinDevice, twinRegistry, pool, firstHandle).ConfigureAwait(false);
        await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(twinDevice, twinRegistry, pool, secondHandle).ConfigureAwait(false);

        return await DrawRandomBareAsync(twin, pool).ConfigureAwait(false);
    }

    /// <summary>
    /// Reads the response parameter area and ONE session entry — parsed into its own
    /// <see cref="TpmsAuthResponse"/>, the type <see cref="TpmSession.VerifyAndUpdateAsync"/> and
    /// <see cref="TpmSession.DecryptFirstParameterAsync"/> consume directly — out of a captured raw response's
    /// octets, disposing every OTHER entry the wire carries.
    /// </summary>
    /// <param name="responseBytes">The raw response octets, tagged <c>TPM_ST_SESSIONS</c>.</param>
    /// <param name="outHandleCount">The number of output handles preceding the parameter area.</param>
    /// <param name="entryIndex">The zero-based, wire-order position of the entry to keep.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The response parameter octets and the kept entry; the caller disposes the entry.</returns>
    private static (byte[] Parameters, TpmsAuthResponse Entry) ReadResponseParametersAndEntry(byte[] responseBytes, int outHandleCount, int entryIndex, BaseMemoryPool pool)
    {
        var reader = new TpmReader(responseBytes);
        _ = TpmHeader.Parse(ref reader);
        for(int i = 0; i < outHandleCount; i++)
        {
            _ = reader.ReadUInt32();
        }

        uint parameterSize = reader.ReadUInt32();
        byte[] parameters = reader.ReadBytes((int)parameterSize).ToArray();

        TpmsAuthResponse? kept = null;
        int index = 0;
        while(reader.Remaining > 0)
        {
            TpmsAuthResponse entry = TpmsAuthResponse.Parse(ref reader, pool);
            if(index == entryIndex)
            {
                kept = entry;
            }
            else
            {
                entry.Dispose();
            }

            index++;
        }

        if(kept is null)
        {
            throw new InvalidOperationException($"The response carries no session entry at index {entryIndex}.");
        }

        return (parameters, kept);
    }

    /// <summary>
    /// Builds a one-slot authorization block naming <c>TPM_RS_PW</c> with an empty nonce and an empty password —
    /// the password form of <c>TPMS_AUTH_COMMAND</c> (TPM 2.0 Library Part 1, clause 16.6.4.1) — a small per-file
    /// mirror of <see cref="TpmInHouseSimulatorZeroHandleSessionTests"/>'s own private helper of the same shape,
    /// since the production helper is private.
    /// </summary>
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

    /// <summary>
    /// Corrupts one built authorization block's own command HMAC by flipping its trailing octet, in place: the
    /// block's handle, nonce and attributes stay exactly as negotiated, and only its command HMAC then fails to
    /// verify against the cpHash it was built over.
    /// </summary>
    /// <param name="block">The block to corrupt, in place.</param>
    /// <returns>The same array, for inline chaining.</returns>
    private static byte[] WithCorruptedHmac(byte[] block)
    {
        block[^1] ^= 0xFF;

        return block;
    }
}
