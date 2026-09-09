using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
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
/// The pool-accounting proofs for a session's retained nonceTPM (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2,
/// clause 10.3.4, Table 92), which every session record owns for the session's whole life and replaces wholesale
/// once per command response (Part 1, clause 16.6.5). Each proof drives the real wire through the production
/// command path and reads real pool telemetry (<see cref="MeteredHousePool"/>), never an internal hook.
/// </summary>
/// <remarks>
/// An unbound, unsalted session is the isolating fixture: its session key is the shared Empty-Buffer carrier and
/// its bound-entity value is the shared unbound sentinel (Part 1, clause 16.6.9 — no <c>KDFa</c> runs at all), so
/// neither rents anything and the retained nonceTPM is the ONLY rental such a session holds. A balance taken over
/// it therefore counts nonce carriers and nothing else.
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorSessionNonceCarrierTests
{
    /// <summary>The session hash algorithm every session here is started with.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The number of random octets each rolling command asks for.</summary>
    private const ushort RandomByteCount = 32;

    /// <summary>The SHA-256 digest width in octets — the width of every policy digest and Name these tests build.</summary>
    private const int Sha256DigestSize = 32;

    /// <summary>The declared data area size of the Index the policy-session roll proof defines.</summary>
    private const ushort IndexDataSize = 8;

    /// <summary>An NV Index handle from this class's assigned block, used only as a Table-57-out-of-range probe — never defined.</summary>
    private const uint NvBlockHandle = 0x0100_02C0;

    /// <summary>The attribute set the policy-session roll proof's Index is defined with — caller-authorized and dictionary-attack exempt.</summary>
    private const TpmaNv OrdinaryIndexAttributes = TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_NO_DA;

    /// <summary>The authorization value the policy-session roll proof's Index is defined with.</summary>
    private static byte[] DefinedIndexAuth { get; } = [0x0A, 0x0B, 0x0C, 0x0D];

    /// <summary>The replacement authorization value the policy-session roll proof rotates to, deliberately a different width.</summary>
    private static byte[] RotatedIndexAuth { get; } = [0x1A, 0x1B, 0x1C, 0x1D, 0x1E];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// A started unbound, unsalted HMAC session holds EXACTLY ONE pooled rental — its retained nonceTPM — and
    /// <c>TPM2_FlushContext()</c> returns it: the balance rises by exactly one over the start and falls back to
    /// the pre-start baseline once the session leaves the table (TPM 2.0 Library Part 3, clause 28.4; Part 1,
    /// clause 16.6.5 for the nonce the session retains).
    /// </summary>
    [TestMethod]
    public async Task FlushContextReturnsAnHmacSessionsRetainedNonceCarrierToPool()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-nonce-flush-hmac").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        long baseline = trackingPool.OutstandingCount;

        uint sessionHandle = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        Assert.AreEqual(
            baseline + 1, trackingPool.OutstandingCount,
            "An unbound, unsalted session's session key and bound-entity value are the shared dispose-immune sentinels, so its retained nonceTPM is the single rental the start leaves outstanding.");

        TpmResult<FlushContextResponse> flushResult = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(flushResult.IsSuccess, $"FlushContext failed: '{flushResult.ResponseCode}'.");

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "Flushing the session must return the retained nonceTPM carrier to the pool.");
    }

    /// <summary>
    /// A started unbound, unsalted POLICY session likewise holds exactly its retained nonceTPM, and
    /// <c>TPM2_FlushContext()</c> returns it — the policy-table counterpart of
    /// <see cref="FlushContextReturnsAnHmacSessionsRetainedNonceCarrierToPool"/>. The nonce is the real
    /// per-session value, never a placeholder, because <c>TPM2_PolicySigned()</c>'s <c>aHash</c> binds to it
    /// (TPM 2.0 Library Part 3, clause 23.3).
    /// </summary>
    [TestMethod]
    public async Task FlushContextReturnsAPolicySessionsRetainedNonceCarrierToPool()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-nonce-flush-policy").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        long baseline = trackingPool.OutstandingCount;

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedPolicySession(SessionAlg, TestEntropy.NewCounterStream(), pool);
        uint sessionHandle;
        {
            TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
                tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse startResponse = startResult.Value;
            sessionHandle = startResponse.SessionHandle.Value;
        }

        Assert.AreEqual(
            baseline + 1, trackingPool.OutstandingCount,
            "A policy session's retained nonceTPM is the single rental an unbound, unsalted start leaves outstanding.");

        TpmResult<FlushContextResponse> flushResult = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(flushResult.IsSuccess, $"FlushContext failed: '{flushResult.ResponseCode}'.");

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "Flushing the policy session must return the retained nonceTPM carrier to the pool.");
    }

    /// <summary>
    /// Two live sessions hold two DISTINCT nonce carriers: the balance rises by exactly one per start and falls
    /// by exactly one per flush, so no session shares another's carrier and none is left behind (TPM 2.0 Library
    /// Part 1, clause 16.6.5 — the nonce is per session).
    /// </summary>
    [TestMethod]
    public async Task EachStartedSessionHoldsItsOwnRetainedNonceCarrier()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-nonce-two-sessions").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        long baseline = trackingPool.OutstandingCount;

        uint firstHandle = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        uint secondHandle = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        Assert.AreNotEqual(firstHandle, secondHandle, "The two starts must allocate distinct session handles for the accounting below to be about two sessions.");
        Assert.AreEqual(
            baseline + 2, trackingPool.OutstandingCount,
            "Each session owns its own retained nonceTPM carrier, so two live sessions hold two rentals.");

        TpmResult<FlushContextResponse> firstFlush = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(firstHandle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(firstFlush.IsSuccess, $"FlushContext failed: '{firstFlush.ResponseCode}'.");
        Assert.AreEqual(
            baseline + 1, trackingPool.OutstandingCount,
            "Flushing one session must return that session's carrier alone — the surviving session's own carrier is a different instance.");

        TpmResult<FlushContextResponse> secondFlush = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(secondHandle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(secondFlush.IsSuccess, $"FlushContext failed: '{secondFlush.ResponseCode}'.");
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "Flushing the surviving session must bring the pool back to the pre-session baseline.");
    }

    /// <summary>
    /// Table 57 (<c>TPMI_DH_CONTEXT</c>, TPM 2.0 Library Part 2, clause 9.11) admits only the HMAC-session,
    /// policy-session and transient ranges; anything else is <c>#TPM_RC_VALUE</c>. <c>flushHandle</c> unmarshals
    /// as <c>TPMI_DH_CONTEXT</c> exactly as <c>TPM2_ContextSave()</c>'s own handle does, so an out-of-range value
    /// is refused at parse rather than falling through to the generic <c>TPM_RC_HANDLE</c> every table-miss
    /// answers.
    /// </summary>
    [TestMethod]
    public async Task FlushContextWithAnOutOfRangeHandleReturnsValue()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-flush-out-of-range").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<FlushContextResponse> flushResult = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(0xFFFFFFFF), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), flushResult.ResponseCode,
            $"Table 228: flushHandle is TPM2_FlushContext()'s sole parameter (index 0), a use of a handle as a " +
            $"parameter; one outside Table 57's HMAC-session, policy-session and transient ranges must be " +
            $"refused at parse with parameter-encoded TPM_RC_VALUE (got '{flushResult.ResponseCode}').");
    }

    /// <summary>
    /// TPM 2.0 Library Part 3, clause 28.4.1: "When flushing a session, the upper byte of the handle is
    /// ignored" — general to a session, not scoped to a saved one (Part 4's <c>TPM2_FlushContext()</c>
    /// implementation resolves the HMAC-session and policy-session handle types through one shared arm). A
    /// loaded POLICY session flushed under
    /// the HMAC top byte at the same index succeeds and is actually removed — a second flush of the session's
    /// own (policy) handle then answers <c>TPM_RC_HANDLE</c>.
    /// </summary>
    [TestMethod]
    public async Task FlushContextOfALoadedPolicySessionUnderTheHmacTopByteSucceedsAndRemovesIt()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-flush-cross-policy").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, StartAuthSessionInput.CreateUnboundUnsaltedPolicySession(SessionAlg, TestEntropy.NewCounterStream(), pool), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");

        using StartAuthSessionResponse started = startResult.Value;
        uint policyHandle = started.SessionHandle.Value;
        uint index = TpmHandleRanges.GetHandleIndex(policyHandle);
        uint crossHandle = TpmHandleRanges.HMAC_SESSION_FIRST + index;

        TpmResult<FlushContextResponse> crossFlushResult = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(crossHandle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            crossFlushResult.IsSuccess,
            $"A loaded policy session flushed under the HMAC top byte at the same index must succeed (got '{crossFlushResult.ResponseCode}').");

        TpmResult<FlushContextResponse> secondFlushResult = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(policyHandle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), secondFlushResult.ResponseCode,
            "The policy session must actually be gone: flushing its own handle again must answer TPM_RC_HANDLE.");
    }

    /// <summary>
    /// The HMAC-session counterpart of
    /// <see cref="FlushContextOfALoadedPolicySessionUnderTheHmacTopByteSucceedsAndRemovesIt"/>: a loaded HMAC
    /// session flushed under the policy top byte at the same index succeeds and is actually removed.
    /// </summary>
    [TestMethod]
    public async Task FlushContextOfALoadedHmacSessionUnderThePolicyTopByteSucceedsAndRemovesIt()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-flush-cross-hmac").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        uint hmacHandle = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        uint index = TpmHandleRanges.GetHandleIndex(hmacHandle);
        uint crossHandle = TpmHandleRanges.POLICY_SESSION_FIRST + index;

        TpmResult<FlushContextResponse> crossFlushResult = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(crossHandle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            crossFlushResult.IsSuccess,
            $"A loaded HMAC session flushed under the policy top byte at the same index must succeed (got '{crossFlushResult.ResponseCode}').");

        TpmResult<FlushContextResponse> secondFlushResult = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(hmacHandle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), secondFlushResult.ResponseCode,
            "The HMAC session must actually be gone: flushing its own handle again must answer TPM_RC_HANDLE.");
    }

    /// <summary>
    /// The nonceTPM ROLL replaces the retained carrier rather than accumulating one per command: three
    /// encrypt-attributed <c>TPM2_GetRandom()</c> commands over one session leave the pool balance exactly where
    /// the first one did, proving the roll releases the superseded carrier as the replacement lands (TPM 2.0
    /// Library Part 1, clause 16.6.5).
    /// </summary>
    /// <remarks>
    /// The measurement starts AFTER the first command so that the balance being compared is the session's steady
    /// state: the host <see cref="TpmSession"/> adopts each response's nonce carrier and releases the one it
    /// held, so both sides of the wire hold exactly one nonce rental per session at every instant, and a roll
    /// that failed to release the superseded carrier would show up as a monotonically growing balance.
    /// </remarks>
    [TestMethod]
    public async Task RollingASessionNonceHoldsExactlyOneCarrierAcrossCommands()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-nonce-roll").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmtSymDef symmetric = TpmtSymDef.Xor(SessionAlg);

        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(SessionAlg), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary failed: '{primaryResult.ResponseCode}'.");

        using CreatePrimaryResponse primary = primaryResult.Value;
        uint objectHandle = primary.ObjectHandle.Value;

        try
        {
            StartAuthSessionInput startInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession(objectHandle, SessionAlg, TestEntropy.NewCounterStream(), pool, symmetric);

            TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
                tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (bound) failed: '{startResult.ResponseCode}'.");

            //The response's nonceTPM carrier transfers into the host session below, which releases it when the
            //session is disposed; the simulator keeps its own carrier for the durable session record.
            StartAuthSessionResponse startResponse = startResult.Value;
            uint sessionHandle = startResponse.SessionHandle.Value;

            try
            {
                using Tpm2bAuth bindAuth = Tpm2bAuth.CreateEmpty(pool);
                using var session = await TpmSession.CreateBoundAsync(
                    new TpmHandle(sessionHandle), bindAuth.AsReadOnlyMemory(), startInput.NonceCaller, startResponse.NonceTPM,
                    SessionAlg, TestEntropy.NewCounterStream(), pool, symmetric: symmetric, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                long beforeAnyCommand = trackingPool.OutstandingCount;
                await DrawRandomAsync(session).ConfigureAwait(false);

                long steady = trackingPool.OutstandingCount;
                Assert.AreEqual(
                    beforeAnyCommand, steady,
                    "A completed command leaves the pool exactly where it found it: each side of the wire replaces its one nonce carrier rather than adding another.");

                await DrawRandomAsync(session).ConfigureAwait(false);
                Assert.AreEqual(
                    steady, trackingPool.OutstandingCount,
                    "The second command's nonce roll must release the superseded carrier, so the balance may not grow.");

                await DrawRandomAsync(session).ConfigureAwait(false);
                Assert.AreEqual(
                    steady, trackingPool.OutstandingCount,
                    "The third command's nonce roll must likewise release the superseded carrier: the balance is flat however many commands the session serves.");
            }
            finally
            {
                _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                    tpm, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(objectHandle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        }

        async Task DrawRandomAsync(TpmSession session)
        {
            var getRandomInput = new GetRandomInput(RandomByteCount);

            TpmResult<GetRandomResponse> randomResult = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                tpm, getRandomInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(randomResult.IsSuccess, $"Encrypted GetRandom over the bound session failed: '{randomResult.ResponseCode}'.");

            using GetRandomResponse randomResponse = randomResult.Value;
            Assert.AreEqual(RandomByteCount, randomResponse.RandomBytes.Size, "Parameter encryption must not change the parameter length.");
        }
    }

    /// <summary>
    /// A POLICY session's nonceTPM roll likewise replaces the retained carrier rather than accumulating one:
    /// a <c>TPM2_NV_ChangeAuth()</c> authorized by a policy session — the ADMIN-role shape Part 3, clause
    /// 31.15.1 demands — rolls that session's nonce as part of the success-only policy-context reset (Part 3,
    /// clause 23.2.4; Part 1, clause 16.6.5), and the pool balance returns to where it stood before the
    /// rotation once the session is flushed.
    /// </summary>
    /// <remarks>
    /// The policy asserts <c>TPM2_PolicyCommandCode(TPM_CC_NV_ChangeAuth)</c> and nothing else, which is the
    /// minimal shape the ADMIN gate accepts, so no authValue is folded anywhere and the only rentals crossing
    /// the measured window are the command's own and the session's retained nonce.
    /// </remarks>
    [TestMethod]
    public async Task RollingAPolicySessionNonceReleasesTheSupersededCarrier()
    {
        const uint IndexHandle = 0x0100_0031;

        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-nonce-policy-roll").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_ChangeAuth, TpmResponseCodec.NvChangeAuth);

        byte[] rotationPolicy = await ComputeCommandCodeOnlyRotationPolicyAsync(pool).ConfigureAwait(false);
        byte[] indexName = await DefineOrdinaryIndexAsync(tpm, pool, registry, IndexHandle, rotationPolicy).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, StartAuthSessionInput.CreateUnboundUnsaltedPolicySession(SessionAlg, TestEntropy.NewCounterStream(), pool), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession session = new(new TpmHandle(sessionHandle), started.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), pool);

            TpmResult<PolicyCommandCodeResponse> commandCodeResult = await tpm.PolicyCommandCodeAsync(
                sessionHandle, TpmCcConstants.TPM_CC_NV_ChangeAuth, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(commandCodeResult.IsSuccess, $"PolicyCommandCodeAsync failed: '{commandCodeResult.ResponseCode}'.");

            using Tpm2bAuth newAuth = Tpm2bAuth.Create(RotatedIndexAuth, pool);
            using NvChangeAuthInput input = new(IndexHandle, newAuth);

            TpmResult<NvChangeAuthResponse> rotationResult = await TpmCommandExecutor.ExecuteAsync<NvChangeAuthResponse>(
                tpm, input, [session], [indexName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(rotationResult.IsSuccess, $"NV_ChangeAuth over a command-code-only policy session failed: '{rotationResult.ResponseCode}'.");
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        }

        //The rotated authValue is now the Index's own carrier, superseding the one the definition installed, so
        //the durable side of the ledger is unchanged and every command-scoped rental — the policy session's
        //original nonce, the nonce the reset rolled it to, and the response entry's own copy — has been released.
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The policy session's context reset must release the nonce carrier it supersedes, and flushing the session must release the one it rolled to.");
    }

    /// <summary>
    /// Part 2, clause 9.11, Table 57 (<c>TPMI_DH_CONTEXT</c>): the only admitted values are the HMAC-session,
    /// policy-session and transient-object ranges, "#TPM_RC_VALUE" on anything else — an NV Index handle, a
    /// permanent handle and a persistent-object handle are all outside those three ranges, so the
    /// <c>TPMI_DH_CONTEXT</c> unmarshal refuses every one of them at parse, before any table lookup runs.
    /// </summary>
    /// <param name="flushHandle">A handle outside Table 57's three admitted ranges.</param>
    [TestMethod]
    [DataRow(NvBlockHandle, DisplayName = "an NV Index handle")]
    [DataRow((uint)TpmRh.TPM_RH_OWNER, DisplayName = "a permanent handle")]
    [DataRow(TpmHandleRanges.PERSISTENT_FIRST, DisplayName = "a persistent-object handle")]
    public async Task FlushContextWithAHandleOutsideTable57sThreeRangesReturnsValue(uint flushHandle)
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-flush-outside-table57").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<FlushContextResponse> flushResult = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(flushHandle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), flushResult.ResponseCode,
            $"Table 228: flushHandle is TPM2_FlushContext()'s sole parameter (index 0), a use of a handle as a parameter; " +
            $"0x{flushHandle:X8}, outside Table 57's HMAC-session, policy-session and transient ranges, must be refused with parameter-encoded TPM_RC_VALUE at parse (got '{flushResult.ResponseCode}').");
    }

    /// <summary>
    /// The invariant counterpart of <see cref="FlushContextWithAHandleOutsideTable57sThreeRangesReturnsValue"/>:
    /// a handle INSIDE the transient-object range (TPM 2.0 Library Part 2, clause 9.11, Table 57) still passes
    /// <c>TpmiDhContext.Parse</c>, so a range that admits no loaded object falls through every resource table to
    /// the generic <c>TPM_RC_HANDLE</c> — Table 57's admission and a live table entry are independent gates.
    /// </summary>
    [TestMethod]
    public async Task FlushContextOfAnUnresolvedTransientHandleReturnsHandle()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-flush-unresolved-transient").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<FlushContextResponse> flushResult = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(TpmHandleRanges.TRANSIENT_FIRST), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), flushResult.ResponseCode,
            $"A transient-range handle naming no loaded object must be refused with the generic TPM_RC_HANDLE, never TPM_RC_VALUE (got '{flushResult.ResponseCode}').");
    }

    /// <summary>
    /// TPM 2.0 Library Part 3, clause 28.4.1: "A session does not have to be loaded in TPM memory to have its
    /// context flushed. The saved session context associated with the indicated handle is invalidated... the
    /// upper byte of the handle is ignored." A saved (not loaded) HMAC session's blob is flushed by presenting
    /// the SAME index under the policy top byte and succeeds, and the load-once tracking entry it removes makes
    /// the ORIGINAL blob unloadable henceforth: a following <c>TPM2_ContextLoad()</c> of that exact blob answers
    /// <c>TPM_RC_HANDLE</c> (TPM 2.0 Library Part 1, clause 27.5's "a saved session context may only be loaded once").
    /// </summary>
    [TestMethod]
    public async Task FlushContextOfASavedSessionUnderTheCrossTypeTopByteSucceedsAndItsContextLoadReturnsHandle()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-flush-saved-cross-type").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_ContextSave, TpmResponseCodec.ContextSave);
        _ = registry.Register(TpmCcConstants.TPM_CC_ContextLoad, TpmResponseCodec.ContextLoad);

        uint hmacHandle = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<ContextSaveResponse> saveResult = await TpmCommandExecutor.ExecuteAsync<ContextSaveResponse>(
            tpm, ContextSaveInput.ForHandle(hmacHandle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(saveResult.IsSuccess, $"ContextSave of the HMAC session failed: '{saveResult.ResponseCode}'.");
        using ContextSaveResponse saved = saveResult.Value;

        uint index = TpmHandleRanges.GetHandleIndex(hmacHandle);
        uint crossHandle = TpmHandleRanges.POLICY_SESSION_FIRST + index;

        TpmResult<FlushContextResponse> crossFlushResult = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(crossHandle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            crossFlushResult.IsSuccess,
            $"A saved session flushed under the other top byte at the same index must succeed (got '{crossFlushResult.ResponseCode}').");

        var loadInput = new ContextLoadInput(saved.Context);
        TpmResult<ContextLoadResponse> loadResult = await TpmCommandExecutor.ExecuteAsync<ContextLoadResponse>(
            tpm, loadInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), loadResult.ResponseCode,
            $"ContextLoad of a blob whose saved-session tracking entry the cross-type flush already removed must answer TPM_RC_HANDLE, not reload it (got '{loadResult.ResponseCode}').");
    }

    /// <summary>
    /// With a loaded POLICY session and a loaded HMAC session occupying the SAME index at once — this
    /// simulator's independent HMAC and policy counters admit that, unlike the reference's one shared array —
    /// flushing the HMAC top byte resolves the handle's OWN presented range first (TPM 2.0 Library Part 4's
    /// <c>TPM2_FlushContext()</c> implementation shares one arm for both session handle types; this simulator
    /// resolves its own type first): the HMAC session is removed and the co-located policy session is left
    /// untouched.
    /// </summary>
    [TestMethod]
    public async Task FlushContextWithBothSessionKindsAtTheSameIndexUnderTheHmacTopByteFlushesOnlyTheHmacSession()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-flush-both-kinds-hmac-first").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        uint policyHandle = await StartUnboundPolicySessionAsync(tpm, registry, pool).ConfigureAwait(false);
        uint hmacHandle = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        Assert.AreEqual(
            TpmHandleRanges.GetHandleIndex(policyHandle), TpmHandleRanges.GetHandleIndex(hmacHandle),
            "The two sessions must land at the same index for this proof to be about co-located sessions.");

        TpmResult<FlushContextResponse> hmacFlush = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(hmacHandle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            hmacFlush.IsSuccess,
            $"Flushing the HMAC top byte must succeed: '{(hmacFlush.IsSuccess ? TpmRcConstants.TPM_RC_SUCCESS : hmacFlush.ResponseCode)}'.");

        //Proves the co-located policy session survived the HMAC-top-byte flush untouched: had it been removed
        //instead, this own-type flush of its OWN handle would answer TPM_RC_HANDLE rather than succeed.
        TpmResult<FlushContextResponse> policyStillPresentFlush = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(policyHandle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            policyStillPresentFlush.IsSuccess,
            $"The co-located policy session must have survived the HMAC-top-byte flush untouched (got '{(policyStillPresentFlush.IsSuccess ? TpmRcConstants.TPM_RC_SUCCESS : policyStillPresentFlush.ResponseCode)}').");

        //With both tables now empty at this index, a further flush of either handle falls through every table
        //(no own-type match, no cross-type fallback left to find) to the generic TPM_RC_HANDLE — proving the
        //first flush genuinely removed the HMAC session rather than merely leaving it unreachable.
        TpmResult<FlushContextResponse> bothGoneCheck = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(hmacHandle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), bothGoneCheck.ResponseCode, "Both co-located sessions must be gone once the survivor is also flushed.");
    }

    /// <summary>
    /// The mirror of <see cref="FlushContextWithBothSessionKindsAtTheSameIndexUnderTheHmacTopByteFlushesOnlyTheHmacSession"/>:
    /// flushing the POLICY top byte at a shared index removes the co-located policy session and leaves the HMAC
    /// session at the same index untouched.
    /// </summary>
    [TestMethod]
    public async Task FlushContextWithBothSessionKindsAtTheSameIndexUnderThePolicyTopByteFlushesOnlyThePolicySession()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-flush-both-kinds-policy-first").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        uint policyHandle = await StartUnboundPolicySessionAsync(tpm, registry, pool).ConfigureAwait(false);
        uint hmacHandle = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        Assert.AreEqual(
            TpmHandleRanges.GetHandleIndex(policyHandle), TpmHandleRanges.GetHandleIndex(hmacHandle),
            "The two sessions must land at the same index for this proof to be about co-located sessions.");

        TpmResult<FlushContextResponse> policyFlush = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(policyHandle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            policyFlush.IsSuccess,
            $"Flushing the policy top byte must succeed: '{(policyFlush.IsSuccess ? TpmRcConstants.TPM_RC_SUCCESS : policyFlush.ResponseCode)}'.");

        //Proves the co-located HMAC session survived the policy-top-byte flush untouched: had it been removed
        //instead, this own-type flush of its OWN handle would answer TPM_RC_HANDLE rather than succeed.
        TpmResult<FlushContextResponse> hmacStillPresentFlush = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(hmacHandle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            hmacStillPresentFlush.IsSuccess,
            $"The co-located HMAC session must have survived the policy-top-byte flush untouched (got '{(hmacStillPresentFlush.IsSuccess ? TpmRcConstants.TPM_RC_SUCCESS : hmacStillPresentFlush.ResponseCode)}').");

        //With both tables now empty at this index, a further flush of either handle falls through to the
        //generic TPM_RC_HANDLE — proving the first flush genuinely removed the policy session.
        TpmResult<FlushContextResponse> bothGoneCheck = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(policyHandle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), bothGoneCheck.ResponseCode, "Both co-located sessions must be gone once the survivor is also flushed.");
    }

    /// <summary>
    /// A parse-time <c>TPM_RC_VALUE</c> refusal (Table 57's range gate) rents nothing that survives the refusal:
    /// the pool balance after a refused <c>TPM2_FlushContext()</c> equals the balance before it.
    /// </summary>
    [TestMethod]
    public async Task FlushContextParseRefusalLeavesNoPoolResidue()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-flush-parse-refusal-pool").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        long baseline = trackingPool.OutstandingCount;

        TpmResult<FlushContextResponse> flushResult = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle((uint)TpmRh.TPM_RH_OWNER), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), flushResult.ResponseCode,
            "Table 228: flushHandle is TPM2_FlushContext()'s sole parameter (index 0); the seeding refusal must be the parse-time parameter-encoded TPM_RC_VALUE.");

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A refusal at TpmiDhContext.Parse must leave the pool exactly where it found it.");
    }

    /// <summary>
    /// "No sessions of any type are allowed with this command and tag is required to be TPM_ST_NO_SESSIONS"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part
    /// 3, clause 28.4.1</see>): a hand-framed <c>TPM2_FlushContext()</c> whose body is a well-formed LOADED
    /// session's own handle, tagged <c>TPM_ST_SESSIONS</c> instead of the required <c>TPM_ST_NO_SESSIONS</c>, is
    /// refused the format-zero <c>TPM_RC_BAD_TAG</c> before the handle is even read — the session stays loaded (a
    /// following, correctly-tagged flush of the SAME handle still succeeds), and the refusal itself leaves no
    /// pool residue, mirroring <see cref="FlushContextParseRefusalLeavesNoPoolResidue"/> and
    /// <c>TpmInHouseSimulatorContextSaveTests.ContextSaveWithSessionsTagIsRefusedWithBadTag</c>'s own proof for
    /// the sibling command.
    /// </summary>
    [TestMethod]
    public async Task FlushContextUnderTpmStSessionsReturnsBadTag()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-flush-sessions-tag-bad-tag").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        long beforeSession = trackingPool.OutstandingCount;
        uint sessionHandle = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        long baseline = trackingPool.OutstandingCount;

        TpmRcConstants responseCode = await SubmitFlushContextFramedAsync(
            simulator, pool, (ushort)TpmStConstants.TPM_ST_SESSIONS, sessionHandle).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_BAD_TAG, responseCode,
            "TPM2_FlushContext() requires tag TPM_ST_NO_SESSIONS; a TPM_ST_SESSIONS arrival must be refused with the format-zero TPM_RC_BAD_TAG before the handle is even read.");
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The parse-time BAD_TAG refusal must leave the pool exactly where it found it.");

        TpmResult<FlushContextResponse> realFlush = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            realFlush.IsSuccess,
            $"The session must still be loaded after the BAD_TAG refusal: a correctly-tagged flush of the same handle must succeed (got '{realFlush.ResponseCode}').");

        Assert.AreEqual(
            beforeSession, trackingPool.OutstandingCount,
            "Once the session is actually flushed, the pool must return to its pre-session baseline.");
    }

    /// <summary>
    /// Hand-frames a complete <c>TPM2_FlushContext()</c> command — header under the caller-chosen
    /// <paramref name="tag"/>, then the raw four-octet <c>flushHandle</c> body — and submits it directly to the
    /// simulator, mirroring <c>TpmInHouseSimulatorContextSaveTests.SubmitContextSaveFramedAsync</c>'s framing for
    /// the sibling command; no shared framing helper covers <c>TPM2_FlushContext()</c> itself.
    /// </summary>
    /// <param name="simulator">The simulator to submit against.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="tag">The command tag to frame under.</param>
    /// <param name="flushHandle">The handle to place in the body.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitFlushContextFramedAsync(TpmSimulator simulator, BaseMemoryPool pool, ushort tag, uint flushHandle)
    {
        byte[] body = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(body, flushHandle);

        int length = TpmHeader.HeaderSize + body.Length;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader(tag, (uint)length, (uint)TpmCcConstants.TPM_CC_FlushContext);
        header.WriteTo(ref writer);
        writer.WriteBytes(body);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        if(result.IsSuccess)
        {
            using TpmResponse response = result.Value;
            var reader = new TpmReader(response.AsReadOnlySpan());

            return (TpmRcConstants)TpmHeader.Parse(ref reader).Code;
        }

        return result.ResponseCode;
    }

    /// <summary>Starts an unbound, unsalted POLICY session and returns its handle, releasing the response's own nonce carrier before returning.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The started session's handle.</returns>
    private async Task<uint> StartUnboundPolicySessionAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedPolicySession(SessionAlg, TestEntropy.NewCounterStream(), pool);

        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");

        using StartAuthSessionResponse startResponse = startResult.Value;

        return startResponse.SessionHandle.Value;
    }

    /// <summary>
    /// Computes the policy digest of a policy asserting <c>TPM2_PolicyCommandCode(TPM_CC_NV_ChangeAuth)</c> and
    /// nothing else — <c>H(0…0 ‖ TPM_CC_PolicyCommandCode ‖ TPM_CC_NV_ChangeAuth)</c> (TPM 2.0 Library Part 3,
    /// clause 23.11).
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The policy digest under <see cref="SessionAlg"/>.</returns>
    private async Task<byte[]> ComputeCommandCodeOnlyRotationPolicyAsync(BaseMemoryPool pool)
    {
        byte[] commandCodeInput = new byte[Sha256DigestSize + sizeof(uint) + sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(commandCodeInput.AsSpan(Sha256DigestSize), (uint)TpmCcConstants.TPM_CC_PolicyCommandCode);
        BinaryPrimitives.WriteUInt32BigEndian(commandCodeInput.AsSpan(Sha256DigestSize + sizeof(uint)), (uint)TpmCcConstants.TPM_CC_NV_ChangeAuth);

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            commandCodeInput, Sha256DigestSize, CryptoTags.Sha256Digest, pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        return digest.AsReadOnlySpan().ToArray();
    }

    /// <summary>
    /// Defines an ordinary, dictionary-attack-exempt NV Index carrying <paramref name="authPolicy"/>, authorized
    /// by the empty owner authValue, and returns the Index's Name (<c>nameAlg ‖ H(TPMS_NV_PUBLIC)</c>, TPM 2.0
    /// Library Part 1, clause 13, Table 9) computed independently of the simulator so the executor can build cpHash.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry, already carrying the NV_DefineSpace codec.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    /// <param name="authPolicy">The access policy digest to define with.</param>
    /// <returns>The defined Index's Name.</returns>
    private async Task<byte[]> DefineOrdinaryIndexAsync(
        TpmDevice tpm, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> authPolicy)
    {
        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);
        using Tpm2bAuth auth = Tpm2bAuth.Create(DefinedIndexAuth, pool);
        using Tpm2bDigest policyDigest = Tpm2bDigest.Create(authPolicy.Span, pool);
        using TpmsNvPublic publicInfo = new(nvIndex, SessionAlg, OrdinaryIndexAttributes, policyDigest, IndexDataSize);
        using NvDefineSpaceInput input = new(TpmRh.TPM_RH_OWNER, auth, publicInfo);

        TpmResult<NvDefineSpaceResponse> defineResult = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            tpm, input, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"NV_DefineSpace failed: '{defineResult.ResponseCode}'.");

        int publicSize = publicInfo.SerializedSize;
        using IMemoryOwner<byte> marshaled = pool.Rent(publicSize);
        var writer = new TpmWriter(marshaled.Memory.Span[..publicSize]);
        publicInfo.WriteTo(ref writer);

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            marshaled.Memory[..publicSize], Sha256DigestSize, CryptoTags.Sha256Digest, pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        byte[] name = new byte[sizeof(ushort) + Sha256DigestSize];
        BinaryPrimitives.WriteUInt16BigEndian(name, (ushort)SessionAlg);
        digest.AsReadOnlySpan().CopyTo(name.AsSpan(sizeof(ushort)));

        return name;
    }

    /// <summary>Starts an unbound, unsalted HMAC session and returns its handle, releasing the response's own nonce carrier before returning.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The started session's handle.</returns>
    private async Task<uint> StartUnboundHmacSessionAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg, TestEntropy.NewCounterStream(), pool);

        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (unbound) failed: '{startResult.ResponseCode}'.");

        using StartAuthSessionResponse startResponse = startResult.Value;

        return startResponse.SessionHandle.Value;
    }

    /// <summary>Builds the response codec registry these tests drive the executor with.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }

    /// <summary>
    /// Creates a simulator with the ECC signing backend wired, powers it on, and brings it through
    /// <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="tpmId">The simulator instance identifier, unique per test so no meter is shared.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool, string tpmId)
    {
        var simulator = new TpmSimulator(tpmId, signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

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

        return simulator;
    }
}
