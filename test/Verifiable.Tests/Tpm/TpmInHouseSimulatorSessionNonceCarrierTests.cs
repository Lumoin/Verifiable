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

namespace Verifiable.Tests.Tpm;

/// <summary>
/// The pool-accounting proofs for a session's retained nonceTPM (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2,
/// clause 10.4.4, Table 94), which every session record owns for the session's whole life and replaces wholesale
/// once per command response (Part 1, clause 17.6.5). Each proof drives the real wire through the production
/// command path and reads real pool telemetry (<see cref="MeteredHousePool"/>), never an internal hook.
/// </summary>
/// <remarks>
/// An unbound, unsalted session is the isolating fixture: its session key is the shared Empty-Buffer carrier and
/// its bound-entity value is the shared unbound sentinel (Part 1, clause 17.6.9 — no <c>KDFa</c> runs at all), so
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
    /// clause 17.6.5 for the nonce the session retains).
    /// </summary>
    [TestMethod]
    public async Task FlushContextReturnsAnHmacSessionsRetainedNonceCarrierToPool()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-nonce-flush-hmac").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
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
    /// (TPM 2.0 Library Part 3, Section 23.3).
    /// </summary>
    [TestMethod]
    public async Task FlushContextReturnsAPolicySessionsRetainedNonceCarrierToPool()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-nonce-flush-policy").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        long baseline = trackingPool.OutstandingCount;

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedPolicySession(SessionAlg);
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
    /// Part 1, clause 17.6.5 — the nonce is per session).
    /// </summary>
    [TestMethod]
    public async Task EachStartedSessionHoldsItsOwnRetainedNonceCarrier()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-nonce-two-sessions").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
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
    /// The nonceTPM ROLL replaces the retained carrier rather than accumulating one per command: three
    /// encrypt-attributed <c>TPM2_GetRandom()</c> commands over one session leave the pool balance exactly where
    /// the first one did, proving the roll releases the superseded carrier as the replacement lands (TPM 2.0
    /// Library Part 1, clause 17.6.5).
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
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
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
            StartAuthSessionInput startInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession(objectHandle, SessionAlg, symmetric);

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
                    SessionAlg, pool, symmetric: symmetric, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

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
    /// Section 23.2.4; Part 1, clause 17.6.5), and the pool balance returns to where it stood before the
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
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_ChangeAuth, TpmResponseCodec.NvChangeAuth);

        byte[] rotationPolicy = await ComputeCommandCodeOnlyRotationPolicyAsync(pool).ConfigureAwait(false);
        byte[] indexName = await DefineOrdinaryIndexAsync(tpm, pool, registry, IndexHandle, rotationPolicy).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, StartAuthSessionInput.CreateUnboundUnsaltedPolicySession(SessionAlg), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession session = new(new TpmHandle(sessionHandle), started.NonceTPM, SessionAlg, pool);

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
    /// Computes the policy digest of a policy asserting <c>TPM2_PolicyCommandCode(TPM_CC_NV_ChangeAuth)</c> and
    /// nothing else — <c>H(0…0 ‖ TPM_CC_PolicyCommandCode ‖ TPM_CC_NV_ChangeAuth)</c> (TPM 2.0 Library Part 3,
    /// Section 23.11).
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
    /// Library Part 1, clause 14, Table 6) computed independently of the simulator so the executor can build cpHash.
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
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg);

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
        var simulator = new TpmSimulator(tpmId, signingBackend: BouncyCastleTpmEccSigningBackend.Create());
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
