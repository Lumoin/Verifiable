using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
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
/// Proves the ownership contract of the audit mechanism's in-flight carriers — the retained cpHash
/// (<see cref="TpmCommandHmacVerified.AuditCpHash"/>) and the in-flight record it becomes
/// (<see cref="TpmSimulatorState.PendingAudit"/>) — across the paths that end a command without an audit
/// completion: a later authorization slot's pre-gate refusal, and an effect fault after the command HMAC has
/// already verified. Every case runs against the in-house behavioural <see cref="TpmSimulator"/> through the
/// production <see cref="TpmCommandExecutor"/> wire path, and every pool assertion is taken over a
/// <see cref="MeteredHousePool"/> whose baseline is captured AFTER whatever destructive setup the case needs,
/// never before it — an earlier baseline would count the setup's own rentals as the case's own imbalance.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorAuditCarrierTests
{
    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The session hash algorithm every session in this class negotiates.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The octet count <c>TPM2_GetRandom()</c> is asked to draw in every case here.</summary>
    private const ushort RandomDrawLength = 16;

    /// <summary>The password bound to the signing key <see cref="CreateUserWithAuthClearEccSigningPrimaryAsync"/> creates.</summary>
    private const string KeyPasswordText = "audit-carrier-key-auth";

    /// <summary>The authorization value assigned to every sequence <see cref="StartSignSequenceAsync"/> starts.</summary>
    private static byte[] SequenceAuth { get; } = "audit-carrier-sequence-auth"u8.ToArray();

    /// <summary>
    /// A first audited slot's own retained cpHash (<see cref="TpmCommandHmacVerified.AuditCpHash"/>) is
    /// released when a LATER queued slot answers a pre-gate refusal before the audit machinery ever sees the
    /// command: "When a command fails, the audit session digest is not changed" — the refused command has no
    /// audit outcome for the retained carrier to be adopted into, so the pool returns to the baseline taken
    /// before the command.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ARetainedAuditCpHashIsReleasedWhenALaterQueuedSlotAnswersAPreGateRefusal()
    {
        using var metered = new MeteredHousePool();
        BaseMemoryPool pool = metered.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ARetainedAuditCpHashIsReleasedWhenALaterQueuedSlotAnswersAPreGateRefusal), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateUserWithAuthClearEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        TpmiDhObject sequenceHandle = await StartSignSequenceAsync(tpm, registry, pool, key.ObjectHandle, SequenceAuth).ConfigureAwait(false);

        (uint sequenceSessionHandle, TpmSession sequenceSession) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        (uint keySessionHandle, TpmSession keySession) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            sequenceSession.SetAuthValue(SequenceAuth, pool);
            sequenceSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
            keySession.SetAuthValue("audit-carrier-key-auth"u8.ToArray(), pool);

            long baseline = metered.OutstandingCount;

            TpmResult<SignSequenceCompleteResponse> result;
            using(SignSequenceCompleteInput input = SignSequenceCompleteInput.Create(sequenceHandle, key.ObjectHandle, "message"u8.ToArray(), pool))
            {
                ReadOnlyMemory<byte>[] handleNames = [ReadOnlyMemory<byte>.Empty, key.Name.AsReadOnlyMemory()];
                result = await TpmCommandExecutor.ExecuteAsync<SignSequenceCompleteResponse>(
                    tpm, input, [sequenceSession, keySession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            }

            Assert.IsFalse(result.IsSuccess, "The key slot's userWithAuth-CLEAR pre-gate refusal must end the command.");
            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_POLICY_FAIL, 1), result.ResponseCode,
                "A userWithAuth-CLEAR entity authorized over a non-policy slot is refused session-encoded TPM_RC_POLICY_FAIL at its own slot, judged ahead of that slot's own HMAC verification.");

            Assert.AreEqual(
                baseline, metered.OutstandingCount,
                "The audit-claiming head slot's own retained cpHash must be released, not adopted, when the command ends in a later slot's pre-gate refusal.");
        }
        finally
        {
            sequenceSession.Dispose();
            keySession.Dispose();
            await FlushIfPresentAsync(tpm, registry, pool, sequenceSessionHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, pool, keySessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// An effect fault observed AFTER the command HMAC has already verified and stamped
    /// <see cref="TpmSimulatorState.PendingAudit"/> — here, <c>TPM2_GetRandom()</c>'s entropy draw throwing —
    /// leaves the session exactly as it was before the faulted command: the NEXT command over the same session,
    /// claiming no audit, succeeds with no <c>audit</c> bit in its response, and <c>TPM2_GetSessionAuditDigest()</c>
    /// answers <c>TPM_RC_TYPE</c> handle-encoded at sessionHandle, handle 3 of Table 103 — "A session does not
    /// become an audit session until the successful completion of the command in which the session is first
    /// used as an audit session."
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.5; Part 3, clause 18.5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task AnEntropyFaultAfterCommandHmacVerificationLeavesTheSessionNonAuditForTheNextCommand()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var entropy = new FaultingEntropySource();
        using TpmSimulator simulator = await CreateOperationalWithEntropyAsync(
            nameof(AnEntropyFaultAfterCommandHmacVerificationLeavesTheSessionNonAuditForTheNextCommand), pool, entropy.Fill).ConfigureAwait(false);
        List<byte[]> responses = [];
        using TpmDevice device = CreateResponseCapturingDevice(simulator, responses);
        TpmResponseRegistry registry = CreateRegistry();

        (uint sessionHandle, TpmSession session) = await StartUnboundAuditSessionAsync(device, pool, registry).ConfigureAwait(false);
        try
        {
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
            entropy.ShouldFault = true;

            await Assert.ThrowsExactlyAsync<InvalidOperationException>(async () =>
                await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                    device, new GetRandomInput(RandomDrawLength), [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);

            entropy.ShouldFault = false;
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;
            TpmResult<GetRandomResponse> plain = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                device, new GetRandomInput(RandomDrawLength), [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(plain.IsSuccess, $"The next command over the same session, claiming no audit, must verify and succeed: '{plain.ResponseCode}'.");
            plain.Value.Dispose();

            (TpmRcConstants code, _, TpmsAuthResponse entry) = ParseSingleSessionResponse(responses[^1], pool);
            using(entry)
            {
                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "The captured response must report success.");
                Assert.AreEqual(
                    (TpmaSession)0, entry.SessionAttributes & TpmaSession.AUDIT,
                    "The response must carry no audit bit: the faulted command never completed, and this one did not claim audit.");
            }

            using GetSessionAuditDigestInput input = GetSessionAuditDigestInput.ForNullSigner(TpmiShHmac.FromValue(sessionHandle), ReadOnlySpan<byte>.Empty, pool);
            using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
            using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
            TpmResult<GetSessionAuditDigestResponse> readBack = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                device, input, [privacyAdminAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_TYPE, 2), readBack.ResponseCode,
                "The session must never have become an audit session: the faulted command's own audit claim never completed.");
        }
        finally
        {
            session.Dispose();
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The same entropy fault, measured over a <see cref="MeteredHousePool"/>: the <see cref="TpmPendingAudit"/>
    /// the fault stranded on <see cref="TpmSimulatorState.PendingAudit"/> is released by
    /// <see cref="TpmSimulator.Dispose"/>'s teardown walk, so the pool is balanced once the simulator itself is
    /// disposed — the last of the three points at which a stranded pending audit is released.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.5</see>.
    /// </summary>
    [TestMethod]
    public async Task TheMeteredPoolIsBalancedAfterDisposeFollowingAnEntropyFaultThatStrandedAPendingAudit()
    {
        using var metered = new MeteredHousePool();
        BaseMemoryPool pool = metered.Pool;
        var entropy = new FaultingEntropySource();
        TpmSimulator simulator = await CreateOperationalWithEntropyAsync(
            nameof(TheMeteredPoolIsBalancedAfterDisposeFollowingAnEntropyFaultThatStrandedAPendingAudit), pool, entropy.Fill).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint sessionHandle, TpmSession session) = await StartUnboundAuditSessionAsync(device, pool, registry).ConfigureAwait(false);
        try
        {
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
            entropy.ShouldFault = true;

            await Assert.ThrowsExactlyAsync<InvalidOperationException>(async () =>
                await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                    device, new GetRandomInput(RandomDrawLength), [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
        }
        finally
        {
            session.Dispose();
        }

        simulator.Dispose();

        Assert.AreEqual(
            metered.RentedCount, metered.ReturnedCount,
            "Disposing the simulator while a fault-stranded PendingAudit still stands must release it, balancing the pool.");
    }

    /// <summary>
    /// An audit session's digest, audit status, and exclusivity survive a <c>TPM2_ContextSave()</c> /
    /// <c>TPM2_ContextLoad()</c> cycle; over a <see cref="MeteredHousePool"/>, one more audited command over the
    /// reloaded handle followed by <c>TPM2_FlushContext()</c> returns the pool to the baseline taken before the
    /// save — the reload's own non-empty digest rental included.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 27.5</see>.
    /// </summary>
    [TestMethod]
    public async Task MeteredPoolBalancesAcrossAnAuditedSessionsSaveLoadCommandAndFlushCycle()
    {
        using var metered = new MeteredHousePool();
        BaseMemoryPool pool = metered.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(MeteredPoolBalancesAcrossAnAuditedSessionsSaveLoadCommandAndFlushCycle), pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint sessionHandle, TpmSession session) = await StartUnboundAuditSessionAsync(device, pool, registry).ConfigureAwait(false);
        uint reloadedHandle = 0;
        try
        {
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
            await RunGetRandomAsync(device, registry, pool, session).ConfigureAwait(false);

            (_, byte[] establishedDigest) = await ReadAuditDigestAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
            Assert.IsGreaterThan(0, establishedDigest.Length, "The established audit session's digest must be non-empty before the save/load cycle.");

            ContextSaveInput saveInput = ContextSaveInput.ForHandle(sessionHandle);
            TpmResult<ContextSaveResponse> saveResult = await TpmCommandExecutor.ExecuteAsync<ContextSaveResponse>(
                device, saveInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(saveResult.IsSuccess, $"TPM2_ContextSave() of the audited session failed: '{saveResult.ResponseCode}'.");
            using ContextSaveResponse saved = saveResult.Value;

            var loadInput = new ContextLoadInput(saved.Context);
            TpmResult<ContextLoadResponse> loadResult = await TpmCommandExecutor.ExecuteAsync<ContextLoadResponse>(
                device, loadInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(loadResult.IsSuccess, $"TPM2_ContextLoad() of the audited session failed: '{loadResult.ResponseCode}'.");
            reloadedHandle = loadResult.Value.LoadedHandle.Value;
            Assert.AreEqual(sessionHandle, reloadedHandle, "An audited HMAC session reloads at its saved handle exactly.");

            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
            await RunGetRandomAsync(device, registry, pool, session).ConfigureAwait(false);

            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                device, FlushContextInput.ForHandle(reloadedHandle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            reloadedHandle = 0;
        }
        finally
        {
            session.Dispose();
            await FlushIfPresentAsync(device, registry, pool, reloadedHandle == 0 ? sessionHandle : reloadedHandle).ConfigureAwait(false);
        }

        Assert.AreEqual(
            metered.RentedCount, metered.ReturnedCount,
            "Establishing an audit session, one audited command, a save, a load, one more audited command over the reloaded handle, and a flush must return every rented carrier — the reload's own non-empty digest rental included.");
    }

    /// <summary>
    /// A deterministic entropy source that fills a counter-based byte stream until <see cref="ShouldFault"/> is
    /// set, after which every draw throws <see cref="InvalidOperationException"/> instead of filling — the
    /// seam that faults a command's effect AFTER its command HMAC has already verified and stamped
    /// <see cref="TpmSimulatorState.PendingAudit"/> (<c>TPM2_GetRandom()</c>'s entropy draw runs at framing
    /// time, inside the effect the transition dispatches once <see cref="TpmLifecycleTransitions"/>'s command-HMAC
    /// continuation has already installed the pending record).
    /// </summary>
    private sealed class FaultingEntropySource
    {
        /// <summary>The next octet the deterministic fill emits.</summary>
        private byte counter;

        /// <summary>Whether the next and every subsequent draw throws instead of filling.</summary>
        public bool ShouldFault { get; set; }

        /// <summary>Fills <paramref name="destination"/> with a deterministic counter stream, or throws when <see cref="ShouldFault"/> is set.</summary>
        /// <param name="destination">The buffer to fill.</param>
        public void Fill(Span<byte> destination)
        {
            if(ShouldFault)
            {
                throw new InvalidOperationException("Injected entropy fault for TpmInHouseSimulatorAuditCarrierTests.");
            }

            for(int i = 0; i < destination.Length; i++)
            {
                destination[i] = counter;
                counter++;
            }
        }
    }

    /// <summary>
    /// Starts an unbound, unsalted HMAC session (TPM 2.0 Library Part 1, clause 16.6.9) with an empty
    /// authorization value — an unauthorizing companion, whose sessionKey and authValue are therefore both the
    /// Empty Buffer for any command it merely audits. XOR obfuscation is negotiated up front (unused unless a
    /// case claims <c>encrypt</c>), so the same session can also carry a valid non-audit companion claim —
    /// <c>CONTINUE_SESSION</c> alone is refused <c>TPM_RC_ATTRIBUTES</c> for a session authorizing no entity
    /// (TPM 2.0 Library Part 1, clause 15.6.1: "a session ... must set at least one of decrypt, encrypt, or
    /// audit").
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <returns>The started session handle and its client-side wrapper.</returns>
    private async Task<(uint Handle, TpmSession Session)> StartUnboundAuditSessionAsync(TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry)
    {
        TpmtSymDef symmetric = TpmtSymDef.Xor(SessionAlg);
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg, TestEntropy.NewCounterStream(), pool, symmetric);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            device, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (unbound) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        var session = new TpmSession(new TpmHandle(started.SessionHandle.Value), started.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), pool, symmetric);

        return (started.SessionHandle.Value, session);
    }

    /// <summary>
    /// Starts an unbound, unsalted HMAC session for the two-slot <c>TPM2_SignSequenceComplete()</c> recipe,
    /// carrying no authorization value of its own until the caller sets one.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The session handle and its client-side wrapper.</returns>
    private async Task<(uint SessionHandle, TpmSession Session)> StartUnboundHmacSessionAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> result = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"StartAuthSession (unbound HMAC) failed: '{result.ResponseCode}'.");

        StartAuthSessionResponse started = result.Value;
        var session = new TpmSession(new TpmHandle(started.SessionHandle.Value), started.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), pool);

        return (started.SessionHandle.Value, session);
    }

    /// <summary>Runs one <c>TPM2_GetRandom()</c> over <paramref name="session"/> and asserts it succeeds.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="session">The authorizing/auditing session.</param>
    private async Task RunGetRandomAsync(TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool, TpmSession session)
    {
        TpmResult<GetRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
            device, new GetRandomInput(RandomDrawLength), [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_GetRandom() over the audit session must succeed: '{result.ResponseCode}'.");
        result.Value.Dispose();
    }

    /// <summary>Flushes <paramref name="handle"/> if it names a started session.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The session handle, or zero when none was started.</param>
    private async Task FlushIfPresentAsync(TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle)
    {
        if(handle == 0)
        {
            return;
        }

        _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            device, FlushContextInput.ForHandle(handle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Reads back an audit session's status through <c>TPM2_GetSessionAuditDigest()</c>'s NULL signer (Part 3,
    /// clause 18.1: "the attestation block is 'signed' with the NULL Signature"), authorized against the
    /// Empty Buffer at both slots — the privacy administrator's and, for the NULL signer, <c>TPM_RH_NULL</c>'s.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sessionHandle">The audit session's handle.</param>
    /// <returns>Whether the session is currently exclusive, and its attested digest.</returns>
    private async Task<(TpmiYesNo Exclusive, byte[] Digest)> ReadAuditDigestAsync(TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool, uint sessionHandle)
    {
        using GetSessionAuditDigestInput input = GetSessionAuditDigestInput.ForNullSigner(TpmiShHmac.FromValue(sessionHandle), ReadOnlySpan<byte>.Empty, pool);
        using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<GetSessionAuditDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
            device, input, [privacyAdminAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_GetSessionAuditDigest(NULL signer) failed: '{result.ResponseCode}'.");

        using GetSessionAuditDigestResponse response = result.Value;
        TpmsSessionAuditInfo info = response.SessionAudit;

        return (info.ExclusiveSession, info.SessionDigest.AsReadOnlySpan().ToArray());
    }

    /// <summary>Parses a captured response's header, and — when it carries exactly one session entry — its parameter octets and its <c>TPMS_AUTH_RESPONSE</c>.</summary>
    /// <param name="capturedResponse">The raw response octets.</param>
    /// <param name="pool">The memory pool the session entry's owned carriers are allocated from.</param>
    /// <returns>The response code, the parameter octets (empty on a <c>TPM_ST_NO_SESSIONS</c> response), and the one session entry (a dispose-immune default when there is none).</returns>
    private static (TpmRcConstants Code, byte[] Parameters, TpmsAuthResponse Entry) ParseSingleSessionResponse(byte[] capturedResponse, BaseMemoryPool pool)
    {
        var reader = new TpmReader(capturedResponse);
        TpmHeader header = TpmHeader.Parse(ref reader);
        var code = (TpmRcConstants)header.Code;

        if(header.Tag != (ushort)TpmStConstants.TPM_ST_SESSIONS)
        {
            return (code, [], EmptySessionEntry(pool));
        }

        uint parameterSize = reader.ReadUInt32();
        byte[] parameters = reader.ReadBytes((int)parameterSize).ToArray();
        TpmsAuthResponse entry = TpmsAuthResponse.Parse(ref reader, pool);

        return (code, parameters, entry);
    }

    /// <summary>Builds a harmless, immediately-disposable session entry for the no-session response shape.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>A zero-attribute, empty-nonce, empty-hmac entry.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of both carriers transfers into the constructed TpmsAuthResponse, which every caller disposes.")]
    private static TpmsAuthResponse EmptySessionEntry(BaseMemoryPool pool) =>
        new(Tpm2bNonce.Create(ReadOnlySpan<byte>.Empty, pool), default, Tpm2bAuth.Create(ReadOnlySpan<byte>.Empty, pool));

    /// <summary>
    /// Wraps the simulator in a device that records every response's raw octets, in submission order, so a test
    /// can independently inspect what the wire actually carried.
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
    /// Starts a signing sequence under <paramref name="keyHandle"/> with <paramref name="sequenceAuth"/> as its
    /// own authorization value, asserting success. <c>keyHandle</c> carries no <c>@</c> at Start (Part 3,
    /// clause 17.5, Table 87), so the command is framed with no session at all.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The signing key the sequence is started under.</param>
    /// <param name="sequenceAuth">The sequence's own authorization value.</param>
    /// <returns>The started sequence's handle.</returns>
    private async Task<TpmiDhObject> StartSignSequenceAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject keyHandle, byte[] sequenceAuth)
    {
        using SignSequenceStartInput input = SignSequenceStartInput.Create(keyHandle, sequenceAuth, pool);
        TpmResult<SignSequenceStartResponse> result = await TpmCommandExecutor.ExecuteAsync<SignSequenceStartResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_SignSequenceStart() failed: '{result.ResponseCode}'.");

        return result.Value.SequenceHandle;
    }

    /// <summary>
    /// Composes a CreatePrimary input for an ECC signing key whose <c>TPMA_OBJECT.userWithAuth</c> bit is
    /// CLEAR — a template no production factory builds, since every production caller wants USER role access
    /// through a password or HMAC session. This is the entity <see cref="ARetainedAuditCpHashIsReleasedWhenALaterQueuedSlotAnswersAPreGateRefusal"/>
    /// authorizes at a NON-head slot, so its pre-gate refusal is judged by the command-HMAC continuation rather
    /// than the area resolver's own head loop.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The command input; the caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the composed sensitive area and public template transfers to the returned CreatePrimaryInput, whose Dispose releases them.")]
    private static CreatePrimaryInput CreateUserWithAuthClearEccSigningKeyInput(BaseMemoryPool pool)
    {
        Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.WithPassword(KeyPasswordText, pool);

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

    /// <summary>Creates the userWithAuth-CLEAR ECC signing primary under the owner hierarchy.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response; the caller owns and disposes it.</returns>
    private async Task<CreatePrimaryResponse> CreateUserWithAuthClearEccSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreateUserWithAuthClearEccSigningKeyInput(pool);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (userWithAuth-CLEAR ECC signing key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Creates the response codec registry for every command this class drives through the production executor.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry() =>
        new TpmResponseRegistry()
            .Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession)
            .Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext)
            .Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom)
            .Register(TpmCcConstants.TPM_CC_GetSessionAuditDigest, TpmResponseCodec.GetSessionAuditDigest)
            .Register(TpmCcConstants.TPM_CC_ContextSave, TpmResponseCodec.ContextSave)
            .Register(TpmCcConstants.TPM_CC_ContextLoad, TpmResponseCodec.ContextLoad)
            .Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary)
            .Register(TpmCcConstants.TPM_CC_SignSequenceStart, TpmResponseCodec.SignSequenceStart)
            .Register(TpmCcConstants.TPM_CC_SignSequenceComplete, TpmResponseCodec.SignSequenceComplete);

    /// <summary>
    /// Creates a simulator, powers it on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the operational
    /// phase — the precondition every command in this class carries.
    /// </summary>
    /// <param name="name">A per-test simulator identifier.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private Task<TpmSimulator> CreateOperationalAsync(string name, BaseMemoryPool pool) =>
        BringOperationalAsync(new TpmSimulator(name, signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch)), pool);

    /// <summary>
    /// Creates a simulator over the supplied entropy delegate, powers it on, and brings it through
    /// <c>TPM2_Startup(CLEAR)</c> into the operational phase — the form
    /// <see cref="AnEntropyFaultAfterCommandHmacVerificationLeavesTheSessionNonAuditForTheNextCommand"/> and
    /// <see cref="TheMeteredPoolIsBalancedAfterDisposeFollowingAnEntropyFaultThatStrandedAPendingAudit"/> use to
    /// fault a command's effect deterministically.
    /// </summary>
    /// <param name="name">A per-test simulator identifier.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="rng">The entropy delegate the simulator draws every random octet from.</param>
    /// <returns>The operational simulator.</returns>
    private Task<TpmSimulator> CreateOperationalWithEntropyAsync(string name, BaseMemoryPool pool, FillEntropyDelegate rng) =>
        BringOperationalAsync(new TpmSimulator(name, rng: rng, timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch)), pool);

    /// <summary>Powers on <paramref name="simulator"/> and issues <c>TPM2_Startup(CLEAR)</c> directly against it.</summary>
    /// <param name="simulator">The powered-off simulator to bring operational.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns><paramref name="simulator"/>, now operational.</returns>
    private async Task<TpmSimulator> BringOperationalAsync(TpmSimulator simulator, BaseMemoryPool pool)
    {
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var startup = new StartupInput(TpmSuConstants.TPM_SU_CLEAR);
        int length = TpmHeader.HeaderSize + startup.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)startup.CommandCode);
        header.WriteTo(ref writer);
        startup.WriteHandles(ref writer);
        startup.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The transport itself must succeed for TPM2_Startup(CLEAR).");
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)responseHeader.Code, "TPM2_Startup(CLEAR) must succeed.");

        return simulator;
    }
}
