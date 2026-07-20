using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cbor.Ctap;
using Verifiable.Cbor.Fido2;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.Foundation.Automata;
using Verifiable.Tests.TestInfrastructure;
using static Verifiable.Tests.TestInfrastructure.CtapWave2AuthenticatorFixtures;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for CTAP 2.3 :2840's user-action (user-presence) timeout model and R2's deferral protocol on
/// <see cref="CtapAuthenticatorSimulator"/>: the injected <see cref="SimulateUserPresenceDelegate"/> seam's
/// <see cref="CtapUserPresenceDecision.Granted"/>/<see cref="CtapUserPresenceDecision.Denied"/>/
/// <see cref="CtapUserPresenceDecision.Pending"/> mapping on both the plain
/// <see cref="CtapAuthenticatorSimulator.TransceiveAsync"/> (synchronous, non-deferring) path and the
/// <see cref="CtapAuthenticatorSimulator.BeginDeferredTransceiveAsync"/>/
/// <see cref="CtapAuthenticatorSimulator.PollDeferredTransceiveAsync"/>/
/// <see cref="CtapAuthenticatorSimulator.CancelDeferredTransceiveAsync"/> deferring path, the R5
/// <c>excludeList</c>/<c>allowList</c> <c>maxCredentialCountInList</c> bound enforcement (and its
/// precedence over user-presence collection), and every discard rule (supersede, <c>PowerCycle</c>,
/// <c>authenticatorReset</c>). Uses <see cref="FakeTimeProvider"/> for every timing-sensitive assertion —
/// never the wall clock.
/// </summary>
[TestClass]
internal sealed class CtapUserPresenceTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// A poll issued at EXACTLY 10 seconds since the wait was armed still finds the wait pending — the
    /// :2840 MUST ("MUST be at least 10 seconds") holds behaviorally, since a configured duration below
    /// 10 seconds would already have timed out here. <see cref="CtapAuthenticatorTransitions.UserActionTimeoutDuration"/>
    /// is <c>private</c> (mirroring <c>GetNextAssertionTimerDuration</c>'s own posture — see
    /// <c>CtapAuthenticatorGetNextAssertionTests</c>'s identical boundary-test style for its 30-second
    /// timer), so this is the direct substitute for a compile-time assertion on the constant: an
    /// observable-behavior proof rather than a reflection-based peek at a private implementation detail.
    /// </summary>
    [TestMethod]
    public async Task PollAtExactlyTenSecondsElapsedStaysPending()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using CtapAuthenticatorSimulator simulator = CreateSimulator(
            "up-tenseconds-boundary", timeProvider: timeProvider, simulateUserPresence: AlwaysPending);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool);
        byte[] envelope = CtapWave2RequestEnvelopes.BuildMakeCredentialEnvelope(request);
        DisposeMakeCredentialRequest(request);

        using PooledMemory begin = await simulator.BeginDeferredTransceiveAsync(envelope, pool, TestContext.CancellationToken);
        Assert.AreEqual(0, begin.Length);

        timeProvider.Advance(TimeSpan.FromSeconds(10));

        using PooledMemory poll = await simulator.PollDeferredTransceiveAsync(pool, TestContext.CancellationToken);
        Assert.AreEqual(0, poll.Length, "a wait armed 10 seconds ago must not yet have timed out.");
    }


    /// <summary>
    /// A poll issued after the configured 30-second duration has elapsed resolves the wait to
    /// <see cref="WellKnownCtapStatusCodes.UserActionTimeout"/> — the non-deferring path's own :2840
    /// abstraction (a deterministic simulator has no wall-clock wait to block on) applied on the deferring
    /// path once the ARMED instant, not the most recent poll, is more than the duration in the past.
    /// </summary>
    [TestMethod]
    public async Task PollDeferredTransceiveAfterTimeoutDurationElapsedReturnsUserActionTimeout()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using CtapAuthenticatorSimulator simulator = CreateSimulator(
            "up-timeout-elapsed", timeProvider: timeProvider, simulateUserPresence: AlwaysPending);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool);
        byte[] envelope = CtapWave2RequestEnvelopes.BuildMakeCredentialEnvelope(request);
        DisposeMakeCredentialRequest(request);

        using PooledMemory begin = await simulator.BeginDeferredTransceiveAsync(envelope, pool, TestContext.CancellationToken);
        Assert.AreEqual(0, begin.Length);

        timeProvider.Advance(TimeSpan.FromSeconds(9));
        using(PooledMemory stillPending = await simulator.PollDeferredTransceiveAsync(pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(0, stillPending.Length);
        }

        timeProvider.Advance(TimeSpan.FromSeconds(21));
        using PooledMemory timedOut = await simulator.PollDeferredTransceiveAsync(pool, TestContext.CancellationToken);

        Assert.AreEqual(1, timedOut.Length);
        Assert.AreEqual(WellKnownCtapStatusCodes.UserActionTimeout, timedOut.AsReadOnlySpan()[0]);
    }


    /// <summary>A provider that counts its own invocations is consulted exactly once for one <c>authenticatorMakeCredential</c>, and a <see cref="CtapUserPresenceDecision.Granted"/> answer succeeds.</summary>
    [TestMethod]
    public async Task MakeCredentialGrantedProviderIsConsultedExactlyOnce()
    {
        int consultCount = 0;
        ValueTask<CtapUserPresenceDecision> CountingGrantedProvider(CancellationToken cancellationToken)
        {
            consultCount++;

            return ValueTask.FromResult(CtapUserPresenceDecision.Granted);
        }

        using CtapAuthenticatorSimulator simulator = CreateSimulator("up-mc-granted-once", simulateUserPresence: CountingGrantedProvider);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
        Assert.AreEqual(1, consultCount);
    }


    /// <summary>A <see cref="CtapUserPresenceDecision.Denied"/> answer aborts <c>authenticatorMakeCredential</c> with <see cref="WellKnownCtapStatusCodes.OperationDenied"/>.</summary>
    [TestMethod]
    public async Task MakeCredentialDeniedProviderReturnsOperationDenied()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("up-mc-denied", simulateUserPresence: AlwaysDenied);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.OperationDenied, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// A never-granting <see cref="CtapUserPresenceDecision.Pending"/> answer on the plain
    /// (non-deferring) <see cref="CtapAuthenticatorSimulator.TransceiveAsync"/> path REPRESENTS an
    /// elapsed :2840 wait, mapping to <see cref="WellKnownCtapStatusCodes.UserActionTimeout"/> — the
    /// sync-path abstraction rule.
    /// </summary>
    [TestMethod]
    public async Task MakeCredentialPendingProviderReturnsUserActionTimeout()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("up-mc-pending-sync", simulateUserPresence: AlwaysPending);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.UserActionTimeout, response.AsReadOnlySpan()[0]);
    }


    /// <summary>A <see cref="CtapUserPresenceDecision.Granted"/> answer succeeds an <c>authenticatorGetAssertion</c> with <c>up</c> unset (defaults <see langword="true"/>).</summary>
    [TestMethod]
    public async Task GetAssertionGrantedProviderSucceeds()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("up-ga-granted");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0x71), TestContext.CancellationToken);

        CtapGetAssertionRequest request = BuildGetAssertionRequest(pool);
        using PooledMemory response = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// A <see cref="CtapUserPresenceDecision.Denied"/> answer aborts <c>authenticatorGetAssertion</c> with
    /// <see cref="WellKnownCtapStatusCodes.OperationDenied"/> — collection happens BEFORE credential
    /// location, so no credential need ever be registered for this outcome.
    /// </summary>
    [TestMethod]
    public async Task GetAssertionDeniedProviderReturnsOperationDenied()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("up-ga-denied", simulateUserPresence: AlwaysDenied);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapGetAssertionRequest request = BuildGetAssertionRequest(pool);
        using PooledMemory response = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.OperationDenied, response.AsReadOnlySpan()[0]);
    }


    /// <summary>A never-granting <see cref="CtapUserPresenceDecision.Pending"/> answer on the sync path maps <c>authenticatorGetAssertion</c> to <see cref="WellKnownCtapStatusCodes.UserActionTimeout"/>.</summary>
    [TestMethod]
    public async Task GetAssertionPendingProviderReturnsUserActionTimeout()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("up-ga-pending-sync", simulateUserPresence: AlwaysPending);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapGetAssertionRequest request = BuildGetAssertionRequest(pool);
        using PooledMemory response = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.UserActionTimeout, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// <c>options.up = false</c> is a pre-flight: the provider is never consulted at all (a throw proves
    /// it), yet the call still SUCCEEDS with the signed <c>authData</c>'s UP bit clear — trap 6.
    /// Registration (the fixture's own internal <c>authenticatorMakeCredential</c>) consumes the
    /// provider's ONE legitimate <see cref="CtapUserPresenceDecision.Granted"/> answer; every consult
    /// after that throws.
    /// </summary>
    [TestMethod]
    public async Task GetAssertionUserPresenceFalseNeverConsultsProviderAndSucceeds()
    {
        int consultCount = 0;
        ValueTask<CtapUserPresenceDecision> GrantOnceThenThrowProvider(CancellationToken cancellationToken)
        {
            consultCount++;
            if(consultCount > 1)
            {
                throw new InvalidOperationException("A pre-flight (up:false) authenticatorGetAssertion must never consult the user-presence provider.");
            }

            return ValueTask.FromResult(CtapUserPresenceDecision.Granted);
        }

        using CtapAuthenticatorSimulator simulator = CreateSimulator("up-ga-upfalse-no-consult", simulateUserPresence: GrantOnceThenThrowProvider);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0x72), TestContext.CancellationToken);

        CtapGetAssertionRequest request = BuildGetAssertionRequest(pool, options: new CtapCommandOptions(UserPresence: false));
        using PooledMemory response = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);

        CtapGetAssertionResponse decoded = CtapGetAssertionResponseCborReader.Read(response.AsReadOnlyMemory()[1..], pool);
        try
        {
            using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(decoded.AuthData, CredentialPublicKeyCborReader.Read, pool);
            Assert.IsFalse(authenticatorData.Flags.UserPresent);
        }
        finally
        {
            decoded.Credential.Id.Dispose();
            decoded.User?.Id.Dispose();
        }
    }


    /// <summary><c>options.up = false</c> stays rejected with <see cref="WellKnownCtapStatusCodes.InvalidOption"/> for <c>authenticatorMakeCredential</c> — the existing behavior fence — and a throwing provider proves it is never consulted.</summary>
    [TestMethod]
    public async Task MakeCredentialUserPresenceFalseStaysInvalidOptionWithoutConsultingProvider()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("up-mc-upfalse-no-consult", simulateUserPresence: AlwaysThrow);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, options: new CtapCommandOptions(UserPresence: false));
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidOption, response.AsReadOnlySpan()[0]);
    }


    /// <summary>R5 (getInfo 0x07, snapshot lines 4405-4409): an <c>excludeList</c> of 9 entries — one past <see cref="CtapAuthenticatorState.MaxCredentialCountInListCapacity"/> — rejects with <see cref="WellKnownCtapStatusCodes.LimitExceeded"/>.</summary>
    [TestMethod]
    public async Task MakeCredentialExcludeListOfNineReturnsLimitExceeded()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("up-mc-excludelist-nine");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        List<PublicKeyCredentialDescriptor> excludeList = BuildDummyDescriptors(pool, count: 9, seed: 0x80);
        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, excludeList: excludeList);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.LimitExceeded, response.AsReadOnlySpan()[0]);
    }


    /// <summary>R5: an <c>excludeList</c> of exactly <see cref="CtapAuthenticatorState.MaxCredentialCountInListCapacity"/> (8) entries is within bound and succeeds.</summary>
    [TestMethod]
    public async Task MakeCredentialExcludeListOfEightSucceeds()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("up-mc-excludelist-eight");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        List<PublicKeyCredentialDescriptor> excludeList = BuildDummyDescriptors(pool, CtapAuthenticatorState.MaxCredentialCountInListCapacity, seed: 0x90);
        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, excludeList: excludeList);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
    }


    /// <summary>R5: an <c>allowList</c> of 9 entries rejects with <see cref="WellKnownCtapStatusCodes.LimitExceeded"/> — no credential lookup is ever attempted, so no credential need be registered.</summary>
    [TestMethod]
    public async Task GetAssertionAllowListOfNineReturnsLimitExceeded()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("up-ga-allowlist-nine");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        List<PublicKeyCredentialDescriptor> allowList = BuildDummyDescriptors(pool, count: 9, seed: 0xA0);
        CtapGetAssertionRequest request = BuildGetAssertionRequest(pool, allowList: allowList);
        using PooledMemory response = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.LimitExceeded, response.AsReadOnlySpan()[0]);
    }


    /// <summary>R5: an <c>allowList</c> of exactly 8 entries — 7 unknown IDs plus one real, registered credential — is within bound and succeeds.</summary>
    [TestMethod]
    public async Task GetAssertionAllowListOfEightWithRealCredentialSucceeds()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("up-ga-allowlist-eight");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        byte[] realCredentialId = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0x73), TestContext.CancellationToken, resident: false);

        List<PublicKeyCredentialDescriptor> allowList = BuildDummyDescriptors(pool, count: CtapAuthenticatorState.MaxCredentialCountInListCapacity - 1, seed: 0xB0);
        allowList.Add(new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = CredentialId.Create(realCredentialId, pool) });

        CtapGetAssertionRequest request = BuildGetAssertionRequest(pool, allowList: allowList);
        using PooledMemory response = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
    }


    /// <summary>R5's enforcement precedes user-presence collection (trap: capability preconditions reject before ever prompting): an oversized <c>excludeList</c> with a throwing provider still rejects with <see cref="WellKnownCtapStatusCodes.LimitExceeded"/>, proving the provider is never consulted.</summary>
    [TestMethod]
    public async Task MakeCredentialExcludeListOfNineReturnsLimitExceededWithoutConsultingProvider()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("up-mc-excludelist-adversarial", simulateUserPresence: AlwaysThrow);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        List<PublicKeyCredentialDescriptor> excludeList = BuildDummyDescriptors(pool, count: 9, seed: 0xC0);
        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, excludeList: excludeList);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.LimitExceeded, response.AsReadOnlySpan()[0]);
    }


    /// <summary>R5's enforcement precedes user-presence collection (trap: capability preconditions reject before ever prompting): an oversized <c>allowList</c> with a throwing provider still rejects with <see cref="WellKnownCtapStatusCodes.LimitExceeded"/>, proving the provider is never consulted — the adversarial mirror of <see cref="GetAssertionAllowListOfNineReturnsLimitExceeded"/> (R5-a).</summary>
    [TestMethod]
    public async Task GetAssertionAllowListOfNineReturnsLimitExceededWithoutConsultingProvider()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("up-ga-allowlist-adversarial", simulateUserPresence: AlwaysThrow);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        List<PublicKeyCredentialDescriptor> allowList = BuildDummyDescriptors(pool, count: 9, seed: 0xD0);
        CtapGetAssertionRequest request = BuildGetAssertionRequest(pool, allowList: allowList);
        using PooledMemory response = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.LimitExceeded, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// C-1: if the injected <see cref="SimulateUserPresenceDelegate"/> throws DURING
    /// <see cref="CtapAuthenticatorSimulator.BeginDeferredTransceiveAsync"/>'s own collect effect, the pure
    /// transition has already armed <see cref="CtapAuthenticatorState.PendingUserPresenceWait"/> on the
    /// simulator's current state (the effectful loop steps the automaton first and executes the declared
    /// action second) — the exception must surface to the caller AND the armed wait must be torn down
    /// rather than left resumable against the carriers Begin's own <c>finally</c> disposes. A subsequent
    /// poll must find nothing pending, throwing the SAME <see cref="InvalidOperationException"/> the
    /// no-pending guard already throws for an ordinary misuse, rather than resuming over disposed
    /// carriers.
    /// </summary>
    [TestMethod]
    public async Task BeginDeferredTransceiveTeardownsArmedWaitWhenUserPresenceProviderThrows()
    {
        static ValueTask<CtapUserPresenceDecision> ThrowingProvider(CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Simulated user-presence collect-effect fault.");

        using CtapAuthenticatorSimulator simulator = CreateSimulator("up-begin-collect-fault", simulateUserPresence: ThrowingProvider);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool);
        byte[] envelope = CtapWave2RequestEnvelopes.BuildMakeCredentialEnvelope(request);
        DisposeMakeCredentialRequest(request);

        InvalidOperationException beginFault = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            () => simulator.BeginDeferredTransceiveAsync(envelope, pool, TestContext.CancellationToken).AsTask());
        Assert.AreEqual("Simulated user-presence collect-effect fault.", beginFault.Message);

        InvalidOperationException pollFault = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            () => simulator.PollDeferredTransceiveAsync(pool, TestContext.CancellationToken).AsTask());
        Assert.AreEqual("PollDeferredTransceiveAsync was called with no user-presence wait pending.", pollFault.Message);
    }


    /// <summary>
    /// <see cref="CtapAuthenticatorSimulator.BeginDeferredTransceiveAsync"/> with a never-granting
    /// provider parks the command: it returns a ZERO-LENGTH marker, and the simulator's own trace shows
    /// <see cref="CtapAuthenticatorState.PendingUserPresenceWait"/> armed on the resulting state.
    /// </summary>
    [TestMethod]
    public async Task BeginDeferredMakeCredentialWithPendingProviderParksAndReturnsEmptyMarker()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("up-begin-parks", simulateUserPresence: AlwaysPending);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var trace = new TestObserver<TraceEntry<CtapAuthenticatorState, CtapAuthenticatorInput>>();
        using(simulator.Subscribe(trace))
        {
            CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool);
            byte[] envelope = CtapWave2RequestEnvelopes.BuildMakeCredentialEnvelope(request);
            DisposeMakeCredentialRequest(request);

            using PooledMemory begin = await simulator.BeginDeferredTransceiveAsync(envelope, pool, TestContext.CancellationToken);
            Assert.AreEqual(0, begin.Length);
        }

        Assert.IsNotNull(trace.Received[^1].StateAfter.PendingUserPresenceWait);
    }


    /// <summary>A still-pending wait keeps returning the ZERO-LENGTH marker across several successive polls, never resolving on its own.</summary>
    [TestMethod]
    public async Task PollDeferredTransceiveWithStillPendingProviderStaysPendingAcrossMultiplePolls()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("up-poll-repeatable", simulateUserPresence: AlwaysPending);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool);
        byte[] envelope = CtapWave2RequestEnvelopes.BuildMakeCredentialEnvelope(request);
        DisposeMakeCredentialRequest(request);

        using PooledMemory begin = await simulator.BeginDeferredTransceiveAsync(envelope, pool, TestContext.CancellationToken);
        Assert.AreEqual(0, begin.Length);

        for(int i = 0; i < 3; i++)
        {
            using PooledMemory poll = await simulator.PollDeferredTransceiveAsync(pool, TestContext.CancellationToken);
            Assert.AreEqual(0, poll.Length);
        }
    }


    /// <summary>
    /// A provider that grants on its third consult resolves a parked <c>authenticatorMakeCredential</c>
    /// on the second poll, returning the full response envelope. The resumed response and the SAME
    /// request run synchronously on a fresh, always-granted simulator agree on every DETERMINISTIC field
    /// (status byte, <c>fmt</c>, <c>attStmt</c> presence, <c>rpIdHash</c>, authData flags, signCount, the
    /// pinned <c>aaguid</c>, and the credential public key's <c>kty</c>/<c>alg</c>). Full byte-identity —
    /// the credential ID and the credential public key's own <c>x</c>/<c>y</c>/attestation-signature bytes
    /// — is NOT assertable: <see cref="CtapCredentialSigningBackend.CreateEs256Default"/>'s key generation
    /// mints its EC key pair via <see cref="CryptographicKeyEvents"/>'s <c>CreateKeyPair</c>, which does
    /// not consume the simulator's injected <see cref="FillEntropyDelegate"/>, so two independently
    /// constructed simulators genuinely draw fresh, unseedable key material even for an otherwise
    /// identical request.
    /// </summary>
    [TestMethod]
    public async Task PollDeferredTransceiveResumesOnGrantedDecisionMatchingSynchronousResponseStructurally()
    {
        Guid sharedAaguid = Guid.NewGuid();

        int consultCount = 0;
        ValueTask<CtapUserPresenceDecision> GrantOnThirdConsultProvider(CancellationToken cancellationToken)
        {
            consultCount++;

            return ValueTask.FromResult(consultCount >= 3 ? CtapUserPresenceDecision.Granted : CtapUserPresenceDecision.Pending);
        }

        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using CtapAuthenticatorSimulator deferredSimulator = CreateSimulator(
            "up-poll-resume-deferred", aaguid: sharedAaguid, simulateUserPresence: GrantOnThirdConsultProvider);

        CtapMakeCredentialRequest deferredRequest = BuildMakeCredentialRequest(pool);
        byte[] envelope = CtapWave2RequestEnvelopes.BuildMakeCredentialEnvelope(deferredRequest);
        DisposeMakeCredentialRequest(deferredRequest);

        using PooledMemory begin = await deferredSimulator.BeginDeferredTransceiveAsync(envelope, pool, TestContext.CancellationToken);
        Assert.AreEqual(0, begin.Length);

        using PooledMemory firstPoll = await deferredSimulator.PollDeferredTransceiveAsync(pool, TestContext.CancellationToken);
        Assert.AreEqual(0, firstPoll.Length);

        using PooledMemory resumedResponse = await deferredSimulator.PollDeferredTransceiveAsync(pool, TestContext.CancellationToken);
        Assert.AreNotEqual(0, resumedResponse.Length);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, resumedResponse.AsReadOnlySpan()[0]);

        using CtapAuthenticatorSimulator syncSimulator = CreateSimulator("up-poll-resume-sync", aaguid: sharedAaguid);
        CtapMakeCredentialRequest syncRequest = BuildMakeCredentialRequest(pool);
        using PooledMemory syncResponse = await SendMakeCredentialAsync(syncSimulator, syncRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, syncResponse.AsReadOnlySpan()[0]);

        CtapMakeCredentialResponse resumedDecoded = CtapMakeCredentialResponseCborReader.Read(resumedResponse.AsReadOnlyMemory()[1..]);
        CtapMakeCredentialResponse syncDecoded = CtapMakeCredentialResponseCborReader.Read(syncResponse.AsReadOnlyMemory()[1..]);

        Assert.AreEqual(syncDecoded.Fmt, resumedDecoded.Fmt);
        Assert.AreEqual(syncDecoded.AttStmt.HasValue, resumedDecoded.AttStmt.HasValue);

        using AuthenticatorData resumedAuthData = AuthenticatorDataReader.Read(resumedDecoded.AuthData, CredentialPublicKeyCborReader.Read, pool);
        using AuthenticatorData syncAuthData = AuthenticatorDataReader.Read(syncDecoded.AuthData, CredentialPublicKeyCborReader.Read, pool);

        Assert.AreSequenceEqual(syncAuthData.RpIdHash.AsReadOnlySpan().ToArray(), resumedAuthData.RpIdHash.AsReadOnlySpan().ToArray());
        Assert.AreEqual(syncAuthData.Flags.UserPresent, resumedAuthData.Flags.UserPresent);
        Assert.AreEqual(syncAuthData.Flags.UserVerified, resumedAuthData.Flags.UserVerified);
        Assert.AreEqual(syncAuthData.Flags.AttestedCredentialDataIncluded, resumedAuthData.Flags.AttestedCredentialDataIncluded);
        Assert.AreEqual(syncAuthData.Flags.ExtensionDataIncluded, resumedAuthData.Flags.ExtensionDataIncluded);
        Assert.AreEqual(syncAuthData.SignCount, resumedAuthData.SignCount);

        AttestedCredentialData resumedAttested = resumedAuthData.AttestedCredentialData!;
        AttestedCredentialData syncAttested = syncAuthData.AttestedCredentialData!;

        Assert.AreEqual(sharedAaguid, resumedAttested.Aaguid);
        Assert.AreEqual(syncAttested.Aaguid, resumedAttested.Aaguid);
        Assert.AreEqual(syncAttested.CredentialPublicKey.Kty, resumedAttested.CredentialPublicKey.Kty);
        Assert.AreEqual(syncAttested.CredentialPublicKey.Alg, resumedAttested.CredentialPublicKey.Alg);
    }


    /// <summary>A provider that denies on a later consult resolves a parked wait to a bare <see cref="WellKnownCtapStatusCodes.OperationDenied"/> envelope.</summary>
    [TestMethod]
    public async Task PollDeferredTransceiveResolvesToOperationDeniedOnLaterDenial()
    {
        int consultCount = 0;
        ValueTask<CtapUserPresenceDecision> DenyOnSecondConsultProvider(CancellationToken cancellationToken)
        {
            consultCount++;

            return ValueTask.FromResult(consultCount >= 2 ? CtapUserPresenceDecision.Denied : CtapUserPresenceDecision.Pending);
        }

        using CtapAuthenticatorSimulator simulator = CreateSimulator("up-poll-denied", simulateUserPresence: DenyOnSecondConsultProvider);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool);
        byte[] envelope = CtapWave2RequestEnvelopes.BuildMakeCredentialEnvelope(request);
        DisposeMakeCredentialRequest(request);

        using PooledMemory begin = await simulator.BeginDeferredTransceiveAsync(envelope, pool, TestContext.CancellationToken);
        Assert.AreEqual(0, begin.Length);

        using PooledMemory poll = await simulator.PollDeferredTransceiveAsync(pool, TestContext.CancellationToken);

        Assert.AreEqual(1, poll.Length);
        Assert.AreEqual(WellKnownCtapStatusCodes.OperationDenied, poll.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// <see cref="CtapAuthenticatorSimulator.CancelDeferredTransceiveAsync"/> (CTAP 2.3 :10821's
    /// authenticator-side model) resolves a parked wait to a bare <see cref="WellKnownCtapStatusCodes.KeepaliveCancel"/>
    /// envelope and discards the wait — a subsequent poll throws.
    /// </summary>
    [TestMethod]
    public async Task CancelDeferredTransceiveReturnsKeepaliveCancelAndDiscardsTheWait()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("up-cancel", simulateUserPresence: AlwaysPending);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool);
        byte[] envelope = CtapWave2RequestEnvelopes.BuildMakeCredentialEnvelope(request);
        DisposeMakeCredentialRequest(request);

        using PooledMemory begin = await simulator.BeginDeferredTransceiveAsync(envelope, pool, TestContext.CancellationToken);
        Assert.AreEqual(0, begin.Length);

        using PooledMemory cancel = await simulator.CancelDeferredTransceiveAsync(pool, TestContext.CancellationToken);
        Assert.AreEqual(1, cancel.Length);
        Assert.AreEqual(WellKnownCtapStatusCodes.KeepaliveCancel, cancel.AsReadOnlySpan()[0]);

        _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            () => simulator.PollDeferredTransceiveAsync(pool, TestContext.CancellationToken).AsTask());
    }


    /// <summary>Any new command arriving while a wait is parked (R2's supersede rule) discards the stale wait and processes normally — a subsequent poll throws.</summary>
    [TestMethod]
    public async Task NewCommandWhilePendingSupersedesAndDiscardsTheWait()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("up-supersede", simulateUserPresence: AlwaysPending);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool);
        byte[] envelope = CtapWave2RequestEnvelopes.BuildMakeCredentialEnvelope(request);
        DisposeMakeCredentialRequest(request);

        using PooledMemory begin = await simulator.BeginDeferredTransceiveAsync(envelope, pool, TestContext.CancellationToken);
        Assert.AreEqual(0, begin.Length);

        byte[] getInfoEnvelope = [WellKnownCtapCommands.GetInfo];
        using PooledMemory getInfoResponse = await simulator.TransceiveAsync(getInfoEnvelope, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, getInfoResponse.AsReadOnlySpan()[0]);

        _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            () => simulator.PollDeferredTransceiveAsync(pool, TestContext.CancellationToken).AsTask());
    }


    /// <summary><see cref="CtapAuthenticatorSimulator.PowerCycle"/> discards a parked wait (CTAP 2.3, section 6, item 1, line 2869: "state SHOULD NOT be maintained across power cycles") — a subsequent poll throws.</summary>
    [TestMethod]
    public async Task PowerCycleDiscardsThePendingWait()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("up-powercycle", simulateUserPresence: AlwaysPending);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool);
        byte[] envelope = CtapWave2RequestEnvelopes.BuildMakeCredentialEnvelope(request);
        DisposeMakeCredentialRequest(request);

        using PooledMemory begin = await simulator.BeginDeferredTransceiveAsync(envelope, pool, TestContext.CancellationToken);
        Assert.AreEqual(0, begin.Length);

        simulator.PowerCycle();

        _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            () => simulator.PollDeferredTransceiveAsync(pool, TestContext.CancellationToken).AsTask());
    }


    /// <summary><c>authenticatorReset</c> discards a parked wait — a subsequent poll throws. Driven within the 10-second power-up window (CTAP 2.3 §6.6, lines 6365-6366) via a <see cref="FakeTimeProvider"/> left unadvanced.</summary>
    [TestMethod]
    public async Task AuthenticatorResetDiscardsThePendingWait()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using CtapAuthenticatorSimulator simulator = CreateSimulator("up-reset", timeProvider: timeProvider, simulateUserPresence: AlwaysPending);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool);
        byte[] envelope = CtapWave2RequestEnvelopes.BuildMakeCredentialEnvelope(request);
        DisposeMakeCredentialRequest(request);

        using PooledMemory begin = await simulator.BeginDeferredTransceiveAsync(envelope, pool, TestContext.CancellationToken);
        Assert.AreEqual(0, begin.Length);

        byte[] resetEnvelope = [WellKnownCtapCommands.Reset];
        using PooledMemory resetResponse = await simulator.TransceiveAsync(resetEnvelope, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, resetResponse.AsReadOnlySpan()[0]);

        _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            () => simulator.PollDeferredTransceiveAsync(pool, TestContext.CancellationToken).AsTask());
    }


    /// <summary><see cref="CtapAuthenticatorSimulator.PollDeferredTransceiveAsync"/> with no wait pending throws <see cref="InvalidOperationException"/> — the internal-misuse guard.</summary>
    [TestMethod]
    public async Task PollDeferredTransceiveWithNothingPendingThrows()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("up-poll-nothing-pending");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            () => simulator.PollDeferredTransceiveAsync(pool, TestContext.CancellationToken).AsTask());
    }


    /// <summary><see cref="CtapAuthenticatorSimulator.CancelDeferredTransceiveAsync"/> with no wait pending throws <see cref="InvalidOperationException"/> — the internal-misuse guard.</summary>
    [TestMethod]
    public async Task CancelDeferredTransceiveWithNothingPendingThrows()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("up-cancel-nothing-pending");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            () => simulator.CancelDeferredTransceiveAsync(pool, TestContext.CancellationToken).AsTask());
    }


    /// <summary>A command other than <c>authenticatorMakeCredential</c>/<c>authenticatorGetAssertion</c> (here <c>authenticatorGetInfo</c>) processes synchronously through <see cref="CtapAuthenticatorSimulator.BeginDeferredTransceiveAsync"/> — it never parks, and the provider is never consulted.</summary>
    [TestMethod]
    public async Task BeginDeferredTransceiveWithGetInfoCompletesSynchronouslyWithoutConsultingProvider()
    {
        int consultCount = 0;
        ValueTask<CtapUserPresenceDecision> CountingPendingProvider(CancellationToken cancellationToken)
        {
            consultCount++;

            return ValueTask.FromResult(CtapUserPresenceDecision.Pending);
        }

        using CtapAuthenticatorSimulator simulator = CreateSimulator("up-begin-getinfo", simulateUserPresence: CountingPendingProvider);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        byte[] envelope = [WellKnownCtapCommands.GetInfo];
        using PooledMemory response = await simulator.BeginDeferredTransceiveAsync(envelope, pool, TestContext.CancellationToken);

        Assert.AreNotEqual(0, response.Length);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
        Assert.AreEqual(0, consultCount);
    }


    /// <summary>An <c>authenticatorGetAssertion</c> with <c>up:false</c> completes synchronously through <see cref="CtapAuthenticatorSimulator.BeginDeferredTransceiveAsync"/> — it never parks, since a pre-flight never consults the provider at all.</summary>
    [TestMethod]
    public async Task BeginDeferredGetAssertionWithUserPresenceFalseCompletesSynchronouslyWithoutParking()
    {
        int consultCount = 0;
        ValueTask<CtapUserPresenceDecision> CountingPendingProvider(CancellationToken cancellationToken)
        {
            consultCount++;

            return ValueTask.FromResult(CtapUserPresenceDecision.Pending);
        }

        using CtapAuthenticatorSimulator simulator = CreateSimulator("up-begin-ga-upfalse", simulateUserPresence: CountingPendingProvider);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapGetAssertionRequest request = BuildGetAssertionRequest(pool, options: new CtapCommandOptions(UserPresence: false));
        byte[] envelope = CtapWave2RequestEnvelopes.BuildGetAssertionEnvelope(request);
        DisposeGetAssertionRequest(request);

        using PooledMemory response = await simulator.BeginDeferredTransceiveAsync(envelope, pool, TestContext.CancellationToken);

        Assert.AreNotEqual(0, response.Length, "up:false must never park.");
        Assert.AreEqual(WellKnownCtapStatusCodes.NoCredentials, response.AsReadOnlySpan()[0]);
        Assert.AreEqual(0, consultCount, "up:false must never consult the user-presence provider.");
    }


    /// <summary>Always answers <see cref="CtapUserPresenceDecision.Pending"/> — a never-granting provider.</summary>
    private static ValueTask<CtapUserPresenceDecision> AlwaysPending(CancellationToken cancellationToken) =>
        ValueTask.FromResult(CtapUserPresenceDecision.Pending);


    /// <summary>Always answers <see cref="CtapUserPresenceDecision.Denied"/>.</summary>
    private static ValueTask<CtapUserPresenceDecision> AlwaysDenied(CancellationToken cancellationToken) =>
        ValueTask.FromResult(CtapUserPresenceDecision.Denied);


    /// <summary>Always throws — proves the seam is never consulted on the path under test.</summary>
    private static ValueTask<CtapUserPresenceDecision> AlwaysThrow(CancellationToken cancellationToken) =>
        throw new InvalidOperationException("The user-presence provider must not be consulted on this path.");


    /// <summary>Builds <paramref name="count"/> credential descriptors naming credential IDs this authenticator never minted, distinguished by <paramref name="seed"/> — used to exercise R5's count bound without needing any of the entries to actually match.</summary>
    private static List<PublicKeyCredentialDescriptor> BuildDummyDescriptors(MemoryPool<byte> pool, int count, byte seed)
    {
        var descriptors = new List<PublicKeyCredentialDescriptor>();
        for(int i = 0; i < count; i++)
        {
            descriptors.Add(new PublicKeyCredentialDescriptor
            {
                Type = WellKnownPublicKeyCredentialTypes.PublicKey,
                Id = CredentialId.Create(BuildFixedBytes(32, (byte)(seed + i)), pool)
            });
        }

        return descriptors;
    }
}
