using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Verifiable.Cbor.Ctap;
using Verifiable.Cbor.Fido2;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.Foundation.Automata;
using Verifiable.Tests.TestInfrastructure;
using static Verifiable.Tests.TestInfrastructure.CtapWave2AuthenticatorFixtures;
using static Verifiable.Tests.TestInfrastructure.CtapWaveBioFixtures;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// The wavebio PKG-C unit-test matrix for the built-in-UV cluster (R9/R10/R11):
/// <c>getPinUvAuthTokenUsingUvWithPermissions</c>'s (<c>0x06</c>) own seventeen-step algorithm,
/// <c>performBuiltInUv</c>'s counter/retry/lockout machinery, and <c>authenticatorMakeCredential</c>/
/// <c>authenticatorGetAssertion</c>'s <c>options.uv</c> built-in-UV branches. Driven in-process through
/// <see cref="CtapAuthenticatorSimulator.TransceiveAsync"/>, mirroring
/// <see cref="CtapAuthenticatorBioEnrollmentTests"/>'s conventions: every fingerprint enrollment this
/// file needs is completed for real through <c>authenticatorBioEnrollment</c>, never injected as
/// internal state. Every assertion reads the response's own decoded wire bytes, except the two
/// <c>userPresent</c> assertions, which read <see cref="CtapPinUvAuthTokenState.UserPresent"/> off a
/// subscribed <see cref="TraceEntry{TState, TInput}"/> — the ONE token-lifecycle fact this codebase
/// exposes no wire-visible signal for at all (<c>getUserPresentFlagValue()</c> is never consulted by any
/// mc/ga path, since evidence of user interaction is unconditionally granted), mirroring
/// <c>CtapAuthenticatorPinTokenIssuanceTests</c>'s own precedent for the identical situation.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorBuiltInUvTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The plaintext PIN every test establishes.</summary>
    private const string DefaultPin = "1234";

    /// <summary>The PIN/UV auth protocol every test uses unless a scenario specifically needs the other one.</summary>
    private const CtapPinUvAuthProtocolId DefaultProtocol = CtapPinUvAuthProtocolId.Two;

    /// <summary><c>acfg</c>'s wire value, mirrored as a compile-time constant for <c>[DataRow]</c> (<see cref="WellKnownCtapPinUvAuthTokenPermissions.Acfg"/> is a getter, not a const).</summary>
    private const int AcfgPermission = 0x20;

    /// <summary><c>pcmr</c>'s wire value — see <see cref="AcfgPermission"/>'s own remark.</summary>
    private const int PcmrPermission = 0x40;

    /// <summary>The fixed <c>clientDataHash</c> pattern <see cref="CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest"/> uses internally (seed <c>0x10</c>).</summary>
    private static byte[] McClientDataHash => BuildFixedBytes(32, 0x10);


    /// <summary>
    /// Replaces the flip half of <c>CtapAuthenticatorClientPinTests.UnsupportedSubCommandReturnsInvalidSubcommand</c>'s
    /// removed <c>DataRow(0x06)</c> case (R14): 0x06 is no longer an unsupported subcommand — it now runs
    /// its own full seventeen-step algorithm, and answers <see cref="WellKnownCtapStatusCodes.NotAllowed"/>
    /// here because the built-in UV method is supported but not yet configured (zero fingerprint
    /// enrollments), CTAP 2.3 §6.5.5.7.3 step 5 (snapshot lines 6077-6079) — DISTINCT from mc/ga's own
    /// <see cref="WellKnownCtapStatusCodes.InvalidOption"/> for the identical underlying state (uv scout
    /// trap 7, proven separately by <see cref="MakeCredentialOptionsUvTrueWithoutEnrollmentReturnsInvalidOption"/>).
    /// </summary>
    [TestMethod]
    public async Task GetPinUvAuthTokenUsingUvWithPermissionsWithoutEnrollmentsReturnsNotAllowed()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using CtapAuthenticatorSimulator simulator = CreateSimulator("0x06-not-configured");
        await CtapWaveConfigFixtures.EstablishPinAsync(simulator, pool, DefaultProtocol, DefaultPin, TestContext.CancellationToken);

        byte status = await SendUvTokenRequestExpectingErrorAsync(simulator, pool, WellKnownCtapPinUvAuthTokenPermissions.Be);

        Assert.AreEqual(WellKnownCtapStatusCodes.NotAllowed, status);
    }


    /// <summary>
    /// 0x06's OWN permission-statement gate (R5, §6.5.5.7.3 lines 6063-6075) denies <c>acfg</c>/
    /// <c>pcmr</c> unconditionally — a SEPARATE statement list from the PIN path's own gate (uv scout
    /// trap 4), never conflated. <c>lbw</c> is EXCLUDED from this set post-wavelb: line 6070's bullet
    /// ("largeBlobs is false or absent") never holds once <c>largeBlobs:true</c> is advertised
    /// unconditionally, so <c>lbw</c> is now grantable on this path too — proven separately by
    /// <see cref="GetPinUvAuthTokenUsingUvWithPermissionsGrantsLbwAlone"/>.
    /// </summary>
    [TestMethod]
    [DataRow(AcfgPermission, DisplayName = "acfg")]
    [DataRow(PcmrPermission, DisplayName = "pcmr")]
    public async Task GetPinUvAuthTokenUsingUvWithPermissionsRequestingDeniedPermissionReturnsUnauthorizedPermission(int deniedPermission)
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using CtapAuthenticatorSimulator simulator = await CreateEnrolledSimulatorAsync($"0x06-denied-{deniedPermission:X2}", pool);

        byte status = await SendUvTokenRequestExpectingErrorAsync(simulator, pool, deniedPermission);

        Assert.AreEqual(WellKnownCtapStatusCodes.UnauthorizedPermission, status);
    }


    /// <summary>
    /// <c>lbw</c> requested alone via <c>getPinUvAuthTokenUsingUvWithPermissions</c> is granted (wavelb
    /// R4: no <c>uvLargeBlobs</c> analogue exists, so the SAME <c>largeBlobs:true</c> getInfo flip that
    /// grants it on the PIN path grants it here too) with NO <c>rpId</c> — <c>lbw</c>'s own RP ID column
    /// is "Ignored" (line 5808).
    /// </summary>
    [TestMethod]
    public async Task GetPinUvAuthTokenUsingUvWithPermissionsGrantsLbwAlone()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using CtapAuthenticatorSimulator simulator = await CreateEnrolledSimulatorAsync("0x06-grants-lbw-alone", pool);

        var trace = new TestObserver<TraceEntry<CtapAuthenticatorState, CtapAuthenticatorInput>>();
        using(simulator.Subscribe(trace))
        {
            _ = await IssueUvTokenAsync(simulator, pool, WellKnownCtapPinUvAuthTokenPermissions.Lbw);
        }

        Assert.AreEqual(
            WellKnownCtapPinUvAuthTokenPermissions.Lbw,
            trace.Received[^1].StateAfter.ProtocolTwoToken.Permissions,
            "lbw requested alone, with no rpId, must be granted exactly lbw.");
    }


    /// <summary>
    /// A successful 0x06 issuance grants exactly the requested permissions and associates the requested
    /// <c>rpId</c> — proven wire-observably by the minted token succeeding at <c>authenticatorMakeCredential</c>
    /// against the matching RP.
    /// </summary>
    [TestMethod]
    public async Task GetPinUvAuthTokenUsingUvWithPermissionsGrantsRequestedPermissionsAndAssociatesRpId()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using CtapAuthenticatorSimulator simulator = await CreateEnrolledSimulatorAsync("0x06-grants-permissions-rpid", pool);

        byte[] token = await IssueUvTokenAsync(simulator, pool, WellKnownCtapPinUvAuthTokenPermissions.Mc, rpId: DefaultRpId);

        byte[] mcParam = await CtapWaveConfigFixtures.ComputeSignatureAsync(token, DefaultProtocol, McClientDataHash, pool, TestContext.CancellationToken);
        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, pinUvAuthParam: mcParam, pinUvAuthProtocol: (int)DefaultProtocol);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0], "the granted mc permission and associated rpId must both take effect.");
    }


    /// <summary>
    /// A 0x06-minted token begins using with <c>userIsPresent</c> already TRUE (steps 13-14, the
    /// simulated fingerprint touch supplies evidence of user interaction); a PIN-path-minted token still
    /// begins with FALSE (uv scout delta (a)).
    /// </summary>
    [TestMethod]
    public async Task GetPinUvAuthTokenUsingUvWithPermissionsMintsTokenWithUserPresentTrueUnlikePinPathToken()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using CtapAuthenticatorSimulator simulator = await CreateEnrolledSimulatorAsync("0x06-userpresent-true", pool);

        var pinPathTrace = new TestObserver<TraceEntry<CtapAuthenticatorState, CtapAuthenticatorInput>>();
        using(simulator.Subscribe(pinPathTrace))
        {
            _ = await CtapWaveConfigFixtures.IssueTokenAsync(
                simulator, pool, DefaultProtocol, DefaultPin, WellKnownCtapPinUvAuthTokenPermissions.Mc, DefaultRpId, TestContext.CancellationToken);
        }
        Assert.IsFalse(pinPathTrace.Received[^1].StateAfter.ProtocolTwoToken.UserPresent, "a PIN-path-minted token must begin using with userIsPresent false.");

        var uvPathTrace = new TestObserver<TraceEntry<CtapAuthenticatorState, CtapAuthenticatorInput>>();
        using(simulator.Subscribe(uvPathTrace))
        {
            _ = await IssueUvTokenAsync(simulator, pool, WellKnownCtapPinUvAuthTokenPermissions.Be);
        }
        Assert.IsTrue(
            uvPathTrace.Received[^1].StateAfter.ProtocolTwoToken.UserPresent,
            "a 0x06-minted token must begin using with userIsPresent true — the simulated gesture supplies evidence of user interaction.");
    }


    /// <summary>
    /// 0x06's own step 12 (<c>resetPinUvAuthToken()</c> "for all") invalidates EVERY existing token for
    /// EVERY supported protocol — including a protocol-one token minted earlier — even though 0x06 itself
    /// was minted under protocol two here.
    /// </summary>
    [TestMethod]
    public async Task GetPinUvAuthTokenUsingUvWithPermissionsInvalidatesEveryExistingTokenForAllProtocols()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using CtapAuthenticatorSimulator simulator = await CreateEnrolledSimulatorAsync("0x06-resets-all-protocols", pool);

        byte[] protocolOneMcToken = await CtapWaveConfigFixtures.IssueTokenAsync(
            simulator, pool, CtapPinUvAuthProtocolId.One, DefaultPin, WellKnownCtapPinUvAuthTokenPermissions.Mc, DefaultRpId, TestContext.CancellationToken);

        _ = await IssueUvTokenAsync(simulator, pool, WellKnownCtapPinUvAuthTokenPermissions.Be);

        byte[] mcParam = await CtapWaveConfigFixtures.ComputeSignatureAsync(
            protocolOneMcToken, CtapPinUvAuthProtocolId.One, McClientDataHash, pool, TestContext.CancellationToken);
        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, pinUvAuthParam: mcParam, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.One);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(
            WellKnownCtapStatusCodes.PinAuthInvalid, response.AsReadOnlySpan()[0],
            "0x06's resetPinUvAuthToken() step invalidates every existing token for every supported protocol, including protocol one's earlier mc token.");
    }


    /// <summary>
    /// A repeated <c>MatchFailure</c> outcome decrements <c>uvRetries</c> one attempt at a time
    /// (<see cref="CtapAuthenticatorState.PreferredPlatformUvAttempts"/> is 3, so 0x06's own
    /// <c>internalRetry</c> is <see langword="false"/> — a single attempt per call): every call while
    /// <c>uvRetries</c> stays above zero answers <see cref="WellKnownCtapStatusCodes.UvInvalid"/>; the
    /// call whose OWN decrement lands exactly on zero answers <see cref="WellKnownCtapStatusCodes.UvBlocked"/>
    /// instead (not <c>UvInvalid</c>); a further call once already zero hits the pre-check (step 7) and
    /// answers <c>UvBlocked</c> again, with no further decrement.
    /// </summary>
    [TestMethod]
    public async Task GetPinUvAuthTokenUsingUvWithPermissionsMatchFailureLadderReachesBlockedThenStaysBlocked()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using CtapAuthenticatorSimulator simulator = await CreateEnrolledSimulatorAsync(
            "0x06-match-failure-ladder", pool, simulateBuiltInUv: static () => CtapBuiltInUvAttemptOutcome.MatchFailure);

        for(int call = 1; call < CtapAuthenticatorState.MaxUvRetries; call++)
        {
            byte status = await SendUvTokenRequestExpectingErrorAsync(simulator, pool, WellKnownCtapPinUvAuthTokenPermissions.Be);
            Assert.AreEqual(WellKnownCtapStatusCodes.UvInvalid, status, $"call {call}: uvRetries is still nonzero after this decrement, so the answer must be UvInvalid.");
        }

        byte finalDecrementStatus = await SendUvTokenRequestExpectingErrorAsync(simulator, pool, WellKnownCtapPinUvAuthTokenPermissions.Be);
        Assert.AreEqual(WellKnownCtapStatusCodes.UvBlocked, finalDecrementStatus, "the decrement that brings uvRetries to exactly zero must answer UvBlocked, not UvInvalid.");

        byte preCheckStatus = await SendUvTokenRequestExpectingErrorAsync(simulator, pool, WellKnownCtapPinUvAuthTokenPermissions.Be);
        Assert.AreEqual(WellKnownCtapStatusCodes.UvBlocked, preCheckStatus, "0x06's own step-7 pre-check must reject with UvBlocked once uvRetries is already zero, before any further attempt.");

        Assert.AreEqual(0, await GetUvRetriesAsync(simulator, pool));
    }


    /// <summary>
    /// A <see cref="CtapBuiltInUvAttemptOutcome.UserActionTimeout"/> outcome answers
    /// <see cref="WellKnownCtapStatusCodes.UserActionTimeout"/> and still consumes the decrement already
    /// applied before the attempt (§6.5.3.1 step 5 precedes step 8's timeout check).
    /// </summary>
    [TestMethod]
    public async Task GetPinUvAuthTokenUsingUvWithPermissionsTimeoutReturnsUserActionTimeoutAndConsumesOneDecrement()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using CtapAuthenticatorSimulator simulator = await CreateEnrolledSimulatorAsync(
            "0x06-timeout", pool, simulateBuiltInUv: static () => CtapBuiltInUvAttemptOutcome.UserActionTimeout);

        byte status = await SendUvTokenRequestExpectingErrorAsync(simulator, pool, WellKnownCtapPinUvAuthTokenPermissions.Be);

        Assert.AreEqual(WellKnownCtapStatusCodes.UserActionTimeout, status);
        Assert.AreEqual(CtapAuthenticatorState.MaxUvRetries - 1, await GetUvRetriesAsync(simulator, pool));
    }


    /// <summary>
    /// <see cref="CtapAuthenticatorState.PreferredPlatformUvAttempts"/> is 3 (greater than 1), so 0x06's
    /// own step 6 computes <c>internalRetry</c> as <see langword="false"/> — <c>performBuiltInUv</c>
    /// attempts exactly ONCE per 0x06 call, proven by counting <see cref="SimulateBuiltInUvDelegate"/>
    /// invocations directly.
    /// </summary>
    [TestMethod]
    public async Task GetPinUvAuthTokenUsingUvWithPermissionsAttemptsExactlyOnceSinceInternalRetryIsFalse()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        int invocationCount = 0;
        CtapBuiltInUvAttemptOutcome CountingSimulateBuiltInUv()
        {
            invocationCount++;

            return CtapBuiltInUvAttemptOutcome.MatchFailure;
        }

        using CtapAuthenticatorSimulator simulator = await CreateEnrolledSimulatorAsync("0x06-single-attempt", pool, CountingSimulateBuiltInUv);

        _ = await SendUvTokenRequestExpectingErrorAsync(simulator, pool, WellKnownCtapPinUvAuthTokenPermissions.Be);

        Assert.AreEqual(1, invocationCount);
    }


    /// <summary>
    /// R10's cross-counter step 3: once <c>pinRetries</c> reaches zero while a PIN remains SET,
    /// <c>performBuiltInUv</c> drags <c>uvRetries</c> straight to zero and returns an error WITHOUT ever
    /// consulting <see cref="SimulateBuiltInUvDelegate"/> — proven here by the default always-succeeding
    /// delegate never actually succeeding.
    /// </summary>
    [TestMethod]
    public async Task PerformBuiltInUvPinLockoutDragsUvRetriesToZero()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using CtapAuthenticatorSimulator simulator = await CreateEnrolledSimulatorAsync("0x06-pin-lockout-dragdown", pool);

        await DrainPinRetriesToZeroAsync(simulator, pool);
        Assert.AreEqual(
            CtapAuthenticatorState.MaxUvRetries, await GetUvRetriesAsync(simulator, pool),
            "pinRetries decrementing on its own must not touch uvRetries — the drag-down only fires on the NEXT performBuiltInUv attempt.");

        byte status = await SendUvTokenRequestExpectingErrorAsync(simulator, pool, WellKnownCtapPinUvAuthTokenPermissions.Be);

        Assert.AreEqual(WellKnownCtapStatusCodes.UvBlocked, status);
        Assert.AreEqual(0, await GetUvRetriesAsync(simulator, pool));
    }


    /// <summary>
    /// Line 5071-5072: a correct clientPIN entry restores <c>uvRetries</c> alongside <c>pinRetries</c> —
    /// proven here via <c>getPinUvAuthTokenUsingPinWithPermissions</c> (0x09) issuance succeeding after a
    /// decremented <c>uvRetries</c>.
    /// </summary>
    [TestMethod]
    public async Task CorrectPinEntryRestoresUvRetriesAlongsidePinRetries()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using CtapAuthenticatorSimulator simulator = await CreateEnrolledSimulatorAsync(
            "0x06-pin-restore", pool, simulateBuiltInUv: static () => CtapBuiltInUvAttemptOutcome.MatchFailure);

        _ = await SendUvTokenRequestExpectingErrorAsync(simulator, pool, WellKnownCtapPinUvAuthTokenPermissions.Be);
        Assert.AreEqual(CtapAuthenticatorState.MaxUvRetries - 1, await GetUvRetriesAsync(simulator, pool));

        _ = await CtapWaveConfigFixtures.IssueTokenAsync(
            simulator, pool, DefaultProtocol, DefaultPin, WellKnownCtapPinUvAuthTokenPermissions.Mc, DefaultRpId, TestContext.CancellationToken);

        Assert.AreEqual(CtapAuthenticatorState.MaxUvRetries, await GetUvRetriesAsync(simulator, pool));
    }


    /// <summary>R11's live flip of mc's step 5.3: <c>uv:true</c> with zero enrollments (not configured) answers <see cref="WellKnownCtapStatusCodes.InvalidOption"/> — DISTINCT from 0x06's own <c>NotAllowed</c> for the identical state.</summary>
    [TestMethod]
    public async Task MakeCredentialOptionsUvTrueWithoutEnrollmentReturnsInvalidOption()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using CtapAuthenticatorSimulator simulator = CreateSimulator("mc-uv-unconfigured");
        await CtapWaveConfigFixtures.EstablishPinAsync(simulator, pool, DefaultProtocol, DefaultPin, TestContext.CancellationToken);

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, options: new CtapCommandOptions(UserVerification: true));
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidOption, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// R11's mc step 11.2, HARDCODED <c>internalRetry: true</c>: a scripted [<c>MatchFailure</c>,
    /// <c>Success</c>] sequence consumes TWO decrements inside the SAME mc call and still succeeds — the
    /// response's own <c>uv</c> bit is set, and a successful gesture resets <c>uvRetries</c> to its
    /// maximum.
    /// </summary>
    [TestMethod]
    public async Task MakeCredentialOptionsUvTrueSucceedsAfterOneInternalFailureAndResetsUvRetries()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var scriptedOutcomes = new Queue<CtapBuiltInUvAttemptOutcome>([CtapBuiltInUvAttemptOutcome.MatchFailure, CtapBuiltInUvAttemptOutcome.Success]);
        int invocationCount = 0;
        CtapBuiltInUvAttemptOutcome SimulateScriptedSequence()
        {
            invocationCount++;

            return scriptedOutcomes.Dequeue();
        }

        using CtapAuthenticatorSimulator simulator = await CreateEnrolledSimulatorAsync("mc-uv-internal-retry", pool, SimulateScriptedSequence);

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, userId: BuildFixedBytes(16, 0x51), options: new CtapCommandOptions(UserVerification: true));
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
        Assert.AreEqual(
            2, invocationCount,
            "maxUvAttemptsForInternalRetries is 2 and mc's own internalRetry is hardcoded true — one internal failure must still succeed within the SAME mc call.");

        CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(decoded.AuthData, CredentialPublicKeyCborReader.Read, pool);
        Assert.IsTrue(authenticatorData.Flags.UserVerified, "a successful built-in UV attempt must set the uv bit.");

        Assert.AreEqual(CtapAuthenticatorState.MaxUvRetries, await GetUvRetriesAsync(simulator, pool), "a successful performBuiltInUv gesture resets uvRetries to its maximum.");
    }


    /// <summary>
    /// The mc/ga <c>options.uv = true</c> error ladder's own <c>uvRetries == 0</c> arm
    /// (<see cref="WellKnownCtapStatusCodes.PinBlocked"/>) is documented UNREACHABLE in this profile: the
    /// only route to a first fingerprint enrollment is the PIN-path <c>be</c> token, so <c>clientPin</c>
    /// is always set whenever built-in UV is configured, and the ladder's earlier
    /// <see cref="WellKnownCtapStatusCodes.PuatRequired"/> arm always intercepts first (R11).
    /// </summary>
    [TestMethod]
    public async Task GetAssertionOptionsUvTrueWithUvRetriesExhaustedReturnsPuatRequiredNotPinBlocked()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using CtapAuthenticatorSimulator simulator = await CreateEnrolledSimulatorAsync(
            "ga-uv-lockout", pool, simulateBuiltInUv: static () => CtapBuiltInUvAttemptOutcome.MatchFailure);

        for(int call = 0; call < CtapAuthenticatorState.MaxUvRetries; call++)
        {
            _ = await SendUvTokenRequestExpectingErrorAsync(simulator, pool, WellKnownCtapPinUvAuthTokenPermissions.Be);
        }
        Assert.AreEqual(0, await GetUvRetriesAsync(simulator, pool));

        CtapGetAssertionRequest request = BuildGetAssertionRequest(pool, options: new CtapCommandOptions(UserVerification: true));
        using PooledMemory response = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PuatRequired, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// R11's live sub-step (mc 6.3/ga 5.4): once built-in UV is configured, <c>alwaysUv</c> force-upgrades
    /// a param-absent, <c>uv</c>-absent mc request to effective <c>uv:true</c> — the call succeeds via
    /// forced built-in UV, with the response's own <c>uv</c> bit set, even though the platform requested
    /// neither <c>pinUvAuthParam</c> nor <c>options.uv</c> at all.
    /// </summary>
    [TestMethod]
    public async Task MakeCredentialAlwaysUvForcesBuiltInUvWhenNeitherParamNorUvRequested()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using CtapAuthenticatorSimulator simulator = CreateSimulator("mc-alwaysuv-forced-uv");

        var enableRequest = new CtapAuthenticatorConfigRequest(SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv);
        using(PooledMemory enableResponse = await CtapWaveConfigFixtures.SendAuthenticatorConfigAsync(simulator, enableRequest, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, enableResponse.AsReadOnlySpan()[0]);
        }

        await CtapWaveConfigFixtures.EstablishPinAsync(simulator, pool, DefaultProtocol, DefaultPin, TestContext.CancellationToken);
        byte[] beToken = await CtapWaveConfigFixtures.IssueTokenAsync(
            simulator, pool, DefaultProtocol, DefaultPin, WellKnownCtapPinUvAuthTokenPermissions.Be, rpId: null, TestContext.CancellationToken);
        await CompleteEnrollmentAsync(simulator, pool, beToken);

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, userId: BuildFixedBytes(16, 0x52));
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(
            WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0],
            "alwaysUv's own forcing sub-step must upgrade uv to true once built-in UV is configured, even though neither pinUvAuthParam nor options.uv was requested.");

        CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(decoded.AuthData, CredentialPublicKeyCborReader.Read, pool);
        Assert.IsTrue(authenticatorData.Flags.UserVerified);
    }


    /// <summary>
    /// R11's REQUIRED credProtect test: a level-3 (<c>userVerificationRequired</c>) discoverable
    /// credential stays invisible to a UV-less discoverable-scan <c>ga</c> call, then becomes visible
    /// through a built-in-UV <c>ga</c> call — no token anywhere in the request — proving
    /// <c>userVerified</c>'s new built-in-UV source threads unchanged through the existing credProtect
    /// filter.
    /// </summary>
    [TestMethod]
    public async Task GetAssertionLevelThreeCredProtectInvisibleWithoutUvVisibleThroughBuiltInUv()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using CtapAuthenticatorSimulator simulator = CreateSimulator("ga-level3-credprotect-uv");

        CtapWave2RegisteredCredential registered = await RegisterCredentialAsync(
            simulator, pool, BuildFixedBytes(16, 0x60), TestContext.CancellationToken, credProtect: 3);

        await CtapWaveConfigFixtures.EstablishPinAsync(simulator, pool, DefaultProtocol, DefaultPin, TestContext.CancellationToken);
        byte[] beToken = await CtapWaveConfigFixtures.IssueTokenAsync(
            simulator, pool, DefaultProtocol, DefaultPin, WellKnownCtapPinUvAuthTokenPermissions.Be, rpId: null, TestContext.CancellationToken);
        await CompleteEnrollmentAsync(simulator, pool, beToken);

        CtapGetAssertionRequest noUvRequest = BuildGetAssertionRequest(pool);
        using(PooledMemory noUvResponse = await SendGetAssertionAsync(simulator, noUvRequest, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(
                WellKnownCtapStatusCodes.NoCredentials, noUvResponse.AsReadOnlySpan()[0],
                "a level-3 credProtect discoverable credential must stay invisible to a UV-less ga scan.");
        }

        CtapGetAssertionRequest uvRequest = BuildGetAssertionRequest(pool, options: new CtapCommandOptions(UserVerification: true));
        using PooledMemory uvResponse = await SendGetAssertionAsync(simulator, uvRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(
            WellKnownCtapStatusCodes.Ok, uvResponse.AsReadOnlySpan()[0],
            "the SAME credential must become visible via a built-in-UV ga call, with no pinUvAuthToken in the request at all.");

        registered.CredentialId.Dispose();
    }


    /// <summary>
    /// Establishes <see cref="DefaultPin"/> on <see cref="DefaultProtocol"/>, issues a <c>be</c>-only
    /// token, and completes exactly one fingerprint enrollment through real
    /// <c>authenticatorBioEnrollment</c> traffic — the shared setup every built-in-UV test needs before
    /// <c>uv</c>/<c>bioEnroll</c> can ever be observed <see langword="true"/>.
    /// </summary>
    /// <param name="runId">The simulator's own run identifier.</param>
    /// <param name="pool">The memory pool every allocation uses.</param>
    /// <param name="simulateBuiltInUv">The R8 outcome-injection knob to compose the simulator with, or <see langword="null"/> for the always-succeeding default.</param>
    /// <returns>The enrolled simulator. The caller owns it and must dispose it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the returned CtapAuthenticatorSimulator transfers to the caller, which every call site wraps in its own using declaration.")]
    private async Task<CtapAuthenticatorSimulator> CreateEnrolledSimulatorAsync(string runId, MemoryPool<byte> pool, SimulateBuiltInUvDelegate? simulateBuiltInUv = null)
    {
        CtapAuthenticatorSimulator simulator = CreateSimulator(runId, simulateBuiltInUv: simulateBuiltInUv);
        await CtapWaveConfigFixtures.EstablishPinAsync(simulator, pool, DefaultProtocol, DefaultPin, TestContext.CancellationToken);
        byte[] beToken = await CtapWaveConfigFixtures.IssueTokenAsync(
            simulator, pool, DefaultProtocol, DefaultPin, WellKnownCtapPinUvAuthTokenPermissions.Be, rpId: null, TestContext.CancellationToken);
        await CompleteEnrollmentAsync(simulator, pool, beToken);

        return simulator;
    }


    /// <summary>
    /// Drives one complete enrollment lifecycle over real <c>authenticatorBioEnrollment</c> traffic — one
    /// <c>enrollBegin</c> plus enough <c>enrollCaptureNextSample</c> calls (the default always-GOOD
    /// simulated sensor) to reach <c>remainingSamples</c> zero — mirroring
    /// <c>CtapAuthenticatorBioEnrollmentTests.CompleteEnrollmentAsync</c>'s own shape.
    /// </summary>
    private async Task CompleteEnrollmentAsync(CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool, byte[] beToken)
    {
        byte[] beginParam = await ComputeBioMessageSignatureAsync(beToken, WellKnownCtapBioEnrollmentSubCommands.EnrollBegin, ReadOnlyMemory<byte>.Empty, pool);
        var beginRequest = new CtapBioEnrollmentRequest(
            Modality: WellKnownCtapBioEnrollmentModalities.Fingerprint, SubCommand: WellKnownCtapBioEnrollmentSubCommands.EnrollBegin,
            PinUvAuthProtocol: (int)DefaultProtocol, PinUvAuthParam: beginParam);
        byte[] templateId;
        using(PooledMemory beginResponse = await SendBioEnrollmentAsync(simulator, beginRequest, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, beginResponse.AsReadOnlySpan()[0]);
            templateId = CtapBioEnrollmentResponseCborReader.Read(beginResponse.AsReadOnlyMemory()[1..]).TemplateId!.Value.ToArray();
        }

        for(int sample = 1; sample < CtapAuthenticatorState.MaxCaptureSamplesRequiredForEnroll; sample++)
        {
            byte[] subCommandParams = BuildSubCommandParams(templateId: templateId);
            byte[] captureParam = await ComputeBioMessageSignatureAsync(beToken, WellKnownCtapBioEnrollmentSubCommands.EnrollCaptureNextSample, subCommandParams, pool);
            var captureRequest = new CtapBioEnrollmentRequest(
                Modality: WellKnownCtapBioEnrollmentModalities.Fingerprint, SubCommand: WellKnownCtapBioEnrollmentSubCommands.EnrollCaptureNextSample,
                TemplateId: templateId, PinUvAuthProtocol: (int)DefaultProtocol, PinUvAuthParam: captureParam);
            using PooledMemory captureResponse = await SendBioEnrollmentAsync(simulator, captureRequest, pool, TestContext.CancellationToken);
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, captureResponse.AsReadOnlySpan()[0]);
        }
    }


    /// <summary>Computes a gated bioEnrollment subcommand's own <c>pinUvAuthParam</c> (the TWO-byte <c>modality || subCommand [|| subCommandParams]</c> prefix).</summary>
    private async Task<byte[]> ComputeBioMessageSignatureAsync(byte[] token, int subCommand, ReadOnlyMemory<byte> subCommandParams, MemoryPool<byte> pool)
    {
        byte[] message = BuildMessage(WellKnownCtapBioEnrollmentModalities.Fingerprint, subCommand, subCommandParams);

        return await CtapWaveConfigFixtures.ComputeSignatureAsync(token, DefaultProtocol, message, pool, TestContext.CancellationToken);
    }


    /// <summary>Issues a permissions-scoped <c>pinUvAuthToken</c> via 0x06 under <see cref="DefaultProtocol"/>.</summary>
    private async Task<byte[]> IssueUvTokenAsync(CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool, int permissions, string? rpId = null) =>
        await CtapWaveConfigFixtures.IssueUvTokenAsync(simulator, pool, DefaultProtocol, permissions, rpId, TestContext.CancellationToken);


    /// <summary>Sends a 0x06 request under <see cref="DefaultProtocol"/> expecting it to fail, returning the exact CTAP2 status code.</summary>
    private async Task<byte> SendUvTokenRequestExpectingErrorAsync(CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool, int? permissions, string? rpId = null)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, DefaultProtocol, pool, TestContext.CancellationToken);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingUvWithPermissions,
            PinUvAuthProtocol: (int)DefaultProtocol, KeyAgreement: session.PlatformPublicKeyCose,
            Permissions: permissions, RpId: rpId);

        return await CtapWaveConfigFixtures.SendClientPinExpectingErrorAsync(simulator, request, pool, TestContext.CancellationToken);
    }


    /// <summary>Reports the live <c>uvRetries</c> counter via <c>getUVRetries</c> (already-shipped, 0x07).</summary>
    private async Task<int> GetUvRetriesAsync(CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool)
    {
        var request = new CtapClientPinRequest(SubCommand: WellKnownCtapClientPinSubCommands.GetUvRetries);
        CtapClientPinResponse response = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            simulator.TransceiveAsync, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, TestContext.CancellationToken);

        return response.UvRetries!.Value;
    }


    /// <summary>
    /// Drives <c>pinRetries</c> to exactly zero via repeated wrong-PIN <c>getPinToken</c> attempts,
    /// power-cycling (clearing only the 3-consecutive-mismatch latch, never <c>pinRetries</c> itself)
    /// whenever the latch fires so the drain can continue — the PIN stays SET throughout (only
    /// <c>pinRetries</c> reaches zero, never <see cref="CtapAuthenticatorState.CurrentStoredPin"/>).
    /// </summary>
    private async Task DrainPinRetriesToZeroAsync(CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool)
    {
        while(true)
        {
            var retriesRequest = new CtapClientPinRequest(SubCommand: WellKnownCtapClientPinSubCommands.GetPinRetries);
            CtapClientPinResponse retriesResponse = await CtapAuthenticatorClientPinClient.ClientPinAsync(
                simulator.TransceiveAsync, CtapClientPinRequestCborWriter.Write, retriesRequest, CtapClientPinResponseCborReader.Read, pool, TestContext.CancellationToken);
            if(retriesResponse.PinRetries == 0)
            {
                return;
            }

            using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
                simulator.TransceiveAsync, DefaultProtocol, pool, TestContext.CancellationToken);
            byte[] wrongPinHashEnc = await session.BuildWrongPinHashEncAsync(TestContext.CancellationToken);

            var request = new CtapClientPinRequest(
                SubCommand: WellKnownCtapClientPinSubCommands.GetPinToken, PinUvAuthProtocol: (int)DefaultProtocol,
                KeyAgreement: session.PlatformPublicKeyCose, PinHashEnc: wrongPinHashEnc);

            try
            {
                _ = await CtapAuthenticatorClientPinClient.ClientPinAsync(
                    simulator.TransceiveAsync, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, TestContext.CancellationToken);
            }
            catch(CtapCommandException exception) when(exception.StatusCode == WellKnownCtapStatusCodes.PinAuthBlocked)
            {
                simulator.PowerCycle();
            }
            catch(CtapCommandException)
            {
            }
        }
    }
}
