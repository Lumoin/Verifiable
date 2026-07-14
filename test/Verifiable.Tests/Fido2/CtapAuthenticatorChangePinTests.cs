using System.Buffers;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cbor.Ctap;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.Foundation.Automata;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="CtapAuthenticatorSimulator"/>'s <c>authenticatorClientPIN</c> <c>changePIN</c>
/// (<c>0x04</c>) subcommand (CTAP 2.3 §6.5.5.6): the pure pre-checks in spec order (including the
/// wave-5b no-PIN ruling and the power-cycle latch precedence), the verify-failure-does-not-decrement
/// versus mismatch-does-decrement distinction, the consecutive-mismatch trilogy through
/// <c>PinInvalid</c>/<c>PinBlocked</c>/<c>PinAuthBlocked</c>, the selected-protocol-only
/// <c>regenerate()</c>, and the success tail's system-wide <c>pinUvAuthToken</c> invalidation.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorChangePinTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>A correct current PIN and a valid new PIN succeed (CTAP2_OK) and the new PIN becomes usable for a later <c>changePIN</c>.</summary>
    [TestMethod]
    public async Task ChangePinHappyPathSucceeds()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("changepin-happy");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        (byte[] newPinEnc, byte[] pinHashEnc, byte[] pinUvAuthParam) =
            await session.BuildChangePinMessagesAsync("5678", "1234", TestContext.CancellationToken);

        var request = BuildRequest(session, newPinEnc, pinHashEnc, pinUvAuthParam);
        CtapClientPinResponse response = await SendAsync(simulator, request, pool);
        Assert.IsNull(response.PinUvAuthToken);

        //The new PIN "5678" must now be the one changePIN accepts as the current PIN.
        using CtapWave5bPlatformPinSession secondSession = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        (byte[] secondNewPinEnc, byte[] secondPinHashEnc, byte[] secondPinUvAuthParam) =
            await secondSession.BuildChangePinMessagesAsync("9999", "5678", TestContext.CancellationToken);
        CtapClientPinResponse secondResponse = await SendAsync(
            simulator, BuildRequest(secondSession, secondNewPinEnc, secondPinHashEnc, secondPinUvAuthParam), pool);
        Assert.IsNull(secondResponse.PinUvAuthToken);
    }


    /// <summary>Each mandatory parameter's absence fails with <c>CTAP2_ERR_MISSING_PARAMETER</c>.</summary>
    [TestMethod]
    public async Task ChangePinMissingMandatoryParametersReturnsMissingParameter()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("changepin-missing-params");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        (byte[] newPinEnc, byte[] pinHashEnc, byte[] pinUvAuthParam) =
            await session.BuildChangePinMessagesAsync("5678", "1234", TestContext.CancellationToken);

        byte statusWithoutProtocol = await SendExpectingErrorAsync(simulator, new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.ChangePin, KeyAgreement: session.PlatformPublicKeyCose,
            PinUvAuthParam: pinUvAuthParam, NewPinEnc: newPinEnc, PinHashEnc: pinHashEnc), pool);
        Assert.AreEqual(WellKnownCtapStatusCodes.MissingParameter, statusWithoutProtocol);

        byte statusWithoutPinHashEnc = await SendExpectingErrorAsync(simulator, new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.ChangePin, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two,
            KeyAgreement: session.PlatformPublicKeyCose, PinUvAuthParam: pinUvAuthParam, NewPinEnc: newPinEnc), pool);
        Assert.AreEqual(WellKnownCtapStatusCodes.MissingParameter, statusWithoutPinHashEnc);
    }


    /// <summary>An unsupported <c>pinUvAuthProtocol</c> value fails with <c>CTAP1_ERR_INVALID_PARAMETER</c>.</summary>
    [TestMethod]
    public async Task ChangePinUnsupportedProtocolReturnsInvalidParameter()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("changepin-unsupported-protocol");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        (byte[] newPinEnc, byte[] pinHashEnc, byte[] pinUvAuthParam) =
            await session.BuildChangePinMessagesAsync("5678", "1234", TestContext.CancellationToken);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.ChangePin, PinUvAuthProtocol: 99,
            KeyAgreement: session.PlatformPublicKeyCose, PinUvAuthParam: pinUvAuthParam, NewPinEnc: newPinEnc, PinHashEnc: pinHashEnc);

        byte statusCode = await SendExpectingErrorAsync(simulator, request, pool);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidParameter, statusCode);
    }


    /// <summary>
    /// <c>changePIN</c> against an authenticator with no PIN set fails with the wave-5b no-PIN ruling's
    /// <c>CTAP2_ERR_PIN_NOT_SET</c>, as a pure pre-check that never touches <c>pinRetries</c> (decision 6).
    /// </summary>
    [TestMethod]
    public async Task ChangePinWithNoPinSetReturnsPinNotSetAndNeverDecrementsRetries()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("changepin-no-pin-set");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        (byte[] newPinEnc, byte[] pinHashEnc, byte[] pinUvAuthParam) =
            await session.BuildChangePinMessagesAsync("5678", "1234", TestContext.CancellationToken);

        byte statusCode = await SendExpectingErrorAsync(simulator, BuildRequest(session, newPinEnc, pinHashEnc, pinUvAuthParam), pool);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinNotSet, statusCode);
        Assert.AreEqual(8, await GetPinRetriesAsync(simulator, pool), "retries must be untouched when no PIN is set.");
    }


    /// <summary>
    /// A <c>pinUvAuthParam</c> that does not verify against <c>newPinEnc || pinHashEnc</c> fails with
    /// <c>CTAP2_ERR_PIN_AUTH_INVALID</c>, and — critically — the failure happens BEFORE line 5666's
    /// decrement point, so <c>pinRetries</c> is observably untouched (CTAP 2.3, lines 5660-5666).
    /// </summary>
    [TestMethod]
    public async Task ChangePinVerifyFailureReturnsPinAuthInvalidWithoutDecrementingRetries()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("changepin-verify-failure");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        (byte[] newPinEnc, byte[] pinHashEnc, _) = await session.BuildChangePinMessagesAsync("5678", "1234", TestContext.CancellationToken);
        byte[] garbageSignature = new byte[32];

        var request = BuildRequest(session, newPinEnc, pinHashEnc, garbageSignature);
        byte statusCode = await SendExpectingErrorAsync(simulator, request, pool);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthInvalid, statusCode);
        Assert.AreEqual(8, await GetPinRetriesAsync(simulator, pool), "a verify failure must not decrement pinRetries.");
    }


    /// <summary>
    /// The consecutive-mismatch trilogy (CTAP 2.3, lines 5678-5685): two wrong-current-PIN attempts
    /// each fail with <c>PIN_INVALID</c> and observably decrement <c>pinRetries</c>; the third
    /// consecutive mismatch fails with <c>PIN_AUTH_BLOCKED</c>, latches the power-cycle requirement
    /// (observable via <c>getPINRetries</c>' <c>powerCycleState</c>), and a correct PIN afterwards is
    /// still rejected with <c>PIN_AUTH_BLOCKED</c> rather than being allowed through.
    /// </summary>
    [TestMethod]
    public async Task ChangePinThreeConsecutiveMismatchesLatchesPowerCycleRequired()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("changepin-mismatch-trilogy");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        byte firstStatus = await AttemptWrongCurrentPinAsync(simulator, pool);
        Assert.AreEqual(WellKnownCtapStatusCodes.PinInvalid, firstStatus);
        Assert.AreEqual(7, await GetPinRetriesAsync(simulator, pool));
        Assert.IsFalse(await GetPowerCycleStateAsync(simulator, pool));

        byte secondStatus = await AttemptWrongCurrentPinAsync(simulator, pool);
        Assert.AreEqual(WellKnownCtapStatusCodes.PinInvalid, secondStatus);
        Assert.AreEqual(6, await GetPinRetriesAsync(simulator, pool));
        Assert.IsFalse(await GetPowerCycleStateAsync(simulator, pool));

        byte thirdStatus = await AttemptWrongCurrentPinAsync(simulator, pool);
        Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthBlocked, thirdStatus);
        Assert.AreEqual(5, await GetPinRetriesAsync(simulator, pool));
        Assert.IsTrue(await GetPowerCycleStateAsync(simulator, pool), "three consecutive mismatches must latch powerCycleState.");

        //Even the CORRECT PIN is rejected once latched (the latch is checked before the crypto action).
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        (byte[] newPinEnc, byte[] pinHashEnc, byte[] pinUvAuthParam) =
            await session.BuildChangePinMessagesAsync("5678", "1234", TestContext.CancellationToken);
        byte lockedOutStatus = await SendExpectingErrorAsync(simulator, BuildRequest(session, newPinEnc, pinHashEnc, pinUvAuthParam), pool);
        Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthBlocked, lockedOutStatus);
    }


    /// <summary>
    /// The simultaneous boundary (CTAP 2.3, lines 5678-5685): a wrong-current-PIN attempt that BOTH
    /// decrements <c>pinRetries</c> to exactly 0 AND completes the 3-consecutive-mismatch trilogy
    /// (since the last reset) returns <c>CTAP2_ERR_PIN_BLOCKED</c>, never <c>CTAP2_ERR_PIN_AUTH_BLOCKED</c>
    /// — the retries-exhausted check (line 5678) is evaluated before the 3-consecutive check (line 5681)
    /// in the spec's own step order, and the resulting block is the PERMANENT one (unaffected by
    /// power-cycling), never the recoverable latch.
    /// </summary>
    [TestMethod]
    public async Task ChangePinMismatchThatSimultaneouslyExhaustsRetriesAndCompletesTheTrilogyReturnsPinBlocked()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("changepin-simultaneous-boundary");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        //Spends pinRetries down from its maximum (8) to exactly 3 through five isolated mismatches, power
        //cycling after each one so the consecutive-mismatch counter never itself reaches the 3rd-consecutive
        //latch along the way - only pinRetries is spent by this setup, leaving a clean (count-0) slate.
        for(int i = 0; i < 5; i++)
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.PinInvalid, await AttemptWrongCurrentPinAsync(simulator, pool));
            simulator.PowerCycle();
        }
        Assert.AreEqual(3, await GetPinRetriesAsync(simulator, pool));
        Assert.IsFalse(await GetPowerCycleStateAsync(simulator, pool));

        //Three CONSECUTIVE mismatches from this clean slate: the first two are ordinary PinInvalid; the
        //third simultaneously drops pinRetries from 1 to 0 and completes the 3-consecutive trilogy.
        Assert.AreEqual(WellKnownCtapStatusCodes.PinInvalid, await AttemptWrongCurrentPinAsync(simulator, pool));
        Assert.AreEqual(2, await GetPinRetriesAsync(simulator, pool));

        Assert.AreEqual(WellKnownCtapStatusCodes.PinInvalid, await AttemptWrongCurrentPinAsync(simulator, pool));
        Assert.AreEqual(1, await GetPinRetriesAsync(simulator, pool));

        byte boundaryStatus = await AttemptWrongCurrentPinAsync(simulator, pool);

        Assert.AreEqual(
            WellKnownCtapStatusCodes.PinBlocked, boundaryStatus,
            "the retries-exhausted check must win when the same attempt also completes the 3-consecutive-mismatch trilogy.");
        Assert.AreEqual(0, await GetPinRetriesAsync(simulator, pool));
        Assert.IsFalse(
            await GetPowerCycleStateAsync(simulator, pool),
            "PinBlocked is the permanent block; it must not also latch the power-cycle-recoverable requirement.");
    }


    /// <summary>
    /// A <c>pinHashEnc</c> that fails to DECRYPT (as opposed to one that decrypts but mismatches) is
    /// handled IDENTICALLY to a decoded mismatch (CTAP 2.3, line 5671: "If an error results, or a
    /// mismatch is detected, the authenticator performs the following operations") — it decrements
    /// <c>pinRetries</c>, regenerates the selected protocol's key-agreement key pair, and returns
    /// <c>PIN_INVALID</c> on a first occurrence, never the verify-failure code <c>PIN_AUTH_INVALID</c>
    /// and never leaving the brute-force counters untouched.
    /// </summary>
    [TestMethod]
    public async Task ChangePinCurrentPinHashDecryptFailureAppliesMismatchSemantics()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("changepin-currentpinhash-decrypt-failure");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        CoseKey protocolTwoKeyBefore = await GetKeyAgreementAsync(simulator, pool, CtapPinUvAuthProtocolId.Two);

        byte statusCode = await AttemptMalformedCurrentPinHashAsync(simulator, pool);

        Assert.AreEqual(
            WellKnownCtapStatusCodes.PinInvalid, statusCode,
            "a pinHashEnc decrypt failure must be handled exactly like a decoded mismatch, never PinAuthInvalid.");
        Assert.AreEqual(
            7, await GetPinRetriesAsync(simulator, pool),
            "a pinHashEnc decrypt failure must decrement pinRetries exactly like a mismatch.");

        CoseKey protocolTwoKeyAfter = await GetKeyAgreementAsync(simulator, pool, CtapPinUvAuthProtocolId.Two);
        Assert.IsFalse(
            protocolTwoKeyBefore.X!.Value.Span.SequenceEqual(protocolTwoKeyAfter.X!.Value.Span),
            "a pinHashEnc decrypt failure must regenerate the selected protocol's key-agreement key pair exactly like a mismatch.");
    }


    /// <summary>
    /// Three CONSECUTIVE <c>pinHashEnc</c> decrypt failures latch the power-cycle requirement exactly
    /// like three consecutive decoded mismatches (CTAP 2.3, lines 5680-5683) — proving the decrypt
    /// failure path feeds the very same consecutive-mismatch counter as a decoded mismatch, rather than
    /// a separate, uncounted branch.
    /// </summary>
    [TestMethod]
    public async Task ChangePinThreeConsecutiveCurrentPinHashDecryptFailuresLatchPowerCycleRequired()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("changepin-currentpinhash-decrypt-failure-trilogy");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        byte firstStatus = await AttemptMalformedCurrentPinHashAsync(simulator, pool);
        Assert.AreEqual(WellKnownCtapStatusCodes.PinInvalid, firstStatus);
        Assert.AreEqual(7, await GetPinRetriesAsync(simulator, pool));

        byte secondStatus = await AttemptMalformedCurrentPinHashAsync(simulator, pool);
        Assert.AreEqual(WellKnownCtapStatusCodes.PinInvalid, secondStatus);
        Assert.AreEqual(6, await GetPinRetriesAsync(simulator, pool));

        byte thirdStatus = await AttemptMalformedCurrentPinHashAsync(simulator, pool);
        Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthBlocked, thirdStatus);
        Assert.AreEqual(5, await GetPinRetriesAsync(simulator, pool));
        Assert.IsTrue(
            await GetPowerCycleStateAsync(simulator, pool),
            "three consecutive pinHashEnc decrypt failures must latch powerCycleState exactly like three consecutive mismatches.");
    }


    /// <summary>A correct current PIN, after prior mismatches, restores <c>pinRetries</c> to maximum and clears the consecutive-mismatch counter.</summary>
    [TestMethod]
    public async Task ChangePinSuccessAfterMismatchesRestoresRetriesToMaximum()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("changepin-success-restores-retries");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        Assert.AreEqual(WellKnownCtapStatusCodes.PinInvalid, await AttemptWrongCurrentPinAsync(simulator, pool));
        Assert.AreEqual(WellKnownCtapStatusCodes.PinInvalid, await AttemptWrongCurrentPinAsync(simulator, pool));
        Assert.AreEqual(6, await GetPinRetriesAsync(simulator, pool));

        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        (byte[] newPinEnc, byte[] pinHashEnc, byte[] pinUvAuthParam) =
            await session.BuildChangePinMessagesAsync("5678", "1234", TestContext.CancellationToken);
        await SendAsync(simulator, BuildRequest(session, newPinEnc, pinHashEnc, pinUvAuthParam), pool);

        Assert.AreEqual(8, await GetPinRetriesAsync(simulator, pool), "a successful changePIN must restore pinRetries to maximum.");
    }


    /// <summary>
    /// A wrong current PIN's <c>regenerate()</c> (line 5674) refreshes only the SELECTED protocol's
    /// key-agreement key pair — <c>getKeyAgreement</c> for that protocol returns a different key
    /// afterwards, while the untouched protocol's key is unchanged.
    /// </summary>
    [TestMethod]
    public async Task ChangePinMismatchRegeneratesOnlySelectedProtocolsKeyAgreementKey()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("changepin-mismatch-regenerate");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        CoseKey protocolTwoKeyBefore = await GetKeyAgreementAsync(simulator, pool, CtapPinUvAuthProtocolId.Two);
        CoseKey protocolOneKeyBefore = await GetKeyAgreementAsync(simulator, pool, CtapPinUvAuthProtocolId.One);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinInvalid, await AttemptWrongCurrentPinAsync(simulator, pool, CtapPinUvAuthProtocolId.Two));

        CoseKey protocolTwoKeyAfter = await GetKeyAgreementAsync(simulator, pool, CtapPinUvAuthProtocolId.Two);
        CoseKey protocolOneKeyAfter = await GetKeyAgreementAsync(simulator, pool, CtapPinUvAuthProtocolId.One);

        Assert.IsFalse(
            protocolTwoKeyBefore.X!.Value.Span.SequenceEqual(protocolTwoKeyAfter.X!.Value.Span),
            "the mismatched (selected) protocol's key-agreement key must be regenerated.");
        Assert.IsTrue(
            protocolOneKeyBefore.X!.Value.Span.SequenceEqual(protocolOneKeyAfter.X!.Value.Span),
            "the untouched protocol's key-agreement key must be unaffected.");
    }


    /// <summary>
    /// A successful <c>changePIN</c> invalidates every outstanding <c>pinUvAuthToken</c> for ALL
    /// protocols (line 5714): a token issued on protocol one before the change is observably dead
    /// afterwards, proven through the in-use verify composition seam
    /// (<see cref="CtapPinUvAuthTokenVerificationExtensions.VerifyPinUvAuthTokenAsync"/>) against the
    /// authenticator's ACTUAL post-change protocol-one token state — captured off the simulator's own
    /// trace stream, never a second independently-issued token (comparing two independently-minted
    /// getPinToken responses would pass even if changePIN's own <c>resetPinUvAuthToken()</c> were a
    /// no-op, since getPinToken always mints a fresh random value on every call regardless) — even
    /// though the change itself ran on protocol two.
    /// </summary>
    [TestMethod]
    public async Task ChangePinSuccessInvalidatesTokensOnAllProtocols()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("changepin-invalidates-all-tokens");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        //Issue a token on protocol one.
        using CtapWave5bPlatformPinSession tokenSession = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.One, pool, TestContext.CancellationToken);
        byte[] pinHashEncForToken = await tokenSession.BuildPinHashEncAsync("1234", TestContext.CancellationToken);
        var getPinTokenRequest = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinToken, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.One,
            KeyAgreement: tokenSession.PlatformPublicKeyCose, PinHashEnc: pinHashEncForToken);
        CtapClientPinResponse tokenResponse = await SendAsync(simulator, getPinTokenRequest, pool);
        byte[] issuedToken = await tokenSession.DecryptTokenAsync(tokenResponse.PinUvAuthToken!.Value, TestContext.CancellationToken);

        //changePIN on protocol two, observed through the simulator's own trace stream so the captured
        //post-change state is the automaton's real state, not a value reconstructed from a later request.
        var trace = new TestObserver<TraceEntry<CtapAuthenticatorState, CtapAuthenticatorInput>>();
        using(simulator.Subscribe(trace))
        {
            using CtapWave5bPlatformPinSession changeSession = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
                simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
            (byte[] newPinEnc, byte[] pinHashEnc, byte[] pinUvAuthParam) =
                await changeSession.BuildChangePinMessagesAsync("5678", "1234", TestContext.CancellationToken);
            await SendAsync(simulator, BuildRequest(changeSession, newPinEnc, pinHashEnc, pinUvAuthParam), pool);
        }

        CtapAuthenticatorState postChangeState = trace.Received[^1].StateAfter;
        CtapPinUvAuthTokenState currentProtocolOneToken = postChangeState.ProtocolOneToken;

        CollectionAssert.AreNotEqual(
            issuedToken, currentProtocolOneToken.Token.AsReadOnlySpan().ToArray(),
            "changePIN must mint a fresh protocol-one token, distinct from the one issued before the change.");

        //A platform still holding the now-dead token computes a signature under it; the authenticator's
        //own current token — the only key its real verify path ever presents — is a different, freshly
        //reset value, so the composition must reject it (whether because the token no longer matches, or
        //because the fresh token has not yet been put in use — either reason is the invalidation).
        CtapPinUvAuthProtocol protocolOne = CtapPinUvAuthProtocol.CreateDefault(CtapPinUvAuthProtocolId.One);
        byte[] probeMessage = Encoding.UTF8.GetBytes("changePIN-invalidation-probe");
        using IMemoryOwner<byte> staleSignature = await protocolOne.AuthenticateAsync(
            issuedToken, probeMessage, pool, TestContext.CancellationToken);

        bool verified = await protocolOne.VerifyPinUvAuthTokenAsync(
            currentProtocolOneToken, currentProtocolOneToken.Token.AsReadOnlyMemory(), probeMessage, staleSignature.Memory, pool, TestContext.CancellationToken);

        Assert.IsFalse(verified, "the previously issued token must fail the in-use verify composition after changePIN invalidates it.");
    }


    /// <summary>
    /// <c>changePIN</c>'s effect zeroes the <c>decapsulate</c> shared secret before it returns to the
    /// pool (CTAP 2.3 §6.5.5.6, wave-5b contract decision 4) — observed by tracking the exact
    /// shared-secret size <see cref="CtapAuthenticatorSimulator"/>'s <c>ChangePinAsync</c> effect rents
    /// at its <c>DecapsulateAsync</c> call site, through the pool-seam parameter every production call
    /// site already takes, mirroring <see cref="CtapPinUvAuthProtocolTests.ProtocolTwoDecapsulateClearsKdfIntermediateHalfBuffersBeforeReturningThemToThePool"/>'s
    /// approach.
    /// </summary>
    [TestMethod]
    [DataRow(CtapPinUvAuthProtocolId.One, 32, DisplayName = "protocol one: 32-byte shared secret")]
    [DataRow(CtapPinUvAuthProtocolId.Two, 64, DisplayName = "protocol two: 64-byte shared secret")]
    public async Task ChangePinZeroesTheSharedSecretBeforeReturningItToThePool(CtapPinUvAuthProtocolId protocolId, int sharedSecretLength)
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator($"changepin-zeroization-{protocolId}");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234", protocolId);

        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, protocolId, pool, TestContext.CancellationToken);
        (byte[] newPinEnc, byte[] pinHashEnc, byte[] pinUvAuthParam) =
            await session.BuildChangePinMessagesAsync("5678", "1234", TestContext.CancellationToken);

        var request = BuildRequest(session, newPinEnc, pinHashEnc, pinUvAuthParam, protocolId);

        using var trackingPool = new ZeroOnDisposeTrackingMemoryPool(sharedSecretLength);
        await SendAsync(simulator, request, trackingPool);

        Assert.IsGreaterThanOrEqualTo(1, trackingPool.TrackedDisposalCount,
            "changePIN's effect must rent and dispose at least the decapsulate shared secret at its exact length.");
        Assert.IsTrue(trackingPool.AllTrackedDisposalsWereZero,
            "every buffer changePIN's effect disposes at the shared-secret length - including the shared secret itself - must be zeroed before it returns to the pool.");
    }


    /// <summary>Attempts a <c>changePIN</c> with a wrong current PIN, returning the exact status code.</summary>
    private async Task<byte> AttemptWrongCurrentPinAsync(
        CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool, CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, protocolId, pool, TestContext.CancellationToken);
        (byte[] newPinEnc, byte[] pinHashEnc, byte[] pinUvAuthParam) =
            await session.BuildChangePinMessagesAsync("5678", "0000", TestContext.CancellationToken);

        return await SendExpectingErrorAsync(simulator, BuildRequest(session, newPinEnc, pinHashEnc, pinUvAuthParam, protocolId), pool);
    }


    /// <summary>Attempts a <c>changePIN</c> whose <c>pinHashEnc</c> fails to DECRYPT, returning the exact status code.</summary>
    private async Task<byte> AttemptMalformedCurrentPinHashAsync(
        CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool, CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, protocolId, pool, TestContext.CancellationToken);
        byte[] malformedPinHashEnc = CtapWave5bPinCryptoFixtures.BuildMalformedPinHashEnc();
        (byte[] newPinEnc, byte[] pinUvAuthParam) =
            await session.BuildChangePinMessagesWithExplicitPinHashEncAsync("5678", malformedPinHashEnc, TestContext.CancellationToken);

        return await SendExpectingErrorAsync(simulator, BuildRequest(session, newPinEnc, malformedPinHashEnc, pinUvAuthParam, protocolId), pool);
    }


    /// <summary>Builds a <c>changePIN</c> request from the session and encrypted message members.</summary>
    private static CtapClientPinRequest BuildRequest(
        CtapWave5bPlatformPinSession session, byte[] newPinEnc, byte[] pinHashEnc, byte[] pinUvAuthParam,
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two) =>
        new(
            SubCommand: WellKnownCtapClientPinSubCommands.ChangePin,
            PinUvAuthProtocol: (int)protocolId,
            KeyAgreement: session.PlatformPublicKeyCose,
            PinUvAuthParam: pinUvAuthParam,
            NewPinEnc: newPinEnc,
            PinHashEnc: pinHashEnc);


    /// <summary>Reads the current <c>pinRetries</c> counter via <c>getPINRetries</c>.</summary>
    private async Task<int> GetPinRetriesAsync(CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool)
    {
        var request = new CtapClientPinRequest(SubCommand: WellKnownCtapClientPinSubCommands.GetPinRetries);
        CtapClientPinResponse response = await SendAsync(simulator, request, pool);

        return response.PinRetries!.Value;
    }


    /// <summary>Reads the current <c>powerCycleState</c> via <c>getPINRetries</c>.</summary>
    private async Task<bool> GetPowerCycleStateAsync(CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool)
    {
        var request = new CtapClientPinRequest(SubCommand: WellKnownCtapClientPinSubCommands.GetPinRetries);
        CtapClientPinResponse response = await SendAsync(simulator, request, pool);

        return response.PowerCycleState!.Value;
    }


    /// <summary>Reads a protocol's current key-agreement public key via <c>getKeyAgreement</c>.</summary>
    private async Task<CoseKey> GetKeyAgreementAsync(CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool, CtapPinUvAuthProtocolId protocolId)
    {
        var request = new CtapClientPinRequest(SubCommand: WellKnownCtapClientPinSubCommands.GetKeyAgreement, PinUvAuthProtocol: (int)protocolId);
        CtapClientPinResponse response = await SendAsync(simulator, request, pool);

        return response.KeyAgreement!;
    }


    /// <summary>Sends an <c>authenticatorClientPIN</c> request expected to succeed and decodes its response.</summary>
    private Task<CtapClientPinResponse> SendAsync(CtapAuthenticatorSimulator simulator, CtapClientPinRequest request, MemoryPool<byte> pool) =>
        CtapAuthenticatorClientPinClient.ClientPinAsync(
            simulator.TransceiveAsync, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, TestContext.CancellationToken).AsTask();


    /// <summary>Sends an <c>authenticatorClientPIN</c> request expected to fail and returns the exact status code.</summary>
    private async Task<byte> SendExpectingErrorAsync(CtapAuthenticatorSimulator simulator, CtapClientPinRequest request, MemoryPool<byte> pool)
    {
        CtapCommandException exception = await Assert.ThrowsExactlyAsync<CtapCommandException>(() => SendAsync(simulator, request, pool));

        return exception.StatusCode;
    }
}
