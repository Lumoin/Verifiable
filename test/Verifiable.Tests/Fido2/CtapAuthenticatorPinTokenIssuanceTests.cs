using System.Buffers;
using System.Text;
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
/// Tests for <see cref="CtapAuthenticatorSimulator"/>'s <c>authenticatorClientPIN</c> <c>getPinToken</c>
/// (<c>0x05</c>) and <c>getPinUvAuthTokenUsingPinWithPermissions</c> (<c>0x09</c>) subcommands (CTAP 2.3
/// §6.5.5.7.1/§6.5.5.7.2): the two subcommands' differing mandatory-parameter/permission rules, the
/// permission-statement gate under this profile's getInfo, the shared mismatch/blocked/latch
/// pre-checks, system-wide token invalidation on every fresh issuance, the selected-protocol-only
/// <c>regenerate()</c>, and the encrypted token's exact ciphertext lengths.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorPinTokenIssuanceTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Every requested permission bit this profile's getInfo denies (CTAP 2.3 §6.5.5.7.2, lines
    /// 5958-5970). <c>acfg</c>, <c>cm</c>, <c>be</c>, and <c>lbw</c> are excluded from this set: this
    /// wave's getInfo advertises <c>authnrCfg:true</c>/<c>credMgmt:true</c>/<c>largeBlobs:true</c>
    /// unconditionally and <c>bioEnroll</c> always present, so the gate's <c>acfg</c> bullet (line
    /// 5964, "authnrCfg is false or absent"), <c>cm</c> bullet (line 5958, "credMgmt is false or
    /// absent"), <c>be</c> bullet (line 5960, "bioEnroll is absent"), and <c>lbw</c> bullet (line 5962,
    /// "largeBlobs is false or absent") never hold — all four are grantable, exercised separately below
    /// (<see cref="PinUvAuthTokenUsingPinGrantsAcfgAlone"/>/<see cref="PinUvAuthTokenUsingPinGrantsLbwAlone"/>).
    /// <c>pcmr</c> is the sole permission this profile's PIN path can never grant.
    /// </summary>
    private static int[] DeniedPermissionBits =>
    [
        WellKnownCtapPinUvAuthTokenPermissions.Pcmr
    ];


    /// <summary>
    /// <c>getPinToken</c>'s happy path: default <c>mc|ga</c> permissions (<c>0x03</c>), an unbound
    /// permissions RP ID, and a 32-byte decrypted token for protocol one / 48-byte encrypted ciphertext
    /// for protocol two (16-byte IV prefix).
    /// </summary>
    [TestMethod]
    [DataRow(CtapPinUvAuthProtocolId.One, 32, DisplayName = "protocol one: 32-byte ciphertext")]
    [DataRow(CtapPinUvAuthProtocolId.Two, 48, DisplayName = "protocol two: iv||ct, 48-byte ciphertext")]
    public async Task GetPinTokenHappyPathReturnsExpectedCiphertextLengthAndThirtyTwoByteDecryptedToken(
        CtapPinUvAuthProtocolId protocolId, int expectedCiphertextLength)
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator($"getpintoken-happy-{protocolId}");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, protocolId, pool, TestContext.CancellationToken);
        byte[] pinHashEnc = await session.BuildPinHashEncAsync("1234", TestContext.CancellationToken);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinToken, PinUvAuthProtocol: (int)protocolId,
            KeyAgreement: session.PlatformPublicKeyCose, PinHashEnc: pinHashEnc);
        CtapClientPinResponse response = await SendAsync(simulator, request, pool);

        Assert.IsNotNull(response.PinUvAuthToken);
        Assert.AreEqual(expectedCiphertextLength, response.PinUvAuthToken!.Value.Length);

        byte[] token = await session.DecryptTokenAsync(response.PinUvAuthToken.Value, TestContext.CancellationToken);
        Assert.HasCount(32, token, "the decrypted pinUvAuthToken itself must be 32 bytes for both protocols.");
    }


    /// <summary>Each mandatory parameter's absence fails with <c>CTAP2_ERR_MISSING_PARAMETER</c>.</summary>
    [TestMethod]
    public async Task GetPinTokenMissingMandatoryParametersReturnsMissingParameter()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("getpintoken-missing-params");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        byte[] pinHashEnc = await session.BuildPinHashEncAsync("1234", TestContext.CancellationToken);

        byte statusWithoutProtocol = await SendExpectingErrorAsync(simulator, new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinToken, KeyAgreement: session.PlatformPublicKeyCose, PinHashEnc: pinHashEnc), pool);
        Assert.AreEqual(WellKnownCtapStatusCodes.MissingParameter, statusWithoutProtocol);

        byte statusWithoutKeyAgreement = await SendExpectingErrorAsync(simulator, new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinToken, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two, PinHashEnc: pinHashEnc), pool);
        Assert.AreEqual(WellKnownCtapStatusCodes.MissingParameter, statusWithoutKeyAgreement);

        byte statusWithoutPinHashEnc = await SendExpectingErrorAsync(simulator, new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinToken, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two,
            KeyAgreement: session.PlatformPublicKeyCose), pool);
        Assert.AreEqual(WellKnownCtapStatusCodes.MissingParameter, statusWithoutPinHashEnc);
    }


    /// <summary><c>getPinToken</c> with <c>permissions</c> present fails with <c>CTAP1_ERR_INVALID_PARAMETER</c> (line 5865-5866) — that member belongs to 0x09 only.</summary>
    [TestMethod]
    public async Task GetPinTokenWithPermissionsPresentReturnsInvalidParameter()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("getpintoken-permissions-present");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        byte[] pinHashEnc = await session.BuildPinHashEncAsync("1234", TestContext.CancellationToken);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinToken, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two,
            KeyAgreement: session.PlatformPublicKeyCose, PinHashEnc: pinHashEnc,
            Permissions: WellKnownCtapPinUvAuthTokenPermissions.Mc);

        byte statusCode = await SendExpectingErrorAsync(simulator, request, pool);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidParameter, statusCode);
    }


    /// <summary><c>getPinToken</c> with <c>rpId</c> present fails with <c>CTAP1_ERR_INVALID_PARAMETER</c> (line 5868-5869) — <c>getPinToken</c> issues unbound tokens only.</summary>
    [TestMethod]
    public async Task GetPinTokenWithRpIdPresentReturnsInvalidParameter()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("getpintoken-rpid-present");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        byte[] pinHashEnc = await session.BuildPinHashEncAsync("1234", TestContext.CancellationToken);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinToken, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two,
            KeyAgreement: session.PlatformPublicKeyCose, PinHashEnc: pinHashEnc, RpId: "example.com");

        byte statusCode = await SendExpectingErrorAsync(simulator, request, pool);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidParameter, statusCode);
    }


    /// <summary><c>getPinToken</c> against an authenticator with no PIN set fails with the wave-5b no-PIN ruling's <c>CTAP2_ERR_PIN_NOT_SET</c>, never decrementing retries.</summary>
    [TestMethod]
    public async Task GetPinTokenWithNoPinSetReturnsPinNotSet()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("getpintoken-no-pin-set");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        byte[] pinHashEnc = await session.BuildPinHashEncAsync("1234", TestContext.CancellationToken);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinToken, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two,
            KeyAgreement: session.PlatformPublicKeyCose, PinHashEnc: pinHashEnc);

        byte statusCode = await SendExpectingErrorAsync(simulator, request, pool);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinNotSet, statusCode);
        Assert.AreEqual(8, await GetPinRetriesAsync(simulator, pool));
    }


    /// <summary>
    /// <c>getPinUvAuthTokenUsingPinWithPermissions</c> against an authenticator with no PIN set fails
    /// with the wave-5b no-PIN ruling's <c>CTAP2_ERR_PIN_NOT_SET</c> (decision 6, "for the three"),
    /// never decrementing retries — the permission gate and mismatch machinery are never reached.
    /// </summary>
    [TestMethod]
    public async Task PinUvAuthTokenUsingPinWithNoPinSetReturnsPinNotSet()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("0x09-no-pin-set");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        byte[] pinHashEnc = await session.BuildPinHashEncAsync("1234", TestContext.CancellationToken);
        int mcGa = WellKnownCtapPinUvAuthTokenPermissions.Mc | WellKnownCtapPinUvAuthTokenPermissions.Ga;

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingPinWithPermissions,
            PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two, KeyAgreement: session.PlatformPublicKeyCose,
            PinHashEnc: pinHashEnc, Permissions: mcGa, RpId: "example.com");

        byte statusCode = await SendExpectingErrorAsync(simulator, request, pool);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinNotSet, statusCode);
        Assert.AreEqual(8, await GetPinRetriesAsync(simulator, pool));
    }


    /// <summary>A wrong current PIN fails with <c>CTAP2_ERR_PIN_INVALID</c> and observably decrements <c>pinRetries</c> (line 5878-5897).</summary>
    [TestMethod]
    public async Task GetPinTokenWithWrongPinReturnsPinInvalidAndDecrementsRetries()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("getpintoken-wrong-pin");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        byte[] wrongPinHashEnc = await session.BuildWrongPinHashEncAsync(TestContext.CancellationToken);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinToken, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two,
            KeyAgreement: session.PlatformPublicKeyCose, PinHashEnc: wrongPinHashEnc);

        byte statusCode = await SendExpectingErrorAsync(simulator, request, pool);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinInvalid, statusCode);
        Assert.AreEqual(7, await GetPinRetriesAsync(simulator, pool));
    }


    /// <summary>
    /// A <c>pinHashEnc</c> that fails to DECRYPT (as opposed to one that decrypts but mismatches) is
    /// handled IDENTICALLY to a decoded mismatch, for both <c>getPinToken</c> and
    /// <c>getPinUvAuthTokenUsingPinWithPermissions</c> (CTAP 2.3 §6.5.5.7.1 line 5883 / §6.5.5.7.2 line
    /// 5985: "If an error results, or a mismatch is detected, the authenticator performs the following
    /// operations") — it decrements <c>pinRetries</c>, regenerates the selected protocol's key-agreement
    /// key pair, and returns <c>PIN_INVALID</c> on a first occurrence, never leaving the brute-force
    /// counters untouched. Neither subcommand has a <c>verify()</c> gate over <c>pinHashEnc</c>, so this
    /// path is reachable from a bare malformed-length request with no forged signature needed.
    /// </summary>
    [TestMethod]
    [DataRow(false, DisplayName = "getPinToken (0x05)")]
    [DataRow(true, DisplayName = "getPinUvAuthTokenUsingPinWithPermissions (0x09)")]
    public async Task PinHashEncDecryptFailureAppliesMismatchSemantics(bool useSubcommandWithPermissions)
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator(
            $"pinhashenc-decrypt-failure-{useSubcommandWithPermissions}");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        CoseKey protocolTwoKeyBefore = await GetKeyAgreementAsync(simulator, pool, CtapPinUvAuthProtocolId.Two);

        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        byte[] malformedPinHashEnc = CtapWave5bPinCryptoFixtures.BuildMalformedPinHashEnc();

        CtapClientPinRequest request = useSubcommandWithPermissions
            ? new CtapClientPinRequest(
                SubCommand: WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingPinWithPermissions,
                PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two, KeyAgreement: session.PlatformPublicKeyCose,
                PinHashEnc: malformedPinHashEnc,
                Permissions: WellKnownCtapPinUvAuthTokenPermissions.Mc | WellKnownCtapPinUvAuthTokenPermissions.Ga,
                RpId: "example.com")
            : new CtapClientPinRequest(
                SubCommand: WellKnownCtapClientPinSubCommands.GetPinToken, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two,
                KeyAgreement: session.PlatformPublicKeyCose, PinHashEnc: malformedPinHashEnc);

        byte statusCode = await SendExpectingErrorAsync(simulator, request, pool);

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


    /// <summary>Retries exhausted (<c>pinRetries == 0</c>) fails with <c>CTAP2_ERR_PIN_BLOCKED</c> as a pure pre-check (line 5871).</summary>
    [TestMethod]
    public async Task GetPinTokenWithRetriesExhaustedReturnsPinBlocked()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("getpintoken-retries-exhausted");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        for(int attempt = 0; attempt < 8; attempt++)
        {
            using CtapWave5bPlatformPinSession mismatchSession = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
                simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
            byte[] wrongPinHashEnc = await mismatchSession.BuildWrongPinHashEncAsync(TestContext.CancellationToken);
            var mismatchRequest = new CtapClientPinRequest(
                SubCommand: WellKnownCtapClientPinSubCommands.GetPinToken, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two,
                KeyAgreement: mismatchSession.PlatformPublicKeyCose, PinHashEnc: wrongPinHashEnc);
            byte statusCode = await SendExpectingErrorAsync(simulator, mismatchRequest, pool);

            //The 3rd of every 3 consecutive mismatches is PinAuthBlocked (latch); the simulator's power
            //cycle clears the latch (but not pinRetries) so the exhaustion can continue toward 0.
            if(statusCode == WellKnownCtapStatusCodes.PinAuthBlocked)
            {
                simulator.PowerCycle();
            }
        }

        Assert.AreEqual(0, await GetPinRetriesAsync(simulator, pool));

        using CtapWave5bPlatformPinSession finalSession = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        byte[] pinHashEnc = await finalSession.BuildPinHashEncAsync("1234", TestContext.CancellationToken);
        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinToken, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two,
            KeyAgreement: finalSession.PlatformPublicKeyCose, PinHashEnc: pinHashEnc);

        byte finalStatus = await SendExpectingErrorAsync(simulator, request, pool);
        Assert.AreEqual(WellKnownCtapStatusCodes.PinBlocked, finalStatus, "once retries reach 0, PinBlocked must be returned even for the correct PIN.");
    }


    /// <summary>
    /// <c>getPinUvAuthTokenUsingPinWithPermissions</c>'s happy path: <c>mc|ga</c> permissions with
    /// <c>rpId</c> bound succeeds and returns a 32-byte decryptable token.
    /// </summary>
    [TestMethod]
    public async Task PinUvAuthTokenUsingPinWithPermissionsHappyPathSucceeds()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("0x09-happy");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        byte[] pinHashEnc = await session.BuildPinHashEncAsync("1234", TestContext.CancellationToken);
        int mcGa = WellKnownCtapPinUvAuthTokenPermissions.Mc | WellKnownCtapPinUvAuthTokenPermissions.Ga;

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingPinWithPermissions,
            PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two, KeyAgreement: session.PlatformPublicKeyCose,
            PinHashEnc: pinHashEnc, Permissions: mcGa, RpId: "example.com");

        CtapClientPinResponse response = await SendAsync(simulator, request, pool);

        byte[] token = await session.DecryptTokenAsync(response.PinUvAuthToken!.Value, TestContext.CancellationToken);
        Assert.HasCount(32, token);
    }


    /// <summary><c>permissions == 0</c> fails with <c>CTAP1_ERR_INVALID_PARAMETER</c> (line 5953), never <c>UnauthorizedPermission</c> nor <c>MissingParameter</c>.</summary>
    [TestMethod]
    public async Task PinUvAuthTokenUsingPinWithZeroPermissionsReturnsInvalidParameter()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("0x09-zero-permissions");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        byte[] pinHashEnc = await session.BuildPinHashEncAsync("1234", TestContext.CancellationToken);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingPinWithPermissions,
            PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two, KeyAgreement: session.PlatformPublicKeyCose,
            PinHashEnc: pinHashEnc, Permissions: 0, RpId: "example.com");

        byte statusCode = await SendExpectingErrorAsync(simulator, request, pool);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidParameter, statusCode);
    }


    /// <summary>Every permission this profile's getInfo still denies (<c>pcmr</c>, the sole remaining one post-wavelb) fails with <c>CTAP2_ERR_UNAUTHORIZED_PERMISSION</c> (lines 5955-5971).</summary>
    [TestMethod]
    [DataRow(0, DisplayName = "pcmr")]
    public async Task PinUvAuthTokenUsingPinWithDeniedPermissionReturnsUnauthorizedPermission(int deniedBitIndex)
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator($"0x09-denied-{deniedBitIndex}");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        byte[] pinHashEnc = await session.BuildPinHashEncAsync("1234", TestContext.CancellationToken);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingPinWithPermissions,
            PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two, KeyAgreement: session.PlatformPublicKeyCose,
            PinHashEnc: pinHashEnc, Permissions: DeniedPermissionBits[deniedBitIndex]);

        byte statusCode = await SendExpectingErrorAsync(simulator, request, pool);

        Assert.AreEqual(WellKnownCtapStatusCodes.UnauthorizedPermission, statusCode);
    }


    /// <summary>
    /// <c>acfg</c> requested alone is granted (this wave's permission-gate flip: <c>authnrCfg:true</c>
    /// is now advertised unconditionally, so the gate's <c>acfg</c> bullet, line 5964, never denies)
    /// with NO <c>rpId</c> — <c>acfg</c>'s own RP ID column is "Ignored" (line 5814), unlike
    /// <c>mc</c>/<c>ga</c>'s "Required". The granted bitfield is observed on the authenticator's own
    /// resulting token state, never by comparing token VALUES (a fresh token is always freshly
    /// random regardless of which permissions it carries).
    /// </summary>
    [TestMethod]
    public async Task PinUvAuthTokenUsingPinGrantsAcfgAlone()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("0x09-grants-acfg-alone");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        byte[] pinHashEnc = await session.BuildPinHashEncAsync("1234", TestContext.CancellationToken);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingPinWithPermissions,
            PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two, KeyAgreement: session.PlatformPublicKeyCose,
            PinHashEnc: pinHashEnc, Permissions: WellKnownCtapPinUvAuthTokenPermissions.Acfg);

        var trace = new TestObserver<TraceEntry<CtapAuthenticatorState, CtapAuthenticatorInput>>();
        using(simulator.Subscribe(trace))
        {
            CtapClientPinResponse response = await SendAsync(simulator, request, pool);
            Assert.IsNotNull(response.PinUvAuthToken);
        }

        Assert.AreEqual(
            WellKnownCtapPinUvAuthTokenPermissions.Acfg,
            trace.Received[^1].StateAfter.ProtocolTwoToken.Permissions,
            "acfg requested alone, with no rpId, must be granted exactly acfg.");
    }


    /// <summary>
    /// <c>lbw</c> requested alone is granted (wavelb R4's permission-gate flip: <c>largeBlobs:true</c>
    /// is now advertised unconditionally, so the gate's <c>lbw</c> bullet, line 5962, never denies) with
    /// NO <c>rpId</c> — <c>lbw</c>'s own RP ID column is "Ignored" (line 5808), like <c>acfg</c>'s.
    /// </summary>
    [TestMethod]
    public async Task PinUvAuthTokenUsingPinGrantsLbwAlone()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("0x09-grants-lbw-alone");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        byte[] pinHashEnc = await session.BuildPinHashEncAsync("1234", TestContext.CancellationToken);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingPinWithPermissions,
            PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two, KeyAgreement: session.PlatformPublicKeyCose,
            PinHashEnc: pinHashEnc, Permissions: WellKnownCtapPinUvAuthTokenPermissions.Lbw);

        var trace = new TestObserver<TraceEntry<CtapAuthenticatorState, CtapAuthenticatorInput>>();
        using(simulator.Subscribe(trace))
        {
            CtapClientPinResponse response = await SendAsync(simulator, request, pool);
            Assert.IsNotNull(response.PinUvAuthToken);
        }

        Assert.AreEqual(
            WellKnownCtapPinUvAuthTokenPermissions.Lbw,
            trace.Received[^1].StateAfter.ProtocolTwoToken.Permissions,
            "lbw requested alone, with no rpId, must be granted exactly lbw.");
    }


    /// <summary>
    /// <c>acfg</c> or-ed with <c>mc</c>/<c>ga</c> grants all three bits together — the grant mask
    /// widens uniformly to <c>mc|ga|acfg</c>, not <c>acfg</c>-exclusive-of the pre-existing bits.
    /// </summary>
    [TestMethod]
    public async Task PinUvAuthTokenUsingPinGrantsAcfgOredWithMcGa()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("0x09-grants-acfg-or-mcga");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        byte[] pinHashEnc = await session.BuildPinHashEncAsync("1234", TestContext.CancellationToken);
        int mcGaAcfg = WellKnownCtapPinUvAuthTokenPermissions.Mc | WellKnownCtapPinUvAuthTokenPermissions.Ga | WellKnownCtapPinUvAuthTokenPermissions.Acfg;

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingPinWithPermissions,
            PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two, KeyAgreement: session.PlatformPublicKeyCose,
            PinHashEnc: pinHashEnc, Permissions: mcGaAcfg, RpId: "example.com");

        var trace = new TestObserver<TraceEntry<CtapAuthenticatorState, CtapAuthenticatorInput>>();
        using(simulator.Subscribe(trace))
        {
            CtapClientPinResponse response = await SendAsync(simulator, request, pool);
            Assert.IsNotNull(response.PinUvAuthToken);
        }

        Assert.AreEqual(
            mcGaAcfg,
            trace.Received[^1].StateAfter.ProtocolTwoToken.Permissions,
            "mc|ga|acfg requested together must all be granted, none silently dropped.");
    }


    /// <summary>
    /// <c>be</c> requested alone is granted (wavebio's own permission-gate flip: <c>bioEnroll</c> is now
    /// always present, so the gate's <c>be</c> bullet, line 5960, never denies) with NO <c>rpId</c> —
    /// <c>be</c>'s own RP ID column is "Ignored" (line 5800), like <c>acfg</c>'s, unlike <c>mc</c>/<c>ga</c>'s
    /// "Required": <c>be</c> never joins <c>mcGaMask</c>'s "RP ID Required" check.
    /// </summary>
    [TestMethod]
    public async Task PinUvAuthTokenUsingPinGrantsBeAlone()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("0x09-grants-be-alone");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        byte[] pinHashEnc = await session.BuildPinHashEncAsync("1234", TestContext.CancellationToken);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingPinWithPermissions,
            PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two, KeyAgreement: session.PlatformPublicKeyCose,
            PinHashEnc: pinHashEnc, Permissions: WellKnownCtapPinUvAuthTokenPermissions.Be);

        var trace = new TestObserver<TraceEntry<CtapAuthenticatorState, CtapAuthenticatorInput>>();
        using(simulator.Subscribe(trace))
        {
            CtapClientPinResponse response = await SendAsync(simulator, request, pool);
            Assert.IsNotNull(response.PinUvAuthToken);
        }

        CtapPinUvAuthTokenState issuedToken = trace.Received[^1].StateAfter.ProtocolTwoToken;
        Assert.AreEqual(WellKnownCtapPinUvAuthTokenPermissions.Be, issuedToken.Permissions, "be requested alone must be granted exactly be.");
        Assert.IsNull(issuedToken.PermissionsRpId, "be requested with no rpId must issue an unbound token.");
    }


    /// <summary>
    /// <c>cm</c> requested alone is granted (this wave's permission-gate flip: <c>credMgmt:true</c> is
    /// now advertised unconditionally, so the gate's <c>cm</c> bullet, line 5958, never denies) with NO
    /// <c>rpId</c> — <c>cm</c>'s own RP ID column is "Optional" (line 5788), unlike <c>mc</c>/<c>ga</c>'s
    /// "Required": a <c>cm</c>-only request needs no <c>rpId</c> to pass the mandatory-parameter check.
    /// A request with no <c>rpId</c> at all issues an UNBOUND token — <see cref="CtapPinUvAuthTokenState.PermissionsRpId"/>
    /// stays <see langword="null"/>, since line 6024's association step only fires when <c>rpId</c> is
    /// present.
    /// </summary>
    [TestMethod]
    public async Task PinUvAuthTokenUsingPinGrantsCmAloneUnbound()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("0x09-grants-cm-alone-unbound");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        byte[] pinHashEnc = await session.BuildPinHashEncAsync("1234", TestContext.CancellationToken);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingPinWithPermissions,
            PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two, KeyAgreement: session.PlatformPublicKeyCose,
            PinHashEnc: pinHashEnc, Permissions: WellKnownCtapPinUvAuthTokenPermissions.Cm);

        var trace = new TestObserver<TraceEntry<CtapAuthenticatorState, CtapAuthenticatorInput>>();
        using(simulator.Subscribe(trace))
        {
            CtapClientPinResponse response = await SendAsync(simulator, request, pool);
            Assert.IsNotNull(response.PinUvAuthToken);
        }

        CtapPinUvAuthTokenState issuedToken = trace.Received[^1].StateAfter.ProtocolTwoToken;
        Assert.AreEqual(WellKnownCtapPinUvAuthTokenPermissions.Cm, issuedToken.Permissions, "cm requested alone must be granted exactly cm.");
        Assert.IsNull(issuedToken.PermissionsRpId, "cm requested with no rpId must issue an unbound token.");
    }


    /// <summary>
    /// <c>cm</c> or-ed with <c>mc</c>/<c>ga</c>/<c>acfg</c> grants all four bits together — the grant
    /// mask widens uniformly to <c>mc|ga|acfg|cm</c>. A present <c>rpId</c> (mandatory here for the
    /// <c>mc</c>/<c>ga</c> bits this request also carries) associates the SAME permissions RP ID with
    /// <c>cm</c> too: line 6024's association is unconditional on which permissions were requested, so
    /// the resulting token is bound for every permission it carries, not just <c>mc</c>/<c>ga</c>.
    /// </summary>
    [TestMethod]
    public async Task PinUvAuthTokenUsingPinGrantsCmOredWithMcGaAcfgBound()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("0x09-grants-cm-or-mcgaacfg-bound");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        byte[] pinHashEnc = await session.BuildPinHashEncAsync("1234", TestContext.CancellationToken);
        int mcGaAcfgCm = WellKnownCtapPinUvAuthTokenPermissions.Mc | WellKnownCtapPinUvAuthTokenPermissions.Ga
            | WellKnownCtapPinUvAuthTokenPermissions.Acfg | WellKnownCtapPinUvAuthTokenPermissions.Cm;

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingPinWithPermissions,
            PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two, KeyAgreement: session.PlatformPublicKeyCose,
            PinHashEnc: pinHashEnc, Permissions: mcGaAcfgCm, RpId: "example.com");

        var trace = new TestObserver<TraceEntry<CtapAuthenticatorState, CtapAuthenticatorInput>>();
        using(simulator.Subscribe(trace))
        {
            CtapClientPinResponse response = await SendAsync(simulator, request, pool);
            Assert.IsNotNull(response.PinUvAuthToken);
        }

        CtapPinUvAuthTokenState issuedToken = trace.Received[^1].StateAfter.ProtocolTwoToken;
        Assert.AreEqual(mcGaAcfgCm, issuedToken.Permissions, "mc|ga|acfg|cm requested together must all be granted, none silently dropped.");
        Assert.AreEqual("example.com", issuedToken.PermissionsRpId, "a present rpId must bind cm's token exactly like mc/ga/acfg's.");
    }


    /// <summary>An undefined permission bit (<c>0x80</c>) is silently ignored, never denying a request that also carries a grantable bit.</summary>
    [TestMethod]
    public async Task PinUvAuthTokenUsingPinIgnoresUndefinedPermissionBit()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("0x09-undefined-bit-ignored");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        byte[] pinHashEnc = await session.BuildPinHashEncAsync("1234", TestContext.CancellationToken);
        const int undefinedBit = 0x80;
        int requestedPermissions = WellKnownCtapPinUvAuthTokenPermissions.Mc | undefinedBit;

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingPinWithPermissions,
            PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two, KeyAgreement: session.PlatformPublicKeyCose,
            PinHashEnc: pinHashEnc, Permissions: requestedPermissions, RpId: "example.com");

        CtapClientPinResponse response = await SendAsync(simulator, request, pool);

        Assert.IsNotNull(response.PinUvAuthToken);
    }


    /// <summary><c>mc</c> requested without <c>rpId</c> fails with <c>CTAP2_ERR_MISSING_PARAMETER</c> (the conditionally-mandatory reading of line 5942).</summary>
    [TestMethod]
    public async Task PinUvAuthTokenUsingPinWithMcPermissionWithoutRpIdReturnsMissingParameter()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("0x09-mc-without-rpid");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        byte[] pinHashEnc = await session.BuildPinHashEncAsync("1234", TestContext.CancellationToken);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingPinWithPermissions,
            PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two, KeyAgreement: session.PlatformPublicKeyCose,
            PinHashEnc: pinHashEnc, Permissions: WellKnownCtapPinUvAuthTokenPermissions.Mc);

        byte statusCode = await SendExpectingErrorAsync(simulator, request, pool);

        Assert.AreEqual(WellKnownCtapStatusCodes.MissingParameter, statusCode);
    }


    /// <summary>
    /// Ordering proof: <c>permissions == 0</c> (5953) is checked BEFORE the permission-statement gate,
    /// which is checked BEFORE <c>PinBlocked</c>, which is checked BEFORE <c>decapsulate</c> — a
    /// request combining a denied permission (<c>pcmr</c>, still denied post-wavelb — the sole
    /// remaining always-denied bit) with retries already exhausted still reports
    /// <c>UnauthorizedPermission</c>, not <c>PinBlocked</c>.
    /// </summary>
    [TestMethod]
    public async Task PinUvAuthTokenUsingPinPermissionGateOrderingBeatsPinBlocked()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("0x09-gate-beats-blocked");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        for(int attempt = 0; attempt < 8; attempt++)
        {
            using CtapWave5bPlatformPinSession mismatchSession = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
                simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
            byte[] wrongPinHashEnc = await mismatchSession.BuildWrongPinHashEncAsync(TestContext.CancellationToken);
            var mismatchRequest = new CtapClientPinRequest(
                SubCommand: WellKnownCtapClientPinSubCommands.GetPinToken, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two,
                KeyAgreement: mismatchSession.PlatformPublicKeyCose, PinHashEnc: wrongPinHashEnc);
            byte statusCode = await SendExpectingErrorAsync(simulator, mismatchRequest, pool);
            if(statusCode == WellKnownCtapStatusCodes.PinAuthBlocked)
            {
                simulator.PowerCycle();
            }
        }

        Assert.AreEqual(0, await GetPinRetriesAsync(simulator, pool), "retries must be fully exhausted for this ordering proof.");

        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        byte[] pinHashEnc = await session.BuildPinHashEncAsync("1234", TestContext.CancellationToken);
        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingPinWithPermissions,
            PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two, KeyAgreement: session.PlatformPublicKeyCose,
            PinHashEnc: pinHashEnc, Permissions: WellKnownCtapPinUvAuthTokenPermissions.Pcmr);

        byte gateStatus = await SendExpectingErrorAsync(simulator, request, pool);

        Assert.AreEqual(
            WellKnownCtapStatusCodes.UnauthorizedPermission, gateStatus,
            "the permission-statement gate must be evaluated before the PinBlocked pre-check.");
    }


    /// <summary>
    /// A fresh <c>getPinToken</c> issuance invalidates every prior outstanding token system-wide
    /// (line 5908/6018, "for all pinUvAuthProtocols"): a token issued on protocol two before a second
    /// <c>getPinToken</c> call is observably dead afterwards, proven through the in-use verify
    /// composition seam (<see cref="CtapPinUvAuthTokenVerificationExtensions.VerifyPinUvAuthTokenAsync"/>)
    /// against the authenticator's ACTUAL post-issuance protocol-two token state — captured off the
    /// simulator's own trace stream, never by comparing two independently-minted token values (which
    /// would differ on every call regardless of whether this line's system-wide invalidation is even
    /// implemented, since a fresh <c>getPinToken</c> always mints a new random token).
    /// </summary>
    [TestMethod]
    public async Task FreshTokenIssuanceInvalidatesEveryPriorOutstandingToken()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("token-issuance-invalidates-prior");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        using CtapWave5bPlatformPinSession firstSession = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        byte[] firstPinHashEnc = await firstSession.BuildPinHashEncAsync("1234", TestContext.CancellationToken);
        CtapClientPinResponse firstResponse = await SendAsync(simulator, new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinToken, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two,
            KeyAgreement: firstSession.PlatformPublicKeyCose, PinHashEnc: firstPinHashEnc), pool);
        byte[] firstToken = await firstSession.DecryptTokenAsync(firstResponse.PinUvAuthToken!.Value, TestContext.CancellationToken);

        var trace = new TestObserver<TraceEntry<CtapAuthenticatorState, CtapAuthenticatorInput>>();
        using(simulator.Subscribe(trace))
        {
            using CtapWave5bPlatformPinSession secondSession = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
                simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
            byte[] secondPinHashEnc = await secondSession.BuildPinHashEncAsync("1234", TestContext.CancellationToken);
            await SendAsync(simulator, new CtapClientPinRequest(
                SubCommand: WellKnownCtapClientPinSubCommands.GetPinToken, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two,
                KeyAgreement: secondSession.PlatformPublicKeyCose, PinHashEnc: secondPinHashEnc), pool);
        }

        CtapPinUvAuthTokenState currentProtocolTwoToken = trace.Received[^1].StateAfter.ProtocolTwoToken;

        CollectionAssert.AreNotEqual(
            firstToken, currentProtocolTwoToken.Token.AsReadOnlySpan().ToArray(),
            "each fresh getPinToken issuance must mint a genuinely new token value.");

        //A platform still holding the first token computes a signature under it; the authenticator's own
        //current token — the only key its real verify path ever presents — is the second, different
        //value, so the composition must reject the stale signature.
        CtapPinUvAuthProtocol protocolTwo = CtapPinUvAuthProtocol.CreateDefault(CtapPinUvAuthProtocolId.Two);
        byte[] probeMessage = Encoding.UTF8.GetBytes("token-reissuance-invalidation-probe");
        using IMemoryOwner<byte> staleSignature = await protocolTwo.AuthenticateAsync(
            firstToken, probeMessage, pool, TestContext.CancellationToken);

        bool verified = await protocolTwo.VerifyPinUvAuthTokenAsync(
            currentProtocolTwoToken, currentProtocolTwoToken.Token.AsReadOnlyMemory(), probeMessage, staleSignature.Memory, pool, TestContext.CancellationToken);

        Assert.IsFalse(verified, "the prior token must fail the in-use verify composition once a fresh issuance replaces it.");
    }


    /// <summary>
    /// A wrong-PIN <c>getPinToken</c> attempt's <c>regenerate()</c> refreshes only the SELECTED
    /// protocol's key-agreement key pair — mirrors <c>changePIN</c>'s equivalent proof.
    /// </summary>
    [TestMethod]
    public async Task GetPinTokenMismatchRegeneratesOnlySelectedProtocolsKeyAgreementKey()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("getpintoken-mismatch-regenerate");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        CoseKey protocolOneKeyBefore = await GetKeyAgreementAsync(simulator, pool, CtapPinUvAuthProtocolId.One);
        CoseKey protocolTwoKeyBefore = await GetKeyAgreementAsync(simulator, pool, CtapPinUvAuthProtocolId.Two);

        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.One, pool, TestContext.CancellationToken);
        byte[] wrongPinHashEnc = await session.BuildWrongPinHashEncAsync(TestContext.CancellationToken);
        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinToken, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.One,
            KeyAgreement: session.PlatformPublicKeyCose, PinHashEnc: wrongPinHashEnc);
        Assert.AreEqual(WellKnownCtapStatusCodes.PinInvalid, await SendExpectingErrorAsync(simulator, request, pool));

        CoseKey protocolOneKeyAfter = await GetKeyAgreementAsync(simulator, pool, CtapPinUvAuthProtocolId.One);
        CoseKey protocolTwoKeyAfter = await GetKeyAgreementAsync(simulator, pool, CtapPinUvAuthProtocolId.Two);

        Assert.IsFalse(protocolOneKeyBefore.X!.Value.Span.SequenceEqual(protocolOneKeyAfter.X!.Value.Span), "the mismatched protocol's key must regenerate.");
        Assert.IsTrue(protocolTwoKeyBefore.X!.Value.Span.SequenceEqual(protocolTwoKeyAfter.X!.Value.Span), "the untouched protocol's key must be unaffected.");
    }


    /// <summary>
    /// The shared <c>getPinToken</c>/<c>getPinUvAuthTokenUsingPinWithPermissions</c> effect zeroes the
    /// <c>decapsulate</c> shared secret before it returns to the pool (CTAP 2.3 §6.5.5.7.1/§6.5.5.7.2,
    /// wave-5b contract decision 4) — observed by tracking the exact shared-secret size
    /// <see cref="CtapAuthenticatorSimulator"/>'s <c>IssuePinTokenAsync</c> effect rents at its
    /// <c>DecapsulateAsync</c> call site, through the pool-seam parameter every production call site
    /// already takes, mirroring <see cref="CtapPinUvAuthProtocolTests.ProtocolTwoDecapsulateClearsKdfIntermediateHalfBuffersBeforeReturningThemToThePool"/>'s
    /// approach. Covers both subcommands, since both dispatch to the same effect.
    /// </summary>
    [TestMethod]
    [DataRow(CtapPinUvAuthProtocolId.One, 32, false, DisplayName = "protocol one, getPinToken: 32-byte shared secret")]
    [DataRow(CtapPinUvAuthProtocolId.Two, 64, false, DisplayName = "protocol two, getPinToken: 64-byte shared secret")]
    [DataRow(CtapPinUvAuthProtocolId.Two, 64, true, DisplayName = "protocol two, 0x09: 64-byte shared secret")]
    public async Task TokenIssuanceZeroesTheSharedSecretBeforeReturningItToThePool(
        CtapPinUvAuthProtocolId protocolId, int sharedSecretLength, bool useSubcommandWithPermissions)
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator(
            $"token-issuance-zeroization-{protocolId}-{useSubcommandWithPermissions}");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234", protocolId);

        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, protocolId, pool, TestContext.CancellationToken);
        byte[] pinHashEnc = await session.BuildPinHashEncAsync("1234", TestContext.CancellationToken);

        CtapClientPinRequest request = useSubcommandWithPermissions
            ? new CtapClientPinRequest(
                SubCommand: WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingPinWithPermissions,
                PinUvAuthProtocol: (int)protocolId, KeyAgreement: session.PlatformPublicKeyCose,
                PinHashEnc: pinHashEnc,
                Permissions: WellKnownCtapPinUvAuthTokenPermissions.Mc | WellKnownCtapPinUvAuthTokenPermissions.Ga,
                RpId: "example.com")
            : new CtapClientPinRequest(
                SubCommand: WellKnownCtapClientPinSubCommands.GetPinToken, PinUvAuthProtocol: (int)protocolId,
                KeyAgreement: session.PlatformPublicKeyCose, PinHashEnc: pinHashEnc);

        using var trackingPool = new ZeroOnDisposeTrackingMemoryPool(sharedSecretLength);
        await SendAsync(simulator, request, trackingPool);

        Assert.IsGreaterThanOrEqualTo(1, trackingPool.TrackedDisposalCount,
            "the token-issuance effect must rent and dispose at least the decapsulate shared secret at its exact length.");
        Assert.IsTrue(trackingPool.AllTrackedDisposalsWereZero,
            "every buffer the token-issuance effect disposes at the shared-secret length - including the shared secret itself - must be zeroed before it returns to the pool.");
    }


    /// <summary>Reads the current <c>pinRetries</c> counter via <c>getPINRetries</c>.</summary>
    private async Task<int> GetPinRetriesAsync(CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool)
    {
        var request = new CtapClientPinRequest(SubCommand: WellKnownCtapClientPinSubCommands.GetPinRetries);
        CtapClientPinResponse response = await SendAsync(simulator, request, pool);

        return response.PinRetries!.Value;
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
