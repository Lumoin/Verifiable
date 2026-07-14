using System.Buffers;
using System.Threading.Tasks;
using Verifiable.Cbor.Ctap;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="CtapAuthenticatorSimulator"/>'s <c>authenticatorClientPIN</c> handler: the three
/// read-only subcommands wave-a implements (<c>getPINRetries</c>, <c>getKeyAgreement</c>,
/// <c>getUVRetries</c>) and the unimplemented-subcommand/missing-parameter/unsupported-protocol error
/// paths — driven over <see cref="CtapAuthenticatorSimulator.TransceiveAsync"/> with the shipped CBOR
/// codecs, mirroring <c>CtapAuthenticatorGetNextAssertionTests</c>'s composition.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorClientPinTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The simulator-realism seeded value for both <c>pinRetries</c> and <c>uvRetries</c> (CTAP 2.3 mandates no specific starting value for either).</summary>
    private const int SeededRetries = 8;


    /// <summary>
    /// <c>getPINRetries</c> reports the seeded <c>pinRetries</c> counter, no other member, and an honest
    /// <c>powerCycleState: false</c> (CTAP 2.3, line 5422-5437) — the authenticator is not latched.
    /// </summary>
    [TestMethod]
    public async Task GetPinRetriesReportsSeededCounter()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("clientpin-get-pin-retries");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapClientPinRequest(SubCommand: WellKnownCtapClientPinSubCommands.GetPinRetries);
        CtapClientPinResponse response = await SendClientPinAsync(simulator, request, pool);

        Assert.AreEqual(SeededRetries, response.PinRetries);
        Assert.IsNull(response.UvRetries);
        Assert.IsNull(response.KeyAgreement);
        Assert.IsNull(response.PinUvAuthToken);
        Assert.IsFalse(response.PowerCycleState);
    }


    /// <summary><c>getUVRetries</c> reports the seeded <c>uvRetries</c> counter and no other member.</summary>
    [TestMethod]
    public async Task GetUvRetriesReportsSeededCounter()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("clientpin-get-uv-retries");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapClientPinRequest(SubCommand: WellKnownCtapClientPinSubCommands.GetUvRetries);
        CtapClientPinResponse response = await SendClientPinAsync(simulator, request, pool);

        Assert.AreEqual(SeededRetries, response.UvRetries);
        Assert.IsNull(response.PinRetries);
        Assert.IsNull(response.KeyAgreement);
    }


    /// <summary>
    /// <c>getKeyAgreement</c> for protocol one returns a valid COSE_Key: <c>kty=EC2</c>, the literal
    /// <c>alg=-25</c>, <c>crv=P-256</c>, 32-byte <c>x</c>/<c>y</c>, and no other optional member (CTAP
    /// 2.3 §2.1's "MUST NOT contain any other optional parameters" constraint).
    /// </summary>
    [TestMethod]
    public async Task GetKeyAgreementForProtocolOneReturnsValidCoseKey()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("clientpin-get-key-agreement-one");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetKeyAgreement, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.One);
        CtapClientPinResponse response = await SendClientPinAsync(simulator, request, pool);

        AssertValidKeyAgreementCoseKey(response.KeyAgreement);
    }


    /// <summary>
    /// <c>getKeyAgreement</c> for protocol two also returns a valid COSE_Key, and it carries different
    /// key bytes than protocol one's — each protocol maintains its own key-agreement key pair.
    /// </summary>
    [TestMethod]
    public async Task GetKeyAgreementForProtocolTwoReturnsValidDistinctCoseKey()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("clientpin-get-key-agreement-two");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapClientPinResponse protocolOneResponse = await SendClientPinAsync(
            simulator, new CtapClientPinRequest(SubCommand: WellKnownCtapClientPinSubCommands.GetKeyAgreement, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.One), pool);
        CtapClientPinResponse protocolTwoResponse = await SendClientPinAsync(
            simulator, new CtapClientPinRequest(SubCommand: WellKnownCtapClientPinSubCommands.GetKeyAgreement, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two), pool);

        AssertValidKeyAgreementCoseKey(protocolTwoResponse.KeyAgreement);
        Assert.IsFalse(
            protocolOneResponse.KeyAgreement!.X!.Value.Span.SequenceEqual(protocolTwoResponse.KeyAgreement!.X!.Value.Span)
            && protocolOneResponse.KeyAgreement.Y!.Value.Span.SequenceEqual(protocolTwoResponse.KeyAgreement.Y!.Value.Span),
            "Protocol one and protocol two must maintain independent key-agreement key pairs.");
    }


    /// <summary><c>getKeyAgreement</c> without <c>pinUvAuthProtocol</c> fails with <c>CTAP2_ERR_MISSING_PARAMETER</c> — its mandatory protocol-selection parameter is absent.</summary>
    [TestMethod]
    public async Task GetKeyAgreementWithoutProtocolReturnsMissingParameter()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("clientpin-get-key-agreement-missing-protocol");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapClientPinRequest(SubCommand: WellKnownCtapClientPinSubCommands.GetKeyAgreement);
        byte statusCode = await SendClientPinExpectingErrorAsync(simulator, request, pool);

        Assert.AreEqual(WellKnownCtapStatusCodes.MissingParameter, statusCode);
    }


    /// <summary><c>getKeyAgreement</c> with an unsupported <c>pinUvAuthProtocol</c> value fails with <c>CTAP1_ERR_INVALID_PARAMETER</c>.</summary>
    [TestMethod]
    public async Task GetKeyAgreementWithUnsupportedProtocolReturnsInvalidParameter()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("clientpin-get-key-agreement-bad-protocol");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapClientPinRequest(SubCommand: WellKnownCtapClientPinSubCommands.GetKeyAgreement, PinUvAuthProtocol: 99);
        byte statusCode = await SendClientPinExpectingErrorAsync(simulator, request, pool);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidParameter, statusCode);
    }


    /// <summary>
    /// An arbitrary out-of-table <c>subCommand</c> value fails with <c>CTAP2_ERR_INVALID_SUBCOMMAND</c>
    /// (R1 ruling: section 8.1's general dispatch MUST, line 8810, governs this event; section 6.5.5's
    /// own command definition names no subcommand-not-supported status of its own to conflict with it),
    /// never a silent success. This is a SPLIT, not a flip: the wavebio wave's own PKG-C removed this
    /// test's former <c>DataRow(0x06)</c> case — <c>getPinUvAuthTokenUsingUvWithPermissions</c> is no
    /// longer unsupported, it runs its own full seventeen-step algorithm
    /// (<c>CtapAuthenticatorBuiltInUvTests</c> exercises its own status ladder, starting with
    /// <c>GetPinUvAuthTokenUsingUvWithPermissionsWithoutEnrollmentsReturnsNotAllowed</c>). The four
    /// PIN-path subcommands (<c>setPIN</c>/<c>changePIN</c>/<c>getPinToken</c>/
    /// <c>getPinUvAuthTokenUsingPinWithPermissions</c>) are exercised by their own dedicated test
    /// suites, since a bare <c>SubCommand</c>-only request now resolves to their own
    /// missing-mandatory-parameter status instead.
    /// </summary>
    [TestMethod]
    [DataRow(0x63, DisplayName = "an arbitrary out-of-table value")]
    public async Task UnsupportedSubCommandReturnsInvalidSubcommand(int subCommand)
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator($"clientpin-unsupported-subcommand-{subCommand:X2}");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapClientPinRequest(SubCommand: subCommand);
        byte statusCode = await SendClientPinExpectingErrorAsync(simulator, request, pool);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidSubcommand, statusCode);
    }


    /// <summary>Asserts <paramref name="coseKey"/> is a spec-valid <c>getKeyAgreement</c> COSE_Key.</summary>
    private static void AssertValidKeyAgreementCoseKey(CoseKey? coseKey)
    {
        Assert.IsNotNull(coseKey);
        Assert.AreEqual(CoseKeyTypes.Ec2, coseKey!.Kty, "kty must be EC2 (2).");
        Assert.AreEqual(-25, coseKey.Alg, "alg must be the literal -25 (CTAP 2.3 §6.5.6 line 6182).");
        Assert.AreEqual(CoseKeyCurves.P256, coseKey.Curve, "crv must be P-256 (1).");
        Assert.IsNotNull(coseKey.X);
        Assert.HasCount(32, coseKey.X!.Value.ToArray());
        Assert.IsNotNull(coseKey.Y);
        Assert.HasCount(32, coseKey.Y!.Value.ToArray());
        Assert.IsNull(coseKey.EncodedYCompressionSign, "getKeyAgreement's COSE_Key carries no other optional member.");
        Assert.IsNull(coseKey.N, "getKeyAgreement's COSE_Key carries no RSA members.");
        Assert.IsNull(coseKey.E, "getKeyAgreement's COSE_Key carries no RSA members.");
    }


    /// <summary>Sends an <c>authenticatorClientPIN</c> request expected to succeed and decodes its response.</summary>
    private async Task<CtapClientPinResponse> SendClientPinAsync(CtapAuthenticatorSimulator simulator, CtapClientPinRequest request, MemoryPool<byte> pool)
    {
        return await CtapAuthenticatorClientPinClient.ClientPinAsync(
            simulator.TransceiveAsync, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, TestContext.CancellationToken);
    }


    /// <summary>Sends an <c>authenticatorClientPIN</c> request expected to fail and returns the exact status code.</summary>
    private async Task<byte> SendClientPinExpectingErrorAsync(CtapAuthenticatorSimulator simulator, CtapClientPinRequest request, MemoryPool<byte> pool)
    {
        CtapCommandException exception = await Assert.ThrowsExactlyAsync<CtapCommandException>(
            () => SendClientPinAsync(simulator, request, pool));

        return exception.StatusCode;
    }
}
