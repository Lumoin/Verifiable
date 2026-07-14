using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cbor.Ctap;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="CtapAuthenticatorSimulator"/>'s <c>authenticatorClientPIN</c> <c>setPIN</c>
/// (<c>0x03</c>) subcommand (CTAP 2.3 §6.5.5.5): every pure pre-check in spec order, the effectful
/// crypto sequence's failure/success outcomes, the new-PIN validation chain (64-byte padded check,
/// trailing-0x00 strip, code-point-not-byte counting, the 63-byte maximum), and the resulting
/// <c>clientPin</c> flip in <c>authenticatorGetInfo</c>. The platform role is driven with the same
/// <see cref="CtapPinUvAuthProtocol"/> operations the authenticator itself uses, per
/// <see cref="CtapWave5bPinCryptoFixtures"/>.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorSetPinTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// A fresh <c>setPIN</c> establishes the PIN (CTAP2_OK, no response body) and flips
    /// <c>authenticatorGetInfo</c>'s <c>clientPin</c> option from <see langword="false"/> to
    /// <see langword="true"/> (CTAP 2.3 §9 line 9076, wave-5b decision 8).
    /// </summary>
    [TestMethod]
    [DataRow(CtapPinUvAuthProtocolId.One, DisplayName = "protocol one")]
    [DataRow(CtapPinUvAuthProtocolId.Two, DisplayName = "protocol two")]
    public async Task SetPinHappyPathSucceedsAndFlipsClientPinToTrue(CtapPinUvAuthProtocolId protocolId)
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator($"setpin-happy-{protocolId}");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapGetInfoResponse beforeInfo = await GetInfoAsync(simulator, pool);
        Assert.IsFalse(beforeInfo.Options!.ClientPin!.Value, "clientPin must be false before any PIN is set.");

        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, protocolId, pool, TestContext.CancellationToken);
        (byte[] newPinEnc, byte[] pinUvAuthParam) = await session.BuildSetPinMessagesAsync("1234", TestContext.CancellationToken);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.SetPin,
            PinUvAuthProtocol: (int)protocolId,
            KeyAgreement: session.PlatformPublicKeyCose,
            PinUvAuthParam: pinUvAuthParam,
            NewPinEnc: newPinEnc);

        CtapClientPinResponse response = await SendAsync(simulator, request, pool);

        Assert.IsNull(response.PinUvAuthToken);
        Assert.IsNull(response.KeyAgreement);

        CtapGetInfoResponse afterInfo = await GetInfoAsync(simulator, pool);
        Assert.IsTrue(afterInfo.Options!.ClientPin!.Value, "clientPin must be true once setPIN has succeeded.");
    }


    /// <summary>Each mandatory parameter's absence fails with <c>CTAP2_ERR_MISSING_PARAMETER</c>, checked before any crypto action.</summary>
    [TestMethod]
    public async Task SetPinMissingMandatoryParametersReturnsMissingParameter()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("setpin-missing-params");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        (byte[] newPinEnc, byte[] pinUvAuthParam) = await session.BuildSetPinMessagesAsync("1234", TestContext.CancellationToken);

        byte statusWithoutProtocol = await SendExpectingErrorAsync(simulator, new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.SetPin, KeyAgreement: session.PlatformPublicKeyCose,
            PinUvAuthParam: pinUvAuthParam, NewPinEnc: newPinEnc), pool);
        Assert.AreEqual(WellKnownCtapStatusCodes.MissingParameter, statusWithoutProtocol);

        byte statusWithoutKeyAgreement = await SendExpectingErrorAsync(simulator, new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.SetPin, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two,
            PinUvAuthParam: pinUvAuthParam, NewPinEnc: newPinEnc), pool);
        Assert.AreEqual(WellKnownCtapStatusCodes.MissingParameter, statusWithoutKeyAgreement);

        byte statusWithoutPinUvAuthParam = await SendExpectingErrorAsync(simulator, new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.SetPin, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two,
            KeyAgreement: session.PlatformPublicKeyCose, NewPinEnc: newPinEnc), pool);
        Assert.AreEqual(WellKnownCtapStatusCodes.MissingParameter, statusWithoutPinUvAuthParam);

        byte statusWithoutNewPinEnc = await SendExpectingErrorAsync(simulator, new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.SetPin, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two,
            KeyAgreement: session.PlatformPublicKeyCose, PinUvAuthParam: pinUvAuthParam), pool);
        Assert.AreEqual(WellKnownCtapStatusCodes.MissingParameter, statusWithoutNewPinEnc);
    }


    /// <summary>An unsupported <c>pinUvAuthProtocol</c> value fails with <c>CTAP1_ERR_INVALID_PARAMETER</c>, before any crypto action.</summary>
    [TestMethod]
    public async Task SetPinUnsupportedProtocolReturnsInvalidParameter()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("setpin-unsupported-protocol");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        (byte[] newPinEnc, byte[] pinUvAuthParam) = await session.BuildSetPinMessagesAsync("1234", TestContext.CancellationToken);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.SetPin, PinUvAuthProtocol: 99,
            KeyAgreement: session.PlatformPublicKeyCose, PinUvAuthParam: pinUvAuthParam, NewPinEnc: newPinEnc);

        byte statusCode = await SendExpectingErrorAsync(simulator, request, pool);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidParameter, statusCode);
    }


    /// <summary>A second <c>setPIN</c> against an authenticator that already has a PIN fails with <c>CTAP2_ERR_PIN_AUTH_INVALID</c> (line 5568), before any crypto action.</summary>
    [TestMethod]
    public async Task SetPinWhenAlreadySetReturnsPinAuthInvalid()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("setpin-already-set");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await EstablishPinAsync(simulator, pool, "1234");

        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        (byte[] newPinEnc, byte[] pinUvAuthParam) = await session.BuildSetPinMessagesAsync("5678", TestContext.CancellationToken);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.SetPin, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two,
            KeyAgreement: session.PlatformPublicKeyCose, PinUvAuthParam: pinUvAuthParam, NewPinEnc: newPinEnc);

        byte statusCode = await SendExpectingErrorAsync(simulator, request, pool);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthInvalid, statusCode);
    }


    /// <summary>A <c>pinUvAuthParam</c> that does not verify against <c>newPinEnc</c> fails with <c>CTAP2_ERR_PIN_AUTH_INVALID</c>.</summary>
    [TestMethod]
    public async Task SetPinWithBadSignatureReturnsPinAuthInvalid()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("setpin-bad-signature");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        (byte[] newPinEnc, _) = await session.BuildSetPinMessagesAsync("1234", TestContext.CancellationToken);

        using IMemoryOwner<byte> garbageSignatureOwner = pool.Rent(32);
        garbageSignatureOwner.Memory.Span[..32].Fill(0xAB);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.SetPin, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two,
            KeyAgreement: session.PlatformPublicKeyCose, PinUvAuthParam: garbageSignatureOwner.Memory[..32], NewPinEnc: newPinEnc);

        byte statusCode = await SendExpectingErrorAsync(simulator, request, pool);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthInvalid, statusCode);
    }


    /// <summary>
    /// A verified <c>newPinEnc</c> that decrypts to something other than exactly 64 bytes fails with
    /// <c>CTAP1_ERR_INVALID_PARAMETER</c> (line 5580) — a check distinct from, and prior to, the
    /// minimum-length policy check.
    /// </summary>
    [TestMethod]
    public async Task SetPinWithNonSixtyFourBytePaddedPinReturnsInvalidParameter()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("setpin-bad-padded-length");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);

        byte[] blockAlignedNonPaddedPlaintext = new byte[32];
        blockAlignedNonPaddedPlaintext.AsSpan().Fill(0x41);
        (byte[] newPinEnc, byte[] pinUvAuthParam) = await session.BuildCustomVerifiedMessageAsync(blockAlignedNonPaddedPlaintext, TestContext.CancellationToken);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.SetPin, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two,
            KeyAgreement: session.PlatformPublicKeyCose, PinUvAuthParam: pinUvAuthParam, NewPinEnc: newPinEnc);

        byte statusCode = await SendExpectingErrorAsync(simulator, request, pool);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidParameter, statusCode);
    }


    /// <summary>A new PIN below the 4-code-point minimum fails with <c>CTAP2_ERR_PIN_POLICY_VIOLATION</c> (line 5584).</summary>
    [TestMethod]
    public async Task SetPinBelowMinimumCodePointLengthReturnsPinPolicyViolation()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("setpin-too-short");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        (byte[] newPinEnc, byte[] pinUvAuthParam) = await session.BuildSetPinMessagesAsync("123", TestContext.CancellationToken);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.SetPin, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two,
            KeyAgreement: session.PlatformPublicKeyCose, PinUvAuthParam: pinUvAuthParam, NewPinEnc: newPinEnc);

        byte statusCode = await SendExpectingErrorAsync(simulator, request, pool);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinPolicyViolation, statusCode);
    }


    /// <summary>
    /// A PIN of three 4-byte-UTF-8 code points (12 bytes, fewer than the 4-code-point minimum) fails
    /// with <c>CTAP2_ERR_PIN_POLICY_VIOLATION</c>, proving the minimum is enforced in Unicode CODE
    /// POINTS: a byte-length check alone would have accepted 12 bytes.
    /// </summary>
    [TestMethod]
    public async Task SetPinCountsCodePointsNotUtf8BytesForTheMinimum()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("setpin-code-point-counting-reject");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);

        //U+1F600 GRINNING FACE: 4 UTF-8 bytes per code point. Three of them: 12 bytes, 3 code points.
        string threeEmojiPin = "\U0001F600\U0001F600\U0001F600";
        (byte[] newPinEnc, byte[] pinUvAuthParam) = await session.BuildSetPinMessagesAsync(threeEmojiPin, TestContext.CancellationToken);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.SetPin, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two,
            KeyAgreement: session.PlatformPublicKeyCose, PinUvAuthParam: pinUvAuthParam, NewPinEnc: newPinEnc);

        byte statusCode = await SendExpectingErrorAsync(simulator, request, pool);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinPolicyViolation, statusCode);
    }


    /// <summary>
    /// A PIN of four 4-byte-UTF-8 code points (16 bytes, exactly the 4-code-point minimum) succeeds,
    /// completing the proof that the minimum is counted in code points rather than bytes.
    /// </summary>
    [TestMethod]
    public async Task SetPinWithFourMultiByteCodePointsSucceeds()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("setpin-code-point-counting-accept");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);

        string fourEmojiPin = "\U0001F600\U0001F600\U0001F600\U0001F600";
        (byte[] newPinEnc, byte[] pinUvAuthParam) = await session.BuildSetPinMessagesAsync(fourEmojiPin, TestContext.CancellationToken);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.SetPin, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two,
            KeyAgreement: session.PlatformPublicKeyCose, PinUvAuthParam: pinUvAuthParam, NewPinEnc: newPinEnc);

        CtapClientPinResponse response = await SendAsync(simulator, request, pool);

        Assert.IsNull(response.PinUvAuthToken);
    }


    /// <summary>
    /// A 63-byte ASCII PIN — the maximum length the padding formula admits (CTAP 2.3 line 5555: "the
    /// maximum length of newPin is 63 bytes, there is always at least one byte of padding") — succeeds.
    /// </summary>
    [TestMethod]
    public async Task SetPinWithSixtyThreeByteMaximumLengthPinSucceeds()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("setpin-63-byte-max");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);

        string sixtyThreeBytePin = new('a', 63);
        (byte[] newPinEnc, byte[] pinUvAuthParam) = await session.BuildSetPinMessagesAsync(sixtyThreeBytePin, TestContext.CancellationToken);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.SetPin, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two,
            KeyAgreement: session.PlatformPublicKeyCose, PinUvAuthParam: pinUvAuthParam, NewPinEnc: newPinEnc);

        CtapClientPinResponse response = await SendAsync(simulator, request, pool);

        Assert.IsNull(response.PinUvAuthToken);
    }


    /// <summary>
    /// <c>setPIN</c>'s effect zeroes the <c>decapsulate</c> shared secret before it returns to the pool
    /// (CTAP 2.3 §6.5.5.5, wave-5b contract decision 4) — observed by tracking the exact shared-secret
    /// size <see cref="CtapAuthenticatorSimulator"/>'s <c>EstablishPinAsync</c> effect rents at its
    /// <c>DecapsulateAsync</c> call site, through the pool-seam parameter every production call site
    /// already takes, mirroring <see cref="CtapPinUvAuthProtocolTests.ProtocolTwoDecapsulateClearsKdfIntermediateHalfBuffersBeforeReturningThemToThePool"/>'s
    /// approach.
    /// </summary>
    [TestMethod]
    [DataRow(CtapPinUvAuthProtocolId.One, 32, DisplayName = "protocol one: 32-byte shared secret")]
    [DataRow(CtapPinUvAuthProtocolId.Two, 64, DisplayName = "protocol two: 64-byte shared secret")]
    public async Task SetPinZeroesTheSharedSecretBeforeReturningItToThePool(CtapPinUvAuthProtocolId protocolId, int sharedSecretLength)
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator($"setpin-zeroization-{protocolId}");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, protocolId, pool, TestContext.CancellationToken);
        (byte[] newPinEnc, byte[] pinUvAuthParam) = await session.BuildSetPinMessagesAsync("1234", TestContext.CancellationToken);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.SetPin, PinUvAuthProtocol: (int)protocolId,
            KeyAgreement: session.PlatformPublicKeyCose, PinUvAuthParam: pinUvAuthParam, NewPinEnc: newPinEnc);

        using var trackingPool = new ZeroOnDisposeTrackingMemoryPool(sharedSecretLength);
        await SendAsync(simulator, request, trackingPool);

        Assert.IsGreaterThanOrEqualTo(1, trackingPool.TrackedDisposalCount,
            "setPIN's effect must rent and dispose at least the decapsulate shared secret at its exact length.");
        Assert.IsTrue(trackingPool.AllTrackedDisposalsWereZero,
            "every buffer setPIN's effect disposes at the shared-secret length - including the shared secret itself - must be zeroed before it returns to the pool.");
    }


    /// <summary>Establishes a PIN on <paramref name="simulator"/> via a fresh protocol-two session, for tests whose focus is a later subcommand.</summary>
    internal static async Task EstablishPinAsync(CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool, string pin, CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, protocolId, pool, CancellationToken.None);
        (byte[] newPinEnc, byte[] pinUvAuthParam) = await session.BuildSetPinMessagesAsync(pin, CancellationToken.None);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.SetPin, PinUvAuthProtocol: (int)protocolId,
            KeyAgreement: session.PlatformPublicKeyCose, PinUvAuthParam: pinUvAuthParam, NewPinEnc: newPinEnc);

        CtapClientPinResponse response = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            simulator.TransceiveAsync, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, CancellationToken.None);
        _ = response;
    }


    /// <summary>Sends an <c>authenticatorGetInfo</c> request and decodes its response.</summary>
    private static async Task<CtapGetInfoResponse> GetInfoAsync(CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool)
    {
        using IMemoryOwner<byte> requestOwner = pool.Rent(1);
        requestOwner.Memory.Span[0] = WellKnownCtapCommands.GetInfo;
        using PooledMemory response = await simulator.TransceiveAsync(requestOwner.Memory[..1], pool, CancellationToken.None);

        return CtapGetInfoResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
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
