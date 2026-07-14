using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cbor.Ctap;
using Verifiable.Cbor.Fido2;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;
using static Verifiable.Tests.TestInfrastructure.CtapWave2AuthenticatorFixtures;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// The wave-5c unit-test matrix for the <c>pinUvAuthToken</c> machinery <c>authenticatorMakeCredential</c>/
/// <c>authenticatorGetAssertion</c> wire in: the zero-length probe, the <c>makeCredUvNotRqd</c>-gated
/// <c>PuatRequired</c>/fast-path split, the verify+permission+RP-ID-binding sequence (each command's own
/// literal order), single-use/first-use-binding semantics, cross-protocol token isolation, usage-timer
/// expiry, and the <c>uv</c> bit's propagation into an <c>authenticatorGetNextAssertion</c> continuation
/// of a UV-verified multi-account sequence. Driven in-process through <see cref="CtapAuthenticatorSimulator.TransceiveAsync"/>
/// (no real transport needed for these unit-level cases — the real-wire capstones live elsewhere), with
/// platform-side crypto computed the same way the wave-5b fixtures already do
/// (<see cref="CtapWave5bPinCryptoFixtures"/>/<see cref="CtapPinUvAuthProtocol.AuthenticateAsync"/>) —
/// never a back-channel read of token state. Every assertion reads the response's decoded wire bytes
/// (<see cref="AuthenticatorDataReader"/>), never internal simulator state.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorPinUvAuthBindingTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The relying party identifier a token's permissions RP ID binds to in these tests, matching <see cref="DefaultRpId"/>.</summary>
    private const string RpIdA = DefaultRpId;

    /// <summary>A second relying party identifier, distinct from <see cref="RpIdA"/>, for RP-ID-mismatch scenarios.</summary>
    private const string RpIdB = "other-rp.example";


    /// <summary>Establishes a PIN and issues a <c>pinUvAuthToken</c> bound to <paramref name="rpId"/> with <paramref name="permissions"/> via <c>getPinUvAuthTokenUsingPinWithPermissions</c> (0x09).</summary>
    private static async Task<byte[]> IssueTokenWithPermissionsAsync(
        CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool, CtapPinUvAuthProtocolId protocolId, int permissions, string rpId, CancellationToken cancellationToken)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, protocolId, pool, cancellationToken).ConfigureAwait(false);
        byte[] pinHashEnc = await session.BuildPinHashEncAsync("1234", cancellationToken).ConfigureAwait(false);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingPinWithPermissions,
            PinUvAuthProtocol: (int)protocolId, KeyAgreement: session.PlatformPublicKeyCose,
            PinHashEnc: pinHashEnc, Permissions: permissions, RpId: rpId);
        CtapClientPinResponse response = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            simulator.TransceiveAsync, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken).ConfigureAwait(false);

        return await session.DecryptTokenAsync(response.PinUvAuthToken!.Value, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>Establishes a PIN and issues an UNBOUND <c>pinUvAuthToken</c> with the default <c>mc|ga</c> permissions via <c>getPinToken</c> (0x05).</summary>
    private static async Task<byte[]> IssueUnboundTokenAsync(
        CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool, CtapPinUvAuthProtocolId protocolId, CancellationToken cancellationToken)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, protocolId, pool, cancellationToken).ConfigureAwait(false);
        byte[] pinHashEnc = await session.BuildPinHashEncAsync("1234", cancellationToken).ConfigureAwait(false);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinToken, PinUvAuthProtocol: (int)protocolId,
            KeyAgreement: session.PlatformPublicKeyCose, PinHashEnc: pinHashEnc);
        CtapClientPinResponse response = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            simulator.TransceiveAsync, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken).ConfigureAwait(false);

        return await session.DecryptTokenAsync(response.PinUvAuthToken!.Value, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>Computes <c>authenticate(token, message)</c> under <paramref name="protocolId"/>'s own truncation rule — the exact platform-side computation <c>verify</c> checks a presented <c>pinUvAuthParam</c> against.</summary>
    private static async Task<byte[]> ComputeSignatureAsync(
        byte[] token, CtapPinUvAuthProtocolId protocolId, byte[] message, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        CtapPinUvAuthProtocol protocol = CtapPinUvAuthProtocol.CreateDefault(protocolId);
        using IMemoryOwner<byte> signature = await protocol.AuthenticateAsync(token, message, pool, cancellationToken).ConfigureAwait(false);

        return signature.Memory.Span.ToArray();
    }


    /// <summary>The fixed <c>clientDataHash</c> bytes <see cref="BuildMakeCredentialRequest"/> always embeds — the mc verify message.</summary>
    private static byte[] McClientDataHash => BuildFixedBytes(32, 0x10);

    /// <summary>The fixed <c>clientDataHash</c> bytes <see cref="BuildGetAssertionRequest"/> always embeds — the ga verify message.</summary>
    private static byte[] GaClientDataHash => BuildFixedBytes(32, 0x20);


    /// <summary>Reads the current <c>pinRetries</c> counter via <c>getPINRetries</c>.</summary>
    private async Task<int> GetPinRetriesAsync(CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool)
    {
        var request = new CtapClientPinRequest(SubCommand: WellKnownCtapClientPinSubCommands.GetPinRetries);
        CtapClientPinResponse response = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            simulator.TransceiveAsync, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, TestContext.CancellationToken).ConfigureAwait(false);

        return response.PinRetries!.Value;
    }


    /// <summary>Step 1: a zero-length <c>pinUvAuthParam</c> with no PIN set returns <c>PinNotSet</c>, even with the protocol parameter absent (the probe wins over <c>MissingParameter</c>).</summary>
    [TestMethod]
    public async Task ZeroLengthPinUvAuthParamOnMakeCredentialWithNoPinSetReturnsPinNotSet()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("mc-probe-no-pin");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, pinUvAuthParam: ReadOnlyMemory<byte>.Empty);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinNotSet, response.AsReadOnlySpan()[0]);
    }


    /// <summary>Step 1: a zero-length <c>pinUvAuthParam</c> once a PIN is set returns <c>PinInvalid</c>.</summary>
    [TestMethod]
    public async Task ZeroLengthPinUvAuthParamOnMakeCredentialWithPinSetReturnsPinInvalid()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("mc-probe-pin-set");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, pinUvAuthParam: ReadOnlyMemory<byte>.Empty);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinInvalid, response.AsReadOnlySpan()[0]);
    }


    /// <summary>Step 1: a zero-length <c>pinUvAuthParam</c> accompanied by an UNSUPPORTED protocol still wins — the probe fires before step 2's <c>InvalidParameter</c> half.</summary>
    [TestMethod]
    public async Task ZeroLengthPinUvAuthParamOnMakeCredentialWithUnsupportedProtocolReturnsPinNotSet()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("mc-probe-unsupported-protocol");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, pinUvAuthParam: ReadOnlyMemory<byte>.Empty, pinUvAuthProtocol: 3);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinNotSet, response.AsReadOnlySpan()[0]);
    }


    /// <summary>Step 1 (ga): a zero-length <c>pinUvAuthParam</c> with no PIN set returns <c>PinNotSet</c>, protocol absent (the probe wins over <c>MissingParameter</c>).</summary>
    [TestMethod]
    public async Task ZeroLengthPinUvAuthParamOnGetAssertionWithNoPinSetReturnsPinNotSet()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("ga-probe-no-pin");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapGetAssertionRequest request = BuildGetAssertionRequest(pool, pinUvAuthParam: ReadOnlyMemory<byte>.Empty);
        using PooledMemory response = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinNotSet, response.AsReadOnlySpan()[0]);
    }


    /// <summary>Step 1 (ga): a zero-length <c>pinUvAuthParam</c> once a PIN is set returns <c>PinInvalid</c>.</summary>
    [TestMethod]
    public async Task ZeroLengthPinUvAuthParamOnGetAssertionWithPinSetReturnsPinInvalid()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("ga-probe-pin-set");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        CtapGetAssertionRequest request = BuildGetAssertionRequest(pool, pinUvAuthParam: ReadOnlyMemory<byte>.Empty);
        using PooledMemory response = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinInvalid, response.AsReadOnlySpan()[0]);
    }


    /// <summary>Step 1 (ga): a zero-length <c>pinUvAuthParam</c> accompanied by an UNSUPPORTED protocol still wins over step 2's <c>InvalidParameter</c> half.</summary>
    [TestMethod]
    public async Task ZeroLengthPinUvAuthParamOnGetAssertionWithUnsupportedProtocolReturnsPinNotSet()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("ga-probe-unsupported-protocol");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapGetAssertionRequest request = BuildGetAssertionRequest(pool, pinUvAuthParam: ReadOnlyMemory<byte>.Empty, pinUvAuthProtocol: 3);
        using PooledMemory response = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinNotSet, response.AsReadOnlySpan()[0]);
    }


    /// <summary>Step 7: once a PIN is set, requesting a discoverable (<c>rk: true</c>) credential with no <c>pinUvAuthParam</c> fails with <c>PuatRequired</c>.</summary>
    [TestMethod]
    public async Task ResidentKeyTrueWithNoParamAndPinSetReturnsPuatRequired()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("mc-step7-puat-required");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, options: new CtapCommandOptions(ResidentKey: true));
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PuatRequired, response.AsReadOnlySpan()[0]);
    }


    /// <summary>Step 10: once a PIN is set, a non-discoverable (<c>rk: false</c>) request with no <c>pinUvAuthParam</c> still succeeds via the <c>makeCredUvNotRqd</c> fast path, with the response authData's <c>uv</c> bit clear.</summary>
    [TestMethod]
    public async Task ResidentKeyFalseWithNoParamAndPinSetSucceedsWithUvClear()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("mc-step10-fast-path");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);

        CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(decoded.AuthData, CredentialPublicKeyCborReader.Read, pool);
        Assert.IsTrue(authenticatorData.Flags.UserPresent);
        Assert.IsFalse(authenticatorData.Flags.UserVerified);
    }


    /// <summary>Step 7's escape hatch: a discoverable (<c>rk: true</c>) request with a VALID <c>pinUvAuthToken</c> succeeds — step 7 only fires when the param is absent.</summary>
    [TestMethod]
    public async Task ResidentKeyTrueWithValidPinUvAuthTokenSucceeds()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("mc-step7-escape-hatch");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        byte[] token = await IssueTokenWithPermissionsAsync(
            simulator, pool, CtapPinUvAuthProtocolId.Two, WellKnownCtapPinUvAuthTokenPermissions.Mc, RpIdA, TestContext.CancellationToken);
        byte[] param = await ComputeSignatureAsync(token, CtapPinUvAuthProtocolId.Two, McClientDataHash, pool, TestContext.CancellationToken);

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(
            pool, options: new CtapCommandOptions(ResidentKey: true), pinUvAuthParam: param, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);

        CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(decoded.AuthData, CredentialPublicKeyCborReader.Read, pool);
        Assert.IsTrue(authenticatorData.Flags.UserPresent);
        Assert.IsTrue(authenticatorData.Flags.UserVerified);
    }


    /// <summary>
    /// A failed <c>verify</c> (garbage <c>pinUvAuthParam</c>) fails with <c>PinAuthInvalid</c> without
    /// touching <c>pinRetries</c> (a clientPIN-only counter, never consulted by mc/ga) or the token's own
    /// state — a SECOND attempt over the SAME token with a genuinely valid signature still succeeds.
    /// </summary>
    [TestMethod]
    public async Task MakeCredentialVerifyFailureReturnsPinAuthInvalidAndLeavesTokenUsable()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("mc-verify-failure");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        byte[] token = await IssueTokenWithPermissionsAsync(
            simulator, pool, CtapPinUvAuthProtocolId.Two, WellKnownCtapPinUvAuthTokenPermissions.Mc, RpIdA, TestContext.CancellationToken);
        byte[] garbageParam = new byte[32];

        CtapMakeCredentialRequest garbageRequest = BuildMakeCredentialRequest(
            pool, pinUvAuthParam: garbageParam, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        using PooledMemory garbageResponse = await SendMakeCredentialAsync(simulator, garbageRequest, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthInvalid, garbageResponse.AsReadOnlySpan()[0]);
        Assert.AreEqual(8, await GetPinRetriesAsync(simulator, pool), "an mc verify failure must never decrement pinRetries.");

        byte[] validParam = await ComputeSignatureAsync(token, CtapPinUvAuthProtocolId.Two, McClientDataHash, pool, TestContext.CancellationToken);
        CtapMakeCredentialRequest validRequest = BuildMakeCredentialRequest(
            pool, userId: BuildFixedBytes(16, 0x70), pinUvAuthParam: validParam, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        using PooledMemory validResponse = await SendMakeCredentialAsync(simulator, validRequest, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, validResponse.AsReadOnlySpan()[0], "the failed verify attempt must not have consumed or corrupted the token.");
    }


    /// <summary>The ga counterpart of <see cref="MakeCredentialVerifyFailureReturnsPinAuthInvalidAndLeavesTokenUsable"/>.</summary>
    [TestMethod]
    public async Task GetAssertionVerifyFailureReturnsPinAuthInvalidAndLeavesTokenUsable()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("ga-verify-failure");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0x16), TestContext.CancellationToken);
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        byte[] token = await IssueTokenWithPermissionsAsync(
            simulator, pool, CtapPinUvAuthProtocolId.Two, WellKnownCtapPinUvAuthTokenPermissions.Ga, RpIdA, TestContext.CancellationToken);
        byte[] garbageParam = new byte[32];

        CtapGetAssertionRequest garbageRequest = BuildGetAssertionRequest(pool, pinUvAuthParam: garbageParam, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        using PooledMemory garbageResponse = await SendGetAssertionAsync(simulator, garbageRequest, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthInvalid, garbageResponse.AsReadOnlySpan()[0]);
        Assert.AreEqual(8, await GetPinRetriesAsync(simulator, pool), "a ga verify failure must never decrement pinRetries.");

        byte[] validParam = await ComputeSignatureAsync(token, CtapPinUvAuthProtocolId.Two, GaClientDataHash, pool, TestContext.CancellationToken);
        CtapGetAssertionRequest validRequest = BuildGetAssertionRequest(pool, pinUvAuthParam: validParam, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        using PooledMemory validResponse = await SendGetAssertionAsync(simulator, validRequest, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, validResponse.AsReadOnlySpan()[0], "the failed verify attempt must not have consumed or corrupted the token.");
    }


    /// <summary>A token issued with ONLY the <c>ga</c> permission fails an <c>authenticatorMakeCredential</c> attempt with <c>PinAuthInvalid</c>.</summary>
    [TestMethod]
    public async Task MakeCredentialWithGaOnlyPermissionReturnsPinAuthInvalid()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("mc-ga-only-permission");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        byte[] token = await IssueTokenWithPermissionsAsync(
            simulator, pool, CtapPinUvAuthProtocolId.Two, WellKnownCtapPinUvAuthTokenPermissions.Ga, RpIdA, TestContext.CancellationToken);
        byte[] param = await ComputeSignatureAsync(token, CtapPinUvAuthProtocolId.Two, McClientDataHash, pool, TestContext.CancellationToken);

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, pinUvAuthParam: param, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthInvalid, response.AsReadOnlySpan()[0]);
    }


    /// <summary>A token issued with ONLY the <c>mc</c> permission fails an <c>authenticatorGetAssertion</c> attempt with <c>PinAuthInvalid</c>.</summary>
    [TestMethod]
    public async Task GetAssertionWithMcOnlyPermissionReturnsPinAuthInvalid()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("ga-mc-only-permission");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0x17), TestContext.CancellationToken);
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        byte[] token = await IssueTokenWithPermissionsAsync(
            simulator, pool, CtapPinUvAuthProtocolId.Two, WellKnownCtapPinUvAuthTokenPermissions.Mc, RpIdA, TestContext.CancellationToken);
        byte[] param = await ComputeSignatureAsync(token, CtapPinUvAuthProtocolId.Two, GaClientDataHash, pool, TestContext.CancellationToken);

        CtapGetAssertionRequest request = BuildGetAssertionRequest(pool, pinUvAuthParam: param, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        using PooledMemory response = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthInvalid, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// A token whose permissions RP ID is already bound to <see cref="RpIdA"/> fails an
    /// <c>authenticatorMakeCredential</c> attempt for <see cref="RpIdB"/> with <c>PinAuthInvalid</c>,
    /// then succeeds for <see cref="RpIdA"/> with the SAME token and signature — proving the rejected
    /// attempt left the token's state untouched.
    /// </summary>
    [TestMethod]
    public async Task MakeCredentialWithTokenBoundToDifferentRpIdReturnsPinAuthInvalidThenSucceedsForBoundRpId()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("mc-rpid-mismatch");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        byte[] token = await IssueTokenWithPermissionsAsync(
            simulator, pool, CtapPinUvAuthProtocolId.Two, WellKnownCtapPinUvAuthTokenPermissions.Mc, RpIdA, TestContext.CancellationToken);
        byte[] param = await ComputeSignatureAsync(token, CtapPinUvAuthProtocolId.Two, McClientDataHash, pool, TestContext.CancellationToken);

        CtapMakeCredentialRequest mismatchedRequest = BuildMakeCredentialRequest(
            pool, rpId: RpIdB, pinUvAuthParam: param, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        using PooledMemory mismatchedResponse = await SendMakeCredentialAsync(simulator, mismatchedRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthInvalid, mismatchedResponse.AsReadOnlySpan()[0]);

        CtapMakeCredentialRequest boundRequest = BuildMakeCredentialRequest(
            pool, rpId: RpIdA, pinUvAuthParam: param, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        using PooledMemory boundResponse = await SendMakeCredentialAsync(simulator, boundRequest, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, boundResponse.AsReadOnlySpan()[0]);
        CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(boundResponse.AsReadOnlyMemory()[1..]);
        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(decoded.AuthData, CredentialPublicKeyCborReader.Read, pool);
        Assert.IsTrue(authenticatorData.Flags.UserVerified);
    }


    /// <summary>The ga counterpart of <see cref="MakeCredentialWithTokenBoundToDifferentRpIdReturnsPinAuthInvalidThenSucceedsForBoundRpId"/>.</summary>
    [TestMethod]
    public async Task GetAssertionWithTokenBoundToDifferentRpIdReturnsPinAuthInvalidThenSucceedsForBoundRpId()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("ga-rpid-mismatch");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0x18), TestContext.CancellationToken, rpId: RpIdA);
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        byte[] token = await IssueTokenWithPermissionsAsync(
            simulator, pool, CtapPinUvAuthProtocolId.Two, WellKnownCtapPinUvAuthTokenPermissions.Ga, RpIdA, TestContext.CancellationToken);
        byte[] param = await ComputeSignatureAsync(token, CtapPinUvAuthProtocolId.Two, GaClientDataHash, pool, TestContext.CancellationToken);

        CtapGetAssertionRequest mismatchedRequest = BuildGetAssertionRequest(
            pool, rpId: RpIdB, pinUvAuthParam: param, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        using PooledMemory mismatchedResponse = await SendGetAssertionAsync(simulator, mismatchedRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthInvalid, mismatchedResponse.AsReadOnlySpan()[0]);

        CtapGetAssertionRequest boundRequest = BuildGetAssertionRequest(
            pool, rpId: RpIdA, pinUvAuthParam: param, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        using PooledMemory boundResponse = await SendGetAssertionAsync(simulator, boundRequest, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, boundResponse.AsReadOnlySpan()[0]);
        CtapGetAssertionResponse decoded = CtapGetAssertionResponseCborReader.Read(boundResponse.AsReadOnlyMemory()[1..], pool);
        try
        {
            using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(decoded.AuthData, CredentialPublicKeyCborReader.Read, pool);
            Assert.IsTrue(authenticatorData.Flags.UserVerified);
        }
        finally
        {
            decoded.Credential.Id.Dispose();
            decoded.User?.Id.Dispose();
        }
    }


    /// <summary>
    /// An UNBOUND token's permissions RP ID binds on FIRST use (CTAP 2.3 line 5830-5834), proven through
    /// a chain of silent (<c>up: false</c>) <c>authenticatorGetAssertion</c> calls: the first call at
    /// <see cref="RpIdA"/> binds the token there, succeeding with <c>uv=1</c>/<c>up=0</c> and no flag
    /// clearing (R6's <c>up: false</c> carve-out); a second call at <see cref="RpIdB"/> over the SAME
    /// token then fails with <c>PinAuthInvalid</c> (already bound to A); a third call back at
    /// <see cref="RpIdA"/> succeeds again, proving the token is still in use with its cached UV and
    /// permissions intact.
    /// </summary>
    [TestMethod]
    public async Task UnboundTokenBindsOnFirstUseAndRejectsADifferentRpIdThereafter()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("ga-first-use-binding");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0x19), TestContext.CancellationToken, rpId: RpIdA);
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        byte[] token = await IssueUnboundTokenAsync(simulator, pool, CtapPinUvAuthProtocolId.Two, TestContext.CancellationToken);
        byte[] param = await ComputeSignatureAsync(token, CtapPinUvAuthProtocolId.Two, GaClientDataHash, pool, TestContext.CancellationToken);

        CtapGetAssertionRequest firstRequest = BuildGetAssertionRequest(
            pool, rpId: RpIdA, options: new CtapCommandOptions(UserPresence: false), pinUvAuthParam: param, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        using PooledMemory firstResponse = await SendGetAssertionAsync(simulator, firstRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, firstResponse.AsReadOnlySpan()[0]);
        CtapGetAssertionResponse firstDecoded = CtapGetAssertionResponseCborReader.Read(firstResponse.AsReadOnlyMemory()[1..], pool);
        using(AuthenticatorData firstAuthenticatorData = AuthenticatorDataReader.Read(firstDecoded.AuthData, CredentialPublicKeyCborReader.Read, pool))
        {
            Assert.IsTrue(firstAuthenticatorData.Flags.UserVerified, "first-use binding must still set uv=1.");
            Assert.IsFalse(firstAuthenticatorData.Flags.UserPresent, "up: false must keep the up bit clear.");
        }
        firstDecoded.Credential.Id.Dispose();
        firstDecoded.User?.Id.Dispose();

        CtapGetAssertionRequest mismatchedRequest = BuildGetAssertionRequest(
            pool, rpId: RpIdB, options: new CtapCommandOptions(UserPresence: false), pinUvAuthParam: param, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        using PooledMemory mismatchedResponse = await SendGetAssertionAsync(simulator, mismatchedRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthInvalid, mismatchedResponse.AsReadOnlySpan()[0], "the token is already bound to RpIdA after first use.");

        CtapGetAssertionRequest thirdRequest = BuildGetAssertionRequest(
            pool, rpId: RpIdA, options: new CtapCommandOptions(UserPresence: false), pinUvAuthParam: param, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        using PooledMemory thirdResponse = await SendGetAssertionAsync(simulator, thirdRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, thirdResponse.AsReadOnlySpan()[0], "no clearing must have occurred, so the token remains usable at its bound RpId.");
        CtapGetAssertionResponse thirdDecoded = CtapGetAssertionResponseCborReader.Read(thirdResponse.AsReadOnlyMemory()[1..], pool);
        using(AuthenticatorData thirdAuthenticatorData = AuthenticatorDataReader.Read(thirdDecoded.AuthData, CredentialPublicKeyCborReader.Read, pool))
        {
            Assert.IsTrue(thirdAuthenticatorData.Flags.UserVerified, "the cached uv state must survive since up: false skips flag clearing.");
        }
        thirdDecoded.Credential.Id.Dispose();
        thirdDecoded.User?.Id.Dispose();
    }


    /// <summary>
    /// A token used once for a successful <c>authenticatorMakeCredential</c> call has every permission
    /// except <c>lbw</c> stripped afterward (R6/line 5828): a second <c>authenticatorMakeCredential</c>
    /// attempt with a freshly computed but otherwise valid signature over the SAME token fails with
    /// <c>PinAuthInvalid</c> (the mc permission bit is gone), and so does a subsequent
    /// <c>authenticatorGetAssertion</c> attempt (the cached <c>userVerified</c> flag is gone too).
    /// </summary>
    [TestMethod]
    public async Task SingleUseMakeCredentialTokenStripsPermissionsForSubsequentMakeCredentialAndGetAssertion()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("mc-single-use-strips");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        int mcGa = WellKnownCtapPinUvAuthTokenPermissions.Mc | WellKnownCtapPinUvAuthTokenPermissions.Ga;
        byte[] token = await IssueTokenWithPermissionsAsync(simulator, pool, CtapPinUvAuthProtocolId.Two, mcGa, RpIdA, TestContext.CancellationToken);

        byte[] mcParam = await ComputeSignatureAsync(token, CtapPinUvAuthProtocolId.Two, McClientDataHash, pool, TestContext.CancellationToken);
        CtapMakeCredentialRequest firstMcRequest = BuildMakeCredentialRequest(pool, pinUvAuthParam: mcParam, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        using PooledMemory firstMcResponse = await SendMakeCredentialAsync(simulator, firstMcRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, firstMcResponse.AsReadOnlySpan()[0]);
        CtapMakeCredentialResponse firstMcDecoded = CtapMakeCredentialResponseCborReader.Read(firstMcResponse.AsReadOnlyMemory()[1..]);
        using(AuthenticatorData firstMcAuthenticatorData = AuthenticatorDataReader.Read(firstMcDecoded.AuthData, CredentialPublicKeyCborReader.Read, pool))
        {
            Assert.IsTrue(firstMcAuthenticatorData.Flags.UserVerified);
            Assert.IsTrue(firstMcAuthenticatorData.Flags.UserPresent);
        }

        byte[] secondMcParam = await ComputeSignatureAsync(token, CtapPinUvAuthProtocolId.Two, McClientDataHash, pool, TestContext.CancellationToken);
        CtapMakeCredentialRequest secondMcRequest = BuildMakeCredentialRequest(
            pool, userId: BuildFixedBytes(16, 0x71), pinUvAuthParam: secondMcParam, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        using PooledMemory secondMcResponse = await SendMakeCredentialAsync(simulator, secondMcRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthInvalid, secondMcResponse.AsReadOnlySpan()[0], "the mc permission must be stripped after the first success.");

        byte[] gaParam = await ComputeSignatureAsync(token, CtapPinUvAuthProtocolId.Two, GaClientDataHash, pool, TestContext.CancellationToken);
        CtapGetAssertionRequest gaRequest = BuildGetAssertionRequest(pool, pinUvAuthParam: gaParam, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        using PooledMemory gaResponse = await SendGetAssertionAsync(simulator, gaRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthInvalid, gaResponse.AsReadOnlySpan()[0], "the cached userVerified flag must be stripped after the first mc success too.");
    }


    /// <summary>
    /// A <c>KeyStoreFull</c> rejection still strips the presented <c>pinUvAuthToken</c>'s permissions.
    /// CTAP 2.3 §6.1.2 step 14.4's flag/permission clearing (line 3545) precedes step 17's
    /// resident-credential capacity check (line 3579) in the spec's own literal step order, so a token
    /// presented to a <c>rk: true</c> request that fails with <c>KeyStoreFull</c> has already been
    /// consumed by the time the rejection fires — proven here by a SECOND <c>authenticatorMakeCredential</c>
    /// over the SAME token, with a freshly computed but otherwise valid signature, failing
    /// <c>PinAuthInvalid</c> (the <c>mc</c> permission bit is gone) rather than a further <c>KeyStoreFull</c>.
    /// </summary>
    [TestMethod]
    public async Task ResidentKeyStoreFullStillStripsTokenPermissionsForSubsequentMakeCredential()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("mc-keystorefull-strips-token", residentCredentialCapacity: 1);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0x50), TestContext.CancellationToken);
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        int mcGa = WellKnownCtapPinUvAuthTokenPermissions.Mc | WellKnownCtapPinUvAuthTokenPermissions.Ga;
        byte[] token = await IssueTokenWithPermissionsAsync(simulator, pool, CtapPinUvAuthProtocolId.Two, mcGa, RpIdA, TestContext.CancellationToken);

        byte[] firstParam = await ComputeSignatureAsync(token, CtapPinUvAuthProtocolId.Two, McClientDataHash, pool, TestContext.CancellationToken);
        CtapMakeCredentialRequest firstRequest = BuildMakeCredentialRequest(
            pool, userId: BuildFixedBytes(16, 0x71), options: new CtapCommandOptions(ResidentKey: true),
            pinUvAuthParam: firstParam, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        using PooledMemory firstResponse = await SendMakeCredentialAsync(simulator, firstRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.KeyStoreFull, firstResponse.AsReadOnlySpan()[0]);

        byte[] secondParam = await ComputeSignatureAsync(token, CtapPinUvAuthProtocolId.Two, McClientDataHash, pool, TestContext.CancellationToken);
        CtapMakeCredentialRequest secondRequest = BuildMakeCredentialRequest(
            pool, userId: BuildFixedBytes(16, 0x72), pinUvAuthParam: secondParam, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        using PooledMemory secondResponse = await SendMakeCredentialAsync(simulator, secondRequest, pool, TestContext.CancellationToken);

        Assert.AreEqual(
            WellKnownCtapStatusCodes.PinAuthInvalid,
            secondResponse.AsReadOnlySpan()[0],
            "a KeyStoreFull rejection must still have stripped the token's permissions, since step 14's clearing precedes step 17's capacity check.");
    }


    /// <summary>
    /// A token used once for a successful <c>authenticatorGetAssertion</c> call whose <c>up</c> option is
    /// ABSENT (defaulting to <see langword="true"/>) also has its permissions stripped: a second attempt
    /// over the SAME token fails with <c>PinAuthInvalid</c>.
    /// </summary>
    [TestMethod]
    public async Task GetAssertionWithDefaultUserPresenceAlsoStripsTokenPermissionsAfterSuccess()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("ga-default-up-strips");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0x1A), TestContext.CancellationToken, rpId: RpIdA);
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        byte[] token = await IssueTokenWithPermissionsAsync(
            simulator, pool, CtapPinUvAuthProtocolId.Two, WellKnownCtapPinUvAuthTokenPermissions.Ga, RpIdA, TestContext.CancellationToken);

        byte[] firstParam = await ComputeSignatureAsync(token, CtapPinUvAuthProtocolId.Two, GaClientDataHash, pool, TestContext.CancellationToken);
        CtapGetAssertionRequest firstRequest = BuildGetAssertionRequest(pool, rpId: RpIdA, pinUvAuthParam: firstParam, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        using PooledMemory firstResponse = await SendGetAssertionAsync(simulator, firstRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, firstResponse.AsReadOnlySpan()[0]);
        CtapGetAssertionResponse firstDecoded = CtapGetAssertionResponseCborReader.Read(firstResponse.AsReadOnlyMemory()[1..], pool);
        using(AuthenticatorData firstAuthenticatorData = AuthenticatorDataReader.Read(firstDecoded.AuthData, CredentialPublicKeyCborReader.Read, pool))
        {
            Assert.IsTrue(firstAuthenticatorData.Flags.UserVerified);
            Assert.IsTrue(firstAuthenticatorData.Flags.UserPresent, "an absent up option must default to true.");
        }
        firstDecoded.Credential.Id.Dispose();
        firstDecoded.User?.Id.Dispose();

        byte[] secondParam = await ComputeSignatureAsync(token, CtapPinUvAuthProtocolId.Two, GaClientDataHash, pool, TestContext.CancellationToken);
        CtapGetAssertionRequest secondRequest = BuildGetAssertionRequest(pool, rpId: RpIdA, pinUvAuthParam: secondParam, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        using PooledMemory secondResponse = await SendGetAssertionAsync(simulator, secondRequest, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthInvalid, secondResponse.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// A token issued on protocol TWO never puts protocol ONE's own token in use: naming protocol ONE in
    /// an <c>authenticatorMakeCredential</c> request, even with a param computed over the known
    /// protocol-two token bytes, fails with <c>PinAuthInvalid</c> — the authenticator's own verify always
    /// checks against protocol one's ACTUAL (never-begun) token, which is never in use.
    /// </summary>
    [TestMethod]
    public async Task CrossProtocolNeverBegunTokenReturnsPinAuthInvalid()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("mc-cross-protocol");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        byte[] protocolTwoToken = await IssueTokenWithPermissionsAsync(
            simulator, pool, CtapPinUvAuthProtocolId.Two, WellKnownCtapPinUvAuthTokenPermissions.Mc, RpIdA, TestContext.CancellationToken);
        byte[] protocolOneComputedParam = await ComputeSignatureAsync(protocolTwoToken, CtapPinUvAuthProtocolId.One, McClientDataHash, pool, TestContext.CancellationToken);

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(
            pool, pinUvAuthParam: protocolOneComputedParam, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.One);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthInvalid, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// A token that has NEVER been used since issuance stops at the exact 19.8-second initial usage time
    /// limit (<see cref="CtapPinUvAuthTokenState.InitialUsageTimeLimit"/>): an <c>authenticatorMakeCredential</c>
    /// attempt at that boundary fails with <c>PinAuthInvalid</c> — the request-arm's
    /// <see cref="CtapPinUvAuthTokenState.EvaluateExpiry"/> call stops the token before <c>verify</c> ever runs.
    /// </summary>
    [TestMethod]
    public async Task MakeCredentialTokenExpiresAtInitialUsageTimeLimitWhenNeverUsed()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using CtapAuthenticatorSimulator simulator = CreateSimulator("mc-expiry-initial-limit", timeProvider: timeProvider);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        byte[] token = await IssueTokenWithPermissionsAsync(
            simulator, pool, CtapPinUvAuthProtocolId.Two, WellKnownCtapPinUvAuthTokenPermissions.Mc, RpIdA, TestContext.CancellationToken);
        byte[] param = await ComputeSignatureAsync(token, CtapPinUvAuthProtocolId.Two, McClientDataHash, pool, TestContext.CancellationToken);

        timeProvider.Advance(CtapPinUvAuthTokenState.InitialUsageTimeLimit);

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, pinUvAuthParam: param, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthInvalid, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// A token that WAS used once (surviving the initial usage time limit clause) still stops once the
    /// TOTAL elapsed time since issuance reaches the 600-second max usage time period
    /// (<see cref="CtapPinUvAuthTokenState.MaxUsageTimePeriod"/>, line 5171's unconditional clause): a
    /// subsequent <c>authenticatorGetAssertion</c> attempt at that boundary fails with <c>PinAuthInvalid</c>.
    /// </summary>
    [TestMethod]
    public async Task GetAssertionTokenExpiresAtMaxUsageTimePeriodAfterPriorUse()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using CtapAuthenticatorSimulator simulator = CreateSimulator("ga-expiry-max-period", timeProvider: timeProvider);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0x1B), TestContext.CancellationToken, rpId: RpIdA);
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        byte[] token = await IssueTokenWithPermissionsAsync(
            simulator, pool, CtapPinUvAuthProtocolId.Two, WellKnownCtapPinUvAuthTokenPermissions.Ga, RpIdA, TestContext.CancellationToken);

        timeProvider.Advance(TimeSpan.FromSeconds(5));
        byte[] firstParam = await ComputeSignatureAsync(token, CtapPinUvAuthProtocolId.Two, GaClientDataHash, pool, TestContext.CancellationToken);
        CtapGetAssertionRequest firstRequest = BuildGetAssertionRequest(
            pool, rpId: RpIdA, options: new CtapCommandOptions(UserPresence: false), pinUvAuthParam: firstParam, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        using PooledMemory firstResponse = await SendGetAssertionAsync(simulator, firstRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, firstResponse.AsReadOnlySpan()[0], "a use within the initial usage limit must survive that clause.");

        timeProvider.Advance(CtapPinUvAuthTokenState.MaxUsageTimePeriod - TimeSpan.FromSeconds(5));
        byte[] secondParam = await ComputeSignatureAsync(token, CtapPinUvAuthProtocolId.Two, GaClientDataHash, pool, TestContext.CancellationToken);
        CtapGetAssertionRequest secondRequest = BuildGetAssertionRequest(
            pool, rpId: RpIdA, options: new CtapCommandOptions(UserPresence: false), pinUvAuthParam: secondParam, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        using PooledMemory secondResponse = await SendGetAssertionAsync(simulator, secondRequest, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthInvalid, secondResponse.AsReadOnlySpan()[0], "the max usage time period must stop the token unconditionally, even though it was used once.");
    }


    /// <summary><c>options.uv: true</c> alongside a VALID <c>pinUvAuthParam</c> succeeds with the response authData's <c>uv</c> bit set — the pinUvAuthParam-takes-precedence rule, never <c>InvalidOption</c>.</summary>
    [TestMethod]
    public async Task MakeCredentialUserVerificationTrueWithValidParamSucceedsWithUvSetNoInvalidOption()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("mc-uv-precedence");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        byte[] token = await IssueTokenWithPermissionsAsync(
            simulator, pool, CtapPinUvAuthProtocolId.Two, WellKnownCtapPinUvAuthTokenPermissions.Mc, RpIdA, TestContext.CancellationToken);
        byte[] param = await ComputeSignatureAsync(token, CtapPinUvAuthProtocolId.Two, McClientDataHash, pool, TestContext.CancellationToken);

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(
            pool, options: new CtapCommandOptions(UserVerification: true), pinUvAuthParam: param, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
        CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(decoded.AuthData, CredentialPublicKeyCborReader.Read, pool);
        Assert.IsTrue(authenticatorData.Flags.UserVerified);
    }


    /// <summary>The ga counterpart of <see cref="MakeCredentialUserVerificationTrueWithValidParamSucceedsWithUvSetNoInvalidOption"/>.</summary>
    [TestMethod]
    public async Task GetAssertionUserVerificationTrueWithValidParamSucceedsWithUvSetNoInvalidOption()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("ga-uv-precedence");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0x1C), TestContext.CancellationToken, rpId: RpIdA);
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        byte[] token = await IssueTokenWithPermissionsAsync(
            simulator, pool, CtapPinUvAuthProtocolId.Two, WellKnownCtapPinUvAuthTokenPermissions.Ga, RpIdA, TestContext.CancellationToken);
        byte[] param = await ComputeSignatureAsync(token, CtapPinUvAuthProtocolId.Two, GaClientDataHash, pool, TestContext.CancellationToken);

        CtapGetAssertionRequest request = BuildGetAssertionRequest(
            pool, rpId: RpIdA, options: new CtapCommandOptions(UserVerification: true), pinUvAuthParam: param, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        using PooledMemory response = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
        CtapGetAssertionResponse decoded = CtapGetAssertionResponseCborReader.Read(response.AsReadOnlyMemory()[1..], pool);
        try
        {
            using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(decoded.AuthData, CredentialPublicKeyCborReader.Read, pool);
            Assert.IsTrue(authenticatorData.Flags.UserVerified);
        }
        finally
        {
            decoded.Credential.Id.Dispose();
            decoded.User?.Id.Dispose();
        }
    }


    /// <summary>
    /// A UV-verified, multi-account <c>authenticatorGetAssertion</c> that locates more than one applicable
    /// resident credential mints remembered state carrying <c>uv=1</c>; every following
    /// <c>authenticatorGetNextAssertion</c> in that sequence must report <c>uv=1</c> too, since
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetNextAssertion">
    /// CTAP 2.3, section 6.3</see> defines it as "return[ing] the same structure as returned by the
    /// authenticatorGetAssertion method" (line 4336) — the continuation itself carries no
    /// <c>pinUvAuthParam</c> of its own to re-verify, so it must instead carry forward the originating
    /// ceremony's own resolved <c>uv</c> bit rather than silently reporting <c>uv=0</c>. A relying party
    /// under <c>UserVerificationRequirement.Required</c> must accept every account in the sequence, not
    /// only the first.
    /// </summary>
    [TestMethod]
    public async Task GetNextAssertionAfterUvVerifiedMultiAccountGetAssertionReportsUvSetOnContinuation()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("ga-next-uv-continuation", residentCredentialCapacity: 3);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0x1D), TestContext.CancellationToken, rpId: RpIdA);
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0x1E), TestContext.CancellationToken, rpId: RpIdA);
        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        byte[] token = await IssueTokenWithPermissionsAsync(
            simulator, pool, CtapPinUvAuthProtocolId.Two, WellKnownCtapPinUvAuthTokenPermissions.Ga, RpIdA, TestContext.CancellationToken);
        byte[] param = await ComputeSignatureAsync(token, CtapPinUvAuthProtocolId.Two, GaClientDataHash, pool, TestContext.CancellationToken);

        CtapGetAssertionRequest request = BuildGetAssertionRequest(
            pool, rpId: RpIdA, pinUvAuthParam: param, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        using(PooledMemory first = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, first.AsReadOnlySpan()[0]);
            CtapGetAssertionResponse firstDecoded = CtapGetAssertionResponseCborReader.Read(first.AsReadOnlyMemory()[1..], pool);
            Assert.AreEqual(2, firstDecoded.NumberOfCredentials, "the fixture must locate more than one applicable credential to mint remembered state.");
            using(AuthenticatorData firstAuthenticatorData = AuthenticatorDataReader.Read(firstDecoded.AuthData, CredentialPublicKeyCborReader.Read, pool))
            {
                Assert.IsTrue(firstAuthenticatorData.Flags.UserVerified, "the originating ga must itself report uv=1.");
            }
            firstDecoded.Credential.Id.Dispose();
            firstDecoded.User?.Id.Dispose();
        }

        using PooledMemory next = await SendGetNextAssertionAsync(simulator, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, next.AsReadOnlySpan()[0]);
        CtapGetAssertionResponse nextDecoded = CtapGetAssertionResponseCborReader.Read(next.AsReadOnlyMemory()[1..], pool);
        using(AuthenticatorData nextAuthenticatorData = AuthenticatorDataReader.Read(nextDecoded.AuthData, CredentialPublicKeyCborReader.Read, pool))
        {
            Assert.IsTrue(nextAuthenticatorData.Flags.UserVerified, "authenticatorGetNextAssertion must carry forward the originating ceremony's uv=1, never silently downgrade to uv=0.");
            Assert.IsTrue(nextAuthenticatorData.Flags.UserPresent);
        }
        nextDecoded.Credential.Id.Dispose();
        nextDecoded.User?.Id.Dispose();
    }


    /// <summary>
    /// A UV-verified multi-account series driven in exactly-30-second <c>authenticatorGetNextAssertion</c>
    /// steps (never crossing the 30-second inter-call timer) keeps succeeding right up to the step whose
    /// elapsed time since the authenticating token's <see cref="CtapPinUvAuthTokenState.BeginUsingAt"/>
    /// reaches the token's own <see cref="CtapPinUvAuthTokenState.MaxUsageTimePeriod"/> (600 seconds): that
    /// step fails with <c>CTAP2_ERR_NOT_ALLOWED</c>, and so does the following
    /// <c>authenticatorGetNextAssertion</c> with NO further time advance — proving the remembered state was
    /// discarded outright, not merely rejected once. <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticator-api">
    /// CTAP 2.3, section 6</see>, item 3 (line 2873): "An authenticator MUST discard the state for a
    /// stateful command command if the pinUvAuthToken that authenticated the state initializing command
    /// expires".
    /// </summary>
    [TestMethod]
    public async Task GetNextAssertionDiscardsUvVerifiedSeriesWhenAuthenticatingTokenCrossesMaxUsagePeriod()
    {
        const int accountCount = 25;
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using CtapAuthenticatorSimulator simulator = CreateSimulator("ga-next-token-max-usage", timeProvider: timeProvider, residentCredentialCapacity: accountCount);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        for(int i = 0; i < accountCount; i++)
        {
            _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, (byte)(0x60 + i)), TestContext.CancellationToken, rpId: RpIdA);
        }

        await CtapAuthenticatorSetPinTests.EstablishPinAsync(simulator, pool, "1234");

        byte[] token = await IssueTokenWithPermissionsAsync(
            simulator, pool, CtapPinUvAuthProtocolId.Two, WellKnownCtapPinUvAuthTokenPermissions.Ga, RpIdA, TestContext.CancellationToken);
        byte[] param = await ComputeSignatureAsync(token, CtapPinUvAuthProtocolId.Two, GaClientDataHash, pool, TestContext.CancellationToken);

        CtapGetAssertionRequest request = BuildGetAssertionRequest(
            pool, rpId: RpIdA, pinUvAuthParam: param, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        using(PooledMemory first = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, first.AsReadOnlySpan()[0]);
        }

        TimeSpan step = TimeSpan.FromSeconds(30);
        int successfulContinuations = (int)(CtapPinUvAuthTokenState.MaxUsageTimePeriod.TotalSeconds / step.TotalSeconds) - 1;
        for(int i = 0; i < successfulContinuations; i++)
        {
            timeProvider.Advance(step);
            using PooledMemory response = await SendGetNextAssertionAsync(simulator, pool, TestContext.CancellationToken);

            Assert.AreEqual(
                WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0], $"continuation {i} must succeed before the authenticating token's max usage time period elapses.");
        }

        timeProvider.Advance(step);
        using(PooledMemory crossing = await SendGetNextAssertionAsync(simulator, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(
                WellKnownCtapStatusCodes.NotAllowed,
                crossing.AsReadOnlySpan()[0],
                "the continuation whose elapsed time crosses the authenticating token's max usage time period must fail.");
        }

        using PooledMemory discarded = await SendGetNextAssertionAsync(simulator, pool, TestContext.CancellationToken);
        Assert.AreEqual(
            WellKnownCtapStatusCodes.NotAllowed, discarded.AsReadOnlySpan()[0], "the remembered state must be discarded outright, not merely rejected once.");
    }


    /// <summary>
    /// A series with NO authenticating <c>pinUvAuthToken</c> at all (no PIN set, so
    /// <c>authenticatorGetAssertion</c> takes the not-protected fallback with no <c>pinUvAuthParam</c>
    /// presented) is unaffected by the 600-second max usage time period that would otherwise govern a
    /// token-authenticated series: only the 30-second inter-call timer applies, so exactly-30-second
    /// <c>authenticatorGetNextAssertion</c> steps keep succeeding well past that horizon.
    /// </summary>
    [TestMethod]
    public async Task GetNextAssertionForNonTokenAuthenticatedSeriesSurvivesPastTokenMaxUsagePeriod()
    {
        const int accountCount = 25;
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using CtapAuthenticatorSimulator simulator = CreateSimulator("ga-next-no-token-survives", timeProvider: timeProvider, residentCredentialCapacity: accountCount);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        for(int i = 0; i < accountCount; i++)
        {
            _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, (byte)(0x90 + i)), TestContext.CancellationToken, rpId: RpIdA);
        }

        CtapGetAssertionRequest request = BuildGetAssertionRequest(pool, rpId: RpIdA);
        using(PooledMemory first = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, first.AsReadOnlySpan()[0]);
        }

        TimeSpan step = TimeSpan.FromSeconds(30);
        int continuationsPastMaxUsagePeriod = (int)(CtapPinUvAuthTokenState.MaxUsageTimePeriod.TotalSeconds / step.TotalSeconds) + 2;
        for(int i = 0; i < continuationsPastMaxUsagePeriod; i++)
        {
            timeProvider.Advance(step);
            using PooledMemory response = await SendGetNextAssertionAsync(simulator, pool, TestContext.CancellationToken);

            Assert.AreEqual(
                WellKnownCtapStatusCodes.Ok,
                response.AsReadOnlySpan()[0],
                $"continuation {i}, at {(i + 1) * step.TotalSeconds}s elapsed, must succeed with no authenticating token to expire.");
        }
    }
}
