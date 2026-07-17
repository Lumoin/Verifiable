using System.Buffers;
using System.Threading.Tasks;
using Verifiable.Cbor.Ctap;
using Verifiable.Cbor.Fido2;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.Tests.TestInfrastructure;
using static Verifiable.Tests.TestInfrastructure.CtapWave2AuthenticatorFixtures;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// The wave PKG-B unit-test matrix for R9: <c>authenticatorMakeCredential</c> step 6 and
/// <c>authenticatorGetAssertion</c> step 5 going LIVE once <c>authenticatorConfig</c>'s
/// <c>toggleAlwaysUv</c> subcommand enables <see cref="CtapAuthenticatorState.IsAlwaysUvEnabled"/>: the
/// step-10 fast-path preemption regardless of <c>rk</c>, ga's additional effective-<c>up</c> gate and
/// its <c>up:false</c> silent-assertion carve-out, and a valid token succeeding with <c>uv=1</c> on both
/// commands. Driven in-process through <see cref="CtapAuthenticatorSimulator.TransceiveAsync"/>, with
/// platform-side <c>pinUvAuthParam</c> computed through <see cref="CtapPinUvAuthProtocol.AuthenticateAsync"/>
/// over the actual token bytes. The wave-5c binding-matrix file itself stays untouched; every
/// <c>alwaysUv</c>-off expectation it already asserts is proven unaffected by the full-suite regression
/// run, not re-asserted here.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorAlwaysUvLiveTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The plaintext PIN every test establishes.</summary>
    private const string DefaultPin = "1234";

    /// <summary>The fixed <c>clientDataHash</c> pattern <see cref="BuildMakeCredentialRequest"/> uses internally (seed <c>0x10</c>).</summary>
    private static byte[] McClientDataHash => BuildFixedBytes(32, 0x10);

    /// <summary>The fixed <c>clientDataHash</c> pattern <see cref="BuildGetAssertionRequest"/> uses internally (seed <c>0x20</c>).</summary>
    private static byte[] GaClientDataHash => BuildFixedBytes(32, 0x20);


    /// <summary>Enables <c>alwaysUv</c> (unprotected, no PIN yet — no gate) and then establishes a PIN under <paramref name="protocolId"/>.</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the returned CtapAuthenticatorSimulator transfers to the caller, which every call site wraps in its own using declaration.")]
    private async Task<CtapAuthenticatorSimulator> CreateAlwaysUvEnabledProtectedSimulatorAsync(string runId, MemoryPool<byte> pool, CtapPinUvAuthProtocolId protocolId)
    {
        CtapAuthenticatorSimulator simulator = CreateSimulator(runId);

        await EnableAlwaysUvAsync(simulator, pool);
        await CtapWaveConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, TestContext.CancellationToken);

        return simulator;
    }


    /// <summary>Enables <c>alwaysUv</c> via <c>toggleAlwaysUv</c>, asserting success.</summary>
    private async Task EnableAlwaysUvAsync(CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool)
    {
        var enableRequest = new CtapAuthenticatorConfigRequest(SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv);
        using PooledMemory enableResponse = await CtapWaveConfigFixtures.SendAuthenticatorConfigAsync(simulator, enableRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, enableResponse.AsReadOnlySpan()[0]);
    }


    /// <summary><c>alwaysUv</c> on, protected, no <c>pinUvAuthParam</c>: mc <c>rk=false</c> fails with <c>PuatRequired</c> — the step-10 fast path is preempted.</summary>
    [TestMethod]
    public async Task McResidentKeyFalseAlwaysUvOnNoParamReturnsPuatRequired()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using CtapAuthenticatorSimulator simulator = await CreateAlwaysUvEnabledProtectedSimulatorAsync("alwaysuv-mc-rk-false", pool, CtapPinUvAuthProtocolId.Two);

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, options: new CtapCommandOptions(ResidentKey: false));
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PuatRequired, response.AsReadOnlySpan()[0]);
    }


    /// <summary><c>alwaysUv</c> on, protected, no <c>pinUvAuthParam</c>: mc <c>rk=true</c> ALSO fails with <c>PuatRequired</c> — step 6 does not care about <c>rk</c>.</summary>
    [TestMethod]
    public async Task McResidentKeyTrueAlwaysUvOnNoParamReturnsPuatRequired()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using CtapAuthenticatorSimulator simulator = await CreateAlwaysUvEnabledProtectedSimulatorAsync("alwaysuv-mc-rk-true", pool, CtapPinUvAuthProtocolId.Two);

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, options: new CtapCommandOptions(ResidentKey: true));
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PuatRequired, response.AsReadOnlySpan()[0]);
    }


    /// <summary><c>alwaysUv</c> on, protected, <c>up</c> absent (effective <c>up=true</c>): ga fails with <c>PuatRequired</c>.</summary>
    [TestMethod]
    public async Task GaUpAbsentAlwaysUvOnReturnsPuatRequired()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("alwaysuv-ga-up-absent");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0x30), TestContext.CancellationToken);
        await EnableAlwaysUvAsync(simulator, pool);
        await CtapWaveConfigFixtures.EstablishPinAsync(simulator, pool, CtapPinUvAuthProtocolId.Two, DefaultPin, TestContext.CancellationToken);

        CtapGetAssertionRequest request = BuildGetAssertionRequest(pool);
        using PooledMemory response = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PuatRequired, response.AsReadOnlySpan()[0]);
    }


    /// <summary><c>alwaysUv</c> on, protected, <c>up:true</c> explicit: ga ALSO fails with <c>PuatRequired</c> (same effective-up reading).</summary>
    [TestMethod]
    public async Task GaUpTrueAlwaysUvOnReturnsPuatRequired()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("alwaysuv-ga-up-true");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0x31), TestContext.CancellationToken);
        await EnableAlwaysUvAsync(simulator, pool);
        await CtapWaveConfigFixtures.EstablishPinAsync(simulator, pool, CtapPinUvAuthProtocolId.Two, DefaultPin, TestContext.CancellationToken);

        CtapGetAssertionRequest request = BuildGetAssertionRequest(pool, options: new CtapCommandOptions(UserPresence: true));
        using PooledMemory response = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PuatRequired, response.AsReadOnlySpan()[0]);
    }


    /// <summary>The <c>up:false</c> silent-assertion carve-out: even with <c>alwaysUv</c> on and protected, a preflight ga call is NEVER subject to the gate and succeeds with <c>uv=0</c>/<c>up=0</c>.</summary>
    [TestMethod]
    public async Task GaUpFalseAlwaysUvOnSucceedsUvZeroUpZero()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("alwaysuv-ga-up-false");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0x32), TestContext.CancellationToken);
        await EnableAlwaysUvAsync(simulator, pool);
        await CtapWaveConfigFixtures.EstablishPinAsync(simulator, pool, CtapPinUvAuthProtocolId.Two, DefaultPin, TestContext.CancellationToken);

        CtapGetAssertionRequest request = BuildGetAssertionRequest(pool, options: new CtapCommandOptions(UserPresence: false));
        using PooledMemory response = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0], "up:false must bypass alwaysUv enforcement entirely (the carve-out).");
        CtapGetAssertionResponse decoded = CtapGetAssertionResponseCborReader.Read(response.AsReadOnlyMemory()[1..], pool);
        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(decoded.AuthData, CredentialPublicKeyCborReader.Read, pool);
        Assert.IsFalse(authenticatorData.Flags.UserVerified);
        Assert.IsFalse(authenticatorData.Flags.UserPresent);
    }


    /// <summary><c>alwaysUv</c> on, a valid <c>mc</c>-permitted token presented: mc succeeds with <c>uv=1</c>.</summary>
    [TestMethod]
    public async Task AlwaysUvOnValidTokenMcSucceedsUvOne()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        using CtapAuthenticatorSimulator simulator = await CreateAlwaysUvEnabledProtectedSimulatorAsync("alwaysuv-mc-valid-token", pool, protocolId);

        byte[] token = await CtapWaveConfigFixtures.IssueTokenAsync(
            simulator, pool, protocolId, DefaultPin, WellKnownCtapPinUvAuthTokenPermissions.Mc, DefaultRpId, TestContext.CancellationToken);
        byte[] param = await CtapWaveConfigFixtures.ComputeSignatureAsync(token, protocolId, McClientDataHash, pool, TestContext.CancellationToken);

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, pinUvAuthParam: param, pinUvAuthProtocol: (int)protocolId);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
        CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(decoded.AuthData, CredentialPublicKeyCborReader.Read, pool);
        Assert.IsTrue(authenticatorData.Flags.UserVerified);
    }


    /// <summary><c>alwaysUv</c> on, a valid <c>ga</c>-permitted token presented: ga succeeds with <c>uv=1</c>.</summary>
    [TestMethod]
    public async Task AlwaysUvOnValidTokenGaSucceedsUvOne()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("alwaysuv-ga-valid-token");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0x33), TestContext.CancellationToken);
        await EnableAlwaysUvAsync(simulator, pool);
        await CtapWaveConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, TestContext.CancellationToken);

        byte[] token = await CtapWaveConfigFixtures.IssueTokenAsync(
            simulator, pool, protocolId, DefaultPin, WellKnownCtapPinUvAuthTokenPermissions.Ga, DefaultRpId, TestContext.CancellationToken);
        byte[] param = await CtapWaveConfigFixtures.ComputeSignatureAsync(token, protocolId, GaClientDataHash, pool, TestContext.CancellationToken);

        CtapGetAssertionRequest request = BuildGetAssertionRequest(pool, pinUvAuthParam: param, pinUvAuthProtocol: (int)protocolId);
        using PooledMemory response = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
        CtapGetAssertionResponse decoded = CtapGetAssertionResponseCborReader.Read(response.AsReadOnlyMemory()[1..], pool);
        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(decoded.AuthData, CredentialPublicKeyCborReader.Read, pool);
        Assert.IsTrue(authenticatorData.Flags.UserVerified);
    }


    /// <summary><c>alwaysUv</c> on, NO PIN ever set (not protected): mc fails with <c>PuatRequired</c> (R2's clientPin-present branch — <c>OperationDenied</c> never fires).</summary>
    [TestMethod]
    public async Task AlwaysUvOnNoPinMcReturnsPuatRequired()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("alwaysuv-mc-no-pin");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var enableRequest = new CtapAuthenticatorConfigRequest(SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv);
        using PooledMemory enableResponse = await CtapWaveConfigFixtures.SendAuthenticatorConfigAsync(simulator, enableRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, enableResponse.AsReadOnlySpan()[0]);

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PuatRequired, response.AsReadOnlySpan()[0]);
    }
}
