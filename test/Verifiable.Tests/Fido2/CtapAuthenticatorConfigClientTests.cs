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
/// Tests for <see cref="CtapAuthenticatorConfigClient"/> against a scripted
/// <see cref="Ctap2TransceiveDelegate"/> — no APDU transport involved, isolating the RP-side
/// request-build/status-check logic, mirroring <see cref="CtapAuthenticatorClientPinClientTests"/>'s
/// shape. A dedicated test proves the success path over the real <see cref="CtapAuthenticatorSimulator"/>
/// loop, since <c>authenticatorConfig</c> defines no response body for a scripted decode to exercise.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorConfigClientTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>The request envelope is the <see cref="WellKnownCtapCommands.AuthenticatorConfig"/> command byte followed by the CBOR-encoded parameter map.</summary>
    [TestMethod]
    public async Task SendsAuthenticatorConfigCommandByte()
    {
        byte[]? capturedRequest = null;

        ValueTask<PooledMemory> Transceive(ReadOnlyMemory<byte> request, MemoryPool<byte> pool, CancellationToken cancellationToken)
        {
            capturedRequest = request.ToArray();

            return ValueTask.FromResult(PooledMemory.FromBytes([WellKnownCtapStatusCodes.Ok], pool, Fido2BufferTags.CtapResponseEnvelope));
        }

        var request = new CtapAuthenticatorConfigRequest(SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv);
        await CtapAuthenticatorConfigClient.AuthenticatorConfigAsync(
            Transceive, CtapAuthenticatorConfigRequestCborWriter.Write, request, BaseMemoryPool.Shared, TestContext.CancellationToken);

        Assert.IsNotNull(capturedRequest);
        Assert.AreEqual(WellKnownCtapCommands.AuthenticatorConfig, capturedRequest![0]);
    }


    /// <summary>A non-success status byte raises <see cref="CtapCommandException"/> carrying that status code.</summary>
    [TestMethod]
    public async Task ThrowsCtapCommandExceptionOnNonSuccessStatus()
    {
        ValueTask<PooledMemory> Transceive(ReadOnlyMemory<byte> request, MemoryPool<byte> pool, CancellationToken cancellationToken) =>
            ValueTask.FromResult(PooledMemory.FromBytes([WellKnownCtapStatusCodes.InvalidSubcommand], pool, Fido2BufferTags.CtapResponseEnvelope));

        var request = new CtapAuthenticatorConfigRequest(SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.SetMinPinLength);
        CtapCommandException exception = await Assert.ThrowsExactlyAsync<CtapCommandException>(
            () => CtapAuthenticatorConfigClient.AuthenticatorConfigAsync(
                Transceive, CtapAuthenticatorConfigRequestCborWriter.Write, request, BaseMemoryPool.Shared, TestContext.CancellationToken).AsTask());

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidSubcommand, exception.StatusCode);
    }


    /// <summary>An empty response envelope is rejected before any status check is attempted.</summary>
    [TestMethod]
    public async Task ThrowsFido2FormatExceptionOnEmptyResponse()
    {
        ValueTask<PooledMemory> Transceive(ReadOnlyMemory<byte> request, MemoryPool<byte> pool, CancellationToken cancellationToken) =>
            ValueTask.FromResult(PooledMemory.FromBytes(ReadOnlySpan<byte>.Empty, pool, Fido2BufferTags.CtapResponseEnvelope));

        var request = new CtapAuthenticatorConfigRequest(SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv);
        await Assert.ThrowsExactlyAsync<Fido2FormatException>(
            () => CtapAuthenticatorConfigClient.AuthenticatorConfigAsync(
                Transceive, CtapAuthenticatorConfigRequestCborWriter.Write, request, BaseMemoryPool.Shared, TestContext.CancellationToken).AsTask());
    }


    /// <summary>A <see langword="null"/> <paramref name="transceive"/> is rejected before anything is sent.</summary>
    [TestMethod]
    public async Task ThrowsArgumentNullExceptionForNullTransceive()
    {
        var request = new CtapAuthenticatorConfigRequest(SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv);
        await Assert.ThrowsExactlyAsync<ArgumentNullException>(
            () => CtapAuthenticatorConfigClient.AuthenticatorConfigAsync(
                null!, CtapAuthenticatorConfigRequestCborWriter.Write, request, BaseMemoryPool.Shared, TestContext.CancellationToken).AsTask());
    }


    /// <summary>A <see langword="null"/> <paramref name="encodeRequest"/> is rejected before anything is sent.</summary>
    [TestMethod]
    public async Task ThrowsArgumentNullExceptionForNullEncodeRequest()
    {
        ValueTask<PooledMemory> Transceive(ReadOnlyMemory<byte> request, MemoryPool<byte> pool, CancellationToken cancellationToken) =>
            ValueTask.FromResult(PooledMemory.FromBytes([WellKnownCtapStatusCodes.Ok], pool, Fido2BufferTags.CtapResponseEnvelope));

        var request = new CtapAuthenticatorConfigRequest(SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv);
        await Assert.ThrowsExactlyAsync<ArgumentNullException>(
            () => CtapAuthenticatorConfigClient.AuthenticatorConfigAsync(
                Transceive, null!, request, BaseMemoryPool.Shared, TestContext.CancellationToken).AsTask());
    }


    /// <summary>A <see langword="null"/> <paramref name="request"/> is rejected before anything is sent.</summary>
    [TestMethod]
    public async Task ThrowsArgumentNullExceptionForNullRequest()
    {
        ValueTask<PooledMemory> Transceive(ReadOnlyMemory<byte> request, MemoryPool<byte> pool, CancellationToken cancellationToken) =>
            ValueTask.FromResult(PooledMemory.FromBytes([WellKnownCtapStatusCodes.Ok], pool, Fido2BufferTags.CtapResponseEnvelope));

        await Assert.ThrowsExactlyAsync<ArgumentNullException>(
            () => CtapAuthenticatorConfigClient.AuthenticatorConfigAsync(
                Transceive, CtapAuthenticatorConfigRequestCborWriter.Write, null!, BaseMemoryPool.Shared, TestContext.CancellationToken).AsTask());
    }


    /// <summary>A <see langword="null"/> <paramref name="pool"/> is rejected before anything is sent.</summary>
    [TestMethod]
    public async Task ThrowsArgumentNullExceptionForNullPool()
    {
        ValueTask<PooledMemory> Transceive(ReadOnlyMemory<byte> request, MemoryPool<byte> pool, CancellationToken cancellationToken) =>
            ValueTask.FromResult(PooledMemory.FromBytes([WellKnownCtapStatusCodes.Ok], pool, Fido2BufferTags.CtapResponseEnvelope));

        var request = new CtapAuthenticatorConfigRequest(SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv);
        await Assert.ThrowsExactlyAsync<ArgumentNullException>(
            () => CtapAuthenticatorConfigClient.AuthenticatorConfigAsync(
                Transceive, CtapAuthenticatorConfigRequestCborWriter.Write, request, null!, TestContext.CancellationToken).AsTask());
    }


    /// <summary>
    /// The success path over the real <see cref="CtapAuthenticatorSimulator"/> loop: a fresh device's
    /// fully unprotected <c>toggleAlwaysUv</c> completes with no exception, and the flip is observable on
    /// the very next <c>authenticatorGetInfo</c>.
    /// </summary>
    [TestMethod]
    public async Task ToggleAlwaysUvSucceedsOverTheSimulator()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("config-client-toggle-always-uv");

        var request = new CtapAuthenticatorConfigRequest(SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv);
        await CtapAuthenticatorConfigClient.AuthenticatorConfigAsync(
            simulator.TransceiveAsync, CtapAuthenticatorConfigRequestCborWriter.Write, request, pool, TestContext.CancellationToken);

        CtapGetInfoResponse info = await CtapWaveConfigFixtures.GetInfoAsync(simulator, pool, TestContext.CancellationToken);
        Assert.IsTrue(info.Options!.AlwaysUv!.Value, "a successful toggleAlwaysUv through the client must flip the wire-observable getInfo option.");
    }
}
