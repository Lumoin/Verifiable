using System;
using System.Buffers;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using static Verifiable.Tests.TestInfrastructure.CtapWave2AuthenticatorFixtures;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Disposal tests for <see cref="CtapAuthenticatorSimulator"/>: idempotent <see cref="CtapAuthenticatorSimulator.Dispose"/>,
/// post-dispose <see cref="ObjectDisposedException"/> on <see cref="CtapAuthenticatorSimulator.TransceiveAsync"/>,
/// and that disposing a simulator holding both resident and non-resident credentials releases every
/// credential's pooled memory without throwing.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorSimulatorDisposalTests
{
    public TestContext TestContext { get; set; } = null!;


    /// <summary>Calling <see cref="CtapAuthenticatorSimulator.Dispose"/> twice is safe — the second call is a no-op.</summary>
    [TestMethod]
    public void DisposeIsIdempotent()
    {
        CtapAuthenticatorSimulator simulator = CreateSimulator("dispose-idempotent");

        simulator.Dispose();
        simulator.Dispose();
    }


    /// <summary>After disposal, <see cref="CtapAuthenticatorSimulator.TransceiveAsync"/> throws <see cref="ObjectDisposedException"/>.</summary>
    [TestMethod]
    public async Task TransceiveAsyncAfterDisposeThrowsObjectDisposedException()
    {
        CtapAuthenticatorSimulator simulator = CreateSimulator("dispose-then-transceive");
        simulator.Dispose();

        byte[] request = [WellKnownCtapCommands.GetInfo];
        await Assert.ThrowsExactlyAsync<ObjectDisposedException>(
            () => simulator.TransceiveAsync(request, BaseMemoryPool.Shared, TestContext.CancellationToken).AsTask());
    }


    /// <summary>
    /// Disposing a simulator that holds both a resident and a non-resident credential releases every
    /// credential's pooled memory (credential ID, user handle, private key) without throwing — exercised
    /// through the real <c>authenticatorMakeCredential</c> wire path, not a hand-built store.
    /// </summary>
    [TestMethod]
    public async Task DisposeReleasesEveryCredentialInTheStore()
    {
        CtapAuthenticatorSimulator simulator = CreateSimulator("dispose-releases-store");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0x21), TestContext.CancellationToken, resident: true);
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0x22), TestContext.CancellationToken, resident: false);

        simulator.Dispose();
        simulator.Dispose();
    }
}
