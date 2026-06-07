using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.OutboundFetch;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Core;

/// <summary>
/// Tests for the connection-time SSRF guard's security logic
/// (<see cref="SsrfHardenedTransport.ResolveAndPinAsync"/>) — resolve, validate
/// every resolved address against the policy, pin to a permitted one. Uses a
/// fake resolver so DNS-rebinding is simulated without the network. The
/// <see cref="System.Net.Sockets"/>/<c>ConnectCallback</c> wiring is reference
/// glue around this logic and is not exercised here.
/// </summary>
[TestClass]
internal sealed class SsrfHardenedTransportTests
{
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public async Task InternalIpLiteralIsBlockedWithoutResolving()
    {
        await Assert.ThrowsExactlyAsync<SsrfBlockedException>(async () =>
            await SsrfHardenedTransport.ResolveAndPinAsync(
                "169.254.169.254", OutboundFetchPolicy.SecureDefault, ThrowingResolver, TestContext.CancellationToken)
            .ConfigureAwait(false)).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task PublicIpLiteralIsPinnedWithoutResolving()
    {
        IPAddress pinned = await SsrfHardenedTransport.ResolveAndPinAsync(
            "93.184.216.34", OutboundFetchPolicy.SecureDefault, ThrowingResolver, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(IPAddress.Parse("93.184.216.34"), pinned);
    }


    [TestMethod]
    public async Task HostThatRebindsToLoopbackIsBlocked()
    {
        HostResolverDelegate rebinding = Resolver(IPAddress.Loopback);

        await Assert.ThrowsExactlyAsync<SsrfBlockedException>(async () =>
            await SsrfHardenedTransport.ResolveAndPinAsync(
                "public-looking.example", OutboundFetchPolicy.SecureDefault, rebinding, TestContext.CancellationToken)
            .ConfigureAwait(false)).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task HostThatResolvesToPublicIsPinned()
    {
        IPAddress expected = IPAddress.Parse("93.184.216.34");
        HostResolverDelegate resolver = Resolver(expected);

        IPAddress pinned = await SsrfHardenedTransport.ResolveAndPinAsync(
            "public.example", OutboundFetchPolicy.SecureDefault, resolver, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(expected, pinned);
    }


    [TestMethod]
    public async Task AnyBlockedAddressInTheResolvedSetRejectsTheHost()
    {
        //Rebinding defense: a host that resolves to both a public and an internal
        //address is rejected wholesale rather than racing to a permitted one.
        HostResolverDelegate mixed = Resolver(IPAddress.Parse("93.184.216.34"), IPAddress.Parse("10.0.0.1"));

        await Assert.ThrowsExactlyAsync<SsrfBlockedException>(async () =>
            await SsrfHardenedTransport.ResolveAndPinAsync(
                "mixed.example", OutboundFetchPolicy.SecureDefault, mixed, TestContext.CancellationToken)
            .ConfigureAwait(false)).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task HostThatDoesNotResolveIsBlocked()
    {
        HostResolverDelegate empty = (host, cancellationToken) =>
            ValueTask.FromResult<IReadOnlyList<IPAddress>>([]);

        await Assert.ThrowsExactlyAsync<SsrfBlockedException>(async () =>
            await SsrfHardenedTransport.ResolveAndPinAsync(
                "nxdomain.example", OutboundFetchPolicy.SecureDefault, empty, TestContext.CancellationToken)
            .ConfigureAwait(false)).ConfigureAwait(false);
    }


    private static HostResolverDelegate Resolver(params IPAddress[] addresses) =>
        (host, cancellationToken) => ValueTask.FromResult<IReadOnlyList<IPAddress>>(addresses);


    private static ValueTask<IReadOnlyList<IPAddress>> ThrowingResolver(string host, CancellationToken cancellationToken) =>
        throw new InvalidOperationException("Resolver must not be called for an IP literal.");
}
