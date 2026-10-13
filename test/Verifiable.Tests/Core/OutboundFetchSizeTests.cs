using Verifiable.Core;
using Verifiable.Core.Outbound;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Core;

/// <summary>Size evidence, read boundaries, and stream lifetime through both single-hop transports.</summary>
[TestClass]
internal sealed class OutboundFetchSizeTests
{
    /// <summary>The runner's cancellation context.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The target whose provenance must survive a size refusal.</summary>
    private static Uri Target { get; } = new("https://issuer.example/metadata");


    /// <summary>A declared excess is refused without reading even when the available body is small.</summary>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task DeclaredLengthOverLimitStopsBeforeReading(bool useHttpClient)
    {
        using StreamingOutboundTransport transport = new([1], 65, useHttpClient);
        OutboundFetchResult result = await FetchAsync(transport, 64).ConfigureAwait(false);

        AssertRefusal(result, 64, 65, OutboundResponseLengthKind.Declared);
        Assert.AreEqual(0, transport.BytesRead);
        Assert.IsTrue(transport.IsDisposed);
        if(!useHttpClient)
        {
            Assert.IsNotNull(transport.Returned);
            Assert.AreSame(transport.Returned.TooLarge, result.TooLarge);
        }
    }


    /// <summary>An undeclared excess stops at the first byte over the limit, without draining the body.</summary>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task StreamedLengthOverLimitStopsAtFirstExcessByte(bool useHttpClient)
    {
        using StreamingOutboundTransport transport = new(new byte[1024], null, useHttpClient);
        OutboundFetchResult result = await FetchAsync(transport, 64).ConfigureAwait(false);

        AssertRefusal(result, 64, 65, OutboundResponseLengthKind.Observed);
        Assert.AreEqual(65, transport.BytesRead);
        Assert.IsTrue(transport.IsDisposed);
    }


    /// <summary>An exact-limit body is accepted after EOF, both with and without a declared length.</summary>
    [TestMethod]
    [DataRow(false, false)]
    [DataRow(false, true)]
    [DataRow(true, false)]
    [DataRow(true, true)]
    public async Task ExactLimitBodyIsFetched(bool useHttpClient, bool declareLength)
    {
        byte[] bytes = Enumerable.Range(0, 64).Select(value => (byte)value).ToArray();
        using StreamingOutboundTransport transport = new(bytes, declareLength ? 64 : null, useHttpClient);
        OutboundFetchResult result = await FetchAsync(transport, 64).ConfigureAwait(false);

        Assert.AreEqual(OutboundFetchOutcome.Fetched, result.Outcome);
        Assert.IsNotNull(result.Response);
        Assert.AreSequenceEqual(bytes, result.Response.Body.Memory.ToArray());
        Assert.IsNull(result.TooLarge);
        Assert.AreEqual(64, transport.BytesRead);
        Assert.IsTrue(transport.IsDisposed);
    }


    /// <summary>A short declaration cannot hide an observed excess.</summary>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task UnderstatedDeclaredLengthStillChecksObservedBytes(bool useHttpClient)
    {
        using StreamingOutboundTransport transport = new(new byte[1024], 1, useHttpClient);
        OutboundFetchResult result = await FetchAsync(transport, 64).ConfigureAwait(false);
        AssertRefusal(result, 64, 65, OutboundResponseLengthKind.Observed);
        Assert.AreEqual(65, transport.BytesRead);
    }


    /// <summary>Runs the actual guarded fetch with an explicit per-request limit.</summary>
    private ValueTask<OutboundFetchResult> FetchAsync(StreamingOutboundTransport transport, long limit) =>
        OutboundFetch.FetchAsync(
            new OutboundRequest { Target = Target, Method = WellKnownHttpMethods.Get, MaxResponseBytes = limit },
            new ExchangeContext(), transport.Delegate, TestContext.CancellationToken);


    /// <summary>Checks typed evidence and the absence of a usable partial response.</summary>
    private static void AssertRefusal(OutboundFetchResult result, long limit, long length, OutboundResponseLengthKind kind)
    {
        Assert.AreEqual(OutboundFetchOutcome.TooLarge, result.Outcome);
        Assert.IsFalse(result.IsFetched);
        Assert.IsNull(result.Response);
        Assert.AreEqual(new OutboundResponseTooLarge(limit, length, kind), result.TooLarge);
        Assert.AreEqual(Target, result.RequestedUri);
        Assert.AreEqual(Target, result.FinalUri);
        Assert.AreEqual(0, result.RedirectCount);
    }
}
