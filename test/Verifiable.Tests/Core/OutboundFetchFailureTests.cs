using Verifiable.Core;
using Verifiable.Core.Outbound;

namespace Verifiable.Tests.Core;

/// <summary>Transport failure boundaries include body reads and every followed redirect hop.</summary>
[TestClass]
internal sealed class OutboundFetchFailureTests
{
    /// <summary>The runner's cancellation context.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The original fetch location.</summary>
    private static Uri Target { get; } = new("https://issuer.example/metadata");

    /// <summary>The redirected location whose failed provenance must be retained.</summary>
    private static Uri RedirectTarget { get; } = new("https://issuer.example/moved");


    /// <summary>A timeout is typed whether transport fails before headers or while the reader awaits the body.</summary>
    [TestMethod]
    [DataRow(false, false)]
    [DataRow(false, true)]
    [DataRow(true, false)]
    [DataRow(true, true)]
    public async Task TimeoutRetainsFailedHopProvenance(bool redirect, bool duringBodyRead)
    {
        ExchangeContext context = [];
        context.SetOutboundFetchPolicy(OutboundFetchPolicy.SecureDefault with { Redirects = RedirectMode.SameOrigin, MaxRedirects = 1 });
        int calls = 0;
        using TimeoutBody body = new();

        //Redirects the first hop when asked; the last hop's budget elapses before its headers or while its body is read.
        async ValueTask<OutboundTransportResult> transport(
            OutboundRequest request, ExchangeContext exchangeContext, OutboundResponseReaderDelegate readResponse, CancellationToken token)
        {
            calls++;
            if(redirect && request.Target == Target)
            {
                using MemoryStream empty = new();
                return await readResponse(302,
                    HttpHeaderSet.FromPairs((WellKnownHttpHeaderNames.Location, RedirectTarget.OriginalString)),
                    empty, token).ConfigureAwait(false);
            }

            using(body)
            {
                return duringBodyRead
                    ? await readResponse(200, HttpHeaderSet.Empty, body, token).ConfigureAwait(false)
                    : throw new TaskCanceledException("Transport budget elapsed.");
            }
        }

        OutboundFetchResult result = await OutboundFetch.FetchAsync(
            new OutboundRequest { Target = Target, Method = WellKnownHttpMethods.Get }, context, transport,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(OutboundFetchOutcome.Unreachable, result.Outcome);
        Assert.AreEqual(typeof(TimeoutException), result.FailureKind);
        Assert.AreEqual(Target, result.RequestedUri);
        Assert.AreEqual(redirect ? RedirectTarget : Target, result.FinalUri);
        Assert.AreEqual(redirect ? 1 : 0, result.RedirectCount);
        Assert.AreEqual(redirect ? 2 : 1, calls);
        Assert.IsNull(result.Response);
        Assert.IsNull(result.TooLarge);
        Assert.IsNull(result.RefusedRedirect);
        Assert.IsTrue(body.IsDisposed);
    }


    /// <summary>A transport that finishes after the caller cancels cannot turn that cancellation into success.</summary>
    [TestMethod]
    public async Task CallerCancellationAfterReaderReturnsStillPropagates()
    {
        using CancellationTokenSource caller = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);

        //Reads a complete response, then the caller cancels before the transport hands that response back.
        async ValueTask<OutboundTransportResult> transport(
            OutboundRequest request, ExchangeContext context, OutboundResponseReaderDelegate readResponse, CancellationToken token)
        {
            using MemoryStream empty = new();
            OutboundTransportResult response = await readResponse(200, HttpHeaderSet.Empty, empty, token).ConfigureAwait(false);
            await caller.CancelAsync().ConfigureAwait(false);
            return response;
        }

        OperationCanceledException caught = await Assert.ThrowsExactlyAsync<OperationCanceledException>(
            async () => await OutboundFetch.FetchAsync(
                new OutboundRequest { Target = Target, Method = WellKnownHttpMethods.Get }, new ExchangeContext(),
                transport, caller.Token).ConfigureAwait(false)).ConfigureAwait(false);

        Assert.AreEqual(caller.Token, caught.CancellationToken);
    }


    /// <summary>A live response stream whose asynchronous read ends on the transport's budget.</summary>
    private sealed class TimeoutBody: MemoryStream
    {
        /// <summary>Whether transport cleanup ran even though no response completed.</summary>
        public bool IsDisposed { get; private set; }

        /// <inheritdoc />
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken) =>
            ValueTask.FromException<int>(new TaskCanceledException("Body read budget elapsed."));

        /// <inheritdoc />
        protected override void Dispose(bool disposing)
        {
            IsDisposed = true;
            base.Dispose(disposing);
        }
    }
}
