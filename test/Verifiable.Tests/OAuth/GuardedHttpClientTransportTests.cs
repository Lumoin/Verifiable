using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core;
using Verifiable.Core.OutboundFetch;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Client;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Proves the OutboundFetch adoption on the OAuth/wallet transport seam: the
/// guarded <see cref="SendFormPostDelegate"/> from
/// <see cref="GuardedHttpClientTransport"/> routes through
/// <see cref="OutboundFetch.FetchAsync"/>, so the per-call
/// <see cref="OutboundFetchPolicy"/> on the <see cref="ExchangeContext"/> decides
/// whether the dereference happens at all — the wallet's <c>request_uri</c> POST
/// (a target that arrives in a semi-trusted authorization request) cannot reach a
/// blocked address. The inner transport is a handler that THROWS if invoked, so a
/// denied target is proven to fail before any network contact.
/// </summary>
[TestClass]
internal sealed class GuardedHttpClientTransportTests
{
    public TestContext TestContext { get; set; } = null!;

    private static readonly OutgoingHeaders NoHeaders = new();

    private static readonly System.Collections.Generic.Dictionary<string, string> Form =
        new(StringComparer.Ordinal) { ["wallet_metadata"] = "{}" };


    [TestMethod]
    public async Task SecureDefaultDeniesLinkLocalMetadataTargetBeforeNetwork()
    {
        using ThrowingHandler handler = new();
        using HttpClient httpClient = new(handler, disposeHandler: false);
        SendFormPostDelegate send = GuardedHttpClientTransport.BuildGuardedFormPost(httpClient);

        //An authorization request pointing the wallet at the cloud metadata
        //service — the classic SSRF target. SecureDefault blocks link-local.
        ExchangeContext context = new();
        HttpResponseData response = await send(
            new Uri("https://169.254.169.254/latest/meta-data/"),
            Form, NoHeaders, context, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(0, response.StatusCode,
            "A policy-denied target must surface as a non-success transport result, not a fetch.");
        Assert.AreEqual(
            nameof(OutboundFetchOutcome.DeniedByPolicy),
            response.TransportMetadata?[GuardedHttpClientTransport.OutcomeMetadataKey],
            "The deny outcome must be carried in the transport metadata.");
    }


    [TestMethod]
    public async Task SecureDefaultDeniesPlainHttpAndLoopbackBeforeNetwork()
    {
        using ThrowingHandler handler = new();
        using HttpClient httpClient = new(handler, disposeHandler: false);
        SendFormPostDelegate send = GuardedHttpClientTransport.BuildGuardedFormPost(httpClient);

        //Plain http is denied by the https-only default; loopback is denied by
        //the private-range rule. Either way the throwing handler is never hit.
        ExchangeContext context = new();
        HttpResponseData response = await send(
            new Uri("http://127.0.0.1:8080/cb"),
            Form, NoHeaders, context, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(0, response.StatusCode);
        Assert.AreEqual(
            nameof(OutboundFetchOutcome.DeniedByPolicy),
            response.TransportMetadata?[GuardedHttpClientTransport.OutcomeMetadataKey]);
    }


    [TestMethod]
    public async Task RelaxedLoopbackPolicyAllowsTheConfiguredLocalListener()
    {
        using StubOkHandler handler = new();
        using HttpClient httpClient = new(handler, disposeHandler: false);
        SendFormPostDelegate send = GuardedHttpClientTransport.BuildGuardedFormPost(httpClient);

        //The deployment's transport endpoint genuinely is a loopback listener, so
        //the policy is relaxed for exactly that — the same principled choice the
        //HTTP-backed flow tests make. The fetch now proceeds to the stub.
        ExchangeContext context = new();
        context.SetOutboundFetchPolicy(TestHostShell.LoopbackOutboundFetchPolicy);

        HttpResponseData response = await send(
            new Uri("http://127.0.0.1:8080/cb"),
            Form, NoHeaders, context, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode,
            "Under the relaxed loopback policy the configured local listener is reachable.");
    }


    /// <summary>An inner transport that must never be invoked on a denied target.</summary>
    private sealed class ThrowingHandler: HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw new InvalidOperationException(
                "The guarded transport reached the network for a policy-denied target.");
    }


    /// <summary>An inner transport that returns 200 with an empty body.</summary>
    private sealed class StubOkHandler: HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(string.Empty)
            });
    }
}
