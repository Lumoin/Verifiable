using System;
using System.Buffers;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core;
using Verifiable.Core.OutboundFetch;
using Verifiable.DidComm;
using Verifiable.DidComm.Transport;
using Verifiable.Foundation;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DidComm;

/// <summary>
/// Tests for the DIDComm v2.1 HTTPS transport (chunk H, <see cref="DidCommHttpTransport"/>): a message is delivered as
/// an HTTPS POST with the message's media type as <c>Content-Type</c>, a 2xx is a successful receipt, and policy
/// denials / non-2xx / transport failures are fail-soft typed outcomes.
/// </summary>
/// <remarks>
/// The library carries no <c>System.Net</c>, so the transport is a stub <see cref="FakeTransport"/> that records the
/// <see cref="OutboundRequest"/> the convention produced — which fully verifies the §HTTPS encoding (POST, Content-Type,
/// body) without a socket. The send is routed through the SSRF-policed <see cref="OutboundFetch"/>, so an empty
/// <see cref="ExchangeContext"/> (the secure default) blocks a loopback IP-literal endpoint.
/// </remarks>
[TestClass]
internal sealed class DidCommHttpTransportTests
{
    private static readonly MemoryPool<byte> Pool = BaseMemoryPool.Shared;
    private static readonly Uri Endpoint = new("https://recipient.example/didcomm");
    private static readonly Uri LoopbackEndpoint = new("https://127.0.0.1/inbox");


    [TestMethod]
    public async Task TransmitsAsPostWithEncryptedContentType()
    {
        var transport = new FakeTransport(statusCode: 202);
        using DidCommEncryptedMessage message = Encrypted("{\"protected\":\"abc\",\"ciphertext\":\"xyz\"}"u8);

        DidCommTransmitResult result = await message.TransmitAsync(Endpoint, new ExchangeContext(), transport.Send, default).ConfigureAwait(false);

        Assert.IsTrue(result.IsAccepted);
        Assert.AreEqual(202, result.TransportStatusCode);

        Assert.HasCount(1, transport.Calls);
        OutboundRequest request = transport.Calls[0];
        Assert.AreEqual("POST", request.Method, "DIDComm messages MUST be transported via HTTPS POST.");
        Assert.AreEqual(Endpoint, request.Target);
        Assert.IsTrue(request.Headers.TryGetValue("Content-Type", out string? contentType));
        Assert.AreEqual("application/didcomm-encrypted+json", contentType, "The Content-Type MUST be the message's media type.");
        Assert.IsNotNull(request.Body);
        Assert.IsTrue(request.Body!.Value.Memory.Span.SequenceEqual(message.AsReadOnlySpan()), "The POST body MUST be the message bytes.");
    }


    [TestMethod]
    public async Task SignedAndPlaintextUseTheirMediaTypes()
    {
        var transport = new FakeTransport(statusCode: 202);

        using DidCommSignedMessage signed = DidCommSignedMessage.Create("{\"payload\":\"p\",\"signatures\":[]}"u8, BufferTags.Json, Pool);
        await signed.TransmitAsync(Endpoint, new ExchangeContext(), transport.Send, default).ConfigureAwait(false);
        Assert.AreEqual("POST", transport.Calls[0].Method);
        Assert.AreEqual("application/didcomm-signed+json", ContentTypeOf(transport.Calls[0]));

        using DidCommPlaintextMessage plaintext = DidCommPlaintextMessage.Create("{\"id\":\"1\",\"type\":\"t\"}"u8, BufferTags.Json, Pool);
        await plaintext.TransmitAsync(Endpoint, new ExchangeContext(), transport.Send, default).ConfigureAwait(false);
        Assert.AreEqual("POST", transport.Calls[1].Method);
        Assert.AreEqual("application/didcomm-plain+json", ContentTypeOf(transport.Calls[1]));
    }


    [TestMethod]
    [DataRow(200)]
    [DataRow(202)]
    [DataRow(204)]
    [DataRow(299)]
    public async Task SuccessStatusRangeIsAccepted(int statusCode)
    {
        var transport = new FakeTransport(statusCode);
        using DidCommEncryptedMessage message = Encrypted("{\"ciphertext\":\"x\"}"u8);

        DidCommTransmitResult result = await message.TransmitAsync(Endpoint, new ExchangeContext(), transport.Send, default).ConfigureAwait(false);

        Assert.IsTrue(result.IsAccepted, $"A {statusCode} status is in the 2xx range and MUST be accepted.");
        Assert.AreEqual(DidCommTransmitError.None, result.Error);
        Assert.AreEqual(statusCode, result.TransportStatusCode);
    }


    [TestMethod]
    [DataRow(400)]
    [DataRow(404)]
    [DataRow(500)]
    public async Task NonSuccessStatusIsNotAccepted(int statusCode)
    {
        var transport = new FakeTransport(statusCode);
        using DidCommEncryptedMessage message = Encrypted("{\"ciphertext\":\"x\"}"u8);

        DidCommTransmitResult result = await message.TransmitAsync(Endpoint, new ExchangeContext(), transport.Send, default).ConfigureAwait(false);

        Assert.IsFalse(result.IsAccepted, $"A {statusCode} status is not 2xx and MUST NOT be accepted.");
        Assert.AreEqual(DidCommTransmitError.Rejected, result.Error);
        Assert.AreEqual(statusCode, result.TransportStatusCode);
    }


    [TestMethod]
    public async Task SsrfDeniedEndpointFailsClosedWithoutContactingTransport()
    {
        var transport = new FakeTransport(statusCode: 202);
        using DidCommEncryptedMessage message = Encrypted("{\"ciphertext\":\"x\"}"u8);

        //An empty context is the secure default: a loopback IP-literal endpoint is denied before any transport call.
        DidCommTransmitResult result = await message.TransmitAsync(LoopbackEndpoint, new ExchangeContext(), transport.Send, default).ConfigureAwait(false);

        Assert.IsFalse(result.IsAccepted);
        Assert.AreEqual(DidCommTransmitError.DeniedByPolicy, result.Error);
        Assert.IsNull(result.TransportStatusCode);
        Assert.IsEmpty(transport.Calls, "A policy-denied endpoint MUST NOT contact the transport.");
    }


    [TestMethod]
    public async Task TransportExceptionFailsClosed()
    {
        var transport = new FakeTransport(statusCode: 202, throwOnSend: true);
        using DidCommEncryptedMessage message = Encrypted("{\"ciphertext\":\"x\"}"u8);

        DidCommTransmitResult result = await message.TransmitAsync(Endpoint, new ExchangeContext(), transport.Send, default).ConfigureAwait(false);

        Assert.IsFalse(result.IsAccepted);
        Assert.AreEqual(DidCommTransmitError.TransportFailed, result.Error);
        Assert.IsNull(result.TransportStatusCode);
    }


    [TestMethod]
    public async Task CancellationPropagatesAndIsNotSwallowed()
    {
        //A cancellation surfacing from the transport MUST propagate, not be folded into a fail-soft result.
        var transport = new FakeTransport(statusCode: 202, throwCancellation: true);
        using DidCommEncryptedMessage message = Encrypted("{\"ciphertext\":\"x\"}"u8);
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync().ConfigureAwait(false);

        await Assert.ThrowsAsync<OperationCanceledException>(
            async () => await message.TransmitAsync(Endpoint, new ExchangeContext(), transport.Send, cts.Token).ConfigureAwait(false)).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task NullArgumentsAreRejected()
    {
        var transport = new FakeTransport(statusCode: 202);
        using DidCommEncryptedMessage message = Encrypted("{\"ciphertext\":\"x\"}"u8);

        await Assert.ThrowsExactlyAsync<ArgumentNullException>(
            async () => await message.TransmitAsync(null!, new ExchangeContext(), transport.Send, default).ConfigureAwait(false)).ConfigureAwait(false);
        await Assert.ThrowsExactlyAsync<ArgumentNullException>(
            async () => await message.TransmitAsync(Endpoint, null!, transport.Send, default).ConfigureAwait(false)).ConfigureAwait(false);
        await Assert.ThrowsExactlyAsync<ArgumentNullException>(
            async () => await message.TransmitAsync(Endpoint, new ExchangeContext(), (DidCommSendDelegate)null!, default).ConfigureAwait(false)).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task ResponseBodyIsIgnoredOneWay()
    {
        //DIDComm POST is one-way: a present response body is never consumed; only the status determines the outcome.
        var transport = new FakeTransport(statusCode: 202, responseBody: "an-ignored-reply-body"u8.ToArray());
        using DidCommEncryptedMessage message = Encrypted("{\"ciphertext\":\"x\"}"u8);

        DidCommTransmitResult result = await message.TransmitAsync(Endpoint, new ExchangeContext(), transport.Send, default).ConfigureAwait(false);

        Assert.IsTrue(result.IsAccepted, "A 2xx with a response body is accepted; the body is ignored.");
        Assert.AreEqual(202, result.TransportStatusCode);
    }


    [TestMethod]
    public async Task HttpTransportUsedAsSendDelegateRoutesThroughNeutralTransmit()
    {
        //CreateSendDelegate adapts the HTTP transport to the neutral DidCommSendDelegate, so the HTTPS binding is
        //just one channel routed through the SAME TransmitAsync a WebSocket/Bluetooth delegate uses — proving HTTP
        //is not privileged in the transport seam.
        var transport = new FakeTransport(statusCode: 202);
        using DidCommEncryptedMessage message = Encrypted("{\"ciphertext\":\"x\"}"u8);

        DidCommSendDelegate send = DidCommHttpTransport.CreateSendDelegate(transport.SendAsync);
        DidCommTransmitResult result = await message.TransmitAsync(Endpoint, new ExchangeContext(), send, default).ConfigureAwait(false);

        Assert.IsTrue(result.IsAccepted);
        Assert.AreEqual(202, result.TransportStatusCode);
        Assert.HasCount(1, transport.Calls);
        Assert.AreEqual("POST", transport.Calls[0].Method, "The HTTP send delegate still POSTs.");
        Assert.AreEqual("application/didcomm-encrypted+json", ContentTypeOf(transport.Calls[0]), "The HTTP send delegate sets the media type as Content-Type.");
    }


    [TestMethod]
    public void CreateSendDelegateRejectsNullTransport()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => DidCommHttpTransport.CreateSendDelegate(null!));
    }


    /// <summary>
    /// DNS-rebinding defense for the service-endpoint send: a public host NAME that resolves to a loopback
    /// address MUST be blocked at connection-time by the pinning send delegate — the URL gate cannot catch a
    /// rebinding host name (it does no DNS). The endpoint is never dialed and the transmit is DeniedByPolicy.
    /// </summary>
    [TestMethod]
    public async Task ServiceEndpointHostRebindingToLoopbackIsBlockedAtConnectionTime()
    {
        HostResolverDelegate rebindToLoopback = (host, cancellationToken) =>
            ValueTask.FromResult<IReadOnlyList<IPAddress>>([IPAddress.Loopback]);

        bool pinned = false;
        bool dialed = false;
        DidCommSendDelegate send = async (message, mediaType, endpoint, context, cancellationToken) =>
        {
            pinned = true;
            try
            {
                _ = await SsrfHardenedTransport.ResolveAndPinAsync(endpoint.Host, context.OutboundFetchPolicy, rebindToLoopback, cancellationToken).ConfigureAwait(false);
            }
            catch(SsrfBlockedException)
            {
                return DidCommTransmitResult.DeniedByPolicy();
            }

            dialed = true;

            return DidCommTransmitResult.Accepted(202);
        };

        using DidCommEncryptedMessage message = Encrypted("{\"ciphertext\":\"x\"}"u8);
        var context = new ExchangeContext();
        context.SetOutboundFetchPolicy(OutboundFetchPolicy.SecureDefault);

        DidCommTransmitResult result = await message.TransmitAsync(
            new Uri("https://rebinding.example/didcomm"), context, send, default).ConfigureAwait(false);

        Assert.IsTrue(pinned, "The connection-time pin MUST run for an absolute, policy-permitted host name.");
        Assert.IsFalse(dialed, "A service-endpoint host that rebinds to loopback MUST be blocked before the dial.");
        Assert.IsFalse(result.IsAccepted);
        Assert.AreEqual(DidCommTransmitError.DeniedByPolicy, result.Error);
    }


    // ---- helpers -------------------------------------------------------------------------------

    private static DidCommEncryptedMessage Encrypted(ReadOnlySpan<byte> wireBytes) =>
        DidCommEncryptedMessage.Create(wireBytes, BufferTags.Json, Pool);


    private static string? ContentTypeOf(OutboundRequest request) =>
        request.Headers.TryGetValue("Content-Type", out string? contentType) ? contentType : null;


    //A stub OutboundTransportDelegate: records every request and returns the configured status (optionally with a
    //response body), or throws a transport failure or a cancellation.
    private sealed class FakeTransport
    {
        private readonly int statusCode;
        private readonly bool throwOnSend;
        private readonly bool throwCancellation;
        private readonly ReadOnlyMemory<byte> responseBody;

        public FakeTransport(int statusCode, bool throwOnSend = false, bool throwCancellation = false, ReadOnlyMemory<byte> responseBody = default)
        {
            this.statusCode = statusCode;
            this.throwOnSend = throwOnSend;
            this.throwCancellation = throwCancellation;
            this.responseBody = responseBody;
        }


        public List<OutboundRequest> Calls { get; } = [];


        //The HTTP transport adapted to the neutral send seam: every TransmitAsync in these tests goes through it, so
        //HTTP is exercised as just one DidCommSendDelegate, not a privileged surface.
        public DidCommSendDelegate Send => DidCommHttpTransport.CreateSendDelegate(SendAsync);


        public ValueTask<OutboundResponse> SendAsync(OutboundRequest request, ExchangeContext context, CancellationToken cancellationToken)
        {
            Calls.Add(request);
            if(throwCancellation)
            {
                throw new OperationCanceledException(cancellationToken);
            }

            if(throwOnSend)
            {
                throw new InvalidOperationException("Simulated transport failure.");
            }

            OutboundResponse response = responseBody.IsEmpty
                ? new OutboundResponse { StatusCode = statusCode }
                : new OutboundResponse { StatusCode = statusCode, Body = new TaggedMemory<byte>(responseBody, BufferTags.Json) };

            return ValueTask.FromResult(response);
        }
    }
}
