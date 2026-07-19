using System;
using System.Buffers;
using System.Linq;
using System.Net;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Verifiable.DidComm;
using Verifiable.DidComm.Transport;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>One DIDComm envelope received over a WebSocket: the media type the transport conveyed and the bytes.</summary>
internal sealed record DidCommWebSocketDelivery(string MediaType, byte[] Bytes);


/// <summary>
/// A genuine loopback WebSocket inbox for DIDComm delivery, paired with the client-side
/// <see cref="DidCommSendDelegate"/> in <see cref="CreateSendDelegate"/>. Test glue proving the library's
/// transport seam carries a packed message over a NON-HTTP channel (WebSockets) with no library change: the
/// envelope is bytes plus a media type, and a <see cref="DidCommSendDelegate"/> moves them over whatever
/// channel the application owns (DIDComm Messaging v2.1 §Transports, §WebSockets).
/// </summary>
/// <remarks>
/// <para>
/// The library carries no <c>System.Net</c>, so the WebSocket lives entirely here in test code: a real Kestrel
/// host with <c>UseWebSockets</c> accepts one connection, reads the leading text frame (the media type the
/// transport conveys, DIDComm v2.1 §Transport Requirements L1070 — "how IANA media types of the content are
/// provided") and the following binary frame (the packed envelope — one message is one unit of transmission,
/// §WebSockets L1134), and surfaces them through <see cref="ReceivedAsync"/>. The text-frame-then-binary-frame
/// split is this channel's own convention, not a spec requirement.
/// </para>
/// <para>
/// The listener binds <c>wss://</c> with a fresh self-signed leaf certificate (<see cref="LoopbackTls"/>);
/// <see cref="CreateSendDelegate"/>'s <see cref="ClientWebSocket"/> pins to that exact certificate via
/// <see cref="System.Net.WebSockets.ClientWebSocketOptions.RemoteCertificateValidationCallback"/> rather than
/// trusting a CA — there is no CA in this loopback test topology. This is orthogonal to the SSRF concern below:
/// a PRODUCTION socket transport cannot reuse the HTTP path's <c>OutboundFetch</c> (its URL + redirect loop is
/// HTTP-only), so it MUST itself resolve the endpoint host and call
/// <c>OutboundFetchPolicy.EvaluateResolvedAddress</c> on each resolved address — connecting only to a permitted,
/// pinned address — BEFORE <c>ClientWebSocket.ConnectAsync</c>, mirroring the connection-time pinning the HTTP
/// path gets for free from <c>OutboundFetch</c>. This loopback test channel skips that policy check because the
/// endpoint is a trusted loopback inbox.
/// </para>
/// </remarks>
internal sealed class DidCommWebSocketInbox: IAsyncDisposable
{
    private readonly WebApplication app;
    private readonly X509Certificate2 certificate;
    private readonly TaskCompletionSource<DidCommWebSocketDelivery> received =
        new(TaskCreationOptions.RunContinuationsAsynchronously);


    private DidCommWebSocketInbox(WebApplication app, X509Certificate2 certificate)
    {
        this.app = app;
        this.certificate = certificate;
    }


    /// <summary>The <c>wss://127.0.0.1:{port}/</c> endpoint a sender delivers to.</summary>
    public Uri Endpoint { get; private set; } = null!;

    /// <summary>The self-signed leaf certificate this inbox's WebSocket listener presents; <see cref="CreateSendDelegate"/> pins to this exact certificate rather than trusting a CA.</summary>
    public X509Certificate2 Certificate => certificate;


    /// <summary>Starts a loopback WebSocket inbox on an ephemeral port.</summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The started inbox.</returns>
    public static async Task<DidCommWebSocketInbox> StartAsync(CancellationToken cancellationToken)
    {
        X509Certificate2 certificate = LoopbackTls.CreateServerCertificate("didcomm-loopback-test-inbox");

        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();

        //A single explicit HTTPS Listen call — no UseUrls — so there is no plaintext fallback on
        //this host at all.
        builder.WebHost.ConfigureKestrel(options =>
            options.Listen(IPAddress.Loopback, port: 0, listenOptions => listenOptions.UseHttps(certificate)));

        WebApplication app = builder.Build();
        app.UseWebSockets();

        var inbox = new DidCommWebSocketInbox(app, certificate);
        app.Run(context => inbox.HandleAsync(context));

        await app.StartAsync(cancellationToken).ConfigureAwait(false);

        IServerAddressesFeature addresses = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()
            ?? throw new InvalidOperationException("Kestrel exposed no server addresses feature.");
        string boundAddress = addresses.Addresses.FirstOrDefault()
            ?? throw new InvalidOperationException("Kestrel bound no address.");

        inbox.Endpoint = new UriBuilder(boundAddress) { Scheme = "wss", Path = "/" }.Uri;

        return inbox;
    }


    /// <summary>Awaits the one envelope the inbox receives.</summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The received envelope.</returns>
    public Task<DidCommWebSocketDelivery> ReceivedAsync(CancellationToken cancellationToken)
    {
        return received.Task.WaitAsync(cancellationToken);
    }


    /// <summary>
    /// The client-side transport: a <see cref="DidCommSendDelegate"/> that opens a <see cref="ClientWebSocket"/> to the
    /// endpoint, sends the media type as a leading text frame and the packed envelope as one binary frame, and reports
    /// a clean delivery as accepted (a WebSocket has no numeric status, so <see cref="DidCommTransmitResult.TransportStatusCode"/>
    /// stays <see langword="null"/>). The TLS validation pins to <paramref name="pinnedCertificate"/> byte-for-byte
    /// rather than trusting a CA — there is no CA in this loopback test topology.
    /// </summary>
    /// <param name="pinnedCertificate">The exact certificate the loopback WebSocket listener presents.</param>
    /// <returns>A send delegate that delivers over a WebSocket.</returns>
    public static DidCommSendDelegate CreateSendDelegate(X509Certificate2 pinnedCertificate)
    {
        ArgumentNullException.ThrowIfNull(pinnedCertificate);

        return async (message, mediaType, endpoint, context, cancellationToken) =>
        {
            try
            {
                using var client = new ClientWebSocket();
                client.Options.RemoteCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) =>
                    certificate is not null
                    && CryptographicOperations.FixedTimeEquals(certificate.GetRawCertData(), pinnedCertificate.RawData);

                await client.ConnectAsync(endpoint, cancellationToken).ConfigureAwait(false);

                //One DIDComm message is one unit of transmission (DIDComm v2.1 §WebSockets L1134); the media type the
                //transport conveys (§Transport Requirements L1070) leads as a text frame, the packed envelope follows
                //as a single binary frame.
                byte[] mediaTypeBytes = Encoding.UTF8.GetBytes(mediaType);
                await client.SendAsync(mediaTypeBytes, WebSocketMessageType.Text, endOfMessage: true, cancellationToken).ConfigureAwait(false);
                await client.SendAsync(message, WebSocketMessageType.Binary, endOfMessage: true, cancellationToken).ConfigureAwait(false);

                await client.CloseAsync(WebSocketCloseStatus.NormalClosure, "delivered", cancellationToken).ConfigureAwait(false);

                return DidCommTransmitResult.Accepted();
            }
            catch(OperationCanceledException)
            {
                throw;
            }
            catch
            {
                return DidCommTransmitResult.TransportFailed();
            }
        };
    }


    public async ValueTask DisposeAsync()
    {
        await app.StopAsync(CancellationToken.None).ConfigureAwait(false);
        await app.DisposeAsync().ConfigureAwait(false);
        certificate.Dispose();
    }


    //Accepts the WebSocket, reads the media-type text frame and the envelope binary frame, and surfaces them.
    private async Task HandleAsync(HttpContext context)
    {
        if(!context.WebSockets.IsWebSocketRequest)
        {
            context.Response.StatusCode = StatusCodes.Status426UpgradeRequired;

            return;
        }

        using WebSocket socket = await context.WebSockets.AcceptWebSocketAsync().ConfigureAwait(false);

        try
        {
            //Assert the channel's own framing contract: the media type is a leading text frame, the envelope a single
            //binary frame. The receive helper turns an early peer close into a clear exception rather than an opaque
            //WebSocketException, so a misbehaving channel produces a readable failure.
            (WebSocketMessageType mediaTypeFrame, byte[] mediaTypeBytes) = await ReceiveMessageAsync(socket, context.RequestAborted).ConfigureAwait(false);
            if(mediaTypeFrame != WebSocketMessageType.Text)
            {
                throw new InvalidOperationException($"The media type MUST arrive as a leading text frame, not {mediaTypeFrame}.");
            }

            (WebSocketMessageType envelopeFrame, byte[] envelopeBytes) = await ReceiveMessageAsync(socket, context.RequestAborted).ConfigureAwait(false);
            if(envelopeFrame != WebSocketMessageType.Binary)
            {
                throw new InvalidOperationException($"The envelope MUST arrive as a binary frame, not {envelopeFrame}.");
            }

            received.TrySetResult(new DidCommWebSocketDelivery(Encoding.UTF8.GetString(mediaTypeBytes), envelopeBytes));

            await socket.CloseAsync(WebSocketCloseStatus.NormalClosure, "received", context.RequestAborted).ConfigureAwait(false);
        }
        catch(Exception ex)
        {
            received.TrySetException(ex);
        }
    }


    //Reads one whole WebSocket message (all continuation frames to EndOfMessage) into a byte array, returning its
    //frame type. A Close frame arriving before the message completes is surfaced as a clear exception.
    private static async Task<(WebSocketMessageType Type, byte[] Payload)> ReceiveMessageAsync(WebSocket socket, CancellationToken cancellationToken)
    {
        var writer = new ArrayBufferWriter<byte>(initialCapacity: 4096);
        ValueWebSocketReceiveResult result;
        do
        {
            Memory<byte> buffer = writer.GetMemory(4096);
            result = await socket.ReceiveAsync(buffer, cancellationToken).ConfigureAwait(false);
            if(result.MessageType == WebSocketMessageType.Close)
            {
                throw new InvalidOperationException("The peer closed the WebSocket before delivering the expected frame.");
            }

            writer.Advance(result.Count);
        }
        while(!result.EndOfMessage);

        return (result.MessageType, writer.WrittenSpan.ToArray());
    }
}
