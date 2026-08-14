using System;
using System.Net.WebSockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Verifiable.DidComm.Transport;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Reads one complete inbound frame off an open <see cref="DidCommDuplexMediatorHost"/>/<see cref="DidCommDuplexWalletConnection"/>
/// socket, delegating to the shared <see cref="DidCommLoopbackWebSocketBootstrap.ReceiveMessageAsync"/> — this
/// type adds no receive logic of its own, only the pair's shared entry point for it.
/// </summary>
internal static class DidCommDuplexFraming
{
    /// <summary>Reads one whole WebSocket message, surfacing the frame type the peer sent it as.</summary>
    /// <param name="socket">The open socket to read one message from.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The frame type the message arrived as, and its complete bytes.</returns>
    public static Task<(WebSocketMessageType Type, byte[] Payload)> ReceiveOneMessageAsync(WebSocket socket, CancellationToken cancellationToken) =>
        DidCommLoopbackWebSocketBootstrap.ReceiveMessageAsync(socket, cancellationToken);
}


/// <summary>
/// A genuine loopback, PERSISTENT duplex WebSocket connection pair for exercising
/// <c>DidCommSocketSession</c> end to end. Unlike <see cref="DidCommWebSocketInbox"/> — which accepts one
/// connection, reads exactly one delivery, and closes — this host keeps the accepted connection open across
/// many frames in both directions, and <see cref="DidCommDuplexWalletConnection"/> dials it and stays
/// connected the same way. Both sides expose a <see cref="DidCommSessionSendDelegate"/>
/// (<see cref="CreateSendDelegate"/>/<see cref="DidCommDuplexWalletConnection.CreateSendDelegate"/>) and a
/// per-call <c>ReceiveFrameAsync</c>, so a caller drives its OWN <c>DidCommSocketSession</c> pump loop on
/// either or both ends — the identical session type serving the mediator's accept side and the recipient's
/// dial side (the seam's documented role symmetry).
/// </summary>
internal sealed class DidCommDuplexMediatorHost: IAsyncDisposable
{
    private readonly WebApplication app;
    private readonly X509Certificate2 certificate;
    private readonly TaskCompletionSource<WebSocket> accepted = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource<bool> closeRequested = new(TaskCreationOptions.RunContinuationsAsynchronously);


    private DidCommDuplexMediatorHost(WebApplication app, X509Certificate2 certificate)
    {
        this.app = app;
        this.certificate = certificate;
    }


    /// <summary>The <c>wss://127.0.0.1:{port}/</c> endpoint the wallet connects to.</summary>
    public Uri Endpoint { get; private set; } = null!;

    /// <summary>The self-signed leaf certificate this host's listener presents; a connecting client pins to this exact certificate.</summary>
    public X509Certificate2 Certificate => certificate;


    /// <summary>Starts a loopback duplex WebSocket mediator host on an ephemeral port.</summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The started host.</returns>
    public static async Task<DidCommDuplexMediatorHost> StartAsync(CancellationToken cancellationToken)
    {
        (WebApplication app, X509Certificate2 certificate) = DidCommLoopbackWebSocketBootstrap.Build("didcomm-duplex-loopback-mediator");

        var host = new DidCommDuplexMediatorHost(app, certificate);
        host.Endpoint = await DidCommLoopbackWebSocketBootstrap.StartAsync(app, host.HandleAsync, cancellationToken).ConfigureAwait(false);

        return host;
    }


    //Accepts the one WebSocket connection this host serves and holds the request open until DisposeAsync
    //signals shutdown — returning here would tear the socket down even though frames keep flowing through
    //direct SendFrameAsync/ReceiveFrameAsync calls against the accepted socket.
    private async Task HandleAsync(HttpContext context)
    {
        if(!context.WebSockets.IsWebSocketRequest)
        {
            context.Response.StatusCode = StatusCodes.Status426UpgradeRequired;

            return;
        }

        WebSocket socket = await context.WebSockets.AcceptWebSocketAsync().ConfigureAwait(false);
        accepted.TrySetResult(socket);

        //Wait for DisposeAsync's shutdown signal rather than returning — returning here would tear the
        //socket down while the test is still driving direct SendFrameAsync/ReceiveFrameAsync calls against
        //it. Once signaled, this returns without its own close handshake: DisposeAsync's app.StopAsync tears
        //the listener (and every accepted connection) down regardless, and by the time it is called the test
        //has already finished asserting everything it needs from this connection.
        await closeRequested.Task.ConfigureAwait(false);
    }


    /// <summary>Reads the next complete inbound frame from the connected wallet.</summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The frame type the peer sent it as, and its complete bytes.</returns>
    public async Task<(WebSocketMessageType Type, byte[] Payload)> ReceiveFrameAsync(CancellationToken cancellationToken)
    {
        WebSocket socket = await accepted.Task.WaitAsync(cancellationToken).ConfigureAwait(false);

        return await DidCommDuplexFraming.ReceiveOneMessageAsync(socket, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// A <see cref="DidCommSessionSendDelegate"/> that sends over the accepted socket as one complete TEXT
    /// frame (UTF-8 JSON) — the measured interop posture (DIDComm v2.1 §WebSockets; the one shipping DIDComm
    /// v2 WebSocket mediator sends text, per <see cref="DidCommSessionSendDelegate"/>'s own remarks).
    /// </summary>
    /// <returns>The send delegate.</returns>
    public DidCommSessionSendDelegate CreateSendDelegate()
    {
        return async (message, mediaType, cancellationToken) =>
        {
            try
            {
                WebSocket socket = await accepted.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
                await socket.SendAsync(message, WebSocketMessageType.Text, endOfMessage: true, cancellationToken).ConfigureAwait(false);

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
        closeRequested.TrySetResult(true);
        await app.StopAsync(CancellationToken.None).ConfigureAwait(false);
        await app.DisposeAsync().ConfigureAwait(false);
        certificate.Dispose();
    }
}


/// <summary>
/// The wallet's dial side of a persistent, duplex loopback WebSocket: a <see cref="ClientWebSocket"/> pinned
/// to the mediator's exact leaf certificate (there is no CA in this loopback topology), staying open across
/// many send/receive round trips — the client-side counterpart to <see cref="DidCommDuplexMediatorHost"/>.
/// </summary>
internal sealed class DidCommDuplexWalletConnection: IAsyncDisposable
{
    private readonly ClientWebSocket client;


    private DidCommDuplexWalletConnection(ClientWebSocket client, WebSocketCertificatePinning pinning)
    {
        this.client = client;
        Pinning = pinning;
    }


    private WebSocketCertificatePinning Pinning { get; }

    /// <summary>
    /// Whether the TLS handshake invoked the certificate validation callback at all — something only a
    /// genuine TLS connection produces, never a stub or an in-process shortcut.
    /// </summary>
    public bool DidInvokeCertificatePinningCallback => Pinning.WasInvoked;

    /// <summary>Whether the invoked callback's presented certificate matched the mediator's pinned certificate byte-for-byte.</summary>
    public bool DidMatchPinnedCertificate => Pinning.DidMatchPinnedCertificate;


    /// <summary>Dials <paramref name="endpoint"/>, pinning TLS validation to <paramref name="pinnedCertificate"/> byte-for-byte.</summary>
    /// <param name="endpoint">The mediator's <c>wss://</c> endpoint.</param>
    /// <param name="pinnedCertificate">The exact certificate the mediator's listener presents.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The connected wallet.</returns>
    public static async Task<DidCommDuplexWalletConnection> ConnectAsync(Uri endpoint, X509Certificate2 pinnedCertificate, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentNullException.ThrowIfNull(pinnedCertificate);

        var client = new ClientWebSocket();
        var pinning = new WebSocketCertificatePinning(pinnedCertificate);
        client.Options.RemoteCertificateValidationCallback = pinning.Create();

        await client.ConnectAsync(endpoint, cancellationToken).ConfigureAwait(false);

        return new DidCommDuplexWalletConnection(client, pinning);
    }


    /// <summary>A <see cref="DidCommSessionSendDelegate"/> that sends over this connection as one complete TEXT frame.</summary>
    /// <returns>The send delegate.</returns>
    public DidCommSessionSendDelegate CreateSendDelegate()
    {
        return async (message, mediaType, cancellationToken) =>
        {
            try
            {
                await client.SendAsync(message, WebSocketMessageType.Text, endOfMessage: true, cancellationToken).ConfigureAwait(false);

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


    /// <summary>
    /// Sends one raw WebSocket frame of the caller-chosen <paramref name="messageType"/> — a test-only escape
    /// hatch from <see cref="CreateSendDelegate"/>'s fixed Text framing, used to exercise the seam's
    /// BINARY-TOLERANT-ACCEPT posture (<see cref="DidCommSessionInboundDelegate"/> remarks): the seam always
    /// SENDS text but must accept a peer that sends binary.
    /// </summary>
    /// <param name="message">The frame bytes to send.</param>
    /// <param name="messageType">The WebSocket frame type to send it as.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public ValueTask SendRawFrameAsync(ReadOnlyMemory<byte> message, WebSocketMessageType messageType, CancellationToken cancellationToken) =>
        client.SendAsync(message, messageType, endOfMessage: true, cancellationToken);


    /// <summary>Reads the next complete inbound frame from the mediator.</summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The frame type the peer sent it as, and its complete bytes.</returns>
    public Task<(WebSocketMessageType Type, byte[] Payload)> ReceiveFrameAsync(CancellationToken cancellationToken) =>
        DidCommDuplexFraming.ReceiveOneMessageAsync(client, cancellationToken);


    public async ValueTask DisposeAsync()
    {
        if(client.State == WebSocketState.Open)
        {
            try
            {
                //CloseOutputAsync, not CloseAsync: this connection may be torn down with no pump on either
                //side still reading (e.g. a test that connects, asserts, and disposes without ever driving a
                //receive loop) — CloseAsync's full closing handshake would block forever waiting for a
                //server-side close-frame echo that nothing is left to send. CloseOutputAsync sends this
                //side's close frame and returns without waiting for one back; the underlying connection is
                //torn down regardless once the host itself is disposed.
                await client.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, "test complete", CancellationToken.None).ConfigureAwait(false);
            }
            catch
            {
                //Best-effort close; the socket is being torn down regardless.
            }
        }

        client.Dispose();
    }
}
