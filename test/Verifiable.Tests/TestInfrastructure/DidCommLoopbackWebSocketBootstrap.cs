using System;
using System.Buffers;
using System.Linq;
using System.Net.Security;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// The one home for the loopback <c>wss://</c> Kestrel bootstrap and whole-message receive loop every
/// DIDComm WebSocket test fixture in this repository shares — <see cref="DidCommWebSocketInbox"/> (one
/// connection, one delivery, then closed) and the duplex pair in <c>DidCommDuplexWebSocketHarness.cs</c>
/// (a persistent, many-frame connection) both build their listener with <see cref="Build"/> and read frames
/// off it with <see cref="ReceiveMessageAsync"/>, so the Kestrel wiring and the WebSocket receive loop exist
/// exactly once.
/// </summary>
internal static class DidCommLoopbackWebSocketBootstrap
{
    /// <summary>
    /// Builds (but does not yet start) a Kestrel host bound to <c>wss://127.0.0.1:{port}</c> presenting
    /// the process-wide shared leaf certificate (<see cref="LoopbackTls.CreateServerCertificate"/>): a
    /// single explicit HTTPS <c>Listen</c> call, no <c>UseUrls</c>, so there is no plaintext fallback on
    /// the host at all.
    /// </summary>
    /// <param name="certificateSubjectName">
    /// Validated non-empty for call-site parity with <see cref="LoopbackTls.CreateDistinctServerCertificate"/>;
    /// the shared certificate's own subject was fixed when it was first minted, so this argument does not
    /// select the returned certificate's identity.
    /// </param>
    /// <returns>The built (not yet started) application and the certificate its listener presents.</returns>
    public static (WebApplication App, X509Certificate2 Certificate) Build(string certificateSubjectName)
    {
        X509Certificate2 certificate = LoopbackTls.CreateServerCertificate(certificateSubjectName);

        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();
        LoopbackKestrel.ConfigureLoopbackLogging(builder.Logging);

        builder.WebHost.ConfigureKestrel(options =>
            LoopbackKestrel.ConfigureLoopbackListener(options, certificate));

        WebApplication app = builder.Build();
        app.UseWebSockets();

        return (app, certificate);
    }


    /// <summary>
    /// Wires <paramref name="handleAsync"/> as the host's terminal request handler and starts it, returning
    /// the bound <c>wss://127.0.0.1:{port}/</c> endpoint. Split from <see cref="Build"/> because a handler
    /// commonly closes over the very object <see cref="Build"/>'s output constructs (the accepting host
    /// itself), so the app and certificate must exist before the handler can be built.
    /// </summary>
    /// <param name="app">The application <see cref="Build"/> returned.</param>
    /// <param name="handleAsync">The terminal WebSocket-accepting request handler.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The bound <c>wss://</c> endpoint.</returns>
    public static async Task<Uri> StartAsync(WebApplication app, RequestDelegate handleAsync, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentNullException.ThrowIfNull(handleAsync);

        app.Run(handleAsync);

        await app.StartAsync(cancellationToken).ConfigureAwait(false);

        IServerAddressesFeature addresses = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()
            ?? throw new InvalidOperationException("Kestrel exposed no server addresses feature.");
        string boundAddress = addresses.Addresses.FirstOrDefault()
            ?? throw new InvalidOperationException("Kestrel bound no address.");

        return new UriBuilder(boundAddress) { Scheme = "wss", Path = "/" }.Uri;
    }


    /// <summary>
    /// Reads one whole WebSocket message (all continuation frames to <see cref="ValueWebSocketReceiveResult.EndOfMessage"/>)
    /// into a byte array, surfacing the frame type the peer actually sent it as — Text or Binary — so a
    /// caller can pin the seam's own framing posture (DIDComm Messaging v2.1 §WebSockets: one complete
    /// message per frame) rather than discarding that information. A Close frame arriving before the
    /// message completes surfaces as a clear exception rather than an opaque one.
    /// </summary>
    /// <param name="socket">The open socket to read one message from.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The frame type the message arrived as, and its complete bytes.</returns>
    public static async Task<(WebSocketMessageType Type, byte[] Payload)> ReceiveMessageAsync(WebSocket socket, CancellationToken cancellationToken)
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


/// <summary>
/// A <see cref="RemoteCertificateValidationCallback"/> factory pinning TLS validation to one exact
/// certificate byte-for-byte rather than trusting a certificate authority — there is no CA in a loopback
/// test topology. Every <see cref="ClientWebSocket"/> dialing a <see cref="DidCommLoopbackWebSocketBootstrap"/>
/// listener in this repository uses the SAME pinning logic through <see cref="Create"/>; an instance also
/// records whether the callback ran at all and whether it matched, so a test can assert something only a
/// genuine TLS handshake produces rather than merely that a connection nominally succeeded.
/// </summary>
internal sealed class WebSocketCertificatePinning
{
    /// <summary>The exact certificate the loopback listener presents, pinned byte-for-byte.</summary>
    private X509Certificate2 PinnedCertificate { get; }


    /// <param name="pinnedCertificate">The exact certificate the loopback listener presents.</param>
    public WebSocketCertificatePinning(X509Certificate2 pinnedCertificate)
    {
        ArgumentNullException.ThrowIfNull(pinnedCertificate);

        this.PinnedCertificate = pinnedCertificate;
    }


    /// <summary>Whether the TLS handshake invoked this callback at all — <see langword="false"/> before a connection attempt runs.</summary>
    public bool WasInvoked { get; private set; }

    /// <summary>Whether the invoked callback's presented certificate matched <see cref="PinnedCertificate"/> byte-for-byte.</summary>
    public bool DidMatchPinnedCertificate { get; private set; }


    /// <summary>The callback delegate, wired onto <see cref="ClientWebSocketOptions.RemoteCertificateValidationCallback"/>.</summary>
    /// <returns>A callback that pins strictly to the constructor's certificate, never to <c>sslPolicyErrors</c>.</returns>
    public RemoteCertificateValidationCallback Create()
    {
        return (_, certificate, _, _) =>
        {
            WasInvoked = true;
            DidMatchPinnedCertificate = certificate is not null
                && CryptographicOperations.FixedTimeEquals(certificate.GetRawCertData(), PinnedCertificate.RawData);

            return DidMatchPinnedCertificate;
        };
    }
}
