using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>A buffered view of one request received by <see cref="MinimalHttpHost"/>.</summary>
internal sealed record MinimalHttpRequest
{
    /// <summary>The request path (no query).</summary>
    public required string Path { get; init; }

    /// <summary>The HTTP method.</summary>
    public required string Method { get; init; }

    /// <summary>The <c>Content-Type</c> header, or <see langword="null"/> when absent.</summary>
    public string? ContentType { get; init; }

    /// <summary>The buffered UTF-8 request body; empty when there was none.</summary>
    public required string Body { get; init; }
}


/// <summary>The response a <see cref="MinimalHttpHandlerDelegate"/> produces.</summary>
internal sealed record MinimalHttpResponse
{
    /// <summary>The HTTP status code.</summary>
    public required int StatusCode { get; init; }

    /// <summary>The <c>Content-Type</c> for the body, when a body is present.</summary>
    public string? ContentType { get; init; }

    /// <summary>The UTF-8 response body, or <see langword="null"/> for an empty response.</summary>
    public string? Body { get; init; }
}


/// <summary>Handles one buffered HTTP request on a <see cref="MinimalHttpHost"/>.</summary>
internal delegate Task<MinimalHttpResponse> MinimalHttpHandlerDelegate(
    MinimalHttpRequest request, CancellationToken cancellationToken);


/// <summary>
/// A minimal in-process Kestrel host that routes every request to one
/// caller-supplied handler. Test glue for the protocol parties that are NOT the
/// authorization server — for example a Shared Signals Receiver's push endpoint
/// or a test Transmitter's poll endpoint — so end-to-end tests move real bytes
/// over a real socket without standing up a full server skin.
/// </summary>
internal sealed class MinimalHttpHost: IAsyncDisposable
{
    private readonly global::Microsoft.AspNetCore.Server.Kestrel.Core.KestrelServer kestrel;

    /// <summary>The loopback base address Kestrel bound (ephemeral port).</summary>
    public Uri BaseAddress { get; }


    private MinimalHttpHost(
        global::Microsoft.AspNetCore.Server.Kestrel.Core.KestrelServer kestrel, Uri baseAddress)
    {
        this.kestrel = kestrel;
        BaseAddress = baseAddress;
    }


    /// <summary>Starts a host on IPv4 loopback with an ephemeral port.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The returned MinimalHttpHost owns the Kestrel server and disposes it in DisposeAsync.")]
    public static async Task<MinimalHttpHost> StartAsync(
        MinimalHttpHandlerDelegate handler, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(handler);

        global::Microsoft.AspNetCore.Server.Kestrel.Core.KestrelServerOptions kestrelOptions = new();
        kestrelOptions.Listen(System.Net.IPAddress.Loopback, port: 0);

        global::Microsoft.AspNetCore.Server.Kestrel.Transport.Sockets.SocketTransportOptions socketOptions = new();
        global::Microsoft.AspNetCore.Server.Kestrel.Transport.Sockets.SocketTransportFactory socketFactory = new(
            global::Microsoft.Extensions.Options.Options.Create(socketOptions),
            global::Microsoft.Extensions.Logging.Abstractions.NullLoggerFactory.Instance);

        global::Microsoft.AspNetCore.Server.Kestrel.Core.KestrelServer kestrel = new(
            global::Microsoft.Extensions.Options.Options.Create(kestrelOptions),
            socketFactory,
            global::Microsoft.Extensions.Logging.Abstractions.NullLoggerFactory.Instance);

        DelegatedApplication application = new(handler);
        await kestrel.StartAsync(application, cancellationToken).ConfigureAwait(false);

        global::Microsoft.AspNetCore.Hosting.Server.Features.IServerAddressesFeature? addresses =
            kestrel.Features.Get<global::Microsoft.AspNetCore.Hosting.Server.Features.IServerAddressesFeature>();
        if(addresses is null || addresses.Addresses.Count == 0)
        {
            kestrel.Dispose();
            throw new InvalidOperationException("Kestrel started but exposed no server addresses.");
        }

        return new MinimalHttpHost(kestrel, new Uri(addresses.Addresses.First()));
    }


    public async ValueTask DisposeAsync()
    {
        await kestrel.StopAsync(CancellationToken.None).ConfigureAwait(false);
        kestrel.Dispose();
    }


    //Buffers each request and bridges it to the handler delegate; mirrors the
    //shape of AuthorizationServerHttpApplication without the dispatcher.
    private sealed class DelegatedApplication: IHttpApplication<HttpContext>
    {
        private readonly MinimalHttpHandlerDelegate handler;


        public DelegatedApplication(MinimalHttpHandlerDelegate handler)
        {
            this.handler = handler;
        }


        public HttpContext CreateContext(IFeatureCollection contextFeatures) =>
            new DefaultHttpContext(contextFeatures);


        public async Task ProcessRequestAsync(HttpContext context)
        {
            string body;
            using(MemoryStream buffer = new())
            {
                await context.Request.Body.CopyToAsync(buffer, context.RequestAborted).ConfigureAwait(false);
                body = Encoding.UTF8.GetString(buffer.ToArray());
            }

            MinimalHttpResponse response = await handler(
                new MinimalHttpRequest
                {
                    Path = context.Request.Path.HasValue ? context.Request.Path.Value! : string.Empty,
                    Method = context.Request.Method,
                    ContentType = context.Request.ContentType,
                    Body = body
                },
                context.RequestAborted).ConfigureAwait(false);

            context.Response.StatusCode = response.StatusCode;
            if(!string.IsNullOrEmpty(response.Body))
            {
                if(!string.IsNullOrEmpty(response.ContentType))
                {
                    context.Response.ContentType = response.ContentType;
                }

                byte[] bytes = Encoding.UTF8.GetBytes(response.Body);
                await context.Response.Body.WriteAsync(bytes, context.RequestAborted).ConfigureAwait(false);
            }
        }


        public void DisposeContext(HttpContext context, Exception? exception) { }
    }
}
