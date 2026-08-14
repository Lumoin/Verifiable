using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>A buffered view of one request received by <see cref="BinaryHttpHost"/>.</summary>
internal sealed record BinaryHttpRequest
{
    /// <summary>The request path (no query).</summary>
    public required string Path { get; init; }

    /// <summary>The HTTP method.</summary>
    public required string Method { get; init; }

    /// <summary>The <c>Content-Type</c> header, or <see langword="null"/> when absent.</summary>
    public string? ContentType { get; init; }

    /// <summary>The buffered raw request body octets; empty when there was none.</summary>
    public required byte[] Body { get; init; }
}


/// <summary>The response a <see cref="BinaryHttpHandlerDelegate"/> produces.</summary>
internal sealed record BinaryHttpResponse
{
    /// <summary>The HTTP status code.</summary>
    public required int StatusCode { get; init; }

    /// <summary>The <c>Content-Type</c> for the body, when a body is present.</summary>
    public string? ContentType { get; init; }

    /// <summary>The raw response body octets, or <see langword="null"/> for an empty response.</summary>
    public byte[]? Body { get; init; }

    /// <summary>
    /// Additional response headers (for example <c>Cache-Control</c> or <c>Location</c>), written
    /// before the body. <see langword="null"/> or empty adds no headers beyond <see cref="ContentType"/>.
    /// </summary>
    public IReadOnlyDictionary<string, string>? Headers { get; init; }
}


/// <summary>Handles one buffered HTTP request on a <see cref="BinaryHttpHost"/>.</summary>
internal delegate Task<BinaryHttpResponse> BinaryHttpHandlerDelegate(
    BinaryHttpRequest request, CancellationToken cancellationToken);


/// <summary>
/// A minimal in-process HTTPS host that routes every request to one caller-supplied handler over a real
/// loopback socket, carrying the request and response bodies as raw octets rather than UTF-8 text — the
/// binary-body sibling of <see cref="MinimalHttpHost"/>, for protocols whose wire bodies are DER (RFC 3161
/// §3.4's <c>TimeStampReq</c>/<c>TimeStampResp</c>, RFC 6960 Appendix A's <c>OCSPRequest</c>/<c>OCSPResponse</c>)
/// rather than text a UTF-8 round trip could silently distort. Test glue for the protocol party on the OTHER
/// end of a caller-supplied transport delegate — a Time-Stamping Authority or an OCSP responder — so an
/// end-to-end test moves real DER bytes over a real socket without standing up a full server skin.
/// </summary>
/// <remarks>
/// Binds through <see cref="WebApplication.CreateSlimBuilder()"/> with a single explicit
/// <see cref="Microsoft.AspNetCore.Hosting.ListenOptionsHttpsExtensions.UseHttps(Microsoft.AspNetCore.Server.Kestrel.Core.ListenOptions, X509Certificate2)"/>
/// listen call presenting <see cref="Certificate"/> — the same generic-host bootstrap
/// <see cref="MinimalHttpHost"/> uses, so there is no plaintext fallback on this host at all. Callers pin their
/// <see cref="System.Net.Http.HttpClient"/> to <see cref="Certificate"/> via
/// <see cref="LoopbackTls.CreatePinnedHttpClient"/>.
/// </remarks>
internal sealed class BinaryHttpHost: IAsyncDisposable
{
    private readonly WebApplication app;

    /// <summary>The loopback base address Kestrel bound (ephemeral port).</summary>
    public Uri BaseAddress { get; }

    /// <summary>The self-signed leaf certificate this host's HTTPS listener presents; callers pin to this via <see cref="LoopbackTls.CreatePinnedHttpClient"/>.</summary>
    internal X509Certificate2 Certificate { get; }


    private BinaryHttpHost(WebApplication app, Uri baseAddress, X509Certificate2 certificate)
    {
        this.app = app;
        BaseAddress = baseAddress;
        Certificate = certificate;
    }


    /// <summary>Starts a host on IPv4 loopback HTTPS with an ephemeral port.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The returned BinaryHttpHost owns the WebApplication and certificate and disposes both in DisposeAsync.")]
    public static async Task<BinaryHttpHost> StartAsync(
        BinaryHttpHandlerDelegate handler, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(handler);

        X509Certificate2 certificate = LoopbackTls.CreateServerCertificate("binary-loopback-test-host");

        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();

        //A single explicit HTTPS Listen call — no UseUrls — so there is no plaintext fallback on
        //this host at all.
        builder.WebHost.ConfigureKestrel(options =>
            options.Listen(IPAddress.Loopback, port: 0, listenOptions => listenOptions.UseHttps(certificate)));

        WebApplication app = builder.Build();

        DelegatedApplication application = new(handler);
        app.Run(application.ProcessRequestAsync);

        await app.StartAsync(cancellationToken).ConfigureAwait(false);

        IServerAddressesFeature addresses = app.Services.GetRequiredService<IServer>()
            .Features.Get<IServerAddressesFeature>()
            ?? throw new InvalidOperationException("Kestrel exposed no server addresses feature.");
        string boundAddress = addresses.Addresses.FirstOrDefault()
            ?? throw new InvalidOperationException("Kestrel bound no address.");

        return new BinaryHttpHost(app, new Uri(boundAddress), certificate);
    }


    public async ValueTask DisposeAsync()
    {
        await app.StopAsync(CancellationToken.None).ConfigureAwait(false);
        await app.DisposeAsync().ConfigureAwait(false);
        Certificate.Dispose();
    }


    //Buffers each request's raw octets and bridges it to the handler delegate; mirrors MinimalHttpHost's own
    //DelegatedApplication, with no UTF-8 encode/decode step on either side of the body.
    private sealed class DelegatedApplication
    {
        private readonly BinaryHttpHandlerDelegate handler;


        public DelegatedApplication(BinaryHttpHandlerDelegate handler)
        {
            this.handler = handler;
        }


        public async Task ProcessRequestAsync(HttpContext context)
        {
            byte[] body;
            using(MemoryStream buffer = new())
            {
                await context.Request.Body.CopyToAsync(buffer, context.RequestAborted).ConfigureAwait(false);
                body = buffer.ToArray();
            }

            BinaryHttpResponse response = await handler(
                new BinaryHttpRequest
                {
                    Path = context.Request.Path.HasValue ? context.Request.Path.Value! : string.Empty,
                    Method = context.Request.Method,
                    ContentType = context.Request.ContentType,
                    Body = body
                },
                context.RequestAborted).ConfigureAwait(false);

            context.Response.StatusCode = response.StatusCode;
            if(response.Headers is not null)
            {
                foreach(KeyValuePair<string, string> header in response.Headers)
                {
                    context.Response.Headers[header.Key] = header.Value;
                }
            }

            if(response.Body is { Length: > 0 } responseBody)
            {
                if(!string.IsNullOrEmpty(response.ContentType))
                {
                    context.Response.ContentType = response.ContentType;
                }

                await context.Response.Body.WriteAsync(responseBody, context.RequestAborted).ConfigureAwait(false);
            }
        }
    }
}
