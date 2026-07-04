using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Transport.Sockets;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// A reusable in-process Kestrel listener bound to the IPv4 loopback socket on an OS-assigned ephemeral port that
/// serves published static content by path and records every requested path, so an end-to-end test can prove a hop
/// crossed the wire. This is the party-server primitive a multi-server, over-the-wire flow test stands up for each
/// firewalled party (for example an ACDC Issuer that publishes its KEL, its credential, and its registry, or a DID
/// publisher node) — bytes move over a real socket, and the verifier reconstructs only from what it fetched.
/// </summary>
/// <remarks>
/// Modeled on the proven publisher-node shape used by the did:webvh cross-wire flow test: a raw
/// <see cref="KestrelServer"/> plus a hand-written <see cref="IHttpApplication{TContext}"/> skin (the test projects
/// never use a full server stack), serving GET requests from a published-content map, 404 for an unknown path and
/// 405 for a non-GET method, with per-path request counts the firewall assertions read.
/// </remarks>
internal sealed class StaticContentHost: IAsyncDisposable
{
    private readonly KestrelServer server;


    private StaticContentHost(KestrelServer server, Uri baseAddress, StaticContentApplication application)
    {
        this.server = server;
        BaseAddress = baseAddress;
        Application = application;
    }


    /// <summary>The loopback base address Kestrel bound (ephemeral port).</summary>
    public Uri BaseAddress { get; }

    private StaticContentApplication Application { get; }

    /// <summary>The total number of requests the host has served.</summary>
    public int TotalRequests => Application.TotalRequests;


    /// <summary>
    /// Publishes content to be served at a path. The host copies the bytes into the HTTP body it owns, so the
    /// caller's buffer (which may be pooled) need not outlive this call.
    /// </summary>
    /// <param name="path">The request path (for example <c>/kel</c>).</param>
    /// <param name="body">The bytes served at the path.</param>
    /// <param name="contentType">The content type the path is served with.</param>
    public void Publish(string path, ReadOnlyMemory<byte> body, string contentType) => Application.Publish(path, body, contentType);


    /// <summary>
    /// Whether the host has been asked for a path, proving the fetch crossed the socket.
    /// </summary>
    /// <param name="path">The request path to test.</param>
    /// <returns><see langword="true"/> when the path was requested at least once.</returns>
    public bool WasRequested(string path) => Application.WasRequested(path);


    /// <summary>
    /// Starts a host on the IPv4 loopback socket with an OS-assigned ephemeral port.
    /// </summary>
    /// <param name="cancellationToken">A token to cancel the start.</param>
    /// <returns>The started host.</returns>
    public static async Task<StaticContentHost> StartAsync(CancellationToken cancellationToken)
    {
        KestrelServerOptions kestrelOptions = new();
        kestrelOptions.Listen(IPAddress.Loopback, port: 0);

        SocketTransportOptions socketOptions = new();
        SocketTransportFactory socketFactory = new(Options.Create(socketOptions), NullLoggerFactory.Instance);

        KestrelServer kestrel = new(Options.Create(kestrelOptions), socketFactory, NullLoggerFactory.Instance);
        StaticContentApplication application = new();
        await kestrel.StartAsync(application, cancellationToken).ConfigureAwait(false);

        IServerAddressesFeature? addresses = kestrel.Features.Get<IServerAddressesFeature>();
        if(addresses is null || addresses.Addresses.Count == 0)
        {
            kestrel.Dispose();
            throw new InvalidOperationException("Kestrel started but exposed no server address.");
        }

        return new StaticContentHost(kestrel, new Uri(addresses.Addresses.First()), application);
    }


    /// <summary>Stops and disposes the host.</summary>
    public async ValueTask DisposeAsync()
    {
        await server.StopAsync(CancellationToken.None).ConfigureAwait(false);
        server.Dispose();
    }


    /// <summary>
    /// The <see cref="IHttpApplication{TContext}"/> skin serving GET <c>{path}</c> from a published-content map: 404
    /// for an unknown path, 405 for a non-GET method. Every requested path is recorded so the cross-wire assertions
    /// can prove the socket was hit.
    /// </summary>
    private sealed class StaticContentApplication: IHttpApplication<HttpContext>
    {
        private readonly ConcurrentDictionary<string, (byte[] Body, string ContentType)> content = new(StringComparer.Ordinal);
        private readonly ConcurrentDictionary<string, int> requestCounts = new(StringComparer.Ordinal);
        private int totalRequests;


        /// <summary>The total number of requests served.</summary>
        public int TotalRequests => Volatile.Read(ref totalRequests);


        /// <summary>Publishes content at a path, copying the bytes into the HTTP body the host owns.</summary>
        /// <param name="path">The request path.</param>
        /// <param name="body">The bytes to serve.</param>
        /// <param name="contentType">The content type.</param>
        public void Publish(string path, ReadOnlyMemory<byte> body, string contentType)
        {
            content[path] = (body.ToArray(), contentType);
        }


        /// <summary>Whether a path was requested at least once.</summary>
        /// <param name="path">The request path to test.</param>
        /// <returns><see langword="true"/> when the path was requested.</returns>
        public bool WasRequested(string path) => requestCounts.ContainsKey(path);


        /// <summary>Creates the per-request context.</summary>
        /// <param name="contextFeatures">The request features.</param>
        /// <returns>The HTTP context.</returns>
        public HttpContext CreateContext(IFeatureCollection contextFeatures) => new DefaultHttpContext(contextFeatures);


        /// <summary>Serves a GET request from the published-content map, recording the requested path.</summary>
        /// <param name="context">The HTTP context.</param>
        /// <returns>A task that completes when the response is written.</returns>
        public async Task ProcessRequestAsync(HttpContext context)
        {
            HttpResponse httpResponse = context.Response;
            string path = context.Request.Path.HasValue ? context.Request.Path.Value! : string.Empty;

            Interlocked.Increment(ref totalRequests);
            requestCounts.AddOrUpdate(path, 1, static (_, count) => count + 1);

            if(!HttpMethods.IsGet(context.Request.Method))
            {
                httpResponse.StatusCode = StatusCodes.Status405MethodNotAllowed;

                return;
            }

            if(!content.TryGetValue(path, out (byte[] Body, string ContentType) served))
            {
                httpResponse.StatusCode = StatusCodes.Status404NotFound;

                return;
            }

            httpResponse.StatusCode = StatusCodes.Status200OK;
            httpResponse.ContentType = served.ContentType;
            await httpResponse.Body.WriteAsync(served.Body, context.RequestAborted).ConfigureAwait(false);
        }


        /// <summary>Disposes the per-request context.</summary>
        /// <param name="context">The HTTP context.</param>
        /// <param name="exception">The exception that aborted the request, if any.</param>
        public void DisposeContext(HttpContext context, Exception? exception) { }
    }
}
