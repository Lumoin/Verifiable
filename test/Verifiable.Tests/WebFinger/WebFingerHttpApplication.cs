using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using StringValues = Microsoft.Extensions.Primitives.StringValues;
using Verifiable.Core;
using Verifiable.Server.Pipeline;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.WebFinger;

namespace Verifiable.Tests.WebFinger;

/// <summary>
/// Bridges Kestrel to <see cref="EndpointServer.DispatchAsync"/> for the
/// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4">RFC 7033 §4</see>
/// <c>GET /.well-known/webfinger</c> endpoint — the test-only Node A skin the firewalled cross-wire
/// flow (<see cref="WebFingerCrossWireFlowTests"/>) hosts over a real HTTPS loopback socket, mirroring
/// <c>AuthorizationServerHttpApplication</c> (the OAuth family's equivalent skin) at the request-mapping
/// level. WebFinger carries no tenant path segment and the query endpoint takes no request body, so this
/// skin is considerably smaller: every GET maps to the one well-known path, and the per-request bridge is
/// a query-string read plus a dispatch call.
/// </summary>
/// <remarks>
/// <para>
/// This type does triple duty, matching the file budget of this conformance slice: it is (1) the
/// request-mapping skin itself (<see cref="ProcessRequestAsync"/>, matching a <c>RequestDelegate</c>),
/// (2) the <see cref="BuildServer"/> factory that wires a fully-validated <see cref="EndpointServer"/>
/// around <see cref="WebFingerEndpoints.Builder"/> with a plain, OAuth-free <see cref="IRegistrationRecord"/>
/// (used directly — dispatch only, no Kestrel — by <c>WebFingerServerResponseTests</c>), and (3) the
/// nested <see cref="Host"/> that starts that server on a real HTTPS loopback listener with a fresh
/// self-signed leaf certificate (used by the cross-wire flow).
/// </para>
/// <para>
/// <see cref="Host"/> hosts through <see cref="WebApplication.CreateSlimBuilder()"/> rather than a raw
/// <c>KestrelServer</c>: enabling HTTPS on a listen endpoint
/// (<c>ListenOptionsHttpsExtensions.UseHttps</c>) resolves an internal <c>IHttpsConfigurationService</c>
/// off <c>KestrelServerOptions.ApplicationServices</c>, which only the generic-host bootstrap wires up —
/// the same proven pattern the DIDComm WebSocket test inbox uses for its own real Kestrel listener.
/// </para>
/// </remarks>
[DebuggerDisplay("WebFingerHttpApplication")]
internal sealed class WebFingerHttpApplication
{
    private readonly EndpointServer server;
    private readonly ConcurrentQueue<string> requestLog = new();


    /// <summary>Wraps <paramref name="server"/> so Kestrel dispatches every inbound request through it.</summary>
    /// <param name="server">A fully-validated <see cref="EndpointServer"/>, typically built by <see cref="BuildServer"/>.</param>
    public WebFingerHttpApplication(EndpointServer server)
    {
        ArgumentNullException.ThrowIfNull(server);
        this.server = server;
    }


    /// <summary>Every request path+query string this application has dispatched, in arrival order.</summary>
    public IReadOnlyCollection<string> RequestLog => requestLog;


    /// <summary>
    /// Maps the inbound Kestrel request to <see cref="IncomingRequest"/>, dispatches it through the
    /// real <see cref="EndpointServer.DispatchAsync"/> — the shipped path, never a hand-called
    /// <c>BuildInputAsync</c> — and maps the resulting <see cref="ServerHttpResponse"/> back onto the
    /// wire. Records the served path+query so cross-wire assertions can prove a request actually
    /// crossed the socket.
    /// </summary>
    public async Task ProcessRequestAsync(HttpContext context)
    {
        string path = context.Request.Path.HasValue ? context.Request.Path.Value! : string.Empty;
        string queryString = context.Request.QueryString.HasValue ? context.Request.QueryString.Value! : string.Empty;
        requestLog.Enqueue(path + queryString);

        IncomingRequest incomingRequest = BuildIncomingRequest(context.Request);
        ExchangeContext exchangeContext = new();

        ServerHttpResponse response = await server.DispatchAsync(
            incomingRequest, exchangeContext, context.RequestAborted).ConfigureAwait(false);

        await WriteResponseAsync(response, context.Response, context.RequestAborted).ConfigureAwait(false);
    }


    /// <summary>Maps a Kestrel <see cref="HttpRequest"/> to the library's <see cref="IncomingRequest"/>. Every WebFinger query is a bodyless GET, so only the query string and headers carry input.</summary>
    private static IncomingRequest BuildIncomingRequest(HttpRequest request)
    {
        RequestFields fields = new();
        foreach(KeyValuePair<string, StringValues> query in request.Query)
        {
            foreach(string? value in query.Value)
            {
                if(value is not null)
                {
                    fields.Add(query.Key, value);
                }
            }
        }

        RequestHeaders headers = MapHeaders(request.Headers);

        return new IncomingRequest(
            Path: request.Path.HasValue ? request.Path.Value! : string.Empty,
            Method: request.Method,
            Fields: fields,
            Headers: headers,
            RouteValues: RouteValues.Empty);
    }


    /// <summary>Writes a <see cref="ServerHttpResponse"/> onto the Kestrel response — status, content type, headers (including the §5 CORS header), and body.</summary>
    private static async ValueTask WriteResponseAsync(
        ServerHttpResponse response, HttpResponse httpResponse, CancellationToken cancellationToken)
    {
        httpResponse.StatusCode = response.StatusCode;

        if(!string.IsNullOrEmpty(response.ContentType))
        {
            httpResponse.ContentType = response.ContentType;
        }

        foreach(KeyValuePair<string, string> header in response.Headers)
        {
            httpResponse.Headers.Append(header.Key, header.Value);
        }

        if(!string.IsNullOrEmpty(response.Body))
        {
            byte[] bodyBytes = Encoding.UTF8.GetBytes(response.Body);
            await httpResponse.Body.WriteAsync(bodyBytes, cancellationToken).ConfigureAwait(false);
        }
    }


    /// <summary>Maps Kestrel's case-insensitive header dictionary to <see cref="RequestHeaders"/>.</summary>
    private static RequestHeaders MapHeaders(IHeaderDictionary source)
    {
        Dictionary<string, string[]> mapped = new(source.Count, StringComparer.OrdinalIgnoreCase);
        foreach(KeyValuePair<string, StringValues> entry in source)
        {
            mapped[entry.Key] = entry.Value.ToArray()!;
        }

        return new RequestHeaders(mapped);
    }


    /// <summary>
    /// Builds a fully-validated <see cref="EndpointServer"/> serving only the WebFinger query endpoint,
    /// with a single plain <see cref="IRegistrationRecord"/> registration carrying
    /// <see cref="WellKnownWebFingerCapabilityIdentifiers.Endpoint"/> — no OAuth vocabulary anywhere in
    /// the wiring, per the family's OAuth independence. Used directly (dispatch only, no Kestrel) by
    /// the server-response conformance tests, and wrapped in a real HTTPS loopback listener by
    /// <see cref="Host.StartAsync"/> for the cross-wire flow.
    /// </summary>
    /// <param name="resolveResource">The application's REQUIRED WebFinger resource resolver.</param>
    /// <param name="resolveCorsOrigin">
    /// The OPTIONAL §5 CORS origin resolver; when <see langword="null"/> every response falls back to
    /// the library's <c>*</c> wildcard default.
    /// </param>
    public static EndpointServer BuildServer(
        ResolveWebFingerResourceDelegate resolveResource,
        ResolveCorsOriginDelegate? resolveCorsOrigin = null)
    {
        ArgumentNullException.ThrowIfNull(resolveResource);

        PlainRegistration registration = new()
        {
            ClientId = "webfinger-test-node",
            TenantId = new TenantId("webfinger-test-tenant"),
            AllowedCapabilities = new HashSet<CapabilityIdentifier> { WellKnownWebFingerCapabilityIdentifiers.Endpoint }
        };

        //The endpoint matcher compares only PathEquals.Equals(req.Path, endpoint.ResolvedUri.AbsolutePath);
        //the authority is never consulted, so a fixed dummy authority suffices for both the in-process
        //dispatch tests and the Kestrel-hosted node.
        Uri resolvedEndpointUri = new($"https://webfinger.test{WellKnownWebFingerValues.WellKnownPath}");

        ServerIntegration integration = new()
        {
            ExtractTenantIdAsync = (ctx, ct) => ValueTask.FromResult<TenantId?>(registration.TenantId),
            LoadRegistrationAsync = (tenantId, ctx, ct) => ValueTask.FromResult<IRegistrationRecord?>(registration),

            //The WebFinger query endpoint is StatelessFlowKind.Instance: EndpointServer.HandleCoreAsync
            //short-circuits on BuildInputAsync's response before any flow-state or identifier seam is
            //reached. These three are wired only to satisfy ServerIntegration.Validate() and are never
            //actually invoked by a WebFinger dispatch.
            SaveFlowStateAsync = static (tenantId, key, state, stepCount, ctx, ct) => ValueTask.CompletedTask,
            LoadFlowStateAsync = static (tenantId, key, ctx, ct) => ValueTask.FromResult<(FlowState?, int)>((null, 0)),
            GenerateIdentifierAsync = static (purpose, ctx, ct) => ValueTask.FromResult(Guid.NewGuid().ToString("N")),

            ResolvePolicyAsync = static (reg, ctx, ct) => ValueTask.CompletedTask,
            ResolveCapabilitiesAsync = DefaultCapabilityResolver.ResolveAsync,
            InspectAsync = DefaultInspector.NoOpAsync,

            ResolveEndpointUriAsync = (endpointKey, reg, ctx, ct) => ValueTask.FromResult(
                string.Equals(endpointKey, WellKnownWebFingerEndpointNames.WebFinger, StringComparison.Ordinal)
                    ? resolvedEndpointUri
                    : null)
        };

        EndpointServer server = new()
        {
            Integration = integration,
            Configuration = new ServerConfiguration
            {
                EndpointBuilders = new EndpointBuilderSet([WebFingerEndpoints.Builder])
            }
        };

        server.AddIntegration(new WebFingerIntegration
        {
            ResolveWebFingerResourceAsync = resolveResource,
            ResolveCorsOriginAsync = resolveCorsOrigin
        });

        server.Validate();

        return server;
    }


    /// <summary>A minimal <see cref="IRegistrationRecord"/> carrying only the host-generic projection the dispatcher reads — no OAuth vocabulary.</summary>
    private sealed record PlainRegistration: IRegistrationRecord
    {
        /// <summary>The stable client identifier surfaced on dispatch telemetry.</summary>
        public required string ClientId { get; init; }

        /// <summary>The tenant this registration belongs to.</summary>
        public required TenantId TenantId { get; init; }

        /// <summary>The capabilities this registration is allowed to exercise.</summary>
        public required IReadOnlySet<CapabilityIdentifier> AllowedCapabilities { get; init; }
    }


    /// <summary>
    /// Node A: a real Kestrel listener bound to an HTTPS loopback socket with a fresh self-signed leaf
    /// certificate, serving <see cref="EndpointServer.DispatchAsync"/> through the enclosing
    /// <see cref="WebFingerHttpApplication"/>. Every request path+query is recorded so the cross-wire
    /// flow can prove a request actually crossed the socket. Per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-9.1">RFC 7033 §9.1</see> and the
    /// method's HTTPS-only construction (a single explicit <c>Listen</c> call, no plaintext <c>UseUrls</c>),
    /// there is no plaintext HTTP listener on this node at all.
    /// </summary>
    internal sealed class Host: IAsyncDisposable
    {
        private readonly WebApplication app;
        private readonly WebFingerHttpApplication application;


        private Host(WebApplication app, WebFingerHttpApplication application, Uri baseAddress, X509Certificate2 certificate)
        {
            this.app = app;
            this.application = application;
            BaseAddress = baseAddress;
            Certificate = certificate;
        }


        /// <summary>The node's real loopback base address, e.g. <c>https://127.0.0.1:{port}</c>.</summary>
        public Uri BaseAddress { get; }

        /// <summary>
        /// The self-signed leaf certificate this node's HTTPS listener presents. Node B validates the
        /// TLS connection by pinning to this exact certificate (RFC 7033 §9.1 — verify, never bypass)
        /// rather than trusting a CA: there is no CA in this loopback test topology, and the client
        /// never disables certificate validation.
        /// </summary>
        public X509Certificate2 Certificate { get; }

        /// <summary>The number of requests this node has served.</summary>
        public int TotalRequests => application.RequestLog.Count;


        /// <summary>Whether any served request's path+query contains <paramref name="substring"/> — used to prove a query actually crossed the socket.</summary>
        public bool WasRequestedWithQueryContaining(string substring)
        {
            foreach(string entry in application.RequestLog)
            {
                if(entry.Contains(substring, StringComparison.Ordinal))
                {
                    return true;
                }
            }

            return false;
        }


        /// <summary>Starts Node A on an OS-assigned loopback HTTPS port, serving <paramref name="server"/>.</summary>
        /// <param name="server">A fully-validated <see cref="EndpointServer"/>, typically built by <see cref="BuildServer"/>.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        public static async Task<Host> StartAsync(EndpointServer server, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(server);

            X509Certificate2 certificate = CreateLoopbackTestCertificate();

            WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();
            builder.Logging.ClearProviders();

            //A single explicit HTTPS Listen call — no UseUrls, so this is the ONLY endpoint Kestrel
            //binds: there is no plaintext HTTP fallback on this node at all.
            builder.WebHost.ConfigureKestrel(options =>
                options.Listen(IPAddress.Loopback, port: 0, listenOptions => listenOptions.UseHttps(certificate)));

            WebApplication app = builder.Build();

            WebFingerHttpApplication application = new(server);
            app.Run(application.ProcessRequestAsync);

            await app.StartAsync(cancellationToken).ConfigureAwait(false);

            IServerAddressesFeature addresses = app.Services.GetRequiredService<IServer>()
                .Features.Get<IServerAddressesFeature>()
                ?? throw new InvalidOperationException("Kestrel exposed no server addresses feature.");
            string boundAddress = addresses.Addresses.FirstOrDefault()
                ?? throw new InvalidOperationException("Kestrel bound no address.");

            return new Host(app, application, new Uri(boundAddress), certificate);
        }


        /// <summary>
        /// Mints a fresh, minimal self-signed leaf certificate for the loopback TLS listener. No CA
        /// chain is minted because this topology's client pins the leaf directly (RFC 7033 §9.1) rather
        /// than validating a chain to a trust anchor.
        /// </summary>
        /// <remarks>
        /// <see cref="CertificateRequest.CreateSelfSigned"/> returns a certificate whose private key is
        /// an EPHEMERAL, in-memory CNG key — sufficient for chain/PKI assertions elsewhere in this
        /// repository, but the platform TLS stack refuses to use an ephemeral key as a SERVER
        /// credential ("the platform does not support ephemeral keys"). Round-tripping through a
        /// PKCS#12 export/reload gives the certificate a persisted key container Kestrel's
        /// <c>SslStream</c> server authentication can actually use.
        /// </remarks>
        private static X509Certificate2 CreateLoopbackTestCertificate()
        {
            //Cert-factory carve-out: CertificateRequest requires a framework AsymmetricAlgorithm
            //to sign the self-signed leaf certificate; this key is never converted to library
            //PrivateKeyMemory, so it stays framework-native for its whole lifetime.
            using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            CertificateRequest request = new("CN=webfinger-loopback-test-node", key, HashAlgorithmName.SHA256);

            SubjectAlternativeNameBuilder sanBuilder = new();
            sanBuilder.AddDnsName("localhost");
            sanBuilder.AddIpAddress(IPAddress.Loopback);
            request.CertificateExtensions.Add(sanBuilder.Build(critical: false));

            request.CertificateExtensions.Add(
                new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, critical: true));

            OidCollection serverAuthEku = new() { new Oid("1.3.6.1.5.5.7.3.1") };
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(serverAuthEku, critical: false));

            DateTimeOffset now = TestClock.CanonicalEpoch;

            using X509Certificate2 ephemeral = request.CreateSelfSigned(now.AddMinutes(-5), now.AddDays(1));
            byte[] pfxBytes = ephemeral.Export(X509ContentType.Pfx);

            return X509CertificateLoader.LoadPkcs12(pfxBytes, password: null, X509KeyStorageFlags.Exportable);
        }


        /// <inheritdoc/>
        public async ValueTask DisposeAsync()
        {
            await app.StopAsync(CancellationToken.None).ConfigureAwait(false);
            await app.DisposeAsync().ConfigureAwait(false);
            Certificate.Dispose();
        }
    }
}
