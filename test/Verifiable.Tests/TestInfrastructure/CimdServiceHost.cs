using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
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

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// A test host for the non-normative Appendix A "CIMD Service" pattern
/// (draft-ietf-oauth-client-id-metadata-document-02 Appendix A, CIMD-062/063/064/065/066/067): a web
/// service through which developers acquire a stable Client Identifier URL that resolves to a Client
/// ID Metadata Document, without hosting one themselves.
/// </summary>
/// <remarks>
/// Same <see cref="LoopbackTls"/> + <see cref="WebApplication.CreateSlimBuilder()"/> + single
/// <c>Listen(...UseHttps(cert))</c> convention as <see cref="StaticContentHost"/>, specialised for CIMD
/// provisioning: <see cref="ProvisionClient"/> mints a fresh path under this host's base address, serves
/// a conformant Client ID Metadata Document there (200, <c>application/json</c>) whose <c>client_id</c>
/// is the minted URL's own <see cref="Uri.OriginalString"/> (CIMD-013/014/015), and expires the
/// provision at the injected <see cref="TimeProvider"/>'s instant (CIMD-065) — an expired or unknown
/// path answers 404, the minimal form of CIMD-067's "MUST return valid ... or a status code indicating
/// an error response". <paramref name="developerInfo"/> on <see cref="ProvisionClient"/> models
/// "MAY require developers to provide additional information about the client being developed"
/// (CIMD-066) and is merely recorded, readable back via <see cref="DeveloperInfo"/>.
/// </remarks>
internal sealed class CimdServiceHost: IAsyncDisposable
{
    private readonly WebApplication app;


    private CimdServiceHost(
        WebApplication app, X509Certificate2 certificate, Uri baseAddress, CimdServiceApplication application)
    {
        this.app = app;
        Certificate = certificate;
        BaseAddress = baseAddress;
        Application = application;
    }


    /// <summary>The loopback base address Kestrel bound (ephemeral port).</summary>
    public Uri BaseAddress { get; }

    /// <summary>The self-signed leaf certificate this host's HTTPS listener presents; callers pin to this via <see cref="LoopbackTls.CreatePinnedHttpClient(X509Certificate2, Uri?)"/>.</summary>
    public X509Certificate2 Certificate { get; }

    private CimdServiceApplication Application { get; }

    /// <summary>The total number of requests the host has served.</summary>
    public int TotalRequests => Application.TotalRequests;


    /// <summary>
    /// Whether the host has been asked for <paramref name="clientIdentifierUrl"/>'s path, proving the
    /// fetch crossed the socket.
    /// </summary>
    public bool WasRequested(Uri clientIdentifierUrl) => Application.WasRequested(clientIdentifierUrl.AbsolutePath);


    /// <summary>
    /// The developer-supplied information recorded for a prior <see cref="ProvisionClient"/> call
    /// (CIMD-066), or <see langword="null"/> when <paramref name="clientIdentifierUrl"/> was never
    /// provisioned or was provisioned with none.
    /// </summary>
    public string? DeveloperInfo(Uri clientIdentifierUrl) => Application.DeveloperInfo(clientIdentifierUrl.AbsolutePath);


    /// <summary>
    /// Provisions a fresh Client Identifier URL under this host and serves a conformant Client ID
    /// Metadata Document there — <c>client_id</c> is the minted URL itself (CIMD-013/014/015),
    /// <c>redirect_uris</c>/<c>token_endpoint_auth_method</c>/<c>jwks</c>/<c>client_name</c> are carried
    /// when supplied. The document is served only until <paramref name="lifetime"/> elapses, measured
    /// from this host's injected <see cref="TimeProvider"/> at call time; <see langword="null"/> never
    /// expires it (CIMD-065's "MAY expire clients from time to time" — expiry is opt-in per provision).
    /// </summary>
    /// <param name="redirectUris">The document's <c>redirect_uris</c>, or <see langword="null"/>/empty to omit the property.</param>
    /// <param name="tokenEndpointAuthMethod">The document's <c>token_endpoint_auth_method</c> wire value, or <see langword="null"/> to omit it.</param>
    /// <param name="jwksJson">The document's <c>jwks</c> value as raw JSON object text (embedded unquoted), or <see langword="null"/> to omit it.</param>
    /// <param name="clientName">The document's <c>client_name</c>, or <see langword="null"/> to omit it.</param>
    /// <param name="lifetime">How long the document remains servable from now, or <see langword="null"/> for no expiry.</param>
    /// <param name="developerInfo">Developer-supplied information about the client under development (CIMD-066), or <see langword="null"/> for none.</param>
    /// <returns>The minted Client Identifier URL, at which the document is now served.</returns>
    public Uri ProvisionClient(
        IReadOnlyList<Uri>? redirectUris = null,
        string? tokenEndpointAuthMethod = null,
        string? jwksJson = null,
        string? clientName = null,
        TimeSpan? lifetime = null,
        string? developerInfo = null)
    {
        string path = $"/cimd/{Guid.NewGuid():N}";
        Uri clientIdentifierUrl = new(BaseAddress, path);

        string documentJson = BuildDocumentJson(
            clientIdentifierUrl.OriginalString, redirectUris, tokenEndpointAuthMethod, jwksJson, clientName);
        DateTimeOffset? expiresAt = lifetime is { } ttl ? Application.TimeProvider.GetUtcNow() + ttl : null;

        Application.Provision(path, documentJson, expiresAt, developerInfo);

        return clientIdentifierUrl;
    }


    /// <summary>
    /// Starts a CIMD Service host on the IPv4 loopback socket with an OS-assigned ephemeral port.
    /// </summary>
    /// <param name="timeProvider">The clock <see cref="ProvisionClient"/> expiry is measured against — the pinned test clock, never the wall clock.</param>
    /// <param name="cancellationToken">A token to cancel the start.</param>
    public static async Task<CimdServiceHost> StartAsync(TimeProvider timeProvider, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);

        X509Certificate2 certificate = LoopbackTls.CreateServerCertificate("cimd-service-loopback-test-host");

        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();

        //A single explicit HTTPS Listen call — no UseUrls — so there is no plaintext fallback on
        //this host at all.
        builder.WebHost.ConfigureKestrel(options =>
            options.Listen(IPAddress.Loopback, port: 0, listenOptions => listenOptions.UseHttps(certificate)));

        WebApplication app = builder.Build();

        CimdServiceApplication application = new(timeProvider);
        app.Run(application.ProcessRequestAsync);

        await app.StartAsync(cancellationToken).ConfigureAwait(false);

        IServerAddressesFeature addresses = app.Services.GetRequiredService<IServer>()
            .Features.Get<IServerAddressesFeature>()
            ?? throw new InvalidOperationException("Kestrel exposed no server addresses feature.");
        string boundAddress = addresses.Addresses.FirstOrDefault()
            ?? throw new InvalidOperationException("Kestrel bound no address.");

        return new CimdServiceHost(app, certificate, new Uri(boundAddress), application);
    }


    /// <summary>Stops and disposes the host.</summary>
    public async ValueTask DisposeAsync()
    {
        await app.StopAsync(CancellationToken.None).ConfigureAwait(false);
        await app.DisposeAsync().ConfigureAwait(false);
        Certificate.Dispose();
    }


    //Builds a conformant Client ID Metadata Document (§4): client_id is REQUIRED (CIMD-013) and always
    //present; every other member is included only when the caller supplied it, so an omitted property
    //stays genuinely absent from the wire JSON rather than present as null. jwksJson is embedded
    //UNQUOTED — it is already a JSON object's text, mirroring PrivateKeyJwtClientAuthenticationTests'
    //BuildJwksJson convention for hand-built JWKS documents in this test suite.
    private static string BuildDocumentJson(
        string clientId,
        IReadOnlyList<Uri>? redirectUris,
        string? tokenEndpointAuthMethod,
        string? jwksJson,
        string? clientName)
    {
        List<string> members = [$"\"client_id\":\"{clientId}\""];

        if(redirectUris is { Count: > 0 })
        {
            string uris = string.Join(',', redirectUris.Select(static uri => $"\"{uri.OriginalString}\""));
            members.Add($"\"redirect_uris\":[{uris}]");
        }

        if(tokenEndpointAuthMethod is not null)
        {
            members.Add($"\"token_endpoint_auth_method\":\"{tokenEndpointAuthMethod}\"");
        }

        if(jwksJson is not null)
        {
            members.Add($"\"jwks\":{jwksJson}");
        }

        if(clientName is not null)
        {
            members.Add($"\"client_name\":\"{clientName}\"");
        }

        return "{" + string.Join(',', members) + "}";
    }


    /// <summary>
    /// The request-handler skin serving GET <c>{path}</c> from the provisioned-document map — mounted
    /// as the host pipeline's <c>RequestDelegate</c> via <c>app.Run(application.ProcessRequestAsync)</c>:
    /// 404 for an unknown or expired path (CIMD-065/067), 405 for a non-GET method. Every requested path
    /// is recorded so the cross-wire assertions can prove the socket was hit.
    /// </summary>
    private sealed class CimdServiceApplication
    {
        private readonly ConcurrentDictionary<string, ProvisionedDocument> provisions = new(StringComparer.Ordinal);
        private readonly ConcurrentDictionary<string, int> requestCounts = new(StringComparer.Ordinal);
        private int totalRequests;


        public CimdServiceApplication(TimeProvider timeProvider)
        {
            TimeProvider = timeProvider;
        }


        /// <summary>The clock provision expiry is measured against.</summary>
        public TimeProvider TimeProvider { get; }

        /// <summary>The total number of requests served.</summary>
        public int TotalRequests => Volatile.Read(ref totalRequests);


        /// <summary>Records a provisioned document, replacing any prior provision at the same path.</summary>
        public void Provision(string path, string documentJson, DateTimeOffset? expiresAt, string? developerInfo) =>
            provisions[path] = new ProvisionedDocument(documentJson, expiresAt, developerInfo);


        /// <summary>Whether a path was requested at least once.</summary>
        public bool WasRequested(string path) => requestCounts.ContainsKey(path);


        /// <summary>The developer-supplied information recorded for a provisioned path, or <see langword="null"/>.</summary>
        public string? DeveloperInfo(string path) =>
            provisions.TryGetValue(path, out ProvisionedDocument? provision) ? provision.DeveloperInfo : null;


        /// <summary>Serves a GET request from the provisioned-document map, recording the requested path.</summary>
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

            //Unknown path, OR a provision whose lifetime has elapsed per TimeProvider — both answer 404,
            //the CIMD-067 "or return a status code indicating an error response" branch. CIMD-065: this
            //service MAY expire clients from time to time; expiry is decided against the injected clock,
            //never DateTimeOffset.UtcNow.
            if(!provisions.TryGetValue(path, out ProvisionedDocument? provision)
                || (provision.ExpiresAt is { } expiresAt && TimeProvider.GetUtcNow() >= expiresAt))
            {
                httpResponse.StatusCode = StatusCodes.Status404NotFound;

                return;
            }

            httpResponse.StatusCode = StatusCodes.Status200OK;
            httpResponse.ContentType = "application/json";
            byte[] bodyBytes = Encoding.UTF8.GetBytes(provision.DocumentJson);
            await httpResponse.Body.WriteAsync(bodyBytes, context.RequestAborted).ConfigureAwait(false);
        }


        private sealed record ProvisionedDocument(string DocumentJson, DateTimeOffset? ExpiresAt, string? DeveloperInfo);
    }
}
