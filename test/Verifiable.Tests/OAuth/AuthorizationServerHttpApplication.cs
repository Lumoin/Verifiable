using Microsoft.AspNetCore.Http;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Diagnostics;
using System.IO.Pipelines;
using System.Text;
using Verifiable.Core;
using Verifiable.JCose;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Registration;
using StringValues = Microsoft.Extensions.Primitives.StringValues;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Bridges a <c>Microsoft.AspNetCore.Builder.WebApplication</c>'s HTTPS pipeline to
/// <see cref="EndpointServer.DispatchAsync"/>. <see cref="ProcessRequestAsync"/> is mounted directly as
/// the pipeline's <c>RequestDelegate</c> (<c>app.Run(application.ProcessRequestAsync)</c>): it maps
/// inbound HTTP requests to the library's <see cref="IncomingRequest"/> and
/// <see cref="ExchangeContext"/>, and maps the outbound <see cref="ServerHttpResponse"/> back to HTTP
/// response bytes.
/// </summary>
/// <remarks>
/// <para>
/// Test-only construct. The library itself does not reference Kestrel or ASP.NET Core. A production
/// deployment writes its own host adapter; the shape of this mapping layer is a useful reference but
/// not part of the library's public surface.
/// </para>
/// <para>
/// Three behaviours worth flagging for any reader:
/// </para>
/// <list type="bullet">
///   <item><description>
///   Body bytes are buffered in full before dispatch — OAuth bodies are
///   tiny (form-encoded fields, short JSON registration metadata) and
///   buffering keeps the mapping straightforward. A streaming adapter
///   would be a separate type when a flow ever requires it.
///   </description></item>
///   <item><description>
///   Tenant identification is pre-resolved from the path prefix
///   (<c>/connect/{segment}/...</c>) and stamped onto
///   <see cref="ExchangeContext"/> via <c>ExchangeContextExtensions.SetTenantId</c>
///   before dispatch. The dispatcher's <see cref="Verifiable.Server.ServerIntegration.ExtractTenantIdAsync"/>
///   then short-circuits on the pre-set value, matching what the
///   in-process transport does.
///   </description></item>
///   <item><description>
///   Diagnostic accessors on the test fixture (e.g.
///   <c>TestHostShell.GetConfirmationForAccessToken</c>) are reachable
///   only through the host instance itself, not through this
///   application. Tests using the HTTP transport see only the wire.
///   </description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("AuthorizationServerHttpApplication")]
internal sealed class AuthorizationServerHttpApplication
{
    /// <summary>
    /// A request header carrying the authenticated end-user identifier for real-wire capstones that
    /// drive the authorize endpoint over an actual socket. Stands in for the ASP.NET authentication
    /// middleware a production deployment runs in front of the authorize endpoint — the same
    /// collapse <see cref="TestBrowser"/> documents for its in-process dispatch, except here the
    /// value crosses the wire as a genuine header rather than being placed on
    /// <see cref="ExchangeContext"/> directly.
    /// </summary>
    public const string TestSubjectHeaderName = "X-Test-Subject-Id";

    /// <summary>The fixture header conveying the per-request region to the context mapper.</summary>
    public static string TestRegionHeaderName { get; } = "X-Test-Region";


    /// <summary>The server every incoming request is dispatched to.</summary>
    private EndpointServer Server { get; }


    /// <summary>The fixture sink retaining the actual named exception observed over the listener.</summary>
    private ConcurrentQueue<Exception>? Faults { get; }


    /// <summary>The fixture arrival hook awaited before requesting admission.</summary>
    private Func<Task>? RequestArriving { get; }


    /// <summary>
    /// The hosted server, when known, whose per-grant ordering gate
    /// (<see cref="HostedAuthorizationServer.EnterGrantOrderGateAsync"/>) this application consults
    /// after <see cref="RequestArriving"/> and before dispatch. <see langword="null"/> for a skin
    /// built directly over an <see cref="EndpointServer"/> with no owning host — every such request
    /// is unordered.
    /// </summary>
    private HostedAuthorizationServer? Host { get; }


    /// <summary>
    /// The listener authority the host configured (<see cref="HostedAuthorizationServer.TrustedListenerAuthority"/>),
    /// read when each request arrives, or <see langword="null"/> for a skin with no owning host or a host that
    /// configured none. It is the host's own configuration, never a value read from the request.
    /// </summary>
    private Uri? TrustedListenerAuthority => Host?.TrustedListenerAuthority;


    /// <summary>Wraps <paramref name="server"/> so <see cref="ProcessRequestAsync"/> can dispatch to it.</summary>
    public AuthorizationServerHttpApplication(
        EndpointServer server,
        ConcurrentQueue<Exception>? faults = null,
        Func<Task>? requestArriving = null,
        HostedAuthorizationServer? host = null)
    {
        ArgumentNullException.ThrowIfNull(server);
        this.Server = server;
        Faults = faults;
        RequestArriving = requestArriving;
        Host = host;
    }


    /// <summary>
    /// Maps <paramref name="context"/>'s inbound HTTP request to an <see cref="IncomingRequest"/>,
    /// dispatches it through <see cref="Server"/>, and maps the resulting <see cref="ServerHttpResponse"/>
    /// back onto the HTTP response.
    /// </summary>
    public async Task ProcessRequestAsync(HttpContext context)
    {
        IncomingRequest incomingRequest = await BuildIncomingRequestAsync(
            context.Request, TrustedListenerAuthority, context.RequestAborted).ConfigureAwait(false);

        //The fixture's arrival observation sees the DPoP field lines as the listener received them.
        Host?.ObserveArrivingRequest?.Invoke(
            incomingRequest.Path, context.Request.Headers[WellKnownHttpHeaderNames.DPoP].ToArray()!);

        ExchangeContext ExchangeContext = [];
        string? tenantSegment = ExtractTenantSegmentFromPath(incomingRequest.Path);
        if(!string.IsNullOrEmpty(tenantSegment))
        {
            ExchangeContext.SetTenantId(new TenantId(tenantSegment));
        }

        //OID4VP request_uri shape — /connect/{segment}/request/{handle}.
        //The JAR endpoint matches on CorrelationKey; the deployment skin owns
        //the JAR-URL mount point, so the handle extraction lives here rather
        //than in the library matcher.
        string? requestUriHandle = ExtractRequestUriHandleFromPath(incomingRequest.Path);
        if(!string.IsNullOrEmpty(requestUriHandle))
        {
            ExchangeContext.SetCorrelationKey(requestUriHandle);
        }

        if(context.Request.Headers.TryGetValue(TestSubjectHeaderName, out StringValues subjectHeaderValues)
            && subjectHeaderValues.Count > 0
            && !string.IsNullOrEmpty(subjectHeaderValues[0]))
        {
            ExchangeContext.SetSubjectId(subjectHeaderValues[0]!);
        }

        if(context.Request.Headers.TryGetValue(TestRegionHeaderName, out var region))
        {
            ExchangeContext["app.region"] = region.ToString();
        }

        if(RequestArriving is not null)
        {
            await RequestArriving().ConfigureAwait(false);
        }

        //The per-grant ordering gate: a request the host's ordering matrix can place
        //(HostedAuthorizationServer.ResolveOrderingKey) waits its FIFO turn for its (tenant, grant
        //key) here, before anything of the library runs for it. A request the matrix cannot place,
        //or a host with ordering off, is never queued.
        IAsyncDisposable? gateTicket = Host is { IsOrderingRequestsPerGrant: true } host
            && host.ResolveOrderingKey(incomingRequest, ExchangeContext) is { } orderingKey
                ? await host.EnterGrantOrderGateAsync(
                    orderingKey.TenantId, orderingKey.GrantKey, context.RequestAborted).ConfigureAwait(false)
                : null;

        try
        {
            ServerHttpResponse response;
            try
            {
                response = incomingRequest.Method == "POST" && incomingRequest.Path == "/connect/register"
                    ? await RegistrationEndpoints.HandleCreateAsync(
                        new TenantId("dynamic-clients"), Encoding.UTF8.GetString(incomingRequest.Body.Bytes.Span),
                        ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.OAuthDynamicClientRegistration),
                        ExchangeContext, Server, context.RequestAborted).ConfigureAwait(false)
                    : await Server.DispatchAsync(incomingRequest, ExchangeContext, context.RequestAborted).ConfigureAwait(false);
            }
            catch(InvalidOperationException exception) when(Faults is not null)
            {
                Faults.Enqueue(exception);
                response = ServerHttpResponse.ServerError(ServerErrors.ServerError, "The server is not ready to serve this request.");
            }

            //OID4VP JAR endpoint: per the library contract documented on
            //Oid4VpServerExchangeContextExtensions.Jar, the application (this skin) reads
            //the signed JWS off context after dispatch and emits it as the response
            //body. BuildResponse on the JAR endpoint returns an empty body for
            //exactly this reason.
            if(string.IsNullOrEmpty(response.Body)
                && ExchangeContext.Jar is string compactJar)
            {
                response = response with { Body = compactJar };
            }

            IReadOnlyList<KeyValuePair<string, string>> appendedFieldLines =
                Host?.AppendAnswerFieldLines?.Invoke(incomingRequest.Path, response) ?? [];
            await WriteResponseAsync(response, appendedFieldLines, context.Response, context.RequestAborted)
                .ConfigureAwait(false);
        }
        finally
        {
            if(gateTicket is not null)
            {
                await gateTicket.DisposeAsync().ConfigureAwait(false);
            }
        }
    }


    /// <summary>
    /// The well-known path prefixes after which the tenant segment rides, because the specifications
    /// insert the well-known suffix between the host and the identifier's path: <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3">RFC 9728 Section 3</see>
    /// (<c>oauth-protected-resource</c>), <see href="https://www.rfc-editor.org/rfc/rfc8414#section-3">RFC 8414 Section 3</see> (<c>oauth-authorization-server</c>) and
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.2.2">OID4VCI 1.0 Section 12.2.2</see> (<c>openid-credential-issuer</c>).
    /// </summary>
    private static string[] InsertedWellKnownPrefixes { get; } =
    [
        "/.well-known/oauth-protected-resource/",
        "/.well-known/oauth-authorization-server/",
        "/.well-known/openid-credential-issuer/"
    ];


    /// <summary>
    /// Slices the first path segment that follows <paramref name="prefix"/>: everything after the
    /// prefix up to the next slash, or to the end of the path when no slash follows.
    /// </summary>
    /// <param name="path">The request path, which begins with <paramref name="prefix"/>.</param>
    /// <param name="prefix">The path prefix that ends with the slash before the segment.</param>
    /// <returns>The segment after <paramref name="prefix"/>, empty when the prefix ends the path.</returns>
    private static string ReadSegmentAfterPrefix(string path, string prefix)
    {
        int start = prefix.Length;
        int end = path.IndexOf('/', start, StringComparison.Ordinal);

        return end < 0 ? path[start..] : path[start..end];
    }


    /// <summary>
    /// Parses the tenant segment from <c>/connect/{segment}/...</c>, or from the segment after an
    /// inserted well-known suffix (<c>oauth-protected-resource</c>, <c>oauth-authorization-server</c>,
    /// <c>openid-credential-issuer</c>). Returns <see langword="null"/> for any other path; the
    /// dispatcher's prologue then reports a missing tenant and the response is the library's
    /// standard 400.
    /// </summary>
    /// <param name="path">The request path as received, beginning with <c>/</c>.</param>
    /// <returns>The tenant segment, or <see langword="null"/> when the path carries none of the recognised forms.</returns>
    private static string? ExtractTenantSegmentFromPath(string path)
    {
        foreach(string insertedPrefix in InsertedWellKnownPrefixes)
        {
            if(path.StartsWith(insertedPrefix, StringComparison.Ordinal))
            {
                return ReadSegmentAfterPrefix(path, insertedPrefix);
            }
        }

        const string prefix = "/connect/";
        if(!path.StartsWith(prefix, StringComparison.Ordinal))
        {
            return null;
        }

        return ReadSegmentAfterPrefix(path, prefix);
    }


    /// <summary>
    /// Parses a per-flow by-reference handle from <c>/connect/{segment}/request/{handle}</c> (the
    /// OID4VP JAR fetch) or <c>/connect/{segment}/siop_request_object/{handle}</c> (the SIOPv2 §9
    /// by-reference Request Object fetch). Returns <see langword="null"/> for any other path. Both
    /// matchers require <c>ExchangeContextServerExtensions.CorrelationKey</c> to be set before dispatch; the
    /// URL shape and extraction live in this skin so neither matcher is mount-point aware.
    /// </summary>
    private static string? ExtractRequestUriHandleFromPath(string path)
    {
        const string prefix = "/connect/";
        if(!path.StartsWith(prefix, StringComparison.Ordinal))
        {
            return null;
        }

        int segmentStart = prefix.Length;
        int segmentEnd = path.IndexOf('/', segmentStart, StringComparison.Ordinal);
        if(segmentEnd < 0)
        {
            return null;
        }

        return ExtractHandleAfterMarker(path, segmentEnd, "/request/")
            ?? ExtractHandleAfterMarker(path, segmentEnd, "/siop_request_object/");
    }


    /// <summary>
    /// Extracts the path segment following <paramref name="marker"/> starting at
    /// <paramref name="markerStart"/>, up to the next <c>/</c> or the end of the path. Returns
    /// <see langword="null"/> when <paramref name="path"/> does not carry <paramref name="marker"/> at
    /// that position.
    /// </summary>
    private static string? ExtractHandleAfterMarker(string path, int markerStart, string marker)
    {
        if(string.Compare(path, markerStart, marker, 0, marker.Length, StringComparison.Ordinal) != 0)
        {
            return null;
        }

        int handleStart = markerStart + marker.Length;
        if(handleStart >= path.Length)
        {
            return null;
        }

        int handleEnd = path.IndexOf('/', handleStart, StringComparison.Ordinal);

        return handleEnd < 0 ? path[handleStart..] : path[handleStart..handleEnd];
    }


    /// <summary>
    /// Reads <paramref name="request"/>'s body (if any) and maps it, its content type, its query
    /// string, and its headers onto a new <see cref="IncomingRequest"/>, stamping
    /// <paramref name="listenerAuthority"/> as its <see cref="IncomingRequest.ListenerAuthority"/>.
    /// </summary>
    /// <param name="request">The inbound HTTP request.</param>
    /// <param name="listenerAuthority">
    /// The listener authority the host configured, or <see langword="null"/> to stamp none; never read from
    /// <paramref name="request"/>.
    /// </param>
    /// <param name="cancellationToken">Cancels the body read.</param>
    /// <returns>The request envelope the library dispatches.</returns>
    private static async ValueTask<IncomingRequest> BuildIncomingRequestAsync(
        HttpRequest request, Uri? listenerAuthority, CancellationToken cancellationToken)
    {
        //Buffer the body bytes. OAuth bodies are tiny — form fields or
        //short JSON registration documents — and buffering keeps the
        //mapping straightforward.
        ReadOnlyMemory<byte> bodyBytes = request.ContentLength is > 0 || HasReadableBody(request)
            ? await ReadBodyBytesAsync(request.BodyReader, cancellationToken).ConfigureAwait(false)
            : ReadOnlyMemory<byte>.Empty;

        string contentType = request.ContentType ?? string.Empty;

        //Form-urlencoded bodies populate Fields; other content types go
        //into Body. GET requests use the query string for Fields.
        RequestFields fields = new();
        RequestBody body = RequestBody.None;

        if(IsFormEncoded(contentType) && bodyBytes.Length > 0)
        {
            string bodyText = System.Text.Encoding.UTF8.GetString(bodyBytes.Span);
            ParseFormUrlEncoded(bodyText, fields);
        }
        else if(bodyBytes.Length > 0)
        {
            body = new RequestBody
            {
                Bytes = bodyBytes,
                ContentType = contentType
            };
        }

        //Merge query parameters onto fields, preserving every value (a key may
        //repeat). Form and query both contribute — matching ASP.NET model-binder
        //behaviour — and a parameter that ends up with more than one value fails
        //the single-valued RequestFields read closed (RFC 6749 §3.1).
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
            Path: request.Path.HasValue ? request.Path.Value : string.Empty,
            Method: request.Method,
            Fields: fields,
            Headers: headers,
            RouteValues: RouteValues.Empty)
        {
            Body = body,
            ListenerAuthority = listenerAuthority
        };
    }


    /// <summary>
    /// Drains <paramref name="bodyReader"/> to completion into a single contiguous buffer. Reads the
    /// request body through the pipe (<see cref="HttpRequest.BodyReader"/>) rather than the
    /// stream-typed <see cref="HttpRequest.Body"/> property, accumulating segments in an
    /// <see cref="ArrayBufferWriter{T}"/>.
    /// </summary>
    private static async ValueTask<ReadOnlyMemory<byte>> ReadBodyBytesAsync(
        PipeReader bodyReader, CancellationToken cancellationToken)
    {
        ArrayBufferWriter<byte> bufferWriter = new();
        while(true)
        {
            ReadResult readResult = await bodyReader.ReadAsync(cancellationToken).ConfigureAwait(false);
            foreach(ReadOnlyMemory<byte> segment in readResult.Buffer)
            {
                bufferWriter.Write(segment.Span);
            }

            bodyReader.AdvanceTo(readResult.Buffer.End);

            if(readResult.IsCompleted)
            {
                break;
            }
        }

        return bufferWriter.WrittenMemory;
    }


    /// <summary>Returns <see langword="true"/> when <paramref name="request"/> carries a body worth reading.</summary>
    private static bool HasReadableBody(HttpRequest request) =>
        !string.IsNullOrEmpty(request.ContentType)
            || request.Headers.ContainsKey("Transfer-Encoding");


    /// <summary>
    /// Maps <paramref name="response"/>'s status, content type, location, headers, and body onto
    /// <paramref name="httpResponse"/>, writing the body through the pipe-based
    /// <see cref="HttpResponse.BodyWriter"/> rather than the stream-typed <see cref="HttpResponse.Body"/>.
    /// The field lines of <paramref name="appendedFieldLines"/> follow the library's own header fields, each
    /// appended as a field line of its own, so a name the library already wrote, or one given twice, goes out on
    /// several field lines.
    /// </summary>
    /// <param name="response">The answer the library gave.</param>
    /// <param name="appendedFieldLines">The field lines the fixture appends to the answer, empty for none.</param>
    /// <param name="httpResponse">The HTTP response the listener writes.</param>
    /// <param name="cancellationToken">Cancels the body write.</param>
    /// <returns>A task that completes when the answer is written.</returns>
    private static async ValueTask WriteResponseAsync(
        ServerHttpResponse response,
        IReadOnlyList<KeyValuePair<string, string>> appendedFieldLines,
        HttpResponse httpResponse,
        CancellationToken cancellationToken)
    {
        httpResponse.StatusCode = response.StatusCode;

        //Content-Type — the library carries it as a string on the response
        //record. Empty string means "no body" (404, redirects).
        if(!string.IsNullOrEmpty(response.ContentType))
        {
            httpResponse.ContentType = response.ContentType;
        }

        //Location — 302 redirects carry the target URI here.
        if(!string.IsNullOrEmpty(response.Location))
        {
            httpResponse.Headers.Location = response.Location;
        }

        //Additional headers (DPoP-Nonce, Cache-Control, future RFC 9457
        //Retry-After). The library serialises them name → value; emit one
        //header line per entry.
        foreach(KeyValuePair<string, string> header in response.Headers)
        {
            httpResponse.Headers.Append(header.Key, header.Value);
        }

        foreach(KeyValuePair<string, string> fieldLine in appendedFieldLines)
        {
            httpResponse.Headers.Append(fieldLine.Key, fieldLine.Value);
        }

        if(!string.IsNullOrEmpty(response.Body))
        {
            int maxByteCount = System.Text.Encoding.UTF8.GetMaxByteCount(response.Body.Length);
            Memory<byte> destination = httpResponse.BodyWriter.GetMemory(maxByteCount);
            int written = System.Text.Encoding.UTF8.GetBytes(response.Body, destination.Span);
            httpResponse.BodyWriter.Advance(written);
            _ = await httpResponse.BodyWriter.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
    }


    /// <summary>Maps Kestrel's header dictionary onto a <see cref="RequestHeaders"/> instance.</summary>
    private static RequestHeaders MapHeaders(IHeaderDictionary source)
    {
        Dictionary<string, string[]> mapped = new(source.Count, StringComparer.OrdinalIgnoreCase);
        foreach(KeyValuePair<string, StringValues> entry in source)
        {
            //StringValues → string[]: ToArray copies the underlying buffer
            //into a regular array the library's RequestHeaders constructor
            //accepts. Empty StringValues becomes an empty array; the
            //library treats it the same as "header absent".
            string[] values = entry.Value.ToArray()!;
            mapped[entry.Key] = values;
        }
        return new RequestHeaders(mapped);
    }


    /// <summary>
    /// Form-urlencoded body parser. Splits on <c>&amp;</c>, then on <c>=</c>;
    /// percent-decodes both halves. ASP.NET's own parser is available via
    /// <see cref="HttpRequest.Form"/> but reading <c>Form</c> consumes the
    /// body stream and races with our own buffering; a small inline parser
    /// avoids the coupling.
    /// </summary>
    private static void ParseFormUrlEncoded(string body, RequestFields fields)
    {
        if(string.IsNullOrEmpty(body))
        {
            return;
        }
        foreach(string pair in body.Split('&'))
        {
            int eq = pair.IndexOf('=', StringComparison.Ordinal);
            if(eq <= 0)
            {
                continue;
            }
            string name = Uri.UnescapeDataString(pair[..eq].Replace('+', ' '));
            string value = Uri.UnescapeDataString(pair[(eq + 1)..].Replace('+', ' '));
            fields.Add(name, value);
        }
    }


    /// <summary>Returns <see langword="true"/> when <paramref name="contentType"/> is form-urlencoded.</summary>
    private static bool IsFormEncoded(string contentType) =>
        contentType.StartsWith(
            WellKnownMediaTypes.Application.FormUrlEncoded,
            StringComparison.OrdinalIgnoreCase);
}
