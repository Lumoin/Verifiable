using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO.Pipelines;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using StringValues = Microsoft.Extensions.Primitives.StringValues;
using Verifiable.Core;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Server;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Bridges minimal Kestrel hosting to
/// <see cref="EndpointServer.DispatchAsync"/>. Maps inbound HTTP
/// requests to the library's <see cref="IncomingRequest"/> and
/// <see cref="ExchangeContext"/>, and maps the outbound
/// <see cref="ServerHttpResponse"/> back to HTTP response bytes.
/// </summary>
/// <remarks>
/// <para>
/// Test-only construct. The library itself does not reference Kestrel.
/// A production deployment writes its own host adapter; the shape of
/// this mapping layer is a useful reference but not part of the
/// library's public surface.
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
///   <see cref="ExchangeContext"/> via <see cref="ExchangeContextServerExtensions.SetTenantId"/>
///   before dispatch. The dispatcher's <see cref="AuthorizationServerIntegration.ExtractTenantIdAsync"/>
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
internal sealed class AuthorizationServerHttpApplication: IHttpApplication<HttpContext>
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

    /// <summary>The server every incoming request is dispatched to.</summary>
    private readonly EndpointServer server;


    /// <summary>Wraps <paramref name="server"/> so <see cref="ProcessRequestAsync"/> can dispatch to it.</summary>
    public AuthorizationServerHttpApplication(EndpointServer server)
    {
        ArgumentNullException.ThrowIfNull(server);
        this.server = server;
    }


    /// <summary>Creates the per-request <see cref="HttpContext"/> Kestrel dispatches through.</summary>
    public HttpContext CreateContext(IFeatureCollection contextFeatures) =>
        new DefaultHttpContext(contextFeatures);


    /// <summary>
    /// Maps <paramref name="context"/>'s inbound HTTP request to an <see cref="IncomingRequest"/>,
    /// dispatches it through <see cref="server"/>, and maps the resulting <see cref="ServerHttpResponse"/>
    /// back onto the HTTP response.
    /// </summary>
    public async Task ProcessRequestAsync(HttpContext context)
    {
        IncomingRequest incomingRequest = await BuildIncomingRequestAsync(
            context.Request, context.RequestAborted).ConfigureAwait(false);

        ExchangeContext ExchangeContext = new();
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

        ServerHttpResponse response = await server.DispatchAsync(
            incomingRequest, ExchangeContext, context.RequestAborted).ConfigureAwait(false);

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

        await WriteResponseAsync(response, context.Response, context.RequestAborted)
            .ConfigureAwait(false);
    }


    /// <summary>No per-request disposable state is held; this is a no-op.</summary>
    public void DisposeContext(HttpContext context, Exception? exception) { }


    /// <summary>
    /// Parses the tenant segment from <c>/connect/{segment}/...</c>. Returns
    /// <see langword="null"/> when the path does not start with <c>/connect/</c>
    /// — the dispatcher's prologue then reports a missing tenant and the
    /// response is the library's standard 400.
    /// </summary>
    private static string? ExtractTenantSegmentFromPath(string path)
    {
        //RFC 9728 §3 inserts the protected-resource well-known suffix between
        //the host and the resource identifier's path, so the tenant rides
        //AFTER the suffix: /.well-known/oauth-protected-resource/{segment}.
        const string insertedPrefix = "/.well-known/oauth-protected-resource/";
        if(path.StartsWith(insertedPrefix, StringComparison.Ordinal))
        {
            int insertedStart = insertedPrefix.Length;
            int insertedEnd = path.IndexOf('/', insertedStart);

            return insertedEnd < 0 ? path[insertedStart..] : path[insertedStart..insertedEnd];
        }

        //RFC 8414 §3 inserts the authorization-server-metadata well-known suffix
        //between the host and the issuer identifier's path, so the tenant rides
        //AFTER the suffix: /.well-known/oauth-authorization-server/{segment}.
        const string oauthMetadataPrefix = "/.well-known/oauth-authorization-server/";
        if(path.StartsWith(oauthMetadataPrefix, StringComparison.Ordinal))
        {
            int oauthMetadataStart = oauthMetadataPrefix.Length;
            int oauthMetadataEnd = path.IndexOf('/', oauthMetadataStart);

            return oauthMetadataEnd < 0 ? path[oauthMetadataStart..] : path[oauthMetadataStart..oauthMetadataEnd];
        }

        const string prefix = "/connect/";
        if(!path.StartsWith(prefix, StringComparison.Ordinal))
        {
            return null;
        }
        int start = prefix.Length;
        int end = path.IndexOf('/', start);
        return end < 0 ? path[start..] : path[start..end];
    }


    /// <summary>
    /// Parses a per-flow by-reference handle from <c>/connect/{segment}/request/{handle}</c> (the
    /// OID4VP JAR fetch) or <c>/connect/{segment}/siop_request_object/{handle}</c> (the SIOPv2 §9
    /// by-reference Request Object fetch). Returns <see langword="null"/> for any other path. Both
    /// matchers require <see cref="ExchangeContext.CorrelationKey"/> to be set before dispatch; the
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
        int segmentEnd = path.IndexOf('/', segmentStart);
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

        int handleEnd = path.IndexOf('/', handleStart);

        return handleEnd < 0 ? path[handleStart..] : path[handleStart..handleEnd];
    }


    /// <summary>
    /// Reads <paramref name="request"/>'s body (if any) and maps it, its content type, its query
    /// string, and its headers onto a new <see cref="IncomingRequest"/>.
    /// </summary>
    private static async ValueTask<IncomingRequest> BuildIncomingRequestAsync(
        HttpRequest request, CancellationToken cancellationToken)
    {
        //Buffer the body bytes. OAuth bodies are tiny — form fields or
        //short JSON registration documents — and buffering keeps the
        //mapping straightforward.
        ReadOnlyMemory<byte> bodyBytes;
        if(request.ContentLength is > 0 || HasReadableBody(request))
        {
            bodyBytes = await ReadBodyBytesAsync(request.BodyReader, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            bodyBytes = ReadOnlyMemory<byte>.Empty;
        }

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
            Path: request.Path.HasValue ? request.Path.Value! : string.Empty,
            Method: request.Method,
            Fields: fields,
            Headers: headers,
            RouteValues: RouteValues.Empty)
        {
            Body = body
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
    /// </summary>
    private static async ValueTask WriteResponseAsync(
        ServerHttpResponse response,
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

        if(!string.IsNullOrEmpty(response.Body))
        {
            int maxByteCount = System.Text.Encoding.UTF8.GetMaxByteCount(response.Body.Length);
            Memory<byte> destination = httpResponse.BodyWriter.GetMemory(maxByteCount);
            int written = System.Text.Encoding.UTF8.GetBytes(response.Body, destination.Span);
            httpResponse.BodyWriter.Advance(written);
            await httpResponse.BodyWriter.FlushAsync(cancellationToken).ConfigureAwait(false);
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
