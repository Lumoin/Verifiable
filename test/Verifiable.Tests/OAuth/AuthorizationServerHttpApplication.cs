using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using StringValues = Microsoft.Extensions.Primitives.StringValues;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Server;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Bridges minimal Kestrel hosting to
/// <see cref="AuthorizationServer.DispatchAsync"/>. Maps inbound HTTP
/// requests to the library's <see cref="IncomingRequest"/> and
/// <see cref="RequestContext"/>, and maps the outbound
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
///   <see cref="RequestContext"/> via <see cref="RequestContextExtensions.SetTenantId"/>
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
    private readonly AuthorizationServer server;


    public AuthorizationServerHttpApplication(AuthorizationServer server)
    {
        ArgumentNullException.ThrowIfNull(server);
        this.server = server;
    }


    public HttpContext CreateContext(IFeatureCollection contextFeatures) =>
        new DefaultHttpContext(contextFeatures);


    public async Task ProcessRequestAsync(HttpContext context)
    {
        IncomingRequest incomingRequest = await BuildIncomingRequestAsync(
            context.Request, context.RequestAborted).ConfigureAwait(false);

        RequestContext requestContext = new();
        string? tenantSegment = ExtractTenantSegmentFromPath(incomingRequest.Path);
        if(!string.IsNullOrEmpty(tenantSegment))
        {
            requestContext.SetTenantId(new TenantId(tenantSegment));
        }

        ServerHttpResponse response = await server.DispatchAsync(
            incomingRequest, requestContext, context.RequestAborted).ConfigureAwait(false);

        await WriteResponseAsync(response, context.Response, context.RequestAborted)
            .ConfigureAwait(false);
    }


    public void DisposeContext(HttpContext context, Exception? exception) { }


    /// <summary>
    /// Parses the tenant segment from <c>/connect/{segment}/...</c>. Returns
    /// <see langword="null"/> when the path does not start with <c>/connect/</c>
    /// — the dispatcher's prologue then reports a missing tenant and the
    /// response is the library's standard 400.
    /// </summary>
    private static string? ExtractTenantSegmentFromPath(string path)
    {
        const string prefix = "/connect/";
        if(!path.StartsWith(prefix, StringComparison.Ordinal))
        {
            return null;
        }
        int start = prefix.Length;
        int end = path.IndexOf('/', start);
        return end < 0 ? path[start..] : path[start..end];
    }


    private static async ValueTask<IncomingRequest> BuildIncomingRequestAsync(
        HttpRequest request, CancellationToken cancellationToken)
    {
        //Buffer the body bytes. OAuth bodies are tiny — form fields or
        //short JSON registration documents — and buffering keeps the
        //mapping straightforward.
        byte[] bodyBytes;
        if(request.ContentLength is > 0 || HasReadableBody(request))
        {
            using MemoryStream ms = new();
            await request.Body.CopyToAsync(ms, cancellationToken).ConfigureAwait(false);
            bodyBytes = ms.ToArray();
        }
        else
        {
            bodyBytes = [];
        }

        string contentType = request.ContentType ?? string.Empty;

        //Form-urlencoded bodies populate Fields; other content types go
        //into Body. GET requests use the query string for Fields.
        RequestFields fields = new();
        RequestBody body = RequestBody.None;

        if(IsFormEncoded(contentType) && bodyBytes.Length > 0)
        {
            string bodyText = System.Text.Encoding.UTF8.GetString(bodyBytes);
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

        //Merge query parameters onto fields. Form body takes precedence on
        //collisions — matching ASP.NET model-binder behaviour and the
        //comment on IncomingRequest.Fields' XML doc.
        foreach(KeyValuePair<string, StringValues> query in request.Query)
        {
            if(!fields.ContainsKey(query.Key))
            {
                fields[query.Key] = query.Value.ToString();
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


    private static bool HasReadableBody(HttpRequest request) =>
        !string.IsNullOrEmpty(request.ContentType)
            || request.Headers.ContainsKey("Transfer-Encoding");


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
            byte[] bodyBytes = System.Text.Encoding.UTF8.GetBytes(response.Body);
            await httpResponse.Body.WriteAsync(
                bodyBytes, cancellationToken).ConfigureAwait(false);
        }
    }


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
            fields[name] = value;
        }
    }


    private static bool IsFormEncoded(string contentType) =>
        contentType.StartsWith(
            WellKnownMediaTypes.Application.FormUrlEncoded,
            StringComparison.OrdinalIgnoreCase);
}
