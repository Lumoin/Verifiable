using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using Microsoft.AspNetCore.Http;
using StringValues = Microsoft.Extensions.Primitives.StringValues;
using Verifiable.Core;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Server;
using Verifiable.Server;
using Verifiable.Server.Routing;

namespace Verifiable.Tests.Vcalm;

/// <summary>
/// The <see cref="Microsoft.AspNetCore.Builder.WebApplication"/> host skin for the W3C VCALM 1.0
/// conformance bridge (chunk V-6a), mounted directly as its HTTPS pipeline's <c>RequestDelegate</c>
/// (<c>app.Run(application.ProcessRequestAsync)</c>). It is the analogue of
/// <see cref="Verifiable.Tests.OAuth.AuthorizationServerHttpApplication"/>, specialised for the
/// external W3C <c>vc-api-issuer-test-suite</c> / <c>vc-api-verifier-test-suite</c> JS suites: it
/// serves the §3.2.1 <c>POST /credentials/issue</c>, §3.3.1 <c>POST /credentials/verify</c>, and
/// §3.3.2 <c>POST /presentations/verify</c> interfaces at STABLE, suite-expected URL paths over real
/// HTTPS, protected by an OAuth2 client-credentials bearer token, and exposes the AS token endpoint
/// the suites obtain that token from.
/// </summary>
/// <remarks>
/// <para>
/// Test-only construct. The library does not reference Kestrel or ASP.NET Core; a production VCALM
/// deployment writes its own host adapter. The body-buffering, header-mapping, and
/// <see cref="ServerHttpResponse"/> → HTTP behaviours are identical to
/// <see cref="Verifiable.Tests.OAuth.AuthorizationServerHttpApplication"/>; this skin adds two
/// conformance-bridge concerns on top of plain dispatch:
/// </para>
/// <list type="bullet">
///   <item><description>
///   <b>Stable suite paths.</b> The W3C suites POST to flat, instance-rooted paths
///   (<c>/credentials/issue</c>, <c>/credentials/verify</c>, <c>/presentations/verify</c>) and read
///   the token from a single token endpoint. The library's dispatcher matches VCALM endpoints on the
///   tenant-scoped <c>/connect/{segment}/vcalm/...</c> path the fixture's
///   <see cref="AuthorizationServerIntegration.ResolveEndpointUriAsync"/> resolver produces, so this
///   skin REWRITES the inbound flat path into that tenant-scoped shape before dispatch (§2.3 instance
///   pathing is deployment-chosen — the suite sees flat paths, the dispatcher sees its own).
///   </description></item>
///   <item><description>
///   <b>OAuth2 client-credentials protection.</b> The VCALM endpoints are a protected resource
///   (RFC 6750): a request to an issue / verify path MUST carry a valid AS-issued bearer access token
///   or the skin answers 401 before dispatch, exactly the gate the registry manifest's <c>oauth2</c>
///   auth path drives. The token endpoint itself is unprotected (it MINTS the token). Validation
///   composes the library's <see cref="BearerTokenValidation"/> — the same RFC 9068 access-token
///   structural-parse → signature → <c>iss</c> → <c>exp</c> sequence the resource-server endpoints use.
///   </description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("VcalmConformanceHttpApplication Tenant={tenantSegment}")]
internal sealed class VcalmConformanceHttpApplication
{
    private readonly EndpointServer server;
    private readonly string tenantSegment;
    private readonly ClientRecord registration;

    /// <summary>
    /// The stable, suite-expected issuer interface path the W3C issuer suite POSTs to. Rewritten to
    /// the tenant-scoped <c>vcalm/credentials/issue</c> suffix the dispatcher matches.
    /// </summary>
    public const string CredentialsIssuePath = "/credentials/issue";

    /// <summary>The stable, suite-expected §3.3.1 verifier interface path.</summary>
    public const string CredentialsVerifyPath = "/credentials/verify";

    /// <summary>The stable, suite-expected §3.3.2 presentation-verify interface path.</summary>
    public const string PresentationsVerifyPath = "/presentations/verify";

    /// <summary>The OAuth2 token endpoint the client-credentials grant runs on (RFC 6749 §4.4).</summary>
    public const string TokenPath = "/token";


    public VcalmConformanceHttpApplication(EndpointServer server, ClientRecord registration)
    {
        ArgumentNullException.ThrowIfNull(server);
        ArgumentNullException.ThrowIfNull(registration);

        this.server = server;
        this.registration = registration;
        tenantSegment = registration.TenantId.Value;
    }


    public async Task ProcessRequestAsync(HttpContext context)
    {
        IncomingRequest incomingRequest = await BuildIncomingRequestAsync(
            context.Request, context.RequestAborted).ConfigureAwait(false);

        ExchangeContext exchangeContext = new();
        exchangeContext.SetTenantId(new TenantId(tenantSegment));

        //Map the inbound flat path the suite uses onto the tenant-scoped path the dispatcher matches.
        //An unmapped path yields null; the dispatcher then reports its standard 404.
        string flatPath = incomingRequest.Path;
        bool isProtectedResource = IsProtectedVcalmResource(flatPath);
        string dispatchPath = RewriteToTenantPath(flatPath);

        //RFC 6750 protected-resource gate: a VCALM endpoint request must carry a valid AS-issued
        //bearer token. The token endpoint and any unmapped path skip the gate — the token endpoint
        //MINTS the token, and an unmapped path falls through to the dispatcher's own 404.
        if(isProtectedResource)
        {
            ServerHttpResponse? authFailure = await EnforceBearerAsync(
                incomingRequest, exchangeContext, context.RequestAborted).ConfigureAwait(false);
            if(authFailure is not null)
            {
                await WriteResponseAsync(authFailure, context.Response, context.RequestAborted)
                    .ConfigureAwait(false);

                return;
            }
        }

        IncomingRequest dispatchRequest = incomingRequest with { Path = dispatchPath };

        ServerHttpResponse response = await server.DispatchAsync(
            dispatchRequest, exchangeContext, context.RequestAborted).ConfigureAwait(false);

        await WriteResponseAsync(response, context.Response, context.RequestAborted)
            .ConfigureAwait(false);
    }


    /// <summary>
    /// Whether the inbound flat path addresses a protected VCALM endpoint (the issue / verify
    /// interfaces). The token endpoint is NOT protected — it mints the very token the others require.
    /// </summary>
    private static bool IsProtectedVcalmResource(string flatPath) =>
        string.Equals(flatPath, CredentialsIssuePath, StringComparison.Ordinal)
        || string.Equals(flatPath, CredentialsVerifyPath, StringComparison.Ordinal)
        || string.Equals(flatPath, PresentationsVerifyPath, StringComparison.Ordinal);


    /// <summary>
    /// Rewrites a stable suite path into the tenant-scoped <c>/connect/{segment}/...</c> path the
    /// dispatcher's endpoint matchers resolve to. The token endpoint maps to the AS token path; the
    /// three VCALM interfaces map to their <c>vcalm/...</c> suffixes. An unrecognised path is returned
    /// unchanged so the dispatcher answers its standard 404.
    /// </summary>
    private string RewriteToTenantPath(string flatPath)
    {
        string? suffix = flatPath switch
        {
            TokenPath => "token",
            CredentialsIssuePath => "vcalm/credentials/issue",
            CredentialsVerifyPath => "vcalm/credentials/verify",
            PresentationsVerifyPath => "vcalm/presentations/verify",
            _ => null
        };

        return suffix is null ? flatPath : $"/connect/{tenantSegment}/{suffix}";
    }


    /// <summary>
    /// Validates the request's bearer token via the library's <see cref="BearerTokenValidation"/>.
    /// Returns the RFC 6750 401 response on a missing / malformed / invalid token, or
    /// <see langword="null"/> when a valid AS-issued token was presented and dispatch may proceed.
    /// </summary>
    private async ValueTask<ServerHttpResponse?> EnforceBearerAsync(
        IncomingRequest incomingRequest, ExchangeContext exchangeContext, CancellationToken cancellationToken)
    {
        //BearerTokenValidation reads the Authorization header off context.IncomingRequest, and
        //ValidateAsync resolves the issuer from the registration — both need the request and the
        //registration on context. The dispatcher sets these later for the dispatched request; the
        //gate sets them itself so it can run BEFORE dispatch.
        exchangeContext.SetIncomingRequest(incomingRequest);
        exchangeContext.SetRegistration(registration);

        if(!BearerTokenValidation.TryExtractBearer(exchangeContext, out string? bearerToken)
            || string.IsNullOrEmpty(bearerToken))
        {
            return ServerHttpResponse.Unauthorized(
                OAuthErrors.InvalidToken,
                "A VCALM protected-resource request must carry a Bearer access token.")
                .WithHeader(WellKnownHttpHeaderNames.WwwAuthenticate, WellKnownAuthenticationSchemes.Bearer);
        }

        (_, ServerHttpResponse? failure) = await BearerTokenValidation.ValidateAsync(
            bearerToken, server, registration, exchangeContext, cancellationToken).ConfigureAwait(false);

        if(failure is not null)
        {
            return failure.WithHeader(
                WellKnownHttpHeaderNames.WwwAuthenticate, WellKnownAuthenticationSchemes.Bearer);
        }

        return null;
    }


    private static async ValueTask<IncomingRequest> BuildIncomingRequestAsync(
        HttpRequest request, CancellationToken cancellationToken)
    {
        //Buffer the body bytes. VCALM bodies are JSON credential / presentation documents (capped at
        //the §2.4 RECOMMENDED 10 MB) and form-encoded token-request fields; buffering keeps the
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

        //Form-urlencoded bodies (the token request) populate Fields; the JSON VCALM bodies go into
        //Body. GET requests use the query string for Fields.
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


    private static bool HasReadableBody(HttpRequest request) =>
        !string.IsNullOrEmpty(request.ContentType)
            || request.Headers.ContainsKey("Transfer-Encoding");


    private static async ValueTask WriteResponseAsync(
        ServerHttpResponse response,
        HttpResponse httpResponse,
        CancellationToken cancellationToken)
    {
        httpResponse.StatusCode = response.StatusCode;

        if(!string.IsNullOrEmpty(response.ContentType))
        {
            httpResponse.ContentType = response.ContentType;
        }

        if(!string.IsNullOrEmpty(response.Location))
        {
            httpResponse.Headers.Location = response.Location;
        }

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
            string[] values = entry.Value.ToArray()!;
            mapped[entry.Key] = values;
        }

        return new RequestHeaders(mapped);
    }


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


    private static bool IsFormEncoded(string contentType) =>
        contentType.StartsWith(
            WellKnownMediaTypes.Application.FormUrlEncoded,
            StringComparison.OrdinalIgnoreCase);
}
