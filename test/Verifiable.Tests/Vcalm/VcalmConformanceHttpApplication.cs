using Microsoft.AspNetCore.Http;
using System.Buffers;
using System.Diagnostics;
using System.IO.Pipelines;
using System.Net;
using Verifiable.Core;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.ProtectedResource;
using Verifiable.OAuth.Server;
using Verifiable.Server.Routing;
using Verifiable.Vcalm;
using StringValues = Microsoft.Extensions.Primitives.StringValues;

namespace Verifiable.Tests.Vcalm;

/// <summary>
/// The <c>Microsoft.AspNetCore.Builder.WebApplication</c> host skin for the W3C VCALM 1.0
/// conformance bridge, mounted directly as its HTTPS pipeline's <c>RequestDelegate</c>
/// (<c>app.Run(application.ProcessRequestAsync)</c>). It is the analogue of
/// <see cref="Verifiable.Tests.OAuth.AuthorizationServerHttpApplication"/>, specialised for the
/// external W3C issuer and verifier test suites: it serves the §3.2.1 <c>POST /credentials/issue</c>,
/// §3.3.1 <c>POST /credentials/verify</c>, and §3.3.2 <c>POST /presentations/verify</c> interfaces at
/// stable, suite-expected URL paths over real HTTPS, protected by an OAuth 2.0 bearer access token,
/// and exposes the authorization server's token endpoint the suites obtain that token from.
/// </summary>
/// <remarks>
/// <para>
/// Test-only construct: the library references no HTTP host; a production VCALM deployment writes
/// its own host adapter. Every inbound request is judged in this order:
/// </para>
/// <list type="number">
///   <item><description>
///   <b>Routing, on the method and the un-rewritten path alone, before the body is read.</b> Exactly
///   four method/path combinations are served: <c>POST /credentials/issue</c>,
///   <c>POST /credentials/verify</c> and <c>POST /presentations/verify</c> (protected), and
///   <c>POST /token</c> (public: it mints the token the others require). The public set is that one
///   token POST; the authorization server's metadata and JWKS endpoints are not served through this
///   host. One of the three protected paths under any other method answers 405 with
///   <c>Allow: POST</c>; every other combination, the tenant-scoped
///   <c>/connect/{segment}/vcalm/...</c> dispatcher paths included, answers 404 with an empty body.
///   Neither carries a bearer challenge.
///   </description></item>
///   <item><description>
///   <b>Admission of the protected interfaces</b> (RFC 6750, RFC 9068 §4 and the
///   <see href="https://www.w3.org/TR/vcalm-1.0/#authorization">VCALM 1.0 OAuth 2.0 scope syntax</see>):
///   no credentials or a scheme other than <c>Bearer</c> answers 401 with a realm-only challenge and
///   an empty body; a token that fails validation, a missing or foreign <c>aud</c> included, answers
///   401 with <c>error="invalid_token"</c>; a valid token whose <c>scope</c> does not grant the path
///   answers 403 with <c>error="insufficient_scope"</c> and the required scope; a server fault during
///   validation answers 500 with no challenge. The audience is judged before the scope.
///   </description></item>
///   <item><description>
///   <b>The body</b>, read only for a served combination and bounded by
///   <see cref="ResolveMaximumBodyLength"/>, one mebibyte above the VCALM endpoints' own
///   <see cref="VcalmIntegration.VcalmMaxRequestBytes"/> cap: a body within the bound is dispatched,
///   so one above the endpoints' cap gets their 413 with a ProblemDetails body; a body above the
///   bound answers the host's 413 with an empty body before dispatch.
///   </description></item>
///   <item><description>
///   <b>Dispatch.</b> The suite-stable path is rewritten onto the tenant-scoped path the
///   dispatcher's endpoint matchers resolve (instance pathing is deployment-chosen) and forwarded
///   to <see cref="Server"/>.
///   </description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("VcalmConformanceHttpApplication Tenant={TenantSegment}")]
internal sealed class VcalmConformanceHttpApplication
{
    /// <summary>
    /// The stable, suite-expected §3.2.1 issuer interface path the W3C issuer suite POSTs to.
    /// Rewritten to the tenant-scoped <c>vcalm/credentials/issue</c> suffix the dispatcher matches.
    /// </summary>
    public const string CredentialsIssuePath = "/credentials/issue";

    /// <summary>The stable, suite-expected §3.3.1 verifier interface path.</summary>
    public const string CredentialsVerifyPath = "/credentials/verify";

    /// <summary>The stable, suite-expected §3.3.2 presentation-verify interface path.</summary>
    public const string PresentationsVerifyPath = "/presentations/verify";

    /// <summary>The OAuth 2.0 token endpoint the client-credentials grant runs on (RFC 6749 §4.4).</summary>
    public const string TokenPath = "/token";

    /// <summary>
    /// The octets this host buffers beyond the payload cap the VCALM endpoints enforce: one mebibyte
    /// (2^20). The endpoints apply <see cref="VcalmIntegration.VcalmMaxRequestBytes"/> themselves and
    /// answer an oversized body with 413 and a ProblemDetails body, the shape
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#error-handling">VCALM 1.0 Error Handling</see>
    /// describes; the host's own bound only limits what it buffers. Sitting a whole mebibyte above the
    /// endpoints' cap, the host's bound never answers first for a body the endpoints would refuse
    /// themselves, while a body larger still is refused without being buffered.
    /// </summary>
    private const long BufferingMarginLength = 1024 * 1024;

    /// <summary>The authorization and VCALM server this instance dispatches into.</summary>
    private EndpointServer Server { get; }

    /// <summary>The conformance tenant's identifier, also the dispatcher's path segment.</summary>
    private string TenantSegment { get; }

    /// <summary>The conformance tenant the VCALM endpoints belong to; token validation resolves its issuer from it.</summary>
    private ClientRecord Registration { get; }

    /// <summary>
    /// The RFC 6750 §3 challenge sent when a request lacks any authentication information: the
    /// <c>Bearer</c> scheme with only the <c>realm</c> auth-param. Built once in the constructor, so an
    /// <see cref="InstanceAudience"/> that cannot be carried as a realm fails construction instead of
    /// the first refused request.
    /// </summary>
    private string RealmOnlyChallenge { get; }

    /// <summary>
    /// The absolute URI identifying this instance for the RFC 9068 §4 <c>aud</c> check: the resource
    /// indicator every admitted access token's <c>aud</c> claim must contain, never derived from the
    /// inbound request's Host header or listening port. Also the challenge realm.
    /// </summary>
    /// <remarks>
    /// The comparison is exact-string, with no case folding and no URI normalisation: an <c>aud</c>
    /// entry whose host differs only in letter case, or that adds a trailing slash or the default port,
    /// is another audience and the token is refused with <c>invalid_token</c>. RFC 9068 §4 names "an
    /// identifier the resource server expects for itself"; this string is that identifier, and the
    /// <c>aud</c> entry is compared as the string the client presented as its resource indicator.
    /// </remarks>
    public string InstanceAudience { get; }


    /// <summary>
    /// Builds the skin for one tenant's instance.
    /// </summary>
    /// <param name="server">The authorization and VCALM server this instance dispatches into.</param>
    /// <param name="registration">The conformance tenant the VCALM endpoints belong to.</param>
    /// <param name="instanceAudience">
    /// This instance's own absolute URI, required to appear in every admitted access token's
    /// <c>aud</c> claim (RFC 9068 §4) and used as the challenge realm.
    /// </param>
    /// <exception cref="ArgumentException">
    /// <paramref name="instanceAudience"/> is not an absolute URI, or cannot be represented as an
    /// RFC 6750 §3 <c>realm</c> quoted-string.
    /// </exception>
    public VcalmConformanceHttpApplication(EndpointServer server, ClientRecord registration, string instanceAudience)
    {
        ArgumentNullException.ThrowIfNull(server);
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentException.ThrowIfNullOrWhiteSpace(instanceAudience);

        if(!Uri.TryCreate(instanceAudience, UriKind.Absolute, out _))
        {
            throw new ArgumentException(
                "instanceAudience must be an absolute URI.", nameof(instanceAudience));
        }

        Server = server;
        Registration = registration;
        TenantSegment = registration.TenantId.Value;
        InstanceAudience = instanceAudience;
        RealmOnlyChallenge = BearerTokenChallenge.BuildChallenge(realm: instanceAudience);
    }


    /// <summary>
    /// Answers one inbound HTTP request in the order the class remarks state: routing on the method
    /// and the un-rewritten path (404 or 405 before the body is read), admission of a protected
    /// interface (401, 403 or a 500 pass-through), the bounded body read (413), then dispatch of the
    /// rewritten request into <see cref="Server"/>. A request reaches <see cref="Server"/> only
    /// through this sequence; no dispatcher path is reachable directly.
    /// </summary>
    /// <param name="context">The request and response pair this call answers.</param>
    /// <returns>A task that completes when the response has been written.</returns>
    public async Task ProcessRequestAsync(HttpContext context)
    {
        HttpRequest request = context.Request;
        CancellationToken cancellationToken = context.RequestAborted;
        string method = request.Method;
        string flatPath = request.Path.HasValue ? request.Path.Value : string.Empty;

        string? requiredScope = RequiredScope(method, flatPath);
        bool isTokenRoute = WellKnownHttpMethods.IsPost(method)
            && string.Equals(flatPath, TokenPath, StringComparison.Ordinal);

        //Routing needs only the method and the path, so an unserved combination is answered before
        //any body byte is read and before an ExchangeContext exists.
        if(requiredScope is null && !isTokenRoute)
        {
            ServerHttpResponse refusal = IsMappedInterfacePath(flatPath)
                ? MethodNotAllowed()
                : ServerHttpResponse.NotFound();
            await WriteResponseAsync(refusal, context.Response, cancellationToken).ConfigureAwait(false);

            return;
        }

        IncomingRequest incomingRequest = BuildIncomingRequest(request, method, flatPath);
        ExchangeContext exchangeContext = [];
        exchangeContext.SetTenantId(new TenantId(TenantSegment));

        //The token endpoint skips admission: it mints the token the protected interfaces require.
        if(requiredScope is not null)
        {
            Result<JwtPayload, ServerHttpResponse> admission = await AdmitBearerAsync(
                requiredScope, incomingRequest, exchangeContext, cancellationToken).ConfigureAwait(false);

            if(!admission.IsSuccess)
            {
                await WriteResponseAsync(admission.Error, context.Response, cancellationToken)
                    .ConfigureAwait(false);

                return;
            }
        }

        Result<byte[], ServerHttpResponse> body = await ReadBoundedBodyAsync(
            request, ResolveMaximumBodyLength(), cancellationToken).ConfigureAwait(false);
        if(!body.IsSuccess)
        {
            await WriteResponseAsync(body.Error, context.Response, cancellationToken).ConfigureAwait(false);

            return;
        }

        IncomingRequest bodiedRequest = AttachBody(incomingRequest, body.Value, request.ContentType);
        IncomingRequest dispatchRequest = bodiedRequest with { Path = RewriteToTenantPath(flatPath) };

        ServerHttpResponse response = await Server.DispatchAsync(
            dispatchRequest, exchangeContext, cancellationToken).ConfigureAwait(false);

        await WriteResponseAsync(response, context.Response, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// The <see href="https://www.w3.org/TR/vcalm-1.0/#authorization">VCALM 1.0 OAuth 2.0 scope</see>
    /// a request against <paramref name="method"/> and <paramref name="flatPath"/> requires, or
    /// <see langword="null"/> when the combination is not one of the three protected interfaces.
    /// Each interface is POST-only and the draft maps scopes "based on the HTTP method (e.g., GET -&gt;
    /// read, POST -&gt; write)", so each maps to the <c>write:</c> scope of its own path. The token
    /// endpoint is not protected; every other method on any path maps to nothing, so a
    /// <c>write:</c> token never reads through this host. The switch compares the un-rewritten path,
    /// so the tenant-scoped dispatcher path is not one of its arms.
    /// </summary>
    /// <param name="method">The inbound request method.</param>
    /// <param name="flatPath">The inbound, un-rewritten request path.</param>
    /// <returns>The required <c>operation:path</c> scope, or <see langword="null"/>.</returns>
    private static string? RequiredScope(string method, string flatPath) => flatPath switch
    {
        CredentialsIssuePath when WellKnownHttpMethods.IsPost(method) => "write:" + CredentialsIssuePath,
        CredentialsVerifyPath when WellKnownHttpMethods.IsPost(method) => "write:" + CredentialsVerifyPath,
        PresentationsVerifyPath when WellKnownHttpMethods.IsPost(method) => "write:" + PresentationsVerifyPath,
        _ => null
    };


    /// <summary>
    /// Whether <paramref name="flatPath"/> is one of the three protected interface paths, whatever the
    /// method: it tells a known resource under an unsupported method (405) apart from a path this host
    /// does not serve at all (404), which <see cref="RequiredScope"/> folds into one
    /// <see langword="null"/>.
    /// </summary>
    /// <param name="flatPath">The inbound, un-rewritten request path.</param>
    /// <returns><see langword="true"/> when the path is one of the three protected interfaces.</returns>
    private static bool IsMappedInterfacePath(string flatPath) =>
        flatPath is CredentialsIssuePath or CredentialsVerifyPath or PresentationsVerifyPath;


    /// <summary>
    /// The 405 (Method Not Allowed) response for a protected interface path under a method other than
    /// <c>POST</c>, carrying the <c>Allow</c> header RFC 9110
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.5.6">§15.5.6</see>) requires on a
    /// 405, an empty body, and no bearer challenge: admission never runs for it.
    /// </summary>
    /// <returns>A new 405 response naming <c>POST</c> as the one allowed method.</returns>
    private static ServerHttpResponse MethodNotAllowed() =>
        new ServerHttpResponse
        {
            StatusCode = (int)HttpStatusCode.MethodNotAllowed,
            Body = string.Empty,
            ContentType = string.Empty
        }.WithHeader(WellKnownHttpHeaderNames.Allow, WellKnownHttpMethods.Post);


    /// <summary>
    /// Rewrites a stable suite path onto the tenant-scoped <c>/connect/{segment}/...</c> path the
    /// dispatcher's endpoint matchers resolve: the token endpoint to the tenant's token path, the three
    /// VCALM interfaces to their <c>vcalm/...</c> suffixes. Reached only for the four served
    /// combinations; any other path is returned unchanged.
    /// </summary>
    /// <param name="flatPath">The inbound, un-rewritten request path.</param>
    /// <returns>The tenant-scoped dispatch path.</returns>
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

        return suffix is null ? flatPath : $"/connect/{TenantSegment}/{suffix}";
    }


    /// <summary>
    /// Admits or refuses one request against <paramref name="requiredScope"/>: extracts the bearer
    /// token, validates it with the audience binding to <see cref="InstanceAudience"/> through
    /// <see cref="BearerTokenValidation"/>, then checks the granted scope, so the audience is judged
    /// before the scope. A 401 or 403 carries the RFC 6750 §3 <c>WWW-Authenticate</c> challenge for
    /// its failure kind, never an <c>error_description</c>; a 500 server fault passes through with no
    /// challenge, since the challenge answers a refused token, not a fault.
    /// </summary>
    /// <param name="requiredScope">The <c>operation:path</c> scope the request needs.</param>
    /// <param name="incomingRequest">The inbound request, read for its <c>Authorization</c> header.</param>
    /// <param name="exchangeContext">The per-request context bag the validation reads and populates.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The validated payload on success, or the refusal response.</returns>
    private async ValueTask<Result<JwtPayload, ServerHttpResponse>> AdmitBearerAsync(
        string requiredScope,
        IncomingRequest incomingRequest,
        ExchangeContext exchangeContext,
        CancellationToken cancellationToken)
    {
        //Token extraction reads the Authorization header off the context's request and validation
        //resolves the issuer from the context's registration; the dispatcher would set both only for
        //the dispatched request, so admission sets them itself to run before dispatch.
        exchangeContext.SetIncomingRequest(incomingRequest);
        exchangeContext.SetRegistration(Registration);

        //RFC 6750 §3.1: "If the request lacks any authentication information (e.g., the client was
        //unaware that authentication is necessary or attempted using an unsupported authentication
        //method), the resource server SHOULD NOT include an error code or other error information."
        if(!BearerTokenValidation.TryExtractBearer(exchangeContext, out string? bearerToken)
            || string.IsNullOrEmpty(bearerToken))
        {
            return Result<JwtPayload, ServerHttpResponse>.Failure(new ServerHttpResponse
            {
                StatusCode = (int)HttpStatusCode.Unauthorized,
                Body = string.Empty,
                ContentType = string.Empty
            }.WithHeader(WellKnownHttpHeaderNames.WwwAuthenticate, RealmOnlyChallenge));
        }

        (JwtPayload? payload, ServerHttpResponse? validationFailure) = await BearerTokenValidation.ValidateAsync(
            bearerToken, InstanceAudience, Server, Registration, exchangeContext, cancellationToken)
            .ConfigureAwait(false);

        if(validationFailure is not null)
        {
            bool isServerFault = validationFailure.StatusCode == (int)HttpStatusCode.InternalServerError;
            ServerHttpResponse refusal = isServerFault
                ? validationFailure
                : validationFailure.WithHeader(
                    WellKnownHttpHeaderNames.WwwAuthenticate,
                    BearerTokenChallenge.BuildChallenge(realm: InstanceAudience, error: OAuthErrors.InvalidToken));

            return Result<JwtPayload, ServerHttpResponse>.Failure(refusal);
        }

        if(!IsScopeGranted(payload!, requiredScope))
        {
            return Result<JwtPayload, ServerHttpResponse>.Failure(
                ServerHttpResponse.Forbidden(
                    OAuthErrors.InsufficientScope,
                    "The presented access token's scope does not grant this VCALM operation.")
                .WithHeader(
                    WellKnownHttpHeaderNames.WwwAuthenticate,
                    BearerTokenChallenge.BuildChallenge(
                        realm: InstanceAudience, error: OAuthErrors.InsufficientScope, scope: requiredScope)));
        }

        return Result<JwtPayload, ServerHttpResponse>.Success(payload!);
    }


    /// <summary>
    /// Whether <paramref name="payload"/>'s <c>scope</c> claim grants <paramref name="requiredScope"/>
    /// under the <see href="https://www.w3.org/TR/vcalm-1.0/#authorization">VCALM 1.0 OAuth 2.0 scope
    /// syntax</see>, "scope = operation ":" path-absolute (defined in [RFC3986])". The claim is split
    /// on single spaces; a scope token grants only when its operation equals the required operation
    /// exactly (so <c>WRITE</c> is not <c>write</c>, and a <c>write</c> scope never grants a
    /// <c>read</c> requirement) and its path is a non-empty span starting with <c>/</c> and not with
    /// <c>//</c>; such a path grants when it equals the required path, or ends in <c>/</c> and the
    /// required path starts with it, or the required path starts with it followed by <c>/</c>. That
    /// is a segment-boundary reading of the draft's "on the provided path, or on any path that
    /// contains the provided path as a prefix", under which <c>write:/</c> grants every
    /// <c>write:</c> path.
    /// </summary>
    /// <param name="payload">The validated access token payload.</param>
    /// <param name="requiredScope">The <c>operation:path</c> scope the request needs.</param>
    /// <returns><see langword="true"/> when some granted scope token covers the requirement.</returns>
    private static bool IsScopeGranted(JwtPayload payload, string requiredScope)
    {
        int requiredSeparator = requiredScope.IndexOf(':', StringComparison.Ordinal);
        ReadOnlySpan<char> requiredOperation = requiredScope.AsSpan(0, requiredSeparator);
        ReadOnlySpan<char> requiredPath = requiredScope.AsSpan(requiredSeparator + 1);

        if(!payload.TryGetValue(WellKnownJwtClaimNames.Scope, out object? scopeValue)
            || scopeValue is not string scopeClaim
            || string.IsNullOrEmpty(scopeClaim))
        {
            return false;
        }

        foreach(Range tokenRange in scopeClaim.AsSpan().Split(' '))
        {
            ReadOnlySpan<char> token = scopeClaim.AsSpan(tokenRange);
            int separator = token.IndexOf(':');
            if(separator < 0)
            {
                continue;
            }

            ReadOnlySpan<char> operation = token[..separator];
            ReadOnlySpan<char> path = token[(separator + 1)..];

            //RFC 3986 path-absolute is "/" optionally followed by a non-empty first segment, so an
            //empty path ("write:") and a path starting with "//" are not path-absolute and grant nothing.
            bool isPathAbsolute = !path.IsEmpty && path[0] == '/' && !path.StartsWith("//");
            if(!isPathAbsolute || !operation.SequenceEqual(requiredOperation))
            {
                continue;
            }

            bool isExactMatch = path.SequenceEqual(requiredPath);
            bool isTrailingSlashPrefix = path.EndsWith("/") && requiredPath.StartsWith(path);
            bool isSegmentBoundaryPrefix = requiredPath.Length > path.Length
                && requiredPath.StartsWith(path)
                && requiredPath[path.Length] == '/';

            if(isExactMatch || isTrailingSlashPrefix || isSegmentBoundaryPrefix)
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Builds the dispatcher's view of the request without its body: the method, the un-rewritten
    /// path, the headers and the query-string fields. Admission needs only these, so the body is read
    /// after it (<see cref="ReadBoundedBodyAsync"/>) and attached by <see cref="AttachBody"/>.
    /// </summary>
    /// <param name="request">The inbound HTTP request.</param>
    /// <param name="method">The inbound request method.</param>
    /// <param name="flatPath">The inbound, un-rewritten request path.</param>
    /// <returns>The body-less request.</returns>
    private static IncomingRequest BuildIncomingRequest(HttpRequest request, string method, string flatPath)
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

        return new IncomingRequest(
            Path: flatPath,
            Method: method,
            Fields: fields,
            Headers: MapHeaders(request.Headers),
            RouteValues: RouteValues.Empty);
    }


    /// <summary>
    /// The largest request body this host buffers for the request being answered, in octets: the
    /// VCALM endpoints' currently published <see cref="VcalmIntegration.VcalmMaxRequestBytes"/> plus
    /// <see cref="BufferingMarginLength"/>, saturating at <see cref="long.MaxValue"/>. The endpoints'
    /// cap is live configuration an alteration may change under traffic, so it is read for each
    /// request rather than fixed at construction, and the host's bound follows it.
    /// </summary>
    /// <returns>The host's buffering bound for this request.</returns>
    private long ResolveMaximumBodyLength()
    {
        long endpointCap = Server.Vcalm().VcalmMaxRequestBytes;

        return endpointCap > long.MaxValue - BufferingMarginLength
            ? long.MaxValue
            : endpointCap + BufferingMarginLength;
    }


    /// <summary>
    /// Reads the request body, refusing it with 413 (Payload Too Large), an empty body and no
    /// challenge once it exceeds <paramref name="maximumBodyLength"/>: at once when the declared
    /// <c>Content-Length</c> is larger, otherwise as soon as the buffered octets pass the bound, so an
    /// undeclared (chunked) body is never buffered beyond it either. A body within the bound is
    /// dispatched, and the VCALM endpoint judges it against its own, lower cap.
    /// </summary>
    /// <param name="request">The inbound HTTP request.</param>
    /// <param name="maximumBodyLength">The bound <see cref="ResolveMaximumBodyLength"/> resolved for this request.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The body octets, or the 413 refusal.</returns>
    private static async ValueTask<Result<byte[], ServerHttpResponse>> ReadBoundedBodyAsync(
        HttpRequest request, long maximumBodyLength, CancellationToken cancellationToken)
    {
        ServerHttpResponse payloadTooLarge = new()
        {
            StatusCode = (int)HttpStatusCode.RequestEntityTooLarge,
            Body = string.Empty,
            ContentType = string.Empty
        };

        if(request.ContentLength is long declaredLength && declaredLength > maximumBodyLength)
        {
            return Result<byte[], ServerHttpResponse>.Failure(payloadTooLarge);
        }

        PipeReader reader = request.BodyReader;
        while(true)
        {
            ReadResult result = await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            ReadOnlySequence<byte> buffered = result.Buffer;
            if(buffered.Length > maximumBodyLength)
            {
                reader.AdvanceTo(buffered.Start, buffered.End);

                return Result<byte[], ServerHttpResponse>.Failure(payloadTooLarge);
            }

            if(result.IsCompleted)
            {
                byte[] bodyBytes = buffered.ToArray();
                reader.AdvanceTo(buffered.End);

                return Result<byte[], ServerHttpResponse>.Success(bodyBytes);
            }

            reader.AdvanceTo(buffered.Start, buffered.End);
        }
    }


    /// <summary>
    /// Attaches the buffered body to <paramref name="request"/>: a form-urlencoded body (the token
    /// request) is parsed into its fields, any other non-empty body (the JSON VCALM documents) is
    /// carried as <see cref="RequestBody"/>.
    /// </summary>
    /// <param name="request">The body-less request <see cref="BuildIncomingRequest"/> produced.</param>
    /// <param name="bodyBytes">The body octets <see cref="ReadBoundedBodyAsync"/> read.</param>
    /// <param name="contentType">The request's <c>Content-Type</c>, or <see langword="null"/>.</param>
    /// <returns>The request with its body attached.</returns>
    private static IncomingRequest AttachBody(IncomingRequest request, byte[] bodyBytes, string? contentType)
    {
        string mediaType = contentType ?? string.Empty;
        if(bodyBytes.Length == 0)
        {
            return request;
        }

        if(IsFormEncoded(mediaType))
        {
            ParseFormUrlEncoded(System.Text.Encoding.UTF8.GetString(bodyBytes), request.Fields);

            return request;
        }

        return request with
        {
            Body = new RequestBody
            {
                Bytes = bodyBytes,
                ContentType = mediaType
            }
        };
    }


    /// <summary>
    /// Writes <paramref name="response"/> onto the HTTP response: its status, content type,
    /// <c>Location</c>, headers and body. A response with an empty body writes no body octets.
    /// </summary>
    /// <param name="response">The response to write.</param>
    /// <param name="httpResponse">The HTTP response being written.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task that completes when the response has been written.</returns>
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
            await httpResponse.Body.WriteAsync(bodyBytes, cancellationToken).ConfigureAwait(false);
        }
    }


    /// <summary>
    /// Copies the inbound headers into the dispatcher's case-insensitive <see cref="RequestHeaders"/>.
    /// </summary>
    /// <param name="source">The inbound HTTP headers.</param>
    /// <returns>The mapped headers.</returns>
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


    /// <summary>
    /// Parses an <c>application/x-www-form-urlencoded</c> body into <paramref name="fields"/>,
    /// unescaping each name and value and skipping a pair without a name.
    /// </summary>
    /// <param name="body">The decoded body text.</param>
    /// <param name="fields">The fields the pairs are added to.</param>
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


    /// <summary>
    /// Whether <paramref name="contentType"/> names the form-urlencoded media type, parameters allowed.
    /// </summary>
    /// <param name="contentType">The request's content type.</param>
    /// <returns><see langword="true"/> for a form-urlencoded body.</returns>
    private static bool IsFormEncoded(string contentType) =>
        contentType.StartsWith(
            WellKnownMediaTypes.Application.FormUrlEncoded,
            StringComparison.OrdinalIgnoreCase);
}
