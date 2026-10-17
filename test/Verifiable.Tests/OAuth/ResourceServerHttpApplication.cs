using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Primitives;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.OAuth;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.ProtectedResource;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Maps inbound HTTP requests for the test resource server to the
/// validator composition. Parallel of
/// <see cref="AuthorizationServerHttpApplication"/>; minimal mapping
/// layer, no DI container, no middleware pipeline. Hosts the
/// <c>/protected</c>, <c>/protected/records</c> and <c>/protected/items/{item}</c> endpoints that exercise
/// <see cref="JwsAccessTokenValidator"/> and presents the token's binding to
/// <see cref="DpopResourceAccess.DecideAsync"/>, plus the RFC 9728 Section 3
/// <c>/.well-known/oauth-protected-resource</c> location whose document
/// bytes come from the library's
/// <see cref="ProtectedResourceMetadataEndpoints"/> builder through
/// <see cref="EndpointServer.DispatchAsync"/>.
/// </summary>
/// <remarks>
/// <para>
/// Challenge surfaces: every Bearer-scheme <c>401</c> and the
/// <c>403</c> <c>insufficient_scope</c> refusal carry a
/// <c>WWW-Authenticate</c> value built by
/// <see cref="BearerTokenChallenge.BuildChallenge"/> (RFC 6750 §3) with the
/// RFC 9728 §5.1 <c>resource_metadata</c> parameter pointing at this
/// resource server's own metadata URL. Every answer to a DPoP-bound token, and
/// every DPoP-scheme challenge (RFC 9449 Section 7.1), is the decision's response the
/// library composed, with this resource's realm, scope and metadata URL. The one <c>Authorization</c> field line is
/// read through <see cref="AuthorizationFieldReading"/> as the library's resources read it: the scheme compared
/// case-insensitively (RFC 9110 Section 11.1) and the credentials held to a token68 (RFC 6750 Section 2.1, RFC 9449
/// Section 7.1), a field naming another scheme carrying no access token, answered, as one naming a scheme alone and as a
/// request with no <c>Authorization</c> field, as missing credentials: 401 with both challenges and no error where the
/// requirement below is not set, as the library's resources answer it; a <c>Bearer</c> or <c>DPoP</c> line whose
/// credentials are no token68 is answered 400 <c>invalid_request</c> with the named scheme's challenge alone, as the
/// library's resources answer it, except a <c>Bearer</c> line under the requirement below. A token failing validation
/// under the <c>DPoP</c> scheme is answered with the <c>DPoP</c> challenge carrying <c>invalid_token</c>. When the resource
/// requires DPoP-bound access tokens, the answers that never reach the decision, a request
/// without credentials, a malformed field, a <c>Bearer</c> presentation, refused before its
/// token is validated, and a token failing validation, carry the same <c>DPoP</c> challenge
/// alone, as the library's resources answer them. An <c>Authorization</c> field sent on two or
/// more lines is answered 400 <c>invalid_request</c> before any token is validated, as the
/// library's resources answer it: with the <c>DPoP</c> challenge under the requirement or where
/// every line names <c>DPoP</c>, the <c>Bearer</c> challenge where every line names
/// <c>Bearer</c>, and both for lines naming two schemes.
/// </para>
/// <para>
/// Span decoration: token-validated and scope-checked outcomes are attached
/// to <see cref="Activity.Current"/> via
/// <see cref="ResourceServerTagNames"/>/<see cref="ResourceServerEventNames"/>
/// so a trace listener observing the hosting spans sees the resource server's
/// decisions inside the request span.
/// </para>
/// </remarks>
[DebuggerDisplay("ResourceServerHttpApplication")]
internal sealed class ResourceServerHttpApplication: IHttpApplication<HttpContext>
{
    private const string BearerScheme = "Bearer";
    private const string DpopScheme = "DPoP";

    /// <summary>The RFC 6750 §3 <c>realm</c> value every Bearer challenge from this host carries.</summary>
    private const string ProtectedRealm = "protected";

    /// <summary>
    /// The protected paths this resource serves, matched exactly: <c>/protected</c> and a second route,
    /// <c>/protected/records</c>, so a row can present one proof's <c>jti</c> at two target URIs of one resource server.
    /// </summary>
    private static IReadOnlyList<string> ProtectedPaths { get; } = ["/protected", "/protected/records"];

    /// <summary>
    /// The prefix of the protected item route, <c>/protected/items/{item}</c>: one path segment after it names an item,
    /// matched as the request's path keeps it, so a percent-encoding in the segment reaches the target URI as sent.
    /// </summary>
    private static string ItemPathPrefix { get; } = "/protected/items/";

    private ResourceServerIntegration Integration { get; }
    private VerificationDelegate VerifySignature { get; }
    private string? RequiredScope { get; }

    /// <summary>Whether <c>/protected</c> always requires DPoP-bound access tokens (RFC 9728 Section 2, <c>dpop_bound_access_tokens_required</c>).</summary>
    private bool RequiresDpop { get; }

    /// <summary>Answers the scheme and authority the resource names its target URIs under, the configured origin, never the request's <c>Host</c>.</summary>
    private Func<Uri?> ResolveTargetAuthority { get; }

    /// <summary>
    /// Receives, for every request whose decision <see cref="DpopResourceAccess.DecideAsync"/> answered, the activity
    /// current in this application when the call returned and whether it had stopped by then, or <see langword="null"/>
    /// when the host observes nothing.
    /// </summary>
    private ConcurrentQueue<(Activity? Activity, bool IsStopped)>? AmbientActivitiesAfterDecision { get; }

    /// <summary>
    /// The RFC 9728 serving surface, assigned by
    /// <see cref="TestResourceServerShell.StartHttpHostAsync"/> once the
    /// listener is bound and the resource identity (scheme://host:port) is
    /// known. While unset — only possible before the shell returns from
    /// startup — the metadata path is unrouted and challenges omit the
    /// <c>resource_metadata</c> parameter, the same fail-closed posture the
    /// co-located SSF transmitter takes when the metadata capability is
    /// inactive.
    /// </summary>
    public ResourceServerMetadataEndpoint? MetadataEndpoint { get; set; }


    /// <summary>
    /// Creates the application over the resource server's slots: the access tokens it validates, the target URIs it
    /// names its resource by, the scope it requires and whether it requires DPoP-bound access tokens.
    /// </summary>
    /// <param name="integration">The resource server's trust, clock and DPoP slots.</param>
    /// <param name="verifySignature">The signature verification access tokens are checked with.</param>
    /// <param name="resolveTargetAuthority">Answers the configured origin the resource's target URIs are named under.</param>
    /// <param name="requiredScope">The scope a token must carry, or <see langword="null"/> for none.</param>
    /// <param name="requiresDpop">Whether <c>/protected</c> always requires DPoP-bound access tokens.</param>
    /// <param name="ambientActivitiesAfterDecision">
    /// Receives the activity current when each decision returned and whether it had stopped then, or
    /// <see langword="null"/> to observe nothing.
    /// </param>
    public ResourceServerHttpApplication(
        ResourceServerIntegration integration,
        VerificationDelegate verifySignature,
        Func<Uri?> resolveTargetAuthority,
        string? requiredScope = null,
        bool requiresDpop = false,
        ConcurrentQueue<(Activity? Activity, bool IsStopped)>? ambientActivitiesAfterDecision = null)
    {
        ArgumentNullException.ThrowIfNull(integration);
        ArgumentNullException.ThrowIfNull(verifySignature);
        ArgumentNullException.ThrowIfNull(resolveTargetAuthority);
        this.Integration = integration;
        this.VerifySignature = verifySignature;
        this.ResolveTargetAuthority = resolveTargetAuthority;
        this.RequiredScope = requiredScope;
        this.RequiresDpop = requiresDpop;
        this.AmbientActivitiesAfterDecision = ambientActivitiesAfterDecision;
    }


    public HttpContext CreateContext(IFeatureCollection contextFeatures) =>
        new DefaultHttpContext(contextFeatures);


    public async Task ProcessRequestAsync(HttpContext context)
    {
        try
        {
            await ProcessRequestCoreAsync(context).ConfigureAwait(false);
        }
        catch(Exception ex)
        {
            //Tests rely on seeing the failure reason; production hosts would
            //surface this through telemetry rather than the response body.
            context.Response.StatusCode = StatusCodes.Status500InternalServerError;
            context.Response.ContentType = "text/plain";
            await WriteBodyAsync(
                context,
                $"Handler threw: {ex.GetType().FullName}: {ex.Message}\n{ex.StackTrace}").ConfigureAwait(false);
        }
    }


    /// <summary>
    /// Answers one request: the metadata document at its location, 404 for any path but the three protected ones
    /// (<c>/protected</c>, <c>/protected/records</c> and <c>/protected/items/{item}</c>, <see cref="IsProtectedPath"/>),
    /// and at a protected path the token validated by <see cref="JwsAccessTokenValidator"/>, its binding presented to
    /// <see cref="DpopResourceAccess.DecideAsync"/> and the decision's refusal written, then the scope checked and the
    /// claims served. Under <see cref="RequiresDpop"/> a request without credentials, a malformed
    /// <c>Authorization</c> field and a <c>Bearer</c> presentation, before its token is validated, are answered with the
    /// <c>DPoP</c> challenge alone and no error, as the library's resources answer them; otherwise a request without the
    /// field and a field carrying no access token with both challenges and no error
    /// (<see cref="WriteMissingCredentialsChallengeAsync"/>). A <c>DPoP</c> presentation of a token that fails validation
    /// is answered with the <c>DPoP</c> challenge
    /// carrying <c>invalid_token</c>. An <c>Authorization</c> field sent on two or more lines is answered 400
    /// <c>invalid_request</c> before any token is validated (<see cref="WriteRepeatedAuthorizationRefusalAsync"/>), and a
    /// <c>Bearer</c> or <c>DPoP</c> credential outside token68 400 <c>invalid_request</c> with the named scheme's challenge
    /// (<see cref="WriteCredentialOutsideToken68RefusalAsync"/>).
    /// </summary>
    /// <param name="context">The request's context.</param>
    /// <returns>A task that completes when the answer is written.</returns>
    private async Task ProcessRequestCoreAsync(HttpContext context)
    {
        if(MetadataEndpoint is { } metadataEndpoint
            && string.Equals(context.Request.Path, metadataEndpoint.MetadataUrl.AbsolutePath, StringComparison.Ordinal))
        {
            await ServeProtectedResourceMetadataAsync(context, metadataEndpoint).ConfigureAwait(false);
            return;
        }

        if(!IsProtectedPath(context.Request.Path.Value ?? string.Empty))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        if(!context.Request.Headers.ContainsKey("Authorization"))
        {
            //RFC 6750 §3: a request without any authentication information is
            //challenged WITHOUT an error code; the RFC 9728 §5.1
            //resource_metadata parameter still rides the challenge so the
            //client can start metadata discovery from this response alone.
            //RFC 9449 Section 7.1: a protection space requiring DPoP
            //authentication challenges for DPoP alone; otherwise both schemes
            //are challenged (RFC 9449 Section 7.2, Figure 17), as the library's
            //resources answer it.
            if(RequiresDpop)
            {
                await WriteDpopChallengeAsync(context, ServerHttpResponse.Unauthorized(), error: null).ConfigureAwait(false);

                return;
            }

            await WriteMissingCredentialsChallengeAsync(context).ConfigureAwait(false);

            return;
        }

        //RFC 9110 Section 11.6.2: "Authorization = credentials" is no list, so a field on two or more lines is a
        //malformed request, answered before any token is validated (RFC 6750 Section 3.1, invalid_request).
        StringValues authorizationLines = context.Request.Headers.Authorization;
        if(authorizationLines.Count > 1)
        {
            await WriteRepeatedAuthorizationRefusalAsync(context, authorizationLines).ConfigureAwait(false);

            return;
        }

        //RFC 6750 Section 3.1: an access token credential outside the token68 form is "otherwise malformed",
        //invalid_request, delivered in the challenge of the scheme the line names (RFC 9449 Section 7.2). Under the
        //requirement a Bearer credential of any shape attempted a method this resource does not accept and is answered
        //below with the DPoP challenge alone, as the library's resources answer them.
        if(IsCredentialOutsideToken68(context.Request, out bool isDpopCredential) && (isDpopCredential || !RequiresDpop))
        {
            await WriteCredentialOutsideToken68RefusalAsync(context, isDpopCredential).ConfigureAwait(false);

            return;
        }

        if(!TryExtractAuthorization(context.Request, out string scheme, out string? accessToken))
        {
            //A field naming a scheme alone or a scheme this resource does not support carries no access token: the
            //request lacks authentication information (RFC 6750 Section 3.1), answered with no error, under the
            //requirement with the DPoP challenge alone and otherwise with both challenges (RFC 9449 Section 7.2,
            //Figure 17), as the library's resources answer it.
            if(RequiresDpop)
            {
                await WriteDpopChallengeAsync(context, ServerHttpResponse.Unauthorized(), error: null).ConfigureAwait(false);

                return;
            }

            await WriteMissingCredentialsChallengeAsync(context).ConfigureAwait(false);

            return;
        }

        bool isDpopPresentation = string.Equals(scheme, DpopScheme, StringComparison.OrdinalIgnoreCase);

        //RFC 9449 Section 7.1 and RFC 6750 Section 3.1: under the requirement a Bearer presentation attempted a method
        //this resource does not accept, answered with the DPoP challenge alone and no error before its token is
        //validated, as the library's resources answer it.
        if(RequiresDpop && !isDpopPresentation)
        {
            await WriteDpopChallengeAsync(context, ServerHttpResponse.Unauthorized(), error: null).ConfigureAwait(false);

            return;
        }

        ExchangeContext exchangeContext = [];

        JwsAccessTokenValidationResult tokenResult = await JwsAccessTokenValidator.ValidateAsync(
            accessToken!,
            Integration.TrustedIssuer.OriginalString,
            Integration.ExpectedAudience,
            Integration.ResolveVerificationKeyAsync,
            VerifySignature,
            JwsAccessTokenTestSupport.Parser,
            TestSetup.Base64UrlDecoder,
            Integration.TimeProvider,
            BaseMemoryPool.Shared,
            Integration.AccessTokenIatSkew,
            tenantId: default,
            exchangeContext,
            expectedAuthorizedParty: null,
            context.RequestAborted).ConfigureAwait(false);

        if(!tokenResult.IsSuccess)
        {
            _ = (Activity.Current?.SetTag(ResourceServerTagNames.TokenValidated, false));
            _ = (Activity.Current?.AddEvent(new ActivityEvent(ResourceServerEventNames.TokenRejected)));

            //A DPoP presentation of a token failing validation, the only presentation that reaches validation under the
            //requirement, is answered with invalid_token in the DPoP challenge, the challenge of the mechanism attempted
            //(RFC 9449 Section 7.1: an error parameter "if the request included an access token but failed
            //authentication"; Section 7.2: "the corresponding challenge SHOULD be used to deliver error information"),
            //as the library's resources answer it.
            if(isDpopPresentation)
            {
                await WriteDpopChallengeAsync(
                    context,
                    ServerHttpResponse.Unauthorized(OAuthErrors.InvalidToken, tokenResult.FailureDescription ?? "Access token validation failed."),
                    OAuthErrors.InvalidToken).ConfigureAwait(false);

                return;
            }

            await WriteBearerChallengeAsync(
                context, StatusCodes.Status401Unauthorized,
                OAuthErrors.InvalidToken,
                tokenResult.FailureDescription ?? "Access token validation failed.",
                scope: null).ConfigureAwait(false);
            return;
        }

        _ = (Activity.Current?.SetTag(ResourceServerTagNames.TokenValidated, true));
        _ = (Activity.Current?.AddEvent(new ActivityEvent(ResourceServerEventNames.TokenValidated)));

        JwsAccessTokenClaims claims = tokenResult.Claims!;

        //RFC 9449 Section 7.1: the token's binding, the request's DPoP field lines and the resource's own protection
        //space go to the library's composition of the resource checks, which answers a permit or the exact refusal.
        Uri targetAuthority = ResolveTargetAuthority()
            ?? throw new InvalidOperationException("The resource server names no target authority before its listener is bound.");
        DpopResourceDecision decision = await DpopResourceAccess.DecideAsync(
            Integration,
            new DpopResourceRequest
            {
                AccessToken = accessToken!,
                IsDpopPresentation = isDpopPresentation,
                IsSenderConstrained = claims.Confirmation is not null,
                BoundThumbprint = claims.Confirmation?.JwkThumbprint,
                HttpMethod = context.Request.Method,
                TargetUri = new Uri(targetAuthority.GetLeftPart(UriPartial.Authority) + context.Request.Path.ToUriComponent()),
                DpopFieldLines = context.Request.Headers.TryGetValue("DPoP", out StringValues dpopFieldLines)
                    ? [.. dpopFieldLines.Select(static line => line ?? string.Empty)]
                    : [],
                IsDpopBoundAccessTokenRequired = RequiresDpop,
                Realm = ProtectedRealm,
                Scope = RequiredScope,
                ResourceMetadata = MetadataEndpoint?.MetadataUrl
            },
            exchangeContext,
            context.RequestAborted).ConfigureAwait(false);
        Activity? afterDecision = Activity.Current;
        AmbientActivitiesAfterDecision?.Enqueue((afterDecision, afterDecision?.IsStopped ?? false));
        if(!decision.IsPermitted)
        {
            ServerHttpResponse refusal = decision.Response!;
            _ = (Activity.Current?.SetTag(ResourceServerTagNames.ChallengeError, refusal.ErrorCode));
            await WriteServerResponseAsync(context, refusal).ConfigureAwait(false);

            return;
        }

        if(RequiredScope is not null)
        {
            bool isScopeSatisfied = HasScope(claims.Scope, RequiredScope);
            _ = (Activity.Current?.SetTag(ResourceServerTagNames.ScopeRequired, RequiredScope));
            _ = (Activity.Current?.SetTag(ResourceServerTagNames.ScopeSatisfied, isScopeSatisfied));
            _ = (Activity.Current?.AddEvent(new ActivityEvent(ResourceServerEventNames.ScopeChecked)));

            if(!isScopeSatisfied)
            {
                //RFC 6750 §3.1: insufficient_scope maps to 403 and the
                //challenge's scope attribute names the scope necessary to
                //access the resource.
                await WriteBearerChallengeAsync(
                    context, StatusCodes.Status403Forbidden,
                    OAuthErrors.InsufficientScope,
                    "The access token does not carry the scope this resource requires.",
                    scope: RequiredScope).ConfigureAwait(false);
                return;
            }
        }

        await WriteClaimsAsync(context, claims).ConfigureAwait(false);
    }


    public void DisposeContext(HttpContext context, Exception? exception) { }


    /// <summary>
    /// Serves the RFC 9728 §3 metadata document by dispatching the request
    /// through <see cref="ResourceServerMetadataEndpoint.Server"/> — the
    /// document bytes are produced by
    /// <see cref="ProtectedResourceMetadataEndpoints"/> exactly as a
    /// co-located deployment would produce them: capability gate, path/method
    /// matcher, §3.2 emission. This skin only maps the wire envelope in and
    /// the <see cref="ServerHttpResponse"/> out.
    /// </summary>
    private static async Task ServeProtectedResourceMetadataAsync(
        HttpContext context, ResourceServerMetadataEndpoint metadataEndpoint)
    {
        IncomingRequest incomingRequest = new(
            Path: context.Request.Path.HasValue ? context.Request.Path.Value : string.Empty,
            Method: context.Request.Method,
            Fields: new RequestFields(),
            Headers: RequestHeaders.Empty,
            RouteValues: RouteValues.Empty);

        ServerHttpResponse response = await metadataEndpoint.Server.DispatchAsync(
            incomingRequest, [], context.RequestAborted).ConfigureAwait(false);

        await WriteServerResponseAsync(context, response).ConfigureAwait(false);
    }


    /// <summary>
    /// Maps a library <see cref="ServerHttpResponse"/> onto the wire: its status, content type, location, every header
    /// field it carries and its body, so the answer the library composed is the answer sent.
    /// </summary>
    /// <param name="context">The request's context.</param>
    /// <param name="response">The answer to write.</param>
    /// <returns>A task that completes when the answer is written.</returns>
    private static async Task WriteServerResponseAsync(HttpContext context, ServerHttpResponse response)
    {
        context.Response.StatusCode = response.StatusCode;
        if(!string.IsNullOrEmpty(response.ContentType))
        {
            context.Response.ContentType = response.ContentType;
        }

        if(!string.IsNullOrEmpty(response.Location))
        {
            context.Response.Headers.Location = response.Location;
        }

        foreach(KeyValuePair<string, string> header in response.Headers)
        {
            context.Response.Headers.Append(header.Key, header.Value);
        }

        if(!string.IsNullOrEmpty(response.Body))
        {
            await WriteBodyAsync(context, response.Body).ConfigureAwait(false);
        }
    }


    /// <summary>
    /// Whether <paramref name="path"/>, the request's path as received, is one this resource protects: one of
    /// <see cref="ProtectedPaths"/>, or <see cref="ItemPathPrefix"/> followed by one non-empty path segment.
    /// </summary>
    /// <param name="path">The request's path.</param>
    /// <returns><see langword="true"/> when the path is protected.</returns>
    private static bool IsProtectedPath(string path)
    {
        if(ProtectedPaths.Contains(path, StringComparer.Ordinal))
        {
            return true;
        }

        return path.StartsWith(ItemPathPrefix, StringComparison.Ordinal)
            && path.Length > ItemPathPrefix.Length
            && !path.AsSpan(ItemPathPrefix.Length).Contains('/');
    }


    /// <summary>
    /// Reads the access token of the request's one <c>Authorization</c> field line as the library's resources read it,
    /// through <see cref="AuthorizationFieldReading"/>: the scheme is <c>Bearer</c> or <c>DPoP</c>, compared
    /// case-insensitively (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.1">RFC 9110 Section 11.1</see>:
    /// "It uses a case-insensitive token to identify the authentication scheme:"), and the credentials are a token68
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6750#section-2.1">RFC 6750 Section 2.1</see>: "credentials =
    /// "Bearer" 1*SP b64token"; <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>:
    /// "credentials = "DPoP" 1*SP token68"). A field naming another scheme, or credentials that are no token68, carries
    /// no access token.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <param name="scheme">The scheme the field names, as sent, or empty when the field carries no access token.</param>
    /// <param name="token">The access token, or <see langword="null"/> when the field carries none.</param>
    /// <returns><see langword="true"/> when the field carries an access token under <c>Bearer</c> or <c>DPoP</c>.</returns>
    private static bool TryExtractAuthorization(
        HttpRequest request, out string scheme, out string? token)
    {
        scheme = string.Empty;
        token = null;

        StringValues lines = request.Headers.Authorization;
        if(lines.Count == 0)
        {
            return false;
        }

        Dictionary<string, string[]> fieldLines = new(StringComparer.Ordinal)
        {
            [WellKnownHttpHeaderNames.Authorization] = [.. lines.Select(static line => line ?? string.Empty)]
        };
        AuthorizationFieldReading reading = AuthorizationFieldReading.Read(new RequestHeaders(fieldLines));
        bool isAccessTokenScheme = reading.IsScheme(BearerScheme) || reading.IsScheme(DpopScheme);
        if(!isAccessTokenScheme || !reading.HasToken68Credentials)
        {
            return false;
        }

        scheme = reading.Scheme!;
        token = reading.Credentials;

        return true;
    }


    /// <summary>
    /// Whether the request's one <c>Authorization</c> field line names an access token scheme, <c>Bearer</c> or
    /// <c>DPoP</c> compared case-insensitively, with credentials that are no token68, read through
    /// <see cref="AuthorizationFieldReading"/> as the library's resources read it; a line naming the scheme alone carries
    /// no credentials and is no such attempt.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <param name="isDpopScheme">Whether the line names the <c>DPoP</c> scheme.</param>
    /// <returns><see langword="true"/> when the line attempts an access token scheme with a malformed credential.</returns>
    private static bool IsCredentialOutsideToken68(HttpRequest request, out bool isDpopScheme)
    {
        StringValues lines = request.Headers.Authorization;
        Dictionary<string, string[]> fieldLines = new(StringComparer.Ordinal)
        {
            [WellKnownHttpHeaderNames.Authorization] = [.. lines.Select(static line => line ?? string.Empty)]
        };
        AuthorizationFieldReading reading = lines.Count == 1 ? AuthorizationFieldReading.Read(new RequestHeaders(fieldLines)) : default;
        isDpopScheme = reading.IsScheme(DpopScheme);

        return (isDpopScheme || reading.IsScheme(BearerScheme))
            && reading.Credentials is { Length: > 0 }
            && !reading.HasToken68Credentials;
    }


    /// <summary>
    /// Writes the answer to an access token credential outside the token68 form: 400 with the body
    /// <c>{"error":"invalid_request","error_description":"The Authorization header credentials are not a token68."}</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>: "invalid_request ...
    /// or is otherwise malformed. The resource server SHOULD respond with the HTTP 400 (Bad Request) status code.") and
    /// the challenge of the scheme the line names alone carrying that error
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449 Section 7.2</see>: "If the mechanism used
    /// to attempt authentication could be established unambiguously, then the corresponding challenge SHOULD be used to
    /// deliver error information (Figure 18)."): this resource's <c>DPoP</c> challenge with the exposure field, or its
    /// <c>Bearer</c> challenge with the realm and the metadata URL and no exposure field.
    /// </summary>
    /// <param name="context">The request's context.</param>
    /// <param name="isDpopScheme">Whether the line names the <c>DPoP</c> scheme.</param>
    /// <returns>A task that completes when the answer is written.</returns>
    private Task WriteCredentialOutsideToken68RefusalAsync(HttpContext context, bool isDpopScheme)
    {
        ServerHttpResponse refusal = ServerHttpResponse.BadRequest(
            OAuthErrors.InvalidRequest, "The Authorization header credentials are not a token68.");
        _ = (Activity.Current?.SetTag(ResourceServerTagNames.ChallengeError, OAuthErrors.InvalidRequest));

        return isDpopScheme switch
        {
            true => WriteDpopChallengeAsync(context, refusal, OAuthErrors.InvalidRequest),
            false => WriteServerResponseAsync(
                context,
                refusal.WithHeader(
                    WellKnownHttpHeaderNames.WwwAuthenticate,
                    BearerTokenChallenge.BuildChallenge(
                        realm: ProtectedRealm, error: OAuthErrors.InvalidRequest, resourceMetadata: MetadataEndpoint?.MetadataUrl)))
        };
    }


    /// <summary>
    /// Whether the RFC 6749 §3.3 space-delimited <paramref name="grantedScopes"/>
    /// list contains <paramref name="requiredScope"/> as a whole scope token,
    /// compared ordinally.
    /// </summary>
    private static bool HasScope(string? grantedScopes, string requiredScope)
    {
        if(string.IsNullOrEmpty(grantedScopes))
        {
            return false;
        }

        ReadOnlySpan<char> granted = grantedScopes.AsSpan();
        foreach(Range segmentRange in granted.Split(' '))
        {
            if(granted[segmentRange].SequenceEqual(requiredScope))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Writes a Bearer-scheme refusal whose <c>WWW-Authenticate</c> value is
    /// built by <see cref="BearerTokenChallenge.BuildChallenge"/> (RFC 6750 §3)
    /// and carries the RFC 9728 §5.1 <c>resource_metadata</c> parameter when
    /// the metadata surface is live. The caller owns the 401-vs-403 mapping;
    /// this writer owns only the header value.
    /// </summary>
    private Task WriteBearerChallengeAsync(
        HttpContext context, int statusCode, string? error, string? errorDescription, string? scope)
    {
        string challenge = BearerTokenChallenge.BuildChallenge(
            realm: ProtectedRealm,
            error: error,
            errorDescription: SanitizeErrorDescription(errorDescription),
            scope: scope,
            resourceMetadata: MetadataEndpoint?.MetadataUrl);

        context.Response.StatusCode = statusCode;
        context.Response.Headers.Append(WellKnownHttpHeaderNames.WwwAuthenticate, challenge);
        if(error is not null)
        {
            _ = (Activity.Current?.SetTag(ResourceServerTagNames.ChallengeError, error));
        }

        return Task.CompletedTask;
    }


    /// <summary>
    /// Writes <paramref name="refusal"/> with the resource's <c>DPoP</c> challenge as its one <c>WWW-Authenticate</c>
    /// value, built by <see cref="DpopChallenge.BuildChallenge"/> with this resource's realm, <paramref name="error"/>, its
    /// scope, the algorithms it accepts and its metadata URL, the challenge <see cref="DpopResourceAccess.DecideAsync"/>
    /// writes, and the field <c>Access-Control-Expose-Headers: WWW-Authenticate, DPoP-Nonce</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "including
    /// WWW-Authenticate in the Access-Control-Expose-Headers response header list value").
    /// </summary>
    /// <param name="context">The request's context.</param>
    /// <param name="refusal">The refusal's status and body.</param>
    /// <param name="error">The challenge's <c>error</c>, or <see langword="null"/> for none.</param>
    /// <returns>A task that completes when the answer is written.</returns>
    private Task WriteDpopChallengeAsync(HttpContext context, ServerHttpResponse refusal, string? error)
    {
        string challenge = BuildDpopChallenge(error);
        if(error is not null)
        {
            _ = (Activity.Current?.SetTag(ResourceServerTagNames.ChallengeError, error));
        }

        return WriteServerResponseAsync(
            context,
            refusal
                .WithHeader(WellKnownHttpHeaderNames.WwwAuthenticate, challenge)
                .WithHeader(WellKnownHttpHeaderNames.AccessControlExposeHeaders, ExposedDpopResponseFields));
    }


    /// <summary>
    /// Writes the answer to a request with no <c>Authorization</c> field, or whose <c>Authorization</c> field carries no
    /// access token, a scheme alone or a scheme this resource does not support, where DPoP-bound access tokens are not
    /// required: 401, an empty body, and one
    /// <c>WWW-Authenticate</c> field line carrying this resource's <c>Bearer</c> challenge and its <c>DPoP</c> challenge,
    /// neither with an <c>error</c>, with the field <c>Access-Control-Expose-Headers: WWW-Authenticate, DPoP-Nonce</c>, as
    /// the library's resources answer missing credentials
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449 Section 7.2</see>: "If no authentication
    /// information has been included with the request, then the challenges SHOULD NOT include an error code or other error
    /// information, as per Section 3.1 of [RFC6750] (Figure 17).").
    /// </summary>
    /// <param name="context">The request's context.</param>
    /// <returns>A task that completes when the answer is written.</returns>
    private Task WriteMissingCredentialsChallengeAsync(HttpContext context)
    {
        string bearerChallenge = BearerTokenChallenge.BuildChallenge(
            realm: ProtectedRealm, resourceMetadata: MetadataEndpoint?.MetadataUrl);

        return WriteServerResponseAsync(
            context,
            ServerHttpResponse.Unauthorized()
                .WithHeader(WellKnownHttpHeaderNames.WwwAuthenticate, $"{bearerChallenge}, {BuildDpopChallenge(error: null)}")
                .WithHeader(WellKnownHttpHeaderNames.AccessControlExposeHeaders, ExposedDpopResponseFields));
    }


    /// <summary>
    /// The <c>DPoP</c> challenge of this resource: <see cref="DpopChallenge.BuildChallenge"/> with its realm
    /// <see cref="ProtectedRealm"/>, <paramref name="error"/>, its scope, the algorithms its integration accepts and its
    /// metadata URL.
    /// </summary>
    /// <param name="error">The challenge's <c>error</c>, or <see langword="null"/> for none.</param>
    /// <returns>The challenge.</returns>
    private string BuildDpopChallenge(string? error) =>
        DpopChallenge.BuildChallenge(
            ProtectedRealm,
            error,
            RequiredScope,
            Integration.AcceptedDpopProofAlgorithms ?? WellKnownDpopValues.SupportedSigningAlgorithms,
            MetadataEndpoint?.MetadataUrl);


    /// <summary>
    /// Writes the answer to an <c>Authorization</c> field sent on two or more lines, before any token is validated: 400,
    /// <c>invalid_request</c> and <see cref="WellKnownOAuthErrorDescriptions.MalformedAuthorizationField"/> in the body,
    /// as the library's resources answer it
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>: "invalid_request The
    /// request is missing a required parameter, includes an unsupported parameter or parameter value, repeats the same
    /// parameter, uses more than one method for including an access token, or is otherwise malformed. The resource
    /// server SHOULD respond with the HTTP 400 (Bad Request) status code."). The challenge carrying the error is the
    /// <c>DPoP</c> one alone under <see cref="RequiresDpop"/>, a protection space accepting the <c>DPoP</c> mechanism
    /// alone, and otherwise the challenge of the mechanism the lines attempt
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449 Section 7.2</see>: "If the mechanism
    /// used to attempt authentication could be established unambiguously, then the corresponding challenge SHOULD be
    /// used to deliver error information (Figure 18)."): the <c>DPoP</c> one alone, with the exposure field, where every
    /// line names <c>DPoP</c>, the <c>Bearer</c> one alone where every line names <c>Bearer</c>, and for lines naming
    /// two schemes both in one field line, the <c>Bearer</c> one first, with the exposure field (Section 7.2:
    /// "Otherwise, both Bearer and DPoP challenges MAY be used to deliver error information (Figure 19).").
    /// </summary>
    /// <param name="context">The request's context.</param>
    /// <param name="authorizationLines">The request's <c>Authorization</c> field lines, two or more.</param>
    /// <returns>A task that completes when the answer is written.</returns>
    private Task WriteRepeatedAuthorizationRefusalAsync(HttpContext context, StringValues authorizationLines)
    {
        ServerHttpResponse refusal = ServerHttpResponse.BadRequest(
            OAuthErrors.InvalidRequest, WellKnownOAuthErrorDescriptions.MalformedAuthorizationField);
        string? sharedScheme = ReadSharedScheme(authorizationLines);
        if(RequiresDpop || string.Equals(sharedScheme, DpopScheme, StringComparison.OrdinalIgnoreCase))
        {
            return WriteDpopChallengeAsync(context, refusal, OAuthErrors.InvalidRequest);
        }

        string bearerChallenge = BearerTokenChallenge.BuildChallenge(
            realm: ProtectedRealm, error: OAuthErrors.InvalidRequest, resourceMetadata: MetadataEndpoint?.MetadataUrl);
        _ = (Activity.Current?.SetTag(ResourceServerTagNames.ChallengeError, OAuthErrors.InvalidRequest));
        ServerHttpResponse answer = string.Equals(sharedScheme, BearerScheme, StringComparison.OrdinalIgnoreCase) switch
        {
            true => refusal.WithHeader(WellKnownHttpHeaderNames.WwwAuthenticate, bearerChallenge),
            false => refusal
                .WithHeader(
                    WellKnownHttpHeaderNames.WwwAuthenticate,
                    $"{bearerChallenge}, {BuildDpopChallenge(OAuthErrors.InvalidRequest)}")
                .WithHeader(WellKnownHttpHeaderNames.AccessControlExposeHeaders, ExposedDpopResponseFields)
        };

        return WriteServerResponseAsync(context, answer);
    }


    /// <summary>
    /// The authentication scheme every <c>Authorization</c> field line names, as the first line sends it, or
    /// <see langword="null"/> when two lines name different schemes, compared case-insensitively
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.1">RFC 9110 Section 11.1</see>: "It uses a
    /// case-insensitive token to identify the authentication scheme"), as the library's resources read a repeated field.
    /// </summary>
    /// <param name="lines">The field lines, two or more.</param>
    /// <returns>The one scheme, or <see langword="null"/>.</returns>
    private static string? ReadSharedScheme(StringValues lines)
    {
        string firstScheme = ReadLineScheme(lines[0]);
        bool isSchemeShared = firstScheme.Length > 0
            && lines.All(line => string.Equals(ReadLineScheme(line), firstScheme, StringComparison.OrdinalIgnoreCase));

        return isSchemeShared ? firstScheme : null;
    }


    /// <summary>
    /// The authentication scheme an <c>Authorization</c> field line names: the token before its first SP, the whole line
    /// without the whitespace around it when it holds none.
    /// </summary>
    /// <param name="line">The field line's value.</param>
    /// <returns>The scheme token, empty for an empty line.</returns>
    private static string ReadLineScheme(string? line)
    {
        ReadOnlySpan<char> value = line.AsSpan().Trim();
        int separator = value.IndexOf(' ');

        return (separator < 0 ? value : value[..separator]).ToString();
    }


    /// <summary>
    /// The value of the <c>Access-Control-Expose-Headers</c> field an answer carrying a <c>DPoP</c> challenge writes: the
    /// challenge's field and the field a resource's nonce rides in, <c>WWW-Authenticate, DPoP-Nonce</c>.
    /// </summary>
    private static string ExposedDpopResponseFields { get; } =
        $"{WellKnownHttpHeaderNames.WwwAuthenticate}, {WellKnownHttpHeaderNames.DPoPNonce}";


    /// <summary>
    /// Restricts a challenge description to the RFC 6750 §3
    /// <c>error_description</c> charset (<c>%x20-21 / %x23-5B / %x5D-7E</c>)
    /// by replacing every other character with a space, so diagnostic text
    /// from validators can ride the challenge without ever producing a value
    /// <see cref="BearerTokenChallenge.BuildChallenge"/> would reject.
    /// </summary>
    private static string? SanitizeErrorDescription(string? description)
    {
        if(string.IsNullOrEmpty(description))
        {
            return null;
        }

        StringBuilder sb = new(description.Length);
        foreach(char c in description)
        {
            bool isAllowed = c is ' ' or '!' or (>= '#' and <= '[') or (>= ']' and <= '~');
            _ = sb.Append(isAllowed ? c : ' ');
        }

        return sb.ToString();
    }


    private static async Task WriteClaimsAsync(HttpContext context, JwsAccessTokenClaims claims)
    {
        Dictionary<string, object?> body = new(StringComparer.Ordinal)
        {
            ["sub"] = claims.Subject,
            ["iss"] = claims.Issuer,
            ["aud"] = claims.Audience,
            ["iat"] = claims.IssuedAt.ToUnixTimeSeconds(),
            ["exp"] = claims.Expiration.ToUnixTimeSeconds(),
        };
        if(claims.NotBefore is not null) { body["nbf"] = claims.NotBefore.Value.ToUnixTimeSeconds(); }
        if(claims.Scope is not null) { body["scope"] = claims.Scope; }
        if(claims.ClientId is not null) { body["client_id"] = claims.ClientId; }
        if(claims.JwtId is not null) { body["jti"] = claims.JwtId; }
        if(claims.Confirmation?.JwkThumbprint is { } jkt)
        {
            body["cnf"] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["jkt"] = jkt
            };
        }

        //RFC 8693 §4.1: the resource echoes the delegation it was shown — the current actor, which is
        //the only party §4.1 lets an access control decision consider, plus the prior actors as the
        //informational history trail this resource attributes the request through.
        if(claims.Act is { } actor)
        {
            Dictionary<string, object> actorBody = new(StringComparer.Ordinal)
            {
                ["sub"] = actor.Subject
            };
            if(actor.Issuer is { } actorIssuer)
            {
                actorBody["iss"] = actorIssuer;
            }

            if(actor.DelegationHistory.Count > 0)
            {
                List<object> priorActors = [];
                foreach(PriorActor prior in actor.DelegationHistory)
                {
                    Dictionary<string, object> priorBody = new(StringComparer.Ordinal)
                    {
                        ["sub"] = prior.Subject
                    };
                    if(prior.Issuer is { } priorIssuer)
                    {
                        priorBody["iss"] = priorIssuer;
                    }

                    priorActors.Add(priorBody);
                }

                actorBody["prior"] = priorActors;
            }

            body["act"] = actorBody;
        }

        byte[] json = JsonSerializer.SerializeToUtf8Bytes(body);
        context.Response.StatusCode = StatusCodes.Status200OK;
        context.Response.ContentType = "application/json";
        context.Response.Headers.CacheControl = "no-store";
        _ = await context.Response.BodyWriter.WriteAsync(json, context.RequestAborted).ConfigureAwait(false);
    }


    /// <summary>
    /// Writes <paramref name="body"/> UTF-8-encoded through the pipe-based
    /// <see cref="HttpResponse.BodyWriter"/> — encoded directly into the
    /// writer's buffer, no intermediate array.
    /// </summary>
    private static async Task WriteBodyAsync(HttpContext context, string body)
    {
        int maxByteCount = Encoding.UTF8.GetMaxByteCount(body.Length);
        Memory<byte> destination = context.Response.BodyWriter.GetMemory(maxByteCount);
        int written = Encoding.UTF8.GetBytes(body, destination.Span);
        context.Response.BodyWriter.Advance(written);
        _ = await context.Response.BodyWriter.FlushAsync(context.RequestAborted).ConfigureAwait(false);
    }
}


/// <summary>
/// The resource server's RFC 9728 serving surface: the minimal
/// <see cref="EndpointServer"/> whose only endpoint builder is
/// <see cref="ProtectedResourceMetadataEndpoints.Builder"/>, and the §3
/// path-inserted metadata URL the document is served at — the same URL every
/// challenge advertises through the §5.1 <c>resource_metadata</c> parameter,
/// so the location a client discovers and the location that answers are one
/// value by construction.
/// </summary>
[DebuggerDisplay("ResourceServerMetadataEndpoint MetadataUrl={MetadataUrl}")]
internal sealed record ResourceServerMetadataEndpoint(EndpointServer Server, Uri MetadataUrl);


/// <summary>
/// Tag names for the test resource server's span decoration, following the
/// <see cref="Verifiable.Server.Diagnostics.ServerTagNames"/> conventions
/// with an <c>rs.</c> domain prefix. Test infrastructure only — the library
/// attaches its events to <see cref="Activity.Current"/> and owns no
/// resource-server host.
/// </summary>
internal static class ResourceServerTagNames
{
    /// <summary>Whether access-token validation succeeded for the request.</summary>
    public const string TokenValidated = "rs.token.validated";

    /// <summary>The scope this resource requires, when scope enforcement is configured.</summary>
    public const string ScopeRequired = "rs.scope.required";

    /// <summary>Whether the validated token's scope list contains the required scope.</summary>
    public const string ScopeSatisfied = "rs.scope.satisfied";

    /// <summary>The RFC 6750 §3.1 error code the emitted challenge carries.</summary>
    public const string ChallengeError = "rs.challenge.error";
}


/// <summary>
/// Span event names for the test resource server's decision points,
/// following the <see cref="Verifiable.Server.Diagnostics.ServerEventNames"/>
/// conventions with an <c>rs.</c> domain prefix.
/// </summary>
internal static class ResourceServerEventNames
{
    /// <summary>Access-token validation succeeded.</summary>
    public const string TokenValidated = "rs.token.validated";

    /// <summary>Access-token validation failed and a challenge was emitted.</summary>
    public const string TokenRejected = "rs.token.rejected";

    /// <summary>The required-scope decision was evaluated for a validated token.</summary>
    public const string ScopeChecked = "rs.scope.checked";
}
