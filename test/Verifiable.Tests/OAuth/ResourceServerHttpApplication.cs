using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.OAuth;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.ProtectedResource;
using Verifiable.OAuth.Server;
using Verifiable.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Maps inbound HTTP requests for the test resource server to the
/// validator composition. Parallel of
/// <see cref="AuthorizationServerHttpApplication"/>; minimal mapping
/// layer, no DI container, no middleware pipeline. Hosts the
/// <c>/protected</c> endpoint that exercises
/// <see cref="JwsAccessTokenValidator"/> and (for DPoP-bound tokens)
/// <see cref="DpopProofValidator"/>, plus the RFC 9728 §3
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
/// resource server's own metadata URL. DPoP-scheme challenges (RFC 9449 §7.1)
/// cannot ride that builder — its scheme is <c>Bearer</c> by definition — so
/// they compose <see cref="ProtectedResourceChallenge.BuildChallenge"/> for
/// the <c>resource_metadata</c> parameter and format their own auth-params
/// over values restricted to the RFC 6750 §3 charset.
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

    private readonly ResourceServerIntegration integration;
    private readonly VerificationDelegate verifySignature;
    private readonly string? requiredScope;

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


    public ResourceServerHttpApplication(
        ResourceServerIntegration integration,
        VerificationDelegate verifySignature,
        string? requiredScope = null)
    {
        ArgumentNullException.ThrowIfNull(integration);
        ArgumentNullException.ThrowIfNull(verifySignature);
        this.integration = integration;
        this.verifySignature = verifySignature;
        this.requiredScope = requiredScope;
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


    private async Task ProcessRequestCoreAsync(HttpContext context)
    {
        if(MetadataEndpoint is { } metadataEndpoint
            && string.Equals(context.Request.Path, metadataEndpoint.MetadataUrl.AbsolutePath, StringComparison.Ordinal))
        {
            await ServeProtectedResourceMetadataAsync(context, metadataEndpoint).ConfigureAwait(false);
            return;
        }

        if(!string.Equals(context.Request.Path, "/protected", StringComparison.Ordinal))
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
            await WriteBearerChallengeAsync(
                context, StatusCodes.Status401Unauthorized,
                error: null, errorDescription: null, scope: null).ConfigureAwait(false);
            return;
        }

        if(!TryExtractAuthorization(context.Request, out string scheme, out string? accessToken))
        {
            await WriteBearerChallengeAsync(
                context, StatusCodes.Status401Unauthorized,
                OAuthErrors.InvalidToken,
                "Authorization header is malformed or uses an unsupported scheme.",
                scope: null).ConfigureAwait(false);
            return;
        }

        ExchangeContext exchangeContext = new();

        JwsAccessTokenValidationResult tokenResult = await JwsAccessTokenValidator.ValidateAsync(
            accessToken!,
            integration.TrustedIssuer.OriginalString,
            integration.ExpectedAudience,
            integration.ResolveVerificationKeyAsync,
            verifySignature,
            JwsAccessTokenTestSupport.Parser,
            TestSetup.Base64UrlDecoder,
            integration.TimeProvider,
            BaseMemoryPool.Shared,
            integration.AccessTokenIatSkew,
            tenantId: default,
            exchangeContext,
            expectedAuthorizedParty: null,
            context.RequestAborted).ConfigureAwait(false);

        if(!tokenResult.IsSuccess)
        {
            Activity.Current?.SetTag(ResourceServerTagNames.TokenValidated, false);
            Activity.Current?.AddEvent(new ActivityEvent(ResourceServerEventNames.TokenRejected));
            await WriteBearerChallengeAsync(
                context, StatusCodes.Status401Unauthorized,
                OAuthErrors.InvalidToken,
                tokenResult.FailureDescription ?? "Access token validation failed.",
                scope: null).ConfigureAwait(false);
            return;
        }

        Activity.Current?.SetTag(ResourceServerTagNames.TokenValidated, true);
        Activity.Current?.AddEvent(new ActivityEvent(ResourceServerEventNames.TokenValidated));

        JwsAccessTokenClaims claims = tokenResult.Claims!;

        if(claims.Confirmation is { JwkThumbprint: not null } confirmation)
        {
            if(!string.Equals(scheme, DpopScheme, StringComparison.Ordinal))
            {
                await WriteDpopChallengeAsync(context, OAuthErrors.InvalidToken,
                    "Access token is DPoP-bound but was presented under Bearer scheme.")
                    .ConfigureAwait(false);
                return;
            }

            if(!TryExtractDpopProof(context.Request, out string? proofJwt))
            {
                await WriteDpopChallengeAsync(context, OAuthErrors.InvalidDpopProof,
                    "DPoP header is missing.").ConfigureAwait(false);
                return;
            }

            string requestUrl = BuildRequestUrl(context.Request);

            DpopProofValidationRequest proofRequest = new()
            {
                Proof = proofJwt!,
                HttpMethod = context.Request.Method,
                HttpUrl = requestUrl,
                AccessToken = accessToken,
                NonceRequired = false
            };

            DpopProofValidationResult proofResult = await DpopProofValidator.ValidateAsync(
                proofRequest,
                verifySignature,
                DpopTestSupport.Parser,
                TestSetup.Base64UrlEncoder,
                TestSetup.Base64UrlDecoder,
                integration.TimeProvider,
                BaseMemoryPool.Shared,
                integration.DpopFreshnessWindow,
                context.RequestAborted).ConfigureAwait(false);

            if(!proofResult.IsSuccess)
            {
                await WriteDpopChallengeAsync(context, OAuthErrors.InvalidDpopProof,
                    $"DPoP proof validation failed: {proofResult.FailureReason}.")
                    .ConfigureAwait(false);
                return;
            }

            if(!string.Equals(proofResult.JwkThumbprint, confirmation.JwkThumbprint, StringComparison.Ordinal))
            {
                await WriteDpopChallengeAsync(context, OAuthErrors.InvalidDpopProof,
                    "DPoP proof thumbprint does not match the access token's cnf.jkt binding.")
                    .ConfigureAwait(false);
                return;
            }

            if(integration.IsDpopProofJtiSeenAsync is not null
                && integration.PersistDpopProofJtiAsync is not null)
            {
                string jti = proofResult.Claims!.Jti;
                bool isReplayed = await integration.IsDpopProofJtiSeenAsync(
                    jti, exchangeContext, context.RequestAborted).ConfigureAwait(false);
                if(isReplayed)
                {
                    await WriteDpopChallengeAsync(context, OAuthErrors.InvalidDpopProof,
                        "DPoP proof jti has been seen previously.").ConfigureAwait(false);
                    return;
                }

                DateTimeOffset expiresAt = integration.TimeProvider.GetUtcNow()
                    + integration.DpopFreshnessWindow;
                await integration.PersistDpopProofJtiAsync(
                    jti, expiresAt, exchangeContext, context.RequestAborted).ConfigureAwait(false);
            }
        }

        if(requiredScope is not null)
        {
            bool isScopeSatisfied = HasScope(claims.Scope, requiredScope);
            Activity.Current?.SetTag(ResourceServerTagNames.ScopeRequired, requiredScope);
            Activity.Current?.SetTag(ResourceServerTagNames.ScopeSatisfied, isScopeSatisfied);
            Activity.Current?.AddEvent(new ActivityEvent(ResourceServerEventNames.ScopeChecked));

            if(!isScopeSatisfied)
            {
                //RFC 6750 §3.1: insufficient_scope maps to 403 and the
                //challenge's scope attribute names the scope necessary to
                //access the resource.
                await WriteBearerChallengeAsync(
                    context, StatusCodes.Status403Forbidden,
                    OAuthErrors.InsufficientScope,
                    "The access token does not carry the scope this resource requires.",
                    scope: requiredScope).ConfigureAwait(false);
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
            Path: context.Request.Path.HasValue ? context.Request.Path.Value! : string.Empty,
            Method: context.Request.Method,
            Fields: new RequestFields(),
            Headers: RequestHeaders.Empty,
            RouteValues: RouteValues.Empty);

        ServerHttpResponse response = await metadataEndpoint.Server.DispatchAsync(
            incomingRequest, new ExchangeContext(), context.RequestAborted).ConfigureAwait(false);

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


    private static bool TryExtractAuthorization(
        HttpRequest request, out string scheme, out string? token)
    {
        scheme = string.Empty;
        token = null;

        if(!request.Headers.TryGetValue("Authorization", out var values) || values.Count == 0)
        {
            return false;
        }

        string header = values[0]!;
        int sep = header.IndexOf(' ', StringComparison.Ordinal);
        if(sep <= 0 || sep == header.Length - 1)
        {
            return false;
        }

        scheme = header[..sep];
        token = header[(sep + 1)..];

        return !string.IsNullOrEmpty(token)
            && (string.Equals(scheme, BearerScheme, StringComparison.Ordinal)
                || string.Equals(scheme, DpopScheme, StringComparison.Ordinal));
    }


    private static bool TryExtractDpopProof(HttpRequest request, out string? proof)
    {
        if(request.Headers.TryGetValue("DPoP", out var values)
            && values.Count > 0
            && !string.IsNullOrEmpty(values[0]))
        {
            proof = values[0];

            return true;
        }

        proof = null;

        return false;
    }


    private static string BuildRequestUrl(HttpRequest request) =>
        $"{request.Scheme}://{request.Host}{request.Path}";


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
            Activity.Current?.SetTag(ResourceServerTagNames.ChallengeError, error);
        }

        return Task.CompletedTask;
    }


    /// <summary>
    /// Writes a DPoP-scheme <c>401</c> (RFC 9449 §7.1).
    /// <see cref="BearerTokenChallenge"/> is Bearer-scheme by definition, so
    /// this challenge composes
    /// <see cref="ProtectedResourceChallenge.BuildChallenge"/> for the
    /// RFC 9728 §5.1 <c>resource_metadata</c> parameter and appends its own
    /// <c>error</c>/<c>error_description</c> auth-params over values
    /// restricted to the RFC 6750 §3 charset, which needs no quoted-pair
    /// escaping.
    /// </summary>
    private Task WriteDpopChallengeAsync(HttpContext context, string error, string? errorDescription)
    {
        StringBuilder sb = new();
        if(MetadataEndpoint is { } metadataEndpoint)
        {
            sb.Append(ProtectedResourceChallenge.BuildChallenge(
                WellKnownAuthenticationSchemes.DPoP, metadataEndpoint.MetadataUrl));
            sb.Append(", ");
        }
        else
        {
            sb.Append(DpopScheme);
            sb.Append(' ');
        }

        sb.Append("error=\"").Append(error).Append('"');
        if(SanitizeErrorDescription(errorDescription) is { Length: > 0 } sanitizedDescription)
        {
            sb.Append(", error_description=\"").Append(sanitizedDescription).Append('"');
        }

        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        context.Response.Headers.Append(WellKnownHttpHeaderNames.WwwAuthenticate, sb.ToString());
        Activity.Current?.SetTag(ResourceServerTagNames.ChallengeError, error);

        return Task.CompletedTask;
    }


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
            sb.Append(isAllowed ? c : ' ');
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

        byte[] json = JsonSerializer.SerializeToUtf8Bytes(body);
        context.Response.StatusCode = StatusCodes.Status200OK;
        context.Response.ContentType = "application/json";
        context.Response.Headers.CacheControl = "no-store";
        await context.Response.BodyWriter.WriteAsync(json, context.RequestAborted).ConfigureAwait(false);
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
        await context.Response.BodyWriter.FlushAsync(context.RequestAborted).ConfigureAwait(false);
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
