using System.Buffers;
using System.Diagnostics;
using System.Globalization;
using Verifiable.Core.Assessment;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth.Jar;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.OAuth.Server.Routing;

namespace Verifiable.OAuth.Oidc;

/// <summary>
/// Endpoint builder module for the OpenID Connect UserInfo endpoint per
/// <see href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfo">OIDC Core §5.3</see>.
/// </summary>
/// <remarks>
/// <para>
/// Register at startup via <see cref="ServerConfiguration.EndpointBuilders"/>:
/// </para>
/// <code>
/// EndpointBuilders = new EndpointBuilderSet(
/// [
///     AuthCodeEndpoints.Builder,
///     UserInfoEndpoints.Builder,
///     MetadataEndpoints.Builder
/// ])
/// </code>
/// <para>
/// Produces endpoints only for registrations whose capability set includes
/// <see cref="ServerCapabilityName.UserInfo"/>. Two candidates are emitted
/// per applicable registration — one for the spec-allowed
/// <see cref="WellKnownHttpMethods.Get"/> request and one for the
/// <see cref="WellKnownHttpMethods.Post"/> request — sharing the
/// <see cref="WellKnownEndpointNames.UserInfo"/> role identifier so the
/// application's
/// <see cref="AuthorizationServerIntegration.ResolveEndpointUriAsync"/>
/// resolves both to the same URL.
/// </para>
/// <para>
/// Authentication uses a bearer access token presented in the
/// <c>Authorization</c> header per
/// <see href="https://www.rfc-editor.org/rfc/rfc6750">RFC 6750</see>. The
/// access token must have been issued by this Authorization Server (the
/// <c>iss</c> claim matches the resolved issuer URI) and must be
/// unexpired. OIDC Core §5.3.1 requires the granted scope to include
/// <c>openid</c>; the endpoint returns 403 <c>insufficient_scope</c> when
/// that condition is not met.
/// </para>
/// <para>
/// <strong>Phase A scaffolding state.</strong> Chunk 10 ships bearer
/// validation, the <c>iss</c> / <c>exp</c> / scope checks, and a minimal
/// response body carrying the validated <c>sub</c>. Chunk 11 adds the
/// per-subject claim emission via the
/// <see cref="ServerConfiguration.ClaimIssuer"/> contributor walk against
/// <see cref="UserInfoTarget"/>.
/// </para>
/// <para>
/// <strong>Serialization firewall.</strong> Response bodies are written
/// as JSON via <see cref="System.Text.StringBuilder"/> rather than through
/// a serializer; the project's banned-symbol analyzer enforces that
/// <c>Verifiable.OAuth</c> takes no dependency on
/// <c>System.Text.Json</c>.
/// </para>
/// </remarks>
[DebuggerDisplay("UserInfoEndpoints")]
public static class UserInfoEndpoints
{
    /// <summary>
    /// The endpoint builder delegate. Pass this to
    /// <see cref="ServerConfiguration.EndpointBuilders"/>.
    /// </summary>
    public static readonly EndpointBuilderDelegate Builder = static (registration, context, ct) =>
    {
        if(!registration.IsCapabilityAllowed(ServerCapabilityName.UserInfo))
        {
            return ValueTask.FromResult<IReadOnlyList<EndpointCandidate>>([]);
        }

        return ValueTask.FromResult<IReadOnlyList<EndpointCandidate>>(
            [BuildUserInfo(WellKnownHttpMethods.Get), BuildUserInfo(WellKnownHttpMethods.Post)]);
    };


    private static EndpointCandidate BuildUserInfo(string httpMethod) =>
        new()
        {
            //Both candidates share the same role identifier — the application's
            //ResolveEndpointUriAsync answers the same URL regardless of method,
            //matching the OIDC Core §5.3 wire shape (GET and POST against
            //the same /userinfo URL).
            Name = WellKnownEndpointNames.UserInfo,
            HttpMethod = httpMethod,
            Capability = ServerCapabilityName.UserInfo,
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,
            DiscoveryMetadataKey = OpenIdProviderMetadataParameterNames.UserinfoEndpoint,

            //Acceptance test: HTTP method matches AND path matches. The chain
            //build guarantees registration is loaded and the UserInfo capability
            //is allowed before any matcher runs.
            MatchesRequest = (fields, context, endpoint, ct) =>
            {
                IncomingRequest? req = context.IncomingRequest;
                if(req is null) { return ValueTask.FromResult<MatchPayload?>(null); }
                if(!WellKnownHttpMethods.Equals(req.Method, httpMethod))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                if(!PathEquals.Equals(req.Path, endpoint.ResolvedUri.AbsolutePath))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
            },

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                AuthorizationServer server = context.Server!;
                ClientRecord registration = context.Registration!;

                //RFC 6750 §2 — the bearer token rides on the Authorization
                //header.
                if(!TryExtractBearer(context, out string? bearerToken))
                {
                    return ((OAuthFlowInput?)null, (ServerHttpResponse?)ServerHttpResponse.Unauthorized(
                        OAuthErrors.InvalidToken,
                        "Missing or malformed Authorization header."));
                }

                (JwtPayload? validatedPayload, ServerHttpResponse? validationFailure) =
                    await ValidateBearerAsync(bearerToken!, server, registration, context, ct)
                        .ConfigureAwait(false);

                if(validationFailure is not null)
                {
                    return ((OAuthFlowInput?)null, validationFailure);
                }

                //OIDC Core §5.3.1 — the access token MUST carry the openid
                //scope. Tokens without it are valid for resource-server access
                //but cannot reach UserInfo.
                if(!validatedPayload!.TryGetValue(WellKnownJwtClaimNames.Scope, out object? scopeObj)
                    || scopeObj is not string scope
                    || !WellKnownScopes.ContainsOpenId(scope))
                {
                    return ((OAuthFlowInput?)null, (ServerHttpResponse?)ServerHttpResponse.Forbidden(
                        OAuthErrors.InsufficientScope,
                        "UserInfo requires the openid scope per OIDC Core §5.3.1."));
                }

                if(!validatedPayload.TryGetValue(WellKnownJwtClaimNames.Sub, out object? subObj)
                    || subObj is not string subject
                    || string.IsNullOrEmpty(subject))
                {
                    return ((OAuthFlowInput?)null, (ServerHttpResponse?)ServerHttpResponse.Unauthorized(
                        OAuthErrors.InvalidToken,
                        "Validated access token does not carry a sub claim."));
                }

                //One-time OidcClaims resolution before the contributor walk —
                //mirrors the token-endpoint walking site's PreResolveOidcClaimsAsync
                //pattern so per-rule contributors don't each re-issue the
                //resolver call.
                Oidc.OidcClaims? preResolvedClaims = null;
                ResolveOidcClaimsDelegate? resolve = server.Integration.ResolveOidcClaimsAsync;
                if(resolve is not null)
                {
                    preResolvedClaims = await resolve(
                        subject, scope, registration.TenantId, context, ct)
                        .ConfigureAwait(false);
                }

                //Compose the response body via the standard contributor walk
                //against UserInfoTarget. The sub claim is always present per
                //OIDC Core §5.3.2; scope-driven extension claims (profile /
                //email / address / phone) flow through the contributors
                //registered on ServerConfiguration.ClaimIssuer.
                UserInfoTarget target = new(registration, subject, scope, context)
                {
                    ResolvedOidcClaims = preResolvedClaims
                };

                Dictionary<string, object> responseClaims =
                    new(StringComparer.Ordinal) { [WellKnownJwtClaimNames.Sub] = subject };

                ClaimIssueResult contributionResult =
                    await server.Configuration.ClaimIssuer.GenerateClaimsAsync(
                        target, Guid.NewGuid().ToString("N"), ct)
                        .ConfigureAwait(false);

                foreach(Claim claim in contributionResult.Claims)
                {
                    if(claim.Outcome == ClaimOutcome.Success
                        && claim.Context is ClaimContributionContext ctx)
                    {
                        responseClaims[ctx.ClaimName] = ctx.ClaimValue;
                    }
                }

                string body = BuildResponseBody(responseClaims);
                return ((OAuthFlowInput?)null, (ServerHttpResponse?)ServerHttpResponse.Ok(
                    body, WellKnownMediaTypes.Application.Json));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(
                    OAuthErrors.ServerError,
                    "UserInfoEndpoints is stateless; BuildResponse must never be reached.")
        };


    /// <summary>
    /// Parses the <c>Authorization</c> header and extracts the bearer token,
    /// rejecting missing / non-Bearer / empty-payload presentations.
    /// </summary>
    private static bool TryExtractBearer(RequestContext context, out string? bearerToken)
    {
        bearerToken = null;
        IncomingRequest? req = context.IncomingRequest;
        string bearerPrefix = WellKnownAuthenticationSchemes.Bearer + " ";

        if(req is null
            || !req.Headers.TryGetSingle(WellKnownHttpHeaderNames.Authorization, out string? authHeader)
            || authHeader is null
            || !authHeader.StartsWith(bearerPrefix, StringComparison.Ordinal)
            || authHeader.Length <= bearerPrefix.Length)
        {
            return false;
        }

        bearerToken = authHeader[bearerPrefix.Length..];
        return true;
    }


    /// <summary>
    /// Validates the structure, signature, issuer, and expiry of a bearer
    /// access token presented to UserInfo. Composes against
    /// <see cref="JwsParsing.ParseCompact"/>, <see cref="Jose.VerifyAsync(string, DecodeDelegate, Func{ReadOnlySpan{byte}, object?}, MemoryPool{byte}, PublicKeyMemory, CancellationToken)"/>,
    /// and the AS's wired
    /// <see cref="AuthorizationServerCryptography.VerificationKeyResolver"/> /
    /// <see cref="AuthorizationServerCodecs.JwtPayloadDeserializer"/>. Does
    /// not validate audience — the UserInfo endpoint accepts any AS-issued
    /// access token whose <c>iss</c> matches the resolved issuer; deployments
    /// that need stricter audience binding install a custom
    /// <see cref="ResolveAccessTokenAudienceDelegate"/> and add the check at
    /// the resource server.
    /// </summary>
    private static async ValueTask<(JwtPayload? payload, ServerHttpResponse? failure)> ValidateBearerAsync(
        string bearerToken,
        AuthorizationServer server,
        ClientRecord registration,
        RequestContext context,
        CancellationToken cancellationToken)
    {
        if(server.Codecs.JwtHeaderDeserializer is null
            || server.Codecs.JwtPayloadDeserializer is null
            || server.Codecs.Decoder is null)
        {
            return (null, ServerHttpResponse.ServerError(
                OAuthErrors.ServerError,
                "AuthorizationServerCodecs is not fully configured for UserInfo validation."));
        }

        if(server.Cryptography.VerificationKeyResolver is null)
        {
            return (null, ServerHttpResponse.ServerError(
                OAuthErrors.ServerError,
                "AuthorizationServerCryptography.VerificationKeyResolver is not configured."));
        }

        //1. Structural parse — three base64url-separated parts, header is
        //   well-formed JSON.
        UnverifiedJwsMessage unverified;
        try
        {
            unverified = JwsParsing.ParseCompact(
                bearerToken,
                server.Codecs.Decoder,
                bytes => server.Codecs.JwtHeaderDeserializer(bytes),
                SensitiveMemoryPool<byte>.Shared);
        }
        catch(Exception ex) when(ex is FormatException or InvalidOperationException)
        {
            return (null, ServerHttpResponse.Unauthorized(
                OAuthErrors.InvalidToken,
                $"Access token is malformed: {ex.Message}"));
        }

        using(unverified)
        {
            //2. kid + alg from protected header. alg=none is rejected per
            //   RFC 8725 §3.1.
            UnverifiedJwtHeader header = unverified.Signatures[0].ProtectedHeader;

            if(!header.TryGetValue(WellKnownJwkMemberNames.Alg, out object? algObj)
                || algObj is not string alg
                || string.IsNullOrEmpty(alg)
                || string.Equals(alg, "none", StringComparison.OrdinalIgnoreCase))
            {
                return (null, ServerHttpResponse.Unauthorized(
                    OAuthErrors.InvalidToken,
                    "Access token header is missing or carries a forbidden alg."));
            }

            if(!header.TryGetValue(WellKnownJwkMemberNames.Kid, out object? kidObj)
                || kidObj is not string kid
                || string.IsNullOrEmpty(kid))
            {
                return (null, ServerHttpResponse.Unauthorized(
                    OAuthErrors.InvalidToken,
                    "Access token header is missing kid."));
            }

            //3. Resolve the verification key.
            PublicKeyMemory? publicKey = await server.Cryptography.VerificationKeyResolver(
                new KeyId(kid), registration.TenantId, context, cancellationToken).ConfigureAwait(false);

            if(publicKey is null)
            {
                return (null, ServerHttpResponse.Unauthorized(
                    OAuthErrors.InvalidToken,
                    $"No verification key found for kid '{kid}'."));
            }

            //4. Verify signature via the algorithm-agnostic Jws.VerifyAsync
            //   overload. The key's tag carries the algorithm; the registry
            //   resolves the verification primitive.
            bool signatureValid;
            try
            {
                signatureValid = await Jws.VerifyAsync<object?>(
                    bearerToken,
                    server.Codecs.Decoder,
                    static (ReadOnlySpan<byte> _) => (object?)null,
                    SensitiveMemoryPool<byte>.Shared,
                    publicKey,
                    cancellationToken).ConfigureAwait(false);
            }
            catch(Exception ex) when(ex is FormatException or InvalidOperationException)
            {
                return (null, ServerHttpResponse.Unauthorized(
                    OAuthErrors.InvalidToken,
                    $"Signature verification raised: {ex.Message}"));
            }

            if(!signatureValid)
            {
                return (null, ServerHttpResponse.Unauthorized(
                    OAuthErrors.InvalidToken,
                    "Access token signature verification failed."));
            }

            //5. Parse the payload now that the signature is verified.
            JwtPayload payload;
            try
            {
                payload = new JwtPayload(server.Codecs.JwtPayloadDeserializer(unverified.Payload.Span));
            }
            catch(Exception ex) when(ex is FormatException or InvalidOperationException)
            {
                return (null, ServerHttpResponse.Unauthorized(
                    OAuthErrors.InvalidToken,
                    $"Access token payload could not be parsed: {ex.Message}"));
            }

            //6. iss claim must match the resolved issuer for this request.
            Uri issuerUri;
            try
            {
                issuerUri = server.Integration.ResolveIssuerAsync is not null
                    ? await server.Integration.ResolveIssuerAsync(registration, context, cancellationToken)
                        .ConfigureAwait(false)
                    : await DefaultIssuerResolver.ResolveAsync(registration, context, cancellationToken)
                        .ConfigureAwait(false);
            }
            catch(InvalidOperationException ex)
            {
                return (null, ServerHttpResponse.ServerError(
                    OAuthErrors.ServerError,
                    $"Could not resolve issuer for UserInfo validation: {ex.Message}"));
            }

            if(!payload.TryGetValue(WellKnownJwtClaimNames.Iss, out object? issObj)
                || issObj is not string iss
                || !string.Equals(iss, issuerUri.OriginalString, StringComparison.Ordinal))
            {
                return (null, ServerHttpResponse.Unauthorized(
                    OAuthErrors.InvalidToken,
                    "Access token iss claim does not match this Authorization Server."));
            }

            //7. exp claim must be in the future. JwtClaimReaders.TryToInt64
            //   handles the broad set of integer types JSON deserializers may
            //   produce for Unix-seconds values (long, int, decimal, ulong, …).
            if(!payload.TryGetValue(WellKnownJwtClaimNames.Exp, out object? expObj)
                || !JwtClaimReaders.TryToInt64(expObj, out long expSeconds))
            {
                return (null, ServerHttpResponse.Unauthorized(
                    OAuthErrors.InvalidToken,
                    "Access token is missing the exp claim."));
            }

            DateTimeOffset now = server.TimeProvider.GetUtcNow();
            if(DateTimeOffset.FromUnixTimeSeconds(expSeconds) < now)
            {
                return (null, ServerHttpResponse.Unauthorized(
                    OAuthErrors.InvalidToken,
                    "Access token has expired."));
            }

            return (payload, null);
        }
    }


    /// <summary>
    /// Composes the UserInfo JSON response body from the merged claim
    /// dictionary. Claim names are sorted lexicographically for
    /// deterministic wire output. Handles the runtime value shapes the
    /// standard contributors produce: <see cref="string"/>,
    /// <see cref="long"/>, <see cref="int"/>, <see cref="bool"/>,
    /// <see cref="IReadOnlyList{T}"/> of <see cref="string"/> for
    /// <c>amr</c>, and nested
    /// <see cref="IDictionary{TKey, TValue}"/> for the <c>address</c>
    /// structured claim. Hand-written via
    /// <see cref="System.Text.StringBuilder"/> per the serialization
    /// firewall.
    /// </summary>
    private static string BuildResponseBody(IDictionary<string, object> claims)
    {
        System.Text.StringBuilder sb = new();
        AppendObject(sb, claims);
        return sb.ToString();
    }


    private static void AppendObject(System.Text.StringBuilder sb, IDictionary<string, object> map)
    {
        sb.Append('{');
        bool first = true;
        foreach(KeyValuePair<string, object> entry in map.OrderBy(
            e => e.Key, StringComparer.Ordinal))
        {
            if(!first) { sb.Append(','); }
            first = false;

            sb.Append('"');
            AppendJsonString(sb, entry.Key);
            sb.Append("\":");
            AppendValue(sb, entry.Value);
        }

        sb.Append('}');
    }


    private static void AppendValue(System.Text.StringBuilder sb, object value)
    {
        switch(value)
        {
            case string s:
            {
                sb.Append('"');
                AppendJsonString(sb, s);
                sb.Append('"');
                break;
            }

            case long l:
            {
                sb.Append(l.ToString(CultureInfo.InvariantCulture));
                break;
            }

            case int i:
            {
                sb.Append(i.ToString(CultureInfo.InvariantCulture));
                break;
            }

            case bool b:
            {
                sb.Append(b ? "true" : "false");
                break;
            }

            case IReadOnlyList<string> list:
            {
                sb.Append('[');
                for(int idx = 0; idx < list.Count; idx++)
                {
                    if(idx > 0) { sb.Append(','); }
                    sb.Append('"');
                    AppendJsonString(sb, list[idx]);
                    sb.Append('"');
                }
                sb.Append(']');
                break;
            }

            case IDictionary<string, object> nested:
            {
                AppendObject(sb, nested);
                break;
            }

            default:
            {
                //Conservative: serialise unknown types as quoted strings to
                //avoid emitting broken JSON. The standard contributors
                //produce only the shapes above; new contributor types should
                //prefer one of those shapes for wire compatibility.
                sb.Append('"');
                AppendJsonString(sb, value.ToString() ?? string.Empty);
                sb.Append('"');
                break;
            }
        }
    }


    /// <summary>
    /// Escapes a string for inclusion inside a JSON string literal. Covers
    /// the RFC 8259 §7 mandatory escapes: <c>"</c>, <c>\</c>, and the
    /// control characters U+0000 through U+001F. Everything else is
    /// emitted verbatim.
    /// </summary>
    private static void AppendJsonString(System.Text.StringBuilder sb, string value)
    {
        foreach(char c in value)
        {
            switch(c)
            {
                case '"':
                {
                    sb.Append("\\\"");
                    break;
                }
                case '\\':
                {
                    sb.Append("\\\\");
                    break;
                }
                case '\b':
                {
                    sb.Append("\\b");
                    break;
                }
                case '\f':
                {
                    sb.Append("\\f");
                    break;
                }
                case '\n':
                {
                    sb.Append("\\n");
                    break;
                }
                case '\r':
                {
                    sb.Append("\\r");
                    break;
                }
                case '\t':
                {
                    sb.Append("\\t");
                    break;
                }
                default:
                {
                    if(c < 0x20)
                    {
                        sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        sb.Append(c);
                    }
                    break;
                }
            }
        }
    }
}
