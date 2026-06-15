using System.Buffers;
using System.Diagnostics;
using System.Globalization;
using System.Text;
using Verifiable.Core;
using Verifiable.Core.Assessment;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth.Jar;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.Server;

namespace Verifiable.OAuth.Oidc;

/// <summary>
/// Endpoint builder module for the OpenID Connect UserInfo endpoint per
/// <see href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfo">OIDC Core §5.3</see>.
/// </summary>
/// <remarks>
/// <para>
/// Register at startup via <see cref="Verifiable.Server.ServerConfiguration.EndpointBuilders"/>:
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
/// <see cref="WellKnownCapabilityIdentifiers.OidcUserInfo"/>. Two candidates are emitted
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
/// <see cref="AuthorizationServerIntegration.ClaimIssuer"/> contributor walk against
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
    /// <see cref="Verifiable.Server.ServerConfiguration.EndpointBuilders"/>.
    /// </summary>
    public static readonly EndpointBuilderDelegate Builder = static (registration, context, ct) =>
    {
        if(!((ClientRecord)registration).IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OidcUserInfo))
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
            Capability = WellKnownCapabilityIdentifiers.OidcUserInfo,
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
                EndpointServer server = context.Server!;
                var oauth = server.OAuth();
                ClientRecord registration = context.ClientRegistration!;

                //RFC 6750 §2 — the bearer token rides on the Authorization
                //header.
                if(!BearerTokenValidation.TryExtractBearer(context, out string? bearerToken))
                {
                    return ((FlowInput?)null, (ServerHttpResponse?)ServerHttpResponse.Unauthorized(
                        OAuthErrors.InvalidToken,
                        "Missing or malformed Authorization header."));
                }

                (JwtPayload? validatedPayload, ServerHttpResponse? validationFailure) =
                    await BearerTokenValidation.ValidateAsync(bearerToken!, server, registration, context, ct)
                        .ConfigureAwait(false);

                if(validationFailure is not null)
                {
                    return ((FlowInput?)null, validationFailure);
                }

                //OIDC Core §5.3.1 — the access token MUST carry the openid
                //scope. Tokens without it are valid for resource-server access
                //but cannot reach UserInfo.
                if(!validatedPayload!.TryGetValue(WellKnownJwtClaimNames.Scope, out object? scopeObj)
                    || scopeObj is not string scope
                    || !WellKnownScopes.ContainsOpenId(scope))
                {
                    return ((FlowInput?)null, (ServerHttpResponse?)ServerHttpResponse.Forbidden(
                        OAuthErrors.InsufficientScope,
                        "UserInfo requires the openid scope per OIDC Core §5.3.1."));
                }

                if(!validatedPayload.TryGetValue(WellKnownJwtClaimNames.Sub, out object? subObj)
                    || subObj is not string subject
                    || string.IsNullOrEmpty(subject))
                {
                    return ((FlowInput?)null, (ServerHttpResponse?)ServerHttpResponse.Unauthorized(
                        OAuthErrors.InvalidToken,
                        "Validated access token does not carry a sub claim."));
                }

                //One-time OidcClaims resolution before the contributor walk —
                //mirrors the token-endpoint walking site's PreResolveOidcClaimsAsync
                //pattern so per-rule contributors don't each re-issue the
                //resolver call.
                Oidc.OidcClaims? preResolvedClaims = null;
                ResolveOidcClaimsDelegate? resolve = oauth.ResolveOidcClaimsAsync;
                if(resolve is not null)
                {
                    preResolvedClaims = await resolve(
                        subject, scope, registration.TenantId, context, ct)
                        .ConfigureAwait(false);
                }

                //Compose the response body via the standard contributor walk
                //against UserInfoTarget. The sub claim — required per OIDC
                //Core §5.3.2 — is emitted by SubjectIdentifierContributor
                //via AuthorizationServerIntegration.ResolveSubjectIdentifierAsync;
                //scope-driven extension claims (profile / email / address /
                //phone) flow through the other contributors registered on
                //AuthorizationServerIntegration.ClaimIssuer.
                UserInfoTarget target = new(registration, subject, scope, context)
                {
                    ResolvedOidcClaims = preResolvedClaims
                };

                Dictionary<string, object> responseClaims = new(StringComparer.Ordinal);

                string correlationId = await oauth.GenerateIdentifierAsync!(
                    WellKnownIdentifierPurposes.OAuthCorrelationId, context, ct)
                    .ConfigureAwait(false);
                ClaimIssueResult contributionResult =
                    await oauth.ClaimIssuer!.GenerateClaimsAsync(
                        target, correlationId, ct)
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
                return ((FlowInput?)null, (ServerHttpResponse?)ServerHttpResponse.Ok(
                    body, WellKnownMediaTypes.Application.Json));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(
                    OAuthErrors.ServerError,
                    "UserInfoEndpoints is stateless; BuildResponse must never be reached.")
        };


    /// <summary>
    /// Composes the UserInfo JSON response body from the merged claim
    /// dictionary. Claim names are sorted lexicographically for
    /// deterministic wire output. Handles the runtime value shapes the
    /// standard contributors produce: <see cref="string"/>,
    /// <see cref="long"/>, <see cref="int"/>, <see cref="bool"/>,
    /// <see cref="IReadOnlyList{T}"/> of <see cref="string"/> for
    /// <c>amr</c>, and nested
    /// <see cref="IDictionary{TKey, TValue}"/> for the <c>address</c>
    /// structured claim. Routed through <see cref="JsonAppender"/> with the
    /// claims pre-sorted into ordinal order so the wire body is stable
    /// across runs (enabling ETag/cache stability for clients).
    /// </summary>
    private static string BuildResponseBody(IDictionary<string, object> claims)
    {
        SortedDictionary<string, object> sorted = new(StringComparer.Ordinal);
        foreach(KeyValuePair<string, object> entry in claims)
        {
            sorted[entry.Key] = entry.Value;
        }

        StringBuilder sb = JsonAppender.Rent();
        try
        {
            JsonAppender.AppendObject(sb, sorted);

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }
}
