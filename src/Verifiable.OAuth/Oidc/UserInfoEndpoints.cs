using System.Text;
using Verifiable.Core.Assessment;
using Verifiable.JCose;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.ProtectedResource;
using Verifiable.OAuth.Server;

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
/// <c>AuthorizationServerIntegration.ResolveEndpointUriAsync</c>
/// resolves both to the same URL.
/// </para>
/// <para>
/// Authentication uses an access token presented in the <c>Authorization</c> header, under the
/// <c>Bearer</c> scheme per <see href="https://www.rfc-editor.org/rfc/rfc6750">RFC 6750</see> or, for
/// a token bound to the client's DPoP key, under the <c>DPoP</c> scheme with a proof per
/// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7">RFC 9449 §7</see>. The access token
/// must have been issued by this Authorization Server (the <c>iss</c> claim matches the resolved
/// issuer URI) and must be unexpired. A token carrying a <c>cnf.jkt</c> binding is served only under
/// the <c>DPoP</c> scheme with a proof from the bound key: RFC 9449 §7.2 "such a protected resource
/// MUST reject a DPoP-bound access token received as a bearer token per [RFC6750]." OIDC Core §5.3.1
/// requires the granted scope to include <c>openid</c>; the endpoint returns 403
/// <c>insufficient_scope</c> when that condition is not met. The refusals of a token presented under
/// the <c>Bearer</c> scheme carry the RFC 6750 §3 <c>WWW-Authenticate</c> challenge.
/// </para>
/// <para>
/// The endpoint performs bearer validation, the <c>iss</c> / <c>exp</c> /
/// scope checks, and emits a response body carrying the validated <c>sub</c>
/// together with the per-subject claim emission via the
/// <see cref="AuthorizationServerIntegration.ClaimIssuer"/> contributor walk against
/// <see cref="UserInfoTarget"/>.
/// </para>
/// <para>
/// <strong>The <c>openid</c> ⇒ authenticated-end-user invariant.</strong> This endpoint's
/// <c>openid</c>-in-token-scope check is correct only because the token endpoint's scope
/// source (<see cref="AuthCode.AuthCodeEndpoints"/>) guarantees that non-end-user grants —
/// <c>client_credentials</c> (whose <c>sub</c> is the <c>client_id</c>, a machine, not an
/// End-User) and <c>pre_authorized_code</c> — never carry <c>openid</c> in the granted scope
/// that ends up on the access token: those grants drop it per
/// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.3">RFC 6749 §3.3</see> at
/// issuance. A <c>token_exchange</c> or <c>jwt_bearer</c> token that legitimately carries
/// <c>openid</c> is correctly served here — the app opted in by granting it, vouching that
/// the exchanged/asserted subject is an End-User. Absent the source-side guarantee, this
/// check alone would be the exact defect <see cref="WellKnownScopes"/> warns against: "An
/// access token issued without <c>openid</c> does not identify the user — it only authorizes
/// actions. Do not use the access token's presence as proof of identity."
/// </para>
/// <para>
/// <strong>Serialization firewall.</strong> Response bodies are written
/// as JSON via <see cref="System.Text.StringBuilder"/> rather than through
/// a serializer; the project's banned-symbol analyzer enforces that
/// <c>Verifiable.OAuth</c> takes no dependency on
/// <c>System.Text.Json</c>.
/// </para>
/// </remarks>
public static class UserInfoEndpoints
{
    /// <summary>
    /// The endpoint builder delegate. Pass this to
    /// <see cref="Verifiable.Server.ServerConfiguration.EndpointBuilders"/>.
    /// </summary>
    public static EndpointBuilderDelegate Builder { get; } = static (registration, context, ct) =>
    {
        if(!((ClientRecord)registration).IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OidcUserInfo))
        {
            return ValueTask.FromResult<IReadOnlyList<EndpointCandidate>>([]);
        }

        return ValueTask.FromResult<IReadOnlyList<EndpointCandidate>>(
            [BuildUserInfo(WellKnownHttpMethods.Get), BuildUserInfo(WellKnownHttpMethods.Post)]);
    };


    /// <summary>
    /// The <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3">RFC 6750 §3</see> challenge
    /// UserInfo answers a presented token it refuses as invalid with, <c>Bearer error="invalid_token"</c>:
    /// "If the protected resource request does not include authentication credentials or does not
    /// contain an access token that enables access to the protected resource, the resource server MUST
    /// include the HTTP "WWW-Authenticate" response header field". Composed by
    /// <see cref="BearerTokenChallenge.BuildChallenge"/>, the same composition
    /// <see cref="BearerTokenValidation"/> attaches to its own refusals.
    /// </summary>
    private static string InvalidTokenChallenge { get; } =
        BearerTokenChallenge.BuildChallenge(error: OAuthErrors.InvalidToken);


    /// <summary>
    /// The challenge UserInfo answers a token without the <c>openid</c> scope with,
    /// <c>Bearer error="insufficient_scope", scope="openid"</c>:
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 §3.1</see>
    /// "insufficient_scope The request requires higher privileges than provided by the access token.
    /// The resource server SHOULD respond with the HTTP 403 (Forbidden) status code and MAY include the
    /// "scope" attribute with the scope necessary to access the protected resource." The scope named is
    /// <see cref="WellKnownScopes.OpenId"/>, the one UserInfo requires.
    /// </summary>
    private static string InsufficientScopeChallenge { get; } =
        BearerTokenChallenge.BuildChallenge(error: OAuthErrors.InsufficientScope, scope: WellKnownScopes.OpenId);


    /// <summary>Builds the UserInfo endpoint using the admitted token validation and claim operations.</summary>
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
                EndpointServer server = context.RequestServer!;
                var oauth = server.OAuth();
                ClientRecord registration = context.ClientRegistration!;

                //RFC 6750 §2.1 and RFC 9449 §7.1 — the access token rides on the
                //Authorization header under the Bearer scheme, or under the DPoP scheme when
                //it is bound to the client's DPoP key.
                if(!BearerTokenValidation.TryExtractAccessToken(
                    context, out string? accessToken, out bool isDpopPresentation))
                {
                    return (null, ServerHttpResponse.Unauthorized(
                        OAuthErrors.InvalidToken,
                        "Missing or malformed Authorization header."));
                }

                (JwtPayload? validatedPayload, ServerHttpResponse? validationFailure) =
                    await BearerTokenValidation.ValidateAsync(accessToken!, server, registration, context, ct)
                        .ConfigureAwait(false);

                if(validationFailure is not null)
                {
                    return (null, validationFailure);
                }

                //RFC 9449 §7.1 and §7.2 — a token bound by cnf.jkt is served only under the
                //DPoP scheme with a proof from the bound key; presented as a bearer token it is
                //refused. The enforcement is the one the OID4VCI protected endpoints run. Under
                //the Bearer scheme its only refusal is that downgrade, a 401 that carries the
                //RFC 6750 §3 challenge.
                ServerHttpResponse? dpopFailure = await CredentialEndpointDpopValidation.EnforceAsync(
                    server, context, registration, validatedPayload!, accessToken!, isDpopPresentation,
                    server.TimeProvider.GetUtcNow(), ct).ConfigureAwait(false);
                if(dpopFailure is not null)
                {
                    return (null, isDpopPresentation
                        ? dpopFailure
                        : dpopFailure.WithHeader(WellKnownHttpHeaderNames.WwwAuthenticate, InvalidTokenChallenge));
                }

                //OIDC Core §5.3.1 — the access token MUST carry the openid
                //scope. Tokens without it are valid for resource-server access
                //but cannot reach UserInfo. RFC 6750 §3.1 — the 403 names the scope
                //the endpoint requires in its challenge.
                if(!validatedPayload!.TryGetValue(WellKnownJwtClaimNames.Scope, out object? scopeObj)
                    || scopeObj is not string scope
                    || !WellKnownScopes.ContainsOpenId(scope))
                {
                    return (null, ServerHttpResponse.Forbidden(
                        OAuthErrors.InsufficientScope,
                        "UserInfo requires the openid scope per OIDC Core §5.3.1.")
                        .WithHeader(WellKnownHttpHeaderNames.WwwAuthenticate, InsufficientScopeChallenge));
                }

                if(!validatedPayload.TryGetValue(WellKnownJwtClaimNames.Sub, out object? subObj)
                    || subObj is not string subject
                    || string.IsNullOrEmpty(subject))
                {
                    return (null, ServerHttpResponse.Unauthorized(
                        OAuthErrors.InvalidToken,
                        "Validated access token does not carry a sub claim.")
                        .WithHeader(WellKnownHttpHeaderNames.WwwAuthenticate, InvalidTokenChallenge));
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
                return (null, ServerHttpResponse.Ok(
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
