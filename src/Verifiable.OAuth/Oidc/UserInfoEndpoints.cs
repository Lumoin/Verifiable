using System.Diagnostics;
using Verifiable.JCose;
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
/// access token must have been issued with the <c>openid</c> scope; the
/// endpoint returns the claims authorised by the granted scope per OIDC
/// Core §5.4.
/// </para>
/// <para>
/// <strong>Phase A scaffolding state.</strong> The chunk-9 commit ships
/// the endpoint shell: registration, routing, and the bearer-header
/// presence check. The presented token's signature, claims, and scope are
/// validated by the chunk-10 follow-up; the per-subject claim emission
/// via the <see cref="ServerConfiguration.ClaimIssuer"/> contributor walk
/// against <see cref="UserInfoTarget"/> lands in chunk 11.
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

            BuildInputAsync = static (fields, context, currentState, ct) =>
            {
                //RFC 6750 §2 — the bearer token rides on the Authorization
                //header. Missing or malformed header is a 401 invalid_token
                //before any token-content validation; the chunk-10 follow-up
                //adds the signature / claim / scope checks against the
                //extracted token.
                IncomingRequest? req = context.IncomingRequest;
                string bearerPrefix = WellKnownAuthenticationSchemes.Bearer + " ";
                if(req is null
                    || !req.Headers.TryGetSingle(WellKnownHttpHeaderNames.Authorization, out string? authHeader)
                    || authHeader is null
                    || !authHeader.StartsWith(bearerPrefix, StringComparison.Ordinal)
                    || authHeader.Length <= bearerPrefix.Length)
                {
                    return ValueTask.FromResult<(OAuthFlowInput?, ServerHttpResponse?)>(
                        (null, ServerHttpResponse.Unauthorized(
                            OAuthErrors.InvalidToken,
                            "Missing or malformed Authorization header.")));
                }

                //Chunk 9 placeholder: the bearer header is structurally
                //present. Return an empty JSON object so callers see a
                //real 2xx response and the endpoint registration is
                //end-to-end exercised. Chunk 10 validates the token and
                //fills the body with sub; chunk 11 adds the contributor
                //walk for scope-driven claims.
                return ValueTask.FromResult<(OAuthFlowInput?, ServerHttpResponse?)>(
                    (null, ServerHttpResponse.Ok("{}", WellKnownMediaTypes.Application.Json)));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(
                    OAuthErrors.ServerError,
                    "UserInfoEndpoints is stateless; BuildResponse must never be reached.")
        };
}
