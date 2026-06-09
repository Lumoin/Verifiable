using System.Diagnostics;
using System.Text;
using Verifiable.Core;
using Verifiable.Core.SecurityEvents;
using Verifiable.JCose;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.OAuth.Server.Routing;

namespace Verifiable.OAuth.Logout;

/// <summary>
/// Endpoint builder for the Global Token Revocation command
/// (<see href="https://datatracker.ietf.org/doc/draft-parecki-oauth-global-token-revocation/">draft-parecki-oauth-global-token-revocation §3</see>)
/// — <c>POST application/json</c> with a single <c>sub_id</c> RFC 9493 Subject
/// Identifier. Register at startup via <see cref="ServerConfiguration.EndpointBuilders"/>.
/// </summary>
/// <remarks>
/// <para>
/// The library owns the wire: it authenticates the client, reads and parses the
/// body (via the application's <see cref="ParseGlobalTokenRevocationRequestDelegate"/>),
/// validates the Subject Identifier, drops out to the application's
/// <see cref="RevokeSubjectTokensDelegate"/>, and maps the returned outcome onto
/// the §3 status codes (204 / 403 / 404 / 422). It owns no JSON — the
/// <c>Verifiable.OAuth</c> serialization firewall keeps that behind the parse seam.
/// </para>
/// <para>
/// There is deliberately no library "orchestrator" object: the revoke-subject
/// seam <em>is</em> the global-logout fan-out. The application revokes the
/// subject's grants against the same store the per-call decision seams read, and
/// — when it runs a Shared Signals Transmitter — MAY emit a CAEP
/// <c>session-revoked</c> event on completion.
/// </para>
/// </remarks>
[DebuggerDisplay("GlobalTokenRevocationEndpoints")]
public static class GlobalTokenRevocationEndpoints
{
    /// <summary>
    /// The endpoint builder delegate. Pass this to
    /// <see cref="ServerConfiguration.EndpointBuilders"/>.
    /// </summary>
    public static readonly EndpointBuilderDelegate Builder = static (registration, context, ct) =>
    {
        List<EndpointCandidate> candidates = [];

        //Fail-closed: the command revokes every token a subject holds, so it
        //materializes only when the capability is allowed AND the parse seam, the
        //revoke-subject seam, and client authentication are all wired.
        AuthorizationServer? server = context.Server;
        if(registration.IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OAuthGlobalTokenRevocation)
            && server?.Integration.ParseGlobalTokenRevocationRequestAsync is not null
            && server?.Integration.RevokeSubjectTokensAsync is not null
            && server?.Integration.ValidateClientCredentialsAsync is not null)
        {
            candidates.Add(BuildGlobalTokenRevocation());
        }

        return ValueTask.FromResult<IReadOnlyList<EndpointCandidate>>(candidates);
    };


    /// <summary>
    /// Builds the Global Token Revocation endpoint candidate. Stateless — a single
    /// authenticated request that revokes a subject's tokens and returns, with no
    /// flow state and no correlation key (the same shape as <c>client_credentials</c>).
    /// </summary>
    private static EndpointCandidate BuildGlobalTokenRevocation() =>
        new()
        {
            Name = WellKnownEndpointNames.GlobalTokenRevocation,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownCapabilityIdentifiers.OAuthGlobalTokenRevocation,
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,
            DiscoveryMetadataKey = AuthorizationServerMetadataParameterNames.GlobalTokenRevocationEndpoint,

            MatchesRequest = static (fields, context, endpoint, ct) =>
            {
                IncomingRequest? req = context.IncomingRequest;
                if(req is null) { return ValueTask.FromResult<MatchPayload?>(null); }
                if(!WellKnownHttpMethods.IsPost(req.Method))
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

                ClientRecord? registration = context.Registration;
                if(registration is null)
                {
                    return (null, ServerHttpResponse.Unauthorized(
                        OAuthErrors.InvalidClient, "Unknown client."));
                }

                //§3.5: the request MUST be authenticated (the draft recommends
                //private_key_jwt). The seam owns the method; the gate guarantees it
                //is wired.
                bool clientAuthenticated = await server.Integration.ValidateClientCredentialsAsync!(
                    context.IncomingRequest, fields, registration, context, ct).ConfigureAwait(false);
                if(!clientAuthenticated)
                {
                    return (null, ServerHttpResponse.Unauthorized(
                        OAuthErrors.InvalidClient, "Client authentication failed."));
                }

                IncomingRequest? req = context.IncomingRequest;
                if(req is null || req.Body.IsEmpty || req.Body.Bytes.IsEmpty)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "Global Token Revocation request body is missing."));
                }

                string requestBody = Encoding.UTF8.GetString(req.Body.Bytes.Span);

                GlobalTokenRevocationRequest? request = await server.Integration.ParseGlobalTokenRevocationRequestAsync!(
                    requestBody, context, ct).ConfigureAwait(false);
                if(request is null)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        "Request body did not parse as a valid Global Token Revocation request."));
                }

                //§3: the sub_id MUST be a well-formed Subject Identifier in a format
                //the server recognizes; a malformed sub_id is a 400, not a seam call.
                if(!request.SubId.IsValidForKnownFormat())
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        "The sub_id is not a recognized, well-formed Subject Identifier."));
                }

                GlobalTokenRevocationOutcome outcome = await server.Integration.RevokeSubjectTokensAsync!(
                    request.SubId, registration, context, ct).ConfigureAwait(false);

                //§3 status-code mapping. 204 conveys "revocation initiated"; 403/404/422
                //are the application-determined outcomes the seam reports.
                return outcome switch
                {
                    GlobalTokenRevocationOutcome.Initiated =>
                        ((OAuthFlowInput?)null, ServerHttpResponse.NoContent()),
                    GlobalTokenRevocationOutcome.SubjectNotFound =>
                        (null, ServerHttpResponse.NotFound()),
                    GlobalTokenRevocationOutcome.Forbidden =>
                        (null, ServerHttpResponse.Forbidden(
                            OAuthErrors.UnauthorizedClient, "Not authorized to revoke this subject.")),
                    _ => (null, ServerHttpResponse.UnprocessableEntity(
                            OAuthErrors.InvalidRequest, "The revocation request could not be processed.")),
                };
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };
}
