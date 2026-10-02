using System.Text;
using Verifiable.Core;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.ProtectedResource;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Logout;

/// <summary>
/// Endpoint builder for the Global Token Revocation command
/// (<see href="https://datatracker.ietf.org/doc/draft-parecki-oauth-global-token-revocation/">draft-parecki-oauth-global-token-revocation §3</see>)
/// — <c>POST application/json</c> with a single <c>sub_id</c> RFC 9493 Subject
/// Identifier. Register at startup via <see cref="Verifiable.Server.ServerConfiguration.EndpointBuilders"/>.
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
/// Two answers carry the <c>Bearer</c> challenge whose <c>realm</c> is the issuer the request
/// is served under, in the shape of <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750
/// Section 3.1</see>: a refusal of the authentication seam (401) and the revoke-subject seam's
/// <see cref="GlobalTokenRevocationOutcome.Forbidden"/> (403 <c>insufficient_scope</c>). A refused
/// request whose <c>Authorization</c> field holds an access token, as
/// <see cref="BearerTokenValidation.TryExtractAccessToken"/> reads it, is 401 <c>invalid_token</c>
/// with the error in the challenge; any other refused request (no <c>Authorization</c> field, an
/// empty or white-space value, a credential of another scheme) is 401 with an empty body and a
/// challenge without an error code. The 400, 404 and 422 answers to a caller the seam
/// authenticated carry no challenge, and neither does the 500 server fault, which answers a
/// registration that is not a <see cref="ClientRecord"/> when the endpoint runs.
/// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3">RFC 6750 Section 3</see>: "If the
/// protected resource request does not include authentication credentials or does not contain an
/// access token that enables access to the protected resource, the resource server MUST include the
/// HTTP "WWW-Authenticate" response header field; it MAY include it in response to other conditions
/// as well." The challenged answers need the issuer resolvable, as the credential endpoint's
/// refusals do.
/// </para>
/// <para>
/// There is deliberately no library "orchestrator" object: the revoke-subject
/// seam <em>is</em> the global-logout fan-out. The application revokes the
/// subject's grants against the same store the per-call decision seams read, and
/// — when it runs a Shared Signals Transmitter — MAY emit a CAEP
/// <c>session-revoked</c> event on completion.
/// </para>
/// </remarks>
public static class GlobalTokenRevocationEndpoints
{
    /// <summary>
    /// The endpoint builder delegate. Pass this to
    /// <see cref="Verifiable.Server.ServerConfiguration.EndpointBuilders"/>.
    /// </summary>
    public static EndpointBuilderDelegate Builder { get; } = static (registration, context, ct) =>
    {
        List<EndpointCandidate> candidates = [];

        //Fail-closed: the command revokes every token a subject holds, so it
        //materializes only when the capability is allowed AND the parse seam, the
        //revoke-subject seam, and client authentication are all wired.
        EndpointServer? server = context.RequestServer;
        if(((ClientRecord)registration).IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OAuthGlobalTokenRevocation)
            && server?.OAuth().ParseGlobalTokenRevocationRequestAsync is not null
            && server?.OAuth().RevokeSubjectTokensAsync is not null
            && server?.OAuth().ValidateClientCredentialsAsync is not null)
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
                EndpointServer server = context.RequestServer!;
                var oauth = server.OAuth();

                //The dispatcher sets the registration before a candidate runs, but an
                //application's materializer may replace it with a record that is not a
                //ClientRecord; the endpoint cannot serve the request then, and the fault
                //is the server's wiring, not the caller's.
                ClientRecord? registration = context.ClientRegistration;
                if(registration is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, WellKnownOAuthErrorDescriptions.ServerNotReady));
                }

                //The draft's Section 3.2: "The request MUST also be authenticated." Its
                //Section 3.5 recommends a private key JWT. The seam owns the method; the
                //gate guarantees it is wired.
                IncomingRequest? req = context.IncomingRequest;
                bool clientAuthenticated = await oauth.ValidateClientCredentialsAsync!(
                    req, fields, registration, context, ct).ConfigureAwait(false);
                if(!clientAuthenticated)
                {
                    //A refused request carried a credential when its Authorization field holds
                    //an access token, as the library's extractor reads that field: it is told
                    //why, invalid_token in the body and in the challenge. Every other refused
                    //request (no Authorization field, an empty or white-space value, another
                    //scheme) lacks the authentication information this endpoint reads and gets
                    //the challenge with no error code and an empty body. RFC 6750 Section 3.1:
                    //"If the request lacks any authentication information (e.g., the client was
                    //unaware that authentication is necessary or attempted using an unsupported
                    //authentication method), the resource server SHOULD NOT include an error code
                    //or other error information." Either way the 401 carries its challenge.
                    bool isAccessTokenCarried = BearerTokenValidation.TryExtractAccessToken(context, out _, out _);
                    ServerHttpResponse refusal = isAccessTokenCarried
                        ? await ChallengedAsync(
                            ServerHttpResponse.Unauthorized(
                                OAuthErrors.InvalidToken, WellKnownOAuthErrorDescriptions.ClientAuthenticationFailed),
                            OAuthErrors.InvalidToken, server, registration, context, ct).ConfigureAwait(false)
                        : await ChallengedAsync(
                            ServerHttpResponse.Unauthorized(), error: null, server, registration, context, ct).ConfigureAwait(false);

                    return (null, refusal);
                }

                if(req is null || req.Body.IsEmpty || req.Body.Bytes.IsEmpty)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "Global Token Revocation request body is missing."));
                }

                string requestBody = Encoding.UTF8.GetString(req.Body.Bytes.Span);

                GlobalTokenRevocationRequest? request = await oauth.ParseGlobalTokenRevocationRequestAsync!(
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

                GlobalTokenRevocationOutcome outcome = await oauth.RevokeSubjectTokensAsync!(
                    request.SubId, registration, context, ct).ConfigureAwait(false);

                //§3 status-code mapping. 204 conveys "revocation initiated"; 403/404/422
                //are the application-determined outcomes the seam reports.
                return outcome switch
                {
                    GlobalTokenRevocationOutcome.Initiated =>
                        (null, ServerHttpResponse.NoContent()),
                    GlobalTokenRevocationOutcome.SubjectNotFound =>
                        (null, ServerHttpResponse.NotFound()),
                    GlobalTokenRevocationOutcome.Forbidden =>
                        (null, await ChallengedAsync(
                            ServerHttpResponse.Forbidden(
                                OAuthErrors.InsufficientScope, "Not authorized to revoke this subject."),
                            OAuthErrors.InsufficientScope, server, registration, context, ct).ConfigureAwait(false)),
                    GlobalTokenRevocationOutcome.Unprocessable =>
                        (null, ServerHttpResponse.UnprocessableEntity(
                            OAuthErrors.InvalidRequest, "The revocation request could not be processed.")),

                    _ => (null, ServerHttpResponse.UnprocessableEntity(
                        OAuthErrors.InvalidRequest, "The revocation request could not be processed."))
                };
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    /// <summary>
    /// Attaches to <paramref name="refusal"/> the <c>WWW-Authenticate</c> challenge
    /// <c>Bearer realm="&lt;issuer&gt;"</c>, with <c>error="&lt;error&gt;"</c> when
    /// <paramref name="error"/> is given, built by <see cref="BearerTokenChallenge.BuildChallenge"/>.
    /// The realm is <see cref="CredentialEndpointDpopValidation.HeaderSafeIssuer"/> of the issuer
    /// <see cref="CredentialEndpointDpopValidation.ResolveIssuerAsync"/> resolves, so an internationalized
    /// issuer is written in its URI form. <see cref="CredentialEndpointDpopValidation.HeaderSafeIssuer"/>
    /// throws for an issuer whose host IDNA cannot map, and the default issuer resolver throws
    /// <see cref="InvalidOperationException"/> when no issuer resolves; either issuer is the application's
    /// own configuration, the one its tokens are issued under.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.5.2">RFC 9110 Section 15.5.2</see>:
    /// "The server generating a 401 response MUST send a WWW-Authenticate header field (Section 11.6.1)
    /// containing at least one challenge applicable to the target resource."
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3">RFC 6750 Section 3</see>: "All
    /// challenges defined by this specification MUST use the auth-scheme value "Bearer"." The
    /// <c>error</c> is the <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750
    /// Section 3.1</see> code of the refusal, the same code its body carries.
    /// </summary>
    /// <param name="refusal">The 401 or 403 refusal the challenge is attached to.</param>
    /// <param name="error">The RFC 6750 Section 3.1 error code, or <see langword="null"/> when the request carried no access token.</param>
    /// <param name="server">The authorization server whose issuer resolver names the realm.</param>
    /// <param name="registration">The client (tenant) the request belongs to.</param>
    /// <param name="context">The per-request context.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The refusal with its challenge.</returns>
    private static async ValueTask<ServerHttpResponse> ChallengedAsync(
        ServerHttpResponse refusal,
        string? error,
        EndpointServer server,
        ClientRecord registration,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        Uri issuer = await CredentialEndpointDpopValidation.ResolveIssuerAsync(
            server, registration, context, cancellationToken).ConfigureAwait(false);
        string challenge = BearerTokenChallenge.BuildChallenge(
            realm: CredentialEndpointDpopValidation.HeaderSafeIssuer(issuer), error: error);

        return refusal.WithHeader(WellKnownHttpHeaderNames.WwwAuthenticate, challenge);
    }
}
