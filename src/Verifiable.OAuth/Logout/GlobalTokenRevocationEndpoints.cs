using System.Text;
using Verifiable.Core;
using Verifiable.OAuth.Oid4Vci;
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
/// The request's client credentials are read once, through <see cref="ClientCredentialReading.Read"/>, before
/// the authentication seam, and the seam receives that reading. A malformed reading (a client authentication
/// field sent twice, the <c>Authorization</c> field on two lines or outside its grammar, two mechanisms) is
/// answered 400 <c>invalid_request</c> with the challenge <c>Bearer realm="&lt;issuer&gt;", error="invalid_request"</c>
/// and never reaches the seam. A present <c>Authorization</c> line that is empty or white space only is read as
/// a request without the authentication information the endpoint reads, as the library's other bearer
/// resources read it, and is answered as below. A refused <c>Basic</c> credential is answered in its own scheme, 401
/// <c>invalid_client</c> with <c>Basic realm="&lt;issuer&gt;"</c>, as the library's client authentication failure
/// is.
/// </para>
/// <para>
/// Two answers carry the <c>Bearer</c> challenge whose <c>realm</c> is the issuer the request
/// is served under, in the shape of <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750
/// Section 3.1</see>: a refusal of the authentication seam (401) and the revoke-subject seam's
/// <see cref="GlobalTokenRevocationOutcome.Forbidden"/> (403 <c>insufficient_scope</c>). A refused
/// request whose <c>Authorization</c> field holds an access token, as
/// <see cref="BearerTokenValidation.TryExtractAccessToken(Verifiable.Core.ExchangeContext, out string?, out bool)"/> reads it, is 401 <c>invalid_token</c>
/// with the error in the challenge; any other refused request (no <c>Authorization</c> field, an
/// empty or white-space value, a credential of another scheme than <c>Basic</c>) is 401 with an empty body and a
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

                //The dispatcher sets the registration before a candidate runs. A loaded
                //registration that is not a ClientRecord reaches the endpoint as no registration;
                //the endpoint cannot serve the request then, and the fault is the server's wiring,
                //not the caller's. A materializer's replacement of another type is answered by
                //the dispatcher before the endpoint runs.
                ClientRecord? registration = context.ClientRegistration;
                if(registration is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, WellKnownOAuthErrorDescriptions.ServerNotReady));
                }

                //The request's client credentials are read once, before the seam, and a malformed
                //reading (a field sent twice, two Authorization lines, a value outside the grammar,
                //two mechanisms) is refused 400 invalid_request with the Bearer challenge, the code
                //RFC 6750 Section 3.1 gives to a request that repeats a parameter, uses more than one
                //method for including an access token, or is otherwise malformed. A present
                //Authorization line that is empty or white space only carries no credential for this
                //endpoint, as at the library's other bearer resources: the request lacks the
                //authentication information the endpoint reads and goes to the seam as such.
                IncomingRequest? req = context.IncomingRequest;
                ClientCredentialReading clientCredentials = AuthCode.AuthCodeEndpoints.CarriedClientCredentials(context, fields);
                bool isAuthorizationLineEmpty = clientCredentials is { IsAuthorizationMalformed: true, Authorization.Scheme.Length: 0 };
                ServerHttpResponse? malformedCredentials = isAuthorizationLineEmpty
                    ? null
                    : AuthCode.AuthCodeEndpoints.RefuseMalformedClientCredentials(clientCredentials);
                if(malformedCredentials is not null)
                {
                    return (null, await CredentialEndpointDpopValidation.ChallengedAsync(
                        malformedCredentials, OAuthErrors.InvalidRequest, server, registration, context, ct).ConfigureAwait(false));
                }

                //The draft's Section 3.2: "The request MUST also be authenticated." Its
                //Section 3.5 recommends a private key JWT. The seam owns the method and judges
                //the reading; the gate guarantees it is wired. A client whose registration names a
                //Client ID Metadata Document presenting a credential is judged against its document:
                //the materialization fetched it before this endpoint ran, or refused the request
                //through RefuseUnauthenticatedAsync.
                bool clientAuthenticated = await oauth.ValidateClientCredentialsAsync!(
                    clientCredentials, registration, context, ct).ConfigureAwait(false);
                if(!clientAuthenticated)
                {
                    return (null, await RefuseUnauthenticatedAsync(clientCredentials, server, registration, context, ct).ConfigureAwait(false));
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
                        (null, await CredentialEndpointDpopValidation.ChallengedAsync(
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
    /// The endpoint's answer to a request it does not authenticate: the client authentication seam refused
    /// <paramref name="reading"/>, or the Client ID Metadata Document materialization
    /// (<see cref="Server.Pipeline.ClientIdMetadataMaterialization.Build"/>) found the client's document unfetchable
    /// or a <c>client_id</c> naming another client, so a caller cannot tell those refusals from a refused
    /// authentication. A failed <c>Basic</c> attempt is answered in its own scheme by the library's client
    /// authentication failure (<see cref="AuthCode.AuthCodeEndpoints.ClientAuthenticationFailureResponseAsync"/>):
    /// 401 <c>invalid_client</c> with <c>Basic realm="&lt;issuer&gt;"</c> when an issuer resolves for the request, and
    /// otherwise 400 <c>invalid_client</c> without a challenge, as the token endpoint answers it. A request whose
    /// <c>Authorization</c> field holds an access token, as the library's extractor reads that field, carried a
    /// credential and is told why: 401 <c>invalid_token</c> in the body and in the <c>Bearer</c> challenge. A request
    /// with no <c>Authorization</c> field, an empty value or another scheme lacks the authentication information this
    /// endpoint reads and is answered 401 with an empty body and the <c>Bearer</c> challenge without an error code,
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>: "If the request
    /// lacks any authentication information (e.g., the client was unaware that authentication is necessary or
    /// attempted using an unsupported authentication method), the resource server SHOULD NOT include an error code or
    /// other error information." A form credential (a client assertion or secret in the request's parameters) is
    /// handed to the client authentication seam, which may accept it; one it refuses is answered as a request without
    /// an <c>Authorization</c> field is, 401 with an empty body and the <c>Bearer</c> challenge without an error code.
    /// The reason: the draft defines no form credential for this endpoint
    /// (<see href="https://datatracker.ietf.org/doc/html/draft-parecki-oauth-global-token-revocation-06#section-3.2">draft-parecki-oauth-global-token-revocation-06 Section 3.2</see>:
    /// "This specification RECOMMENDS using a private key JWT as described in Section 3.5. Other authentication methods
    /// such as OAuth 2.0 Bearer Token [RFC6750] MAY be used where appropriate."), and <c>Bearer</c> is the challenge
    /// this refusal's branch selects for a request that is not a <c>Basic</c> attempt, where the endpoint reads
    /// <c>Basic</c> in the <c>Authorization</c> field as a client authentication and extracts a <c>Bearer</c> or a
    /// <c>DPoP</c> token there
    /// (<see cref="BearerTokenValidation.TryExtractAccessToken(Verifiable.Core.ExchangeContext, out string?, out bool)"/>),
    /// so the refusal tells the caller the scheme the draft names and gives no error information about a credential of
    /// another kind. Every 401 carries its challenge, whose realm is the issuer the request is served under.
    /// </summary>
    /// <param name="reading">The request's one reading of its client credentials.</param>
    /// <param name="server">The server the request is served by.</param>
    /// <param name="registration">The registration the request is served for.</param>
    /// <param name="context">The per-request context.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The 401 refusal with its challenge, or, for a failed <c>Basic</c> attempt where no issuer resolves for the
    /// request, the 400 <c>invalid_client</c> refusal without a challenge.
    /// </returns>
    internal static async ValueTask<ServerHttpResponse> RefuseUnauthenticatedAsync(
        ClientCredentialReading reading,
        EndpointServer server,
        ClientRecord registration,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        if(reading.HasBasicAuthorization)
        {
            return await AuthCode.AuthCodeEndpoints.ClientAuthenticationFailureResponseAsync(
                reading, WellKnownOAuthErrorDescriptions.ClientAuthenticationFailed,
                registration, context, cancellationToken).ConfigureAwait(false);
        }

        bool isAccessTokenCarried = BearerTokenValidation.TryExtractAccessToken(reading.Authorization, out _, out _);

        return isAccessTokenCarried
            ? await CredentialEndpointDpopValidation.ChallengedAsync(
                ServerHttpResponse.Unauthorized(
                    OAuthErrors.InvalidToken, WellKnownOAuthErrorDescriptions.ClientAuthenticationFailed),
                OAuthErrors.InvalidToken, server, registration, context, cancellationToken).ConfigureAwait(false)
            : await CredentialEndpointDpopValidation.ChallengedAsync(
                ServerHttpResponse.Unauthorized(), error: null, server, registration, context, cancellationToken).ConfigureAwait(false);
    }
}
