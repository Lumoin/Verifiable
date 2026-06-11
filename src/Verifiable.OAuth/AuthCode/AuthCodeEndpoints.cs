using System.Buffers;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Verifiable.Core;
using Verifiable.Core.Assessment;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.OAuth.AuthCode.Server;
using Verifiable.OAuth.AuthCode.Server.States;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Introspection;
using Verifiable.OAuth.Jar;
using Verifiable.OAuth.Jarm;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oidc;
using Verifiable.OAuth.Validation;

using Verifiable.OAuth.Server;

using Verifiable.OAuth.Server.Audit;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.OAuth.Server.Routing;
using Verifiable.OAuth.Server.States;
namespace Verifiable.OAuth.AuthCode;

/// <summary>
/// Endpoint builder module for the OAuth 2.0 Authorization Code flow with PKCE.
/// </summary>
/// <remarks>
/// <para>
/// Produces PAR, Authorize (PAR-backed), Direct Authorize, and Token endpoints.
/// Register at startup via <see cref="AuthorizationServer.EndpointBuilders"/>:
/// </para>
/// <code>
/// server.EndpointBuilders.AddRange([
///     AuthCodeEndpoints.Builder,
///     MetadataEndpoints.Builder
/// ]);
/// </code>
/// <para>
/// <strong>JSON wire format and the serialization firewall.</strong> The
/// HTTP response bodies this module emits — the PAR response and the token
/// response — are written as JSON by hand using
/// <see cref="System.Text.StringBuilder"/> rather than through a serializer.
/// This is deliberate. <c>Verifiable.OAuth</c> takes no dependency on
/// <c>Verifiable.Json</c>, on <c>System.Text.Json</c>, or on any other JSON
/// library, and the project's banned-symbol analyzer enforces this. The
/// library does not impose a JSON implementation on the application.
/// </para>
/// <para>
/// The wire shapes here are RFC-defined and stable: a handful of well-known
/// field names per
/// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 §5.1</see>
/// for the token response and
/// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.2">RFC 9126 §2.2</see>
/// for the PAR response, all primitive values (strings, integers), no
/// nested or schema-variable structure. For shapes like that, manual
/// <see cref="System.Text.StringBuilder"/> construction is the simplest
/// path that respects the firewall and stays AOT-safe without
/// source-generator context maintenance.
/// </para>
/// <para>
/// The corresponding parsing direction lives behind delegate slots so the
/// application chooses the parser; default implementations live in
/// <c>Verifiable.Json</c> and a CBOR-speaking or otherwise custom
/// deployment supplies its own. The output side stays symmetric: a
/// non-JSON-format deployment that needs to swap the response-building
/// surface replaces these endpoint builders with its own. The library
/// remains agnostic to wire format.
/// </para>
/// </remarks>
[DebuggerDisplay("AuthCodeEndpoints")]
public static class AuthCodeEndpoints
{

    /// <summary>
    /// The endpoint builder delegate. Pass this to
    /// <see cref="AuthorizationServer.EndpointBuilders"/>.
    /// </summary>
    public static readonly EndpointBuilderDelegate Builder = static (registration, context, ct) =>
    {
        List<EndpointCandidate> candidates = [];

        if(registration.IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OAuthPushedAuthorization))
        {
            candidates.Add(BuildPar());
        }

        if(registration.IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OAuthAuthorizationCode))
        {
            candidates.Add(BuildAuthorize());
            //RFC 9101 §5 — explicit both-present (request + request_uri) rejection on the
            //authorize URL; the routing matchers decline that case, this one owns it.
            candidates.Add(BuildAuthorizeRequestObjectConflict());
        }

        if(registration.IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OAuthDirectAuthorization))
        {
            candidates.Add(BuildDirectAuthorize());
        }

        if(registration.IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OAuthPushedAuthorization)
            && registration.IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OAuthJwtSecuredAuthorizationRequest))
        {
            candidates.Add(BuildJarPar());
        }

        if(registration.IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OAuthDirectAuthorization)
            && registration.IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OAuthJwtSecuredAuthorizationRequest))
        {
            candidates.Add(BuildAuthorizeJarByValue());
        }

        bool hasTokenCapability =
            registration.IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OAuthAuthorizationCode) ||
            registration.IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OAuthClientCredentials) ||
            registration.IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OAuthTokenExchange);

        if(hasTokenCapability)
        {
            candidates.Add(BuildToken());
        }

        //client_credentials grant (RFC 6749 §4.4) — machine-to-machine token
        //issuance (for example a Shared Signals Receiver obtaining ssf.manage).
        //Activates only when BOTH the capability and the client-authentication
        //seam are present: an unauthenticated client-credentials grant would
        //mint tokens for anyone claiming a client_id.
        if(registration.IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OAuthClientCredentials)
            && context.Server?.Integration.ValidateClientCredentialsAsync is not null)
        {
            candidates.Add(BuildClientCredentials());
        }

        //OID4VCI 1.0 §6 Pre-Authorized Code grant — shares the token endpoint URL,
        //disjoint from the other grants by the grant_type filter. Activates only when
        //BOTH the capability and the code-validation seam are present: an advertised
        //pre-authorized grant with no seam would mint access tokens for any code string
        //(fail-closed, like client_credentials).
        if(registration.IsCapabilityAllowed(WellKnownCapabilityIdentifiers.Oid4VciPreAuthorizedCodeGrant)
            && context.Server?.Integration.ValidatePreAuthorizedCodeAsync is not null)
        {
            candidates.Add(BuildPreAuthorizedCodeToken());
        }

        //Refresh-token grant per RFC 6749 §6 is enabled whenever the
        //registration allows AuthorizationCode capability. RFC 9700 §2.2.2
        //rotation is enforced unconditionally on every successful refresh.
        if(registration.IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OAuthAuthorizationCode))
        {
            candidates.Add(BuildRefreshToken());
        }

        //Token revocation (RFC 7009). Activates only when the capability is
        //allowed AND both the revocation seam and the client-authentication seam
        //are wired: a revocation endpoint that cannot authenticate the client or
        //cannot revoke would be a silent no-op that misleads clients into
        //believing their tokens were killed (fail-closed, like client_credentials).
        if(registration.IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OAuthTokenRevocation)
            && context.Server?.Integration.RevokeTokenAsync is not null
            && context.Server?.Integration.ValidateClientCredentialsAsync is not null)
        {
            candidates.Add(BuildRevocation());
        }

        //RFC 7662 introspection materializes only when the capability is allowed
        //AND both the introspection seam and the client-authentication seam are
        //wired: an endpoint that cannot authenticate the caller would leak token
        //state, and one with no store to read could only answer active:false —
        //both fail-closed, like revocation above.
        if(registration.IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OAuthTokenIntrospection)
            && context.Server?.Integration.IntrospectTokenAsync is not null
            && context.Server?.Integration.ValidateClientCredentialsAsync is not null)
        {
            candidates.Add(BuildIntrospection());
        }

        return ValueTask.FromResult<IReadOnlyList<EndpointCandidate>>(candidates);
    };


    /// <summary>
    /// Builds the PAR endpoint per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126">RFC 9126</see>.
    /// </summary>
    /// <remarks>
    /// <see cref="ServerEndpoint.BuildResponse"/> writes the response body —
    /// <c>request_uri</c> and <c>expires_in</c> — directly with
    /// <see cref="System.Text.StringBuilder"/>. See the serialization-firewall
    /// paragraph in the remarks on <see cref="AuthCodeEndpoints"/> for the
    /// rationale.
    /// </remarks>
    private static EndpointCandidate BuildPar() =>
        new()
        {
            Name = WellKnownEndpointNames.AuthCodePar,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownCapabilityIdentifiers.OAuthPushedAuthorization,
            StartsNewFlow = true,
            Kind = FlowKind.AuthCodeServer,
            DiscoveryMetadataKey = AuthorizationServerMetadataParameterNames.PushedAuthorizationRequestEndpoint,

            //Acceptance test: POST to /par with PKCE body fields, no JAR request
            //parameter, and no TransactionNonce on context. Disjointness vs
            //JarPar (Request present) and vs OID4VP PAR (TransactionNonce
            //present).
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
                if(!fields.ContainsKey(OAuthRequestParameterNames.CodeChallenge))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                //Disjointness vs JAR-PAR per RFC 9101 §6.1.
                if(fields.ContainsKey(OAuthRequestParameterNames.Request))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                //Disjointness vs OID4VP PAR.
                if(context.TransactionNonce is not null)
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
            },

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                AuthorizationServer server = context.Server!;

                if(!fields.TryGetValue(OAuthRequestParameterNames.ClientId, out string? clientId)
                    || string.IsNullOrWhiteSpace(clientId))
                {
                    return ((OAuthFlowInput?)null, (ServerHttpResponse?)ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "Missing client_id."));
                }

                if(!fields.TryGetValue(OAuthRequestParameterNames.CodeChallenge, out string? challenge)
                    || string.IsNullOrWhiteSpace(challenge))
                {
                    return ((OAuthFlowInput?)null, (ServerHttpResponse?)ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "Missing code_challenge."));
                }

                fields.TryGetValue(OAuthRequestParameterNames.CodeChallengeMethod, out string? method);
                if(!IsAcceptedPkceMethod(method, context))
                {
                    return ((OAuthFlowInput?)null, (ServerHttpResponse?)ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        "code_challenge_method is not accepted under the active policy."));
                }

                if(!fields.TryGetValue(OAuthRequestParameterNames.RedirectUri, out string? redirectUriString)
                    || !Uri.TryCreate(redirectUriString, UriKind.Absolute, out Uri? redirectUri))
                {
                    return ((OAuthFlowInput?)null, (ServerHttpResponse?)ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "Missing or invalid redirect_uri."));
                }

                //RFC 9700 §2.1 + OAuth 2.1 §2.3.1 — redirect_uri exact-match
                //against the registered set. Parallel to the JAR-PAR check
                //around line 988; this matcher's MatchesRequest already
                //asserts context.Registration is non-null, so the read is
                //unconditional here.
                ClientRecord registration = context.Registration!;
                if(!registration.AllowedRedirectUris.Contains(redirectUri))
                {
                    return ((OAuthFlowInput?)null, (ServerHttpResponse?)ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        $"redirect_uri '{redirectUri}' is not among the registered redirect URIs."));
                }

                fields.TryGetValue(OAuthRequestParameterNames.Scope, out string? scope);
                if(context.ScopeRequiredOnRequest && string.IsNullOrEmpty(scope))
                {
                    return ((OAuthFlowInput?)null, (ServerHttpResponse?)ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        "scope is required under the active policy."));
                }
                scope ??= string.Empty;

                fields.TryGetValue(WellKnownJwtClaimNames.Nonce, out string? nonce);
                nonce ??= string.Empty;

                //RFC 9470 §4 step-up: the authentication-requirement parameters
                //(acr_values, max_age) are carried forward to the authorization
                //endpoint where they are evaluated against the established
                //authentication. max_age is a non-negative integer (OIDC Core
                //§3.1.2.1); a malformed value is a request error.
                fields.TryGetValue(OAuthRequestParameterNames.AcrValues, out string? acrValues);
                fields.TryGetValue(OAuthRequestParameterNames.State, out string? requestState);
                (int? maxAge, bool isMaxAgeWellFormed) = ReadRequestedMaxAge(fields);
                if(!isMaxAgeWellFormed)
                {
                    return ((OAuthFlowInput?)null, (ServerHttpResponse?)ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "max_age must be a non-negative integer."));
                }

                //JARM / FAPI 2.0 Message Signing §5.4 — a response_mode requesting a
                //JWT-secured authorization response is validated for servability at
                //receipt and the pushed value is carried verbatim, so it wins over any
                //front-channel duplicate by construction.
                (string? responseMode, ServerHttpResponse? responseModeFailure) =
                    ReadResponseMode(fields, server, context);
                if(responseModeFailure is not null)
                {
                    return ((OAuthFlowInput?)null, (ServerHttpResponse?)responseModeFailure);
                }

                //RFC 9396 / OID4VCI 1.0 §5.1.1 — authorization_details is shape-validated at
                //receipt (fail fast on an unsupported type or a missing
                //credential_configuration_id) and the pushed value is carried verbatim; the
                //granted credential_identifiers are resolved at the token endpoint.
                string? authorizationDetails = ReadAuthorizationDetails(fields);
                if(authorizationDetails is not null)
                {
                    ServerHttpResponse? detailsFailure = await ValidateAuthorizationDetailsShapeAsync(
                        server, authorizationDetails, registration, context, ct).ConfigureAwait(false);
                    if(detailsFailure is not null)
                    {
                        return ((OAuthFlowInput?)null, (ServerHttpResponse?)detailsFailure);
                    }
                }

                //OID4VCI 1.0 §5.1.3 issuer_state and RFC 8707 resource (§5.1.2). The pushed value
                //is authoritative (RFC 9101 §6.3 via RFC 9126 §4); issuer_state is carried UNTRUSTED
                //and surfaced to the application's decision seam at the authorization endpoint.
                string? issuerState = ReadIssuerState(fields);
                string? resource = ReadResource(fields);

                DateTimeOffset now = server.TimeProvider.GetUtcNow();

                string flowId = context.FlowId!;
                string requestUriToken = await server.Integration.GenerateIdentifierAsync!(
                    WellKnownIdentifierPurposes.OAuthRequestUriToken, context, ct)
                    .ConfigureAwait(false);
                Uri requestUri = new($"urn:ietf:params:oauth:request_uri:{requestUriToken}");

                //RFC 9126 §2.2 leaves the request_uri lifetime implementation-defined.
                //Library policy lives in policy.RequestUriLifetime (default 60s).
                TimeSpan parLifetime = context.RequestUriLifetime;
                DateTimeOffset expiresAt = now + parLifetime;
                int expiresIn = (int)parLifetime.TotalSeconds;

                return ((OAuthFlowInput?)new ServerParValidated(
                    FlowId: flowId,
                    RequestUri: requestUri,
                    CodeChallenge: challenge,
                    RedirectUri: redirectUri,
                    Scope: scope,
                    ClientId: clientId,
                    Nonce: nonce,
                    ExpectedIssuer: clientId,
                    ReceivedAt: now,
                    ExpiresAt: expiresAt,
                    ExpiresIn: expiresIn,
                    AcrValues: acrValues,
                    MaxAge: maxAge,
                    State: requestState,
                    AuthorizationDetails: authorizationDetails,
                    ResponseMode: responseMode,
                    IssuerState: issuerState,
                    Resource: resource), (ServerHttpResponse?)null);
            },
            BuildResponse = static (state, _, _) =>
            {
                if(state is not ParRequestReceivedState par)
                {
                    return ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, "Unexpected state after PAR.");
                }

                //ExpiresIn is the wire value preserved from PAR-input time so the
                //response value is exactly what the client was promised at PAR
                //receipt, with no recomputation drift between BuildInputAsync and
                //BuildResponse. The source policy is TimingPolicy.AuthCodeParLifetime.
                string body =
                    $"{{\"request_uri\":\"{par.RequestUri}\",\"expires_in\":{par.ExpiresIn}}}";
                //RFC 9126 §2.2: a successful PAR response MUST use HTTP 201 Created.
                return ServerHttpResponse
                    .Created(body, WellKnownMediaTypes.Application.Json)
                    .WithHeader(WellKnownHttpHeaderNames.CacheControl, WellKnownCacheControlValues.NoStore);
            }
        };


    private static EndpointCandidate BuildAuthorize() =>
        new()
        {
            Name = WellKnownEndpointNames.AuthCodeAuthorize,
            HttpMethod = WellKnownHttpMethods.Get,
            Capability = WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            StartsNewFlow = false,
            Kind = FlowKind.AuthCodeServer,
            DiscoveryMetadataKey = AuthorizationServerMetadataParameterNames.AuthorizationEndpoint,

            ExtractCorrelationKey = static (path, fields, context) =>
            {
                if(fields.TryGetValue(OAuthRequestParameterNames.RequestUri, out string? requestUri)
                    && !string.IsNullOrWhiteSpace(requestUri))
                {
                    const string urnPrefix = "urn:ietf:params:oauth:request_uri:";
                    return requestUri.StartsWith(urnPrefix, StringComparison.Ordinal)
                        ? requestUri[urnPrefix.Length..]
                        : requestUri;
                }

                return null;
            },

            //Acceptance test: GET to /authorize with a request_uri query
            //parameter (PAR-completed authorize). Disjointness vs the direct
            //PKCE matcher (no request_uri) is enforced by the request_uri
            //presence requirement here.
            MatchesRequest = static (fields, context, endpoint, ct) =>
            {
                IncomingRequest? req = context.IncomingRequest;
                if(req is null) { return ValueTask.FromResult<MatchPayload?>(null); }
                if(!WellKnownHttpMethods.IsGet(req.Method))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                if(!PathEquals.Equals(req.Path, endpoint.ResolvedUri.AbsolutePath))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                if(!fields.ContainsKey(OAuthRequestParameterNames.RequestUri))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                //RFC 9101 §5 — request and request_uri MUST NOT both be present. The
                //both-present case is owned by BuildAuthorizeRequestObjectConflict, which
                //rejects it explicitly; decline here so it doesn't route through PAR-flow
                //correlation (which would surface a misleading "flow not found").
                if(fields.ContainsKey(OAuthRequestParameterNames.Request))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
            },

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                AuthorizationServer server = context.Server!;

                if(currentState is not ParRequestReceivedState)
                {
                    return ((OAuthFlowInput?)null, (ServerHttpResponse?)ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "Flow not in expected state."));
                }

                string? subjectId = context.SubjectId;
                if(string.IsNullOrWhiteSpace(subjectId))
                {
                    return ((OAuthFlowInput?)null, (ServerHttpResponse?)ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, "Subject not authenticated."));
                }

                ParRequestReceivedState parState = (ParRequestReceivedState)currentState;

                DateTimeOffset now = server.TimeProvider.GetUtcNow();
                DateTimeOffset authTime = context.AuthTime ?? now;

                //RFC 9101 §6.3 (applied to PAR via RFC 9126 §4): when the authorization request
                //is passed by reference (request_uri), the authorization server MUST only use the
                //pushed parameters, even if the same parameter is duplicated in the query. Honoring
                //a front-channel scope would defeat PAR's integrity guarantee (RFC 9126 §1), so the
                //pushed scope is authoritative and a query-string scope is ignored.
                string grantedScope = parState.Scope;

                //Extraneous front-channel parameters are ignored, but their presence on a
                //request_uri-referenced request may indicate a non-conformant client or a tampering
                //attempt — surface it on the request's trace (observational; does not change behavior).
                if(HasExtraneousReferencedRequestParameters(fields))
                {
                    System.Diagnostics.Activity.Current?.AddEvent(
                        new System.Diagnostics.ActivityEvent(
                            Diagnostics.OAuthEventNames.ExtraneousAuthorizeParameters));
                }

                ServerHttpResponse? requirementFailure = await EvaluateAuthenticationRequirementsAsync(
                    server, context, parState.AcrValues, parState.MaxAge, grantedScope,
                    subjectId, now, parState.RedirectUri, parState.State, ct,
                    requestedAuthorizationDetails: parState.AuthorizationDetails,
                    responseMode: parState.ResponseMode,
                    clientId: parState.ClientId,
                    requestedIssuerState: parState.IssuerState,
                    requestedResource: parState.Resource).ConfigureAwait(false);
                if(requirementFailure is not null)
                {
                    return ((OAuthFlowInput?)null, (ServerHttpResponse?)requirementFailure);
                }

                string rawCode = await server.Integration.GenerateIdentifierAsync!(
                    WellKnownIdentifierPurposes.OAuthAuthorizationCode, context, ct)
                    .ConfigureAwait(false);
                string codeHash = ComputeDigestBase64Url(
                    rawCode,
                    CryptoTags.Sha256Digest,
                    WellKnownHashAlgorithms.Sha256SizeBytes,
                    server.Codecs.ComputeDigest!,
                    server.Codecs.Encoder!,
                    SensitiveMemoryPool<byte>.Shared);

                //JARM: the success response parameters are signed into the JWT Response
                //Document here, where the code exists; BuildResponse encodes it per the
                //carried response_mode.
                (string? jarmResponseJwt, ServerHttpResponse? jarmFailure) =
                    await TryIssueJarmResponseJwtAsync(
                        server, context, parState.ResponseMode, parState.ClientId,
                        BuildAuthorizeSuccessParameters(codeHash, parState.State), ct)
                        .ConfigureAwait(false);
                if(jarmFailure is not null)
                {
                    return ((OAuthFlowInput?)null, (ServerHttpResponse?)jarmFailure);
                }

                if(jarmResponseJwt is not null)
                {
                    context.SetJarmResponseJwt(jarmResponseJwt);
                }

                OAuthFlowInput input = new ServerAuthorizeCompleted(
                    CodeHash: codeHash,
                    SubjectId: subjectId,
                    AuthTime: authTime,
                    Scope: grantedScope,
                    CompletedAt: now,
                    SessionId: context.SessionId,
                    Acr: context.Acr);

                return ((OAuthFlowInput?)input, (ServerHttpResponse?)null);
            },
            BuildResponse = static (state, _, context) =>
            {
                if(state is not ServerCodeIssuedState code)
                {
                    return ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, "Unexpected state after authorize.");
                }

                return BuildAuthorizeCompletedResponse(code, context);
            }
        };


    private static EndpointCandidate BuildDirectAuthorize() =>
        new()
        {
            Name = WellKnownEndpointNames.AuthCodeDirectAuthorize,
            HttpMethod = WellKnownHttpMethods.Get,
            Capability = WellKnownCapabilityIdentifiers.OAuthDirectAuthorization,
            StartsNewFlow = true,
            Kind = FlowKind.AuthCodeServer,
            //DiscoveryMetadataKey null — direct authorize shares the URL with
            //AuthCodeAuthorize which is advertised; emitting twice would be
            //wrong.

            //Acceptance test: GET to /authorize with code_challenge in the
            //query (direct PKCE) and no request_uri (which would route to the
            //PAR-completed Authorize) and no Request (which would route to
            //JAR-by-value).
            MatchesRequest = static (fields, context, endpoint, ct) =>
            {
                IncomingRequest? req = context.IncomingRequest;
                if(req is null) { return ValueTask.FromResult<MatchPayload?>(null); }
                if(!WellKnownHttpMethods.IsGet(req.Method))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                if(!PathEquals.Equals(req.Path, endpoint.ResolvedUri.AbsolutePath))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                if(fields.ContainsKey(OAuthRequestParameterNames.RequestUri))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                //Disjointness vs JAR-by-value Authorize.
                if(fields.ContainsKey(OAuthRequestParameterNames.Request))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                if(!fields.ContainsKey(OAuthRequestParameterNames.CodeChallenge))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
            },

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                AuthorizationServer server = context.Server!;

                if(!fields.TryGetValue(OAuthRequestParameterNames.ClientId, out string? clientId)
                    || string.IsNullOrWhiteSpace(clientId))
                {
                    return ((OAuthFlowInput?)null, (ServerHttpResponse?)ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "Missing client_id."));
                }

                if(!fields.TryGetValue(OAuthRequestParameterNames.CodeChallenge, out string? challenge)
                    || string.IsNullOrWhiteSpace(challenge))
                {
                    return ((OAuthFlowInput?)null, (ServerHttpResponse?)ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "Missing code_challenge."));
                }

                fields.TryGetValue(OAuthRequestParameterNames.CodeChallengeMethod, out string? method);
                if(!IsAcceptedPkceMethod(method, context))
                {
                    return ((OAuthFlowInput?)null, (ServerHttpResponse?)ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        "code_challenge_method is not accepted under the active policy."));
                }

                //FAPI 2.0 §5.2.2 — when the profile mandates PAR, the direct Authorize
                //path is refused; the client must push the request first.
                if(context.RequirePushedAuthorizationRequests)
                {
                    return ((OAuthFlowInput?)null, (ServerHttpResponse?)ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        "This authorization server requires Pushed Authorization Requests; a direct "
                        + "authorization request is not accepted (FAPI 2.0 §5.2.2)."));
                }

                if(!fields.TryGetValue(OAuthRequestParameterNames.RedirectUri, out string? redirectUriString)
                    || !Uri.TryCreate(redirectUriString, UriKind.Absolute, out Uri? redirectUri))
                {
                    return ((OAuthFlowInput?)null, (ServerHttpResponse?)ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "Missing or invalid redirect_uri."));
                }

                string? subjectId = context.SubjectId;
                if(string.IsNullOrWhiteSpace(subjectId))
                {
                    return ((OAuthFlowInput?)null, (ServerHttpResponse?)ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, "Subject not authenticated."));
                }

                fields.TryGetValue(OAuthRequestParameterNames.Scope, out string? scope);
                scope ??= string.Empty;

                fields.TryGetValue(WellKnownJwtClaimNames.Nonce, out string? nonce);
                nonce ??= string.Empty;

                //RFC 9470 §4 step-up — the authentication-requirement parameters arrive
                //directly on the authorization request (RFC 9470 Figures 4 and 5). max_age
                //is a non-negative integer (OIDC Core §3.1.2.1); a malformed value is a
                //request error.
                fields.TryGetValue(OAuthRequestParameterNames.AcrValues, out string? acrValues);
                fields.TryGetValue(OAuthRequestParameterNames.State, out string? requestState);
                (int? maxAge, bool isMaxAgeWellFormed) = ReadRequestedMaxAge(fields);
                if(!isMaxAgeWellFormed)
                {
                    return ((OAuthFlowInput?)null, (ServerHttpResponse?)ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "max_age must be a non-negative integer."));
                }

                //JARM / FAPI 2.0 Message Signing §5.4 — same servability gate as the PAR
                //path; on the direct authorization request the parameter arrives on the
                //front channel itself.
                (string? responseMode, ServerHttpResponse? responseModeFailure) =
                    ReadResponseMode(fields, server, context);
                if(responseModeFailure is not null)
                {
                    return ((OAuthFlowInput?)null, (ServerHttpResponse?)responseModeFailure);
                }

                //RFC 9396 / OID4VCI 1.0 §5.1.1 — same shape-validation as the PAR path; on the
                //direct authorization request the parameter arrives on the front channel itself.
                string? authorizationDetails = ReadAuthorizationDetails(fields);
                if(authorizationDetails is not null)
                {
                    //The matcher asserts context.Registration is non-null before this handler runs.
                    ClientRecord registration = context.Registration!;
                    ServerHttpResponse? detailsFailure = await ValidateAuthorizationDetailsShapeAsync(
                        server, authorizationDetails, registration, context, ct).ConfigureAwait(false);
                    if(detailsFailure is not null)
                    {
                        return ((OAuthFlowInput?)null, (ServerHttpResponse?)detailsFailure);
                    }
                }

                //OID4VCI 1.0 §5.1.3 issuer_state and RFC 8707 resource (§5.1.2) — on the direct
                //authorization request they arrive on the front channel itself. issuer_state is
                //surfaced UNTRUSTED to the decision seam, validated by neither the library nor read.
                string? issuerState = ReadIssuerState(fields);
                string? resource = ReadResource(fields);

                DateTimeOffset now = server.TimeProvider.GetUtcNow();
                DateTimeOffset authTime = context.AuthTime ?? now;

                ServerHttpResponse? requirementFailure = await EvaluateAuthenticationRequirementsAsync(
                    server, context, acrValues, maxAge, scope, subjectId, now, redirectUri, requestState, ct,
                    requestedAuthorizationDetails: authorizationDetails,
                    responseMode: responseMode,
                    clientId: clientId,
                    requestedIssuerState: issuerState,
                    requestedResource: resource)
                    .ConfigureAwait(false);
                if(requirementFailure is not null)
                {
                    return ((OAuthFlowInput?)null, (ServerHttpResponse?)requirementFailure);
                }

                string flowId = context.FlowId!;

                //RFC 6749 §4.1.2 recommends a maximum of 10 minutes for
                //authorization codes. Library policy lives in
                //policy.AuthorizationCodeLifetime (default 600s).
                DateTimeOffset expiresAt = now + context.AuthorizationCodeLifetime;

                string rawCode = await server.Integration.GenerateIdentifierAsync!(
                    WellKnownIdentifierPurposes.OAuthAuthorizationCode, context, ct)
                    .ConfigureAwait(false);
                string codeHash = ComputeDigestBase64Url(
                    rawCode,
                    CryptoTags.Sha256Digest,
                    WellKnownHashAlgorithms.Sha256SizeBytes,
                    server.Codecs.ComputeDigest!,
                    server.Codecs.Encoder!,
                    SensitiveMemoryPool<byte>.Shared);

                //JARM: signed here, where the code exists; BuildResponse encodes per the
                //carried response_mode.
                (string? jarmResponseJwt, ServerHttpResponse? jarmFailure) =
                    await TryIssueJarmResponseJwtAsync(
                        server, context, responseMode, clientId,
                        BuildAuthorizeSuccessParameters(codeHash, requestState), ct)
                        .ConfigureAwait(false);
                if(jarmFailure is not null)
                {
                    return ((OAuthFlowInput?)null, (ServerHttpResponse?)jarmFailure);
                }

                if(jarmResponseJwt is not null)
                {
                    context.SetJarmResponseJwt(jarmResponseJwt);
                }

                return ((OAuthFlowInput?)new ServerDirectAuthorizeCompleted(
                    FlowId: flowId,
                    CodeHash: codeHash,
                    CodeChallenge: challenge,
                    RedirectUri: redirectUri,
                    Scope: scope,
                    ClientId: clientId,
                    Nonce: nonce,
                    SubjectId: subjectId,
                    AuthTime: authTime,
                    ExpectedIssuer: clientId,
                    CompletedAt: now,
                    ExpiresAt: expiresAt,
                    SessionId: context.SessionId,
                    Acr: context.Acr,
                    State: requestState,
                    AuthorizationDetails: authorizationDetails,
                    ResponseMode: responseMode,
                    IssuerState: issuerState,
                    Resource: resource), (ServerHttpResponse?)null);
            },

            BuildResponse = static (state, _, context) =>
            {
                if(state is not ServerCodeIssuedState code)
                {
                    return ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, "Unexpected state after direct authorize.");
                }

                return BuildAuthorizeCompletedResponse(code, context);
            }
        };


    /// <summary>
    /// Builds the matcher that enforces RFC 9101 §5: an authorization request MUST NOT
    /// contain both <c>request</c> and <c>request_uri</c>. It uniquely matches the
    /// both-present GET <c>/authorize</c> case the three routing matchers each decline,
    /// and rejects it with an explicit <c>invalid_request</c> — deterministically, with
    /// no PAR-flow correlation (which would otherwise surface a misleading "flow not
    /// found").
    /// </summary>
    private static EndpointCandidate BuildAuthorizeRequestObjectConflict() =>
        new()
        {
            Name = WellKnownEndpointNames.AuthCodeRequestObjectConflict,
            HttpMethod = WellKnownHttpMethods.Get,
            Capability = WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            StartsNewFlow = true,
            Kind = FlowKind.AuthCodeServer,
            //DiscoveryMetadataKey null — this is a guard on the authorize URL, not an
            //independently advertised endpoint.

            MatchesRequest = static (fields, context, endpoint, ct) =>
            {
                IncomingRequest? req = context.IncomingRequest;
                if(req is null) { return ValueTask.FromResult<MatchPayload?>(null); }
                if(!WellKnownHttpMethods.IsGet(req.Method))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                if(!PathEquals.Equals(req.Path, endpoint.ResolvedUri.AbsolutePath))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                //Matches only when BOTH are present — the case every routing matcher declines.
                if(!fields.ContainsKey(OAuthRequestParameterNames.Request)
                    || !fields.ContainsKey(OAuthRequestParameterNames.RequestUri))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
            },

            BuildInputAsync = static (fields, context, currentState, ct) =>
                ValueTask.FromResult<(OAuthFlowInput?, ServerHttpResponse?)>(
                    ((OAuthFlowInput?)null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        "An authorization request MUST NOT contain both 'request' and 'request_uri' (RFC 9101 §5)."))),

            //Never reached — BuildInputAsync always returns the early-exit response.
            BuildResponse = static (_, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Unreachable."),
        };


    /// <summary>
    /// Builds the JAR-PAR endpoint per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101">RFC 9101</see> +
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126">RFC 9126</see>:
    /// PAR with a signed Request Object (JAR) instead of bare PKCE fields.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Disjoint from <see cref="BuildPar"/> on a single body-field signal —
    /// presence of the <c>request</c> parameter. The PKCE matcher's MatchesRequest
    /// rejects a body that carries <c>request</c>, the JAR matcher's MatchesRequest
    /// requires it; the chain remains disjoint and the DEBUG disjointness assertion
    /// passes.
    /// </para>
    /// </remarks>
    private static EndpointCandidate BuildJarPar() =>
        new()
        {
            Name = WellKnownEndpointNames.AuthCodeJarPar,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownCapabilityIdentifiers.OAuthPushedAuthorization,
            StartsNewFlow = true,
            Kind = FlowKind.AuthCodeServer,
            //DiscoveryMetadataKey null — JAR-PAR shares the URL with the
            //non-JAR PAR endpoint which advertises; emitting twice would be
            //wrong.

            //Acceptance test: POST to /par with the JAR Request parameter in
            //the body. Disjointness vs PKCE PAR (no Request) is enforced by
            //the Request presence requirement here.
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
                if(!fields.ContainsKey(OAuthRequestParameterNames.Request))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
            },

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                AuthorizationServer server = context.Server!;

                (AuthCodeRequestObject? requestObject, ServerHttpResponse? earlyExit) =
                    await VerifyAndValidateAuthCodeJarAsync(fields, context, server, ct)
                        .ConfigureAwait(false);

                if(earlyExit is not null)
                {
                    return ((OAuthFlowInput?)null, earlyExit);
                }

                AuthCodeRequestObject ro = requestObject!;
                DateTimeOffset now = server.TimeProvider.GetUtcNow();

                string flowId = context.FlowId!;
                string requestUriToken = await server.Integration.GenerateIdentifierAsync!(
                    WellKnownIdentifierPurposes.OAuthRequestUriToken, context, ct)
                    .ConfigureAwait(false);
                Uri requestUri = new($"urn:ietf:params:oauth:request_uri:{requestUriToken}");

                //RFC 9126 §2.2 leaves the request_uri lifetime implementation-defined.
                //Library policy lives in policy.RequestUriLifetime (default 60s).
                TimeSpan parLifetime = context.RequestUriLifetime;
                DateTimeOffset expiresAt = now + parLifetime;
                int expiresIn = (int)parLifetime.TotalSeconds;

                //The signed request's authorization_details and response_mode ride the same
                //carry as the bare PAR path — already shape-validated and servability-gated
                //by VerifyAndValidateAuthCodeJarAsync.
                return ((OAuthFlowInput?)new ServerParValidated(
                    FlowId: flowId,
                    RequestUri: requestUri,
                    CodeChallenge: ro.CodeChallenge,
                    RedirectUri: ro.RedirectUri,
                    Scope: ro.Scope,
                    ClientId: ro.ClientId,
                    Nonce: ro.Nonce,
                    ExpectedIssuer: ro.ClientId,
                    ReceivedAt: now,
                    ExpiresAt: expiresAt,
                    ExpiresIn: expiresIn,
                    AcrValues: ro.AcrValues,
                    MaxAge: ro.MaxAge,
                    State: ro.State,
                    AuthorizationDetails: ro.AuthorizationDetails,
                    ResponseMode: ro.ResponseMode,
                    IssuerState: ro.IssuerState,
                    Resource: ro.Resource), null);
            },

            BuildResponse = static (state, _, _) =>
            {
                if(state is not ParRequestReceivedState par)
                {
                    return ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, "Unexpected state after JAR-PAR.");
                }

                string body =
                    $"{{\"request_uri\":\"{par.RequestUri}\",\"expires_in\":{par.ExpiresIn}}}";
                //RFC 9126 §2.2: a successful PAR response MUST use HTTP 201 Created.
                return ServerHttpResponse
                    .Created(body, WellKnownMediaTypes.Application.Json)
                    .WithHeader(WellKnownHttpHeaderNames.CacheControl, WellKnownCacheControlValues.NoStore);
            }
        };


    /// <summary>
    /// Builds the JAR-by-value direct Authorize endpoint per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-6.1">RFC 9101 §6.1</see>:
    /// the authorize endpoint accepts a signed Request Object directly via the
    /// <c>request</c> query parameter without a prior PAR.
    /// </summary>
    /// <remarks>
    /// Disjoint from <see cref="BuildDirectAuthorize"/> and the PAR-completed
    /// <see cref="BuildAuthorize"/> on body/query signals — JAR-by-value matches
    /// when <c>request</c> is present and <c>request_uri</c> is absent; the
    /// PKCE direct matcher matches when neither <c>request</c> nor
    /// <c>request_uri</c> is present; the PAR-completed matcher matches when
    /// <c>request_uri</c> is present.
    /// </remarks>
    private static EndpointCandidate BuildAuthorizeJarByValue() =>
        new()
        {
            Name = WellKnownEndpointNames.AuthCodeAuthorizeJarByValue,
            HttpMethod = WellKnownHttpMethods.Get,
            Capability = WellKnownCapabilityIdentifiers.OAuthDirectAuthorization,
            StartsNewFlow = true,
            Kind = FlowKind.AuthCodeServer,
            //DiscoveryMetadataKey null — JAR-by-value shares the URL with the
            //non-JAR authorize endpoint which advertises.

            //Acceptance test: GET to /authorize with the JAR Request parameter
            //in the query and no request_uri (which would route to the
            //PAR-completed Authorize per RFC 9101 §6.1). Disjointness vs the
            //direct PKCE matcher is enforced by the Request presence
            //requirement here.
            MatchesRequest = static (fields, context, endpoint, ct) =>
            {
                IncomingRequest? req = context.IncomingRequest;
                if(req is null) { return ValueTask.FromResult<MatchPayload?>(null); }
                if(!WellKnownHttpMethods.IsGet(req.Method))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                if(!PathEquals.Equals(req.Path, endpoint.ResolvedUri.AbsolutePath))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                //RFC 9101 §5/§6.1 — request and request_uri MUST NOT both be present.
                //This JAR-by-value matcher declines when request_uri is also present; the
                //both-present case is matched by the PAR-completed BuildAuthorize, whose
                //BuildInputAsync rejects it with an explicit invalid_request.
                if(fields.ContainsKey(OAuthRequestParameterNames.RequestUri))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                if(!fields.ContainsKey(OAuthRequestParameterNames.Request))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
            },

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                AuthorizationServer server = context.Server!;

                (AuthCodeRequestObject? requestObject, ServerHttpResponse? earlyExit) =
                    await VerifyAndValidateAuthCodeJarAsync(fields, context, server, ct)
                        .ConfigureAwait(false);

                if(earlyExit is not null)
                {
                    return ((OAuthFlowInput?)null, earlyExit);
                }

                AuthCodeRequestObject ro = requestObject!;

                //FAPI 2.0 §5.2.2 — when the profile mandates PAR, the JAR-by-value path
                //is refused; the client must push the request first.
                if(context.RequirePushedAuthorizationRequests)
                {
                    return ((OAuthFlowInput?)null,
                        ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidRequest,
                            "This authorization server requires Pushed Authorization Requests; a JAR-by-value "
                            + "authorization request is not accepted (FAPI 2.0 §5.2.2)."));
                }

                string? subjectId = context.SubjectId;
                if(string.IsNullOrWhiteSpace(subjectId))
                {
                    return ((OAuthFlowInput?)null,
                        ServerHttpResponse.ServerError(
                            OAuthErrors.ServerError, "Subject not authenticated."));
                }

                DateTimeOffset now = server.TimeProvider.GetUtcNow();
                DateTimeOffset authTime = context.AuthTime ?? now;

                ServerHttpResponse? requirementFailure = await EvaluateAuthenticationRequirementsAsync(
                    server, context, ro.AcrValues, ro.MaxAge, ro.Scope, subjectId, now,
                    ro.RedirectUri, ro.State, ct,
                    requestedAuthorizationDetails: ro.AuthorizationDetails,
                    responseMode: ro.ResponseMode,
                    clientId: ro.ClientId,
                    requestedIssuerState: ro.IssuerState,
                    requestedResource: ro.Resource).ConfigureAwait(false);
                if(requirementFailure is not null)
                {
                    return ((OAuthFlowInput?)null, requirementFailure);
                }

                string flowId = context.FlowId!;

                //RFC 6749 §4.1.2 recommends a maximum of 10 minutes for
                //authorization codes. Library policy lives in
                //policy.AuthorizationCodeLifetime (default 600s).
                DateTimeOffset expiresAt = now + context.AuthorizationCodeLifetime;

                string rawCode = await server.Integration.GenerateIdentifierAsync!(
                    WellKnownIdentifierPurposes.OAuthAuthorizationCode, context, ct)
                    .ConfigureAwait(false);
                string codeHash = ComputeDigestBase64Url(
                    rawCode,
                    CryptoTags.Sha256Digest,
                    WellKnownHashAlgorithms.Sha256SizeBytes,
                    server.Codecs.ComputeDigest!,
                    server.Codecs.Encoder!,
                    SensitiveMemoryPool<byte>.Shared);

                //JARM: signed here, where the code exists; BuildResponse encodes per the
                //carried response_mode.
                (string? jarmResponseJwt, ServerHttpResponse? jarmFailure) =
                    await TryIssueJarmResponseJwtAsync(
                        server, context, ro.ResponseMode, ro.ClientId,
                        BuildAuthorizeSuccessParameters(codeHash, ro.State), ct)
                        .ConfigureAwait(false);
                if(jarmFailure is not null)
                {
                    return ((OAuthFlowInput?)null, jarmFailure);
                }

                if(jarmResponseJwt is not null)
                {
                    context.SetJarmResponseJwt(jarmResponseJwt);
                }

                return ((OAuthFlowInput?)new ServerDirectAuthorizeCompleted(
                    FlowId: flowId,
                    CodeHash: codeHash,
                    CodeChallenge: ro.CodeChallenge,
                    RedirectUri: ro.RedirectUri,
                    Scope: ro.Scope,
                    ClientId: ro.ClientId,
                    Nonce: ro.Nonce,
                    SubjectId: subjectId,
                    AuthTime: authTime,
                    ExpectedIssuer: ro.ClientId,
                    CompletedAt: now,
                    ExpiresAt: expiresAt,
                    SessionId: context.SessionId,
                    Acr: context.Acr,
                    State: ro.State,
                    AuthorizationDetails: ro.AuthorizationDetails,
                    ResponseMode: ro.ResponseMode,
                    IssuerState: ro.IssuerState,
                    Resource: ro.Resource), null);
            },

            BuildResponse = static (state, _, context) =>
            {
                if(state is not ServerCodeIssuedState code)
                {
                    return ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "Unexpected state after JAR-by-value direct authorize.");
                }

                return BuildAuthorizeCompletedResponse(code, context);
            }
        };


    /// <summary>
    /// Shared validation pipeline for JAR-bearing AuthCode matchers (JAR-PAR and
    /// JAR-by-value direct Authorize). Verifies the JAR's signature, JOSE header,
    /// and timing claims via <see cref="JarVerification.VerifyAsync"/>; projects
    /// onto a typed <see cref="AuthCodeRequestObject"/>; runs the protocol-shaped
    /// claim checks RFC 9101 §10.2 and RFC 9700 §4 mandate; and validates the
    /// outer <c>client_id</c> against the JAR's per RFC 9700 §4.6 substitution
    /// defense.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Returns <c>(requestObject, null)</c> on success and <c>(null, response)</c>
    /// when validation fails. The matchers project the returned
    /// <see cref="AuthCodeRequestObject"/> onto their endpoint-specific input
    /// records (<see cref="ServerParValidated"/> for JAR-PAR;
    /// <see cref="ServerDirectAuthorizeCompleted"/> for JAR-by-value).
    /// </para>
    /// <para>
    /// The <c>aud</c> check enforces the RFC 9101 §10.2 reading: <c>aud</c> must
    /// equal the AS issuer URL resolved through
    /// <see cref="AuthorizationServerIntegration.ResolveIssuerAsync"/>. The
    /// EUDI/Microsoft <c>aud == client_id</c> reading is rejected; tenant-divergent
    /// audience policy is a planned future extension point and is not in scope here.
    /// </para>
    /// </remarks>
    private static async ValueTask<(AuthCodeRequestObject? RequestObject, ServerHttpResponse? EarlyExit)>
        VerifyAndValidateAuthCodeJarAsync(
            RequestFields fields,
            ExchangeContext context,
            AuthorizationServer server,
            CancellationToken cancellationToken)
    {
        if(!fields.TryGetValue(OAuthRequestParameterNames.Request, out string? compactJar)
            || string.IsNullOrWhiteSpace(compactJar))
        {
            return (null, ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidRequest, "Missing request parameter."));
        }

        //RFC 9101 §5 explicitly permits the AS to require an outer client_id for
        //pre-verification client identification. Requiring it sidesteps the
        //"identify the registration before the JAR is verified" problem cleanly
        //and defends against substitution per RFC 9700 §4.6.
        if(!fields.TryGetValue(OAuthRequestParameterNames.ClientId, out string? outerClientId)
            || string.IsNullOrWhiteSpace(outerClientId))
        {
            return (null, ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidRequest,
                "Missing outer client_id. The library requires an outer client_id alongside a JAR per RFC 9101 §5."));
        }

        ClientRecord? registration = context.Registration;
        if(registration is null)
        {
            return (null, ServerHttpResponse.Unauthorized(
                OAuthErrors.InvalidClient, "Unknown client."));
        }

        if(!string.Equals(outerClientId, registration.ClientId, StringComparison.Ordinal))
        {
            return (null, ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidRequest, "Outer client_id does not match the registered client."));
        }

        //Resolve the JAR signing public key for this registration. The library
        //reads the JAR signing key id from the registration's JarSigning slot —
        //never from the JAR's own header. Doing the latter would defeat the
        //CVE-class header-key-injection defense.
        KeyId verificationKeyId;
        try
        {
            verificationKeyId = registration.GetDefaultSigningKeyId(KeyUsageContext.JarSigning);
        }
        catch(Exception ex) when(ex is KeyNotFoundException or InvalidOperationException)
        {
            return (null, ServerHttpResponse.ServerError(
                OAuthErrors.ServerError,
                $"Registration '{registration.ClientId}' has no JAR signing key configured: {ex.Message}"));
        }

        ServerVerificationKeyResolverDelegate? resolver = server.Cryptography.VerificationKeyResolver;
        if(resolver is null)
        {
            return (null, ServerHttpResponse.ServerError(
                OAuthErrors.ServerError, "VerificationKeyResolver is not configured."));
        }

        PublicKeyMemory? signingPublicKey = await resolver(
            verificationKeyId, registration.TenantId, context, cancellationToken).ConfigureAwait(false);

        if(signingPublicKey is null)
        {
            return (null, ServerHttpResponse.ServerError(
                OAuthErrors.ServerError,
                $"Verification key '{verificationKeyId.Value}' is unavailable."));
        }

        JwtHeaderDeserializer? headerDeserializer = server.Codecs.JwtHeaderDeserializer;
        JwtPayloadDeserializer? payloadDeserializer = server.Codecs.JwtPayloadDeserializer;
        DecodeDelegate? decoder = server.Codecs.Decoder;

        if(headerDeserializer is null || payloadDeserializer is null || decoder is null)
        {
            return (null, ServerHttpResponse.ServerError(
                OAuthErrors.ServerError, "Required JWT codecs are not configured."));
        }

        DateTimeOffset now = server.TimeProvider.GetUtcNow();

        //Clock skew and JAR lifetime ceiling come from per-request policy
        //(populated by ResolvePolicyAsync at dispatch entry). Defaults match
        //the historical TimingPolicy values for the strict reading.
        JarVerificationResult verification = await JarVerification.VerifyAsync(
            compactJar,
            signingPublicKey,
            now,
            context.ClockSkewTolerance,
            context.JarLifetimeCeiling,
            decoder,
            headerDeserializer,
            payloadDeserializer,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken).ConfigureAwait(false);

        if(verification is JarRejected rejected)
        {
            return (null, ServerHttpResponse.BadRequest(rejected.ErrorCode, rejected.Reason));
        }

        JarVerified verified = (JarVerified)verification;

        //RFC 9396 §3: inside a Request Object, authorization_details is a native JSON
        //array. The verbatim array text is re-sliced from the now-verified payload so the
        //carried value is exactly what the client signed — a reserialisation of the parsed
        //claims could diverge from the signed bytes.
        string? jarAuthorizationDetails;
        {
            string[] jarParts = compactJar.Split('.');
            using IMemoryOwner<byte> payloadBytes = decoder(jarParts[1], SensitiveMemoryPool<byte>.Shared);
            jarAuthorizationDetails = JwkJsonReader.ExtractArrayAsString(
                payloadBytes.Memory.Span, OAuthRequestParameterNames.AuthorizationDetailsUtf8);
        }

        AuthCodeRequestObject requestObject;
        try
        {
            requestObject = verified.ProjectAuthCode(jarAuthorizationDetails);
        }
        catch(FormatException ex)
        {
            return (null, ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidRequestObject, ex.Message));
        }

        //RFC 9101 §10.2 — iss MUST equal client_id when present in the JAR. The
        //library treats iss as required for JAR per the same section; absence
        //is rejected.
        if(string.IsNullOrEmpty(requestObject.Iss)
            || !string.Equals(requestObject.Iss, requestObject.ClientId, StringComparison.Ordinal))
        {
            return (null, ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidRequestObject,
                "JAR iss must be present and equal to client_id per RFC 9101 §10.2."));
        }

        //RFC 9700 §4.6 — the JAR's client_id MUST match the registered client.
        if(!string.Equals(requestObject.ClientId, registration.ClientId, StringComparison.Ordinal))
        {
            return (null, ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidRequestObject,
                "JAR client_id does not match the registered client."));
        }

        //RFC 9101 §10.2, RFC 9700 §4.2 — aud MUST equal the AS issuer URL
        //(the FAPI-conformant reading). Tenant-divergent aud policy is a
        //planned follow-up. One call site here so the future delegate
        //extension point replaces a single method call. The validation runs
        //against verified.Claims rather than the projected requestObject.Aud
        //so the array form per RFC 7519 §4.1.3 is honoured — the projection
        //is single-string only.
        ServerHttpResponse? audFailure = await ValidateJarAudienceAsync(
            verified.Claims, registration, context, server, cancellationToken).ConfigureAwait(false);
        if(audFailure is not null)
        {
            return (null, audFailure);
        }

        //RFC 9700 §4.1 — redirect_uri exact-match against the registered set.
        if(!registration.AllowedRedirectUris.Contains(requestObject.RedirectUri))
        {
            return (null, ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidRequestObject,
                $"redirect_uri '{requestObject.RedirectUri}' is not among the registered redirect URIs."));
        }

        //Scope-required-on-request is a policy axis (Finding 4). Aligns the
        //JAR-bearing matcher with the PKCE PAR matcher — either both require
        //scope (the strict default) or both treat it as optional.
        if(context.ScopeRequiredOnRequest && string.IsNullOrEmpty(requestObject.Scope))
        {
            return (null, ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidRequestObject,
                "scope is required under the active policy."));
        }

        //FAPI 2.0 §5.2.2, HAIP §3 — code_challenge_method MUST be S256 in the
        //strict default. Permissive deployments via policy.AllowedPkceMethods
        //may also accept "plain".
        if(!IsAcceptedPkceMethod(requestObject.CodeChallengeMethod, context))
        {
            return (null, ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidRequestObject,
                "code_challenge_method is not accepted under the active policy."));
        }

        //RFC 9396 / OID4VCI 1.0 §5.1.1 — the signed request's authorization_details is
        //shape-validated at receipt, the same fail-fast the bare PAR/authorize paths run.
        if(requestObject.AuthorizationDetails is not null)
        {
            ServerHttpResponse? detailsFailure = await ValidateAuthorizationDetailsShapeAsync(
                server, requestObject.AuthorizationDetails, registration, context, cancellationToken).ConfigureAwait(false);
            if(detailsFailure is not null)
            {
                return (null, detailsFailure);
            }
        }

        //JARM / FAPI 2.0 MS §5.4 — a response_mode inside the signed request asking for a
        //JWT-secured authorization response is gated for servability at receipt, the same
        //fail-fast the bare paths run via ReadResponseMode.
        if(requestObject.ResponseMode is string jarResponseMode)
        {
            ServerHttpResponse? jarmFailure = ValidateJarmResponseModeServability(
                jarResponseMode, server, context);
            if(jarmFailure is not null)
            {
                return (null, jarmFailure);
            }
        }

        //RFC 9101 §10.2 / RFC 9700 §4 — jti replay defense, running LAST so only a JAR that
        //passed every other check consumes its jti. Consultation goes through the one shared
        //(issuer, jti) correlation store via JtiReplayGuard, governed by JtiReplayPolicy: the
        //strict profile's Required value fails closed when no store is wired, the read and the
        //first-use record happen as one unit, and the entry is retained until exp plus skew —
        //exactly the window the temporal checks accept the JAR in.
        if(!string.IsNullOrEmpty(requestObject.Jti))
        {
            JtiReplayOutcome jtiOutcome = await JtiReplayGuard.ConsultAsync(
                server, context, registration.TenantId,
                requestObject.Iss!, requestObject.Jti!,
                requestObject.Exp + context.ClockSkewTolerance,
                cancellationToken).ConfigureAwait(false);

            if(jtiOutcome == JtiReplayOutcome.Replayed)
            {
                return (null, ServerHttpResponse.BadRequest(
                    OAuthErrors.InvalidRequestObject,
                    "The JAR jti has already been presented within its validity window."));
            }

            if(jtiOutcome == JtiReplayOutcome.StoreUnavailable)
            {
                return (null, ServerHttpResponse.ServerError(
                    OAuthErrors.ServerError,
                    "JAR jti replay defense is required by policy but no jti store is configured."));
            }
        }

        return (requestObject, null);
    }


    /// <summary>
    /// Validates the JAR <c>aud</c> claim against the AS issuer URL per RFC 9101
    /// §10.2 and RFC 9700 §4.2. Single call site so the future
    /// <c>ValidateJarAudienceDelegate</c> extension point — see the planned-
    /// follow-up note in the JAR brief — can replace one method call rather
    /// than tracking sprinkled checks. Delegates the string-or-array shape
    /// handling to <see cref="ValidationChecks.CheckTokenAudContainsExpectedIssuer"/>
    /// so both single-string and array-form <c>aud</c> per RFC 7519 §4.1.3 work.
    /// </summary>
    private static async ValueTask<ServerHttpResponse?> ValidateJarAudienceAsync(
        IReadOnlyDictionary<string, object> claims,
        ClientRecord registration,
        ExchangeContext context,
        AuthorizationServer server,
        CancellationToken cancellationToken)
    {
        if(!claims.ContainsKey(WellKnownJwtClaimNames.Aud))
        {
            return ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidRequestObject,
                "JAR aud claim is required per RFC 9101 §10.2.");
        }

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
            return ServerHttpResponse.ServerError(OAuthErrors.ServerError, ex.Message);
        }

        ValidationContext validationContext = new()
        {
            Context = context,
            TokenClaims = claims,
            ExpectedIssuer = issuerUri.ToString(),
            Now = server.TimeProvider.GetUtcNow()
        };

        List<Claim> result = await ValidationChecks.CheckTokenAudContainsExpectedIssuer(
            validationContext, cancellationToken).ConfigureAwait(false);

        if(result[0].Outcome == ClaimOutcome.Success)
        {
            return null;
        }

        return ServerHttpResponse.BadRequest(
            OAuthErrors.InvalidRequestObject,
            $"JAR aud does not match the AS issuer '{issuerUri}' per RFC 9101 §10.2.");
    }


    /// <summary>
    /// Default producer list when
    /// <see cref="ServerConfiguration.TokenProducers"/> is empty. Single producer
    /// matches the library's historical access-token-only response shape.
    /// </summary>
    private static readonly IReadOnlyList<TokenProducer> DefaultTokenProducers =
        [TokenProducer.Rfc9068AccessToken];


    /// <summary>
    /// Pre-resolves the OIDC claim set for the current issuance once per token
    /// request, before the producer loop. The resolved value flows through every
    /// <see cref="IdTokenTarget"/> and <see cref="UserInfoTarget"/> the
    /// contributor walk constructs in this request, so per-rule contributors
    /// don't each re-issue the resolver call.
    /// </summary>
    private static async ValueTask<OidcClaims?> PreResolveOidcClaimsAsync(
        AuthorizationServer server,
        IssuanceContext issuance,
        CancellationToken cancellationToken)
    {
        ResolveOidcClaimsDelegate? resolve = server.Integration.ResolveOidcClaimsAsync;
        if(resolve is null)
        {
            return null;
        }

        return await resolve(
            issuance.Subject,
            issuance.Scope,
            issuance.Registration.TenantId,
            issuance.Context,
            cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Builds the <see cref="ClaimContributionTarget"/> appropriate to a
    /// <paramref name="producer"/>'s response field, or <see langword="null"/>
    /// when the producer's token type has no contributor walk wired in this
    /// phase (refresh tokens, custom producers).
    /// </summary>
    private static ClaimContributionTarget? BuildTargetForProducer(
        TokenProducer producer,
        IssuanceContext issuance,
        OidcClaims? preResolvedClaims)
    {
        if(string.Equals(producer.ResponseField, WellKnownTokenTypes.IdToken, StringComparison.Ordinal))
        {
            return new IdTokenTarget(issuance) { ResolvedOidcClaims = preResolvedClaims };
        }

        if(string.Equals(producer.ResponseField, WellKnownTokenTypes.AccessToken, StringComparison.Ordinal))
        {
            return new AccessTokenTarget(issuance);
        }

        return null;
    }


    /// <summary>
    /// Runs the configured <see cref="ServerConfiguration.ClaimIssuer"/>
    /// against <paramref name="target"/> and merges every
    /// <see cref="ClaimOutcome.Success"/> contribution into
    /// <paramref name="payload"/> via the indexer. No-op when the
    /// configuration has no issuer wired.
    /// </summary>
    private static async ValueTask MergeContributedClaimsAsync(
        AuthorizationServer server,
        ClaimContributionTarget? target,
        JwtPayload payload,
        CancellationToken cancellationToken)
    {
        if(target is null || server.Configuration.ClaimIssuer is not { } issuer)
        {
            return;
        }

        string correlationId = await server.Integration.GenerateIdentifierAsync!(
            WellKnownIdentifierPurposes.OAuthCorrelationId, null, cancellationToken)
            .ConfigureAwait(false);
        ClaimIssueResult result = await issuer.GenerateClaimsAsync(
            target,
            correlationId,
            cancellationToken).ConfigureAwait(false);

        foreach(Claim claim in result.Claims)
        {
            if(claim.Outcome == ClaimOutcome.Success
                && claim.Context is ClaimContributionContext ctx)
            {
                payload[ctx.ClaimName] = ctx.ClaimValue;
            }
        }
    }


    /// <summary>
    /// Builds the Token endpoint per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 §5.1</see>.
    /// </summary>
    /// <remarks>
    /// <see cref="ServerEndpoint.BuildResponse"/> writes the response body —
    /// <c>access_token</c>, <c>token_type</c>, <c>expires_in</c>, and the
    /// optional <c>id_token</c>, <c>refresh_token</c>, and <c>scope</c>
    /// fields — directly with <see cref="System.Text.StringBuilder"/>. See
    /// the serialization-firewall paragraph in the remarks on
    /// <see cref="AuthCodeEndpoints"/> for the rationale.
    /// </remarks>
    private static EndpointCandidate BuildToken() =>
        new()
        {
            Name = WellKnownEndpointNames.AuthCodeToken,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            StartsNewFlow = false,
            Kind = FlowKind.AuthCodeServer,
            DiscoveryMetadataKey = AuthorizationServerMetadataParameterNames.TokenEndpoint,

            //Acceptance test: POST to /token with grant_type=authorization_code
            //and a code parameter. Disjointness vs the refresh-token matcher
            //(different grant_type) and the OID4VP token matcher (different
            //path) is enforced by the grant_type filter here.
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
                if(!fields.TryGetValue(OAuthRequestParameterNames.GrantType, out string? grantType)
                    || !string.Equals(grantType, OAuthRequestParameterValues.GrantTypeAuthorizationCode, StringComparison.Ordinal))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                if(!fields.ContainsKey(OAuthRequestParameterNames.Code))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
            },

            ExtractCorrelationKey = static (path, fields, context) =>
                fields.TryGetValue(OAuthRequestParameterNames.Code, out string? code)
                    && !string.IsNullOrWhiteSpace(code) ? code : null,
            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                AuthorizationServer server = context.Server!;

                if(currentState is not ServerCodeIssuedState codeState)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidGrant, "Flow not in expected state."));
                }

                if(!fields.TryGetValue(OAuthRequestParameterNames.CodeVerifier, out string? verifier)
                    || string.IsNullOrWhiteSpace(verifier))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "Missing code_verifier."));
                }

                string computedChallenge = ComputeDigestBase64Url(
                    verifier,
                    CryptoTags.Sha256Digest,
                    WellKnownHashAlgorithms.Sha256SizeBytes,
                    server.Codecs.ComputeDigest!,
                    server.Codecs.Encoder!,
                    SensitiveMemoryPool<byte>.Shared);
                //Fixed-time: this comparison decides the grant, so a match-length
                //timing oracle on it must not exist even though the challenge
                //itself transited the front channel.
                if(!FixedTimeComparison.AreEqual(computedChallenge, codeState.CodeChallenge))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidGrant, "PKCE verification failed."));
                }

                if(!fields.TryGetValue(OAuthRequestParameterNames.ClientId, out string? clientId)
                    || !string.Equals(clientId, codeState.ClientId, StringComparison.Ordinal))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidGrant, "client_id mismatch."));
                }

                //The dispatcher already loaded the registration for this tenant onto
                //the context. Use that rather than re-loading by client_id; doing the
                //lookup again under a different identifier would conflate clientId
                //and tenantId, which the protocol layer keeps distinct.
                ClientRecord? registration = context.Registration;
                if(registration is null)
                {
                    return (null, ServerHttpResponse.Unauthorized(
                        OAuthErrors.InvalidClient, "Unknown client."));
                }

                Uri issuerUri;
                try
                {
                    issuerUri = server.Integration.ResolveIssuerAsync is not null
                        ? await server.Integration.ResolveIssuerAsync(registration, context, ct)
                            .ConfigureAwait(false)
                        : await DefaultIssuerResolver.ResolveAsync(registration, context, ct)
                            .ConfigureAwait(false);
                }
                catch(InvalidOperationException ex)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, ex.Message));
                }

                DateTimeOffset now = server.TimeProvider.GetUtcNow();

                //RFC 9449 DPoP enforcement at the token endpoint. The helper
                //returns a shaped failure response on any rejection path
                //(missing proof, nonce challenge, invalid proof, jti replay)
                //and the established Confirmation on success. Code-grant
                //passes expectedThumbprint=null because the binding is being
                //established here; refresh-grant verifies against the stored
                //thumbprint in BuildRefreshToken.
                bool dpopRequired = ClientPolicyProfiles.RequiresDpop(registration.Profile);
                DpopValidationOutcome dpopOutcome = await DpopTokenEndpointValidation.ValidateAsync(
                    server, context, registration, issuerUri, now,
                    expectedThumbprint: null, dpopRequired, ct).ConfigureAwait(false);

                if(!dpopOutcome.IsSuccess)
                {
                    return (null, dpopOutcome.FailureResponse!);
                }

                ConfirmationMethod? confirmation = dpopOutcome.Confirmation;

                //RFC 9396 / OID4VCI 1.0 §6.1.1–§6.2: resolve the granted authorization_details
                //BEFORE any token is minted — the authorized details ride the code state (the
                //pushed value), a token-request value may narrow them to a subset, and the
                //application's seam mints the credential_identifiers the response advertises.
                fields.TryGetValue(OAuthRequestParameterNames.AuthorizationDetails, out string? tokenRequestDetails);
                (string? grantedDetailsJson, IReadOnlyList<object>? grantedDetailsClaim, ServerHttpResponse? detailsFailure) =
                    await ResolveGrantedAuthorizationDetailsAsync(
                        server,
                        string.IsNullOrWhiteSpace(tokenRequestDetails) ? null : tokenRequestDetails,
                        codeState.AuthorizationDetails,
                        codeState.SubjectId,
                        registration,
                        context,
                        ct).ConfigureAwait(false);
                if(detailsFailure is not null)
                {
                    return (null, detailsFailure);
                }

                if(grantedDetailsJson is not null)
                {
                    context.SetGrantedAuthorizationDetails(grantedDetailsJson);

                    //RFC 9396 §9.1: the granted authorization_details ride the context into the
                    //producer walk so the RFC 9068 JWT access token carries them as a top-level claim.
                    if(grantedDetailsClaim is not null)
                    {
                        context.SetGrantedAuthorizationDetailsClaim(grantedDetailsClaim);
                    }

                    //OID4VCI 1.0 §13.10 — this access token gives access to Credentials (the request
                    //produced an openid_credential grant). A long-lived bearer Credential token MUST
                    //NOT be issued unless sender-constrained; the DPoP enforcement above set the
                    //confirmation when it bound the token.
                    ServerHttpResponse? protectionFailure = GuardCredentialAccessTokenProtection(
                        server, registration, isSenderConstrained: confirmation is { IsEmpty: false });
                    if(protectionFailure is not null)
                    {
                        return (null, protectionFailure);
                    }
                }

                IssuanceContext issuance = new()
                {
                    Registration = registration,
                    Context = context,
                    IssuerUri = issuerUri,
                    Subject = codeState.SubjectId,
                    Scope = codeState.Scope,
                    ClientId = codeState.ClientId,
                    IssuedAt = now,
                    Nonce = string.IsNullOrEmpty(codeState.Nonce) ? null : codeState.Nonce,
                    AuthTime = codeState.AuthTime,
                    SessionId = codeState.SessionId,
                    Acr = codeState.Acr,
                    Confirmation = confirmation
                };

                IReadOnlyList<TokenProducer> producers =
                    server.Configuration.TokenProducers.Count > 0 ? server.Configuration.TokenProducers : DefaultTokenProducers;

                //One-time OidcClaims resolution per request — every
                //IdTokenTarget / UserInfoTarget built below in the producer
                //loop reads from the same resolved instance so per-rule
                //contributors don't each re-issue the resolver call.
                OidcClaims? preResolvedOidcClaims = await PreResolveOidcClaimsAsync(
                    server, issuance, ct).ConfigureAwait(false);

                Dictionary<string, string> issuedTokens = new(producers.Count);
                Dictionary<string, IssuedTokenAudit> issuedAudits = new(producers.Count);
                DateTimeOffset latestExpiry = now;

                foreach(TokenProducer producer in producers)
                {
                    //Per-producer capability filter. The chain-level filter via
                    //ResolveCapabilitiesAsync gated the token *endpoint* itself
                    //on the AuthorizationCode capability; the producer loop here
                    //gates each individual token producer (access token, ID
                    //token, refresh token) on its own RequiredCapability so the
                    //response contains only the token shapes this request is
                    //allowed to issue. Reads the resolver's per-request output
                    //(stashed by EndpointChain.BuildForRequestAsync) rather
                    //than the registration's static AllowedCapabilities — CAEP/
                    //RISC attenuation between issuance steps applies here.
                    IReadOnlySet<CapabilityIdentifier>? resolved =
                        context.ResolvedCapabilities;
                    if(resolved is null || !resolved.Contains(producer.RequiredCapability))
                    {
                        continue;
                    }

                    if(!await producer.IsApplicable(issuance, ct).ConfigureAwait(false))
                    {
                        continue;
                    }

                    KeyId signingKeyId = await SigningKeySelection.ResolveSigningKeyIdAsync(
                        server, registration, producer.KeyUsage, context, ct)
                        .ConfigureAwait(false);

                    PrivateKeyMemory? signingKey = await server.Cryptography.SigningKeyResolver!(
                        signingKeyId, registration.TenantId, context, ct).ConfigureAwait(false);

                    if(signingKey is null)
                    {
                        return (null, ServerHttpResponse.ServerError(
                            OAuthErrors.ServerError,
                            $"Signing key unavailable for producer '{producer.Name}'."));
                    }

                    string algorithm =
                        CryptoFormatConversions.DefaultTagToJwaConverter(signingKey.Tag);

                    TokenProducerOutput output = await producer.BuildAsync(
                        issuance, signingKeyId, algorithm, ct).ConfigureAwait(false);

                    JwtPayload payload = output.Payload;

                    //Composed contributor walk via ServerConfiguration.ClaimIssuer.
                    //Emits scope-driven extension claims (profile / email /
                    //address / phone / cnf / acr / amr) after the producer
                    //returned its spec-mandated baseline.
                    ClaimContributionTarget? contributionTarget =
                        BuildTargetForProducer(producer, issuance, preResolvedOidcClaims);
                    await MergeContributedClaimsAsync(
                        server, contributionTarget, payload, ct).ConfigureAwait(false);

                    UnsignedJwt unsigned = new(output.Header, payload);

                    using JwsMessage jws = await unsigned.SignAsync(
                        signingKey,
                        server.Codecs.JwtHeaderSerializer!,
                        server.Codecs.JwtPayloadSerializer!,
                        server.Codecs.Encoder!,
                        SensitiveMemoryPool<byte>.Shared,
                        ct).ConfigureAwait(false);

                    string compactJws = JwsSerialization.SerializeCompact(jws, server.Codecs.Encoder!);

                    issuedTokens[producer.ResponseField] = compactJws;

                    string jti = ExtractJti(payload);
                    DateTimeOffset issuedAt = ExtractInstant(payload, WellKnownJwtClaimNames.Iat, now);
                    DateTimeOffset expiresAt = ExtractInstant(payload, WellKnownJwtClaimNames.Exp, now);

                    issuedAudits[producer.ResponseField] = new IssuedTokenAudit
                    {
                        Jti = jti,
                        SigningKeyId = signingKeyId.Value,
                        IssuedAt = issuedAt,
                        ExpiresAt = expiresAt
                    };

                    if(expiresAt > latestExpiry)
                    {
                        latestExpiry = expiresAt;
                    }
                }

                if(issuedTokens.Count == 0)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, "No applicable token producers."));
                }

                //RFC 6749 §6 — issue a refresh token alongside the access
                //token. Refresh tokens are opaque random strings (not JWTs),
                //stored as ServerRefreshTokenIssuedState in flow storage.
                //RFC 9700 §2.2.2 requires rotation on every use; the
                //BuildRefreshToken endpoint handles the rotation when the
                //refresh is presented. The value is a bearer secret, so it
                //goes through the identifier seam like the authorization-code
                //value — the application owns the entropy source and its
                //provenance tracking; the library never fills from the OS
                //CSPRNG directly.
                string refreshToken = await server.Integration.GenerateIdentifierAsync!(
                    WellKnownIdentifierPurposes.OAuthRefreshToken, context, ct)
                    .ConfigureAwait(false);
                DateTimeOffset refreshExpiresAt = now + context.RefreshTokenLifetime;

                if(server.Integration.SaveFlowStateAsync is not null)
                {
                    string refreshFlowId = await server.Integration.GenerateIdentifierAsync!(
                        WellKnownIdentifierPurposes.OAuthRefreshFlowId, context, ct)
                        .ConfigureAwait(false);
                    ServerRefreshTokenIssuedState refreshState = new()
                    {
                        FlowId = refreshFlowId,
                        ExpectedIssuer = issuerUri.OriginalString,
                        EnteredAt = now,
                        ExpiresAt = refreshExpiresAt,
                        Kind = FlowKind.AuthCodeServer,
                        ClientId = codeState.ClientId,
                        RefreshToken = refreshToken,
                        IssuedAt = now,
                        SubjectId = codeState.SubjectId,
                        Scope = codeState.Scope,
                        Confirmation = confirmation,
                        AuthTime = codeState.AuthTime,
                        Acr = codeState.Acr,
                        //RFC 9396 §11.2: granted authorization_details are stored as part of the
                        //grant so the refresh exchange can re-emit the §7 echo and §9.1 claim. The
                        //baseline a later refresh narrows against is the resource owner's
                        //authorization (§6.1: "the resource owner's previous authorization is
                        //unchanged by such requests"), not a token-request-narrowed grant; when the
                        //details entered at the token request alone (the §6.1.1 scope-authorized
                        //selection), the granted result is that authorization.
                        AuthorizationDetails = codeState.AuthorizationDetails ?? grantedDetailsJson
                    };
                    await server.Integration.SaveFlowStateAsync(
                        registration.TenantId, refreshFlowId, refreshState, stepCount: 0, context, ct)
                        .ConfigureAwait(false);
                }

                issuedTokens[WellKnownTokenTypes.RefreshToken] = refreshToken;

                IssuedTokenSet tokenSet = new() { Tokens = issuedTokens };
                context.SetIssuedTokens(tokenSet);

                IssuedTokenAuditSet auditSet = new() { Audits = issuedAudits };

                return (new ServerTokenExchangeSucceeded(
                    IssuedTokens: auditSet,
                    IssuedAt: now,
                    ExpiresAt: latestExpiry)
                {
                    Confirmation = confirmation
                }, null);
            },
            BuildResponse = static (state, _, context) =>
            {
                if(state is not ServerTokenIssuedState issued)
                {
                    return ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, "Unexpected state after token exchange.");
                }

                IssuedTokenSet? tokenSet = context.IssuedTokens;
                if(tokenSet is null || tokenSet.AccessToken is null)
                {
                    return ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, "Issued tokens not found in context.");
                }

                IssuedTokenAudit? accessAudit = issued.IssuedTokens.AccessTokenAudit;
                if(accessAudit is null)
                {
                    //Structural invariant: the upstream check above already
                    //returned ServerError when tokenSet.AccessToken was null.
                    //Reaching here without an audit means the audit set was
                    //assembled out of sync with the tokens dictionary —
                    //library bug, not a runtime condition.
                    return ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "Access token audit missing alongside an issued access token — library invariant violation.");
                }

                int expiresIn = (int)(accessAudit.ExpiresAt - accessAudit.IssuedAt).TotalSeconds;

                //RFC 9449 §5: when DPoP enforcement bound the access token,
                //token_type is "DPoP"; otherwise the RFC 6750 "Bearer" default.
                //The Confirmation slot on the terminal state carries the binding
                //the producer embedded as cnf in the JWT payload; the wire-level
                //token_type mirrors that decision so RS code can dispatch the
                //right scheme without parsing the JWT.
                string tokenTypeWireName = issued.Confirmation is { IsEmpty: false }
                    ? WellKnownAuthenticationSchemes.DPoP
                    : WellKnownAuthenticationSchemes.Bearer;

                StringBuilder sb = JsonAppender.Rent();
                string responseJson;
                try
                {
                    sb.Append('{');
                    bool first = true;
                    JsonAppender.AppendStringField(sb, "access_token",
                        tokenSet.AccessToken ?? string.Empty, ref first);
                    JsonAppender.AppendStringField(sb, "token_type",
                        tokenTypeWireName, ref first);
                    JsonAppender.AppendInt64Field(sb, "expires_in",
                        expiresIn, ref first);

                    string? idToken = tokenSet.IdToken;
                    if(idToken is not null)
                    {
                        JsonAppender.AppendStringField(sb, "id_token",
                            idToken, ref first);
                    }

                    string? refreshToken = tokenSet.RefreshToken;
                    if(refreshToken is not null)
                    {
                        JsonAppender.AppendStringField(sb, "refresh_token",
                            refreshToken, ref first);
                    }

                    string? scope = issued.Scope;
                    if(!string.IsNullOrEmpty(scope))
                    {
                        JsonAppender.AppendStringField(sb, "scope", scope, ref first);
                    }

                    //OID4VCI 1.0 §6.2 / RFC 9396 §7: when the grant carried
                    //authorization_details, the response echoes the granted details
                    //enriched with credential_identifiers.
                    string? grantedDetails = context.GrantedAuthorizationDetails;
                    if(grantedDetails is not null)
                    {
                        JsonAppender.AppendRawField(
                            sb, OAuthRequestParameterNames.AuthorizationDetails, grantedDetails, ref first);
                    }

                    sb.Append('}');
                    responseJson = sb.ToString();
                }
                finally
                {
                    JsonAppender.Return(sb);
                }

                //OAuth 2.1 §3.2.3 — token-bearing response MUST set
                //Cache-Control: no-store. RFC 7234 §5.2.2.3.
                return ServerHttpResponse
                    .Ok(responseJson, WellKnownMediaTypes.Application.Json)
                    .WithHeader(WellKnownHttpHeaderNames.CacheControl, WellKnownCacheControlValues.NoStore);
            }
        };


    /// <summary>
    /// Refresh-token grant per RFC 6749 §6 + RFC 9700 §2.2.2 rotation.
    /// Endpoint Kind is <see cref="FlowKind.RefreshToken"/> so the AS's
    /// correlation-key resolver looks up the refresh-token string in the
    /// refresh-token secondary index. The matcher is path+method+grant_type-
    /// disjoint from BuildToken (which handles authorization_code grant).
    /// </summary>
    /// <summary>
    /// Builds the <c>client_credentials</c> grant candidate (RFC 6749 §4.4) on
    /// the shared token endpoint URL. Stateless: the client authenticates
    /// through the application's
    /// <see cref="AuthorizationServerIntegration.ValidateClientCredentialsAsync"/>
    /// seam, the requested scope is validated against the registration's
    /// allowed scopes, and the configured token producers mint the access token
    /// directly into the response — no flow state, no refresh token, no
    /// end-user subject (the <c>sub</c> is the client itself per RFC 9068 §3).
    /// </summary>
    private static EndpointCandidate BuildClientCredentials() =>
        new()
        {
            Name = WellKnownEndpointNames.ClientCredentialsToken,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownCapabilityIdentifiers.OAuthClientCredentials,
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,
            //DiscoveryMetadataKey null — the grant shares the token endpoint URL.

            //Disjointness vs the code and refresh grant matchers is enforced by
            //the grant_type filter, exactly as the refresh matcher does.
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

                if(!fields.TryGetValue(OAuthRequestParameterNames.GrantType, out string? grantType)
                    || !string.Equals(grantType, OAuthRequestParameterValues.GrantTypeClientCredentials, StringComparison.Ordinal))
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

                //RFC 6749 §4.4.2: the client MUST authenticate. The seam owns the
                //method (client_secret_basic/post, private_key_jwt, mTLS) and the
                //credential comparison; the builder guarantees it is wired.
                bool clientAuthenticated = await server.Integration.ValidateClientCredentialsAsync!(
                    context.IncomingRequest, fields, registration, context, ct).ConfigureAwait(false);
                if(!clientAuthenticated)
                {
                    return (null, ServerHttpResponse.Unauthorized(
                        OAuthErrors.InvalidClient, "Client authentication failed."));
                }

                //RFC 6749 §3.3: requested scope tokens must each be allowed for
                //this client; an omitted scope grants the registration's full set.
                string grantedScope;
                if(fields.TryGetValue(OAuthRequestParameterNames.Scope, out string? requestedScope)
                    && !string.IsNullOrWhiteSpace(requestedScope))
                {
                    string[] requested = requestedScope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    foreach(string scopeToken in requested)
                    {
                        if(!registration.AllowedScopes.Contains(scopeToken))
                        {
                            return (null, ServerHttpResponse.BadRequest(
                                OAuthErrors.InvalidScope,
                                $"Scope '{scopeToken}' is not allowed for this client."));
                        }
                    }

                    grantedScope = string.Join(' ', requested);
                }
                else
                {
                    grantedScope = string.Join(' ', registration.AllowedScopes);
                }

                //RFC 9396 §6: "The AS checks whether ... the client's policy (in case of grant
                //type client_credentials) allows the issuance of an access token with the
                //requested authorization details. Otherwise, the AS refuses the request with the
                //error code invalid_authorization_details." A client_credentials request that
                //carries authorization_details MUST NOT have the parameter silently dropped: it is
                //first run through the same §5 shape validation as every other grant — the wired-
                //parser check, the registry dispatch, and the client's
                //authorization_details_types allowlist (§10) — so a malformed, unknown, or
                //unentitled type yields the precise §5 error. A shape-valid request is then refused:
                //the credential decision seam is subject-bound (the OID4VCI End-User authorization),
                //which has no meaning for this machine-to-machine grant, so this AS has no policy
                //through which the issuance of an authorization-details-bound token can be allowed.
                //§6 makes refusal the conformant outcome whenever policy cannot allow the issuance.
                string? clientCredentialsDetails = ReadAuthorizationDetails(fields);
                if(clientCredentialsDetails is not null)
                {
                    ServerHttpResponse? shapeFailure = await ValidateAuthorizationDetailsShapeAsync(
                        server, clientCredentialsDetails, registration, context, ct).ConfigureAwait(false);
                    if(shapeFailure is not null)
                    {
                        return (null, shapeFailure);
                    }

                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidAuthorizationDetails,
                        "The client_credentials grant of this authorization server does not issue "
                        + "authorization-details-bound access tokens."));
                }

                Uri issuerUri;
                try
                {
                    issuerUri = server.Integration.ResolveIssuerAsync is not null
                        ? await server.Integration.ResolveIssuerAsync(registration, context, ct)
                            .ConfigureAwait(false)
                        : await DefaultIssuerResolver.ResolveAsync(registration, context, ct)
                            .ConfigureAwait(false);
                }
                catch(InvalidOperationException ex)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, ex.Message));
                }

                DateTimeOffset now = server.TimeProvider.GetUtcNow();

                //No end-user is involved: the token's subject is the client
                //itself (RFC 9068 §3 for client_credentials), with no nonce,
                //auth_time, or proof-of-possession binding in this grant shape.
                IssuanceContext issuance = new()
                {
                    Registration = registration,
                    Context = context,
                    IssuerUri = issuerUri,
                    Subject = registration.ClientId,
                    Scope = grantedScope,
                    ClientId = registration.ClientId,
                    IssuedAt = now
                };

                IReadOnlyList<TokenProducer> producers =
                    server.Configuration.TokenProducers.Count > 0
                        ? server.Configuration.TokenProducers
                        : DefaultTokenProducers;

                OidcClaims? preResolvedOidcClaims = await PreResolveOidcClaimsAsync(
                    server, issuance, ct).ConfigureAwait(false);

                Dictionary<string, string> issuedTokens = new(producers.Count);
                int expiresIn = 0;

                foreach(TokenProducer producer in producers)
                {
                    //Per-producer capability filter — see BuildToken for the
                    //rationale; reads the resolver's per-request output so
                    //capability attenuation applies to this grant too.
                    IReadOnlySet<CapabilityIdentifier>? resolved =
                        context.ResolvedCapabilities;
                    if(resolved is null || !resolved.Contains(producer.RequiredCapability))
                    {
                        continue;
                    }

                    if(!await producer.IsApplicable(issuance, ct).ConfigureAwait(false))
                    {
                        continue;
                    }

                    KeyId signingKeyId = await SigningKeySelection.ResolveSigningKeyIdAsync(
                        server, registration, producer.KeyUsage, context, ct).ConfigureAwait(false);
                    PrivateKeyMemory? signingKey = await server.Cryptography.SigningKeyResolver!(
                        signingKeyId, registration.TenantId, context, ct).ConfigureAwait(false);
                    if(signingKey is null)
                    {
                        return (null, ServerHttpResponse.ServerError(
                            OAuthErrors.ServerError,
                            $"Signing key unavailable for producer '{producer.Name}'."));
                    }

                    string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(signingKey.Tag);
                    TokenProducerOutput output = await producer.BuildAsync(
                        issuance, signingKeyId, algorithm, ct).ConfigureAwait(false);
                    JwtPayload payload = output.Payload;

                    ClaimContributionTarget? contributionTarget =
                        BuildTargetForProducer(producer, issuance, preResolvedOidcClaims);
                    await MergeContributedClaimsAsync(
                        server, contributionTarget, payload, ct).ConfigureAwait(false);

                    UnsignedJwt unsigned = new(output.Header, payload);
                    using JwsMessage jws = await unsigned.SignAsync(
                        signingKey,
                        server.Codecs.JwtHeaderSerializer!,
                        server.Codecs.JwtPayloadSerializer!,
                        server.Codecs.Encoder!,
                        SensitiveMemoryPool<byte>.Shared,
                        ct).ConfigureAwait(false);

                    string compactJws = JwsSerialization.SerializeCompact(jws, server.Codecs.Encoder!);
                    issuedTokens[producer.ResponseField] = compactJws;

                    if(WellKnownTokenTypes.IsAccessToken(producer.ResponseField))
                    {
                        DateTimeOffset issuedAtClaim = ExtractInstant(payload, WellKnownJwtClaimNames.Iat, now);
                        DateTimeOffset expiresAtClaim = ExtractInstant(payload, WellKnownJwtClaimNames.Exp, now);
                        expiresIn = (int)(expiresAtClaim - issuedAtClaim).TotalSeconds;
                    }
                }

                if(!issuedTokens.TryGetValue(WellKnownTokenTypes.AccessToken, out string? accessToken))
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "No access token was produced for the client_credentials grant."));
                }

                //RFC 6749 §4.4.3/§5.1: access_token, token_type, expires_in, and
                //the granted scope; the response is stateless and uncacheable.
                StringBuilder sb = JsonAppender.Rent();
                string responseJson;
                try
                {
                    sb.Append('{');
                    bool first = true;
                    JsonAppender.AppendStringField(sb, WellKnownTokenTypes.AccessToken, accessToken, ref first);
                    JsonAppender.AppendStringField(sb, "token_type",
                        WellKnownAuthenticationSchemes.Bearer, ref first);
                    JsonAppender.AppendInt64Field(sb, "expires_in", expiresIn, ref first);
                    JsonAppender.AppendStringField(sb, OAuthRequestParameterNames.Scope, grantedScope, ref first);
                    sb.Append('}');
                    responseJson = sb.ToString();
                }
                finally
                {
                    JsonAppender.Return(sb);
                }

                return (null, ServerHttpResponse.Ok(responseJson, WellKnownMediaTypes.Application.Json)
                    .WithHeader(WellKnownHttpHeaderNames.CacheControl, WellKnownCacheControlValues.NoStore));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    /// <summary>
    /// Builds the OID4VCI 1.0 §6 Pre-Authorized Code grant candidate on the shared token
    /// endpoint URL. Stateless: the Wallet presents a <c>pre-authorized_code</c> (and
    /// optional <c>tx_code</c>) the Credential Issuer minted in a Credential Offer, the
    /// application's
    /// <see cref="AuthorizationServerIntegration.ValidatePreAuthorizedCodeAsync"/> seam
    /// validates it and resolves the subject, and the configured token producers mint the
    /// access token directly into the response — no flow state, no prior Authorization
    /// Request, and no <c>c_nonce</c> in the token response (§6.2; the Wallet obtains a
    /// <c>c_nonce</c> from the Nonce Endpoint).
    /// </summary>
    /// <remarks>
    /// Client authentication is OPTIONAL for this grant (§6.1), so — unlike
    /// <see cref="BuildClientCredentials"/> — the candidate does not run the
    /// client-authentication seam; the code itself is the authorization grant, and the
    /// validation seam decides whether an anonymous request is acceptable. The §6.3 error
    /// distinctions (wrong code vs. wrong / missing / unexpected Transaction Code vs.
    /// anonymous-access-not-supported) come from the seam, since only the application's
    /// code store knows them.
    /// </remarks>
    private static EndpointCandidate BuildPreAuthorizedCodeToken() =>
        new()
        {
            Name = WellKnownEndpointNames.Oid4VciPreAuthorizedToken,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownCapabilityIdentifiers.Oid4VciPreAuthorizedCodeGrant,
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,
            //DiscoveryMetadataKey null — the grant shares the token endpoint URL.

            //Disjointness vs the code, refresh, and client_credentials grant matchers is
            //enforced by the grant_type filter; no other grant uses this grant_type.
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

                if(!fields.TryGetValue(OAuthRequestParameterNames.GrantType, out string? grantType)
                    || !string.Equals(grantType, OAuthRequestParameterValues.GrantTypePreAuthorizedCode, StringComparison.Ordinal))
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

                //§6.1: pre-authorized_code MUST be present when this grant type is used.
                if(!fields.TryGetValue(OAuthRequestParameterNames.PreAuthorizedCode, out string? preAuthorizedCode)
                    || string.IsNullOrWhiteSpace(preAuthorizedCode))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "Missing pre-authorized_code."));
                }

                //§6.1: tx_code and client_id are OPTIONAL. The seam owns whether an absent
                //tx_code or an anonymous (no client_id) request is acceptable.
                string? transactionCode = fields.TryGetValue(OAuthRequestParameterNames.TxCode, out string? tx)
                    && !string.IsNullOrWhiteSpace(tx) ? tx : null;
                string? clientId = fields.TryGetValue(OAuthRequestParameterNames.ClientId, out string? cid)
                    && !string.IsNullOrWhiteSpace(cid) ? cid : null;

                //The application owns the pre-authorized code store; the builder guarantees
                //the seam is wired. It resolves the subject and tells the library which §6.3
                //error a refusal maps to.
                PreAuthorizedCodeDecision decision = await server.Integration.ValidatePreAuthorizedCodeAsync!(
                    preAuthorizedCode, transactionCode, clientId, registration, context, ct).ConfigureAwait(false);

                if(!decision.IsGranted)
                {
                    return (null, MapPreAuthorizedCodeDenial(decision));
                }

                string? subject = decision.Subject;
                if(string.IsNullOrWhiteSpace(subject))
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "Pre-Authorized Code grant was granted without a subject."));
                }

                //OID4VCI 1.0 §6.1.1: the Wallet MAY present authorization_details directly in
                //the Pre-Authorized Code token request to select specific configurations from
                //the Credential Offer. There is no authorize-step value in this flow, so the
                //token-request value alone is the effective request.
                (string? grantedDetailsJson, IReadOnlyList<object>? grantedDetailsClaim, ServerHttpResponse? detailsFailure) =
                    await ResolveGrantedAuthorizationDetailsAsync(
                        server,
                        ReadAuthorizationDetails(fields),
                        authorizedDetailsJson: null,
                        subject,
                        registration,
                        context,
                        ct).ConfigureAwait(false);
                if(detailsFailure is not null)
                {
                    return (null, detailsFailure);
                }

                //RFC 9396 §9.1: the granted authorization_details ride the context into the
                //producer walk so the RFC 9068 JWT access token carries them as a top-level claim.
                if(grantedDetailsClaim is not null)
                {
                    context.SetGrantedAuthorizationDetailsClaim(grantedDetailsClaim);
                }

                Uri issuerUri;
                try
                {
                    issuerUri = server.Integration.ResolveIssuerAsync is not null
                        ? await server.Integration.ResolveIssuerAsync(registration, context, ct)
                            .ConfigureAwait(false)
                        : await DefaultIssuerResolver.ResolveAsync(registration, context, ct)
                            .ConfigureAwait(false);
                }
                catch(InvalidOperationException ex)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, ex.Message));
                }

                DateTimeOffset now = server.TimeProvider.GetUtcNow();

                //OID4VCI 1.0 §13.10 — the Pre-Authorized Code grant always mints an Access Token
                //giving access to Credentials and the pre-authorized token response is a plain
                //bearer token (no DPoP binding on this path). A long-lived bearer Credential token
                //MUST NOT be issued; refuse unless the access-token lifetime is within the §13.10
                //threshold.
                ServerHttpResponse? protectionFailure = GuardCredentialAccessTokenProtection(
                    server, registration, isSenderConstrained: false);
                if(protectionFailure is not null)
                {
                    return (null, protectionFailure);
                }

                //§6.2: the token is bound to the End-User the Credential is about (the
                //seam-resolved subject), not to the Wallet. An absent scope is the
                //authorization_details path (§6.1.1); the granted scope, when present,
                //is echoed in the response.
                string grantedScope = decision.Scope ?? string.Empty;

                IssuanceContext issuance = new()
                {
                    Registration = registration,
                    Context = context,
                    IssuerUri = issuerUri,
                    Subject = subject,
                    Scope = grantedScope,
                    ClientId = clientId ?? registration.ClientId,
                    IssuedAt = now
                };

                IReadOnlyList<TokenProducer> producers =
                    server.Configuration.TokenProducers.Count > 0
                        ? server.Configuration.TokenProducers
                        : DefaultTokenProducers;

                OidcClaims? preResolvedOidcClaims = await PreResolveOidcClaimsAsync(
                    server, issuance, ct).ConfigureAwait(false);

                Dictionary<string, string> issuedTokens = new(producers.Count);
                int expiresIn = 0;

                foreach(TokenProducer producer in producers)
                {
                    //Per-producer capability filter — see BuildToken for the rationale;
                    //reads the resolver's per-request output so capability attenuation
                    //applies to this grant too.
                    IReadOnlySet<CapabilityIdentifier>? resolved =
                        context.ResolvedCapabilities;
                    if(resolved is null || !resolved.Contains(producer.RequiredCapability))
                    {
                        continue;
                    }

                    if(!await producer.IsApplicable(issuance, ct).ConfigureAwait(false))
                    {
                        continue;
                    }

                    KeyId signingKeyId = await SigningKeySelection.ResolveSigningKeyIdAsync(
                        server, registration, producer.KeyUsage, context, ct).ConfigureAwait(false);
                    PrivateKeyMemory? signingKey = await server.Cryptography.SigningKeyResolver!(
                        signingKeyId, registration.TenantId, context, ct).ConfigureAwait(false);
                    if(signingKey is null)
                    {
                        return (null, ServerHttpResponse.ServerError(
                            OAuthErrors.ServerError,
                            $"Signing key unavailable for producer '{producer.Name}'."));
                    }

                    string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(signingKey.Tag);
                    TokenProducerOutput output = await producer.BuildAsync(
                        issuance, signingKeyId, algorithm, ct).ConfigureAwait(false);
                    JwtPayload payload = output.Payload;

                    ClaimContributionTarget? contributionTarget =
                        BuildTargetForProducer(producer, issuance, preResolvedOidcClaims);
                    await MergeContributedClaimsAsync(
                        server, contributionTarget, payload, ct).ConfigureAwait(false);

                    UnsignedJwt unsigned = new(output.Header, payload);
                    using JwsMessage jws = await unsigned.SignAsync(
                        signingKey,
                        server.Codecs.JwtHeaderSerializer!,
                        server.Codecs.JwtPayloadSerializer!,
                        server.Codecs.Encoder!,
                        SensitiveMemoryPool<byte>.Shared,
                        ct).ConfigureAwait(false);

                    string compactJws = JwsSerialization.SerializeCompact(jws, server.Codecs.Encoder!);
                    issuedTokens[producer.ResponseField] = compactJws;

                    if(WellKnownTokenTypes.IsAccessToken(producer.ResponseField))
                    {
                        DateTimeOffset issuedAtClaim = ExtractInstant(payload, WellKnownJwtClaimNames.Iat, now);
                        DateTimeOffset expiresAtClaim = ExtractInstant(payload, WellKnownJwtClaimNames.Exp, now);
                        expiresIn = (int)(expiresAtClaim - issuedAtClaim).TotalSeconds;
                    }
                }

                if(!issuedTokens.TryGetValue(WellKnownTokenTypes.AccessToken, out string? accessToken))
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "No access token was produced for the pre-authorized_code grant."));
                }

                //§6.2/RFC 6749 §5.1: access_token, token_type, expires_in, and the granted
                //scope when one was requested. The c_nonce is deliberately absent — OID4VCI
                //1.0 moved it to the Nonce Endpoint (§7). The response is uncacheable.
                StringBuilder sb = JsonAppender.Rent();
                string responseJson;
                try
                {
                    sb.Append('{');
                    bool first = true;
                    JsonAppender.AppendStringField(sb, WellKnownTokenTypes.AccessToken, accessToken, ref first);
                    JsonAppender.AppendStringField(sb, "token_type",
                        WellKnownAuthenticationSchemes.Bearer, ref first);
                    JsonAppender.AppendInt64Field(sb, "expires_in", expiresIn, ref first);
                    if(!string.IsNullOrEmpty(grantedScope))
                    {
                        JsonAppender.AppendStringField(sb, OAuthRequestParameterNames.Scope, grantedScope, ref first);
                    }

                    //§6.2: when the token request carried authorization_details, the response
                    //echoes the granted details enriched with credential_identifiers.
                    if(grantedDetailsJson is not null)
                    {
                        JsonAppender.AppendRawField(
                            sb, OAuthRequestParameterNames.AuthorizationDetails, grantedDetailsJson, ref first);
                    }

                    sb.Append('}');
                    responseJson = sb.ToString();
                }
                finally
                {
                    JsonAppender.Return(sb);
                }

                return (null, ServerHttpResponse.Ok(responseJson, WellKnownMediaTypes.Application.Json)
                    .WithHeader(WellKnownHttpHeaderNames.CacheControl, WellKnownCacheControlValues.NoStore));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    /// <summary>
    /// Maps an OID4VCI 1.0 §6.3 Pre-Authorized Code denial to the corresponding OAuth 2.0
    /// Token Error Response. A denial with no reason set defaults to <c>invalid_grant</c>,
    /// the spec's catch-all for an unaccepted Pre-Authorized Code.
    /// </summary>
    private static ServerHttpResponse MapPreAuthorizedCodeDenial(PreAuthorizedCodeDecision decision) =>
        decision.DenialReason switch
        {
            PreAuthorizedCodeDenialReason.TransactionCodeRequired =>
                ServerHttpResponse.BadRequest(OAuthErrors.InvalidRequest,
                    decision.DenialDescription ?? "A Transaction Code is required but was not provided."),
            PreAuthorizedCodeDenialReason.TransactionCodeUnexpected =>
                ServerHttpResponse.BadRequest(OAuthErrors.InvalidRequest,
                    decision.DenialDescription ?? "A Transaction Code was provided but is not expected."),
            PreAuthorizedCodeDenialReason.TransactionCodeInvalid =>
                ServerHttpResponse.BadRequest(OAuthErrors.InvalidGrant,
                    decision.DenialDescription ?? "The Transaction Code is invalid."),
            PreAuthorizedCodeDenialReason.ClientAuthenticationRequired =>
                ServerHttpResponse.Unauthorized(OAuthErrors.InvalidClient,
                    decision.DenialDescription ?? "Anonymous access is not supported; a client_id is required."),
            _ => ServerHttpResponse.BadRequest(OAuthErrors.InvalidGrant,
                decision.DenialDescription ?? "The pre-authorized_code is invalid or has expired.")
        };


    /// <summary>
    /// Reads the RFC 9396 <c>authorization_details</c> request field, normalising an absent or
    /// blank value to <see langword="null"/>.
    /// </summary>
    private static string? ReadAuthorizationDetails(RequestFields fields)
    {
        return fields.TryGetValue(OAuthRequestParameterNames.AuthorizationDetails, out string? value)
            && !string.IsNullOrWhiteSpace(value)
            ? value
            : null;
    }


    /// <summary>
    /// Reads the OID4VCI 1.0 §5.1.3 <c>issuer_state</c> request field, normalising an absent or
    /// blank value to <see langword="null"/>. The value is carried verbatim and never validated by
    /// the library: §5.1.3 requires the issuer to treat it as not guaranteed to originate from this
    /// Credential Issuer — it could have been injected by an attacker.
    /// </summary>
    private static string? ReadIssuerState(RequestFields fields)
    {
        return fields.TryGetValue(OAuthRequestParameterNames.IssuerState, out string? value)
            && !string.IsNullOrWhiteSpace(value)
            ? value
            : null;
    }


    /// <summary>
    /// Reads the RFC 8707 <c>resource</c> request field, normalising an absent or blank value to
    /// <see langword="null"/>. Repeated <c>resource</c> query parameters are collapsed by the skin
    /// into a single space-delimited value (the convention this library also uses for
    /// <c>scope</c> and <c>acr_values</c>); <see cref="ParseResourceIndicators"/> splits it back to
    /// the individual absolute-URI indicators.
    /// </summary>
    private static string? ReadResource(RequestFields fields)
    {
        return fields.TryGetValue(OAuthRequestParameterNames.Resource, out string? value)
            && !string.IsNullOrWhiteSpace(value)
            ? value
            : null;
    }


    /// <summary>
    /// Splits the space-delimited <c>resource</c> field value into its individual RFC 8707 §2
    /// indicators, or <see langword="null"/> when none was present. Resource indicators are
    /// absolute URIs and so carry no internal spaces, making the split unambiguous.
    /// </summary>
    private static string[]? ParseResourceIndicators(string? resource)
    {
        if(string.IsNullOrWhiteSpace(resource))
        {
            return null;
        }

        return resource.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }


    /// <summary>
    /// Shape-validates an inbound <c>authorization_details</c> value at receipt: the parse seam
    /// must be wired (an unwired seam means the server does not support the parameter — RFC
    /// 9396 §5 fail-closed), the value must parse as an array of typed objects, every entry
    /// must be of a supported type, and each <c>openid_credential</c> entry must carry a
    /// <c>credential_configuration_id</c> (OID4VCI 1.0 §5.1.1). When the Credential Issuer
    /// metadata declares <c>authorization_servers</c>, each entry must additionally carry the
    /// Credential Issuer Identifier in its <c>locations</c> element (§5.1.1).
    /// </summary>
    /// <returns>
    /// <see langword="null"/> when the value is acceptable; the
    /// <c>invalid_authorization_details</c> failure response otherwise.
    /// </returns>
    private static async ValueTask<ServerHttpResponse?> ValidateAuthorizationDetailsShapeAsync(
        AuthorizationServer server,
        string authorizationDetailsJson,
        ClientRecord registration,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ParseAuthorizationDetailListDelegate? parse = server.Integration.ParseAuthorizationDetailsAsync;
        if(parse is null)
        {
            return ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidAuthorizationDetails,
                "authorization_details is not supported by this authorization server.");
        }

        IReadOnlyList<AuthorizationDetail>? details = await parse(
            authorizationDetailsJson, context, cancellationToken).ConfigureAwait(false);
        if(details is null)
        {
            return ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidAuthorizationDetails,
                "authorization_details could not be parsed.");
        }

        string? requiredLocation = await ResolveRequiredAuthorizationDetailsLocationAsync(
            server, registration, context, cancellationToken).ConfigureAwait(false);

        string? shapeError = AuthorizationDetailsShapeError(
            server.Integration.AuthorizationDetailTypes, details, requiredLocation,
            registration.AllowedAuthorizationDetailsTypes);
        if(shapeError is not null)
        {
            return ServerHttpResponse.BadRequest(OAuthErrors.InvalidAuthorizationDetails, shapeError);
        }

        return null;
    }


    /// <summary>
    /// The RFC 9396 §5 shape requirements for parsed authorization details: a non-empty array
    /// (an empty array carries no authorization to grant) whose every entry's <c>type</c> has a
    /// registered handler that accepts the entry's shape, and — when the client registered an
    /// <c>authorization_details_types</c> allowlist (RFC 9396 §10) — whose every entry's
    /// <c>type</c> is within that allowlist. Each entry is dispatched to its handler in
    /// <paramref name="registry"/>; a <c>type</c> with no handler is the §5 unknown type. The
    /// <paramref name="requiredLocation"/>, when set, is the location each entry MUST carry in
    /// its <c>locations</c> common field (for <c>openid_credential</c>, the OID4VCI 1.0 §5.1.1
    /// Credential Issuer Identifier). The <paramref name="allowedTypes"/>, when non-null, is the
    /// client's registered <c>authorization_details_types</c> allowlist; <see langword="null"/>
    /// means the client registered no restriction and may use any supported type. Returns the
    /// error description, or <see langword="null"/> when the shape is acceptable.
    /// </summary>
    private static string? AuthorizationDetailsShapeError(
        AuthorizationDetailTypeRegistry registry,
        IReadOnlyList<AuthorizationDetail> details,
        string? requiredLocation,
        ImmutableHashSet<string>? allowedTypes)
    {
        if(details.Count == 0)
        {
            return "authorization_details must be a non-empty array.";
        }

        AuthorizationDetailValidationContext validation = new() { RequiredLocation = requiredLocation };
        foreach(AuthorizationDetail detail in details)
        {
            //RFC 9396 §10: a client that registered an authorization_details_types allowlist may
            //use only those types. The gate sits beside the registry's unknown-type check so the
            //pushed/authorize receipt and token-request paths enforce it uniformly. An absent
            //allowlist (null) registers no restriction, so any supported type passes.
            if(allowedTypes is not null && !allowedTypes.Contains(detail.Type))
            {
                return $"The client is not registered to use authorization details type '{detail.Type}'.";
            }

            string? shapeError = registry.ValidateShape(detail, validation);
            if(shapeError is not null)
            {
                return shapeError;
            }
        }

        return null;
    }


    /// <summary>
    /// Projects the <c>openid_credential</c> entries of a shape-validated authorization details
    /// list into the <see cref="CredentialAuthorizationDetail"/> list the OID4VCI token logic
    /// works on, reading each entry's §5.1.1 <c>credential_configuration_id</c> from its
    /// type-specific members. The <c>openid_credential</c> handler owns the projection so the
    /// profile semantics live with the profile.
    /// </summary>
    private static List<CredentialAuthorizationDetail> ProjectOpenIdCredentialDetails(
        IReadOnlyList<AuthorizationDetail> details)
    {
        List<CredentialAuthorizationDetail> projected = new(details.Count);
        foreach(AuthorizationDetail detail in details)
        {
            if(string.Equals(detail.Type, AuthorizationDetailsTypeValues.OpenIdCredential, StringComparison.Ordinal))
            {
                projected.Add(OpenIdCredentialAuthorizationDetailHandler.Project(detail));
            }
        }

        return projected;
    }


    /// <summary>
    /// Resolves the OID4VCI 1.0 §5.1.1 / §6.1.1 <c>locations</c> requirement: when the
    /// deployment's Credential Issuer metadata declares an <c>authorization_servers</c>
    /// parameter, returns the Credential Issuer Identifier value every <c>openid_credential</c>
    /// authorization details object MUST carry in its <c>locations</c> element; otherwise
    /// <see langword="null"/> (the AS is the issuer, so no <c>locations</c> is required).
    /// </summary>
    private static async ValueTask<string?> ResolveRequiredAuthorizationDetailsLocationAsync(
        AuthorizationServer server,
        ClientRecord registration,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        if(server.Integration.ContributeCredentialIssuerMetadataAsync is null)
        {
            return null;
        }

        CredentialIssuerMetadataContribution contribution =
            await server.Integration.ContributeCredentialIssuerMetadataAsync(
                registration, context, cancellationToken).ConfigureAwait(false);
        if(contribution.AuthorizationServers is not { Count: > 0 })
        {
            return null;
        }

        Uri issuer = server.Integration.ResolveIssuerAsync is not null
            ? await server.Integration.ResolveIssuerAsync(registration, context, cancellationToken)
                .ConfigureAwait(false)
            : await DefaultIssuerResolver.ResolveAsync(registration, context, cancellationToken)
                .ConfigureAwait(false);

        return issuer.OriginalString;
    }


    /// <summary>
    /// The OID4VCI 1.0 §13.10 guard for an Access Token that gives access to Credentials.
    /// </summary>
    /// <remarks>
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-13.10">OID4VCI 1.0 §13.10</see>:
    /// "Long-lived Access Tokens giving access to Credentials MUST not be issued unless
    /// sender-constrained. Access Tokens with lifetimes longer than 5 minutes are, in general,
    /// considered long lived." A token outliving
    /// <see cref="TimingPolicy.CredentialAccessTokenSenderConstraintThreshold"/> that is not
    /// sender-constrained (DPoP / <c>cnf.jkt</c>) is refused fail-closed rather than minted; a
    /// short-lived bearer token or any sender-constrained token is permitted.
    /// </remarks>
    /// <returns>
    /// <see langword="null"/> when the token may be issued; the <c>invalid_request</c> failure
    /// response otherwise.
    /// </returns>
    private static ServerHttpResponse? GuardCredentialAccessTokenProtection(
        AuthorizationServer server,
        ClientRecord registration,
        bool isSenderConstrained)
    {
        if(isSenderConstrained)
        {
            return null;
        }

        //Mirror the access-token lifetime the Rfc9068AccessTokenProducer will apply: the
        //per-registration override when set, else the one-hour producer default.
        TimeSpan lifetime =
            registration.GetTokenLifetime(WellKnownTokenTypes.AccessToken) ?? TimeSpan.FromHours(1);

        if(lifetime <= server.Timings.CredentialAccessTokenSenderConstraintThreshold)
        {
            return null;
        }

        //A long-lived plain bearer Credential token — the §13.10 violation. Surface the detection
        //on the request's trace before failing closed.
        System.Diagnostics.Activity.Current?.AddEvent(
            new System.Diagnostics.ActivityEvent(
                Diagnostics.OAuthEventNames.LongLivedBearerCredentialTokenRefused));

        return ServerHttpResponse.BadRequest(
            OAuthErrors.InvalidRequest,
            "A long-lived Access Token giving access to Credentials MUST NOT be issued unless "
            + "sender-constrained (OID4VCI 1.0 §13.10). Issue a sender-constrained (DPoP) token, "
            + "or shorten the access-token lifetime to at most "
            + $"{(int)server.Timings.CredentialAccessTokenSenderConstraintThreshold.TotalSeconds} seconds.");
    }


    /// <summary>
    /// Resolves the granted <c>authorization_details</c> for a token response. The effective
    /// request is the token-request value when present (OID4VCI 1.0 §6.1.1 — it must be a
    /// subset of the configurations authorized at the authorization endpoint when the grant
    /// carried any), else the grant-carried value; the application's
    /// <see cref="AuthorizationServerIntegration.ResolveCredentialAuthorizationAsync"/> seam
    /// decides the grant and mints the §6.2 <c>credential_identifiers</c>.
    /// </summary>
    /// <returns>
    /// The serialised response array, the same granted details in structured form (the list of
    /// authorization details objects the RFC 9396 §9.1 JWT access-token claim carries), and a
    /// <see langword="null"/> failure on success; a <c>(null, null, null)</c> tuple when no
    /// authorization details are in play; a failure response otherwise.
    /// </returns>
    private static async ValueTask<(string? ResponseJson, IReadOnlyList<object>? ClaimDetails, ServerHttpResponse? Failure)> ResolveGrantedAuthorizationDetailsAsync(
        AuthorizationServer server,
        string? tokenRequestDetailsJson,
        string? authorizedDetailsJson,
        string subject,
        ClientRecord registration,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        if(tokenRequestDetailsJson is null && authorizedDetailsJson is null)
        {
            return (null, null, null);
        }

        ParseAuthorizationDetailListDelegate? parse = server.Integration.ParseAuthorizationDetailsAsync;
        ResolveCredentialAuthorizationDelegate? resolve = server.Integration.ResolveCredentialAuthorizationAsync;
        if(parse is null || resolve is null)
        {
            return (null, null, ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidAuthorizationDetails,
                "authorization_details is not supported by this authorization server."));
        }

        //OID4VCI 1.0 §6.1.1: "If the Token Request contains an authorization_details parameter ...
        //of type openid_credential and the Credential Issuer's metadata contains an
        //authorization_servers parameter, the authorization_details object MUST contain the
        //Credential Issuer's identifier in the locations element." The grant-carried value was
        //already enforced at the authorization endpoint (§5.1.1), so the requirement is applied to
        //the token-request value here.
        string? requiredLocation = await ResolveRequiredAuthorizationDetailsLocationAsync(
            server, registration, context, cancellationToken).ConfigureAwait(false);

        IReadOnlyList<CredentialAuthorizationDetail>? requested = null;
        if(tokenRequestDetailsJson is not null)
        {
            IReadOnlyList<AuthorizationDetail>? parsed = await parse(
                tokenRequestDetailsJson, context, cancellationToken).ConfigureAwait(false);
            if(parsed is null)
            {
                return (null, null, ServerHttpResponse.BadRequest(
                    OAuthErrors.InvalidAuthorizationDetails,
                    "authorization_details could not be parsed."));
            }

            string? shapeError = AuthorizationDetailsShapeError(
                server.Integration.AuthorizationDetailTypes, parsed, requiredLocation,
                registration.AllowedAuthorizationDetailsTypes);
            if(shapeError is not null)
            {
                return (null, null, ServerHttpResponse.BadRequest(OAuthErrors.InvalidAuthorizationDetails, shapeError));
            }

            requested = ProjectOpenIdCredentialDetails(parsed);
        }

        IReadOnlyList<CredentialAuthorizationDetail>? authorized = null;
        if(authorizedDetailsJson is not null)
        {
            //The grant-carried value was shape-validated at receipt; a parse failure here
            //means the stored value and the wired parser have diverged — a deployment
            //inconsistency, not a client error.
            IReadOnlyList<AuthorizationDetail>? parsed = await parse(
                authorizedDetailsJson, context, cancellationToken).ConfigureAwait(false);
            if(parsed is null)
            {
                return (null, null, ServerHttpResponse.ServerError(
                    OAuthErrors.ServerError,
                    "The authorization_details carried by the grant could not be re-parsed."));
            }

            authorized = ProjectOpenIdCredentialDetails(parsed);
        }

        //§6.1.1: a token-request value narrows the authorized configurations — every requested
        //credential_configuration_id must have been authorized at the authorization endpoint.
        if(requested is not null && authorized is not null)
        {
            HashSet<string> authorizedConfigurationIds = new(StringComparer.Ordinal);
            foreach(CredentialAuthorizationDetail detail in authorized)
            {
                authorizedConfigurationIds.Add(detail.CredentialConfigurationId!);
            }

            foreach(CredentialAuthorizationDetail detail in requested)
            {
                if(!authorizedConfigurationIds.Contains(detail.CredentialConfigurationId!))
                {
                    return (null, null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidAuthorizationDetails,
                        $"credential_configuration_id '{detail.CredentialConfigurationId}' was not authorized "
                        + "by the authorization request."));
                }
            }
        }

        IReadOnlyList<CredentialAuthorizationDetail> effective = requested ?? authorized!;

        CredentialAuthorizationDecision decision = await resolve(
            effective, subject, registration, context, cancellationToken).ConfigureAwait(false);

        if(!decision.IsGranted)
        {
            return (null, null, MapCredentialAuthorizationDenial(decision));
        }

        if(decision.Granted.Count == 0)
        {
            return (null, null, ServerHttpResponse.ServerError(
                OAuthErrors.ServerError,
                "Credential authorization was granted without any granted configurations."));
        }

        foreach(GrantedCredentialAuthorization granted in decision.Granted)
        {
            //§6.2: credential_identifiers is REQUIRED and non-empty in each granted object.
            if(granted.CredentialIdentifiers.Count == 0)
            {
                return (null, null, ServerHttpResponse.ServerError(
                    OAuthErrors.ServerError,
                    $"Granted configuration '{granted.CredentialConfigurationId}' carries no credential_identifiers."));
            }
        }

        //OID4VCI 1.0 §5.1.2: "if both [scope and an openid_credential authorization details object]
        //request the same Credential type, then the Credential Issuer MUST follow the request as
        //given by the authorization details object." A scope value that maps to the same Credential
        //Configuration as a granted authorization_details object must NOT produce a second §6.2
        //entry — the authorization_details object takes precedence and the type is granted once.
        List<GrantedCredentialAuthorization> deduplicated =
            DeduplicateGrantedByConfiguration(decision.Granted);

        return (
            BuildGrantedAuthorizationDetailsJson(deduplicated),
            BuildGrantedAuthorizationDetailsClaim(deduplicated),
            null);
    }


    /// <summary>
    /// Collapses the granted authorizations to one per <c>credential_configuration_id</c>,
    /// enforcing the OID4VCI 1.0 §5.1.2 precedence rule: when a <c>scope</c> value and an
    /// <c>openid_credential</c> authorization details object request the same Credential type, the
    /// type is granted once — the request is followed as given by the authorization details object,
    /// so the first (authorization-details-derived) grant for a configuration wins and any later
    /// duplicate for the same type is dropped. Emits an observational trace event when a duplicate
    /// is collapsed.
    /// </summary>
    private static List<GrantedCredentialAuthorization> DeduplicateGrantedByConfiguration(
        IReadOnlyList<GrantedCredentialAuthorization> granted)
    {
        HashSet<string> seenConfigurationIds = new(StringComparer.Ordinal);
        List<GrantedCredentialAuthorization> deduplicated = new(granted.Count);
        foreach(GrantedCredentialAuthorization item in granted)
        {
            if(seenConfigurationIds.Add(item.CredentialConfigurationId))
            {
                deduplicated.Add(item);

                continue;
            }

            //A second grant for an already-granted Credential type — the §5.1.2 scope-vs-details
            //collision. The authorization details object already won; surface the collapse on the
            //request's trace (observational; does not change the single-grant outcome).
            System.Diagnostics.Activity.Current?.AddEvent(
                new System.Diagnostics.ActivityEvent(
                    Diagnostics.OAuthEventNames.DuplicateGrantedCredentialConfigurationCollapsed));
        }

        return deduplicated;
    }


    /// <summary>
    /// Maps a refused <see cref="CredentialAuthorizationDecision"/> to the RFC 9396 §5
    /// <c>invalid_authorization_details</c> Token Error Response, with a reason-specific
    /// default description.
    /// </summary>
    private static ServerHttpResponse MapCredentialAuthorizationDenial(CredentialAuthorizationDecision decision) =>
        decision.DenialReason switch
        {
            CredentialAuthorizationDenialReason.UnknownCredentialConfiguration =>
                ServerHttpResponse.BadRequest(OAuthErrors.InvalidAuthorizationDetails,
                    decision.DenialDescription ?? "A requested credential_configuration_id is not known to this issuer."),
            _ => ServerHttpResponse.BadRequest(OAuthErrors.InvalidAuthorizationDetails,
                decision.DenialDescription ?? "The requested authorization details were not granted.")
        };


    /// <summary>
    /// Serialises the OID4VCI 1.0 §6.2 token-response <c>authorization_details</c> array — one
    /// <c>{"type":"openid_credential","credential_configuration_id":…,"credential_identifiers":[…]}</c>
    /// object per granted configuration.
    /// </summary>
    private static string BuildGrantedAuthorizationDetailsJson(
        IReadOnlyList<GrantedCredentialAuthorization> granted)
    {
        StringBuilder sb = JsonAppender.Rent();
        try
        {
            sb.Append('[');
            bool firstItem = true;
            foreach(GrantedCredentialAuthorization item in granted)
            {
                if(!firstItem)
                {
                    sb.Append(',');
                }

                firstItem = false;
                sb.Append('{');
                bool first = true;
                JsonAppender.AppendStringField(sb, AuthorizationDetailsParameterNames.Type,
                    AuthorizationDetailsTypeValues.OpenIdCredential, ref first);
                JsonAppender.AppendStringField(sb, Oid4VciCredentialParameterNames.CredentialConfigurationId,
                    item.CredentialConfigurationId, ref first);
                JsonAppender.AppendStringArrayField(sb, Oid4VciCredentialParameterNames.CredentialIdentifiers,
                    item.CredentialIdentifiers, ref first);
                sb.Append('}');
            }

            sb.Append(']');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    /// <summary>
    /// Builds the structured form of the OID4VCI 1.0 §6.2 granted <c>authorization_details</c> — a
    /// list of authorization details objects, each carrying <c>type</c>,
    /// <c>credential_configuration_id</c>, and <c>credential_identifiers</c> — for the RFC 9396
    /// §9.1 <c>authorization_details</c> top-level claim of the JWT access token. The same
    /// <paramref name="granted"/> source as <see cref="BuildGrantedAuthorizationDetailsJson"/>, so
    /// the JWT claim and the token-response echo carry identical content.
    /// </summary>
    private static List<object> BuildGrantedAuthorizationDetailsClaim(
        List<GrantedCredentialAuthorization> granted)
    {
        List<object> details = new(granted.Count);
        foreach(GrantedCredentialAuthorization item in granted)
        {
            details.Add(new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [AuthorizationDetailsParameterNames.Type] = AuthorizationDetailsTypeValues.OpenIdCredential,
                [Oid4VciCredentialParameterNames.CredentialConfigurationId] = item.CredentialConfigurationId,
                [Oid4VciCredentialParameterNames.CredentialIdentifiers] = new List<object>(item.CredentialIdentifiers)
            });
        }

        return details;
    }


    private static EndpointCandidate BuildRefreshToken() =>
        new()
        {
            Name = WellKnownEndpointNames.AuthCodeRefreshToken,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            StartsNewFlow = false,
            Kind = FlowKind.RefreshToken,
            //DiscoveryMetadataKey null — refresh shares the token endpoint URL.

            //Acceptance test: POST to /token with grant_type=refresh_token and
            //a refresh_token parameter. Disjointness vs the code-grant matcher
            //is enforced by the grant_type filter here.
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
                if(!fields.TryGetValue(OAuthRequestParameterNames.GrantType, out string? grantType)
                    || !string.Equals(grantType, OAuthRequestParameterValues.GrantTypeRefreshToken, StringComparison.Ordinal))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                if(!fields.ContainsKey(OAuthRequestParameterNames.RefreshToken))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
            },

            ExtractCorrelationKey = static (path, fields, context) =>
                fields.TryGetValue(OAuthRequestParameterNames.RefreshToken, out string? refreshToken)
                    && !string.IsNullOrWhiteSpace(refreshToken) ? refreshToken : null,

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                AuthorizationServer server = context.Server!;

                //ResolveCorrelationKeyAsync + LoadFlowStateAsync delivered
                //the persisted refresh-token state; pattern-match to recover
                //its slots. If the loaded state has the wrong type, the
                //refresh-token-index entry has gone stale (a rotated-out
                //token still maps to a flow id whose current state is the
                //ServerTokenIssuedState replacement).
                if(currentState is not ServerRefreshTokenIssuedState storedRefresh)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidGrant, "refresh_token is not valid."));
                }

                ClientRecord? registration = context.Registration;
                if(registration is null)
                {
                    return (null, ServerHttpResponse.Unauthorized(
                        OAuthErrors.InvalidClient, "Unknown client."));
                }

                //RFC 6749 §6 — client_id on the refresh request must match
                //the client the refresh token was originally issued to.
                if(!fields.TryGetValue(OAuthRequestParameterNames.ClientId, out string? clientId)
                    || !string.Equals(clientId, storedRefresh.ClientId, StringComparison.Ordinal))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidGrant,
                        "client_id does not match the refresh token's bound client."));
                }

                Uri issuerUri;
                try
                {
                    issuerUri = server.Integration.ResolveIssuerAsync is not null
                        ? await server.Integration.ResolveIssuerAsync(registration, context, ct)
                            .ConfigureAwait(false)
                        : await DefaultIssuerResolver.ResolveAsync(registration, context, ct)
                            .ConfigureAwait(false);
                }
                catch(InvalidOperationException ex)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, ex.Message));
                }

                DateTimeOffset now = server.TimeProvider.GetUtcNow();

                //RFC 9449 §5 — when the refresh token was issued under a
                //DPoP-bound flow, the refresh exchange MUST present a proof
                //whose thumbprint matches the stored binding. The helper
                //rejects on thumbprint mismatch with invalid_dpop_proof.
                ConfirmationMethod? boundConfirmation = storedRefresh.Confirmation;
                bool dpopRequired = boundConfirmation is { IsEmpty: false };
                DpopValidationOutcome dpopOutcome = await DpopTokenEndpointValidation.ValidateAsync(
                    server, context, registration, issuerUri, now,
                    expectedThumbprint: boundConfirmation?.JwkThumbprint,
                    dpopRequired, ct).ConfigureAwait(false);

                if(!dpopOutcome.IsSuccess)
                {
                    return (null, dpopOutcome.FailureResponse!);
                }

                //Inherit the binding from the stored refresh state, not the
                //fresh validation outcome — the validated proof matched the
                //bound thumbprint, so they're equal, but conceptually the
                //binding is owned by the original issuance.
                ConfirmationMethod? confirmation = boundConfirmation;

                //RFC 9396 §7 / §9.1 / §11.2: the granted authorization_details stored with the
                //grant ride the refresh exchange. The stored value is the authorized baseline; a
                //refresh-request authorization_details value is the §6.1 narrowing request,
                //exactly as in the authorization-code token exchange. The decision seam re-runs
                //and re-mints the §6.2 credential_identifiers (each token response carries them
                //fresh). A grant with no stored details and no request parameter resolves to a
                //(null, null, null) no-op, leaving the response byte-identical to a detail-less
                //refresh.
                fields.TryGetValue(OAuthRequestParameterNames.AuthorizationDetails, out string? refreshRequestDetails);
                (string? grantedDetailsJson, IReadOnlyList<object>? grantedDetailsClaim, ServerHttpResponse? detailsFailure) =
                    await ResolveGrantedAuthorizationDetailsAsync(
                        server,
                        string.IsNullOrWhiteSpace(refreshRequestDetails) ? null : refreshRequestDetails,
                        storedRefresh.AuthorizationDetails,
                        storedRefresh.SubjectId,
                        registration,
                        context,
                        ct).ConfigureAwait(false);
                if(detailsFailure is not null)
                {
                    return (null, detailsFailure);
                }

                if(grantedDetailsJson is not null)
                {
                    context.SetGrantedAuthorizationDetails(grantedDetailsJson);

                    //RFC 9396 §9.1: the granted authorization_details ride the context into the
                    //producer walk so the refreshed RFC 9068 JWT access token carries them as a
                    //top-level claim.
                    if(grantedDetailsClaim is not null)
                    {
                        context.SetGrantedAuthorizationDetailsClaim(grantedDetailsClaim);
                    }

                    //OID4VCI 1.0 §13.10 — the refreshed token gives access to Credentials. A
                    //long-lived bearer Credential token MUST NOT be issued unless sender-
                    //constrained; the refresh exchange inherits the binding from the original
                    //issuance (confirmation above).
                    ServerHttpResponse? protectionFailure = GuardCredentialAccessTokenProtection(
                        server, registration, isSenderConstrained: confirmation is { IsEmpty: false });
                    if(protectionFailure is not null)
                    {
                        return (null, protectionFailure);
                    }
                }

                IssuanceContext issuance = new()
                {
                    Registration = registration,
                    Context = context,
                    IssuerUri = issuerUri,
                    Subject = storedRefresh.SubjectId,
                    Scope = storedRefresh.Scope,
                    ClientId = storedRefresh.ClientId,
                    IssuedAt = now,
                    AuthTime = storedRefresh.AuthTime,
                    Acr = storedRefresh.Acr,
                    Confirmation = confirmation
                };

                IReadOnlyList<TokenProducer> producers =
                    server.Configuration.TokenProducers.Count > 0
                        ? server.Configuration.TokenProducers
                        : DefaultTokenProducers;

                //One-time OidcClaims resolution per request — see BuildToken
                //for rationale.
                OidcClaims? preResolvedOidcClaims = await PreResolveOidcClaimsAsync(
                    server, issuance, ct).ConfigureAwait(false);

                Dictionary<string, string> issuedTokens = new(producers.Count);
                Dictionary<string, IssuedTokenAudit> issuedAudits = new(producers.Count);
                DateTimeOffset latestExpiry = now;

                foreach(TokenProducer producer in producers)
                {
                    //Per-producer capability filter — see BuildToken for the
                    //rationale on filtering producers (not the endpoint) here.
                    //Reads the resolver's per-request output rather than the
                    //registration's static set, so CAEP/RISC attenuation
                    //applies to refresh-exchange just as to code-exchange.
                    IReadOnlySet<CapabilityIdentifier>? resolved =
                        context.ResolvedCapabilities;
                    if(resolved is null || !resolved.Contains(producer.RequiredCapability))
                    {
                        continue;
                    }
                    if(!await producer.IsApplicable(issuance, ct).ConfigureAwait(false))
                    {
                        continue;
                    }

                    KeyId signingKeyId = await SigningKeySelection.ResolveSigningKeyIdAsync(
                        server, registration, producer.KeyUsage, context, ct).ConfigureAwait(false);
                    PrivateKeyMemory? signingKey = await server.Cryptography.SigningKeyResolver!(
                        signingKeyId, registration.TenantId, context, ct).ConfigureAwait(false);
                    if(signingKey is null)
                    {
                        return (null, ServerHttpResponse.ServerError(
                            OAuthErrors.ServerError,
                            $"Signing key unavailable for producer '{producer.Name}'."));
                    }

                    string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(signingKey.Tag);
                    TokenProducerOutput output = await producer.BuildAsync(
                        issuance, signingKeyId, algorithm, ct).ConfigureAwait(false);
                    JwtPayload payload = output.Payload;

                    //Composed contributor walk via ServerConfiguration.ClaimIssuer.
                    //See BuildToken for rationale.
                    ClaimContributionTarget? contributionTarget =
                        BuildTargetForProducer(producer, issuance, preResolvedOidcClaims);
                    await MergeContributedClaimsAsync(
                        server, contributionTarget, payload, ct).ConfigureAwait(false);

                    UnsignedJwt unsigned = new(output.Header, payload);
                    using JwsMessage jws = await unsigned.SignAsync(
                        signingKey,
                        server.Codecs.JwtHeaderSerializer!,
                        server.Codecs.JwtPayloadSerializer!,
                        server.Codecs.Encoder!,
                        SensitiveMemoryPool<byte>.Shared,
                        ct).ConfigureAwait(false);

                    string compactJws = JwsSerialization.SerializeCompact(jws, server.Codecs.Encoder!);
                    issuedTokens[producer.ResponseField] = compactJws;

                    string jti = ExtractJti(payload);
                    DateTimeOffset issuedAt = ExtractInstant(payload, WellKnownJwtClaimNames.Iat, now);
                    DateTimeOffset expiresAt = ExtractInstant(payload, WellKnownJwtClaimNames.Exp, now);

                    issuedAudits[producer.ResponseField] = new IssuedTokenAudit
                    {
                        Jti = jti,
                        SigningKeyId = signingKeyId.Value,
                        IssuedAt = issuedAt,
                        ExpiresAt = expiresAt
                    };

                    if(expiresAt > latestExpiry)
                    {
                        latestExpiry = expiresAt;
                    }
                }

                if(issuedTokens.Count == 0)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, "No applicable token producers."));
                }

                //RFC 9700 §2.2.2 rotation: invalidate the presented refresh
                //token by deleting its flow state, then issue a fresh refresh
                //token under a new flow id. Subsequent presentation of the
                //old refresh token resolves to a missing entry and returns
                //invalid_grant naturally. The value rides the identifier seam
                //so the application owns the entropy source and its
                //provenance tracking.
                string newRefreshToken = await server.Integration.GenerateIdentifierAsync!(
                    WellKnownIdentifierPurposes.OAuthRefreshToken, context, ct)
                    .ConfigureAwait(false);
                DateTimeOffset newRefreshExpiresAt = now + context.RefreshTokenLifetime;

                if(server.Integration.SaveFlowStateAsync is not null)
                {
                    string newRefreshFlowId = await server.Integration.GenerateIdentifierAsync!(
                        WellKnownIdentifierPurposes.OAuthRefreshFlowId, context, ct)
                        .ConfigureAwait(false);
                    ServerRefreshTokenIssuedState newRefreshState = new()
                    {
                        FlowId = newRefreshFlowId,
                        ExpectedIssuer = issuerUri.OriginalString,
                        EnteredAt = now,
                        ExpiresAt = newRefreshExpiresAt,
                        Kind = FlowKind.AuthCodeServer,
                        ClientId = storedRefresh.ClientId,
                        RefreshToken = newRefreshToken,
                        IssuedAt = now,
                        SubjectId = storedRefresh.SubjectId,
                        Scope = storedRefresh.Scope,
                        Confirmation = confirmation,
                        AuthTime = storedRefresh.AuthTime,
                        Acr = storedRefresh.Acr,
                        //RFC 9396 §6.1: the authorization details ride rotation unchanged — a
                        //narrowing refresh reduces only the access token it mints, "but the
                        //resource owner's previous authorization is unchanged by such requests" —
                        //exactly as the scope above rides rotation from the stored grant. A
                        //detail-less grant keeps a null slot.
                        AuthorizationDetails = storedRefresh.AuthorizationDetails
                    };
                    await server.Integration.SaveFlowStateAsync(
                        registration.TenantId, newRefreshFlowId, newRefreshState, stepCount: 0, context, ct)
                        .ConfigureAwait(false);
                }

                //Delete the old refresh state. The dispatcher will overwrite
                //the loaded state's flow id with the transition's result
                //anyway, but the refresh-token-index entry persists until
                //the application's delegate prunes it. DeleteFlowStateAsync
                //is the standardised mechanism for that pruning.
                if(server.Integration.DeleteFlowStateAsync is not null)
                {
                    await server.Integration.DeleteFlowStateAsync(
                        registration.TenantId, storedRefresh.FlowId, context, ct)
                        .ConfigureAwait(false);
                }

                issuedTokens[WellKnownTokenTypes.RefreshToken] = newRefreshToken;

                IssuedTokenSet tokenSet = new() { Tokens = issuedTokens };
                context.SetIssuedTokens(tokenSet);

                IssuedTokenAuditSet auditSet = new() { Audits = issuedAudits };

                return (new ServerTokenExchangeSucceeded(
                    IssuedTokens: auditSet,
                    IssuedAt: now,
                    ExpiresAt: latestExpiry)
                {
                    Confirmation = confirmation
                }, null);
            },

            BuildResponse = static (state, _, context) =>
            {
                if(state is not ServerTokenIssuedState issued)
                {
                    return ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, "Unexpected state after refresh exchange.");
                }

                IssuedTokenSet? tokenSet = context.IssuedTokens;
                if(tokenSet is null || tokenSet.AccessToken is null)
                {
                    return ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, "Issued tokens not found in context.");
                }

                IssuedTokenAudit? accessAudit = issued.IssuedTokens.AccessTokenAudit;
                if(accessAudit is null)
                {
                    return ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "Access token audit missing alongside an issued access token — library invariant violation.");
                }

                int expiresIn = (int)(accessAudit.ExpiresAt - accessAudit.IssuedAt).TotalSeconds;

                string tokenTypeWireName = issued.Confirmation is { IsEmpty: false }
                    ? WellKnownAuthenticationSchemes.DPoP
                    : WellKnownAuthenticationSchemes.Bearer;

                StringBuilder sb = JsonAppender.Rent();
                string responseJson;
                try
                {
                    sb.Append('{');
                    bool first = true;
                    JsonAppender.AppendStringField(sb, "access_token",
                        tokenSet.AccessToken ?? string.Empty, ref first);
                    JsonAppender.AppendStringField(sb, "token_type",
                        tokenTypeWireName, ref first);
                    JsonAppender.AppendInt64Field(sb, "expires_in",
                        expiresIn, ref first);

                    string? refreshToken = tokenSet.RefreshToken;
                    if(refreshToken is not null)
                    {
                        JsonAppender.AppendStringField(sb, "refresh_token",
                            refreshToken, ref first);
                    }

                    string? scope = issued.Scope;
                    if(!string.IsNullOrEmpty(scope))
                    {
                        JsonAppender.AppendStringField(sb, "scope", scope, ref first);
                    }

                    //RFC 9396 §7 / OID4VCI 1.0 §6.2: when the grant carried authorization_details,
                    //the refresh response echoes the granted details enriched with freshly minted
                    //credential_identifiers — the §9.1 access-token claim and this echo carry
                    //identical content. A detail-less grant leaves the member absent, byte-identical
                    //to a refresh that never touched authorization_details.
                    string? grantedDetails = context.GrantedAuthorizationDetails;
                    if(grantedDetails is not null)
                    {
                        JsonAppender.AppendRawField(
                            sb, OAuthRequestParameterNames.AuthorizationDetails, grantedDetails, ref first);
                    }

                    sb.Append('}');
                    responseJson = sb.ToString();
                }
                finally
                {
                    JsonAppender.Return(sb);
                }

                return ServerHttpResponse
                    .Ok(responseJson, WellKnownMediaTypes.Application.Json)
                    .WithHeader(WellKnownHttpHeaderNames.CacheControl, WellKnownCacheControlValues.NoStore);
            }
        };


    private static EndpointCandidate BuildRevocation() =>
        new()
        {
            Name = WellKnownEndpointNames.AuthCodeRevoke,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownCapabilityIdentifiers.OAuthTokenRevocation,
            //RFC 7009 revocation is stateless — a single request that revokes a
            //token and returns, with no multi-step flow and no correlation key to
            //resolve. It uses the same stateless shape as the client_credentials
            //grant (StartsNewFlow + FlowKind.Stateless), not the stateful
            //AuthCodeServer path that would demand a flow handle the request never
            //carries.
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,
            DiscoveryMetadataKey = AuthorizationServerMetadataParameterNames.RevocationEndpoint,

            //Acceptance test: POST to /revoke with a token body parameter per
            //RFC 7009 §2.1.
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
                if(!fields.ContainsKey(OAuthRequestParameterNames.Token))
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

                //RFC 7009 §2.1: the client MUST authenticate using the same method
                //it uses at the token endpoint. The seam owns the method and the
                //credential comparison; the candidate gate guarantees it is wired.
                bool clientAuthenticated = await server.Integration.ValidateClientCredentialsAsync!(
                    context.IncomingRequest, fields, registration, context, ct).ConfigureAwait(false);
                if(!clientAuthenticated)
                {
                    return (null, ServerHttpResponse.Unauthorized(
                        OAuthErrors.InvalidClient, "Client authentication failed."));
                }

                //RFC 7009 §2.1: token is REQUIRED. The matcher already guaranteed
                //its presence; the guard keeps the contract explicit and local.
                if(!fields.TryGetValue(OAuthRequestParameterNames.Token, out string? token)
                    || string.IsNullOrEmpty(token))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "Missing token parameter."));
                }

                fields.TryGetValue(OAuthRequestParameterNames.TokenTypeHint, out string? tokenTypeHint);

                //RFC 7009 §2.1: revoke on behalf of the authenticated client; the
                //application scopes the revocation to that client's tokens and
                //cascades refresh -> access. An unrecognized token_type_hint is a
                //hint, not an error.
                await server.Integration.RevokeTokenAsync!(
                    token, tokenTypeHint, registration, context, ct).ConfigureAwait(false);

                //RFC 7009 §2.2: HTTP 200 with an empty body whether the token was
                //live, already revoked, or unknown — the response never reveals
                //which, so a probing client learns nothing about token validity.
                return (null, ServerHttpResponse.Ok());
            },
            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    private static EndpointCandidate BuildIntrospection() =>
        new()
        {
            Name = WellKnownEndpointNames.AuthCodeIntrospect,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownCapabilityIdentifiers.OAuthTokenIntrospection,
            //RFC 7662 introspection is stateless — a single request that reads a
            //token's status and returns, with no multi-step flow and no correlation
            //key to resolve. It uses the same stateless shape as revocation
            //(StartsNewFlow + FlowKind.Stateless), not the stateful AuthCodeServer
            //path that would demand a flow handle the request never carries.
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,
            DiscoveryMetadataKey = AuthorizationServerMetadataParameterNames.IntrospectionEndpoint,

            //Acceptance test: POST to /introspect with a token body parameter
            //per RFC 7662 §2.1.
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
                if(!fields.ContainsKey(OAuthRequestParameterNames.Token))
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

                //RFC 7662 §2.3: a caller authenticating with client credentials that
                //fail authentication gets HTTP 401. The candidate gate guarantees the
                //seam is wired.
                bool clientAuthenticated = await server.Integration.ValidateClientCredentialsAsync!(
                    context.IncomingRequest, fields, registration, context, ct).ConfigureAwait(false);
                if(!clientAuthenticated)
                {
                    return (null, ServerHttpResponse.Unauthorized(
                        OAuthErrors.InvalidClient, "Client authentication failed."));
                }

                //RFC 7662 §2.1: token is REQUIRED. The matcher already guaranteed its
                //presence; the guard keeps the contract explicit and local.
                if(!fields.TryGetValue(OAuthRequestParameterNames.Token, out string? token)
                    || string.IsNullOrEmpty(token))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "Missing token parameter."));
                }

                fields.TryGetValue(OAuthRequestParameterNames.TokenTypeHint, out string? tokenTypeHint);

                //RFC 7662 §2.2: the application reads its own token store and returns the
                //token's metadata, or an inactive result for an unknown / expired / revoked
                //token (or one this caller may not see). An unrecognized token_type_hint is
                //a hint, not an error. A well-formed, authorized query for an inactive token
                //is NOT an error (RFC 7662 §2.3) — it answers 200 with {"active":false}.
                TokenIntrospectionResult result = await server.Integration.IntrospectTokenAsync!(
                    token, tokenTypeHint, registration, context, ct).ConfigureAwait(false);

                //RFC 9701 §4: a resource server asks for a signed JWT response by sending
                //Accept: application/token-introspection+jwt. The caller is authenticated
                //above — the §5 precondition for serving the JWT form.
                if(IsJwtIntrospectionResponseRequested(context))
                {
                    return (null, await BuildSignedIntrospectionResponseAsync(
                        server, context, registration, result, ct).ConfigureAwait(false));
                }

                //RFC 7662 §2.2: a JSON object in application/json. The library owns the wire
                //shape and the rule that an inactive token discloses nothing further. The
                //response is left cacheable per RFC 7662 §4 (cache up to the token's exp).
                string responseJson = SerializeIntrospectionResponse(result);

                return (null, ServerHttpResponse.Ok(responseJson, WellKnownMediaTypes.Application.Json));
            },
            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    /// <summary>
    /// Serialises a <see cref="TokenIntrospectionResult"/> to its RFC 7662 §2.2
    /// <c>application/json</c> response body — the JSON encoding of
    /// <see cref="BuildIntrospectionMembers"/>.
    /// </summary>
    private static string SerializeIntrospectionResponse(TokenIntrospectionResult result)
    {
        StringBuilder sb = JsonAppender.Rent();
        try
        {
            JsonAppender.AppendObject(sb, BuildIntrospectionMembers(result));

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    /// <summary>
    /// Projects a <see cref="TokenIntrospectionResult"/> to its RFC 7662 §2.2 response
    /// members — the single mapping behind both the plain <c>application/json</c> body and
    /// the RFC 9701 §5 <c>token_introspection</c> claim. <c>active</c> is always present;
    /// every other member appears only when the token is active and the value is supplied.
    /// An inactive token yields exactly <c>{"active":false}</c> — RFC 7662 §2.2 (and
    /// RFC 9701 §5 for the JWT form) direct the server not to disclose anything further,
    /// including why it is inactive.
    /// </summary>
    private static Dictionary<string, object> BuildIntrospectionMembers(TokenIntrospectionResult result)
    {
        Dictionary<string, object> members = new(StringComparer.Ordinal)
        {
            ["active"] = result.IsActive
        };

        if(!result.IsActive)
        {
            return members;
        }

        if(result.Scope is not null)
        {
            members["scope"] = result.Scope;
        }

        if(result.ClientId is not null)
        {
            members["client_id"] = result.ClientId;
        }

        if(result.Username is not null)
        {
            members["username"] = result.Username;
        }

        if(result.TokenType is not null)
        {
            members["token_type"] = result.TokenType;
        }

        if(result.ExpiresAt is { } expiresAt)
        {
            members["exp"] = expiresAt.ToUnixTimeSeconds();
        }

        if(result.IssuedAt is { } issuedAt)
        {
            members["iat"] = issuedAt.ToUnixTimeSeconds();
        }

        if(result.NotBefore is { } notBefore)
        {
            members["nbf"] = notBefore.ToUnixTimeSeconds();
        }

        if(result.Subject is not null)
        {
            members["sub"] = result.Subject;
        }

        //RFC 7662 §2.2 aud: "string identifier or list of string identifiers" — a single
        //audience is written as a JSON string, multiple as an array, both valid per RFC 7519.
        if(result.Audience is { Count: > 0 } audience)
        {
            if(audience.Count == 1)
            {
                members["aud"] = audience[0];
            }
            else
            {
                List<object> audiences = new(audience.Count);
                foreach(string entry in audience)
                {
                    audiences.Add(entry);
                }

                members["aud"] = audiences;
            }
        }

        if(result.Issuer is not null)
        {
            members["iss"] = result.Issuer;
        }

        if(result.JwtId is not null)
        {
            members["jti"] = result.JwtId;
        }

        //RFC 9396 §9.2: "If the AS includes authorization detail information for the token in its
        //response, the information MUST be conveyed with authorization_details as a top-level
        //member of the introspection response JSON object." The application supplies the granted
        //details — already "potentially filtered and extended for the RS making the introspection
        //request" (§9.2), the same per-caller projection it applies to scope — and the library
        //emits them as the §2 structure.
        if(result.AuthorizationDetails is { Count: > 0 } authorizationDetails)
        {
            members[OAuthRequestParameterNames.AuthorizationDetails] =
                BuildAuthorizationDetailsMember(authorizationDetails);
        }

        //RFC 7662 §2.2: service-specific extension members as further top-level members of
        //the introspection response (and, per RFC 9701 §5, of the token_introspection claim).
        if(result.AdditionalClaims is not null)
        {
            foreach(KeyValuePair<string, object> claim in result.AdditionalClaims)
            {
                members[claim.Key] = claim.Value;
            }
        }

        return members;
    }


    /// <summary>
    /// Projects the granted RFC 9396 <c>authorization_details</c> onto the structured CLR form the
    /// library's JSON writers render natively (a list of string-keyed objects): the §2 REQUIRED
    /// <c>type</c>, the §2.2 common fields when present, and every type-specific member from
    /// <see cref="AuthorizationDetail.ExtensionData"/> decoded from its raw JSON text via
    /// <see cref="JsonScalarText.DecodeValue"/>. The same value renders identically through the
    /// manual <see cref="JsonAppender"/> body and the wired JWT payload serializer of the RFC 9701
    /// signed response.
    /// </summary>
    private static List<object> BuildAuthorizationDetailsMember(
        IReadOnlyList<AuthorizationDetail> details)
    {
        List<object> projected = new(details.Count);
        foreach(AuthorizationDetail detail in details)
        {
            Dictionary<string, object> entry = new(StringComparer.Ordinal)
            {
                [AuthorizationDetailsParameterNames.Type] = detail.Type
            };

            if(detail.Locations is not null)
            {
                entry[AuthorizationDetailsParameterNames.Locations] = new List<object>(detail.Locations);
            }

            if(detail.Actions is not null)
            {
                entry[AuthorizationDetailsParameterNames.Actions] = new List<object>(detail.Actions);
            }

            if(detail.DataTypes is not null)
            {
                entry[AuthorizationDetailsParameterNames.DataTypes] = new List<object>(detail.DataTypes);
            }

            if(detail.Identifier is not null)
            {
                entry[AuthorizationDetailsParameterNames.Identifier] = detail.Identifier;
            }

            if(detail.Privileges is not null)
            {
                entry[AuthorizationDetailsParameterNames.Privileges] = new List<object>(detail.Privileges);
            }

            foreach(KeyValuePair<string, string> extension in detail.ExtensionData)
            {
                object? decoded = JsonScalarText.DecodeValue(extension.Value);
                if(decoded is not null)
                {
                    entry[extension.Key] = decoded;
                }
            }

            projected.Add(entry);
        }

        return projected;
    }


    /// <summary>
    /// Returns whether the introspection request asked for the RFC 9701 §4 JWT response
    /// form: an <c>Accept</c> header carrying
    /// <c>application/token-introspection+jwt</c>.
    /// </summary>
    private static bool IsJwtIntrospectionResponseRequested(ExchangeContext context) =>
        context.IncomingRequest is { } request
            && request.Headers.TryGetSingle(WellKnownHttpHeaderNames.Accept, out string? accept)
            && accept is not null
            && accept.Contains(WellKnownMediaTypes.Application.TokenIntrospectionJwt, StringComparison.Ordinal);


    /// <summary>
    /// Builds the RFC 9701 §5 signed JWT introspection response: <c>typ</c>
    /// <c>token-introspection+jwt</c>; top-level claims <c>iss</c> (the AS issuer URL),
    /// <c>aud</c> (the authenticated resource server), and <c>iat</c>; the RFC 7662
    /// members inside the <c>token_introspection</c> claim. The top level deliberately
    /// carries no <c>sub</c> or <c>exp</c> — the §8.1 measure against the response being
    /// replayed as an access token. Signing mirrors the JARM composition: the
    /// <see cref="KeyUsageContext.IntrospectionResponseSigning"/> key set, failing the
    /// request rather than downgrading to an unsigned body the caller did not ask for.
    /// </summary>
    private static async ValueTask<ServerHttpResponse> BuildSignedIntrospectionResponseAsync(
        AuthorizationServer server,
        ExchangeContext context,
        ClientRecord registration,
        TokenIntrospectionResult result,
        CancellationToken cancellationToken)
    {
        if(!registration.SigningKeys.TryGetValue(
                KeyUsageContext.IntrospectionResponseSigning, out SigningKeySet? introspectionKeys)
            || introspectionKeys.Current.IsEmpty)
        {
            return ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidRequest,
                "A JWT introspection response was requested but no introspection-response "
                + "signing key is configured for this caller.");
        }

        if(server.Cryptography.SigningKeyResolver is null
            || server.Codecs.JwtHeaderSerializer is null
            || server.Codecs.JwtPayloadSerializer is null
            || server.Codecs.Encoder is null)
        {
            return ServerHttpResponse.ServerError(
                OAuthErrors.ServerError,
                "The introspection-response signing configuration is incomplete.");
        }

        KeyId signingKeyId = introspectionKeys.Current[0];
        PrivateKeyMemory? signingKey = await server.Cryptography.SigningKeyResolver(
            signingKeyId, registration.TenantId, context, cancellationToken).ConfigureAwait(false);
        if(signingKey is null)
        {
            return ServerHttpResponse.ServerError(
                OAuthErrors.ServerError,
                $"Introspection-response signing key '{signingKeyId.Value}' could not be resolved.");
        }

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
            return ServerHttpResponse.ServerError(
                OAuthErrors.ServerError,
                $"Could not resolve issuer for the JWT introspection response: {ex.Message}");
        }

        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(signingKey.Tag);
        JwtHeader header = new(capacity: 3)
        {
            [WellKnownJwkMemberNames.Alg] = algorithm,
            [WellKnownJoseHeaderNames.Typ] = WellKnownMediaTypes.Jwt.TokenIntrospectionJwt,
            [WellKnownJwkMemberNames.Kid] = signingKeyId.Value
        };

        JwtPayload payload = new(capacity: 4)
        {
            [WellKnownJwtClaimNames.Iss] = issuerUri.OriginalString,
            [WellKnownJwtClaimNames.Aud] = registration.ClientId,
            [WellKnownJwtClaimNames.Iat] = server.TimeProvider.GetUtcNow().ToUnixTimeSeconds(),
            ["token_introspection"] = BuildIntrospectionMembers(result)
        };

        UnsignedJwt unsigned = new(header, payload);
        using JwsMessage jws = await unsigned.SignAsync(
            signingKey,
            server.Codecs.JwtHeaderSerializer,
            server.Codecs.JwtPayloadSerializer,
            server.Codecs.Encoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken).ConfigureAwait(false);
        string responseJwt = JwsSerialization.SerializeCompact(jws, server.Codecs.Encoder);

        return ServerHttpResponse.Ok(responseJwt, WellKnownMediaTypes.Application.TokenIntrospectionJwt);
    }


    /// <summary>
    /// Composes the Authorize-completed redirect Location, optionally
    /// appending the RFC 9207 / FAPI 2.0 §5.3.1.2 <c>iss</c> response
    /// parameter under <c>policy.EmitIssOnRedirect</c>. Closes audit Finding
    /// 1 (missing <c>iss</c> on Authorize redirect).
    /// </summary>
    /// <remarks>
    /// The issuer URL source order mirrors <c>DefaultIssuerResolver</c>:
    /// <see cref="ClientRecord.IssuerUri"/> first, then the per-request
    /// <see cref="ExchangeContextServerExtensions.Issuer"/>. When neither is
    /// populated the parameter is omitted rather than failing the redirect —
    /// the strict-default deployment populates one of the two and the
    /// permissive deployment opts out via <c>policy.EmitIssOnRedirect</c>.
    /// </remarks>
    private static ServerHttpResponse BuildAuthorizeRedirect(
        ServerCodeIssuedState code, ExchangeContext context) =>
        BuildAuthorizeRedirectWithParameters(
            code.RedirectUri,
            $"code={Uri.EscapeDataString(code.CodeHash)}",
            code.State,
            context);


    /// <summary>
    /// Builds an OAuth 2.0 Authorization Error Response as a redirect per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 §4.1.2.1</see>:
    /// a 302 to the client's already-validated <paramref name="redirectUri"/> carrying the
    /// <c>error</c> and <c>error_description</c> query parameters, plus the request's
    /// <paramref name="state"/> when one was sent. Used for authentication-requirement failures
    /// (<c>unmet_authentication_requirements</c>, RFC 9470 §5) discovered after the redirect URI
    /// has been validated, so the error is delivered to the client via the redirect rather than
    /// rendered to the user agent.
    /// </summary>
    private static ServerHttpResponse BuildAuthorizeErrorRedirect(
        Uri redirectUri, string error, string errorDescription, string? state, ExchangeContext context) =>
        BuildAuthorizeRedirectWithParameters(
            redirectUri,
            $"error={Uri.EscapeDataString(error)}&error_description={Uri.EscapeDataString(errorDescription)}",
            state,
            context);


    /// <summary>
    /// Builds a 302 redirect to a validated authorization <paramref name="redirectUri"/>,
    /// appending the already-encoded <paramref name="parameters"/> query fragment, the request's
    /// <paramref name="state"/> when present, and the RFC 9207 <c>iss</c> parameter when
    /// <c>policy.EmitIssOnRedirect</c> is set. A <c>redirect_uri</c> MAY carry its own query
    /// component (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2">RFC 6749 §3.1.2</see> /
    /// RFC 3986), which MUST be retained, so the first appended parameter uses <c>&amp;</c>
    /// when a query is already present and <c>?</c> otherwise. The <c>state</c> is echoed
    /// verbatim on both the success and error responses per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2">RFC 6749 §4.1.2</see> so
    /// the client can bind the redirect to its pending request. The issuer URL source order
    /// mirrors <c>DefaultIssuerResolver</c>: <see cref="ClientRecord.IssuerUri"/> first, then
    /// the per-request <see cref="ExchangeContextServerExtensions.Issuer"/>; the parameter is
    /// omitted when neither is populated.
    /// </summary>
    private static ServerHttpResponse BuildAuthorizeRedirectWithParameters(
        Uri redirectUri, string parameters, string? state, ExchangeContext context)
    {
        string baseUri = redirectUri.ToString();
        char separator = baseUri.Contains('?', StringComparison.Ordinal) ? '&' : '?';
        string location = $"{baseUri}{separator}{parameters}";

        if(!string.IsNullOrEmpty(state))
        {
            location += $"&state={Uri.EscapeDataString(state)}";
        }

        if(context.EmitIssOnRedirect)
        {
            Uri? issuer = context.Registration?.IssuerUri ?? context.Issuer;
            if(issuer is not null)
            {
                location += $"&iss={Uri.EscapeDataString(issuer.ToString())}";
            }
        }

        return ServerHttpResponse.Redirect(location);
    }


    /// <summary>
    /// Composes the RFC 6749 §4.1.2 success response parameters that ride inside a JARM
    /// JWT Response Document: the <c>code</c>, plus <c>state</c> when the request sent one.
    /// </summary>
    private static Dictionary<string, object> BuildAuthorizeSuccessParameters(
        string codeHash, string? state)
    {
        Dictionary<string, object> parameters = new(2, StringComparer.Ordinal)
        {
            ["code"] = codeHash
        };

        if(!string.IsNullOrEmpty(state))
        {
            parameters["state"] = state;
        }

        return parameters;
    }


    /// <summary>
    /// Builds the authorize-completed response: the JARM-encoded response when the request
    /// asked for a JWT-secured authorization response, otherwise the plain RFC 6749 §4.1.2
    /// redirect. Fails closed — a JARM request whose response JWT is missing from the
    /// context produces a server error rather than leaking the code on an unsigned redirect
    /// the client is not expecting.
    /// </summary>
    private static ServerHttpResponse BuildAuthorizeCompletedResponse(
        ServerCodeIssuedState code, ExchangeContext context)
    {
        if(code.ResponseMode is string responseMode
            && JarmResponseModes.IsJwtSecuredResponseMode(responseMode))
        {
            if(context.JarmResponseJwt is not string responseJwt)
            {
                return ServerHttpResponse.ServerError(
                    OAuthErrors.ServerError,
                    "A JWT-secured authorization response was requested but no response JWT was issued.");
            }

            return BuildJarmAuthorizeResponse(code.RedirectUri, responseMode, responseJwt);
        }

        return BuildAuthorizeRedirect(code, context);
    }


    /// <summary>
    /// Reads the optional <c>response_mode</c> request parameter and, when it asks for a
    /// JWT-secured authorization response (JARM), verifies the response can actually be
    /// signed for this client — a <see cref="SigningKeySet"/> under
    /// <see cref="KeyUsageContext.AuthorizationResponseSigning"/> plus the signing codecs
    /// and key resolver. A JARM request the server cannot honour fails fast at receipt
    /// rather than falling back to an unsigned redirect the client is not expecting.
    /// </summary>
    private static (string? ResponseMode, ServerHttpResponse? Failure) ReadResponseMode(
        RequestFields fields, AuthorizationServer server, ExchangeContext context)
    {
        fields.TryGetValue(OAuthRequestParameterNames.ResponseMode, out string? responseMode);
        if(responseMode is null)
        {
            return (null, null);
        }

        return (responseMode, ValidateJarmResponseModeServability(responseMode, server, context));
    }


    /// <summary>
    /// Verifies a JARM <c>response_mode</c> can actually be served for this client — a
    /// <see cref="SigningKeySet"/> under
    /// <see cref="KeyUsageContext.AuthorizationResponseSigning"/> plus the signing codecs and
    /// key resolver. Returns <see langword="null"/> for non-JARM modes and for servable JARM
    /// requests; otherwise the fail-fast <c>invalid_request</c>. Shared by the bare
    /// (<see cref="ReadResponseMode"/>) and signed-request paths so the gate cannot drift.
    /// </summary>
    private static ServerHttpResponse? ValidateJarmResponseModeServability(
        string responseMode, AuthorizationServer server, ExchangeContext context)
    {
        if(!JarmResponseModes.IsJwtSecuredResponseMode(responseMode))
        {
            return null;
        }

        ClientRecord? registration = context.Registration;
        bool isJarmServable = registration is not null
            && registration.SigningKeys.TryGetValue(
                KeyUsageContext.AuthorizationResponseSigning, out SigningKeySet? jarmKeys)
            && !jarmKeys.Current.IsEmpty
            && server.Cryptography.SigningKeyResolver is not null
            && server.Codecs.JwtHeaderSerializer is not null
            && server.Codecs.JwtPayloadSerializer is not null
            && server.Codecs.Encoder is not null;

        if(!isJarmServable)
        {
            return ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidRequest,
                $"response_mode '{responseMode}' requests a JWT-secured authorization response, "
                + "but no authorization-response signing key is configured for this client.");
        }

        return null;
    }


    /// <summary>
    /// Issues the signed JARM JWT Response Document for an authorize response when
    /// <paramref name="responseMode"/> asks for one, per JARM §2.1/§2.2. Returns
    /// <c>(null, null)</c> when the request did not ask for a JWT-secured response.
    /// </summary>
    /// <remarks>
    /// The response JWT expires with the authorization code it conveys
    /// (<c>policy.AuthorizationCodeLifetime</c>, default 600 seconds) — within the ten
    /// minutes JARM §2.1 recommends as the maximum JWT lifetime. The RFC 9207 <c>iss</c>
    /// response parameter needs no separate emission: the JWT's <c>iss</c> claim carries
    /// the same issuer URL, the placement FAPI 2.0 Message Signing §5.4.1 prescribes.
    /// </remarks>
    private static async ValueTask<(string? ResponseJwt, ServerHttpResponse? Failure)> TryIssueJarmResponseJwtAsync(
        AuthorizationServer server,
        ExchangeContext context,
        string? responseMode,
        string clientId,
        IReadOnlyDictionary<string, object> responseParameters,
        CancellationToken cancellationToken)
    {
        if(responseMode is null || !JarmResponseModes.IsJwtSecuredResponseMode(responseMode))
        {
            return (null, null);
        }

        ClientRecord? registration = context.Registration;
        if(registration is null
            || !registration.SigningKeys.TryGetValue(
                KeyUsageContext.AuthorizationResponseSigning, out SigningKeySet? jarmKeys)
            || jarmKeys.Current.IsEmpty
            || server.Cryptography.SigningKeyResolver is null
            || server.Codecs.JwtHeaderSerializer is null
            || server.Codecs.JwtPayloadSerializer is null
            || server.Codecs.Encoder is null)
        {
            return (null, ServerHttpResponse.ServerError(
                OAuthErrors.ServerError,
                "A JWT-secured authorization response was requested but the "
                + "authorization-response signing configuration is incomplete."));
        }

        KeyId signingKeyId = jarmKeys.Current[0];
        PrivateKeyMemory? signingKey = await server.Cryptography.SigningKeyResolver(
            signingKeyId, registration.TenantId, context, cancellationToken).ConfigureAwait(false);
        if(signingKey is null)
        {
            return (null, ServerHttpResponse.ServerError(
                OAuthErrors.ServerError,
                $"Authorization-response signing key '{signingKeyId.Value}' could not be resolved."));
        }

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
                $"Could not resolve issuer for the JWT-secured authorization response: {ex.Message}"));
        }

        DateTimeOffset expiresAt = server.TimeProvider.GetUtcNow() + context.AuthorizationCodeLifetime;

        string responseJwt = await JarmResponseIssuance.IssueAsync(
            signingKey,
            signingKeyId.Value,
            issuerUri.OriginalString,
            clientId,
            expiresAt,
            responseParameters,
            server.Codecs.Encoder,
            server.Codecs.JwtHeaderSerializer,
            server.Codecs.JwtPayloadSerializer,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken).ConfigureAwait(false);

        return (responseJwt, null);
    }


    /// <summary>
    /// Encodes an issued JARM JWT Response Document into the HTTP response for the
    /// requested <c>response_mode</c> per JARM §2.3. The authorize paths here are
    /// <c>response_type=code</c> by construction, so the <c>jwt</c> shortcut resolves
    /// to <c>query.jwt</c> (§2.3.4).
    /// </summary>
    private static ServerHttpResponse BuildJarmAuthorizeResponse(
        Uri redirectUri, string responseMode, string responseJwt)
    {
        string encodingMode = JarmResponseEncoding.ResolveEncodingMode(responseMode, "code");

        if(JarmResponseModes.IsFormPostJwt(encodingMode))
        {
            return ServerHttpResponse
                .Ok(JarmResponseEncoding.ToFormPostHtml(redirectUri, responseJwt), "text/html;charset=UTF-8")
                .WithHeader(WellKnownHttpHeaderNames.CacheControl, WellKnownCacheControlValues.NoStore);
        }

        string location = JarmResponseModes.IsFragmentJwt(encodingMode)
            ? JarmResponseEncoding.ToFragmentRedirectLocation(redirectUri, responseJwt)
            : JarmResponseEncoding.ToQueryRedirectLocation(redirectUri, responseJwt);

        return ServerHttpResponse.Redirect(location);
    }


    /// <summary>
    /// Builds the Authorization Error Response for an authorize-time failure: a JARM
    /// JWT-secured response when the request asked for one (JARM §2.1 carries the error
    /// parameters inside the JWT, even for error responses), otherwise the plain RFC 6749
    /// §4.1.2.1 error redirect.
    /// </summary>
    private static async ValueTask<ServerHttpResponse> BuildAuthorizeErrorResponseAsync(
        AuthorizationServer server,
        ExchangeContext context,
        Uri redirectUri,
        string error,
        string errorDescription,
        string? state,
        string? responseMode,
        string? clientId,
        CancellationToken cancellationToken)
    {
        if(responseMode is not null
            && clientId is not null
            && JarmResponseModes.IsJwtSecuredResponseMode(responseMode))
        {
            Dictionary<string, object> errorParameters = new(3, StringComparer.Ordinal)
            {
                ["error"] = error,
                ["error_description"] = errorDescription
            };

            if(!string.IsNullOrEmpty(state))
            {
                errorParameters["state"] = state;
            }

            (string? responseJwt, ServerHttpResponse? failure) = await TryIssueJarmResponseJwtAsync(
                server, context, responseMode, clientId, errorParameters, cancellationToken)
                .ConfigureAwait(false);
            if(failure is not null)
            {
                return failure;
            }

            return BuildJarmAuthorizeResponse(redirectUri, responseMode, responseJwt!);
        }

        return BuildAuthorizeErrorRedirect(redirectUri, error, errorDescription, state, context);
    }


    /// <summary>
    /// Maps an application <see cref="AuthorizationDenialReason"/> to its OAuth 2.0
    /// Authorization Error Response code. A denial with no reason set is treated as
    /// <see cref="AuthorizationDenialReason.AccessDenied"/>.
    /// </summary>
    private static string MapDenialReasonToError(AuthorizationDenialReason? reason) => reason switch
    {
        AuthorizationDenialReason.UnmetAuthenticationRequirements => OAuthErrors.UnmetAuthenticationRequirements,
        AuthorizationDenialReason.AccessDenied => OAuthErrors.AccessDenied,
        _ => OAuthErrors.AccessDenied
    };


    /// <summary>
    /// Supplies a reason-specific <c>error_description</c> for an application denial that
    /// carried none.
    /// </summary>
    private static string DefaultDenialDescription(AuthorizationDenialReason? reason) => reason switch
    {
        AuthorizationDenialReason.UnmetAuthenticationRequirements =>
            "The established authentication does not satisfy the request's authentication requirements.",
        _ => "The authorization request was denied."
    };


    /// <summary>
    /// Evaluates a request's RFC 9470 §5 step-up authentication requirements at the
    /// authorization endpoint, shared across every code-issuing authorize path (PAR-backed,
    /// direct, and JAR). Enforces the temporal <c>max_age</c> recency requirement itself
    /// (OIDC Core §3.1.2.1, using the deployment's <c>ClockSkewTolerance</c>), then invokes
    /// the application's <see cref="EvaluateAuthorizationRequestDelegate"/> for the semantic
    /// decision (<c>acr</c> satisfaction, consent, policy). Returns the OAuth Authorization
    /// Error Response redirect to use when a requirement is unmet, or <see langword="null"/>
    /// when the request may proceed to code issuance.
    /// </summary>
    /// <summary>
    /// Reads the optional <c>max_age</c> request parameter (OIDC Core §3.1.2.1) — the maximum
    /// authentication age in whole seconds, a non-negative integer. Returns the parsed value
    /// (or <see langword="null"/> when the parameter is absent) and whether it was well-formed;
    /// a present-but-malformed value reports <c>IsWellFormed = false</c> so the caller rejects
    /// the request with <c>invalid_request</c>. Shared by the query-parameter authorize paths
    /// (PAR and direct); the JAR path reads the same parameter from the signed request object.
    /// </summary>
    /// <summary>
    /// Returns whether a <c>request_uri</c>-referenced authorize request carries any front-channel
    /// parameter beyond <c>request_uri</c> and <c>client_id</c>. Per RFC 9126 §4 / RFC 9101 §6.3
    /// such a request carries only those two; anything else is ignored (the pushed request is
    /// authoritative) and is a signal worth surfacing for observability.
    /// </summary>
    private static bool HasExtraneousReferencedRequestParameters(RequestFields fields)
    {
        foreach(string key in fields.Keys)
        {
            if(!string.Equals(key, OAuthRequestParameterNames.RequestUri, StringComparison.Ordinal)
                && !string.Equals(key, OAuthRequestParameterNames.ClientId, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }


    private static (int? MaxAge, bool IsWellFormed) ReadRequestedMaxAge(RequestFields fields)
    {
        if(!fields.TryGetValue(OAuthRequestParameterNames.MaxAge, out string? raw)
            || string.IsNullOrEmpty(raw))
        {
            return (null, true);
        }

        if(!int.TryParse(raw, out int parsed) || parsed < 0)
        {
            return (null, false);
        }

        return (parsed, true);
    }


    private static async ValueTask<ServerHttpResponse?> EvaluateAuthenticationRequirementsAsync(
        AuthorizationServer server,
        ExchangeContext context,
        string? requestedAcrValues,
        int? requestedMaxAge,
        string requestedScope,
        string subjectId,
        DateTimeOffset now,
        Uri redirectUri,
        string? requestState,
        CancellationToken cancellationToken,
        string? requestedAuthorizationDetails = null,
        string? responseMode = null,
        string? clientId = null,
        string? requestedIssuerState = null,
        string? requestedResource = null)
    {
        if(requestedMaxAge is int maxAge)
        {
            //RFC 9470 §5 / OIDC Core §3.1.2.1 — max_age bounds the elapsed seconds since the
            //End-User's last active authentication. The comparison is in WHOLE SECONDS, the
            //unit max_age and the auth_time claim are both defined in, and carries NO clock-skew
            //padding: auth_time and now are both produced within this authorization server (one
            //clock), so there is no two-party divergence to absorb — unlike the JAR / access-token
            //iat/exp checks, which compare a remote issuer's timestamps. Padding here would
            //silently widen max_age=0 ("prompt=login", requiring a fresh authentication) into a
            //tolerance-wide window through which a stale session would pass. The requirement is
            //necessary (RFC 9470 §5): an absent auth_time cannot be confirmed recent and so fails
            //closed rather than being assumed fresh.
            if(context.AuthTime is not { } establishedAuthTime
                || now.ToUnixTimeSeconds() - establishedAuthTime.ToUnixTimeSeconds() > maxAge)
            {
                return await BuildAuthorizeErrorResponseAsync(
                    server,
                    context,
                    redirectUri,
                    OAuthErrors.UnmetAuthenticationRequirements,
                    "The established authentication does not satisfy the requested max_age.",
                    requestState,
                    responseMode,
                    clientId,
                    cancellationToken).ConfigureAwait(false);
            }
        }

        if(server.Integration.EvaluateAuthorizationRequestAsync is { } evaluateRequest
            && context.Registration is { } registration)
        {
            AuthorizationRequestDecision decision = await evaluateRequest(
                new AuthorizationRequestEvaluation
                {
                    RequestedAcrValues = requestedAcrValues,
                    RequestedMaxAge = requestedMaxAge,
                    RequestedScope = requestedScope,
                    RequestedAuthorizationDetails = requestedAuthorizationDetails,
                    //OID4VCI 1.0 §5.1.3: issuer_state is surfaced UNTRUSTED — the seam owns
                    //correlating it to the Offer; the library validates nothing about it. RFC 8707
                    //resource is surfaced as the parsed indicator list (§5.1.2).
                    RequestedIssuerState = requestedIssuerState,
                    RequestedResource = ParseResourceIndicators(requestedResource),
                    Subject = subjectId,
                    EstablishedAcr = context.Acr,
                    EstablishedAuthTime = context.AuthTime
                },
                registration, context, cancellationToken).ConfigureAwait(false);

            if(!decision.IsPermitted)
            {
                return await BuildAuthorizeErrorResponseAsync(
                    server,
                    context,
                    redirectUri,
                    MapDenialReasonToError(decision.DenialReason),
                    decision.DenialDescription ?? DefaultDenialDescription(decision.DenialReason),
                    requestState,
                    responseMode,
                    clientId,
                    cancellationToken).ConfigureAwait(false);
            }
        }

        return null;
    }


    /// <summary>
    /// Returns whether <paramref name="method"/> is an accepted PKCE
    /// <c>code_challenge_method</c> value under the deployment's policy. The
    /// strict default (<see cref="PkceMethodSet.S256Only"/>) accepts only
    /// <c>S256</c>; the permissive baseline
    /// (<see cref="PkceMethodSet.S256AndPlain"/>) also accepts <c>plain</c>.
    /// </summary>
    private static bool IsAcceptedPkceMethod(string? method, ExchangeContext context)
    {
        if(string.IsNullOrEmpty(method))
        {
            return false;
        }

        if(string.Equals(method, OAuthRequestParameterValues.CodeChallengeMethodS256,
            StringComparison.Ordinal))
        {
            return true;
        }

        return context.AllowedPkceMethods == PkceMethodSet.S256AndPlain
            && string.Equals(method, "plain", StringComparison.Ordinal);
    }


    /// <summary>
    /// Hashes <paramref name="input"/> as ASCII bytes and returns the digest
    /// base64url-encoded. Used for PKCE S256 challenge recomputation per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.6">RFC 7636 §4.6</see>
    /// and for authorization-code hashing.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Both the input bytes and the digest output are pool-allocated; nothing
    /// crosses the boundary as a managed array. The algorithm is carried in
    /// <paramref name="algorithmTag"/>; the same helper handles SHA-256 (RFC 7636
    /// §4.2 PKCE), SHA-384, SHA-512, or future post-quantum hashes without
    /// signature changes.
    /// </para>
    /// <para>
    /// The <see cref="CryptoEvent"/> the digest delegate emits is dropped here
    /// because the helper's two call contexts — code-hash storage and PKCE
    /// verification — already produce flow-level events through the AS pipeline.
    /// A separate digest event would duplicate that audit trail.
    /// </para>
    /// </remarks>
    internal static string ComputeDigestBase64Url(
        string input,
        Tag algorithmTag,
        int digestByteLength,
        ComputeDigestDelegate computeDigest,
        EncodeDelegate encoder,
        MemoryPool<byte> pool)
    {
        //AuthCode endpoint handlers run inside sync endpoint-builder lambdas that
        //don't have an await boundary at this layer; bridge to async via
        //CryptographicKeyEvents.ComputeDigestSyncBridge. The computeDigest
        //parameter is retained for API stability but the registered delegate is
        //used directly via the bridge — both resolve to the same backend in
        //practice. If a future profile needs a non-default qualifier here, the
        //helper migrates to async at that point.
        _ = computeDigest;

        int inputByteCount = System.Text.Encoding.ASCII.GetByteCount(input);
        using IMemoryOwner<byte> inputOwner = pool.Rent(inputByteCount);
        Span<byte> inputBytes = inputOwner.Memory.Span[..inputByteCount];
        System.Text.Encoding.ASCII.GetBytes(input, inputBytes);

        using DigestValue digest = CryptographicKeyEvents.ComputeDigestSyncBridge(
            inputOwner.Memory[..inputByteCount], digestByteLength, algorithmTag, pool);

        return encoder(digest.AsReadOnlySpan());
    }


    private static string ExtractJti(JwtPayload payload)
    {
        if(payload.TryGetValue(WellKnownJwtClaimNames.Jti, out object? value) && value is string jti)
        {
            return jti;
        }

        //A producer that does not set jti is a library bug; return an empty
        //value rather than throwing so the request still succeeds. The audit
        //record will carry an empty string and the absence is observable.
        return string.Empty;
    }


    private static DateTimeOffset ExtractInstant(JwtPayload payload, string claim, DateTimeOffset fallback)
    {
        if(!payload.TryGetValue(claim, out object? value))
        {
            return fallback;
        }

        return value switch
        {
            long unixSeconds => DateTimeOffset.FromUnixTimeSeconds(unixSeconds),
            int unixSecondsInt => DateTimeOffset.FromUnixTimeSeconds(unixSecondsInt),
            DateTimeOffset dt => dt,
            _ => fallback
        };
    }
}
