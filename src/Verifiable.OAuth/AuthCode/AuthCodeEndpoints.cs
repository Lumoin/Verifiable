using System.Buffers;
using System.Collections.Immutable;
using System.Text;
using Verifiable.Core;
using Verifiable.Core.Assessment;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.OAuth.AuthCode.Server;
using Verifiable.OAuth.AuthCode.Server.States;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.IdJag;
using Verifiable.OAuth.Introspection;
using Verifiable.OAuth.Jar;
using Verifiable.OAuth.Jarm;
using Verifiable.OAuth.JwtBearer;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oidc;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Audit;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.OAuth.Validation;
namespace Verifiable.OAuth.AuthCode;

/// <summary>
/// Endpoint builder module for the OAuth 2.0 Authorization Code flow with PKCE.
/// </summary>
/// <remarks>
/// <para>
/// Produces PAR, Authorize (PAR-backed), Direct Authorize, and Token endpoints.
/// Register at startup via <see cref="ServerConfiguration.EndpointBuilders"/>:
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
public static class AuthCodeEndpoints
{

    /// <summary>
    /// The endpoint builder delegate. Pass this to
    /// <see cref="ServerConfiguration.EndpointBuilders"/>.
    /// </summary>
    public static EndpointBuilderDelegate Builder { get; } = static (registration, context, ct) =>
    {
        List<EndpointCandidate> candidates = [];

        if(((ClientRecord)registration).IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OAuthPushedAuthorization))
        {
            candidates.Add(BuildPar());
        }

        if(((ClientRecord)registration).IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OAuthAuthorizationCode))
        {
            candidates.Add(BuildAuthorize());
            //RFC 9101 §5 — explicit both-present (request + request_uri) rejection on the
            //authorize URL; the routing matchers decline that case, this one owns it.
            candidates.Add(BuildAuthorizeRequestObjectConflict());
        }

        if(((ClientRecord)registration).IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OAuthDirectAuthorization))
        {
            candidates.Add(BuildDirectAuthorize());
        }

        if(((ClientRecord)registration).IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OAuthPushedAuthorization)
            && ((ClientRecord)registration).IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OAuthJwtSecuredAuthorizationRequest))
        {
            candidates.Add(BuildJarPar());
        }

        if(((ClientRecord)registration).IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OAuthDirectAuthorization)
            && ((ClientRecord)registration).IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OAuthJwtSecuredAuthorizationRequest))
        {
            candidates.Add(BuildAuthorizeJarByValue());
        }

        bool hasTokenCapability =
            ((ClientRecord)registration).IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OAuthAuthorizationCode) ||
            ((ClientRecord)registration).IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OAuthClientCredentials) ||
            ((ClientRecord)registration).IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OAuthTokenExchange);

        //Grant types this registration actually materializes a candidate for below.
        //BuildTokenGrantTypeRefusal reads this set to tell "this registration is not
        //registered for this grant type" (RFC 6749 §5.2 unauthorized_client) apart from
        //"this server's wiring does not serve it at all" (§5.2 unsupported_grant_type),
        //which serverServedGrantTypes below answers instead.
        HashSet<string> registeredGrantTypes = new(StringComparer.Ordinal);

        //Server-wiring seams, independent of any registration's allowed capabilities.
        //serverServedGrantTypes below reads these to tell a grant type THIS server never
        //serves (RFC 6749 §5.2 unsupported_grant_type) apart from one it serves that a
        //particular registration is not registered for (§5.2 unauthorized_client) —
        //conflating the two would answer unauthorized_client for a grant type the library
        //implements but this server's wiring does not serve, such as token exchange
        //without its validation seam.
        bool clientCredentialsSeamWired = context.RequestServer?.OAuth().ValidateClientCredentialsAsync is not null;
        bool tokenExchangeSeamWired = clientCredentialsSeamWired
            && context.RequestServer?.OAuth().ValidateTokenExchangeTokenAsync is not null
            && context.RequestServer?.OAuth().AuthorizeTokenExchangeAsync is not null;
        bool jwtBearerSeamWired = context.RequestServer?.OAuth().ValidateJwtBearerAssertionAsync is not null;
        bool preAuthorizedCodeSeamWired = context.RequestServer?.OAuth().ValidatePreAuthorizedCodeAsync is not null;

        //Authorization code and refresh token need no external seam — this module
        //implements their token issuance directly — so both are always server-served,
        //regardless of any registration's allowed capabilities.
        HashSet<string> serverServedGrantTypes = new(StringComparer.Ordinal)
        {
            WellKnownGrantTypes.AuthorizationCode,
            WellKnownGrantTypes.RefreshToken
        };

        if(clientCredentialsSeamWired)
        {
            _ = serverServedGrantTypes.Add(WellKnownGrantTypes.ClientCredentials);
        }

        if(tokenExchangeSeamWired)
        {
            _ = serverServedGrantTypes.Add(WellKnownGrantTypes.TokenExchange);
        }

        if(jwtBearerSeamWired)
        {
            _ = serverServedGrantTypes.Add(WellKnownGrantTypes.JwtBearer);
        }

        if(preAuthorizedCodeSeamWired)
        {
            _ = serverServedGrantTypes.Add(WellKnownGrantTypes.PreAuthorizedCode);
        }

        //The code-grant candidate, and the ownership registeredGrantTypes records for it, are
        //gated on the capability the candidate itself declares (OAuthAuthorizationCode), not on
        //the broader hasTokenCapability, which also holds for a registration allowed only
        //client_credentials or only token_exchange. A grant type is owned by a candidate only
        //when that candidate survives EndpointChain's capability filter for THIS registration;
        //otherwise the grant_type refusal below answers it with unauthorized_client
        //(RFC 6749 §5.2).
        if(((ClientRecord)registration).IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OAuthAuthorizationCode))
        {
            candidates.Add(BuildToken());
            _ = registeredGrantTypes.Add(WellKnownGrantTypes.AuthorizationCode);
        }

        //client_credentials grant (RFC 6749 §4.4) — machine-to-machine token
        //issuance (for example a Shared Signals Receiver obtaining ssf.manage).
        //Activates only when BOTH the capability and the client-authentication
        //seam are present: an unauthenticated client-credentials grant would
        //mint tokens for anyone claiming a client_id.
        if(((ClientRecord)registration).IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OAuthClientCredentials)
            && clientCredentialsSeamWired)
        {
            candidates.Add(BuildClientCredentials());
            _ = registeredGrantTypes.Add(WellKnownGrantTypes.ClientCredentials);
        }

        //Token Exchange grant (RFC 8693 §2.1) — impersonation only — shares the token
        //endpoint URL, disjoint from the other grants by the grant_type filter. Activates
        //only when the capability AND the client-authentication seam AND both token-exchange
        //seams (subject-token validation and the impersonation policy decision) are present:
        //an advertised grant missing either seam would mint tokens for any subject-token
        //string or skip the authorization decision (fail-closed, like client_credentials).
        if(((ClientRecord)registration).IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OAuthTokenExchange)
            && tokenExchangeSeamWired)
        {
            candidates.Add(BuildTokenExchange());
            _ = registeredGrantTypes.Add(WellKnownGrantTypes.TokenExchange);
        }

        //JWT Bearer authorization grant (RFC 7523 §2.1/§3.1) — shares the token endpoint URL,
        //disjoint from the other grants by the grant_type filter. Activates only when the capability
        //AND the assertion-validation seam are present: an advertised grant missing the seam would
        //mint tokens for any assertion string (fail-closed, like client_credentials). Unlike
        //token-exchange/client_credentials, client AUTHENTICATION is OPTIONAL for this grant (§3.1),
        //so the client-authentication seam is NOT required to materialize it — the assertion is the
        //grant; the endpoint validates client credentials only if the request carries them.
        if(((ClientRecord)registration).IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OAuthJwtBearer)
            && jwtBearerSeamWired)
        {
            candidates.Add(BuildJwtBearer());
            _ = registeredGrantTypes.Add(WellKnownGrantTypes.JwtBearer);
        }

        //OID4VCI 1.0 §6 Pre-Authorized Code grant — shares the token endpoint URL,
        //disjoint from the other grants by the grant_type filter. Activates only when
        //BOTH the capability and the code-validation seam are present: an advertised
        //pre-authorized grant with no seam would mint access tokens for any code string
        //(fail-closed, like client_credentials).
        if(((ClientRecord)registration).IsCapabilityAllowed(WellKnownCapabilityIdentifiers.Oid4VciPreAuthorizedCodeGrant)
            && preAuthorizedCodeSeamWired)
        {
            candidates.Add(BuildPreAuthorizedCodeToken());
            _ = registeredGrantTypes.Add(WellKnownGrantTypes.PreAuthorizedCode);
        }

        //Refresh-token grant per RFC 6749 §6 is enabled whenever the
        //registration allows AuthorizationCode capability. RFC 9700 §2.2.2
        //rotation is enforced unconditionally on every successful refresh.
        if(((ClientRecord)registration).IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OAuthAuthorizationCode))
        {
            candidates.Add(BuildRefreshToken());
            _ = registeredGrantTypes.Add(WellKnownGrantTypes.RefreshToken);
        }

        //RFC 6749 §5.2 grant_type refusal — the token endpoint's residual arm for a
        //grant_type none of the candidates above accepted. Added last so every specific
        //grant candidate gets first refusal; live-configuration correct because it reads
        //serverServedGrantTypes and registeredGrantTypes captured from THIS request's own
        //wiring, not a fixed list. Appended for EVERY registration allowed any
        //token-serving capability — hasTokenCapability alone misses a registration whose
        //only such capability is JWT bearer or pre-authorized code, which would otherwise
        //fall through every candidate above and reach the host's generic 404.
        bool hasAnyTokenServingCapability =
            hasTokenCapability ||
            ((ClientRecord)registration).IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OAuthJwtBearer) ||
            ((ClientRecord)registration).IsCapabilityAllowed(WellKnownCapabilityIdentifiers.Oid4VciPreAuthorizedCodeGrant);

        if(hasAnyTokenServingCapability)
        {
            CapabilityIdentifier tokenEndpointCapability =
                SelectTokenEndpointCapability((ClientRecord)registration);

            candidates.Add(BuildTokenGrantTypeRefusal(
                tokenEndpointCapability, serverServedGrantTypes, registeredGrantTypes));
        }

        //Token revocation (RFC 7009). Activates only when the capability is
        //allowed AND both the revocation seam and the client-authentication seam
        //are wired: a revocation endpoint that cannot authenticate the client or
        //cannot revoke would be a silent no-op that misleads clients into
        //believing their tokens were killed (fail-closed, like client_credentials).
        if(((ClientRecord)registration).IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OAuthTokenRevocation)
            && context.RequestServer?.OAuth().RevokeTokenAsync is not null
            && context.RequestServer?.OAuth().ValidateClientCredentialsAsync is not null)
        {
            candidates.Add(BuildRevocation());
        }

        //RFC 7662 introspection materializes only when the capability is allowed
        //AND both the introspection seam and the client-authentication seam are
        //wired: an endpoint that cannot authenticate the caller would leak token
        //state, and one with no store to read could only answer active:false —
        //both fail-closed, like revocation above.
        if(((ClientRecord)registration).IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OAuthTokenIntrospection)
            && context.RequestServer?.OAuth().IntrospectTokenAsync is not null
            && context.RequestServer?.OAuth().ValidateClientCredentialsAsync is not null)
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
                EndpointServer server = context.RequestServer!;
                var oauth = server.OAuth();

                if(!fields.TryGetValue(OAuthRequestParameterNames.ClientId, out string? clientId)
                    || string.IsNullOrWhiteSpace(clientId))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "Missing client_id."));
                }

                //RFC 9126 §2.1: "the client_id parameter is defined with the same semantics for
                //both authorization requests and requests to the token endpoint; as a required
                //authorization request parameter, it is similarly required in a pushed
                //authorization request" — identification against the tenant's ALREADY
                //SELECTED registration, never a substitute for client authentication and never
                //substituted BY it. This matcher already asserts context.ClientRegistration is
                //non-null, so the read is unconditional here.
                ClientRecord registration = context.ClientRegistration!;
                if(!IsPresentedClientIdentifierTheRegistration(registration, clientId))
                {
                    return (null, UnknownClientResponse(context.IncomingRequest));
                }

                //RFC 9126 §2: "the rules for client authentication ... for token endpoint requests
                //... apply for the PAR endpoint as well" — the declared method authenticates here
                //exactly as it would at the token endpoint, before any pushed-request effect (no
                //request_uri generated, no state saved).
                ServerHttpResponse? parAuthenticationFailure = await RequireClientAuthenticationIfDeclaredAsync(
                    oauth, context.IncomingRequest, fields, registration, context, ct).ConfigureAwait(false);
                if(parAuthenticationFailure is not null)
                {
                    return (null, parAuthenticationFailure);
                }

                if(!fields.TryGetValue(OAuthRequestParameterNames.CodeChallenge, out string? challenge)
                    || string.IsNullOrWhiteSpace(challenge))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "Missing code_challenge."));
                }

                _ = fields.TryGetValue(OAuthRequestParameterNames.CodeChallengeMethod, out string? method);
                if(!IsAcceptedPkceMethod(method))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        "only the S256 code challenge method is supported"));
                }

                if(!fields.TryGetValue(OAuthRequestParameterNames.RedirectUri, out string? redirectUriString)
                    || !Uri.TryCreate(redirectUriString, UriKind.Absolute, out Uri? redirectUri))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "Missing or invalid redirect_uri."));
                }

                //RFC 9700 §2.1 + OAuth 2.1 §2.3.1 — redirect_uri exact-match
                //against the registered set, per RedirectUriMatching (simple
                //string comparison, not Uri equality), with the RFC 8252 §7.3
                //loopback fallback for a public PKCE-S256 client. The direct
                //authorization request applies the same gate to its own redirect_uri.
                if(!IsAcceptableRedirectUri(
                    registration.AllowedRedirectUris, redirectUri, registration.TokenEndpointAuthMethod, method, context))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        $"redirect_uri '{redirectUri}' is not among the registered redirect URIs."));
                }

                //RFC 6749 §4.1.1 / OAuth 2.1 §4.1.1 — response_type is REQUIRED; an absent
                //value is a malformed request rather than an implicit request for the code
                //grant. RFC 9126 §2.3 error responses at the PAR endpoint use the same
                //error registry as the authorization endpoint, returned directly (PAR
                //has no redirect leg of its own).
                _ = fields.TryGetValue(OAuthRequestParameterNames.ResponseType, out string? responseType);
                if(string.IsNullOrEmpty(responseType))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "Missing response_type."));
                }

                if(IsUnsupportedResponseType(responseType))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        UnsupportedResponseTypeError,
                        $"response_type '{responseType}' is not supported; this authorization "
                        + $"server issues '{WellKnownResponseTypes.Code}' only."));
                }

                _ = fields.TryGetValue(OAuthRequestParameterNames.Scope, out string? scope);
                if(context.ScopeRequiredOnRequest && string.IsNullOrEmpty(scope))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        "scope is required under the active policy."));
                }
                scope ??= string.Empty;

                _ = fields.TryGetValue(WellKnownJwtClaimNames.Nonce, out string? nonce);
                nonce ??= string.Empty;

                //RFC 9470 §4 step-up: the authentication-requirement parameters
                //(acr_values, max_age) are carried forward to the authorization
                //endpoint where they are evaluated against the established
                //authentication. max_age is a non-negative integer (OIDC Core
                //§3.1.2.1); a malformed value is a request error.
                _ = fields.TryGetValue(OAuthRequestParameterNames.AcrValues, out string? acrValues);
                _ = fields.TryGetValue(OAuthRequestParameterNames.State, out string? requestState);
                (int? maxAge, bool isMaxAgeWellFormed) = ReadRequestedMaxAge(fields);
                if(!isMaxAgeWellFormed)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "max_age must be a non-negative integer."));
                }

                //OIDC Core §3.1.2.1: "If this parameter contains none with any other value, an
                //error is returned." PAR has no front channel to redirect through (RFC 9126
                //§2.3), so — like every other malformed-request rejection at this leg — the
                //answer is a bare 400.
                _ = fields.TryGetValue(OAuthRequestParameterNames.Prompt, out string? prompt);
                if(HasNoneWithOtherPromptValues(prompt))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        "prompt must not contain \"none\" together with any other value."));
                }

                //JARM / FAPI 2.0 Message Signing §5.4 — a response_mode requesting a
                //JWT-secured authorization response is validated for servability at
                //receipt and the pushed value is carried verbatim, so it wins over any
                //front-channel duplicate by construction.
                (string? responseMode, ServerHttpResponse? responseModeFailure) =
                    ReadResponseMode(fields, server, context);
                if(responseModeFailure is not null)
                {
                    return (null, responseModeFailure);
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
                        return (null, detailsFailure);
                    }
                }

                //OID4VCI 1.0 §5.1.3 issuer_state and RFC 8707 resource (§5.1.2). The pushed value
                //is authoritative (RFC 9101 §6.3 via RFC 9126 §4); issuer_state is carried UNTRUSTED
                //and surfaced to the application's decision seam at the authorization endpoint.
                string? issuerState = ReadIssuerState(fields);
                string? resource = ReadResource(fields);
                ServerHttpResponse? resourceShapeFailure = ValidateResourceIndicatorsShape(resource);
                if(resourceShapeFailure is not null)
                {
                    return (null, resourceShapeFailure);
                }

                //Resolved once here and stamped onto ExpectedIssuer so a later redemption
                //(BuildInputAsync of BuildAuthCodeToken) can compare the issuer it resolves for
                //the PRESENTING request against the issuer resolved when the grant was issued —
                //OpenID Connect Core 1.0 §12.2 / RFC 9700 §4.4 mix-up defense.
                Uri issuerUri;
                try
                {
                    issuerUri = oauth.ResolveIssuerAsync is not null
                        ? (await oauth.ResolveIssuerAsync(registration, context, ct)
                            .ConfigureAwait(false))!
                        : await DefaultIssuerResolver.ResolveAsync(registration, context, ct)
                            .ConfigureAwait(false);
                }
                catch(InvalidOperationException ex)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, ex.Message));
                }

                DateTimeOffset now = server.TimeProvider.GetUtcNow();

                string flowId = context.FlowId!;
                string requestUriToken = await oauth.GenerateIdentifierAsync!(
                    WellKnownIdentifierPurposes.OAuthRequestUriToken, context, ct)
                    .ConfigureAwait(false);
                Uri requestUri = new($"urn:ietf:params:oauth:request_uri:{requestUriToken}");

                //RFC 9126 §2.2 leaves the request_uri lifetime implementation-defined.
                //Library policy lives in policy.RequestUriLifetime (default 60s).
                TimeSpan parLifetime = context.RequestUriLifetime;
                DateTimeOffset expiresAt = now + parLifetime;
                int expiresIn = (int)parLifetime.TotalSeconds;

                return (new ServerParValidated(
                    FlowId: flowId,
                    RequestUri: requestUri,
                    CodeChallenge: challenge,
                    CodeChallengeMethod: method!,
                    RedirectUri: redirectUri,
                    Scope: scope,
                    ClientId: clientId,
                    Nonce: nonce,
                    ExpectedIssuer: issuerUri.OriginalString,
                    ReceivedAt: now,
                    ExpiresAt: expiresAt,
                    ExpiresIn: expiresIn,
                    AcrValues: acrValues,
                    MaxAge: maxAge,
                    Prompt: prompt,
                    State: requestState,
                    AuthorizationDetails: authorizationDetails,
                    ResponseMode: responseMode,
                    IssuerState: issuerState,
                    Resource: resource), null);
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


    /// <summary>
    /// The <c>request_uri</c> completion endpoint's pre-correlation step: the outer
    /// <c>client_id</c>'s presence and its identification against the tenant's already-selected
    /// registration, run before the pushed request is ever looked up. Wired as
    /// <see cref="EndpointCandidate.BeforeCorrelationAsync"/> on <see cref="BuildAuthorize"/>.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1">RFC 6749 §4.1.1</see>, restated
    /// for the pushed request by <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.1">RFC
    /// 9126 §2.1</see>: <c>client_id</c> is REQUIRED on the authorization request that presents a
    /// <c>request_uri</c>, "as a required authorization request parameter". A missing field answers
    /// "Missing client_id."; a present field naming a registration other than the tenant's own
    /// answers <see cref="PushedRequestClientMismatchDescription"/> — the SAME constant the handler
    /// answers with when the field agrees with the registration but disagrees with the PUSHED
    /// request's own <c>client_id</c>, a comparison that needs the loaded record and stays there.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.2">RFC 9126 §2.2</see> binds the
    /// reference to the client that pushed it; <see href="https://www.rfc-editor.org/rfc/rfc9126#section-4">
    /// RFC 9126 §4</see> requires validation at authorization. Either mismatch makes the reference
    /// invalid for this client and answers <see cref="OAuthErrors.InvalidRequestUri"/>, defined by
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-7">RFC 9101 §7</see>.
    /// </remarks>
    private static ValueTask<ServerHttpResponse?> BeforeAuthorizeCompletionCorrelationAsync(
        ServerEndpoint endpoint, RequestFields fields, ExchangeContext context, CancellationToken cancellationToken)
    {
        if(!fields.TryGetValue(OAuthRequestParameterNames.ClientId, out string? outerClientId)
            || string.IsNullOrWhiteSpace(outerClientId))
        {

            return ValueTask.FromResult<ServerHttpResponse?>(ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidRequest, "Missing client_id."));
        }

        ClientRecord? requestUriRegistration = context.ClientRegistration;
        if(requestUriRegistration is null)
        {

            return ValueTask.FromResult<ServerHttpResponse?>(UnidentifiedClientDirectResponse());
        }

        if(!IsPresentedClientIdentifierTheRegistration(requestUriRegistration, outerClientId))
        {

            return ValueTask.FromResult<ServerHttpResponse?>(ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidRequestUri,
                PushedRequestClientMismatchDescription));
        }

        return ValueTask.FromResult<ServerHttpResponse?>(null);
    }


    /// <summary>Builds authorization of a pushed request using the admitted host seams.</summary>
    /// <remarks>
    /// Unknown mappings, missing records, and expired references use
    /// <see cref="EndpointCandidate.HandleNotFoundError"/> to answer
    /// <see cref="OAuthErrors.InvalidRequestUri"/> under
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-7">RFC 9101 §7</see>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-4">RFC 9126 §4</see> requires
    /// expired references to be rejected as invalid.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 §3.1</see> states:
    /// "Parameters sent without a value MUST be treated as if they were omitted from the request."
    /// Only a null or empty <c>request_uri</c> is omitted, answering <c>invalid_request</c> with a
    /// description naming <c>request_uri</c>. A whitespace-only value is a present invalid reference
    /// and must be preserved for resolution to answer <c>invalid_request_uri</c>.
    /// </remarks>
    private static EndpointCandidate BuildAuthorize() =>
        new()
        {
            Name = WellKnownEndpointNames.AuthCodeAuthorize,
            HttpMethod = WellKnownHttpMethods.Get,
            Capability = WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            StartsNewFlow = false,
            Kind = FlowKind.AuthCodeServer,
            DiscoveryMetadataKey = AuthorizationServerMetadataParameterNames.AuthorizationEndpoint,

            MissingCorrelationKeyErrorDescription = "Missing request_uri.",
            HandleNotFoundError = OAuthErrors.InvalidRequestUri,

            BeforeCorrelationAsync = BeforeAuthorizeCompletionCorrelationAsync,

            ExtractCorrelationKey = static (path, fields, context) =>
            {
                if(fields.TryGetValue(OAuthRequestParameterNames.RequestUri, out string? requestUri)
                    && !string.IsNullOrEmpty(requestUri))
                {
                    const string urnPrefix = "urn:ietf:params:oauth:request_uri:";
                    string correlationKey = requestUri.StartsWith(urnPrefix, StringComparison.Ordinal)
                        ? requestUri[urnPrefix.Length..]
                        : requestUri;

                    //A nonempty URN with no usable token is an invalid reference (RFC 9126
                    //§2.2 / RFC 9101 §7), not an omitted parameter. Preserve it for resolution
                    //so the host answers HandleNotFoundError rather than its missing-field error.

                    return string.IsNullOrWhiteSpace(correlationKey) ? requestUri : correlationKey;
                }

                return null;
            },

            MatchesRequest = static (fields, context, endpoint, ct) =>
            {
                //GET to /authorize with request_uri selects PAR completion. The direct PKCE
                //matcher requires request_uri to be absent, keeping the endpoints disjoint.
                IncomingRequest? req = context.IncomingRequest;
                if(req is null)
                {

                    return ValueTask.FromResult<MatchPayload?>(null);
                }

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
                EndpointServer server = context.RequestServer!;
                var oauth = server.OAuth();

                if(currentState is not ParRequestReceivedState)
                {
                    //RFC 9126 §2.2 / §4: the single-use reference must still identify a pending
                    //pushed request. Saved consumption or another state is invalid reference data
                    //and answers invalid_request_uri as defined by RFC 9101 §7.

                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequestUri, "Flow not in expected state."));
                }

                //RFC 6749 §3.1: the authorization server MUST first authenticate the resource
                //owner. An unestablished subject is not surfaced here as a server fault — the
                //shared EvaluateAuthenticationRequirementsAsync helper below answers the RFC 6749
                //§4.1.2.1 login_required redirect for it, uniformly across every code-issuing
                //authorize path.
                string? subjectId = context.SubjectId;

                ParRequestReceivedState parState = (ParRequestReceivedState)currentState;

                //RFC 6749 §4.1.1 / RFC 9126 §2.1: "client_id" is REQUIRED on the authorization
                //request that presents a request_uri. RFC 9126 §4 is the separate rule that the
                //authorization server MUST validate that request as it
                //would any other — identification against the tenant's ALREADY SELECTED
                //registration, AND agreement with the client the request_uri was pushed for
                //(RFC 9101 §6.3's outer/inner agreement, applied here to outer/pushed). The field's
                //presence and its identification against the registration already ran, in
                //BeforeAuthorizeCompletionCorrelationAsync, the endpoint's pre-correlation step;
                //this is the second, record-dependent comparison — agreement with the PUSHED
                //request's own client_id — which needs parState and so stays here. Both answer the
                //SAME body: invalid_request_uri (RFC 9101 §7) for the reference's client-binding
                //failure (RFC 9126 §2.2), with no redirect (RFC 6749 §4.1.2.1) and no consumption.
                _ = fields.TryGetValue(OAuthRequestParameterNames.ClientId, out string? outerClientId);
                if(!string.Equals(outerClientId, parState.ClientId, StringComparison.Ordinal))
                {

                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequestUri,
                        PushedRequestClientMismatchDescription));
                }

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
                    _ = (System.Diagnostics.Activity.Current?.AddEvent(
                        new System.Diagnostics.ActivityEvent(
                            OAuthEventNames.ExtraneousAuthorizeParameters)));
                }

                (string effectiveScope, ServerHttpResponse? requirementFailure) =
                    await EvaluateAuthenticationRequirementsAsync(
                    server, context, parState.AcrValues, parState.MaxAge, grantedScope,
                    subjectId, now, parState.RedirectUri, parState.State,
                    requestedAuthorizationDetails: parState.AuthorizationDetails,
                    responseMode: parState.ResponseMode,
                    clientId: parState.ClientId,
                    requestedIssuerState: parState.IssuerState,
                    requestedResource: parState.Resource,
                    //RFC 9101 §6.3 via RFC 9126 §4 — the pushed prompt is authoritative; a
                    //front-channel prompt on this request_uri completion is never read.
                    requestedPrompt: parState.Prompt,
                    cancellationToken: ct).ConfigureAwait(false);
                if(requirementFailure is not null)
                {

                    return (null, requirementFailure);
                }

                grantedScope = effectiveScope;

                //RFC 6749 §4.1.2 recommends a maximum of 10 minutes for authorization codes.
                //Library policy lives in policy.AuthorizationCodeLifetime (default 600s) — the
                //code's own lifetime, independent of parState.ExpiresAt (the request_uri's RFC
                //9126 §4 lifetime, which may be shorter and already close to elapsed by now).
                DateTimeOffset expiresAt = now + context.AuthorizationCodeLifetime;

                string rawCode = await oauth.GenerateIdentifierAsync!(
                    WellKnownIdentifierPurposes.OAuthAuthorizationCode, context, ct)
                    .ConfigureAwait(false);
                string codeHash = ComputeDigestBase64Url(
                    rawCode,
                    CryptoTags.Sha256Digest,
                    WellKnownHashAlgorithms.Sha256SizeBytes,
                    oauth.Codecs.ComputeDigest!,
                    oauth.Codecs.Encoder!,
                    oauth.MemoryPool!);

                //RFC 6749 §10.5: the raw code rides the redirect (and, for a JARM response, the
                //signed response JWT below); the PDA state carries only codeHash. BuildResponse's
                //non-JARM path reads this back off the context to build the redirect — the state
                //itself is never asked for anything but the hash.
                context.SetRawAuthorizationCode(rawCode);

                //JARM: the success response parameters are signed into the JWT Response
                //Document here, where the code exists; BuildResponse encodes it per the
                //carried response_mode.
                (string? jarmResponseJwt, ServerHttpResponse? jarmFailure) =
                    await TryIssueJarmResponseJwtAsync(
                        server, context, parState.ResponseMode, parState.ClientId,
                        BuildAuthorizeSuccessParameters(rawCode, parState.State), ct)
                        .ConfigureAwait(false);
                if(jarmFailure is not null)
                {

                    return (null, jarmFailure);
                }

                if(jarmResponseJwt is not null)
                {
                    context.SetJarmResponseJwt(jarmResponseJwt);
                }

                //RFC 9126 §4: "the client MUST only use a request_uri value once. Authorization
                //servers SHOULD treat request_uri values as one-time use but MAY allow for
                //duplicate requests due to a user reloading/refreshing their user agent." This
                //library elects the SHOULD unconditionally and does not offer the reload/refresh
                //MAY — the same exactly-once claim the token endpoint uses on its authorization
                //code applies here to the PAR-issued request_uri, since a concurrent second
                //authorize GET against this same request_uri would otherwise load the identical
                //ParRequestReceivedState and mint a second, orphaned code before this request's
                //SaveFlowStateAsync ever runs. The claim runs LAST — after the code is generated,
                //hashed, and any JARM response signed — the same reason the token endpoint claims
                //its code only once verification has fully succeeded: a server-side failure past
                //this point never consumes the request_uri, because nothing was actually issued to
                //the client.
                bool isRequestUriClaimed = await oauth.ClaimFlowStateAsync!(
                    context.TenantId!.Value, context.FlowId!, context.FlowStepCount ?? 0, context, ct)
                    .ConfigureAwait(false);
                if(!isRequestUriClaimed)
                {
                    //RFC 9126 §4 recommends one-time use and requires rejection of expired
                    //request_uri values as invalid. This server refuses every losing single-use
                    //claim with invalid_request_uri: RFC 9101 §7 defines it for a request_uri
                    //that returns an error or contains invalid data. RFC 6749 §4.1.2.1 determines
                    //the redirect shape: parState.RedirectUri and parState.State are already
                    //validated, so the error is carried on the client's redirect URI.

                    return (null, BuildAuthorizeErrorRedirect(
                        parState.RedirectUri,
                        OAuthErrors.InvalidRequestUri,
                        "The request_uri has already been used.",
                        parState.State,
                        context));
                }

                FlowInput input = new ServerAuthorizeCompleted(
                    CodeHash: codeHash,
                    //Non-null here: EvaluateAuthenticationRequirementsAsync above answers
                    //login_required and returns before this point whenever subjectId is null.
                    SubjectId: subjectId!,
                    AuthTime: authTime,
                    Scope: grantedScope,
                    CompletedAt: now,
                    ExpiresAt: expiresAt,
                    SessionId: context.SessionId,
                    Acr: context.Acr);

                return (input, null);
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


    /// <summary>
    /// Builds direct authorization using the admitted policy and registration snapshot.
    /// Client and redirect-URI validation precede PKCE-method refusal. A validated destination
    /// receives <c>invalid_request</c> with the request's state in an error redirect per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 §4.1.2.1</see>:
    /// "the authorization server informs the client by adding the following parameters to the
    /// query component of the redirection URI using the "application/x-www-form-urlencoded" format".
    /// An invalid client or redirect URI receives a direct refusal: "MUST NOT automatically
    /// redirect the user-agent to the invalid redirection URI".
    /// </summary>
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
                EndpointServer server = context.RequestServer!;
                var oauth = server.OAuth();

                if(!fields.TryGetValue(OAuthRequestParameterNames.ClientId, out string? clientId)
                    || string.IsNullOrWhiteSpace(clientId))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "Missing client_id."));
                }

                //RFC 6749 §4.1.2.1 / draft-ietf-oauth-v2-1-16 §4.1.2.1: "if the client identifier
                //is missing or invalid, the authorization server ... MUST NOT automatically
                //redirect the user agent to the invalid redirect URI" — identification
                //against the tenant's ALREADY SELECTED registration is a DIRECT refusal, never a
                //redirect, and comes before the redirect_uri is even trusted enough to build an
                //error redirect through. The dispatcher guarantees context.ClientRegistration is
                //non-null before this handler runs.
                ClientRecord directRegistration = context.ClientRegistration!;
                if(!IsPresentedClientIdentifierTheRegistration(directRegistration, clientId))
                {
                    return (null, UnidentifiedClientDirectResponse());
                }

                if(!fields.TryGetValue(OAuthRequestParameterNames.CodeChallenge, out string? challenge)
                    || string.IsNullOrWhiteSpace(challenge))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "Missing code_challenge."));
                }

                _ = fields.TryGetValue(OAuthRequestParameterNames.CodeChallengeMethod, out string? method);
                if(!fields.TryGetValue(OAuthRequestParameterNames.RedirectUri, out string? redirectUriString)
                    || !Uri.TryCreate(redirectUriString, UriKind.Absolute, out Uri? redirectUri))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "Missing or invalid redirect_uri."));
                }

                //RFC 9700 §2.1 + OAuth 2.1 §2.3.1 — redirect_uri exact-match against the
                //registered set, per RedirectUriMatching (simple string comparison, not
                //Uri equality), with the RFC 8252 §7.3 loopback fallback for a public
                //PKCE-S256 client. The pushed request applies the same gate to its own
                //redirect_uri; every redirect issued below this point (unsupported response_type,
                //invalid_target, authentication-requirement failures, and the final
                //success redirect) is only safe to emit once the destination is known
                //to be registered.
                if(!IsAcceptableRedirectUri(
                    directRegistration.AllowedRedirectUris, redirectUri, directRegistration.TokenEndpointAuthMethod, method, context))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        $"redirect_uri '{redirectUri}' is not among the registered redirect URIs."));
                }

                _ = fields.TryGetValue(OAuthRequestParameterNames.State, out string? requestState);
                if(!IsAcceptedPkceMethod(method))
                {
                    return (null, BuildAuthorizeErrorRedirect(
                        redirectUri, OAuthErrors.InvalidRequest,
                        "only the S256 code challenge method is supported", requestState, context));
                }

                //FAPI 2.0 §5.2.2 — when the profile mandates PAR, the direct Authorize
                //path is refused; the client must push the request first.
                if(context.RequirePushedAuthorizationRequests)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        "This authorization server requires Pushed Authorization Requests; a direct "
                        + "authorization request is not accepted (FAPI 2.0 §5.2.2)."));
                }

                //RFC 6749 §3.1: the authorization server MUST first authenticate the resource
                //owner. An unestablished subject is not surfaced here as a server fault — the
                //shared EvaluateAuthenticationRequirementsAsync helper below answers the RFC 6749
                //§4.1.2.1 login_required redirect for it, uniformly across every code-issuing
                //authorize path.
                string? subjectId = context.SubjectId;

                _ = fields.TryGetValue(OAuthRequestParameterNames.Scope, out string? scope);
                scope ??= string.Empty;

                _ = fields.TryGetValue(WellKnownJwtClaimNames.Nonce, out string? nonce);
                nonce ??= string.Empty;

                //RFC 9470 §4 step-up — the authentication-requirement parameters arrive
                //directly on the authorization request (RFC 9470 Figures 4 and 5). max_age
                //is a non-negative integer (OIDC Core §3.1.2.1); a malformed value is a
                //request error.
                _ = fields.TryGetValue(OAuthRequestParameterNames.AcrValues, out string? acrValues);
                (int? maxAge, bool isMaxAgeWellFormed) = ReadRequestedMaxAge(fields);
                if(!isMaxAgeWellFormed)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "max_age must be a non-negative integer."));
                }

                _ = fields.TryGetValue(OAuthRequestParameterNames.Prompt, out string? prompt);

                //JARM / FAPI 2.0 Message Signing §5.4 — same servability gate as the PAR
                //path; on the direct authorization request the parameter arrives on the
                //front channel itself.
                (string? responseMode, ServerHttpResponse? responseModeFailure) =
                    ReadResponseMode(fields, server, context);
                if(responseModeFailure is not null)
                {
                    return (null, responseModeFailure);
                }

                //OIDC Core §3.1.2.1: "If this parameter contains none with any other value, an
                //error is returned." redirect_uri is already registration-matched above, so this
                //is reported as an Authorization Error Response redirect (RFC 6749 §4.1.2.1).
                if(HasNoneWithOtherPromptValues(prompt))
                {
                    return (null, await BuildAuthorizeErrorResponseAsync(
                        server, context, redirectUri, OAuthErrors.InvalidRequest,
                        "prompt must not contain \"none\" together with any other value.",
                        requestState, responseMode, clientId, ct).ConfigureAwait(false));
                }

                //RFC 6749 §4.1.1 / OAuth 2.1 §4.1.1 — response_type is REQUIRED; an absent
                //value is a malformed request rather than an implicit request for the code
                //grant. redirect_uri is already parsed and registration-matched at this
                //point, so both the missing- and unsupported-value cases are reported as an
                //Authorization Error Response redirect per §4.1.2.1 rather than a bare 400.
                _ = fields.TryGetValue(OAuthRequestParameterNames.ResponseType, out string? responseType);
                if(string.IsNullOrEmpty(responseType))
                {
                    return (null, await BuildAuthorizeErrorResponseAsync(
                        server, context, redirectUri, OAuthErrors.InvalidRequest, "Missing response_type.",
                        requestState, responseMode, clientId, ct).ConfigureAwait(false));
                }

                if(IsUnsupportedResponseType(responseType))
                {
                    return (null, await BuildAuthorizeErrorResponseAsync(
                        server, context, redirectUri, UnsupportedResponseTypeError,
                        $"response_type '{responseType}' is not supported; this authorization "
                        + $"server issues '{WellKnownResponseTypes.Code}' only.",
                        requestState, responseMode, clientId, ct).ConfigureAwait(false));
                }

                //RFC 9396 / OID4VCI 1.0 §5.1.1 — same shape-validation as the PAR path; on the
                //direct authorization request the parameter arrives on the front channel itself.
                string? authorizationDetails = ReadAuthorizationDetails(fields);
                if(authorizationDetails is not null)
                {
                    //The matcher asserts context.ClientRegistration is non-null before this handler runs.
                    ClientRecord registration = context.ClientRegistration!;
                    ServerHttpResponse? detailsFailure = await ValidateAuthorizationDetailsShapeAsync(
                        server, authorizationDetails, registration, context, ct).ConfigureAwait(false);
                    if(detailsFailure is not null)
                    {
                        return (null, detailsFailure);
                    }
                }

                //OID4VCI 1.0 §5.1.3 issuer_state and RFC 8707 resource (§5.1.2) — on the direct
                //authorization request they arrive on the front channel itself. issuer_state is
                //surfaced UNTRUSTED to the decision seam, validated by neither the library nor read.
                string? issuerState = ReadIssuerState(fields);
                string? resource = ReadResource(fields);
                ServerHttpResponse? resourceShapeFailure = ValidateResourceIndicatorsShape(resource);
                if(resourceShapeFailure is not null)
                {
                    //redirect_uri is already parsed as absolute (the gate above), so — per RFC
                    //6749 §4.1.2.1 — a malformed resource is reported as an Authorization Error
                    //Response redirect carrying error=invalid_target, the same transport the
                    //application's own InvalidTarget denial uses, rather than a bare 400.
                    return (null, await BuildAuthorizeErrorResponseAsync(
                        server, context, redirectUri, OAuthErrors.InvalidTarget,
                        "The resource parameter must be an absolute URI (RFC 3986 §4.3) without a fragment.",
                        requestState, responseMode, clientId, ct).ConfigureAwait(false));
                }

                //Resolved once here and stamped onto ExpectedIssuer so a later redemption can
                //compare the issuer it resolves for the PRESENTING request against the issuer
                //resolved when the grant was issued — OpenID Connect Core 1.0 §12.2 / RFC 9700
                //§4.4 mix-up defense.
                Uri directIssuerUri;
                try
                {
                    directIssuerUri = oauth.ResolveIssuerAsync is not null
                        ? (await oauth.ResolveIssuerAsync(directRegistration, context, ct)
                            .ConfigureAwait(false))!
                        : await DefaultIssuerResolver.ResolveAsync(directRegistration, context, ct)
                            .ConfigureAwait(false);
                }
                catch(InvalidOperationException ex)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, ex.Message));
                }

                DateTimeOffset now = server.TimeProvider.GetUtcNow();
                DateTimeOffset authTime = context.AuthTime ?? now;

                (string effectiveScope, ServerHttpResponse? requirementFailure) =
                    await EvaluateAuthenticationRequirementsAsync(
                    server, context, acrValues, maxAge, scope, subjectId, now, redirectUri, requestState,
                    cancellationToken: ct,
                    requestedAuthorizationDetails: authorizationDetails,
                    responseMode: responseMode,
                    clientId: clientId,
                    requestedIssuerState: issuerState,
                    requestedResource: resource,
                    requestedPrompt: prompt)
                    .ConfigureAwait(false);
                if(requirementFailure is not null)
                {
                    return (null, requirementFailure);
                }
                scope = effectiveScope;

                string flowId = context.FlowId!;

                //RFC 6749 §4.1.2 recommends a maximum of 10 minutes for
                //authorization codes. Library policy lives in
                //policy.AuthorizationCodeLifetime (default 600s).
                DateTimeOffset expiresAt = now + context.AuthorizationCodeLifetime;

                string rawCode = await oauth.GenerateIdentifierAsync!(
                    WellKnownIdentifierPurposes.OAuthAuthorizationCode, context, ct)
                    .ConfigureAwait(false);
                string codeHash = ComputeDigestBase64Url(
                    rawCode,
                    CryptoTags.Sha256Digest,
                    WellKnownHashAlgorithms.Sha256SizeBytes,
                    oauth.Codecs.ComputeDigest!,
                    oauth.Codecs.Encoder!,
                    oauth.MemoryPool!);

                //RFC 6749 §10.5: the raw code rides the redirect; the PDA state carries only
                //codeHash. BuildResponse's non-JARM path reads this back off the context.
                context.SetRawAuthorizationCode(rawCode);

                //JARM: signed here, where the code exists; BuildResponse encodes per the
                //carried response_mode.
                (string? jarmResponseJwt, ServerHttpResponse? jarmFailure) =
                    await TryIssueJarmResponseJwtAsync(
                        server, context, responseMode, clientId,
                        BuildAuthorizeSuccessParameters(rawCode, requestState), ct)
                        .ConfigureAwait(false);
                if(jarmFailure is not null)
                {
                    return (null, jarmFailure);
                }

                if(jarmResponseJwt is not null)
                {
                    context.SetJarmResponseJwt(jarmResponseJwt);
                }

                return (new ServerDirectAuthorizeCompleted(
                    FlowId: flowId,
                    CodeHash: codeHash,
                    CodeChallenge: challenge,
                    CodeChallengeMethod: method!,
                    RedirectUri: redirectUri,
                    Scope: scope,
                    ClientId: clientId,
                    Nonce: nonce,
                    //Non-null here: EvaluateAuthenticationRequirementsAsync above answers
                    //login_required and returns before this point whenever subjectId is null.
                    SubjectId: subjectId!,
                    AuthTime: authTime,
                    ExpectedIssuer: directIssuerUri.OriginalString,
                    CompletedAt: now,
                    ExpiresAt: expiresAt,
                    SessionId: context.SessionId,
                    Acr: context.Acr,
                    State: requestState,
                    AuthorizationDetails: authorizationDetails,
                    ResponseMode: responseMode,
                    IssuerState: issuerState,
                    Resource: resource), null);
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
                ValueTask.FromResult<(FlowInput?, ServerHttpResponse?)>(
                    (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        "An authorization request MUST NOT contain both 'request' and 'request_uri' (RFC 9101 §5)."))),

            //Never reached — BuildInputAsync always returns the early-exit response.
            BuildResponse = static (_, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Unreachable."),
        };


    /// <summary>
    /// Picks the <see cref="CapabilityIdentifier"/> the token endpoint's grant_type
    /// refusal candidate (<see cref="BuildTokenGrantTypeRefusal"/>) advertises, from the
    /// first token-serving capability <paramref name="registration"/> is allowed, in a
    /// fixed precedence order.
    /// </summary>
    /// <param name="registration">The registration the token endpoint is building candidates for.</param>
    /// <returns>The first allowed capability among the token-serving capabilities, in precedence order.</returns>
    /// <remarks>
    /// The tag must be one <paramref name="registration"/> is actually allowed:
    /// <see cref="EndpointChain"/> filters every candidate in a chain by whether its
    /// <see cref="EndpointCandidate.Capability"/> is allowed, so a tag the registration
    /// is not allowed would make the refusal candidate itself unreachable. Called only
    /// when the builder already found at least one token-serving capability allowed, so
    /// the loop always returns before falling through.
    /// </remarks>
    private static CapabilityIdentifier SelectTokenEndpointCapability(ClientRecord registration)
    {
        CapabilityIdentifier[] tokenServingCapabilitiesInPrecedenceOrder =
        [
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthClientCredentials,
            WellKnownCapabilityIdentifiers.OAuthTokenExchange,
            WellKnownCapabilityIdentifiers.OAuthJwtBearer,
            WellKnownCapabilityIdentifiers.Oid4VciPreAuthorizedCodeGrant
        ];

        foreach(CapabilityIdentifier capability in tokenServingCapabilitiesInPrecedenceOrder)
        {
            if(registration.IsCapabilityAllowed(capability))
            {

                return capability;
            }
        }

        throw new InvalidOperationException(
            "SelectTokenEndpointCapability requires the registration to allow at least one token-serving capability.");
    }


    /// <summary>
    /// Builds the token endpoint's grant_type refusal per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 §5.2</see>.
    /// </summary>
    /// <param name="capability">
    /// A capability this registration is actually allowed, chosen by
    /// <see cref="SelectTokenEndpointCapability"/>, so this candidate survives
    /// <see cref="EndpointChain"/>'s own per-request capability filter alongside the grant
    /// candidates above.
    /// </param>
    /// <param name="serverServedGrantTypes">
    /// Every grant_type value this authorization server's own wiring serves, captured from
    /// the seam checks above, independent of any registration's allowed capabilities.
    /// </param>
    /// <param name="registeredGrantTypes">
    /// The grant_type values this registration and request actually materialized a
    /// candidate for above, captured from the same capability and seam checks — the
    /// live wiring for this request, not a fixed list.
    /// </param>
    /// <remarks>
    /// Added last among the token endpoint's candidates so every specific grant matcher
    /// gets first refusal. <see cref="EndpointChain"/> requires every candidate in a chain
    /// to be mutually disjoint (at most one match per request), so this matcher explicitly
    /// declines any <c>grant_type</c> already in <paramref name="registeredGrantTypes"/> —
    /// that value's own candidate owns every request naming it, matching or not, rather
    /// than letting this one double-match a request the owning candidate merely declined
    /// for some other reason (for example a missing correlation handle). It accepts only a
    /// missing/blank <c>grant_type</c> or one no candidate above claimed, then
    /// <see cref="EndpointCandidate.BuildInputAsync"/> classifies the refusal: missing/blank is
    /// <c>invalid_request</c> ("the request is missing a required parameter"); a value
    /// outside <paramref name="serverServedGrantTypes"/> is <c>unsupported_grant_type</c>
    /// ("the authorization grant type is not supported by the authorization server"); a
    /// server-served value this registration did not materialize a candidate for is
    /// <c>unauthorized_client</c> ("the authenticated client is not authorized to use this
    /// authorization grant type").
    /// </remarks>
    private static EndpointCandidate BuildTokenGrantTypeRefusal(
        CapabilityIdentifier capability,
        HashSet<string> serverServedGrantTypes,
        HashSet<string> registeredGrantTypes) =>
        new()
        {
            Name = WellKnownEndpointNames.AuthCodeToken,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = capability,
            StartsNewFlow = false,
            Kind = FlowKind.Stateless,
            //DiscoveryMetadataKey null — this guards the token endpoint URL BuildToken
            //already advertises; it is not an independently advertised endpoint.

            MatchesRequest = (fields, context, endpoint, ct) =>
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

                //Disjointness: a grant_type one of the candidates above already owns is that
                //candidate's request to accept or decline, never this one's to double-match.
                if(fields.TryGetValue(OAuthRequestParameterNames.GrantType, out string? ownedGrantType)
                    && !string.IsNullOrWhiteSpace(ownedGrantType)
                    && registeredGrantTypes.Contains(ownedGrantType))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
            },

            BuildInputAsync = (fields, context, currentState, ct) =>
            {
                if(!fields.TryGetValue(OAuthRequestParameterNames.GrantType, out string? grantType)
                    || string.IsNullOrWhiteSpace(grantType))
                {
                    return ValueTask.FromResult<(FlowInput?, ServerHttpResponse?)>(
                        (null, ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidRequest, "Missing grant_type.")));
                }

                //MatchesRequest already excluded every grantType in registeredGrantTypes, so
                //reaching here means either a value this server's wiring does not serve at all
                //(unsupported_grant_type) or one it serves that this registration is not
                //registered for (unauthorized_client).
                ServerHttpResponse response = !serverServedGrantTypes.Contains(grantType)
                    ? ServerHttpResponse.BadRequest(
                        OAuthErrors.UnsupportedGrantType,
                        $"grant_type '{grantType}' is not supported by this authorization server.")
                    : ServerHttpResponse.BadRequest(
                        OAuthErrors.UnauthorizedClient,
                        $"This client is not authorized to use the '{grantType}' grant type.");

                return ValueTask.FromResult<(FlowInput?, ServerHttpResponse?)>((null, response));
            },

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
                EndpointServer server = context.RequestServer!;
                var oauth = server.OAuth();

                (AuthCodeRequestObject? requestObject, ServerHttpResponse? earlyExit) =
                    await VerifyAndValidateAuthCodeJarAsync(
                        fields, context, server, requireDeclaredClientAuthentication: true, ct)
                        .ConfigureAwait(false);

                if(earlyExit is not null)
                {
                    return (null, earlyExit);
                }

                AuthCodeRequestObject ro = requestObject!;

                //RFC 6749 §4.1.1 — same response_type gate as the bare PAR path; the
                //JAR-PAR endpoint returns a JSON error directly, like PAR, rather than
                //a redirect (there is no front channel at this leg).
                if(IsUnsupportedResponseType(ro.ResponseType))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        UnsupportedResponseTypeError,
                        $"response_type '{ro.ResponseType}' is not supported; this authorization "
                        + $"server issues '{WellKnownResponseTypes.Code}' only."));
                }

                //RFC 8707 §2.1 — same resource shape gate as the bare PAR path; JAR-PAR answers
                //400 directly like every other malformed-request rejection at this leg (no front
                //channel to redirect through).
                ServerHttpResponse? resourceShapeFailure = ValidateResourceIndicatorsShape(ro.Resource);
                if(resourceShapeFailure is not null)
                {
                    return (null, resourceShapeFailure);
                }

                //OIDC Core §3.1.2.1 — same none-with-other-value gate as the bare PAR path;
                //JAR-PAR answers 400 directly like every other malformed-request rejection at
                //this leg (no front channel to redirect through).
                if(HasNoneWithOtherPromptValues(ro.Prompt))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        "prompt must not contain \"none\" together with any other value."));
                }

                //Resolved once here and stamped onto ExpectedIssuer so a later redemption can
                //compare the issuer it resolves for the PRESENTING request against the issuer
                //resolved when the grant was issued — OpenID Connect Core 1.0 §12.2 / RFC 9700
                //§4.4 mix-up defense, the same pattern the bare PAR path above uses.
                ClientRecord registration = context.ClientRegistration!;
                Uri issuerUri;
                try
                {
                    issuerUri = oauth.ResolveIssuerAsync is not null
                        ? (await oauth.ResolveIssuerAsync(registration, context, ct)
                            .ConfigureAwait(false))!
                        : await DefaultIssuerResolver.ResolveAsync(registration, context, ct)
                            .ConfigureAwait(false);
                }
                catch(InvalidOperationException ex)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, ex.Message));
                }

                DateTimeOffset now = server.TimeProvider.GetUtcNow();

                string flowId = context.FlowId!;
                string requestUriToken = await oauth.GenerateIdentifierAsync!(
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
                return (new ServerParValidated(
                    FlowId: flowId,
                    RequestUri: requestUri,
                    CodeChallenge: ro.CodeChallenge,
                    CodeChallengeMethod: ro.CodeChallengeMethod!,
                    RedirectUri: ro.RedirectUri,
                    Scope: ro.Scope,
                    ClientId: ro.ClientId,
                    Nonce: ro.Nonce,
                    ExpectedIssuer: issuerUri.OriginalString,
                    ReceivedAt: now,
                    ExpiresAt: expiresAt,
                    ExpiresIn: expiresIn,
                    AcrValues: ro.AcrValues,
                    MaxAge: ro.MaxAge,
                    Prompt: ro.Prompt,
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
                EndpointServer server = context.RequestServer!;
                var oauth = server.OAuth();

                (AuthCodeRequestObject? requestObject, ServerHttpResponse? earlyExit) =
                    await VerifyAndValidateAuthCodeJarAsync(
                        fields, context, server, requireDeclaredClientAuthentication: false, ct)
                        .ConfigureAwait(false);

                if(earlyExit is not null)
                {
                    return (null, earlyExit);
                }

                AuthCodeRequestObject ro = requestObject!;

                //RFC 6749 §4.1.1 / §4.1.2.1 — same response_type gate as the direct PKCE
                //path. ro.RedirectUri is already registration-validated inside
                //VerifyAndValidateAuthCodeJarAsync, so the error is safe to redirect.
                if(IsUnsupportedResponseType(ro.ResponseType))
                {
                    return (null, await BuildAuthorizeErrorResponseAsync(
                        server, context, ro.RedirectUri, UnsupportedResponseTypeError,
                        $"response_type '{ro.ResponseType}' is not supported; this authorization "
                        + $"server issues '{WellKnownResponseTypes.Code}' only.",
                        ro.State, ro.ResponseMode, ro.ClientId, ct).ConfigureAwait(false));
                }

                //RFC 8707 §2.1 / RFC 6749 §4.1.2.1 — same resource shape gate as the direct PKCE
                //path (BuildAuthorize): redirect_uri is already registration-validated above, so a
                //malformed resource is reported as an Authorization Error Response redirect
                //carrying error=invalid_target rather than a bare 400.
                ServerHttpResponse? resourceShapeFailure = ValidateResourceIndicatorsShape(ro.Resource);
                if(resourceShapeFailure is not null)
                {
                    return (null, await BuildAuthorizeErrorResponseAsync(
                        server, context, ro.RedirectUri, OAuthErrors.InvalidTarget,
                        "The resource parameter must be an absolute URI (RFC 3986 §4.3) without a fragment.",
                        ro.State, ro.ResponseMode, ro.ClientId, ct).ConfigureAwait(false));
                }

                //OIDC Core §3.1.2.1 — same none-with-other-value gate as the direct PKCE path:
                //ro.RedirectUri is already registration-validated, so the error is safe to
                //redirect (RFC 6749 §4.1.2.1).
                if(HasNoneWithOtherPromptValues(ro.Prompt))
                {
                    return (null, await BuildAuthorizeErrorResponseAsync(
                        server, context, ro.RedirectUri, OAuthErrors.InvalidRequest,
                        "prompt must not contain \"none\" together with any other value.",
                        ro.State, ro.ResponseMode, ro.ClientId, ct).ConfigureAwait(false));
                }

                //FAPI 2.0 §5.2.2 — when the profile mandates PAR, the JAR-by-value path
                //is refused; the client must push the request first.
                if(context.RequirePushedAuthorizationRequests)
                {
                    return (null,
                        ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidRequest,
                            "This authorization server requires Pushed Authorization Requests; a JAR-by-value "
                            + "authorization request is not accepted (FAPI 2.0 §5.2.2)."));
                }

                //RFC 6749 §3.1: the authorization server MUST first authenticate the resource
                //owner. An unestablished subject is not surfaced here as a server fault — the
                //shared EvaluateAuthenticationRequirementsAsync helper below answers the RFC 6749
                //§4.1.2.1 login_required redirect for it, uniformly across every code-issuing
                //authorize path.
                string? subjectId = context.SubjectId;

                //Resolved once here and stamped onto ExpectedIssuer so a later redemption can
                //compare the issuer it resolves for the PRESENTING request against the issuer
                //resolved when the grant was issued — OpenID Connect Core 1.0 §12.2 / RFC 9700
                //§4.4 mix-up defense.
                ClientRecord jarDirectRegistration = context.ClientRegistration!;
                Uri jarDirectIssuerUri;
                try
                {
                    jarDirectIssuerUri = oauth.ResolveIssuerAsync is not null
                        ? (await oauth.ResolveIssuerAsync(jarDirectRegistration, context, ct)
                            .ConfigureAwait(false))!
                        : await DefaultIssuerResolver.ResolveAsync(jarDirectRegistration, context, ct)
                            .ConfigureAwait(false);
                }
                catch(InvalidOperationException ex)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, ex.Message));
                }

                DateTimeOffset now = server.TimeProvider.GetUtcNow();
                DateTimeOffset authTime = context.AuthTime ?? now;

                (string effectiveScope, ServerHttpResponse? requirementFailure) =
                    await EvaluateAuthenticationRequirementsAsync(
                    server, context, ro.AcrValues, ro.MaxAge, ro.Scope, subjectId, now,
                    ro.RedirectUri, ro.State,
                    cancellationToken: ct,
                    requestedAuthorizationDetails: ro.AuthorizationDetails,
                    responseMode: ro.ResponseMode,
                    clientId: ro.ClientId,
                    requestedIssuerState: ro.IssuerState,
                    requestedResource: ro.Resource,
                    requestedPrompt: ro.Prompt).ConfigureAwait(false);
                if(requirementFailure is not null)
                {
                    return (null, requirementFailure);
                }

                string flowId = context.FlowId!;

                //RFC 6749 §4.1.2 recommends a maximum of 10 minutes for
                //authorization codes. Library policy lives in
                //policy.AuthorizationCodeLifetime (default 600s).
                DateTimeOffset expiresAt = now + context.AuthorizationCodeLifetime;

                string rawCode = await oauth.GenerateIdentifierAsync!(
                    WellKnownIdentifierPurposes.OAuthAuthorizationCode, context, ct)
                    .ConfigureAwait(false);
                string codeHash = ComputeDigestBase64Url(
                    rawCode,
                    CryptoTags.Sha256Digest,
                    WellKnownHashAlgorithms.Sha256SizeBytes,
                    oauth.Codecs.ComputeDigest!,
                    oauth.Codecs.Encoder!,
                    oauth.MemoryPool!);

                //RFC 6749 §10.5: the raw code rides the redirect; the PDA state carries only
                //codeHash. BuildResponse's non-JARM path reads this back off the context.
                context.SetRawAuthorizationCode(rawCode);

                //JARM: signed here, where the code exists; BuildResponse encodes per the
                //carried response_mode.
                (string? jarmResponseJwt, ServerHttpResponse? jarmFailure) =
                    await TryIssueJarmResponseJwtAsync(
                        server, context, ro.ResponseMode, ro.ClientId,
                        BuildAuthorizeSuccessParameters(rawCode, ro.State), ct)
                        .ConfigureAwait(false);
                if(jarmFailure is not null)
                {
                    return (null, jarmFailure);
                }

                if(jarmResponseJwt is not null)
                {
                    context.SetJarmResponseJwt(jarmResponseJwt);
                }

                return (new ServerDirectAuthorizeCompleted(
                    FlowId: flowId,
                    CodeHash: codeHash,
                    CodeChallenge: ro.CodeChallenge,
                    CodeChallengeMethod: ro.CodeChallengeMethod!,
                    RedirectUri: ro.RedirectUri,
                    Scope: effectiveScope,
                    ClientId: ro.ClientId,
                    Nonce: ro.Nonce,
                    //Non-null here: EvaluateAuthenticationRequirementsAsync above answers
                    //login_required and returns before this point whenever subjectId is null.
                    SubjectId: subjectId!,
                    AuthTime: authTime,
                    ExpectedIssuer: jarDirectIssuerUri.OriginalString,
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
    /// <see cref="Verifiable.Server.ServerIntegration.ResolveIssuerAsync"/>. The
    /// EUDI/Microsoft <c>aud == client_id</c> reading is rejected; tenant-divergent
    /// audience policy is a planned future extension point and is not in scope here.
    /// </para>
    /// <para>
    /// <paramref name="requireDeclaredClientAuthentication"/> is <see langword="true"/> for
    /// JAR-PAR: <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2">RFC 9126 §2</see>
    /// applies the token endpoint's client-authentication rules to every pushed request, JAR-carrying
    /// or not, and a valid signed request object is not the separately declared client credential.
    /// It is <see langword="false"/> for JAR-by-value direct Authorize, which never authenticates a
    /// declared method — only PAR does. The check runs immediately after identification, before the
    /// JAR's signature is verified, before its replay identifier is consulted, and before any handle
    /// is generated.
    /// </para>
    /// </remarks>
    private static async ValueTask<(AuthCodeRequestObject? RequestObject, ServerHttpResponse? EarlyExit)>
        VerifyAndValidateAuthCodeJarAsync(
            RequestFields fields,
            ExchangeContext context,
            EndpointServer server,
            bool requireDeclaredClientAuthentication,
            CancellationToken cancellationToken)
    {
        var oauth = server.OAuth();
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

        ClientRecord? registration = context.ClientRegistration;
        if(registration is null)
        {
            return (null, ClientAuthenticationFailureResponse(context.IncomingRequest, "Unknown client."));
        }

        //RFC 9101 §6.3: the outer client_id and the request object's must agree; the comparison
        //is identification, the one IsPresentedClientIdentifierTheRegistration applies
        //everywhere else.
        if(!IsPresentedClientIdentifierTheRegistration(registration, outerClientId))
        {
            return (null, ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidRequest, "Outer client_id does not match the registered client."));
        }

        if(requireDeclaredClientAuthentication)
        {
            ServerHttpResponse? jarParAuthenticationFailure = await RequireClientAuthenticationIfDeclaredAsync(
                oauth, context.IncomingRequest, fields, registration, context, cancellationToken)
                .ConfigureAwait(false);
            if(jarParAuthenticationFailure is not null)
            {
                return (null, jarParAuthenticationFailure);
            }
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

        ServerVerificationKeyResolverDelegate? resolver = oauth.Cryptography.VerificationKeyResolver;
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

        JwtHeaderDeserializer? headerDeserializer = oauth.Codecs.JwtHeaderDeserializer;
        JwtPayloadDeserializer? payloadDeserializer = oauth.Codecs.JwtPayloadDeserializer;
        DecodeDelegate? decoder = oauth.Codecs.Decoder;

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
            oauth.MemoryPool,
            cancellationToken).ConfigureAwait(false);

        if(verification is JarRejected rejected)
        {
            return (null, ServerHttpResponse.BadRequest(rejected.ErrorCode, rejected.Reason));
        }

        JarVerified verified = (JarVerified)verification;

        //RFC 7636 §4.4.1 assigns invalid_request to an unsupported transformation.
        //RFC 9101 §6.3 routes verified request-parameter errors to RFC 6749 §5.2.
        if(!IsAcceptedPkceMethod(JwtClaimReaders.OptionalClaim(
            verified.Claims, OAuthRequestParameterNames.CodeChallengeMethod)))
        {
            return (null, ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidRequest,
                "only the S256 code challenge method is supported"));
        }


        //RFC 9396 §3: inside a Request Object, authorization_details is a native JSON
        //array. The verbatim array text is re-sliced from the now-verified payload so the
        //carried value is exactly what the client signed — a reserialisation of the parsed
        //claims could diverge from the signed bytes.
        string? jarAuthorizationDetails;
        {
            string[] jarParts = compactJar.Split('.');
            using IMemoryOwner<byte> payloadBytes = decoder(jarParts[1], oauth.MemoryPool);
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

        //OpenID Federation 1.0 §12.1.1.1 — a Request Object MUST NOT carry a sub
        //claim. A request object whose sub equalled its iss/client_id would be
        //shaped exactly like a private_key_jwt client assertion (OIDC Core §9),
        //so accepting one would let a captured Request Object be replayed as
        //client authentication. There is no authorization-request parameter
        //named sub (RFC 9101 §4, OIDC Core §6.1), so its presence is always a
        //defect — the check is applied to every JAR, not only the federation
        //automatic-registration path, because the reuse vector is general.
        if(verified.Claims.ContainsKey(WellKnownJwtClaimNames.Sub))
        {
            return (null, ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidRequestObject,
                "JAR must not carry a sub claim per OpenID Federation 1.0 §12.1.1.1."));
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

        //RFC 9700 §4.1 — redirect_uri exact-match against the registered set, per
        //RedirectUriMatching (simple string comparison, not Uri equality), with the
        //RFC 8252 §7.3 loopback fallback for a public PKCE-S256 client.
        if(!IsAcceptableRedirectUri(
            registration.AllowedRedirectUris, requestObject.RedirectUri, registration.TokenEndpointAuthMethod,
            requestObject.CodeChallengeMethod, context))
        {
            return (null, ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidRequestObject,
                $"redirect_uri '{requestObject.RedirectUri}' is not among the registered redirect URIs."));
        }

        //Scope-required-on-request is a policy axis. Aligns the
        //JAR-bearing matcher with the PKCE PAR matcher — either both require
        //scope (the strict default) or both treat it as optional.
        if(context.ScopeRequiredOnRequest && string.IsNullOrEmpty(requestObject.Scope))
        {
            return (null, ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidRequestObject,
                "scope is required under the active policy."));
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

        //RFC 8707 §2.1's resource shape gate is NOT run here: unlike every other shape check in
        //this shared pipeline, its failure transport differs by caller — JAR-PAR (no front
        //channel) answers 400 directly, JAR-by-value redirects per RFC 6749 §4.1.2.1. The
        //response_type gate is left to each caller for the identical reason (see BuildJarPar and
        //BuildAuthorizeJarByValue). Both callers run <see cref="ValidateResourceIndicatorsShape"/>
        //against <see cref="AuthCodeRequestObject.Resource"/> themselves, immediately after this
        //method returns.

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
                requestObject.Iss, requestObject.Jti,
                requestObject.Exp + context.ClockSkewTolerance,
                cancellationToken).ConfigureAwait(false);

            ServerHttpResponse? jtiFailure = jtiOutcome switch
            {
                JtiReplayOutcome.FirstUse => null,
                JtiReplayOutcome.Replayed => ServerHttpResponse.BadRequest(
                    OAuthErrors.InvalidRequestObject,
                    "The JAR jti has already been presented within its validity window."),
                JtiReplayOutcome.Unacceptable => ServerHttpResponse.BadRequest(
                    OAuthErrors.InvalidRequestObject,
                    "The JAR jti exceeds the length the replay guard can track."),
                JtiReplayOutcome.StoreUnavailable => ServerHttpResponse.ServerError(
                    OAuthErrors.ServerError,
                    "JAR jti replay defense is required by policy but no jti store is configured."),

                _ => null
            };
            if(jtiFailure is not null)
            {
                return (null, jtiFailure);
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
        EndpointServer server,
        CancellationToken cancellationToken)
    {
        var oauth = server.OAuth();
        if(!claims.ContainsKey(WellKnownJwtClaimNames.Aud))
        {
            return ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidRequestObject,
                "JAR aud claim is required per RFC 9101 §10.2.");
        }

        Uri issuerUri;
        try
        {
            issuerUri = oauth.ResolveIssuerAsync is not null
                ? (await oauth.ResolveIssuerAsync(registration, context, cancellationToken)
                    .ConfigureAwait(false))!
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
    /// <see cref="AuthorizationServerIntegration.TokenProducers"/> is empty. Single producer
    /// matches the library's historical access-token-only response shape.
    /// </summary>
    private static IReadOnlyList<TokenProducer> DefaultTokenProducers { get; } =
        [TokenProducer.Rfc9068AccessToken];


    /// <summary>
    /// Pre-resolves the OIDC claim set for the current issuance once per token
    /// request, before the producer loop. The resolved value flows through every
    /// <see cref="IdTokenTarget"/> and <see cref="UserInfoTarget"/> the
    /// contributor walk constructs in this request, so per-rule contributors
    /// don't each re-issue the resolver call. Gated on <c>openid</c> being in
    /// <see cref="IssuanceContext.Scope"/>: the app's OIDC-claims resolver carries
    /// end-user identity data, so it must not run for a request that never asked
    /// for identity, per the data-minimization principle in
    /// <see cref="WellKnownScopes"/>.
    /// </summary>
    private static async ValueTask<OidcClaims?> PreResolveOidcClaimsAsync(
        EndpointServer server,
        IssuanceContext issuance,
        CancellationToken cancellationToken)
    {
        if(!WellKnownScopes.ContainsOpenId(issuance.Scope))
        {
            return null;
        }

        var oauth = server.OAuth();
        ResolveOidcClaimsDelegate? resolve = oauth.ResolveOidcClaimsAsync;
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
    /// Runs the configured <see cref="AuthorizationServerIntegration.ClaimIssuer"/>
    /// against <paramref name="target"/> and merges every
    /// <see cref="ClaimOutcome.Success"/> contribution into
    /// <paramref name="payload"/> via the indexer. No-op when the
    /// configuration has no issuer wired.
    /// </summary>
    private static async ValueTask MergeContributedClaimsAsync(
        EndpointServer server,
        ClaimContributionTarget? target,
        JwtPayload payload,
        CancellationToken cancellationToken)
    {
        var oauth = server.OAuth();
        if(target is null || oauth.ClaimIssuer is not { } issuer)
        {
            return;
        }

        string correlationId = await oauth.GenerateIdentifierAsync!(
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
    /// The result of a successful <see cref="IssueTokensAsync"/> walk: every token minted for
    /// the request, keyed by <see cref="TokenProducer.ResponseField"/>, alongside the matching
    /// per-token audit record and the latest <c>exp</c> across all issued tokens.
    /// </summary>
    private sealed record TokenIssuanceResult
    {
        /// <summary>The compact JWS of each issued token, keyed by response field name.</summary>
        public required Dictionary<string, string> IssuedTokens { get; init; }

        /// <summary>The <see cref="IssuedTokenAudit"/> of each issued token, keyed by response field name.</summary>
        public required Dictionary<string, IssuedTokenAudit> IssuedAudits { get; init; }

        /// <summary>The latest <c>exp</c> among every token issued in this walk.</summary>
        public required DateTimeOffset LatestExpiry { get; init; }
    }


    /// <summary>
    /// Walks <paramref name="producers"/> and mints every applicable token for
    /// <paramref name="issuance"/>: the per-producer optional-capability feature gate and
    /// <see cref="TokenProducer.IsApplicable"/> filter, key resolution
    /// (<see cref="SigningKeySelection.ResolveSigningKeyIdAsync"/> +
    /// <see cref="AuthorizationServerCryptography.SigningKeyResolver"/>), algorithm derivation,
    /// <see cref="TokenProducer.BuildAsync"/>, the claim-contributor merge
    /// (<see cref="BuildTargetForProducer"/> + <see cref="MergeContributedClaimsAsync"/>),
    /// <see cref="JwtSigningExtensions.SignAsync(UnsignedJwt, PrivateKeyMemory, JwtHeaderSerializer, JwtPayloadSerializer, EncodeDelegate, BaseMemoryPool, CancellationToken)"/>, and compact serialization. Shared by all six grants
    /// that mint tokens through the producer set — the walk is identical across grants; only
    /// the <see cref="IssuanceContext"/> construction before it and the response shaping after
    /// it are grant-specific.
    /// </summary>
    /// <returns>
    /// The <see cref="TokenIssuanceResult"/> on success; a <see cref="ServerHttpResponse"/>
    /// <c>server_error</c> failure when a producer's signing key could not be resolved.
    /// </returns>
    private static async ValueTask<(TokenIssuanceResult? Result, ServerHttpResponse? Failure)> IssueTokensAsync(
        EndpointServer server,
        ClientRecord registration,
        ExchangeContext context,
        IssuanceContext issuance,
        IReadOnlyList<TokenProducer> producers,
        OidcClaims? preResolvedOidcClaims,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var oauth = server.OAuth();

        Dictionary<string, string> issuedTokens = new(producers.Count);
        Dictionary<string, IssuedTokenAudit> issuedAudits = new(producers.Count);
        DateTimeOffset latestExpiry = now;

        foreach(TokenProducer producer in producers)
        {
            //RequiredCapability is an optional coarse tenant-feature gate (null = every tenant
            //may run this producer); when set, the resolver's per-request ResolvedCapabilities
            //output must allow it — CAEP/RISC attenuation between issuance steps applies here,
            //not just the registration's static AllowedCapabilities. IsApplicable is the
            //producer's own grant/scope-aware decision (for example the ID Token producer's
            //openid + end-user-authenticating-grant check). Together these replace the single
            //endpoint-level capability match, which only gated the grant itself.
            IReadOnlySet<CapabilityIdentifier>? resolved = context.ResolvedCapabilities;
            if(producer.RequiredCapability is { } requiredCapability
                && (resolved is null || !resolved.Contains(requiredCapability)))
            {
                continue;
            }

            if(!await producer.IsApplicable(issuance, cancellationToken).ConfigureAwait(false))
            {
                continue;
            }

            KeyId signingKeyId = await SigningKeySelection.ResolveSigningKeyIdAsync(
                server, registration, producer.KeyUsage, context, cancellationToken)
                .ConfigureAwait(false);

            PrivateKeyMemory? signingKey = await oauth.Cryptography.SigningKeyResolver!(
                signingKeyId, registration.TenantId, context, cancellationToken).ConfigureAwait(false);

            if(signingKey is null)
            {
                return (null, ServerHttpResponse.ServerError(
                    OAuthErrors.ServerError,
                    $"Signing key unavailable for producer '{producer.Name}'."));
            }

            string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(signingKey.Tag);

            TokenProducerOutput output = await producer.BuildAsync(
                issuance, signingKeyId, algorithm, cancellationToken).ConfigureAwait(false);

            JwtPayload payload = output.Payload;

            ClaimContributionTarget? contributionTarget =
                BuildTargetForProducer(producer, issuance, preResolvedOidcClaims);
            await MergeContributedClaimsAsync(
                server, contributionTarget, payload, cancellationToken).ConfigureAwait(false);

            UnsignedJwt unsigned = new(output.Header, payload);

            using JwsMessage jws = await unsigned.SignAsync(
                signingKey,
                oauth.Codecs.JwtHeaderSerializer!,
                oauth.Codecs.JwtPayloadSerializer!,
                oauth.Codecs.Encoder!,
                oauth.MemoryPool!,
                cancellationToken).ConfigureAwait(false);

            string compactJws = JwsSerialization.SerializeCompact(jws, oauth.Codecs.Encoder!);

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

        //Every grant calls this one function to issue its tokens, so tagging the dispatch span
        //here — from the already-typed IssuanceContext and the audits just recorded — carries
        //grant type, client id, granted scope and the issued access token's jti for every grant
        //alike, with no new parsing and no widened signature.
        System.Diagnostics.Activity? activity = System.Diagnostics.Activity.Current;
        if(activity is not null)
        {
            _ = activity.SetTag(OAuthTagNames.GrantType, issuance.GrantType);
            _ = activity.SetTag(OAuthTagNames.ClientId, issuance.ClientId);
            _ = activity.SetTag(OAuthTagNames.GrantedScope, issuance.Scope);

            if(issuedAudits.TryGetValue(WellKnownTokenTypes.AccessToken, out IssuedTokenAudit? accessTokenAudit))
            {
                _ = activity.SetTag(OAuthTagNames.AccessTokenJti, accessTokenAudit.Jti);
            }
        }

        return (new TokenIssuanceResult
        {
            IssuedTokens = issuedTokens,
            IssuedAudits = issuedAudits,
            LatestExpiry = latestExpiry
        }, null);
    }


    /// <summary>
    /// RFC 6749 §3.3 scope narrowing for the library's non-end-user grants —
    /// <c>client_credentials</c> (subject is the client itself) and <c>pre_authorized_code</c>
    /// (no established End-User session). Drops <c>openid</c> and the OIDC Core §5.4 identity
    /// scopes (<c>profile</c> / <c>email</c> / <c>address</c> / <c>phone</c>) from
    /// <paramref name="grantedScope"/> so the source enforces the <c>openid</c> ⇒
    /// authenticated-end-user invariant; <see cref="Oidc10IdTokenProducer"/> and
    /// <see cref="Oidc.UserInfoEndpoints"/> are the two independent consumer-side layers of the
    /// same invariant. <c>token_exchange</c> and <c>jwt_bearer</c> do not call this — their
    /// authorization seams (<see cref="AuthorizationServerIntegration.AuthorizeTokenExchangeAsync"/>,
    /// <see cref="AuthorizationServerIntegration.ValidateJwtBearerAssertionAsync"/>) own whether
    /// the subject is an End-User, and the app opts in by granting <c>openid</c> itself.
    /// </summary>
    /// <returns>
    /// <paramref name="grantedScope"/> unchanged when it carries none of the dropped scopes;
    /// otherwise the narrowed scope string with those tokens removed. Emits
    /// <see cref="OAuthEventNames.IdentityScopesDroppedForNonEndUserGrant"/> naming the dropped
    /// scopes when narrowing occurred.
    /// </returns>
    private static string DropIdentityScopesForNonEndUserGrant(string grantedScope)
    {
        if(string.IsNullOrEmpty(grantedScope))
        {
            return grantedScope;
        }

        string[] tokens = grantedScope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        List<string> retained = new(tokens.Length);
        List<string>? dropped = null;

        foreach(string token in tokens)
        {
            bool isIdentityScope = WellKnownScopes.IsOpenId(token)
                || WellKnownScopes.IsProfile(token)
                || WellKnownScopes.IsEmail(token)
                || WellKnownScopes.IsAddress(token)
                || WellKnownScopes.IsPhone(token);

            if(isIdentityScope)
            {
                (dropped ??= []).Add(token);
                continue;
            }

            retained.Add(token);
        }

        if(dropped is null)
        {
            return grantedScope;
        }

        _ = (System.Diagnostics.Activity.Current?.AddEvent(
            new System.Diagnostics.ActivityEvent(
                OAuthEventNames.IdentityScopesDroppedForNonEndUserGrant,
                tags: new System.Diagnostics.ActivityTagsCollection
                {
                    [OAuthEventNames.DroppedScopesTagName] = string.Join(' ', dropped)
                })));

        return string.Join(' ', retained);
    }


    /// <summary>
    /// The code-redemption endpoint's pre-correlation step: identification, issuer resolution,
    /// PKCE presentation shape, declared client authentication, the <c>client_id</c>-required
    /// rule, the <c>resource</c> and <c>authorization_details</c> request-only shapes, and DPoP —
    /// run, in that order, before the presented <c>code</c> is ever looked up. Wired as
    /// <see cref="EndpointCandidate.BeforeCorrelationAsync"/> on <see cref="BuildToken"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every check here reads only <paramref name="fields"/>, <paramref name="endpoint"/>,
    /// <paramref name="context"/>'s registration, and the server — never the stored GRANT record,
    /// since none is loaded yet. The authentication stores (a client assertion's <c>jti</c>, a
    /// DPoP proof's <c>jti</c>, a nonce) ARE reached, through the same
    /// <c>LoadFlowStateAsync</c>/<c>SaveFlowStateAsync</c> delegates the grant store uses, as
    /// <see cref="BeforeCorrelationDelegate"/>'s remarks describe. Identification, the
    /// <c>code_verifier</c>'s absence, and a resolver fault or decline each answer
    /// <paramref name="endpoint"/>'s own
    /// <see cref="ServerEndpoint.HandleNotFoundError"/> / <see cref="ServerEndpoint.HandleNotFoundErrorDescription"/>
    /// (falling back to <see cref="CodeGrantNotFoundDescription"/> when the endpoint sets
    /// neither) — identical for a <c>code</c> that does not correlate to any flow, so a caller
    /// with no credentials cannot distinguish the two. A grammatically malformed
    /// <c>code_verifier</c> answers its own <c>invalid_grant</c> "PKCE verification failed.",
    /// distinct from that constant, since the grammar itself — never the endpoint's identity —
    /// decides it. Declared client authentication runs here, in the step, and answers its own
    /// <c>401 invalid_client</c> untranslated; <see cref="VerifyCodeGrantPresentation"/> performs
    /// no authentication of its own.
    /// </para>
    /// <para>
    /// The issuer is resolved and carried (<c>SetCorrelationStepIssuer</c>) BEFORE declared
    /// authentication and the <c>authorization_details</c> decision, both of which read the
    /// carried value instead of resolving a second time for the same request —
    /// <see cref="PrivateKeyJwtClientAuthentication"/>'s assertion validator reads it via
    /// <c>context.CorrelationStepIssuer</c>, and
    /// <see cref="ValidateAndCarryTokenRequestAuthorizationDetailsAsync"/> takes it as a
    /// parameter, never resolving on its own. <see cref="BuildToken"/> and
    /// <see cref="HandleAuthorizationCodeReplayAsync"/> read the same carried issuer once the code
    /// state is loaded.
    /// </para>
    /// <para>
    /// The request-only half of DPoP validation runs last, through
    /// <see cref="DpopTokenEndpointValidation.ValidatePresentedProofAsync"/>: a proof is
    /// validated, or its absence answered, entirely from the request and the registration's
    /// profile, exactly once. <see cref="BuildToken"/>'s <c>BuildInputAsync</c> reads the carried
    /// outcome through <see cref="DpopTokenEndpointValidation.BindValidatedProofAsync"/> once the
    /// code state is loaded; it never re-runs proof or nonce validation.
    /// </para>
    /// </remarks>
    private static async ValueTask<ServerHttpResponse?> BeforeCodeRedemptionCorrelationAsync(
        ServerEndpoint endpoint, RequestFields fields, ExchangeContext context, CancellationToken cancellationToken)
    {
        //The dispatcher runs this step, for a continuing-flow endpoint, only after its own
        //handle-presence refusal ("Missing code.") has already found a `code` field present —
        //see BeforeCorrelationDelegate's remarks — so this step never needs its own presence
        //guard for the correlation key itself.
        EndpointServer server = context.RequestServer!;
        var oauth = server.OAuth();

        ClientRecord? registration = context.ClientRegistration;
        if(registration is null)
        {
            return ClientAuthenticationFailureResponse(context.IncomingRequest, "Unknown client.");
        }

        if(RefuseUnidentifiedClient(registration, fields, context.IncomingRequest) is not null)
        {
            return ServerHttpResponse.BadRequest(
                endpoint.HandleNotFoundError ?? OAuthErrors.InvalidGrant,
                endpoint.HandleNotFoundErrorDescription ?? CodeGrantNotFoundDescription);
        }

        //Resolved and carried BEFORE declared authentication and the authorization_details
        //decision below, both of which read it (PrivateKeyJwtClientAuthentication's assertion
        //validator; ValidateAndCarryTokenRequestAuthorizationDetailsAsync) — never resolving a
        //second time for the same request. BuildToken and HandleAuthorizationCodeReplayAsync read
        //the same carried value once the code state is loaded.
        Uri? resolvedIssuerUri;
        try
        {
            resolvedIssuerUri = oauth.ResolveIssuerAsync is not null
                ? await oauth.ResolveIssuerAsync(registration, context, cancellationToken).ConfigureAwait(false)
                : await DefaultIssuerResolver.ResolveAsync(registration, context, cancellationToken).ConfigureAwait(false);
        }
        catch(InvalidOperationException)
        {
            //Folded onto the endpoint's own constant, exactly as an unknown code is answered — a
            //caller with no credentials must not learn whether a resolver fault or a nonexistent
            //code produced this response, and this step runs identically for both.
            return ServerHttpResponse.BadRequest(
                endpoint.HandleNotFoundError ?? OAuthErrors.InvalidGrant,
                endpoint.HandleNotFoundErrorDescription ?? CodeGrantNotFoundDescription);
        }

        if(resolvedIssuerUri is not Uri issuerUri)
        {
            //ResolveServerIssuerDelegate explicitly permits a null result (a declined
            //resolution); folded onto the same constant for the same reason.
            return ServerHttpResponse.BadRequest(
                endpoint.HandleNotFoundError ?? OAuthErrors.InvalidGrant,
                endpoint.HandleNotFoundErrorDescription ?? CodeGrantNotFoundDescription);
        }

        context.SetCorrelationStepIssuer(issuerUri);

        if(!fields.TryGetValue(OAuthRequestParameterNames.CodeVerifier, out string? verifier)
            || string.IsNullOrWhiteSpace(verifier))
        {
            return ServerHttpResponse.BadRequest(
                endpoint.HandleNotFoundError ?? OAuthErrors.InvalidGrant,
                endpoint.HandleNotFoundErrorDescription ?? CodeGrantNotFoundDescription);
        }

        if(!IsValidCodeVerifierGrammar(verifier))
        {
            return ServerHttpResponse.BadRequest(OAuthErrors.InvalidGrant, "PKCE verification failed.");
        }

        ServerHttpResponse? clientAuthFailure = await RequireClientAuthenticationIfDeclaredAsync(
            oauth, context.IncomingRequest, fields, registration, context, cancellationToken).ConfigureAwait(false);
        if(clientAuthFailure is not null)
        {
            return clientAuthFailure;
        }

        bool hasFieldClientId = fields.TryGetValue(OAuthRequestParameterNames.ClientId, out string? fieldClientId)
            && !string.IsNullOrEmpty(fieldClientId);
        if(!hasFieldClientId && !HasClientCredentials(context.IncomingRequest, fields))
        {
            return ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidRequest, "client_id is required for a client that is not authenticating.");
        }

        ServerHttpResponse? resourceShapeFailure = ValidateRequestOnlyResourceShape(fields);
        if(resourceShapeFailure is not null)
        {
            return resourceShapeFailure;
        }

        string? tokenRequestAuthorizationDetails = ReadAuthorizationDetails(fields);
        if(tokenRequestAuthorizationDetails is not null)
        {
            ServerHttpResponse? detailsShapeFailure = await ValidateAndCarryTokenRequestAuthorizationDetailsAsync(
                server, tokenRequestAuthorizationDetails, registration, context, issuerUri, cancellationToken)
                .ConfigureAwait(false);
            if(detailsShapeFailure is not null)
            {
                return detailsShapeFailure;
            }
        }

        bool proofRequiredByRegistration = ClientPolicyProfiles.RequiresDpop(registration.Profile);
        return await DpopTokenEndpointValidation.ValidatePresentedProofAsync(
            server, context, registration, issuerUri, server.TimeProvider.GetUtcNow(),
            proofRequiredByRegistration, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Re-runs the token-request checks a code-grant presentation must pass, shared by the
    /// code's first presentation and, per
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §7.5.3</see>, by <see cref="HandleAuthorizationCodeReplayAsync"/> for a replay of
    /// an already-redeemed code — the SAME function decides both, so a replay is refused (or
    /// accepted) by exactly the rule a first presentation would have been.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Identification of a presented <c>client_id</c>, the <c>code_verifier</c>'s presence and
    /// grammar, and declared client authentication answer at
    /// <see cref="BeforeCodeRedemptionCorrelationAsync"/>, the endpoint's pre-correlation step —
    /// every one of those checks reads only the request and the registration, so it runs before
    /// this method, and before the presented <c>code</c> is ever looked up. A field naming a
    /// registration other than the one this tenant selected answers the SAME body as an unknown,
    /// expired, or already-redeemed code (<see cref="CodeGrantNotFoundDescription"/>) —
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 §5.2</see> names
    /// <c>invalid_grant</c> for a grant "issued to another client" — so a presenter with no
    /// credentials cannot distinguish a wrong <c>client_id</c> on a live code from one on a code
    /// that never existed. This method performs the checks that need the stored code state: the
    /// PKCE digest, the grant-binding comparison, and the <c>redirect_uri</c> comparison.
    /// </para>
    /// <para>
    /// PKCE verification per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.6">RFC 7636 §4.6</see>
    /// dispatches on <paramref name="codeChallengeMethod"/> — the method PERSISTED at
    /// authorization time, never one named on the token request itself, which carries no
    /// <c>code_challenge_method</c> parameter at all. The <c>redirect_uri</c> check is
    /// CONDITIONAL per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3">RFC 6749 §4.1.3</see>:
    /// present -> must equal <paramref name="boundRedirectUri"/>'s <see cref="Uri.OriginalString"/>
    /// exactly; absent -> accepted without re-validation against the registered set. Returns the
    /// authenticated client registration alongside a <see langword="null"/> failure on success.
    /// </para>
    /// </remarks>
    private static (ClientRecord? Registration, ServerHttpResponse? Failure)
        VerifyCodeGrantPresentation(
            AuthorizationServerIntegration oauth,
            RequestFields fields,
            ExchangeContext context,
            string codeChallenge,
            string codeChallengeMethod,
            string boundClientId,
            Uri boundRedirectUri)
    {
        //The dispatcher already loaded the registration for this tenant onto the context. Use
        //that rather than re-loading by client_id; doing the lookup again under a different
        //identifier would conflate clientId and tenantId, which the protocol layer keeps distinct.
        //BeforeCodeRedemptionCorrelationAsync already verified: registration is non-null, a
        //presented client_id (if any) names this registration, code_verifier is present and
        //well-formed, and declared client authentication passed — so every read below is trusted.
        //A step that did not run answers ServerError here, the same fail-closed treatment the
        //carried issuer and DPoP outcome get, never a null-forgiving throw.
        if(context.ClientRegistration is not ClientRecord registration)
        {
            return (null, ServerHttpResponse.ServerError(OAuthErrors.ServerError,
                "The endpoint's pre-correlation step recorded no client registration."));
        }

        if(!fields.TryGetValue(OAuthRequestParameterNames.CodeVerifier, out string? verifier)
            || verifier is null)
        {
            return (null, ServerHttpResponse.ServerError(OAuthErrors.ServerError,
                "The endpoint's pre-correlation step recorded no code_verifier."));
        }

        //Fixed-time: this comparison decides the grant, so a match-length timing oracle on it
        //must not exist even though the challenge itself transited the front channel. Any
        //persisted method other than S256 is refused, including a storage-corrupted value.
        bool isPkceVerified = codeChallengeMethod switch
        {
            string method when WellKnownCodeChallengeMethods.IsS256(method) =>
                FixedTimeComparison.AreEqual(
                    ComputeDigestBase64Url(
                        verifier,
                        CryptoTags.Sha256Digest,
                        WellKnownHashAlgorithms.Sha256SizeBytes,
                        oauth.Codecs.ComputeDigest!,
                        oauth.Codecs.Encoder!,
                        oauth.MemoryPool!),
                    codeChallenge),
            _ => false
        };
        if(!isPkceVerified)
        {
            //A refusal that reads the record answers the endpoint's constant so the answer never
            //tells whether the record exists — RFC 6749 §5.2's invalid_grant.
            return (null, ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidGrant, CodeGrantNotFoundDescription));
        }

        //RFC 6749 §4.1.3 / draft-ietf-oauth-v2-1-16 §4.1.3: "client_id: REQUIRED, if the client
        //is not authenticating with the authorization server" — present or absent; the field's
        //identity and the declared client authentication were already checked by
        //BeforeCodeRedemptionCorrelationAsync.
        bool hasFieldClientId = fields.TryGetValue(OAuthRequestParameterNames.ClientId, out string? fieldClientId)
            && !string.IsNullOrEmpty(fieldClientId);

        //Grant binding: the EFFECTIVE identity — the field when present (already identified,
        //above, as the registration's own) or the authenticated registration's when the field is
        //absent — must be the client this code was issued to. A stored client that is not the
        //registration's own (a legacy or hostile record) is never "repaired"; it answers
        //RFC 6749 §5.2's invalid_grant "issued to another client".
        string effectiveClientId = hasFieldClientId ? fieldClientId! : registration.ClientId;
        if(!string.Equals(effectiveClientId, boundClientId, StringComparison.Ordinal))
        {
            //A refusal that reads the record answers the endpoint's constant so the answer never
            //tells whether the record exists — RFC 6749 §5.2's invalid_grant.
            return (null, ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidGrant, CodeGrantNotFoundDescription));
        }

        if(fields.TryGetValue(OAuthRequestParameterNames.RedirectUri, out string? tokenRedirectUri)
            && !string.Equals(tokenRedirectUri, boundRedirectUri.OriginalString, StringComparison.Ordinal))
        {
            //A refusal that reads the record answers the endpoint's constant so the answer never
            //tells whether the record exists — RFC 6749 §4.1.3's redirect_uri comparison.
            return (null, ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidGrant, CodeGrantNotFoundDescription));
        }

        return (registration, null);
    }


    /// <summary>
    /// Handles a code-grant token request whose correlation key resolved to an ALREADY-REDEEMED
    /// flow (<see cref="ServerTokenIssuedState"/>) instead of a live <see cref="ServerCodeIssuedState"/> —
    /// a replay of a spent authorization code. Re-verifies the presentation exactly as a first
    /// presentation would be verified via <see cref="VerifyCodeGrantPresentation"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §7.5.3</see>: "the authorization server should only revoke issued tokens if the
    /// request containing the authorization code is also valid, including any other parameters
    /// such as the code_verifier and client authentication. The authorization server SHOULD NOT
    /// revoke any issued tokens when receiving a replayed authorization code that contains
    /// invalid parameters" — otherwise anyone who merely observes a spent code (or guesses one)
    /// could deny service to its legitimate holder by presenting it with wrong parameters.
    /// </para>
    /// <para>
    /// Before any revocation, the issuer resolved for THIS replay presentation is compared against
    /// <see cref="FlowState.ExpectedIssuer"/> — the issuer resolved when the code was originally
    /// issued — per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse">OpenID
    /// Connect Core 1.0 §12.2</see> and the <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.4">RFC
    /// 9700 §4.4</see> mix-up defense it generalizes. A mismatch — including a declined or faulting
    /// resolution — answers the same constant <c>invalid_grant</c> body as an invalid presentation,
    /// revoking nothing, before <see cref="RevokeGrantAsync"/> ever runs.
    /// </para>
    /// <para>
    /// A VALID replay — every check in <see cref="VerifyCodeGrantPresentation"/> passes —
    /// revokes the tokens the legitimate redemption issued per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2">RFC 6749 §4.1.2</see>
    /// ("SHOULD revoke (when possible)") through the optional
    /// <see cref="AuthorizationServerIntegration.RevokeIssuedTokenAsync"/> delegate, keyed by each
    /// audited token's <c>jti</c> since the compact JWS bytes themselves are never persisted
    /// (see <see cref="ServerTokenIssuedState"/>) — see that delegate's remarks for the documented
    /// degradation when it is left unwired. Every other record of the grant — including the
    /// sibling refresh token, never covered by the jti-keyed audit set — is revoked by the one
    /// read <see cref="RevokeGrantAsync"/> makes through
    /// <see cref="Verifiable.OAuth.Server.LoadGrantFlowStatesDelegate"/>, shared with
    /// <see cref="HandleRefreshTokenReuseAsync"/>'s own grant revocation, which claims and deletes
    /// the grant's live refresh record through the required
    /// <see cref="ServerIntegration.DeleteFlowStateAsync"/>, even when the code-issued refresh
    /// token has itself rotated since. The response is <c>invalid_grant</c> —
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 §5.2</see>'s
    /// "provided authorization grant ... is invalid, expired, revoked."
    /// </para>
    /// <para>
    /// The first VALID replay whose grant revocation reports a COMPLETED outcome writes
    /// <see cref="ServerTokenIssuedState.RevokedAt"/> through <see cref="ServerAuthorizationCodeReplayDetected"/>
    /// — returned here as the stepped input rather than an early-exit response, so
    /// <see cref="EndpointServer"/>'s runner persists the marker via the same unconditional save
    /// every other transition uses. When revocation instead gives up on its bounded claim retry,
    /// this method answers the same <c>invalid_grant</c> refusal WITHOUT persisting the marker, so a
    /// later presentation of the same code re-runs it rather than early-exiting on a marker
    /// that recorded revocation which never happened. A SECOND and every later valid presentation
    /// after a COMPLETED replay observes <see cref="ServerTokenIssuedState.RevokedAt"/> already set
    /// and answers <c>invalid_grant</c> as an early exit — no PDA step, no re-run of revocation: per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7009#section-2.2">RFC 7009 §2.2</see>, "the
    /// purpose of the revocation request, invalidating the particular token, is already achieved,"
    /// so there is nothing further for a repeat revocation to do.
    /// </para>
    /// <para>
    /// The once-only guarantee is SEQUENTIAL: this method reads <see cref="ServerTokenIssuedState.RevokedAt"/>
    /// without first claiming the flow, so N concurrent valid replays of one code can all observe it
    /// unset and all run the revocation loop before any of them saves the marker. This is a property
    /// gap, not an exploitable break — RFC 7009 §2.2's idempotence means every extra revocation call
    /// is harmless and the marker still converges to set — but callers relying on "revocation runs
    /// exactly once" must serialize their own replay presentations to get it.
    /// </para>
    /// </remarks>
    private static async ValueTask<(FlowInput? Input, ServerHttpResponse? EarlyExit)> HandleAuthorizationCodeReplayAsync(
        AuthorizationServerIntegration oauth,
        RequestFields fields,
        ServerTokenIssuedState replayedState,
        ExchangeContext context,
        CancellationToken ct)
    {
        if(replayedState.ClientId is not string boundClientId
            || replayedState.RedirectUri is not Uri boundRedirectUri
            || replayedState.CodeChallenge is not string codeChallenge
            || replayedState.CodeChallengeMethod is not string codeChallengeMethod)
        {
            //This ServerTokenIssuedState was reached via refresh-token rotation, not a code
            //grant — a `code` correlation key can never resolve to it (the code index and the
            //refresh-token index are disjoint, and a code grant's flowId never changes across
            //redemption), so this branch is defensive rather than reachable from client input. A
            //refusal that reads the record answers the endpoint's constant so the answer never
            //tells whether the record exists — RFC 6749 §5.2's invalid_grant.

            return (null, ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidGrant, CodeGrantNotFoundDescription));
        }

        (ClientRecord? registration, ServerHttpResponse? presentationFailure) =
            VerifyCodeGrantPresentation(
                oauth, fields, context, codeChallenge, codeChallengeMethod,
                boundClientId, boundRedirectUri);
        if(presentationFailure is not null)
        {
            return (null, presentationFailure);
        }

        if(replayedState.RevokedAt is not null)
        {
            //A refusal that reads the record answers the endpoint's constant so the answer never
            //tells whether the record exists — RFC 6749 §4.1.2 / RFC 9700 §4.5.3's replay defense.
            return (null, ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidGrant, CodeGrantNotFoundDescription));
        }

        //OpenID Connect Core 1.0 §12.2 / RFC 9700 §4.4 mix-up defense: the issuer resolved for
        //THIS replay presentation must be the same issuer resolved when the code was originally
        //issued. BeforeCodeRedemptionCorrelationAsync already resolved it once for this request
        //and carried it — a missing carry means the endpoint's step did not run as the dispatcher
        //requires, and is answered as a server fault rather than resolving it a second time.
        if(context.CorrelationStepIssuer is not Uri issuerUri)
        {
            return (null, ServerHttpResponse.ServerError(OAuthErrors.ServerError,
                "The endpoint's pre-correlation step recorded no resolved issuer."));
        }

        if(!IsSameIssuerAsIssuance(issuerUri, replayedState.ExpectedIssuer))
        {
            //A refusal that reads the record answers the endpoint's constant so the answer never
            //tells whether the record exists — RFC 6749 §4.1.2 / RFC 9700 §4.5.3's replay defense.
            return (null, ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidGrant, CodeGrantNotFoundDescription));
        }

        //GrantKeyOf resolves the grant this terminal state itself roots (its own FlowId, since a
        //code redemption's terminal state always carries GrantFlowId = FlowId) — the single read
        //RevokeGrantAsync makes reaches every sibling record of the grant, including a refresh
        //token that has itself rotated one or more times since this code was redeemed. An
        //incomplete revocation must not be recorded as a completed replay, or a race with an
        //in-flight legitimate rotation could leave the grant alive with the marker already
        //consumed and no further attempt to revoke it.
        string grantFlowId = GrantKeyOf(replayedState);
        bool isGrantRevoked = await RevokeGrantAsync(
            oauth, registration!, replayedState, grantFlowId, context, ct).ConfigureAwait(false);
        if(!isGrantRevoked)
        {
            //A refusal that reads the record answers the endpoint's constant so the answer never
            //tells whether the record exists — RFC 6749 §4.1.2 / RFC 9700 §4.5.3's replay defense.
            return (null, ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidGrant, CodeGrantNotFoundDescription));
        }

        return (new ServerAuthorizationCodeReplayDetected(context.VerifiedAt!.Value), null);
    }


    /// <summary>
    /// The refresh endpoint's pre-correlation step: identification, issuer resolution, declared
    /// client authentication, the <c>client_id</c>-required rule, the <c>resource</c> and
    /// <c>authorization_details</c> request-only shapes, and DPoP, run, in that order, before the
    /// presented <c>refresh_token</c> is ever looked up. Wired as
    /// <see cref="EndpointCandidate.BeforeCorrelationAsync"/> on <see cref="BuildRefreshToken"/>.
    /// Answers a live presentation, a retired (reuse) presentation, and an unknown handle alike,
    /// since none of them is distinguished until the handle is resolved.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every check here reads only <paramref name="fields"/>, <paramref name="endpoint"/>,
    /// <paramref name="context"/>'s registration, and the server — never the stored GRANT record,
    /// since none is loaded yet. The authentication stores (a client assertion's <c>jti</c>, a
    /// DPoP proof's <c>jti</c>, a nonce) ARE reached, through the same
    /// <c>LoadFlowStateAsync</c>/<c>SaveFlowStateAsync</c> delegates the grant store uses, as
    /// <see cref="BeforeCorrelationDelegate"/>'s remarks describe.
    /// </para>
    /// <para>
    /// Identification of a present <c>client_id</c> field against the effective registration runs
    /// FIRST — before authentication — and a mismatch answers the SAME body
    /// <see cref="RefreshTokenNotFoundDescription"/> an unknown, expired, retired, or revoked
    /// refresh token receives from the dispatcher, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 §5.2</see>'s
    /// <c>invalid_grant</c> "issued to another client": a presenter with no credentials cannot
    /// distinguish a wrong <c>client_id</c> on a live token from one on a token that never
    /// existed. The issuer is resolved and carried (<c>SetCorrelationStepIssuer</c>) next, BEFORE
    /// declared authentication and the <c>authorization_details</c> decision, both of which read
    /// the carried value instead of resolving a second time for the same request.
    /// <see cref="RequireClientAuthenticationIfDeclaredAsync"/> then authenticates the declared
    /// method, answering its own <c>401 invalid_client</c> untranslated.
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1 draft-16
    /// §4.3.1</see>'s stored-grant binding rule — "if client authentication is included in the
    /// request, ensure that the refresh token was issued to the authenticated client, OR if a
    /// client_id is included in the request, ensure the refresh token was issued to the matching
    /// client" — has a request-only half decidable without any record: this library reads
    /// "neither identity" (no <c>client_id</c> field and no declared credentials) as fail-closed,
    /// and answers its own <c>invalid_request</c> next, mirroring
    /// <see cref="BeforeCodeRedemptionCorrelationAsync"/>'s identical rule; the record-dependent
    /// half, against the record's own bound client id, stays in <see cref="VerifyRefreshClient"/>,
    /// once the record is loaded, and is never satisfied by relabelling a stored record to the
    /// registration's identifier.
    /// </para>
    /// <para>
    /// <see cref="DpopTokenEndpointValidation.ValidatePresentedProofAsync"/> runs last, deciding
    /// the request-only half of DPoP from the registration's profile alone; the handler reads the
    /// carried outcome through <see cref="DpopTokenEndpointValidation.BindValidatedProofAsync"/>
    /// once it knows whether the stored record itself binds a proof.
    /// </para>
    /// </remarks>
    private static async ValueTask<ServerHttpResponse?> BeforeRefreshCorrelationAsync(
        ServerEndpoint endpoint, RequestFields fields, ExchangeContext context, CancellationToken cancellationToken)
    {
        EndpointServer server = context.RequestServer!;
        var oauth = server.OAuth();

        ClientRecord? registration = context.ClientRegistration;
        if(registration is null)
        {
            return ClientAuthenticationFailureResponse(context.IncomingRequest, "Unknown client.");
        }

        if(RefuseUnidentifiedClient(registration, fields, context.IncomingRequest) is not null)
        {
            return ServerHttpResponse.BadRequest(
                endpoint.HandleNotFoundError ?? OAuthErrors.InvalidGrant,
                endpoint.HandleNotFoundErrorDescription ?? RefreshTokenNotFoundDescription);
        }

        //Resolved and carried BEFORE declared authentication and the authorization_details
        //decision below, both of which read it — never resolving a second time for the same
        //request. BuildRefreshToken and HandleRefreshTokenReuseAsync read the same carried value
        //once the stored record is loaded.
        Uri? resolvedIssuerUri;
        try
        {
            resolvedIssuerUri = oauth.ResolveIssuerAsync is not null
                ? await oauth.ResolveIssuerAsync(registration, context, cancellationToken).ConfigureAwait(false)
                : await DefaultIssuerResolver.ResolveAsync(registration, context, cancellationToken).ConfigureAwait(false);
        }
        catch(InvalidOperationException)
        {
            //Folded onto the endpoint's own constant, exactly as an unknown refresh token is
            //answered — a caller with no credentials must not learn whether a resolver fault or
            //a nonexistent token produced this response, and this step runs identically for both.
            return ServerHttpResponse.BadRequest(
                endpoint.HandleNotFoundError ?? OAuthErrors.InvalidGrant,
                endpoint.HandleNotFoundErrorDescription ?? RefreshTokenNotFoundDescription);
        }

        if(resolvedIssuerUri is not Uri issuerUri)
        {
            //ResolveServerIssuerDelegate explicitly permits a null result (a declined
            //resolution); folded onto the same constant for the same reason.
            return ServerHttpResponse.BadRequest(
                endpoint.HandleNotFoundError ?? OAuthErrors.InvalidGrant,
                endpoint.HandleNotFoundErrorDescription ?? RefreshTokenNotFoundDescription);
        }

        context.SetCorrelationStepIssuer(issuerUri);

        ServerHttpResponse? authenticationFailure = await RequireClientAuthenticationIfDeclaredAsync(
            oauth, context.IncomingRequest, fields, registration, context, cancellationToken).ConfigureAwait(false);
        if(authenticationFailure is not null)
        {
            return authenticationFailure;
        }

        //OAuth 2.1 draft-16 §4.3.1's stored-grant binding rule has a request-only half this
        //library reads as fail-closed on neither identity: no client_id field and no declared
        //credentials is decidable from the request alone, mirroring
        //BeforeCodeRedemptionCorrelationAsync's identical rule. The record-dependent half — the
        //presented identity against the token's BOUND client — stays in VerifyRefreshClient, once
        //the record is loaded.
        bool hasFieldClientId = fields.TryGetValue(OAuthRequestParameterNames.ClientId, out string? fieldClientId)
            && !string.IsNullOrEmpty(fieldClientId);
        if(!hasFieldClientId && !HasClientCredentials(context.IncomingRequest, fields))
        {
            return ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidRequest, "client_id is required for a client that is not authenticating.");
        }

        ServerHttpResponse? resourceShapeFailure = ValidateRequestOnlyResourceShape(fields);
        if(resourceShapeFailure is not null)
        {
            return resourceShapeFailure;
        }

        string? tokenRequestAuthorizationDetails = ReadAuthorizationDetails(fields);
        if(tokenRequestAuthorizationDetails is not null)
        {
            ServerHttpResponse? detailsShapeFailure = await ValidateAndCarryTokenRequestAuthorizationDetailsAsync(
                server, tokenRequestAuthorizationDetails, registration, context, issuerUri, cancellationToken)
                .ConfigureAwait(false);
            if(detailsShapeFailure is not null)
            {
                return detailsShapeFailure;
            }
        }

        bool proofRequiredByRegistration = ClientPolicyProfiles.RequiresDpop(registration.Profile);
        return await DpopTokenEndpointValidation.ValidatePresentedProofAsync(
            server, context, registration, issuerUri, server.TimeProvider.GetUtcNow(),
            proofRequiredByRegistration, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// The stored-grant binding comparison a refresh presentation must still pass once the
    /// record is loaded: the effective client identity must be the one this refresh token was
    /// issued to. Identification, declared authentication, and the request-only
    /// <c>client_id</c>-required rule already ran, in <see cref="BeforeRefreshCorrelationAsync"/>,
    /// the endpoint's pre-correlation step.
    /// </summary>
    /// <remarks>
    /// This comparison IS purely record-dependent: <see cref="BeforeRefreshCorrelationAsync"/>
    /// already refused a request presenting neither a <c>client_id</c> field nor declared
    /// credentials (<c>invalid_request</c>), so every <paramref name="fields"/>/
    /// <paramref name="context"/> pair reaching here yields a non-null, non-empty
    /// <c>clientId</c> — the only fact left to decide is whether it equals
    /// <paramref name="boundClientId"/>, which needs the stored record. Never satisfied by
    /// relabelling a stored record to the registration's own identifier — a stored client id
    /// that is not <paramref name="boundClientId"/> answers RFC 6749 §5.2's <c>invalid_grant</c>
    /// under <see cref="RefreshTokenNotFoundDescription"/>: a refusal that reads the record
    /// answers the endpoint's constant so the answer never tells whether the record exists.
    /// </remarks>
    private static ServerHttpResponse? VerifyRefreshClient(
        RequestFields fields,
        ClientRecord registration,
        string? boundClientId,
        ExchangeContext context)
    {
        string? clientId = HasClientCredentials(context.IncomingRequest, fields)
            ? registration.ClientId
            : fields.TryGetValue(OAuthRequestParameterNames.ClientId, out string? formClientId)
                ? formClientId : null;
        if(!string.Equals(clientId, boundClientId, StringComparison.Ordinal))
        {
            //A refusal that reads the record answers the endpoint's constant so the answer never
            //tells whether the record exists — RFC 6749 §5.2's invalid_grant.
            return ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidGrant, RefreshTokenNotFoundDescription);
        }

        return null;
    }


    /// <summary>
    /// Handles reuse of a retired refresh token by verifying the client and proof before revoking
    /// its grant. The presented token is refused with a constant invalid_grant response.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §4.3.1</see>: "Authorization servers MUST utilize one of these methods to detect
    /// refresh token replay by malicious actors for public clients". With rotation, "The
    /// authorization server cannot determine which party submitted the invalid refresh token,
    /// but it will revoke the active refresh token as well as the access authorization grant
    /// associated with it." <see cref="BeforeRefreshCorrelationAsync"/> applies the same client
    /// identity and authentication checks as live refresh before this method ever runs, and
    /// <see cref="DpopTokenEndpointValidation.BindValidatedProofAsync"/> applies the same proof
    /// check here, including the carried outcome for a request presenting no proof at all on an
    /// unbound token. Invalid presentations revoke nothing, applying
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §7.5.3</see>'s denial-of-service reasoning: "The authorization server SHOULD NOT
    /// revoke any issued tokens when receiving a replayed authorization code that contains
    /// invalid parameters".
    /// </para>
    /// <para>
    /// The issuer resolved for THIS reuse presentation is compared against
    /// <see cref="FlowState.ExpectedIssuer"/> — the issuer resolved when the retired token's grant
    /// was issued — before the DPoP check, per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse">OpenID
    /// Connect Core 1.0 §12.2</see> and the RFC 9700 §4.4 mix-up defense it generalizes. A mismatch
    /// answers the same constant <c>invalid_grant</c> body as every other refusal here.
    /// </para>
    /// <para>
    /// All refusal exits reachable by an INVALID presentation — including issuer-resolution
    /// failure — use the same response bytes as an unknown refresh token. Only the response bytes
    /// are constant; the work performed varies with the presentation. This is not a timing
    /// guarantee. It is also not a fault-tolerance guarantee: the storage and revocation seams a
    /// VALID presentation drives (<see cref="ServerIntegration.LoadFlowStateAsync"/>,
    /// <see cref="ServerIntegration.ClaimFlowStateAsync"/>, <see cref="ServerIntegration.DeleteFlowStateAsync"/>,
    /// <see cref="AuthorizationServerIntegration.RevokeIssuedTokenAsync"/>) run without a catch
    /// around them, so a deployment whose store or revoke delegate throws while revoking a
    /// genuinely retired token surfaces that exception as a server error distinguishable from the
    /// constant <c>invalid_grant</c> body an unknown token or an INVALID presentation receives —
    /// an existence oracle for a retired token in a faulting deployment.
    /// </para>
    /// <para>
    /// A valid reuse revokes this record's own audits and, through <see cref="RevokeGrantAsync"/>,
    /// every other record of the grant read in that one call. Only when that revocation reports a
    /// completed outcome does this method return <see cref="ServerRefreshTokenReuseDetected"/>
    /// so the pure transition and runner persist <see cref="ServerTokenIssuedState.RevokedAt"/>.
    /// When revocation gives up on its bounded claim retry without claiming the grant's live end,
    /// this method returns the same constant <c>invalid_grant</c> refusal WITHOUT persisting the
    /// marker, so the next presentation of this same retired token re-runs it rather than
    /// early-exiting on a marker that recorded work which never happened. Subsequent presentations
    /// after a COMPLETED reuse early-exit without repeating it. The once-only marker
    /// guarantee is sequential: concurrent valid presentations can repeat audit revocations, so the
    /// optional delegate must be idempotent, consistent with
    /// <see href="https://www.rfc-editor.org/rfc/rfc7009#section-2.2">RFC 7009 §2.2</see>: "the
    /// purpose of the revocation request, invalidating the particular token, is already achieved".
    /// </para>
    /// <para>
    /// A legitimate client presenting one refresh token concurrently can lose its grant. A request
    /// loading the retired record after another request rotates it is a reuse under the strict
    /// OAuth 2.1 §4.3.1 rule above and revokes the successful request's grant. A request that loaded
    /// the live record instead competes for the rotation claim; a losing claim has no side effects.
    /// </para>
    /// </remarks>
    private static async ValueTask<(FlowInput? Input, ServerHttpResponse? EarlyExit)> HandleRefreshTokenReuseAsync(
        AuthorizationServerIntegration oauth,
        RequestFields fields,
        ServerTokenIssuedState retiredState,
        ExchangeContext context,
        CancellationToken ct)
    {
        if(retiredState.RevokedAt is not null)
        {
            //Already revoked by an earlier valid reuse — RFC 7009 §2.2's "the purpose of the
            //revocation request ... is already achieved" applies identically to a repeat reuse
            //presentation, so there is nothing further to run.

            return (null, ServerHttpResponse.BadRequest(OAuthErrors.InvalidGrant, RefreshTokenNotFoundDescription));
        }

        ClientRecord? registration = context.ClientRegistration;
        if(registration is null)
        {
            //An INVALID presentation: revoke nothing. Collapsed onto the same body as every other
            //refusal below — see the remarks on why this method never distinguishes them.

            return (null, ServerHttpResponse.BadRequest(OAuthErrors.InvalidGrant, RefreshTokenNotFoundDescription));
        }

        ServerHttpResponse? clientFailure = VerifyRefreshClient(
            fields, registration, retiredState.ClientId, context);
        if(clientFailure is not null)
        {
            //Identification and declared authentication already ran, in
            //BeforeRefreshCorrelationAsync, before this presentation was even known to be a reuse
            //of a retired token — reaching here means both passed. Only the stored-grant binding
            //mismatch remains, and it collapses onto this reuse path's own constant invalid_grant
            //body: an unauthenticated observer must not be able to tell it apart from an unknown,
            //expired, or already-revoked token.
            return (null, ServerHttpResponse.BadRequest(OAuthErrors.InvalidGrant, RefreshTokenNotFoundDescription));
        }

        EndpointServer server = context.RequestServer!;
        ConfirmationMethod? boundConfirmation = retiredState.Confirmation;

        //BeforeRefreshCorrelationAsync already resolved the issuer once for this request and
        //carried it. A missing carry means the endpoint's step did not run as the dispatcher
        //requires; answered as a server fault rather than a divergent second resolution that
        //could also fingerprint a retired token by a distinguishable response.
        if(context.CorrelationStepIssuer is not Uri issuerUri)
        {
            return (null, ServerHttpResponse.ServerError(OAuthErrors.ServerError,
                "The endpoint's pre-correlation step recorded no resolved issuer."));
        }

        //OpenID Connect Core 1.0 §12.2 / RFC 9700 §4.4 mix-up defense: the issuer resolved for
        //THIS reuse presentation must be the same issuer resolved when retiredState's grant was
        //issued. Collapsed onto the same constant invalid_grant body as every other refusal in
        //this method — a distinct exit here would fingerprint a retired token.
        if(!IsSameIssuerAsIssuance(issuerUri, retiredState.ExpectedIssuer))
        {
            return (null, ServerHttpResponse.BadRequest(OAuthErrors.InvalidGrant, RefreshTokenNotFoundDescription));
        }

        //Runs unconditionally — including for an unbound (Bearer) retired token — mirroring
        //BuildRefreshToken's own unconditional call. A malformed or invalid DPoP proof was already
        //refused in BeforeRefreshCorrelationAsync's step, before this presentation was even known
        //to be a reuse — this method's call never parses a proof and cannot refuse one; it reads
        //the carried outcome and applies only the record-dependent remainder: a bound (non-Bearer)
        //retired token presented with no carried proof still answers the fresh-nonce challenge,
        //and a carried proof whose thumbprint disagrees with the retired record's own still answers
        //the thumbprint mismatch. A missing carry is a server fault, not a silent Bearer fallback.
        if(context.DpopStepOutcome is not DpopValidationOutcome carriedDpopOutcome)
        {
            return (null, ServerHttpResponse.ServerError(OAuthErrors.ServerError,
                "The endpoint's pre-correlation step recorded no DPoP outcome."));
        }

        DpopValidationOutcome dpopOutcome = await DpopTokenEndpointValidation.BindValidatedProofAsync(
            server, context, registration, issuerUri, carriedDpopOutcome,
            expectedThumbprint: boundConfirmation?.JwkThumbprint,
            proofRequiredByRecord: boundConfirmation is { IsEmpty: false }, ct).ConfigureAwait(false);
        if(!dpopOutcome.IsSuccess)
        {
            //An INVALID presentation: revoke nothing. Collapsed onto the constant body rather
            //than dpopOutcome.FailureResponse — a distinct invalid_dpop_proof response here
            //would tell an attacker the presented token IS a real, retired one.

            return (null, ServerHttpResponse.BadRequest(OAuthErrors.InvalidGrant, RefreshTokenNotFoundDescription));
        }

        //A VALID presentation of a retired refresh token: revoke the grant, then persist the
        //once-only marker exactly as a code replay does — but ONLY when revocation actually
        //claimed and deleted the grant's live end. An incomplete revocation (the bounded-retry
        //give-up) must not be recorded as a completed reuse: doing so would make the live
        //record's survival permanent and silent, since every later presentation of this same
        //retired token would then early-exit on RevokedAt before ever re-running it.
        string grantFlowId = GrantKeyOf(retiredState);
        bool isGrantRevoked = await RevokeGrantAsync(
            oauth, registration, retiredState, grantFlowId, context, ct).ConfigureAwait(false);
        if(!isGrantRevoked)
        {
            return (null, ServerHttpResponse.BadRequest(OAuthErrors.InvalidGrant, RefreshTokenNotFoundDescription));
        }

        return (new ServerRefreshTokenReuseDetected(context.VerifiedAt!.Value), null);
    }


    /// <summary>
    /// Whether <paramref name="resolvedIssuerUri"/> — the issuer resolved for the request now
    /// presenting a code or refresh token — is the same issuer under which the presented grant was
    /// issued. Every <see cref="FlowState"/> carries the issuer resolved at issuance on
    /// <see cref="FlowState.ExpectedIssuer"/> (<see cref="Uri.OriginalString"/> at the time it was
    /// stamped); the comparison here uses that same string form, ordinally, per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse">OpenID
    /// Connect Core 1.0 §12.2</see>'s ID Token <c>iss</c> rule and the
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.4">RFC 9700 §4.4</see> mix-up
    /// defense it generalizes to every grant redemption, not only a refreshed ID Token.
    /// </summary>
    private static bool IsSameIssuerAsIssuance(Uri resolvedIssuerUri, string expectedIssuer) =>
        string.Equals(resolvedIssuerUri.OriginalString, expectedIssuer, StringComparison.Ordinal);


    /// <summary>
    /// The grant key a record belongs to — its own <see cref="ServerTokenIssuedState.GrantFlowId"/>
    /// or <see cref="ServerRefreshTokenIssuedState.GrantFlowId"/> when set, its own
    /// <see cref="FlowState.FlowId"/> otherwise. The one place both fields resolve to the value
    /// <see cref="Verifiable.OAuth.Server.LoadGrantFlowStatesDelegate"/> is called with.
    /// </summary>
    private static string GrantKeyOf(FlowState state) =>
        state switch
        {
            ServerTokenIssuedState issued => issued.GrantFlowId ?? issued.FlowId,
            ServerRefreshTokenIssuedState refresh => refresh.GrantFlowId ?? refresh.FlowId,
            _ => state.FlowId
        };


    /// <summary>
    /// Revokes a grant by one read of every retained record sharing its grant key, rather than by
    /// following links between records. Revokes the audits of <paramref name="presentedState"/>
    /// (the record the dispatcher already loaded), then reads the grant once through
    /// <see cref="Verifiable.OAuth.Server.LoadGrantFlowStatesDelegate"/>, revokes every accepted
    /// <see cref="ServerTokenIssuedState"/>'s audits, and claims and deletes every accepted live
    /// <see cref="ServerRefreshTokenIssuedState"/>. Shared by code replay and refresh reuse to
    /// implement
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §4.3.1</see>: "it will revoke the active refresh token as well as the access
    /// authorization grant associated with it."
    /// </summary>
    /// <remarks>
    /// A returned record is accepted only when its own type is one of the two grant record types,
    /// its <c>ClientId</c> equals <paramref name="registration"/>'s, and its own grant key
    /// (<see cref="GrantKeyOf"/>) equals <paramref name="grantFlowId"/> — a store fault that
    /// returns a foreign record never reaches another client's tokens: an ignored record is
    /// neither revoked nor deleted. A returned <see cref="ServerTokenIssuedState"/> whose own flow
    /// id equals <paramref name="presentedState"/>'s is also skipped: its audits were already
    /// revoked once, before the grant read, and are not revoked a second time when the grant read
    /// returns that same record. A lost claim on a live record re-reads the grant once more and
    /// retries whatever it still reports live; a record that still cannot be claimed after that
    /// leaves this call reporting NOT completed, so the caller must not persist a completion
    /// marker for it.
    /// </remarks>
    /// <returns>
    /// <see langword="true"/> when no accepted live record is left unclaimed — including when the
    /// grant read returns no live record at all. <see langword="false"/> only when a live record
    /// still could not be claimed after the one retry.
    /// </returns>
    private static async ValueTask<bool> RevokeGrantAsync(
        AuthorizationServerIntegration oauth,
        ClientRecord registration,
        ServerTokenIssuedState presentedState,
        string grantFlowId,
        ExchangeContext context,
        CancellationToken ct)
    {
        await RevokeAuditedTokensAsync(
            oauth, registration, presentedState.IssuedTokens, context, ct).ConfigureAwait(false);

        bool isRetryAfterLostClaim = false;

        while(true)
        {
            IReadOnlyList<(string FlowId, FlowState State, int StepCount)> records =
                await oauth.LoadGrantFlowStatesAsync!(
                    registration.TenantId, grantFlowId, context, ct).ConfigureAwait(false);

            bool isFullyClaimed = true;

            foreach((string flowId, FlowState state, int stepCount) in records)
            {
                if(state is ServerTokenIssuedState issuedRecord)
                {
                    if(string.Equals(flowId, presentedState.FlowId, StringComparison.Ordinal)
                        || !string.Equals(issuedRecord.ClientId, registration.ClientId, StringComparison.Ordinal)
                        || !string.Equals(GrantKeyOf(issuedRecord), grantFlowId, StringComparison.Ordinal))
                    {
                        continue;
                    }

                    await RevokeAuditedTokensAsync(
                        oauth, registration, issuedRecord.IssuedTokens, context, ct).ConfigureAwait(false);

                    continue;
                }

                if(state is not ServerRefreshTokenIssuedState liveRecord
                    || !string.Equals(liveRecord.ClientId, registration.ClientId, StringComparison.Ordinal)
                    || !string.Equals(GrantKeyOf(liveRecord), grantFlowId, StringComparison.Ordinal))
                {
                    continue;
                }

                bool isClaimed = await oauth.ClaimFlowStateAsync!(
                    registration.TenantId, flowId, stepCount, context, ct).ConfigureAwait(false);
                if(!isClaimed)
                {
                    isFullyClaimed = false;

                    continue;
                }

                await oauth.DeleteFlowStateAsync!(
                    registration.TenantId, flowId, context, ct).ConfigureAwait(false);
            }

            if(isFullyClaimed || isRetryAfterLostClaim)
            {
                return isFullyClaimed;
            }

            isRetryAfterLostClaim = true;
        }
    }


    /// <summary>
    /// Revokes every token audited in <paramref name="audits"/> through the optional
    /// <see cref="AuthorizationServerIntegration.RevokeIssuedTokenAsync"/>, keyed by each token's
    /// persisted <c>jti</c> rather than its wire bytes. A no-op when the delegate is unwired — see
    /// that delegate's remarks for the documented degradation.
    /// </summary>
    private static async ValueTask RevokeAuditedTokensAsync(
        AuthorizationServerIntegration oauth,
        ClientRecord registration,
        IssuedTokenAuditSet audits,
        ExchangeContext context,
        CancellationToken ct)
    {
        if(oauth.RevokeIssuedTokenAsync is null)
        {
            return;
        }

        foreach(KeyValuePair<string, IssuedTokenAudit> audit in audits.Audits)
        {
            await oauth.RevokeIssuedTokenAsync(
                audit.Value.Jti, audit.Key, registration, context, ct).ConfigureAwait(false);
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

            //RFC 6749 §5.2 defines invalid_grant as "the provided authorization grant ... is
            //invalid, expired, revoked ..." — the exact three ways this endpoint's `code` handle
            //can fail to resolve to a live flow (unknown, expired, already redeemed). The host-generic
            //fallback (invalid_request) is correct for a malformed request but wrong for a grant the
            //request named correctly and that simply is not good anymore.
            HandleNotFoundError = OAuthErrors.InvalidGrant,
            HandleNotFoundErrorDescription = CodeGrantNotFoundDescription,

            BeforeCorrelationAsync = BeforeCodeRedemptionCorrelationAsync,

            //RFC 6749 §5.2: "invalid_request ... The request is missing a required parameter" — a
            //code-grant token request missing `code` must still be identified as THIS endpoint so
            //the refusal carries an OAuth error body, never the host's bare 404. Disjointness vs the
            //refresh-token matcher (different grant_type) and the OID4VP token matcher (different
            //path) is enforced by the grant_type filter alone; a missing `code` fails correlation-key
            //resolution in EndpointServer.HandleCoreAsync with invalid_request before BuildInputAsync
            //ever runs (ExtractCorrelationKey below returns null). The description names the
            //parameter this endpoint alone knows is missing, in the style of "Missing grant_type."
            //below, rather than the host-generic "Cannot determine correlation key."
            MissingCorrelationKeyErrorDescription = "Missing code.",

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
                    || !string.Equals(grantType, WellKnownGrantTypes.AuthorizationCode, StringComparison.Ordinal))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
            },

            //The class doc on ServerCodeIssuedState is exact: "the raw code was returned to the
            //client in the redirect ... The token endpoint hashes the received code and compares
            //against CodeHash." The application's SaveServerFlowStateDelegate builds the code
            //index this correlation key resolves against; resolving the presented code to that
            //index means hashing it here, through the same ComputeDigestBase64Url path issuance
            //used, rather than treating the wire secret itself as the lookup key.
            ExtractCorrelationKey = static (path, fields, context) =>
            {
                if(!fields.TryGetValue(OAuthRequestParameterNames.Code, out string? code)
                    || string.IsNullOrWhiteSpace(code))
                {
                    return null;
                }

                //RFC 6749 Appendix A.11: "code = 1*VSCHAR". A presented code outside this grammar
                //cannot be one this server issued — every issued code is generated from this same
                //VSCHAR-only alphabet — so it must resolve exactly the way an unknown-but-well-formed
                //code does: EndpointServer.HandleCoreAsync's invalid_grant handle-miss, never the
                //invalid_request "Cannot determine correlation key" a null/empty key here produces.
                //The sentinel below is a fixed length no SHA-256 base64url digest below ever equals,
                //so ResolveCorrelationKeyAsync always reports it not found.
                if(!IsValidAuthorizationCodeGrammar(code))
                {
                    return NonExistentAuthorizationCodeCorrelationKey;
                }

                var oauth = context.RequestServer!.OAuth();

                return ComputeDigestBase64Url(
                    code,
                    CryptoTags.Sha256Digest,
                    WellKnownHashAlgorithms.Sha256SizeBytes,
                    oauth.Codecs.ComputeDigest!,
                    oauth.Codecs.Encoder!,
                    oauth.MemoryPool!);
            },
            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.RequestServer!;
                var oauth = server.OAuth();

                if(currentState is ServerTokenIssuedState replayedState)
                {
                    return await HandleAuthorizationCodeReplayAsync(
                        oauth, fields, replayedState, context, ct).ConfigureAwait(false);
                }

                if(currentState is not ServerCodeIssuedState codeState)
                {
                    //A refusal that reads the record answers the endpoint's constant so the answer
                    //never tells whether the record exists — RFC 6749 §5.2's invalid_grant.
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidGrant, CodeGrantNotFoundDescription));
                }

                (ClientRecord? verifiedRegistration, ServerHttpResponse? presentationFailure) =
                    VerifyCodeGrantPresentation(
                        oauth, fields, context, codeState.CodeChallenge, codeState.CodeChallengeMethod,
                        codeState.ClientId, codeState.RedirectUri);
                if(presentationFailure is not null)
                {
                    return (null, presentationFailure);
                }

                //The redeemed code's PKCE method is typed here at the code grant's own token
                //endpoint, where codeState already carries it — IssueTokensAsync below tags the
                //other four OAuth wire facts from IssuanceContext, common to every grant, but
                //PKCE is specific to this one.
                _ = (System.Diagnostics.Activity.Current?.SetTag(
                    OAuthTagNames.PkceMethod, codeState.CodeChallengeMethod));

                ClientRecord registration = verifiedRegistration!;

                //BeforeCodeRedemptionCorrelationAsync already resolved the issuer once for this
                //request and carried it; a missing carry means the endpoint's step did not run
                //as the dispatcher requires, and is answered as a server fault rather than
                //silently resolving a second, possibly different, issuer.
                if(context.CorrelationStepIssuer is not Uri issuerUri)
                {
                    return (null, ServerHttpResponse.ServerError(OAuthErrors.ServerError,
                        "The endpoint's pre-correlation step recorded no resolved issuer."));
                }

                //OpenID Connect Core 1.0 §12.2 / RFC 9700 §4.4 mix-up defense: the issuer resolved
                //for THIS redemption request must be the same issuer resolved when the code was
                //issued (codeState.ExpectedIssuer, stamped at the authorization request). A
                //mismatch is an INVALID presentation, refused before any DPoP check or claim,
                //minting nothing.
                if(!IsSameIssuerAsIssuance(issuerUri, codeState.ExpectedIssuer))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidGrant, CodeGrantNotFoundDescription));
                }

                DateTimeOffset now = server.TimeProvider.GetUtcNow();

                //RFC 9449 DPoP enforcement at the token endpoint. The request-only decision ran
                //once already, in BeforeCodeRedemptionCorrelationAsync; this reads the outcome it
                //carried and applies the record-dependent remainder. Code-grant passes
                //expectedThumbprint: null and proofRequiredByRecord: false because the binding is
                //being ESTABLISHED here, never verified against a prior record — refresh-grant
                //verifies against the stored thumbprint in BuildRefreshToken. A missing carry means
                //the step did not run as the dispatcher requires, and is a server fault rather than
                //a silent Bearer fallback.
                if(context.DpopStepOutcome is not DpopValidationOutcome carriedDpopOutcome)
                {
                    return (null, ServerHttpResponse.ServerError(OAuthErrors.ServerError,
                        "The endpoint's pre-correlation step recorded no DPoP outcome."));
                }

                DpopValidationOutcome dpopOutcome = await DpopTokenEndpointValidation.BindValidatedProofAsync(
                    server, context, registration, issuerUri, carriedDpopOutcome,
                    expectedThumbprint: null, proofRequiredByRecord: false, ct).ConfigureAwait(false);

                if(!dpopOutcome.IsSuccess)
                {
                    return (null, dpopOutcome.FailureResponse!);
                }

                ConfirmationMethod? confirmation = dpopOutcome.Confirmation;

                //RFC 9396 / OID4VCI 1.0 §6.1.1–§6.2: resolve the granted authorization_details
                //BEFORE any token is minted — the authorized details ride the code state (the
                //pushed value), a token-request value may narrow them to a subset, and the
                //application's seam mints the credential_identifiers the response advertises.
                _ = fields.TryGetValue(OAuthRequestParameterNames.AuthorizationDetails, out string? tokenRequestDetails);
                (string? grantedDetailsJson, IReadOnlyList<object>? grantedDetailsClaim, ServerHttpResponse? detailsFailure) =
                    await ResolveGrantedAuthorizationDetailsAsync(
                        server,
                        string.IsNullOrWhiteSpace(tokenRequestDetails) ? null : tokenRequestDetails,
                        codeState.AuthorizationDetails,
                        codeState.SubjectId,
                        registration,
                        context,
                        context.AuthorizationDetailsStepOutcome,
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

                //RFC 8707 §2.2: resolve the effective resource set for this access token. No
                //token-request resource leaves the full grant carried on codeState.Resource in
                //force; a present one MUST be a subset of it (narrowed to that subset) or the
                //request fails invalid_target. The effective set — when non-empty — takes
                //precedence over ScopeToAudience per §2's SHOULD (Rfc9068AccessTokenProducer
                //already prefers a populated IssuanceContext.Audience over the resolver).
                (IReadOnlyList<string>? effectiveResource, ServerHttpResponse? resourceFailure) =
                    ResolveEffectiveResource(codeState.Resource, ReadResource(fields));
                if(resourceFailure is not null)
                {
                    return (null, resourceFailure);
                }

                //OAuth 2.1 draft-16 §4.1.3: "The authorization server MUST return an access token
                //only once for a given authorization code." Every verification above has now
                //passed, so this is the last possible moment before minting; claiming here — after
                //verification, before any effect a second caller could also perform — is what
                //makes the MUST hold under concurrent redemption rather than only in the
                //single-writer case the unconditional SaveFlowStateAsync at the end of this request
                //already covered. A losing claim means another caller (or, on a strict replay, a
                //later request against the resulting ServerTokenIssuedState — see
                //HandleAuthorizationCodeReplayAsync) already redeemed this exact step.
                bool isClaimed = await oauth.ClaimFlowStateAsync!(
                    context.TenantId!.Value, context.FlowId!, context.FlowStepCount ?? 0, context, ct)
                    .ConfigureAwait(false);
                if(!isClaimed)
                {
                    //RFC 6749 §4.1.2's SHOULD-revoke is met only on the sequential replay path
                    //(HandleAuthorizationCodeReplayAsync, reached once ServerTokenIssuedState has
                    //been saved) — a claim lost to a concurrent winner returns invalid_grant here
                    //without revoking anything, since no ServerTokenIssuedState carrying the
                    //winner's issued tokens exists yet for this caller to read. A refusal that
                    //reads the record answers the endpoint's constant so the answer never tells
                    //whether the record exists.
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidGrant, CodeGrantNotFoundDescription));
                }

                IssuanceContext issuance = new()
                {
                    Registration = registration,
                    Context = context,
                    IssuerUri = issuerUri,
                    Subject = codeState.SubjectId,
                    Scope = codeState.Scope,
                    ClientId = codeState.ClientId,
                    GrantType = WellKnownGrantTypes.AuthorizationCode,
                    IssuedAt = now,
                    Nonce = string.IsNullOrEmpty(codeState.Nonce) ? null : codeState.Nonce,
                    AuthTime = codeState.AuthTime,
                    SessionId = codeState.SessionId,
                    Acr = codeState.Acr,
                    Confirmation = confirmation,
                    Audience = effectiveResource is { Count: > 0 } ? effectiveResource : null
                };

                IReadOnlyList<TokenProducer> producers =
                    oauth.TokenProducers.Count > 0 ? oauth.TokenProducers : DefaultTokenProducers;

                //One-time OidcClaims resolution per request — every
                //IdTokenTarget / UserInfoTarget built below in the producer
                //loop reads from the same resolved instance so per-rule
                //contributors don't each re-issue the resolver call.
                OidcClaims? preResolvedOidcClaims = await PreResolveOidcClaimsAsync(
                    server, issuance, ct).ConfigureAwait(false);

                (TokenIssuanceResult? issuanceResult, ServerHttpResponse? issuanceFailure) =
                    await IssueTokensAsync(
                        server, registration, context, issuance, producers, preResolvedOidcClaims, now, ct)
                        .ConfigureAwait(false);
                if(issuanceFailure is not null)
                {
                    return (null, issuanceFailure);
                }

                TokenIssuanceResult issued = issuanceResult!;
                Dictionary<string, string> issuedTokens = issued.IssuedTokens;
                Dictionary<string, IssuedTokenAudit> issuedAudits = issued.IssuedAudits;
                DateTimeOffset latestExpiry = issued.LatestExpiry;

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
                string refreshToken = await oauth.GenerateIdentifierAsync!(
                    WellKnownIdentifierPurposes.OAuthRefreshToken, context, ct)
                    .ConfigureAwait(false);
                DateTimeOffset refreshExpiresAt = now + context.RefreshTokenLifetime;

                if(oauth.SaveFlowStateAsync is not null)
                {
                    string refreshFlowId = await oauth.GenerateIdentifierAsync!(
                        WellKnownIdentifierPurposes.OAuthRefreshFlowId, context, ct)
                        .ConfigureAwait(false);
                    ServerRefreshTokenIssuedState refreshState = new()
                    {
                        FlowId = refreshFlowId,

                        //The code flow's own id names the grant this refresh token is born
                        //into — a later VALID replay of this code (OAuth 2.1 §7.5.3) or reuse of
                        //this refresh token reads every record under this key in one call.
                        GrantFlowId = codeState.FlowId,
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
                        SessionId = codeState.SessionId,
                        Acr = codeState.Acr,
                        OriginatingGrantType = WellKnownGrantTypes.AuthorizationCode,
                        //RFC 9396 §11.2: granted authorization_details are stored as part of the
                        //grant so the refresh exchange can re-emit the §7 echo and §9.1 claim. The
                        //baseline a later refresh narrows against is the resource owner's
                        //authorization (§6.1: "the resource owner's previous authorization is
                        //unchanged by such requests"), not a token-request-narrowed grant; when the
                        //details entered at the token request alone (the §6.1.1 scope-authorized
                        //selection), the granted result is that authorization.
                        AuthorizationDetails = codeState.AuthorizationDetails ?? grantedDetailsJson,

                        //RFC 8707 §2.2: "any refresh token that is returned is bound to the full
                        //original grant" — the FULL codeState.Resource, never the effectiveResource
                        //this response's access token may have been narrowed to.
                        Resource = codeState.Resource
                    };
                    await oauth.SaveFlowStateAsync(
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
                    Confirmation = confirmation,
                    ClientId = codeState.ClientId,
                    RedirectUri = codeState.RedirectUri,
                    CodeChallenge = codeState.CodeChallenge,
                    CodeChallengeMethod = codeState.CodeChallengeMethod
                }, null);
            },
            BuildResponse = static (state, flowKindName, context) =>
            {
                if(state is not ServerTokenIssuedState issued)
                {
                    return ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, "Unexpected state after token exchange.");
                }

                //A ServerAuthorizationCodeReplayDetected transition re-enters this same state
                //type with RevokedAt now set and mints no tokens this request — the response is
                //invalid_grant per RFC 6749 §5.2, never the success shape below.
                if(issued.RevokedAt is not null)
                {
                    return ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidGrant, "The authorization code has already been redeemed.");
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
                    _ = sb.Append('{');
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

                    //RFC 6749 §5.1: "scope: OPTIONAL, if identical to the scope requested by the
                    //client; otherwise, REQUIRED." Echoing scope whenever the grant carries one
                    //satisfies both branches with no state to track.
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

                    _ = sb.Append('}');
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
    /// Builds the <c>client_credentials</c> grant candidate (RFC 6749 §4.4) on
    /// the shared token endpoint URL. Stateless: the client authenticates
    /// through the application's
    /// <see cref="AuthorizationServerIntegration.ValidateClientCredentialsAsync"/>
    /// seam, the requested scope is validated against the registration's
    /// allowed scopes, and a presented proof runs through
    /// <see cref="DpopTokenEndpointValidation.ValidateAsync"/> exactly as it does
    /// for the Pre-Authorized Code, Token Exchange and JWT-bearer grants — endpoints with no
    /// pre-correlation step, unlike the authorization-code and refresh-token grants, which run
    /// the same request-only decision earlier, through
    /// <see cref="DpopTokenEndpointValidation.ValidatePresentedProofAsync"/> (<see
    /// href="https://www.rfc-editor.org/rfc/rfc9449#section-5">RFC 9449 §5</see>:
    /// "This is applicable for all access token requests regardless of grant
    /// type") — no flow state, no refresh token, no end-user subject (the
    /// <c>sub</c> is the client itself per RFC 9068 §3).
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
                    || !string.Equals(grantType, WellKnownGrantTypes.ClientCredentials, StringComparison.Ordinal))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
            },

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.RequestServer!;
                var oauth = server.OAuth();

                ClientRecord? registration = context.ClientRegistration;
                if(registration is null)
                {
                    return (null, ClientAuthenticationFailureResponse(context.IncomingRequest, "Unknown client."));
                }

                //Identification of an optional client_id form field runs before every other
                //check: a field that names another registration is refused invalid_client here,
                //never forwarded into the declared-method check or the authentication seam.
                ServerHttpResponse? clientCredentialsIdentificationFailure =
                    RefuseUnidentifiedClient(registration, fields, context.IncomingRequest);
                if(clientCredentialsIdentificationFailure is not null)
                {
                    return (null, clientCredentialsIdentificationFailure);
                }

                //draft-ietf-oauth-client-id-metadata-document-02 §8.2: a registration declaring a
                //confidential method this endpoint does not advertise is refused before the validator
                //runs, so the advertisement and the judgment are one set at every grant.
                ServerHttpResponse? undeclaredMethodRefusal =
                    RefuseUndeclaredClientAuthenticationMethod(oauth, registration, context.IncomingRequest);
                if(undeclaredMethodRefusal is not null)
                {
                    return (null, undeclaredMethodRefusal);
                }

                //RFC 6749 §4.4.2: the client MUST authenticate. The seam owns the
                //method (client_secret_basic/post, private_key_jwt, mTLS) and the
                //credential comparison; the builder guarantees it is wired.
                bool isClientAuthenticated = await oauth.ValidateClientCredentialsAsync!(
                    context.IncomingRequest, fields, registration, context, ct).ConfigureAwait(false);
                if(!isClientAuthenticated)
                {
                    return (null, ClientAuthenticationFailureResponse(
                        context.IncomingRequest, "Client authentication failed."));
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

                //RFC 6749 §3.3 narrowing — client_credentials has no authenticated End-User (the
                //subject is the client itself), so openid and the identity scopes never reach the
                //granted set. See DropIdentityScopesForNonEndUserGrant's remarks for the invariant.
                grantedScope = DropIdentityScopesForNonEndUserGrant(grantedScope);

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

                //RFC 8707 §2.2: client_credentials has no prior authorization to narrow against —
                //there is no PAR/authorize grant this request could be a subset of — so a validated
                //resource here IS the grant itself, feeding the issued token's audience directly
                //(the same absolute-URI/no-fragment shape gate the authorization-code family runs
                //at PAR/authorize receipt).
                string? clientCredentialsResource = ReadResource(fields);
                ServerHttpResponse? clientCredentialsResourceFailure =
                    ValidateResourceIndicatorsShape(clientCredentialsResource);
                if(clientCredentialsResourceFailure is not null)
                {
                    return (null, clientCredentialsResourceFailure);
                }

                IReadOnlyList<string>? clientCredentialsAudience =
                    ParseResourceIndicators(clientCredentialsResource) is { Length: > 0 } indicators
                        ? DeduplicateOrdinal(indicators)
                        : null;

                Uri issuerUri;
                try
                {
                    issuerUri = oauth.ResolveIssuerAsync is not null
                        ? (await oauth.ResolveIssuerAsync(registration, context, ct)
                            .ConfigureAwait(false))!
                        : await DefaultIssuerResolver.ResolveAsync(registration, context, ct)
                            .ConfigureAwait(false);
                }
                catch(InvalidOperationException ex)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, ex.Message));
                }

                DateTimeOffset now = server.TimeProvider.GetUtcNow();

                //RFC 9449 §5: the same DPoP enforcement the authorization-code and
                //Pre-Authorized Code grants run, at the same point — after client
                //authentication and the scope, authorization-details, and resource
                //checks, after issuer resolution, before issuance. expectedThumbprint
                //is null because this grant establishes no prior binding to verify
                //against.
                bool dpopRequired = ClientPolicyProfiles.RequiresDpop(registration.Profile);
                DpopValidationOutcome dpopOutcome = await DpopTokenEndpointValidation.ValidateAsync(
                    server, context, registration, issuerUri, now,
                    expectedThumbprint: null, dpopRequired, ct).ConfigureAwait(false);

                if(!dpopOutcome.IsSuccess)
                {
                    return (null, dpopOutcome.FailureResponse!);
                }

                ConfirmationMethod? confirmation = dpopOutcome.Confirmation;

                //No end-user is involved: the token's subject is the client itself
                //(RFC 9068 §3 for client_credentials), with no nonce or auth_time in
                //this grant shape.
                IssuanceContext issuance = new()
                {
                    Registration = registration,
                    Context = context,
                    IssuerUri = issuerUri,
                    Subject = registration.ClientId,
                    Scope = grantedScope,
                    ClientId = registration.ClientId,
                    GrantType = WellKnownGrantTypes.ClientCredentials,
                    IssuedAt = now,
                    Confirmation = confirmation,
                    Audience = clientCredentialsAudience
                };

                IReadOnlyList<TokenProducer> producers =
                    oauth.TokenProducers.Count > 0
                        ? oauth.TokenProducers
                        : DefaultTokenProducers;

                OidcClaims? preResolvedOidcClaims = await PreResolveOidcClaimsAsync(
                    server, issuance, ct).ConfigureAwait(false);

                (TokenIssuanceResult? issuanceResult, ServerHttpResponse? issuanceFailure) =
                    await IssueTokensAsync(
                        server, registration, context, issuance, producers, preResolvedOidcClaims, now, ct)
                        .ConfigureAwait(false);
                if(issuanceFailure is not null)
                {
                    return (null, issuanceFailure);
                }

                TokenIssuanceResult issued = issuanceResult!;
                Dictionary<string, string> issuedTokens = issued.IssuedTokens;

                if(!issuedTokens.TryGetValue(WellKnownTokenTypes.AccessToken, out string? accessToken))
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "No access token was produced for the client_credentials grant."));
                }

                int expiresIn = issued.IssuedAudits.TryGetValue(
                    WellKnownTokenTypes.AccessToken, out IssuedTokenAudit? accessAudit)
                    ? (int)(accessAudit.ExpiresAt - accessAudit.IssuedAt).TotalSeconds
                    : 0;

                //RFC 9449 §5: token_type is "DPoP" when the request bound the token, the
                //RFC 6750 "Bearer" default otherwise — the rule every other grant's token
                //response applies.
                string tokenTypeWireName = confirmation is { IsEmpty: false }
                    ? WellKnownAuthenticationSchemes.DPoP
                    : WellKnownAuthenticationSchemes.Bearer;

                //RFC 6749 §4.4.3/§5.1: access_token, token_type, expires_in, and
                //the granted scope; the response is stateless and uncacheable.
                StringBuilder sb = JsonAppender.Rent();
                string responseJson;
                try
                {
                    _ = sb.Append('{');
                    bool first = true;
                    JsonAppender.AppendStringField(sb, WellKnownTokenTypes.AccessToken, accessToken, ref first);
                    JsonAppender.AppendStringField(sb, "token_type", tokenTypeWireName, ref first);
                    JsonAppender.AppendInt64Field(sb, "expires_in", expiresIn, ref first);
                    JsonAppender.AppendStringField(sb, OAuthRequestParameterNames.Scope, grantedScope, ref first);
                    _ = sb.Append('}');
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
    /// Builds the OAuth 2.0 Token Exchange grant candidate
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.1">RFC 8693 §2.1</see>) on the
    /// shared token endpoint URL — IMPERSONATION and DELEGATION. Stateless: the client authenticates
    /// through <see cref="AuthorizationServerIntegration.ValidateClientCredentialsAsync"/>, the
    /// application's <see cref="AuthorizationServerIntegration.ValidateTokenExchangeTokenAsync"/> seam
    /// validates the presented <c>subject_token</c> (and, for delegation, the <c>actor_token</c>) as
    /// the trust authority, the
    /// <see cref="AuthorizationServerIntegration.AuthorizeTokenExchangeAsync"/> seam makes the
    /// impersonation/delegation policy decision and shapes the issued token, and the configured token
    /// producers mint the access token directly into the response — no flow state.
    /// </summary>
    /// <remarks>
    /// A request carrying an <c>actor_token</c> selects DELEGATION (RFC 8693 §1.1): the acting party
    /// (the actor token's subject) is recorded in the issued token's <c>act</c> claim (§4.1) while the
    /// top-level <c>sub</c> remains the subject. Before the policy seam runs, the library enforces the
    /// §4.4 <c>may_act</c> MUST: when the subject token names an authorized actor, the actor token must
    /// match every <c>may_act</c> member present — its <c>sub</c> and, since §4.4 notes "the combination
    /// of the two claims <c>iss</c> and <c>sub</c> are sometimes necessary to uniquely identify an
    /// authorized actor," its <c>iss</c> too whenever <c>may_act</c> names one. A request with no
    /// <c>actor_token</c> is IMPERSONATION — the issued token
    /// carries no <c>act</c> claim and the subject becomes the issued token's subject (§1.1).
    /// </remarks>
    private static EndpointCandidate BuildTokenExchange() =>
        new()
        {
            Name = WellKnownEndpointNames.TokenExchangeToken,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownCapabilityIdentifiers.OAuthTokenExchange,
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,
            //DiscoveryMetadataKey null — the grant shares the token endpoint URL.

            //Disjointness vs the other grants is enforced by the grant_type filter,
            //exactly as the client_credentials and refresh matchers do.
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
                    || !string.Equals(grantType, WellKnownGrantTypes.TokenExchange, StringComparison.Ordinal))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
            },

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.RequestServer!;
                var oauth = server.OAuth();

                ClientRecord? registration = context.ClientRegistration;
                if(registration is null)
                {
                    return (null, ClientAuthenticationFailureResponse(context.IncomingRequest, "Unknown client."));
                }

                //Identification of an optional client_id form field runs before every other
                //check: a field that names another registration is refused invalid_client here,
                //never forwarded into the declared-method check or the authentication seam.
                ServerHttpResponse? tokenExchangeIdentificationFailure =
                    RefuseUnidentifiedClient(registration, fields, context.IncomingRequest);
                if(tokenExchangeIdentificationFailure is not null)
                {
                    return (null, tokenExchangeIdentificationFailure);
                }

                //draft-ietf-oauth-client-id-metadata-document-02 §8.2: a registration declaring a
                //confidential method this endpoint does not advertise is refused before the validator
                //runs, so the advertisement and the judgment are one set at every grant.
                ServerHttpResponse? undeclaredMethodRefusal =
                    RefuseUndeclaredClientAuthenticationMethod(oauth, registration, context.IncomingRequest);
                if(undeclaredMethodRefusal is not null)
                {
                    return (null, undeclaredMethodRefusal);
                }

                //RFC 8693 §2.1: client authentication is done using the normal OAuth 2.0
                //mechanisms; the seam owns the method and the comparison, and the builder
                //guarantees it is wired. Authenticating the client is what lets the STS apply
                //the §2.1 "which entities are permitted to impersonate" checks downstream.
                bool isClientAuthenticated = await oauth.ValidateClientCredentialsAsync!(
                    context.IncomingRequest, fields, registration, context, ct).ConfigureAwait(false);
                if(!isClientAuthenticated)
                {
                    return (null, ClientAuthenticationFailureResponse(
                        context.IncomingRequest, "Client authentication failed."));
                }

                Uri issuerUri;
                try
                {
                    issuerUri = oauth.ResolveIssuerAsync is not null
                        ? (await oauth.ResolveIssuerAsync(registration, context, ct)
                            .ConfigureAwait(false))!
                        : await DefaultIssuerResolver.ResolveAsync(registration, context, ct)
                            .ConfigureAwait(false);
                }
                catch(InvalidOperationException ex)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, ex.Message));
                }

                DateTimeOffset now = server.TimeProvider.GetUtcNow();

                //RFC 9449 §5: "This is applicable for all access token requests regardless of grant
                //type ... and extension grants such as the JWT authorization grant [RFC7523]" — Token
                //Exchange is such an extension grant, and this call enforces the registration's own
                //mandate (ClientPolicyProfiles.RequiresDpop) exactly as the authorization-code and
                //client_credentials grants do. It runs BEFORE the subject-token, actor-token, and
                //authorization seams below: each MAY be implemented with a side effect, so a
                //use_dpop_nonce challenge (RFC 9449 §8) or a rejected proof MUST NOT consume any of
                //them — the caller retries the same request once it has satisfied the challenge. The
                //obligation the matrix below applies attaches to the subject_token being presented,
                //not to which of the three issuance branches serves it: validate any presented proof
                //once, then apply the same §9.8.1.2-shaped matrix the ID-JAG mint and redemption legs
                //use — a bound subject token requires a matching proof, an unbound one may still opt a
                //fresh key in, and an unbound token with no proof is refused only when the
                //registration's own profile mandates DPoP.
                bool dpopRequired = ClientPolicyProfiles.RequiresDpop(registration.Profile);
                DpopValidationOutcome dpopOutcome = await DpopTokenEndpointValidation.ValidateAsync(
                    server, context, registration, issuerUri, now,
                    expectedThumbprint: null, dpopRequired, ct).ConfigureAwait(false);
                if(!dpopOutcome.IsSuccess)
                {
                    return (null, dpopOutcome.FailureResponse!);
                }

                //RFC 8693 §2.1: subject_token is REQUIRED.
                if(!fields.TryGetValue(OAuthRequestParameterNames.SubjectToken, out string? subjectToken)
                    || string.IsNullOrEmpty(subjectToken))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "The subject_token parameter is required."));
                }

                //RFC 8693 §2.1/§3: subject_token_type is REQUIRED and must be a known token-type URI.
                if(!fields.TryGetValue(OAuthRequestParameterNames.SubjectTokenType, out string? subjectTokenTypeValue)
                    || string.IsNullOrEmpty(subjectTokenTypeValue)
                    || !TokenTypeNames.TryParse(subjectTokenTypeValue, out TokenType subjectTokenType))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        "The subject_token_type parameter is required and must be a supported token type."));
                }

                //RFC 8693 §2.1: actor_token (OPTIONAL) selects DELEGATION over impersonation; when it
                //is present, actor_token_type is REQUIRED and must be a known token-type URI (§3), and
                //it MUST be absent when actor_token is absent. Parse both before reaching the validation
                //and authorization seams so a malformed acting-party request fails closed up front.
                bool hasActorToken = fields.TryGetValue(OAuthRequestParameterNames.ActorToken, out string? actorToken)
                    && !string.IsNullOrEmpty(actorToken);
                bool hasActorTokenTypeValue = fields.TryGetValue(OAuthRequestParameterNames.ActorTokenType, out string? actorTokenTypeValue)
                    && !string.IsNullOrEmpty(actorTokenTypeValue);

                TokenType? actorTokenType = null;
                if(hasActorToken)
                {
                    //RFC 8693 §2.1: "actor_token_type ... REQUIRED when actor_token is present in the request."
                    if(!hasActorTokenTypeValue
                        || !TokenTypeNames.TryParse(actorTokenTypeValue!, out TokenType parsedActorTokenType))
                    {
                        return (null, ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidRequest,
                            "The actor_token_type parameter is required and must be a supported token type when actor_token is present."));
                    }

                    actorTokenType = parsedActorTokenType;
                }
                else if(hasActorTokenTypeValue)
                {
                    //RFC 8693 §2.1: actor_token_type "MUST NOT be included [when] actor_token is not present."
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        "The actor_token_type parameter must not be present without an actor_token."));
                }

                //RFC 8693 §2.1/§3: requested_token_type is OPTIONAL but, when present, must parse to
                //a known token-type URI. The issued type is the authorization seam's decision.
                TokenType? requestedTokenType = null;
                if(fields.TryGetValue(OAuthRequestParameterNames.RequestedTokenType, out string? requestedTokenTypeValue)
                    && !string.IsNullOrEmpty(requestedTokenTypeValue))
                {
                    if(!TokenTypeNames.TryParse(requestedTokenTypeValue, out TokenType parsedRequestedTokenType))
                    {
                        return (null, ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidRequest,
                            "The requested_token_type parameter must be a supported token type."));
                    }

                    requestedTokenType = parsedRequestedTokenType;
                }

                //RFC 8693 §2.1: resource / audience / scope are OPTIONAL and indicate the target and
                //requested scope. §2.1.1's multi-resource wire form is the REPEATED resource
                //parameter — RequestFields.GetValues aggregates every occurrence (the same read the
                //authorization-code path's ReadResource performs) — never several URIs packed into one
                //occurrence separated by spaces (a resource indicator IS one absolute URI; RFC 3986
                //§2 / Appendix A's ABNF forbids a raw space inside one), so each raw occurrence is
                //checked BEFORE joining and rejected — with RFC 8707 §2's own invalid_target, the
                //uniform outcome for this whole defect class — when it is null, empty, or
                //all-whitespace (a blank occurrence has no indicator to contribute; silently dropping
                //it via ParseResourceIndicators's RemoveEmptyEntries after joining would let one bad
                //occurrence vanish from an otherwise-valid aggregate) or when it carries embedded
                //whitespace. Past that check every value is non-blank and space-free, so joining with
                //a space and splitting back via ParseResourceIndicators (the convention the library
                //also uses for scope / acr_values) recovers exactly the individual RFC 8707 §2
                //absolute-URI indicators.
                IReadOnlyList<string> resource = [];
                IReadOnlyList<string> resourceValues = fields.GetValues(OAuthRequestParameterNames.Resource);
                if(resourceValues.Count > 0)
                {
                    foreach(string rawValue in resourceValues)
                    {
                        if(string.IsNullOrEmpty(rawValue) || rawValue.Any(char.IsWhiteSpace))
                        {
                            return (null, ServerHttpResponse.BadRequest(
                                OAuthErrors.InvalidTarget,
                                "The resource parameter must not contain a null, empty, or "
                                + "whitespace-only occurrence, and each occurrence must carry no "
                                + "embedded whitespace."));
                        }
                    }

                    //A present-but-empty/blank resource value (every occurrence blank, or a single
                    //empty parameter) parses to zero indicators — malformed, not "no resource
                    //requested" — the same distinction ValidateResourceIndicatorsShape draws for the
                    //authorization-code family. Unreachable once every raw occurrence has already
                    //passed the null/empty/whitespace gate above; retained defensively so a future
                    //change to that gate cannot silently reopen "all-blank resource parses to no
                    //indicators."
                    string[] resourceIndicators =
                        ParseResourceIndicators(string.Join(' ', resourceValues)) ?? [];
                    if(resourceIndicators.Length == 0)
                    {
                        return (null, ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidTarget,
                            "The resource parameter, when present, must not be empty."));
                    }

                    //RFC 8707 §2 / RFC 8693 §2.1: each resource value MUST be an absolute URI (RFC 3986
                    //§4.3) and MUST NOT include a fragment component. Validate before the validation seam
                    //runs so a malformed target fails closed up front. Shares its shape check with the
                    //PAR/authorize gate (IsAbsoluteResourceIndicatorUri); RFC 8693's own §2.2.2 boundary
                    //keeps THIS shape check's error invalid_request rather than invalid_target — distinct
                    //from the null/empty/whitespace defect class above, which RFC 8707 §2 itself
                    //registers invalid_target for ("missing... or malformed").
                    foreach(string indicator in resourceIndicators)
                    {
                        if(!IsAbsoluteResourceIndicatorUri(indicator))
                        {
                            return (null, ServerHttpResponse.BadRequest(
                                OAuthErrors.InvalidRequest,
                                "The resource parameter must be an absolute URI (RFC 3986 §4.3) without a fragment."));
                        }
                    }

                    //§2's resource set is a SET — deduplicate (ordinal) so a repeated indicator never
                    //reaches the authorization seam or a resulting aud twice.
                    resource = DeduplicateOrdinal(resourceIndicators);
                }

                //RFC 8693 §2.1: "Multiple "audience" parameters may be used to indicate that the
                //issued token is intended to be used at the multiple audiences listed" — every
                //occurrence is read (RequestFields.GetValues, the same multi-valued read "resource"
                //uses above), never folded into one value by TryGetValue's exactly-one semantics.
                //audience values are logical names that MAY contain spaces, so an occurrence is never
                //space-split the way a resource occurrence is joined and reparsed; each occurrence IS
                //one audience. §2.2.2 registers no audience-specific error code for a malformed
                //occurrence the way RFC 8707 §2 registers invalid_target for "resource" — a null,
                //empty, or whitespace-only occurrence is simply a request that is "not... valid" under
                //§2.2.2's general rule, so it is invalid_request. §2's audience set is a SET —
                //deduplicate (ordinal) so a repeated value never reaches the authorization seam twice.
                string[] audience = [];
                IReadOnlyList<string> audienceValues = fields.GetValues(OAuthRequestParameterNames.Audience);
                if(audienceValues.Count > 0)
                {
                    foreach(string rawValue in audienceValues)
                    {
                        if(string.IsNullOrWhiteSpace(rawValue))
                        {
                            return (null, ServerHttpResponse.BadRequest(
                                OAuthErrors.InvalidRequest,
                                "The audience parameter must not contain a null, empty, or "
                                + "whitespace-only occurrence."));
                        }
                    }

                    audience = DeduplicateOrdinal([.. audienceValues]);
                }

                //ID-JAG §4.3: when an Identity Assertion JWT Authorization Grant is requested
                //(requested_token_type=id-jag), audience is REQUIRED and names THE Resource
                //Authorization Server the grant is minted for — the §4.3 profile paragraph speaks of
                //"the Resource Authorization Server to which the ID-JAG is issued", one identifier
                //that becomes the JAG's aud claim. A missing audience is a malformed request
                //(invalid_request), not a grant failure. More than one audience is equally malformed
                //against that singular definition — RFC 8693 §2.2.2's "If the request itself is not
                //valid... MUST... invalid_request" — and is refused here, before the subject token is
                //validated or the authorization seam runs: neither identity resolution nor the policy
                //decision is meaningful when the mint does not yet know which single Resource
                //Authorization Server it is for.
                if(requestedTokenType == TokenType.IdJag)
                {
                    if(audience.Length == 0)
                    {
                        return (null, ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidRequest,
                            "The audience parameter is required when requesting an id-jag token type."));
                    }

                    if(audience.Length > 1)
                    {
                        return (null, ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidRequest,
                            "The audience parameter must name exactly one Resource Authorization "
                            + "Server when requesting an id-jag token type; this request named more "
                            + "than one."));
                    }
                }

                string? requestedScope = null;
                if(fields.TryGetValue(OAuthRequestParameterNames.Scope, out string? scopeValue)
                    && !string.IsNullOrWhiteSpace(scopeValue))
                {
                    requestedScope = scopeValue;
                }

                Verifiable.OAuth.TokenExchange.TokenExchangeRequest exchangeRequest = new()
                {
                    SubjectToken = subjectToken,
                    SubjectTokenType = subjectTokenType,
                    ActorToken = hasActorToken ? actorToken : null,
                    ActorTokenType = actorTokenType,
                    RequestedTokenType = requestedTokenType,
                    Resource = resource,
                    Audience = audience,
                    Scope = requestedScope,

                    //ID-JAG §4.3.3: authorization_details is carried verbatim for the IdP's seam to
                    //parse and process per RFC 9396; base RFC 8693 token exchange ignores it.
                    AuthorizationDetails = ReadAuthorizationDetails(fields)
                };

                //RFC 8693 §2.1: validate the subject_token for its indicated type. The application is
                //the trust authority; a null result means the token is invalid, untrusted, or expired.
                //§2.2.2: an invalid or unacceptable subject_token MUST be rejected with invalid_request.
                Verifiable.OAuth.TokenExchange.ValidatedSecurityToken? validatedSubject =
                    await oauth.ValidateTokenExchangeTokenAsync!(
                        subjectToken, subjectTokenType, registration, context, ct).ConfigureAwait(false);
                if(validatedSubject is null)
                {
                    //ID-JAG §4.3.3 / §4.3.4.3: an ID-JAG mint whose subject token (the Identity
                    //Assertion) fails validation — including the §4.3.3 MUST that its audience match
                    //the authenticating client_id — is a grant failure (invalid_grant), not the base
                    //RFC 8693 §2.2.2 invalid_request used for a plain token exchange.
                    return (null, ServerHttpResponse.BadRequest(
                        requestedTokenType == TokenType.IdJag ? OAuthErrors.InvalidGrant : OAuthErrors.InvalidRequest,
                        "The subject_token is not valid."));
                }

                //DELEGATION (RFC 8693 §1.1): an actor_token was presented. Validate it through the same
                //trust-authority seam — the application owns which issuers and keys it accepts — and
                //build the §4.1 "act" claim that records the acting party in the composite token. For
                //IMPERSONATION (no actor_token) the actor and the act claim stay null: unchanged behavior.
                Verifiable.OAuth.TokenExchange.ValidatedSecurityToken? validatedActor = null;
                IReadOnlyDictionary<string, object>? act = null;
                if(hasActorToken)
                {
                    validatedActor = await oauth.ValidateTokenExchangeTokenAsync!(
                        actorToken!, actorTokenType!.Value, registration, context, ct).ConfigureAwait(false);
                    if(validatedActor is null)
                    {
                        return (null, ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidRequest, "The actor_token is not valid."));
                    }

                    //RFC 8693 §4.4 MUST: when the subject token names an authorized actor via may_act,
                    //the actor token must be that party — the subject authorized only that party to act
                    //for it, so any other actor is unauthorized. §4.4: "the combination of the two claims
                    //iss and sub are sometimes necessary to uniquely identify an authorized actor." When
                    //may_act names an issuer, a matching subject under a different issuer is a different,
                    //unauthorized party — the actor MUST match every may_act member that is present.
                    bool subjectMatches = validatedSubject.MayActSubject is null
                        || string.Equals(validatedSubject.MayActSubject, validatedActor.Subject, StringComparison.Ordinal);
                    bool issuerMatches = validatedSubject.MayActIssuer is null
                        || string.Equals(validatedSubject.MayActIssuer, validatedActor.Issuer, StringComparison.Ordinal);
                    if((validatedSubject.MayActSubject is not null || validatedSubject.MayActIssuer is not null)
                        && !(subjectMatches && issuerMatches))
                    {
                        return (null, ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidRequest, "The actor is not authorized to act for the subject."));
                    }

                    //RFC 8693 §4.1: the "act" claim value is a JSON object whose members identify the
                    //current actor (its sub). A delegation chain is expressed by nesting the prior actor's
                    //"act" object under this one — the outermost is the current actor, nested ones are
                    //prior actors. The subject token's own "act" (if it was already a delegated token) is
                    //that prior chain, carried through verbatim.
                    Dictionary<string, object> actClaim = new(StringComparer.Ordinal)
                    {
                        [WellKnownJwtClaimNames.Sub] = validatedActor.Subject
                    };
                    if(validatedSubject.Act is not null)
                    {
                        actClaim[WellKnownJwtClaimNames.Act] = validatedSubject.Act;
                    }

                    act = actClaim;
                }

                //RFC 8693 §2.1: the impersonation/delegation policy decision — which client may exchange
                //this subject (and, for delegation, act as this actor) for whom, at which target. A null
                //result denies the exchange. §2.2.2: invalid_target SHOULD be used when the server is
                //unwilling or unable to issue for a named resource/audience target; an exchange refused on
                //policy with no named target is the general invalid_request MUST.
                Verifiable.OAuth.TokenExchange.TokenExchangeAuthorization? authorization =
                    await oauth.AuthorizeTokenExchangeAsync!(
                        validatedSubject, validatedActor, exchangeRequest, registration, context, ct).ConfigureAwait(false);
                if(authorization is null)
                {
                    //ID-JAG §4.3.4.3: a denied ID-JAG mint (for example audience validation failing)
                    //is invalid_grant. The base RFC 8693 §2.2.2 mapping — invalid_target for a named
                    //resource/audience target, else invalid_request — applies to a plain exchange.
                    if(requestedTokenType == TokenType.IdJag)
                    {
                        return (null, ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidGrant, "The id-jag token exchange was not authorized."));
                    }

                    bool hasNamedTarget = exchangeRequest.Resource.Count > 0 || exchangeRequest.Audience.Count > 0;

                    return (null, ServerHttpResponse.BadRequest(
                        hasNamedTarget ? OAuthErrors.InvalidTarget : OAuthErrors.InvalidRequest,
                        "The token exchange was not authorized."));
                }

                //RFC 8693 §2.2.1: token_type describes how to use the issued access_token, and
                //issued_token_type identifies its representation. This grant mints either an RFC 9068
                //access-token JWT (token_type Bearer) or — when the authorization seam selects it — an
                //Identity Assertion JWT Authorization Grant (ID-JAG §4.3, token_type N_A). Any other
                //issued_token_type would be inconsistent with the token actually returned; that
                //mismatch is the AS's own misconfiguration of the authorization seam → server_error.
                if(authorization.IssuedTokenType != TokenType.AccessToken
                    && authorization.IssuedTokenType != TokenType.IdJag
                    && authorization.IssuedTokenType != TokenType.RefreshToken)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "This authorization server issues only access tokens, id-jag grants, or refresh tokens for token exchange; this issued_token_type is not supported."));
                }

                //ID-JAG §9.8.1.2-shaped proof-of-possession matrix: reads the proof outcome already
                //validated above, before the subject-token, actor-token, and authorization seams.
                IdJagDpopDecision subjectDpopDecision = IdJagDpopDecision.Evaluate(
                    validatedSubject.RequiredKeyThumbprint,
                    dpopOutcome.Confirmation?.JwkThumbprint,
                    resourceServerRequiresSenderConstrained: false);
                if(subjectDpopDecision.IsRejected)
                {
                    string dpopRefusal = subjectDpopDecision.Kind switch
                    {
                        IdJagDpopDecisionKind.RejectProofRequired => "Proof of possession required for this subject token.",
                        IdJagDpopDecisionKind.RejectKeyMismatch => "The DPoP proof key does not match the subject token's bound key.",
                        _ => "Sender-constrained tokens are required for this exchange."
                    };

                    return (null, ServerHttpResponse.BadRequest(OAuthErrors.InvalidGrant, dpopRefusal)
                        .WithHeader(WellKnownHttpHeaderNames.CacheControl, WellKnownCacheControlValues.NoStore));
                }

                ConfirmationMethod? tokenConfirmation = subjectDpopDecision.BoundKeyThumbprint is { } subjectBoundThumbprint
                    ? new ConfirmationMethod { JwkThumbprint = subjectBoundThumbprint }
                    : null;

                //ID-JAG §4.3.4: when the authorization seam selected the id-jag issued type, mint and
                //return the Identity Assertion JWT Authorization Grant directly — a precise §3.1 claim
                //set signed with the IdP key, returned as the access_token with token_type N_A. It does
                //not flow through the access-token producer walk (no OIDC/access-token claim
                //contribution applies to a JAG), so this branch is self-contained.
                if(authorization.IssuedTokenType == TokenType.IdJag)
                {
                    //RFC 8693 §4.1: the delegation chain this leg already built from the validated
                    //actor_token (and the subject token's own prior act) rides into the JAG's claim set
                    //— the mint threads that one value rather than deriving a second, so a JAG and an
                    //access token minted from the same exchange record the identical acting party.
                    return await BuildIdJagMintResponseAsync(
                        server, registration, context, exchangeRequest, authorization, act, tokenConfirmation, issuerUri, now, ct)
                        .ConfigureAwait(false);
                }

                //ID-JAG §4.5: the SAML-2.0-to-OAuth protocol transition — the authorization seam selected
                //the refresh_token issued type (e.g. after validating a SAML assertion subject token and
                //its §4.5 Audience->client_id mapping), so mint and return an opaque Refresh Token the
                //client later uses as a §4.3.2 subject_token to obtain an ID-JAG.
                if(authorization.IssuedTokenType == TokenType.RefreshToken)
                {
                    return await BuildRefreshTokenExchangeResponseAsync(
                        server, registration, context, authorization, tokenConfirmation, issuerUri, now, ct)
                        .ConfigureAwait(false);
                }

                //RFC 8693 §1.1: the issued token's subject is the validated subject token's subject. For
                //impersonation the client becomes indistinguishable from that party at the target; for
                //delegation the subject stays the subject while the acting party is recorded in the §4.1
                //"act" claim (act is null for impersonation, so no act claim is emitted then). The
                //authorization seam returns the effective subject and scope.
                IssuanceContext issuance = new()
                {
                    Registration = registration,
                    Context = context,
                    IssuerUri = issuerUri,
                    Subject = authorization.Subject,
                    Scope = authorization.Scope,
                    ClientId = registration.ClientId,
                    GrantType = WellKnownGrantTypes.TokenExchange,
                    IssuedAt = now,
                    Act = act,

                    //RFC 8693 §2.1.1: when the authorization seam shaped the issued token for explicit
                    //target(s), those become the access token's aud verbatim — the scope→audience
                    //resolver is bypassed. An empty override leaves Audience null so the resolver runs.
                    Audience = authorization.Audience is { Count: > 0 } ? authorization.Audience : null,

                    //RFC 9449 §6.1: a subject token bound key that a presented proof matched (or a
                    //fresh key an unbound subject token's proof opted into) sender-constrains the
                    //issued access token; the CnfClaimContributor stamps cnf from this slot.
                    Confirmation = tokenConfirmation
                };

                IReadOnlyList<TokenProducer> producers =
                    oauth.TokenProducers.Count > 0
                        ? oauth.TokenProducers
                        : DefaultTokenProducers;

                OidcClaims? preResolvedOidcClaims = await PreResolveOidcClaimsAsync(
                    server, issuance, ct).ConfigureAwait(false);

                (TokenIssuanceResult? issuanceResult, ServerHttpResponse? issuanceFailure) =
                    await IssueTokensAsync(
                        server, registration, context, issuance, producers, preResolvedOidcClaims, now, ct)
                        .ConfigureAwait(false);
                if(issuanceFailure is not null)
                {
                    return (null, issuanceFailure);
                }

                TokenIssuanceResult issued = issuanceResult!;
                Dictionary<string, string> issuedTokens = issued.IssuedTokens;

                if(!issuedTokens.TryGetValue(WellKnownTokenTypes.AccessToken, out string? accessToken))
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "No access token was produced for the token-exchange grant."));
                }

                int expiresIn = issued.IssuedAudits.TryGetValue(
                    WellKnownTokenTypes.AccessToken, out IssuedTokenAudit? accessAudit)
                    ? (int)(accessAudit.ExpiresAt - accessAudit.IssuedAt).TotalSeconds
                    : 0;

                //RFC 8693 §2.2.1: access_token, issued_token_type, token_type, expires_in, scope.
                //issued_token_type is the wire URI of the type the authorization seam decided.
                //token_type is DPoP (RFC 9449 §6.1) when the subject token's binding (or a fresh
                //proof under an unbound one) sender-constrained this issuance, else the RFC 6750
                //Bearer default. The response is stateless and uncacheable.
                string tokenTypeWireName = tokenConfirmation is { IsEmpty: false }
                    ? WellKnownAuthenticationSchemes.DPoP
                    : WellKnownAuthenticationSchemes.Bearer;

                StringBuilder sb = JsonAppender.Rent();
                string responseJson;
                try
                {
                    _ = sb.Append('{');
                    bool first = true;
                    JsonAppender.AppendStringField(sb, WellKnownTokenTypes.AccessToken, accessToken, ref first);
                    JsonAppender.AppendStringField(sb, OAuthRequestParameterNames.IssuedTokenType,
                        TokenTypeNames.GetName(authorization.IssuedTokenType), ref first);
                    JsonAppender.AppendStringField(sb, "token_type",
                        tokenTypeWireName, ref first);
                    JsonAppender.AppendInt64Field(sb, "expires_in", expiresIn, ref first);
                    JsonAppender.AppendStringField(sb, OAuthRequestParameterNames.Scope, authorization.Scope, ref first);
                    _ = sb.Append('}');
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
    /// Default lifetime of an Identity Assertion JWT Authorization Grant when the registration sets no
    /// <see cref="WellKnownTokenTypes.IdJag"/> entry in <see cref="ClientRecord.TokenLifetimes"/>. A
    /// JAG is short-lived — it is presented once at the Resource Authorization Server and not stored —
    /// matching the 5-minute example in draft-ietf-oauth-identity-assertion-authz-grant-04
    /// (21 May 2026) §4.3.4.
    /// </summary>
    private static TimeSpan DefaultIdJagLifetime { get; } = TimeSpan.FromMinutes(5);


    /// <summary>
    /// The ID-JAG claim names the mint controls (the §3.1 core set plus the grant-shaped claims). A
    /// <see cref="TokenExchange.TokenExchangeAuthorization.AdditionalClaims"/> entry whose key is one of
    /// these is ignored, so application-supplied identity claims can never override the grant semantics.
    /// </summary>
    private static HashSet<string> ReservedIdJagClaimNames { get; } = new(StringComparer.Ordinal)
    {
        WellKnownJwtClaimNames.Iss,
        WellKnownJwtClaimNames.Sub,
        WellKnownJwtClaimNames.Aud,
        WellKnownJwtClaimNames.ClientId,
        WellKnownJwtClaimNames.Jti,
        WellKnownJwtClaimNames.Iat,
        WellKnownJwtClaimNames.Exp,
        WellKnownJwtClaimNames.Scope,
        WellKnownJwtClaimNames.Cnf,
        WellKnownJwtClaimNames.Tenant,
        WellKnownJwtClaimNames.AudienceTenant,
        WellKnownJwtClaimNames.AudienceSubject,
        WellKnownJwtClaimNames.SubId,
        WellKnownJwtClaimNames.Act,
        WellKnownJwtClaimNames.MayAct,
        OAuthRequestParameterNames.Resource,
        OAuthRequestParameterNames.AuthorizationDetails
    };


    /// <summary>
    /// Mints an opaque Refresh Token and writes the
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.2">RFC 8693 §2.2</see> Token Exchange
    /// response that carries it, per draft-ietf-oauth-identity-assertion-authz-grant-04 §4.5 — the SAML 2.0
    /// to OAuth protocol transition: a client exchanges a SAML assertion for a Refresh Token, which it
    /// later uses as a §4.3.2 <c>subject_token</c> to mint an ID-JAG without a new SSO round trip.
    /// Reached from the Token Exchange grant when the authorization seam set
    /// <see cref="TokenExchange.TokenExchangeAuthorization.IssuedTokenType"/> to
    /// <see cref="TokenType.RefreshToken"/>.
    /// </summary>
    /// <remarks>
    /// The application is the trust authority for the §4.5 MUST that the SAML Audience / SPEntityID maps
    /// to the authenticated client — it enforces that in its
    /// <see cref="ValidateTokenExchangeTokenDelegate"/> before authorizing the exchange (the
    /// library never parses SAML). This branch mints an opaque Refresh Token through the same identifier
    /// seam and <see cref="Server.States.ServerRefreshTokenIssuedState"/> storage the authorization-code
    /// and refresh-rotation flows use, so a later <c>refresh_token</c> grant or §4.3.2 refresh-token
    /// subject-token exchange can validate it, and returns it in the <c>access_token</c> field with
    /// <c>issued_token_type</c> the refresh_token URN and <c>token_type</c> <c>N_A</c>. Per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-5">RFC 9449 §5</see> the minted Refresh
    /// Token itself carries <paramref name="confirmation"/> when the subject token's binding (or a
    /// fresh proof under an unbound one) sender-constrained this issuance, so a later
    /// <c>refresh_token</c> grant enforces the same binding the code grant already does.
    /// </remarks>
    /// <param name="server">The endpoint server.</param>
    /// <param name="registration">The authenticated client requesting the exchange.</param>
    /// <param name="context">The per-request context bag.</param>
    /// <param name="authorization">The authorization seam's verdict, which shapes the minted Refresh Token's subject and scope.</param>
    /// <param name="confirmation">
    /// The RFC 9449 §6.1 confirmation the exchange established for this issuance (the subject token's
    /// bound key matched by a presented proof, or a fresh key an unbound subject token's proof opted
    /// into), or <see langword="null"/> when the issuance is unbound.
    /// </param>
    /// <param name="issuerUri">The resolved issuer identifier.</param>
    /// <param name="now">The current instant.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The mint response, or the early-exit failure response.</returns>
    private static async ValueTask<(FlowInput? Input, ServerHttpResponse? EarlyExit)> BuildRefreshTokenExchangeResponseAsync(
        EndpointServer server,
        ClientRecord registration,
        ExchangeContext context,
        TokenExchange.TokenExchangeAuthorization authorization,
        ConfirmationMethod? confirmation,
        Uri issuerUri,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var oauth = server.OAuth();

        //§4.5: a Refresh Token is an opaque random string (not a JWT), minted through the identifier seam
        //(the application owns the entropy + provenance) and stored as ServerRefreshTokenIssuedState.
        string refreshToken = await oauth.GenerateIdentifierAsync!(
            WellKnownIdentifierPurposes.OAuthRefreshToken, context, cancellationToken).ConfigureAwait(false);
        DateTimeOffset refreshExpiresAt = now + context.RefreshTokenLifetime;

        if(oauth.SaveFlowStateAsync is not null)
        {
            string refreshFlowId = await oauth.GenerateIdentifierAsync!(
                WellKnownIdentifierPurposes.OAuthRefreshFlowId, context, cancellationToken).ConfigureAwait(false);
            ServerRefreshTokenIssuedState refreshState = new()
            {
                FlowId = refreshFlowId,

                //This record is the grant's own root: no code precedes it, so its own flow id
                //is the grant key every later rotation of it carries forward.
                GrantFlowId = refreshFlowId,
                ExpectedIssuer = issuerUri.OriginalString,
                EnteredAt = now,
                ExpiresAt = refreshExpiresAt,
                Kind = FlowKind.AuthCodeServer,
                ClientId = registration.ClientId,
                RefreshToken = refreshToken,
                IssuedAt = now,
                SubjectId = authorization.Subject,
                Scope = authorization.Scope,
                OriginatingGrantType = WellKnownGrantTypes.TokenExchange,

                //RFC 8707 §2.2: the target(s) the authorization seam shaped this exchange for
                //(TokenExchangeAuthorization.Audience — the request's resource/audience per §2.1.1)
                //become the refresh token's own granted resource set, so a later refresh_token
                //grant redeeming this token can narrow against the real grant via
                //ResolveEffectiveResource instead of failing closed with "none were granted".
                //Audience is RFC 8693's own field — a logical name (§2.1's audience parameter),
                //not necessarily an RFC 8707 §2 absolute URI, and it MAY itself contain spaces
                //(the authorization seam's own shaping, not this library's parsed indicators).
                //Space-joining it into the space-delimited Resource slot unparsed would corrupt
                //that slot: ParseResourceIndicators/ResolveEffectiveResource would later split a
                //single spacey audience name into several bogus "indicators". The carry is
                //therefore gated: it populates Resource ONLY when every audience entry already IS
                //a well-formed, whitespace-free absolute resource indicator
                //(IsAbsoluteResourceIndicatorUri); otherwise Resource stays null — the same
                //fail-closed outcome as "nothing was granted" — rather than smuggling a malformed
                //value into a slot every downstream reader assumes is clean.
                Resource = authorization.Audience is { Count: > 0 } audienceEntries
                    && audienceEntries.All(IsAbsoluteResourceIndicatorUri)
                    ? string.Join(' ', audienceEntries)
                    : null,

                Confirmation = confirmation
            };
            await oauth.SaveFlowStateAsync(
                registration.TenantId, refreshFlowId, refreshState, stepCount: 0, context, cancellationToken).ConfigureAwait(false);
        }

        int expiresIn = (int)context.RefreshTokenLifetime.TotalSeconds;

        //§4.5: issued_token_type = the refresh_token URN; access_token carries the Refresh Token (Token
        //Exchange always returns the issued token in access_token); token_type = N_A; expires_in; scope.
        StringBuilder sb = JsonAppender.Rent();
        string responseJson;
        try
        {
            _ = sb.Append('{');
            bool first = true;
            JsonAppender.AppendStringField(sb, WellKnownTokenTypes.AccessToken, refreshToken, ref first);
            JsonAppender.AppendStringField(sb, OAuthRequestParameterNames.IssuedTokenType,
                TokenTypeNames.GetName(TokenType.RefreshToken), ref first);
            JsonAppender.AppendStringField(sb, "token_type",
                WellKnownTokenTypeIdentifiers.NotApplicable, ref first);
            JsonAppender.AppendInt64Field(sb, "expires_in", expiresIn, ref first);
            if(!string.IsNullOrEmpty(authorization.Scope))
            {
                JsonAppender.AppendStringField(sb, OAuthRequestParameterNames.Scope, authorization.Scope, ref first);
            }

            _ = sb.Append('}');
            responseJson = sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }

        return (null, ServerHttpResponse.Ok(responseJson, WellKnownMediaTypes.Application.Json)
            .WithHeader(WellKnownHttpHeaderNames.CacheControl, WellKnownCacheControlValues.NoStore));
    }


    /// <summary>
    /// Mints an Identity Assertion JWT Authorization Grant (ID-JAG) and writes the
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.2">RFC 8693 §2.2</see> Token
    /// Exchange response that carries it, per draft-ietf-oauth-identity-assertion-authz-grant-04 §3.1
    /// (claim set) and §4.3.4 (response). Reached from the Token Exchange grant when the authorization
    /// seam set <see cref="TokenExchange.TokenExchangeAuthorization.IssuedTokenType"/> to
    /// <see cref="TokenType.IdJag"/>.
    /// </summary>
    /// <remarks>
    /// The JAG is built from the precise §3.1 claim set (no access-token / OIDC claim contribution
    /// applies), signed with the IdP's <see cref="KeyUsageContext.IdTokenIssuance"/> key — a JAG is
    /// "issued and signed by an IdP Authorization Server similar to an ID Token" (§3) — and returned in
    /// the <c>access_token</c> field with <c>issued_token_type</c> the id-jag URN and <c>token_type</c>
    /// <c>N_A</c> (§4.3.4). The crypto seams are the same the access-token producers use; only the claim
    /// shaping and response assembly differ.
    /// </remarks>
    /// <param name="server">The endpoint server.</param>
    /// <param name="registration">The authenticated client requesting the exchange.</param>
    /// <param name="context">The per-request context bag.</param>
    /// <param name="exchangeRequest">The shape-validated Token Exchange request.</param>
    /// <param name="authorization">The authorization seam's verdict, which shapes the §3.1 claim set.</param>
    /// <param name="act">
    /// The <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see> <c>act</c>
    /// claim this exchange computed from the validated <c>actor_token</c> and the subject token's own
    /// prior chain, or <see langword="null"/> for an impersonation exchange.
    /// <see cref="TokenExchange.TokenExchangeAuthorization.Actor"/> overrides it when the seam shapes
    /// the actor itself (§9.7 leaves the derivation to the profile).
    /// </param>
    /// <param name="confirmation">
    /// The RFC 9449 §6.1 confirmation the Token Exchange grant's shared DPoP validation established
    /// for this issuance (the subject token's bound key matched by a presented proof, or a fresh key an
    /// unbound subject token's proof opted into), or <see langword="null"/> when the issuance is
    /// unbound. Stamped onto the JAG's <c>cnf</c> claim per §9.8.1.1.
    /// </param>
    /// <param name="issuerUri">The resolved IdP issuer identifier.</param>
    /// <param name="now">The current instant.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The mint response, or the early-exit failure response.</returns>
    private static async ValueTask<(FlowInput? Input, ServerHttpResponse? EarlyExit)> BuildIdJagMintResponseAsync(
        EndpointServer server,
        ClientRecord registration,
        ExchangeContext context,
        TokenExchange.TokenExchangeRequest exchangeRequest,
        TokenExchange.TokenExchangeAuthorization authorization,
        IReadOnlyDictionary<string, object>? act,
        ConfirmationMethod? confirmation,
        Uri issuerUri,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var oauth = server.OAuth();

        //The id-jag mint is gated per-client by the OAuthIdJag capability. The authorization seam
        //selecting the id-jag issued type for a client that lacks the capability is an AS
        //misconfiguration → server_error, mirroring the producer-walk capability filter.
        IReadOnlySet<CapabilityIdentifier>? resolved = context.ResolvedCapabilities;
        if(resolved is null || !resolved.Contains(WellKnownCapabilityIdentifiers.OAuthIdJag))
        {
            return (null, ServerHttpResponse.ServerError(
                OAuthErrors.ServerError,
                "The authorization seam selected the id-jag issued type but the client lacks the id-jag capability."));
        }

        //§3.1 aud / §4.3: the audience is the Resource Authorization Server's issuer identifier. The
        //authorization seam's shaped audience wins — §4.3 lets the IdP resolve an implementation-
        //specific audience value (e.g. a URN) to the RS issuer it stamps into aud — otherwise the
        //request's REQUIRED audience is used verbatim.
        string? resourceAudience =
            authorization.Audience is { Count: > 0 } shaped ? shaped[0]
            : exchangeRequest.Audience.Count > 0 ? exchangeRequest.Audience[0]
            : null;
        if(string.IsNullOrEmpty(resourceAudience))
        {
            //§4.3.4.3: an ID-JAG mint failure (audience validation) is invalid_grant.
            return (null, ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidGrant,
                "The id-jag audience could not be resolved to a Resource Authorization Server identifier."));
        }

        //§3.1 client_id: the client at the Resource Authorization Server that will act on behalf of the
        //subject. It MAY differ from the requesting client (an independent client relationship in the
        //resource trust domain); it defaults to the requesting client when the seam names none.
        string resourceClientId = authorization.ResourceClientId ?? registration.ClientId;

        //§3.1 jti: a unique identifier for this grant.
        string jti = await oauth.GenerateIdentifierAsync!(
            WellKnownIdentifierPurposes.OAuthJti, context, cancellationToken).ConfigureAwait(false);

        TimeSpan lifetime = registration.GetTokenLifetime(WellKnownTokenTypes.IdJag) ?? DefaultIdJagLifetime;
        DateTimeOffset expiresAt = now.Add(lifetime);

        //§3.1 iss: the IdP Authorization Server issuer identifier. RFC 8414 §3 requires exact-string
        //equality — preserve the resolved issuer verbatim (path component, port, tenant segment).
        string issuerValue = issuerUri.OriginalString;

        KeyId signingKeyId = await SigningKeySelection.ResolveSigningKeyIdAsync(
            server, registration, KeyUsageContext.IdTokenIssuance, context, cancellationToken).ConfigureAwait(false);
        PrivateKeyMemory? signingKey = await oauth.Cryptography.SigningKeyResolver!(
            signingKeyId, registration.TenantId, context, cancellationToken).ConfigureAwait(false);
        if(signingKey is null)
        {
            return (null, ServerHttpResponse.ServerError(
                OAuthErrors.ServerError, "Signing key unavailable for the id-jag grant."));
        }

        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(signingKey.Tag);

        //§3.1 / §4.3.3: the IdP MUST include the granted resource and authorization_details (if any) in
        //the JAG. RFC 8707 / §3.1 allow a single resource URI as a JSON string or multiple as a JSON
        //array; authorization_details is a JSON array of authorization detail objects.
        Dictionary<string, object>? extraClaims = null;
        if(authorization.Resource is { Count: > 0 } grantedResources)
        {
            extraClaims ??= new(StringComparer.Ordinal);
            extraClaims[OAuthRequestParameterNames.Resource] = grantedResources.Count == 1
                ? grantedResources[0]
                : grantedResources;
        }

        if(authorization.AuthorizationDetailsClaim is { Count: > 0 } grantedDetails)
        {
            extraClaims ??= new(StringComparer.Ordinal);
            extraClaims[OAuthRequestParameterNames.AuthorizationDetails] = grantedDetails;
        }

        //§3.1 / §6: a multi-tenant IdP includes the tenant claim so the subject identifier scopes as
        //iss + tenant + sub; the Resource Authorization Server's own tenant (aud_tenant) and subject
        //(aud_sub) are included when the IdP knows them, for subject resolution at that server. Each is
        //emitted only when the authorization seam supplied it (whether the issuer is multi-tenant is the
        //application's policy decision, not the library's).
        if(!string.IsNullOrEmpty(authorization.Tenant))
        {
            extraClaims ??= new(StringComparer.Ordinal);
            extraClaims[WellKnownJwtClaimNames.Tenant] = authorization.Tenant;
        }

        if(!string.IsNullOrEmpty(authorization.AudienceTenant))
        {
            extraClaims ??= new(StringComparer.Ordinal);
            extraClaims[WellKnownJwtClaimNames.AudienceTenant] = authorization.AudienceTenant;
        }

        if(!string.IsNullOrEmpty(authorization.AudienceSubject))
        {
            extraClaims ??= new(StringComparer.Ordinal);
            extraClaims[WellKnownJwtClaimNames.AudienceSubject] = authorization.AudienceSubject;
        }

        //§3.2: the saml-nameid sub_id identifies the End-User in the Resource Authorization Server's SAML
        //SSO subject namespace (the same subject as sub). The carrier renders the §3.2.1 object with each
        //optional member included exactly when present; the runtime Dictionary serialises as a nested JSON
        //object (the same shape the cnf claim uses).
        if(authorization.SubjectIdentifier is { } subjectIdentifier)
        {
            extraClaims ??= new(StringComparer.Ordinal);
            extraClaims[WellKnownJwtClaimNames.SubId] = subjectIdentifier.ToClaimObject();
        }

        //§3.1: "act: OPTIONAL - Actor claim as defined in Section 4.1 of [RFC8693]. When present, this
        //claim identifies the actor that is acting on behalf of the subject (sub)." §4.3/§9.7 define no
        //derivation for it, leaving that to a profile; this server's is to record the acting party the
        //exchange established — the chain built from the validated actor_token with the subject token's
        //prior actors already nested beneath it, carried verbatim so the least recent stays deepest per
        //§4.1. The authorization seam's own Actor wins when it shapes one. RFC 8693 §1.1 keeps this
        //delegation, not impersonation: sub remains the resource owner and act names who acts for it.
        IReadOnlyDictionary<string, object>? actorClaim = authorization.Actor ?? act;
        if(actorClaim is not null)
        {
            extraClaims ??= new(StringComparer.Ordinal);
            extraClaims[WellKnownJwtClaimNames.Act] = actorClaim;
        }

        //RFC 8693 §4.4: a may_act claim states that a named party "is authorized to become the actor and
        //act on behalf of another party" — here, which client may redeem this grant and become the actor
        //of the access token it yields. The IdP states it through the authorization seam; the Resource
        //Authorization Server enforces it on redemption.
        if(authorization.AuthorizedActor is { } authorizedActorClaim)
        {
            extraClaims ??= new(StringComparer.Ordinal);
            extraClaims[WellKnownJwtClaimNames.MayAct] = authorizedActorClaim;
        }

        //§3.1: the ID-JAG MAY also carry ID Token identity claims (auth_time, acr, amr, email, ...). The
        //authorization seam supplies them; reserved grant-controlled names are skipped so an application
        //claim can never override the claims the mint owns.
        if(authorization.AdditionalClaims is { Count: > 0 } additionalClaims)
        {
            foreach(KeyValuePair<string, object> additionalClaim in additionalClaims)
            {
                if(ReservedIdJagClaimNames.Contains(additionalClaim.Key))
                {
                    continue;
                }

                extraClaims ??= new(StringComparer.Ordinal);
                extraClaims[additionalClaim.Key] = additionalClaim.Value;
            }
        }

        //§9.8.1.1: a validated DPoP proof binds the grant — cnf carries the proof's JWK SHA-256
        //thumbprint as jkt (RFC 9449 §6.1), which the Resource Authorization Server compares by string
        //equality against the proof presented on redemption.
        if(confirmation is { JwkThumbprint: { } boundThumbprint })
        {
            extraClaims ??= new(StringComparer.Ordinal);
            extraClaims[WellKnownJwtClaimNames.Cnf] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [WellKnownJwtClaimNames.JwkThumbprint] = boundThumbprint
            };
        }

        JwtHeader header = JwtHeader.ForIdJag(algorithm, signingKeyId.Value);
        JwtPayload payload = JwtPayload.ForIdJag(
            issuer: issuerValue,
            subject: authorization.Subject,
            audience: resourceAudience,
            clientId: resourceClientId,
            jti: jti,
            issuedAt: now,
            expiresAt: expiresAt,
            scope: authorization.Scope,
            claims: extraClaims);

        UnsignedJwt unsigned = new(header, payload);
        using JwsMessage jws = await unsigned.SignAsync(
            signingKey,
            oauth.Codecs.JwtHeaderSerializer!,
            oauth.Codecs.JwtPayloadSerializer!,
            oauth.Codecs.Encoder!,
            oauth.MemoryPool!,
            cancellationToken).ConfigureAwait(false);

        string compactJws = JwsSerialization.SerializeCompact(jws, oauth.Codecs.Encoder!);
        int expiresIn = (int)lifetime.TotalSeconds;

        //§4.3.4: issued_token_type = the id-jag URN; access_token = the JAG (Token Exchange requires
        //the access_token field even though this is not an OAuth access token); token_type = N_A;
        //expires_in (RECOMMENDED); scope (included when granted). The response is uncacheable.
        StringBuilder sb = JsonAppender.Rent();
        string responseJson;
        try
        {
            _ = sb.Append('{');
            bool first = true;
            JsonAppender.AppendStringField(sb, WellKnownTokenTypes.AccessToken, compactJws, ref first);
            JsonAppender.AppendStringField(sb, OAuthRequestParameterNames.IssuedTokenType,
                TokenTypeNames.GetName(TokenType.IdJag), ref first);
            JsonAppender.AppendStringField(sb, "token_type",
                WellKnownTokenTypeIdentifiers.NotApplicable, ref first);
            JsonAppender.AppendInt64Field(sb, "expires_in", expiresIn, ref first);

            //§4.3.4: scope is OPTIONAL when the granted scope is identical to the requested scope and
            //REQUIRED otherwise. Including it whenever it is non-empty covers the identical case; the
            //differs check additionally conveys a granted scope that narrowed to empty.
            bool scopeDiffersFromRequest = !string.Equals(
                authorization.Scope ?? string.Empty, exchangeRequest.Scope ?? string.Empty, StringComparison.Ordinal);
            if(!string.IsNullOrEmpty(authorization.Scope) || scopeDiffersFromRequest)
            {
                JsonAppender.AppendStringField(sb, OAuthRequestParameterNames.Scope, authorization.Scope ?? string.Empty, ref first);
            }

            //§4.3.4: authorization_details is included only when the IdP granted details that differ
            //from the request or modified them; the seam pre-serialises that value as a JSON array.
            if(!string.IsNullOrEmpty(authorization.AuthorizationDetailsResponseJson))
            {
                JsonAppender.AppendRawField(
                    sb, OAuthRequestParameterNames.AuthorizationDetails, authorization.AuthorizationDetailsResponseJson, ref first);
            }

            _ = sb.Append('}');
            responseJson = sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }

        return (null, ServerHttpResponse.Ok(responseJson, WellKnownMediaTypes.Application.Json)
            .WithHeader(WellKnownHttpHeaderNames.CacheControl, WellKnownCacheControlValues.NoStore));
    }


    /// <summary>
    /// Builds the JWT Bearer authorization-grant candidate
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7523#section-2.1">RFC 7523 §2.1</see> /
    /// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3.1">§3.1</see>) on the shared token
    /// endpoint URL. Stateless: the client presents an <c>assertion</c> (a single JWT) the
    /// application's <see cref="AuthorizationServerIntegration.ValidateJwtBearerAssertionAsync"/> seam
    /// validates as the trust authority — signature (§3 rule 9), trusted <c>iss</c> (rule 1), the
    /// <c>aud</c>-names-this-AS check (rule 3, which only the application can make), and the
    /// <c>exp</c>/<c>nbf</c> window (rules 4–5) — and shapes the issued token from; the configured
    /// token producers mint the access token directly into the response — no flow state.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Client AUTHENTICATION is OPTIONAL for this grant (§2.1 / §3.1): the assertion itself is the
    /// authorization grant, expressing an existing trust relationship without a user-approval step.
    /// However §3.1 requires that "if client credentials are present in the request, the authorization
    /// server MUST validate them," so when the request carries credentials the endpoint runs
    /// <see cref="AuthorizationServerIntegration.ValidateClientCredentialsAsync"/> and rejects a bad
    /// one with <c>401 invalid_client</c>. Presented credentials are never silently ignored: if the
    /// request carries credentials but the client-authentication seam is not configured, the request is
    /// refused with <c>401 invalid_client</c> rather than proceeding as anonymous (proceeding would be a
    /// §3.1 MUST bypass). An anonymous request — one carrying no credentials at all — proceeds.
    /// </para>
    /// <para>
    /// Client IDENTIFICATION is nonetheless required even though authentication is optional: the
    /// shipped RFC 9068 access-token producer needs a <c>client_id</c> (<see cref="IssuanceContext.ClientId"/>
    /// is required), so a request whose tenant resolves no <see cref="ClientRecord"/> is refused with
    /// <c>401 invalid_client</c>.
    /// </para>
    /// <para>
    /// A <see langword="null"/> assertion-validation result is RFC 7523 §3.1's mandated
    /// <c>invalid_grant</c> (NOT <c>invalid_request</c>): the §3 processing failed, so the grant is
    /// invalid. The §5.1 token response is a plain RFC 6749 token response — <c>access_token</c>,
    /// <c>token_type</c> Bearer, <c>expires_in</c>, <c>scope</c> — with no <c>issued_token_type</c>
    /// (that is a token-exchange §2.2.1 field, not part of this grant).
    /// </para>
    /// </remarks>
    //RFC 7523's jwt-bearer grant does not consume the RFC 8707 resource parameter — its audience
    //is the authorization seam's own JwtBearerGrant.Audience decision (assigned to
    //IssuanceContext.Audience below), the same RFC 8693-style target-binding shape the token
    //exchange grant uses, not a client-supplied resource indicator.
    private static EndpointCandidate BuildJwtBearer() =>
        new()
        {
            Name = WellKnownEndpointNames.JwtBearerToken,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownCapabilityIdentifiers.OAuthJwtBearer,
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,
            //DiscoveryMetadataKey null — the grant shares the token endpoint URL.

            //Disjointness vs the other grants is enforced by the grant_type filter, exactly as the
            //client_credentials, refresh, and token-exchange matchers do.
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
                    || !string.Equals(grantType, WellKnownGrantTypes.JwtBearer, StringComparison.Ordinal))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
            },

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.RequestServer!;
                var oauth = server.OAuth();

                //RFC 9068 constraint: a JWT access token requires a client_id, and IssuanceContext.ClientId
                //is required, so the client MUST be identified even though authentication is optional (§2.1).
                //A request whose tenant resolves no registration cannot stamp a conformant token.
                ClientRecord? registration = context.ClientRegistration;
                if(registration is null)
                {
                    return (null, ClientAuthenticationFailureResponse(
                        context.IncomingRequest, "Client identification is required for the jwt-bearer grant."));
                }

                //RFC 7523 §3.1 composed with draft-ietf-oauth-client-id-metadata-document-02 §8.2
                //(CIMD-049): "if client credentials are present in the request, the authorization
                //server MUST validate them." Client authentication is OPTIONAL for this grant (the
                //assertion is the grant), so a credential-less request from a client whose effective
                //registration declares no token_endpoint_auth_method (or declares None) proceeds as
                //anonymous. Presence is an Authorization header (client_secret_basic /
                //private_key_jwt / mTLS) OR a client_secret / client_assertion form field; the seam owns
                //the method and the comparison. When credentials ARE present they MUST be validated:
                //if the client-authentication seam is not configured, the request cannot proceed as
                //anonymous (that would silently ignore presented credentials, a §3.1 MUST bypass), so it
                //is refused with 401 invalid_client. A present-but-invalid credential is 401 invalid_client.
                //When credentials are ABSENT and the effective (possibly CIMD-materialized) registration
                //declares a non-None token_endpoint_auth_method, the client is confidential and CIMD-049's
                //"any communication with the authorization server MUST include client authentication of
                //the registered type" governs: RequireClientAuthenticationIfDeclaredAsync refuses the
                //request with 401 invalid_client, fail-closed. The two branches are disjoint, so
                //credentials are never validated twice.
                if(HasClientCredentials(context.IncomingRequest, fields))
                {
                    //Identification of an optional client_id form field before authentication:
                    //a field that names another registration is refused invalid_client here, never
                    //forwarded into the authentication seam.
                    ServerHttpResponse? jwtBearerIdentificationFailure =
                        RefuseUnidentifiedClient(registration, fields, context.IncomingRequest);
                    if(jwtBearerIdentificationFailure is not null)
                    {
                        return (null, jwtBearerIdentificationFailure);
                    }

                    if(oauth.ValidateClientCredentialsAsync is null)
                    {
                        return (null, ClientAuthenticationFailureResponse(
                            context.IncomingRequest,
                            "Client credentials were presented but client authentication is not configured for this authorization server."));
                    }

                    bool isClientAuthenticated = await oauth.ValidateClientCredentialsAsync(
                        context.IncomingRequest, fields, registration, context, ct).ConfigureAwait(false);
                    if(!isClientAuthenticated)
                    {
                        return (null, ClientAuthenticationFailureResponse(
                            context.IncomingRequest, "Client authentication failed."));
                    }
                }
                else
                {
                    ServerHttpResponse? declaredAuthFailure = await RequireClientAuthenticationIfDeclaredAsync(
                        oauth, context.IncomingRequest, fields, registration, context, ct).ConfigureAwait(false);
                    if(declaredAuthFailure is not null)
                    {
                        return (null, declaredAuthFailure);
                    }
                }

                //RFC 7523 §2.1: the assertion parameter is REQUIRED and "MUST contain a single JWT."
                if(!fields.TryGetValue(OAuthRequestParameterNames.Assertion, out string? assertion)
                    || string.IsNullOrEmpty(assertion))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "The assertion parameter is required and must contain a single JWT."));
                }

                //RFC 7523 §2.1 / RFC 7521 §4.1: scope is OPTIONAL and indicates the requested scope.
                string? requestedScope = null;
                if(fields.TryGetValue(OAuthRequestParameterNames.Scope, out string? scopeValue)
                    && !string.IsNullOrWhiteSpace(scopeValue))
                {
                    requestedScope = scopeValue;
                }

                Uri issuerUri;
                try
                {
                    issuerUri = oauth.ResolveIssuerAsync is not null
                        ? (await oauth.ResolveIssuerAsync(registration, context, ct)
                            .ConfigureAwait(false))!
                        : await DefaultIssuerResolver.ResolveAsync(registration, context, ct)
                            .ConfigureAwait(false);
                }
                catch(InvalidOperationException ex)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, ex.Message));
                }

                DateTimeOffset now = server.TimeProvider.GetUtcNow();

                //RFC 9449 §5: "This is applicable for all access token requests regardless of grant
                //type ... and extension grants such as the JWT authorization grant [RFC7523]" — this
                //grant runs the SAME validation the authorization-code grant's token endpoint runs,
                //with the SAME expectedThumbprint=null (the binding is being established here). It
                //runs BEFORE the assertion-validation seam below: the assertion's jti is single-use
                //(RFC 7523 §3 rule 7 / JtiReplayGuard consumes it), so a use_dpop_nonce challenge
                //(RFC 9449 §8) or a rejected proof MUST NOT consume it — the caller retries the same
                //assertion once it has satisfied the challenge.
                bool dpopRequired = ClientPolicyProfiles.RequiresDpop(registration.Profile);
                DpopValidationOutcome dpopOutcome = await DpopTokenEndpointValidation.ValidateAsync(
                    server, context, registration, issuerUri, now,
                    expectedThumbprint: null, dpopRequired, ct).ConfigureAwait(false);
                if(!dpopOutcome.IsSuccess)
                {
                    return (null, dpopOutcome.FailureResponse!);
                }

                //RFC 7523 §3: validate the assertion JWT against the processing rules. The application
                //is the trust authority; the builder guarantees the seam is wired. A null result is a
                //§3 failure — invalid signature (rule 9), untrusted iss (rule 1), an aud that does not
                //name this AS (rule 3), an expired/not-yet-valid window (rules 4–5), or any other JWT
                //defect. Per §3.1 the error MUST be invalid_grant (NOT invalid_request).
                JwtBearerGrant? grant = await oauth.ValidateJwtBearerAssertionAsync!(
                    assertion, requestedScope, registration, context, ct).ConfigureAwait(false);
                if(grant is null)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidGrant, "The JWT assertion is not valid."));
                }

                //RFC 7523 §3 (rule 7): when the validated assertion carries a jti (an ID-JAG always does,
                //§3.1), apply the shared (issuer, jti) replay defense — the same JtiReplayGuard the JAR and
                //DPoP paths use, governed by JtiReplayPolicy and keyed on the assertion's own iss so
                //independent IdPs are isolated. The read and first-use record happen as one unit; Required
                //fails closed when no store is wired.
                if(grant.Jti is { } assertionJti
                    && grant.Issuer is { } assertionIssuer
                    && grant.Expiration is { } assertionExpiry)
                {
                    //RFC 7523 §3 rule 7: the recorded jti is retained "for the length of time for
                    //which the JWT would be considered valid based on the applicable exp instant" —
                    //the application's ValidateJwtBearerAssertionDelegate is the trust authority for
                    //that instant (§3 rules 4-5) and the library cannot read its timing tolerance, so
                    //the recorded window floors at the library's own clock-skew tolerance, never
                    //shorter than what the JAR and private_key_jwt callers honour.
                    JtiReplayOutcome jtiOutcome = await JtiReplayGuard.ConsultAsync(
                        server, context, registration.TenantId,
                        assertionIssuer, assertionJti, assertionExpiry + context.ClockSkewTolerance, ct).ConfigureAwait(false);

                    ServerHttpResponse? jtiFailure = jtiOutcome switch
                    {
                        JtiReplayOutcome.FirstUse => null,
                        JtiReplayOutcome.Replayed => ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidGrant, "The assertion jti has been seen previously (replay).")
                            .WithHeader(WellKnownHttpHeaderNames.CacheControl, WellKnownCacheControlValues.NoStore),
                        JtiReplayOutcome.Unacceptable => ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidGrant,
                            "The assertion jti exceeds the length the replay guard can track."),
                        JtiReplayOutcome.StoreUnavailable => ServerHttpResponse.ServerError(
                            OAuthErrors.ServerError,
                            "Assertion jti replay defense is required by policy but no jti store is configured."),

                        _ => null
                    };
                    if(jtiFailure is not null)
                    {
                        return (null, jtiFailure);
                    }
                }

                //RFC 8693 §4.1/§4.4: decide the delegation the redeemed access token records — the act
                //claim composed from the grant's own chain and the redeeming client — and enforce the
                //grant's may_act statement about which client may become that actor. Stamping act here
                //is this server's profile decision under §1.1's "at the discretion of the authorization
                //server" (ID-JAG §4.3/§9.7 define no actor processing; the identity-chaining redemption
                //leg, draft-ietf-oauth-identity-chaining-16 §2.4, never mentions act) — and having
                //exercised it, §4.4's authorized-actor statement binds. The refusal is the RFC 7523
                //§3.1 invalid_grant this endpoint answers every grant defect with, decided before the
                //granted authorization_details reach the context so a refused redemption grants nothing.
                IdJagActorDecision actorDecision = IdJagActorDecision.Evaluate(
                    grant.Act, grant.MayAct, registration.ClientId, grant.Subject, issuerUri.OriginalString);
                if(actorDecision.IsRefused)
                {
                    string actorRefusal = actorDecision.Kind switch
                    {
                        IdJagActorDecisionKind.RefuseUnauthorizedActor => "The client is not authorized to act for the subject of this authorization grant.",
                        IdJagActorDecisionKind.RefuseMalformedActor => "The authorization grant's act claim does not identify an actor.",
                        IdJagActorDecisionKind.NoDelegation or
                        IdJagActorDecisionKind.ChainPreserved or
                        IdJagActorDecisionKind.ChainExtended or
                        IdJagActorDecisionKind.DelegationRecorded => "The authorization grant's act claim does not identify an actor.",

                        _ => "The authorization grant's act claim does not identify an actor."
                    };

                    return (null, ServerHttpResponse.BadRequest(OAuthErrors.InvalidGrant, actorRefusal)
                        .WithHeader(WellKnownHttpHeaderNames.CacheControl, WellKnownCacheControlValues.NoStore));
                }

                //ID-JAG §4.4.1: the granted authorization_details ride the context into the producer
                //walk so the RFC 9068 access token carries them as a top-level claim — the same seam
                //the authorization-code grant uses. The response echo below reflects them per §4.4.2.
                if(grant.AuthorizationDetailsClaim is not null)
                {
                    context.SetGrantedAuthorizationDetailsClaim(grant.AuthorizationDetailsClaim);
                }

                //ID-JAG §9.8.1.2 proof-of-possession matrix: combines the proof's key thumbprint
                //(already validated above, before the assertion seam) with the grant's bound
                //thumbprint (cnf.jkt) and the Resource Server's sender-constraint requirement to
                //decide Bearer vs DPoP-bound vs reject. A grant with neither a bound key nor a
                //constraint requirement and no presented proof yields the Bearer flow unless the
                //registration's own profile mandates DPoP.
                IdJagDpopDecision dpopDecision = IdJagDpopDecision.Evaluate(
                    grant.RequiredKeyThumbprint,
                    dpopOutcome.Confirmation?.JwkThumbprint,
                    grant.RequiresSenderConstrainedToken);
                if(dpopDecision.IsRejected)
                {
                    string description = dpopDecision.Kind switch
                    {
                        IdJagDpopDecisionKind.RejectProofRequired => "Proof of possession required for this authorization grant.",
                        IdJagDpopDecisionKind.RejectKeyMismatch => "The DPoP proof key does not match the grant's bound key.",
                        IdJagDpopDecisionKind.RejectSenderConstrainedRequired => "Sender-constrained tokens are required for this resource server.",
                        IdJagDpopDecisionKind.BearerToken or
                        IdJagDpopDecisionKind.SenderConstrainedToken => "Sender-constrained tokens are required for this resource server.",

                        _ => "Sender-constrained tokens are required for this resource server."
                    };

                    return (null, ServerHttpResponse.BadRequest(OAuthErrors.InvalidGrant, description)
                        .WithHeader(WellKnownHttpHeaderNames.CacheControl, WellKnownCacheControlValues.NoStore));
                }

                ConfirmationMethod? tokenConfirmation = dpopDecision.BoundKeyThumbprint is { } boundThumbprint
                    ? new ConfirmationMethod { JwkThumbprint = boundThumbprint }
                    : null;

                //RFC 7523 §2.1: the issued token's subject is the assertion's subject (§3 rule 2.A —
                //the principal access is requested for), and the granted scope is the seam's decision.
                //A non-empty grant audience confines the issued token (its aud) verbatim, bypassing the
                //scope→audience resolver (RFC 8693-style target binding); an empty list leaves Audience
                //null so the resolver runs. A non-empty Confirmation sender-constrains the token (§9.8).
                //RFC 8693 §1.1 delegation is preserved by keeping Subject the assertion's subject while
                //Act names the party acting for it; Act is null when no party does (§1.1 "acting
                //directly on its own behalf"), so no self-referential actor is ever emitted.
                IssuanceContext issuance = new()
                {
                    Registration = registration,
                    Context = context,
                    IssuerUri = issuerUri,
                    Subject = grant.Subject,
                    Scope = grant.Scope,
                    ClientId = registration.ClientId,
                    GrantType = WellKnownGrantTypes.JwtBearer,
                    IssuedAt = now,
                    Act = actorDecision.Act,
                    Audience = grant.Audience is { Count: > 0 } ? grant.Audience : null,
                    Confirmation = tokenConfirmation
                };

                IReadOnlyList<TokenProducer> producers =
                    oauth.TokenProducers.Count > 0
                        ? oauth.TokenProducers
                        : DefaultTokenProducers;

                OidcClaims? preResolvedOidcClaims = await PreResolveOidcClaimsAsync(
                    server, issuance, ct).ConfigureAwait(false);

                (TokenIssuanceResult? issuanceResult, ServerHttpResponse? issuanceFailure) =
                    await IssueTokensAsync(
                        server, registration, context, issuance, producers, preResolvedOidcClaims, now, ct)
                        .ConfigureAwait(false);
                if(issuanceFailure is not null)
                {
                    return (null, issuanceFailure);
                }

                TokenIssuanceResult issued = issuanceResult!;
                Dictionary<string, string> issuedTokens = issued.IssuedTokens;

                if(!issuedTokens.TryGetValue(WellKnownTokenTypes.AccessToken, out string? accessToken))
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "No access token was produced for the jwt-bearer grant."));
                }

                int expiresIn = issued.IssuedAudits.TryGetValue(
                    WellKnownTokenTypes.AccessToken, out IssuedTokenAudit? accessAudit)
                    ? (int)(accessAudit.ExpiresAt - accessAudit.IssuedAt).TotalSeconds
                    : 0;

                //RFC 6749 §5.1: a plain access-token response — access_token, token_type Bearer,
                //expires_in, scope. No issued_token_type (that is the token-exchange §2.2.1 field).
                //The response is stateless and uncacheable.
                StringBuilder sb = JsonAppender.Rent();
                string responseJson;
                try
                {
                    _ = sb.Append('{');
                    bool first = true;
                    JsonAppender.AppendStringField(sb, WellKnownTokenTypes.AccessToken, accessToken, ref first);

                    //RFC 9449 §5 / §9.8.1.2: a sender-constrained token reports token_type DPoP so the
                    //Resource Server dispatches the right scheme; an unconstrained token is Bearer. The
                    //wire value mirrors the cnf binding the producer embedded in the token.
                    JsonAppender.AppendStringField(sb, "token_type",
                        tokenConfirmation is { IsEmpty: false }
                            ? WellKnownAuthenticationSchemes.DPoP
                            : WellKnownAuthenticationSchemes.Bearer,
                        ref first);
                    JsonAppender.AppendInt64Field(sb, "expires_in", expiresIn, ref first);
                    JsonAppender.AppendStringField(sb, OAuthRequestParameterNames.Scope, grant.Scope, ref first);

                    //ID-JAG §4.4.1/§4.4.2: a Resource Authorization Server echoes the granted
                    //authorization_details in the token response; the seam pre-serialises the value.
                    if(!string.IsNullOrEmpty(grant.AuthorizationDetailsResponseJson))
                    {
                        JsonAppender.AppendRawField(
                            sb, OAuthRequestParameterNames.AuthorizationDetails, grant.AuthorizationDetailsResponseJson, ref first);
                    }

                    _ = sb.Append('}');
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
    /// Identification (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-2.2">RFC 6749
    /// §2.2</see>): whether <paramref name="presentedClientId"/> IS the identifier of
    /// <paramref name="registration"/> — the registration ALREADY SELECTED for this request. This
    /// is never client authentication (§2.3, validated through
    /// <see cref="RequireClientAuthenticationIfDeclaredAsync"/> /
    /// <see cref="AuthorizationServerIntegration.ValidateClientCredentialsAsync"/>) and never the
    /// binding of a stored grant to the client it was issued to (§4.1.2, §4.1.3, §5.2 "issued to
    /// another client"), which each redemption path keeps as its own separate comparison. A Client
    /// ID Metadata Document registration (<see cref="ClientRecord.ClientMetadataUri"/> non-null)
    /// compares with the ordinal-equality
    /// <see cref="ClientIdentifierUrl.IsMatch(string, string)"/> the materialization path already
    /// applies to that identifier URL (<see cref="Verifiable.OAuth.Server.Pipeline.ClientIdMetadataMaterialization"/>); every
    /// other registration compares <paramref name="presentedClientId"/> ordinally against
    /// <see cref="ClientRecord.ClientId"/>. The one comparison every identification call site in
    /// this file uses.
    /// </summary>
    private static bool IsPresentedClientIdentifierTheRegistration(
        ClientRecord registration, string presentedClientId) =>
        registration.ClientMetadataUri is not null
            ? ClientIdentifierUrl.IsMatch(presentedClientId, registration.ClientId)
            : string.Equals(presentedClientId, registration.ClientId, StringComparison.Ordinal);


    /// <summary>
    /// The description text <see cref="UnknownClientResponse"/> answers with, at the endpoints
    /// that START a grant or authenticate independently of one — the pushed request, the direct
    /// and <c>request_uri</c> authorization requests, client credentials, token exchange, the
    /// jwt-bearer grant, revocation, and introspection.
    /// </summary>
    private const string UnknownClientDescription = "Unknown client.";


    /// <summary>
    /// The body <see cref="BeforeCodeRedemptionCorrelationAsync"/> answers a <c>client_id</c>
    /// naming a registration other than this tenant's own, or an absent <c>code_verifier</c>,
    /// with — byte-identical to the dispatcher's own answer for an unknown, expired, or
    /// already-redeemed code (<see cref="BuildToken"/>'s <c>HandleNotFoundErrorDescription</c>).
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 §5.2</see> names
    /// <c>invalid_grant</c> for a grant "issued to another client", which is what a caller
    /// presenting a foreign <c>client_id</c> for this code is told — the same body an existence
    /// or state oracle would otherwise leak through.
    /// </summary>
    /// <remarks>
    /// Every refusal in <see cref="VerifyCodeGrantPresentation"/> that reads
    /// <see cref="ServerCodeIssuedState"/> or the replayed <see cref="ServerTokenIssuedState"/>
    /// answers this same body, never text of its own: the PKCE digest compare
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.6">RFC 7636 §4.6</see>), the
    /// stored-client and <c>redirect_uri</c> comparisons
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3">RFC 6749 §4.1.3</see>),
    /// every exit of <see cref="HandleAuthorizationCodeReplayAsync"/>'s replay defense
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2">RFC 6749 §4.1.2</see> /
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.5.3">RFC 9700 §4.5.3</see>,
    /// including a stored record shaped by refresh-token rotation rather than a code grant),
    /// <see cref="BuildToken"/>'s own "not the expected record type" and lost-claim exits. A
    /// caller who reaches a distinguishable answer at any of these sites has proven the code
    /// exists; this constant is why none of them can. A refusal reachable only after a caller has
    /// already proven possession of the grant's secrets — the <see cref="ResolveEffectiveResource"/>
    /// granted-set subset refusal
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.2">RFC 8707 §2.2</see>), the
    /// <see cref="ResolveGrantedAuthorizationDetailsAsync"/> narrowing-beyond-grant refusal
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9396#section-6">RFC 9396 §6</see>), and the
    /// application's own
    /// <see cref="AuthorizationServerIntegration.ResolveCredentialAuthorizationAsync"/> denial —
    /// tells the caller nothing about the code's existence that it did not already know, so it
    /// keeps its own body instead of this one.
    /// </remarks>
    private const string CodeGrantNotFoundDescription = "The authorization code is unknown, expired, or already used.";


    /// <summary>
    /// The body <see cref="BeforeRefreshCorrelationAsync"/> answers a <c>client_id</c> naming a
    /// registration other than this tenant's own with — byte-identical to the dispatcher's own
    /// answer for an unknown, expired, retired, or revoked refresh token
    /// (<see cref="BuildRefreshToken"/>'s <c>HandleNotFoundErrorDescription</c>), for the same
    /// reason <see cref="CodeGrantNotFoundDescription"/> exists.
    /// </summary>
    /// <remarks>
    /// Every refusal that reads the stored <see cref="ServerRefreshTokenIssuedState"/> or the
    /// retired <see cref="ServerTokenIssuedState"/> answers this same body, never text of its own:
    /// <see cref="VerifyRefreshClient"/>'s stored-grant binding comparison
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 §5.2</see>,
    /// live and reuse alike), <see cref="BuildRefreshToken"/>'s and
    /// <see cref="HandleRefreshTokenReuseAsync"/>'s own "not the expected record type" and every
    /// other exit of the reuse defense
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2">RFC 6749 §4.1.2</see>),
    /// and the two DPoP binding refusals internal to
    /// <see cref="Verifiable.OAuth.AuthCode.Server.DpopTokenEndpointValidation.BindValidatedProofAsync"/>:
    /// a DPoP-bound refresh token presented with no proof under a profile that does not itself
    /// require DPoP (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-5">RFC 9449 §5</see>
    /// names no error for a missing proof; <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">§8</see>
    /// governs a proof presented without a nonce, not a request presenting no proof at all), and a
    /// valid proof bound to a key other than the one the record itself names
    /// (RFC 9449 §5 prescribes <c>invalid_dpop_proof</c> for an INVALID proof — already answered
    /// before correlation — and prescribes nothing for a valid proof with the wrong key). A caller
    /// who reaches a distinguishable answer at any of these sites has proven the refresh token
    /// exists; this constant, referenced rather than copied, is why none of them can. Internal
    /// rather than private so the DPoP helper above — a different class in the same assembly —
    /// references the one constant instead of copying its text. A refusal reachable only after a
    /// caller has already proven possession of the grant's secrets — the bound client's identity
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-6">RFC 6749 §6</see>) — such as
    /// the <see cref="ResolveEffectiveResource"/> granted-set subset refusal
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.2">RFC 8707 §2.2</see>), the
    /// sibling <see cref="ResolveEffectiveScope"/> granted-set subset refusal (RFC 6749 §6 /
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">§5.2</see>'s
    /// <c>invalid_scope</c>), the
    /// <see cref="ResolveGrantedAuthorizationDetailsAsync"/> narrowing-beyond-grant refusal
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9396#section-6">RFC 9396 §6</see>), and the
    /// application's own
    /// <see cref="AuthorizationServerIntegration.ResolveCredentialAuthorizationAsync"/> denial —
    /// tells the caller nothing about the refresh token's existence that it did not already know,
    /// so it keeps its own body instead of this one.
    /// </remarks>
    internal const string RefreshTokenNotFoundDescription = "The refresh token is unknown, expired, or has been revoked.";


    /// <summary>
    /// The body both the <c>request_uri</c> completion's pre-correlation step (its registration
    /// comparison, <see cref="BeforeAuthorizeCompletionCorrelationAsync"/>) and
    /// <see cref="BuildAuthorize"/>'s handler (its pushed-request <c>ClientId</c> comparison)
    /// answer with — referenced from both sites so the two comparisons this security invariant
    /// depends on staying byte-identical can never drift apart by a one-character edit to a
    /// copied literal.
    /// </summary>
    private const string PushedRequestClientMismatchDescription = "client_id does not match the pushed authorization request.";


    /// <summary>
    /// Adds the <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 §5.2</see>
    /// <c>WWW-Authenticate</c> challenge to <paramref name="response"/> when
    /// <paramref name="request"/> attempted authentication through the <c>Authorization: Basic</c>
    /// header — the one place every <c>invalid_client</c> response this file answers with, whether
    /// a mismatch against a resolved registration (<see cref="UnknownClientResponse"/>) or any
    /// other identification or authentication failure (<see cref="ClientAuthenticationFailureResponse"/>),
    /// applies the challenge from. A continuing grant's <c>invalid_grant</c> refusal never calls this.
    /// </summary>
    private static ServerHttpResponse AddBasicChallengeIfAttempted(ServerHttpResponse response, IncomingRequest? request)
    {
        if(request is not null
            && request.Headers.TryGetSingle(WellKnownHttpHeaderNames.Authorization, out string? authHeader)
            && !string.IsNullOrEmpty(authHeader)
            && authHeader.StartsWith(WellKnownAuthenticationSchemes.Basic, StringComparison.OrdinalIgnoreCase))
        {
            return response.WithHeader(WellKnownHttpHeaderNames.WwwAuthenticate, WellKnownAuthenticationSchemes.Basic);
        }

        return response;
    }


    /// <summary>
    /// The wire body <see cref="UnknownClientDescription"/> names — the identification refusal at
    /// the endpoints listed on that constant's own doc —
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 §5.2</see>
    /// <c>invalid_client</c> — so the body never discloses whether the presented identifier
    /// belongs to another registration. Carries the <see cref="AddBasicChallengeIfAttempted"/>
    /// challenge when <paramref name="request"/> attempted <c>Authorization: Basic</c>. The
    /// continuing-grant endpoints (code redemption, refresh) answer their own identification
    /// mismatch with <see cref="CodeGrantNotFoundDescription"/> / <see cref="RefreshTokenNotFoundDescription"/>
    /// instead, never through this response.
    /// </summary>
    private static ServerHttpResponse UnknownClientResponse(IncomingRequest? request) =>
        AddBasicChallengeIfAttempted(
            ServerHttpResponse.Unauthorized(OAuthErrors.InvalidClient, UnknownClientDescription),
            request);


    /// <summary>
    /// The <c>401 invalid_client</c> response every client-authentication failure and every site
    /// that finds no registration to identify against in this file answers with —
    /// <paramref name="description"/> names the specific failure. Carries the
    /// <see cref="AddBasicChallengeIfAttempted"/> challenge when <paramref name="request"/>
    /// attempted <c>Authorization: Basic</c>, exactly as <see cref="UnknownClientResponse"/> does
    /// for a mismatch against a resolved registration —
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 §5.2</see> draws no
    /// distinction between the failure kinds for the challenge requirement.
    /// </summary>
    private static ServerHttpResponse ClientAuthenticationFailureResponse(IncomingRequest? request, string description) =>
        AddBasicChallengeIfAttempted(
            ServerHttpResponse.Unauthorized(OAuthErrors.InvalidClient, description),
            request);


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 §4.1.2.1</see>:
    /// "if the client identifier is missing or invalid, the authorization server ... MUST NOT
    /// automatically redirect the user agent to the invalid redirection URI" — the authorization
    /// endpoint's own identification refusal, a direct response with no redirect, distinct from
    /// the token endpoint family's <see cref="UnknownClientResponse"/>.
    /// </summary>
    private static ServerHttpResponse UnidentifiedClientDirectResponse() =>
        ServerHttpResponse.BadRequest(OAuthErrors.InvalidRequest, UnknownClientDescription);


    /// <summary>
    /// Identification at every site that reads an OPTIONAL <c>client_id</c> field: when the
    /// field is present it MUST be <paramref name="registration"/>'s own identifier
    /// (<see cref="IsPresentedClientIdentifierTheRegistration"/>); an absent field is not a
    /// failure here — a caller with its own required-field rule (a public client, or a request
    /// that never authenticates) enforces that separately. Runs BEFORE the declared
    /// authentication method and before any grant-binding comparison, per the
    /// identification-then-authentication-then-binding order client authentication for this
    /// authorization server follows throughout.
    /// </summary>
    private static ServerHttpResponse? RefuseUnidentifiedClient(
        ClientRecord registration, RequestFields fields, IncomingRequest? request)
    {
        if(fields.TryGetValue(OAuthRequestParameterNames.ClientId, out string? presentedClientId)
            && !string.IsNullOrEmpty(presentedClientId)
            && !IsPresentedClientIdentifierTheRegistration(registration, presentedClientId))
        {
            return UnknownClientResponse(request);
        }

        return null;
    }


    /// <summary>
    /// Reports whether the request carries client credentials — the §3.1 "if client credentials are
    /// present" predicate for the jwt-bearer grant. A credential is present when the request bears an
    /// <c>Authorization</c> header (<c>client_secret_basic</c> / <c>private_key_jwt</c> / mTLS surface)
    /// OR a <c>client_secret</c> / <c>client_assertion</c> form field (<c>client_secret_post</c> /
    /// <c>private_key_jwt</c> body form). A bare <c>client_id</c> with no secret is identification, not
    /// a credential, so it is NOT treated as present — that keeps the §2.1 anonymous path open.
    /// </summary>
    private static bool HasClientCredentials(IncomingRequest? request, RequestFields fields)
    {
        if(request is not null
            && request.Headers.TryGetSingle(WellKnownHttpHeaderNames.Authorization, out string? authHeader)
            && !string.IsNullOrEmpty(authHeader))
        {
            return true;
        }

        return (fields.TryGetValue(OAuthRequestParameterNames.ClientSecret, out string? secret)
                && !string.IsNullOrEmpty(secret))
            || (fields.TryGetValue(OAuthRequestParameterNames.ClientAssertion, out string? assertion)
                && !string.IsNullOrEmpty(assertion));
    }


    /// <summary>
    /// Refuses a registration whose declared <c>token_endpoint_auth_method</c> is a confidential
    /// method this token endpoint does not advertise in
    /// <see cref="AuthorizationServerIntegration.ClientAuthenticationMethodsSupported"/>, so the
    /// discovery advertisement and the endpoint's judgment are one set rather than two independently
    /// maintained facts (draft-ietf-oauth-client-id-metadata-document-02 §8.2). The refusal keys off a
    /// DECLARED method only: a registration whose <see cref="ClientRecord.TokenEndpointAuthMethod"/> is
    /// <see langword="null"/> or <see cref="ClientAuthenticationMethod.None"/> keeps its dispatch — the
    /// PKCE-only public-client shape the revocation and logout endpoints authenticate. Returns the
    /// <c>401 invalid_client</c> refusal when the declared method is unadvertised, otherwise
    /// <see langword="null"/>. Every grant that authenticates a client — the authorization_code,
    /// refresh_token and jwt-bearer grants through
    /// <see cref="RequireClientAuthenticationIfDeclaredAsync"/>, and the client_credentials and
    /// token-exchange grants that call <see cref="AuthorizationServerIntegration.ValidateClientCredentialsAsync"/>
    /// directly — consults this before any validator runs.
    /// </summary>
    /// <param name="oauth">The authorization server integration whose advertised methods bound the declaration.</param>
    /// <param name="registration">The effective client registration whose declared method is judged.</param>
    /// <param name="request">The incoming request, so a Basic-attempted refusal carries the challenge.</param>
    /// <returns>A <c>401 invalid_client</c> response when the declared method is unadvertised; otherwise <see langword="null"/>.</returns>
    private static ServerHttpResponse? RefuseUndeclaredClientAuthenticationMethod(
        AuthorizationServerIntegration oauth,
        ClientRecord registration,
        IncomingRequest? request)
    {
        if(registration.TokenEndpointAuthMethod is { } authMethod
            && authMethod != ClientAuthenticationMethod.None
            && !oauth.ClientAuthenticationMethodsSupported.Contains(authMethod))
        {
            return ClientAuthenticationFailureResponse(
                request,
                "The client's declared token_endpoint_auth_method is not supported by this "
                + "token endpoint.");
        }

        return null;
    }


    /// <summary>
    /// Enforces draft-ietf-oauth-client-id-metadata-document-02 §8.2 (CIMD-049/050) at the
    /// authorization_code, refresh_token, and jwt-bearer grants: when the effective registration
    /// declares a non-<see cref="ClientAuthenticationMethod.None"/> <c>token_endpoint_auth_method</c>,
    /// this is a confidential client and "any communication with the authorization server MUST include
    /// client authentication of the registered type." The declared method must first be one this token
    /// endpoint actually advertises (<see cref="AuthorizationServerIntegration.ClientAuthenticationMethodsSupported"/>)
    /// — a registration declaring a method the server does not support is refused with
    /// <c>401 invalid_client</c> before any validator runs, so the discovery advertisement and the
    /// endpoint's judgment are never two independently maintained facts. Once coherent,
    /// <see cref="AuthorizationServerIntegration.ValidateClientCredentialsAsync"/>
    /// must be wired AND must return <see langword="true"/>; an unwired seam is a fail-closed
    /// <c>401 invalid_client</c>, never silent passthrough.
    /// A <see langword="null"/> or <see cref="ClientAuthenticationMethod.None"/> method is the
    /// PKCE-only public-client shape, but RFC 7523 §3.1's principle — "if client credentials are
    /// present in the request, the authorization server MUST validate them" — generalizes to every
    /// caller of this helper, not only the jwt-bearer grant it was written for: a request that
    /// attaches a <c>client_secret</c> / <c>client_assertion</c> / <c>Authorization</c> header is
    /// never silently waved through just because the registration never declared a method. That
    /// branch validates a present credential through the same seam and fail-closed rule as the
    /// declared-method path below, and returns <see langword="null"/> immediately only when
    /// <see cref="HasClientCredentials"/> reports none — the true anonymous public client. The
    /// jwt-bearer grant invokes this only when the request carries no credentials: its own §3.1
    /// validate-if-present branch authenticates a credential-bearing request before this helper is
    /// ever reached, so composing the two never validates the same credentials twice.
    /// </summary>
    private static async ValueTask<ServerHttpResponse?> RequireClientAuthenticationIfDeclaredAsync(
        AuthorizationServerIntegration oauth,
        IncomingRequest? request,
        RequestFields fields,
        ClientRecord registration,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ServerHttpResponse? identificationFailure = RefuseUnidentifiedClient(registration, fields, request);
        if(identificationFailure is not null)
        {
            return identificationFailure;
        }

        if(registration.TokenEndpointAuthMethod is not { } authMethod
            || authMethod == ClientAuthenticationMethod.None)
        {
            if(!HasClientCredentials(request, fields))
            {
                return null;
            }

            if(oauth.ValidateClientCredentialsAsync is null)
            {
                return ClientAuthenticationFailureResponse(
                    request,
                    "Client credentials were presented but this authorization server has no client "
                    + "authentication configured to validate them.");
            }

            bool arePresentedCredentialsAuthenticated = await oauth.ValidateClientCredentialsAsync(
                request, fields, registration, context, cancellationToken).ConfigureAwait(false);
            if(!arePresentedCredentialsAuthenticated)
            {
                return ClientAuthenticationFailureResponse(request, "Client authentication failed.");
            }

            return null;
        }

        ServerHttpResponse? undeclaredMethodRefusal = RefuseUndeclaredClientAuthenticationMethod(oauth, registration, request);
        if(undeclaredMethodRefusal is not null)
        {
            return undeclaredMethodRefusal;
        }

        if(oauth.ValidateClientCredentialsAsync is null)
        {
            return ClientAuthenticationFailureResponse(
                request,
                "This client declared a confidential token_endpoint_auth_method but client "
                + "authentication is not configured for this authorization server.");
        }

        bool isClientAuthenticated = await oauth.ValidateClientCredentialsAsync(
            request, fields, registration, context, cancellationToken).ConfigureAwait(false);
        if(!isClientAuthenticated)
        {
            return ClientAuthenticationFailureResponse(request, "Client authentication failed.");
        }

        return null;
    }


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
    /// code store knows them. This grant does not consume the RFC 8707 §2 <c>resource</c>
    /// parameter — OID4VCI 1.0 scopes the issued token to the Credential Offer's
    /// <c>credential_configuration_id</c> set instead.
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
                    || !string.Equals(grantType, WellKnownGrantTypes.PreAuthorizedCode, StringComparison.Ordinal))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
            },

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.RequestServer!;
                var oauth = server.OAuth();

                ClientRecord? registration = context.ClientRegistration;
                if(registration is null)
                {
                    return (null, ClientAuthenticationFailureResponse(context.IncomingRequest, "Unknown client."));
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

                Uri issuerUri;
                try
                {
                    issuerUri = oauth.ResolveIssuerAsync is not null
                        ? (await oauth.ResolveIssuerAsync(registration, context, ct)
                            .ConfigureAwait(false))!
                        : await DefaultIssuerResolver.ResolveAsync(registration, context, ct)
                            .ConfigureAwait(false);
                }
                catch(InvalidOperationException ex)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, ex.Message));
                }

                DateTimeOffset now = server.TimeProvider.GetUtcNow();

                //RFC 9449 §5: "This is applicable for all access token requests regardless of
                //grant type" — this grant runs the SAME validation the authorization-code grant's
                //token endpoint runs, with the SAME expectedThumbprint=null (the binding is being
                //established here). It runs BEFORE the code-validation seam below: the
                //pre-authorized_code is single-use and the seam may consume it, so a
                //use_dpop_nonce challenge (RFC 9449 §8) or a rejected proof MUST NOT consume it
                //— the Wallet retries the same code once it has satisfied the challenge.
                bool dpopRequired = ClientPolicyProfiles.RequiresDpop(registration.Profile);
                DpopValidationOutcome dpopOutcome = await DpopTokenEndpointValidation.ValidateAsync(
                    server, context, registration, issuerUri, now,
                    expectedThumbprint: null, dpopRequired, ct).ConfigureAwait(false);

                if(!dpopOutcome.IsSuccess)
                {
                    return (null, dpopOutcome.FailureResponse!);
                }

                ConfirmationMethod? confirmation = dpopOutcome.Confirmation;

                //The application owns the pre-authorized code store; the builder guarantees
                //the seam is wired. It resolves the subject and tells the library which §6.3
                //error a refusal maps to.
                PreAuthorizedCodeDecision decision = await oauth.ValidatePreAuthorizedCodeAsync!(
                    preAuthorizedCode, transactionCode, clientId, registration, context, ct).ConfigureAwait(false);

                if(!decision.IsGranted)
                {
                    return (null, MapPreAuthorizedCodeDenial(decision, context.IncomingRequest));
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
                        stepOutcome: null,
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

                //OID4VCI 1.0 §13.10 — the Pre-Authorized Code grant always mints an Access Token
                //giving access to Credentials. A long-lived bearer Credential token MUST NOT be
                //issued unless sender-constrained; the DPoP enforcement above set the
                //confirmation when it bound the token.
                ServerHttpResponse? protectionFailure = GuardCredentialAccessTokenProtection(
                    server, registration, isSenderConstrained: confirmation is { IsEmpty: false });
                if(protectionFailure is not null)
                {
                    return (null, protectionFailure);
                }

                //§6.2: the token is bound to the End-User the Credential is about (the
                //seam-resolved subject), not to the Wallet. An absent scope is the
                //authorization_details path (§6.1.1); the granted scope, when present,
                //is echoed in the response.
                //
                //RFC 6749 §3.3 narrowing — the Pre-Authorized Code grant establishes no
                //authenticated End-User session (there is no prior Authorization Request), so
                //openid and the identity scopes never reach the granted set. See
                //DropIdentityScopesForNonEndUserGrant's remarks for the invariant.
                string grantedScope = DropIdentityScopesForNonEndUserGrant(decision.Scope ?? string.Empty);

                IssuanceContext issuance = new()
                {
                    Registration = registration,
                    Context = context,
                    IssuerUri = issuerUri,
                    Subject = subject,
                    Scope = grantedScope,
                    ClientId = clientId ?? registration.ClientId,
                    GrantType = WellKnownGrantTypes.PreAuthorizedCode,
                    IssuedAt = now,
                    Confirmation = confirmation
                };

                IReadOnlyList<TokenProducer> producers =
                    oauth.TokenProducers.Count > 0
                        ? oauth.TokenProducers
                        : DefaultTokenProducers;

                OidcClaims? preResolvedOidcClaims = await PreResolveOidcClaimsAsync(
                    server, issuance, ct).ConfigureAwait(false);

                (TokenIssuanceResult? issuanceResult, ServerHttpResponse? issuanceFailure) =
                    await IssueTokensAsync(
                        server, registration, context, issuance, producers, preResolvedOidcClaims, now, ct)
                        .ConfigureAwait(false);
                if(issuanceFailure is not null)
                {
                    return (null, issuanceFailure);
                }

                TokenIssuanceResult issued = issuanceResult!;
                Dictionary<string, string> issuedTokens = issued.IssuedTokens;

                if(!issuedTokens.TryGetValue(WellKnownTokenTypes.AccessToken, out string? accessToken))
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "No access token was produced for the pre-authorized_code grant."));
                }

                int expiresIn = issued.IssuedAudits.TryGetValue(
                    WellKnownTokenTypes.AccessToken, out IssuedTokenAudit? accessAudit)
                    ? (int)(accessAudit.ExpiresAt - accessAudit.IssuedAt).TotalSeconds
                    : 0;

                //RFC 9449 §5: token_type is "DPoP" when the request bound the token, the
                //RFC 6750 "Bearer" default otherwise — the rule every other grant's token
                //response applies.
                string tokenTypeWireName = confirmation is { IsEmpty: false }
                    ? WellKnownAuthenticationSchemes.DPoP
                    : WellKnownAuthenticationSchemes.Bearer;

                //§6.2/RFC 6749 §5.1: access_token, token_type, expires_in, and the granted
                //scope when one was requested. The c_nonce is deliberately absent — OID4VCI
                //1.0 moved it to the Nonce Endpoint (§7). The response is uncacheable.
                StringBuilder sb = JsonAppender.Rent();
                string responseJson;
                try
                {
                    _ = sb.Append('{');
                    bool first = true;
                    JsonAppender.AppendStringField(sb, WellKnownTokenTypes.AccessToken, accessToken, ref first);
                    JsonAppender.AppendStringField(sb, "token_type", tokenTypeWireName, ref first);
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

                    _ = sb.Append('}');
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
    /// the spec's catch-all for an unaccepted Pre-Authorized Code. <paramref name="request"/>
    /// carries the <see cref="ClientAuthenticationFailureResponse"/> challenge on the
    /// <see cref="PreAuthorizedCodeDenialReason.ClientAuthenticationRequired"/> branch, the
    /// one <c>invalid_client</c> answer this mapping can produce.
    /// </summary>
    private static ServerHttpResponse MapPreAuthorizedCodeDenial(
        PreAuthorizedCodeDecision decision, IncomingRequest? request) =>
        decision.DenialReason switch
        {
            //A denial with no reason set, and an explicit InvalidCode denial, share the
            //same OID4VCI 1.0 §6.3 catch-all mapping.
            null => ServerHttpResponse.BadRequest(OAuthErrors.InvalidGrant,
                decision.DenialDescription ?? "The pre-authorized_code is invalid or has expired."),
            PreAuthorizedCodeDenialReason.InvalidCode => ServerHttpResponse.BadRequest(OAuthErrors.InvalidGrant,
                decision.DenialDescription ?? "The pre-authorized_code is invalid or has expired."),
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
                ClientAuthenticationFailureResponse(request,
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
    /// A malformed-resource sentinel deliberately shaped to fail
    /// <see cref="IsAbsoluteResourceIndicatorUri"/> (it carries a fragment, which §2 forbids), so a
    /// defect caught while reading raw wire values reaches the SAME downstream
    /// <see cref="ValidateResourceIndicatorsShape"/> gate every other malformed resource value goes
    /// through, with <c>invalid_target</c>, rather than a distinct read-time error code.
    /// </summary>
    private const string MalformedResourceIndicatorSentinel = "urn:invalid-resource-parameter#malformed";


    /// <summary>
    /// Reads the RFC 8707 <c>resource</c> request field, normalising an entirely absent field to
    /// <see langword="null"/>. A PRESENT field — even an empty or blank one — is returned verbatim
    /// (never collapsed to <see langword="null"/>): <see cref="ValidateResourceIndicatorsShape"/>
    /// and <see cref="ResolveEffectiveResource"/> both treat that distinctly from "no resource
    /// requested" and fail closed, per §2's <c>invalid_target</c> ("missing, unknown, or
    /// malformed"). §2's multi-resource wire form is the REPEATED <c>resource</c> parameter
    /// (<see cref="RequestFields.GetValues"/> aggregates every occurrence), never a single
    /// occurrence with several URIs packed inside it separated by spaces — a resource indicator IS
    /// one absolute URI, and RFC 3986 §2 / Appendix A's ABNF does not permit a raw, un-encoded
    /// space inside one. Each raw occurrence is therefore checked BEFORE joining, and rejected as
    /// malformed — via <see cref="MalformedResourceIndicatorSentinel"/> — when it is
    /// <see langword="null"/>, empty, or all-whitespace (a blank occurrence has no indicator to
    /// contribute; silently dropping it via <see cref="ParseResourceIndicators"/>'s
    /// <see cref="StringSplitOptions.RemoveEmptyEntries"/> after joining would let one bad
    /// occurrence vanish from an otherwise-valid aggregate) or when it carries embedded
    /// whitespace (not "two indicators sent as one" to silently recover by splitting). Once past
    /// that check, every value is guaranteed non-blank and space-free, so joining the aggregated
    /// set with a space (the convention this library also uses for <c>scope</c> and
    /// <c>acr_values</c>) is lossless — <see cref="ParseResourceIndicators"/> splits it back to
    /// exactly the individual indicators.
    /// </summary>
    private static string? ReadResource(RequestFields fields)
    {
        IReadOnlyList<string> values = fields.GetValues(OAuthRequestParameterNames.Resource);
        if(values.Count == 0)
        {
            return null;
        }

        foreach(string value in values)
        {
            if(string.IsNullOrEmpty(value) || value.Any(char.IsWhiteSpace))
            {
                return MalformedResourceIndicatorSentinel;
            }
        }

        return string.Join(' ', values);
    }


    /// <summary>
    /// Splits the space-delimited <c>resource</c> field value into its individual RFC 8707 §2
    /// indicators. Returns <see langword="null"/> only when <paramref name="resource"/> itself is
    /// <see langword="null"/> ("no resource parameter present"); an empty or all-whitespace but
    /// non-null value returns an EMPTY array rather than <see langword="null"/>, so a caller can
    /// distinguish "the parameter was absent" from "the parameter was present but blank" — the
    /// latter is malformed, not absent (§2's <c>invalid_target</c> covers "missing" values, and a
    /// present-but-empty value parses to no indicators at all). Resource indicators are absolute
    /// URIs and so carry no internal spaces, making the split unambiguous.
    /// </summary>
    private static string[]? ParseResourceIndicators(string? resource)
    {
        return resource?.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }


    /// <summary>
    /// Returns whether <paramref name="indicator"/> satisfies
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 §2</see>'s resource
    /// indicator shape: an absolute URI (RFC 3986 §4.3) with no fragment component. §2 places no
    /// scheme restriction on the value — any scheme is a valid resource indicator, not only
    /// https/http/urn. <see cref="UriKind.Absolute"/> alone is not enough to enforce that: on Unix
    /// a leading-slash value like <c>/relative</c> parses as an absolute <c>file:</c> URI (it is
    /// a valid Unix file path) even though the wire text carries no scheme at all, so a relative
    /// resource would slip through while a genuinely equivalent value is rejected on Windows
    /// (where the same string fails to parse as absolute in the first place). Rather than
    /// allowlisting schemes to close that gap, the coercion itself is rejected: when parsing
    /// yields a <c>file:</c> URI whose original text did not literally start with the <c>file:</c>
    /// scheme, that is .NET's implicit path-to-URI coercion, not a genuine resource indicator — a
    /// caller who does write out <c>file:...</c> explicitly still passes. §2 ALSO states the value
    /// "SHOULD NOT include a query component, but it is recognized that there are cases that make
    /// a query component a useful and necessary part of the resource parameter" — a SHOULD-NOT,
    /// not a MUST-NOT, so this gate deliberately does not enforce it: a query-bearing indicator is
    /// accepted like any other absolute URI without a fragment. <see cref="Uri.TryCreate(string, UriKind, out Uri)"/>
    /// itself is lenient about embedded whitespace: a value like <c>https://api.example.com/orders v2</c>
    /// still parses as absolute because the space is percent-escaped into the path during parsing, even
    /// though the raw wire text was never one URI. Every caller of this gate that reads raw wire
    /// occurrences (<see cref="ReadResource"/> and its token-exchange-grant equivalent) already rejects
    /// embedded whitespace before this method ever sees the value, but <see cref="ServerRefreshTokenIssuedState.Resource"/>'s
    /// exchange&#8594;refresh carry runs this gate directly against RFC 8693 <c>audience</c> entries — a
    /// logical name the authorization seam MAY have shaped with spaces — so an explicit whitespace check
    /// here (not "already whitespace-free by construction") is what keeps that carry fail-closed.
    /// </summary>
    private static bool IsAbsoluteResourceIndicatorUri(string indicator)
    {
        if(indicator.Any(char.IsWhiteSpace))
        {
            return false;
        }

        if(!Uri.TryCreate(indicator, UriKind.Absolute, out Uri? parsed))
        {
            return false;
        }

        if(parsed.IsFile
            && !indicator.StartsWith(Uri.UriSchemeFile + ":", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return string.IsNullOrEmpty(parsed.Fragment);
    }


    /// <summary>
    /// Shape-validates every space-delimited RFC 8707 §2 indicator in <paramref name="resource"/>
    /// at PAR/authorize receipt, mirroring the RFC 8693 token-exchange grant's own shape gate
    /// (<see cref="IsAbsoluteResourceIndicatorUri"/>) but with the authorize/PAR-specific error
    /// code: §2.1 directs the authorization server to reject a value it fails to parse
    /// with <c>invalid_target</c>, not <c>invalid_request</c> — <see cref="OAuthErrors.InvalidTarget"/>
    /// is the error registered for exactly this parameter (§5.2). Runs before the application's
    /// <see cref="EvaluateAuthorizationRequestDelegate"/> sees the value, the same fail-fast the
    /// <c>authorization_details</c> shape gate applies. A <paramref name="resource"/> that is
    /// present but empty or all-whitespace parses to zero indicators
    /// (<see cref="ParseResourceIndicators"/>) and is rejected the same way — §2's
    /// <c>invalid_target</c> covers a "missing" resource value, and a present-but-empty parameter
    /// is not the same fact as the parameter never having been sent. Returns
    /// <see langword="null"/> only when <paramref name="resource"/> is <see langword="null"/>
    /// (the parameter was never sent) or every indicator is well-formed.
    /// </summary>
    private static ServerHttpResponse? ValidateResourceIndicatorsShape(string? resource)
    {
        string[]? indicators = ParseResourceIndicators(resource);
        if(indicators is null)
        {
            return null;
        }

        if(indicators.Length == 0)
        {
            return ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidTarget,
                "The resource parameter, when present, must not be empty.");
        }

        foreach(string indicator in indicators)
        {
            if(!IsAbsoluteResourceIndicatorUri(indicator))
            {
                return ServerHttpResponse.BadRequest(
                    OAuthErrors.InvalidTarget,
                    "The resource parameter must be an absolute URI (RFC 3986 §4.3) without a fragment.");
            }
        }

        return null;
    }


    /// <summary>
    /// The request-only half of an inbound token-request <c>resource</c> field's shape: present
    /// but empty is malformed, the same fact <see cref="ResolveEffectiveResource"/> also checks —
    /// duplicated here, in each step endpoint's pre-correlation step, so the answer is
    /// byte-identical for a grant that does not exist and one that does. Reads only
    /// <paramref name="fields"/>.
    /// </summary>
    /// <param name="fields">The inbound token request's form fields.</param>
    /// <returns>
    /// The <c>invalid_target</c> refusal when the request's own <c>resource</c> field is present
    /// but empty, all-whitespace, or carries a malformed raw occurrence (<see cref="ReadResource"/>'s
    /// <see cref="MalformedResourceIndicatorSentinel"/>); <see langword="null"/> when the field is
    /// absent or well-formed — the granted-set subset comparison that also lives in
    /// <see cref="ResolveEffectiveResource"/> stays there, since it needs the stored grant.
    /// </returns>
    private static ServerHttpResponse? ValidateRequestOnlyResourceShape(RequestFields fields)
    {
        string? requestedResource = ReadResource(fields);
        if(requestedResource is null)
        {
            return null;
        }

        //ReadResource collapses ANY malformed raw occurrence — present but empty, all-whitespace,
        //or embedding whitespace — into MalformedResourceIndicatorSentinel, discarding every other
        //occurrence in the same request. Splitting that sentinel string yields one non-empty
        //element, so the parsed-length-zero check below alone can never see it; it is checked
        //directly, first.
        if(string.Equals(requestedResource, MalformedResourceIndicatorSentinel, StringComparison.Ordinal))
        {
            return ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidTarget, "The resource parameter, when present, must not be empty.");
        }

        string[] requested = ParseResourceIndicators(requestedResource) ?? [];

        return requested.Length == 0
            ? ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidTarget, "The resource parameter, when present, must not be empty.")
            : null;
    }


    /// <summary>
    /// Resolves the effective RFC 8707 §2.2 resource set for a token-endpoint response from the
    /// granted set carried on the code/refresh state and an optional token-request <c>resource</c>.
    /// No token-request value leaves the full <paramref name="grantedResource"/> set (possibly
    /// <see langword="null"/>) in force. A token-request value MUST be a subset of the granted set
    /// (§2.2 — "the authorization server will issue an access token based on that subset of
    /// requested resources"); a grant with no stored resource has nothing to narrow from, and any
    /// indicator not present in the granted set, fails closed with <c>invalid_target</c>. Because
    /// every granted indicator was already shape-validated at PAR/authorize
    /// (<see cref="ValidateResourceIndicatorsShape"/>), a malformed token-request value can never
    /// match a granted one and is rejected by the same subset check — no separate shape check is
    /// needed here (the request-only empty-value case is <see cref="ValidateRequestOnlyResourceShape"/>'s,
    /// which the endpoint's pre-correlation step already ran before this method is ever reached).
    /// §2's resource set is a SET — the granted and requested indicator lists are
    /// each deduplicated (ordinal) before use, via <see cref="DeduplicateOrdinal"/>, so a client or
    /// stored grant that repeated an indicator never surfaces a duplicate <c>aud</c> member. Shared
    /// by the <c>authorization_code</c> grant (<see cref="BuildToken"/>) and the
    /// <c>refresh_token</c> grant (<see cref="BuildRefreshToken"/>); the caller alone decides what
    /// to persist onto <see cref="ServerRefreshTokenIssuedState.Resource"/> — this method never
    /// narrows the stored grant itself (§2.2's "any refresh token that is returned is bound to the
    /// full original grant").
    /// </summary>
    /// <remarks>
    /// <para>
    /// Subset membership (<see cref="Array.IndexOf{T}(T[], T)"/> below) is byte-exact ordinal
    /// string comparison — the library's own reading, not a §2.2 mandate.
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-6.2.1">RFC 3986 §6.2.1</see>
    /// ranks simple string comparison as the least accurate but least costly of its URI-equivalence
    /// tiers, and a conformant one; a stricter, non-normalizing comparison is the fail-closed
    /// direction — a requested indicator that a
    /// looser (scheme/host-case-insensitive, percent-decoding) comparison would have matched but
    /// this one does not is refused, never silently accepted, so this reading can only reject a
    /// grant that a looser one would allow, never the reverse.
    /// </para>
    /// <para>
    /// §2.2 leaves "[t]he resource value(s) that is acceptable to an authorization server in
    /// fulfilling an access token request" to the server's "sole discretion based on local policy
    /// or configuration." A token-request resource when NOTHING was granted (no PAR/authorize
    /// <c>resource</c> at all) has an empty set to be a subset of — this exercises that §2.2
    /// discretion by keeping the request fail-closed (<c>invalid_target</c>) rather than treating
    /// an empty granted set as "anything goes."
    /// </para>
    /// </remarks>
    private static (IReadOnlyList<string>? Effective, ServerHttpResponse? Failure) ResolveEffectiveResource(
        string? grantedResource, string? requestedResource)
    {
        if(requestedResource is null)
        {
            string[]? granted = ParseResourceIndicators(grantedResource);

            return (granted is null ? null : DeduplicateOrdinal(granted), null);
        }

        //A PRESENT but blank token-request resource (ParseResourceIndicators returns a
        //non-null, zero-length array for it) is malformed, not "no narrowing requested" —
        //§2's invalid_target covers a missing/malformed resource value the same as at
        //PAR/authorize receipt (ValidateResourceIndicatorsShape).
        string[] requested = DeduplicateOrdinal(ParseResourceIndicators(requestedResource) ?? []);
        if(requested.Length == 0)
        {
            return (null, ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidTarget,
                "The resource parameter, when present, must not be empty."));
        }

        //§2.2's "sole discretion" — the library's fail-closed exercise of it — refuses a
        //token-request resource when the grant carries none to narrow from, rather than treating
        //an empty granted set as unconstrained.
        string[] grantedIndicators = DeduplicateOrdinal(ParseResourceIndicators(grantedResource) ?? []);
        if(grantedIndicators.Length == 0)
        {
            return (null, ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidTarget,
                "The resource parameter must be a subset of the resource(s) originally granted; none were granted."));
        }

        //Ordinal (byte-exact) subset membership — see the remarks above.
        foreach(string indicator in requested)
        {
            if(Array.IndexOf(grantedIndicators, indicator) < 0)
            {
                return (null, ServerHttpResponse.BadRequest(
                    OAuthErrors.InvalidTarget,
                    $"The resource parameter must be a subset of the resource(s) originally granted; '{indicator}' was not granted."));
            }
        }

        return (requested, null);
    }


    /// <summary>
    /// Removes ordinal-duplicate entries from <paramref name="indicators"/>, preserving the first
    /// occurrence's position. Shared by the two space-delimited token sets this endpoint narrows at
    /// the token boundary: RFC 8707 §2's resource indicators (a client repeating an indicator, or a
    /// stored grant that accumulated one, must never surface as a duplicate <c>aud</c> member) and
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.3">RFC 6749 §3.3</see>'s scope
    /// tokens (a repeated token adds no additional access range beyond what the set already has).
    /// </summary>
    private static string[] DeduplicateOrdinal(string[] indicators)
    {
        if(indicators.Length < 2)
        {
            return indicators;
        }

        List<string> deduplicated = new(indicators.Length);
        HashSet<string> seen = new(StringComparer.Ordinal);
        foreach(string indicator in indicators)
        {
            if(seen.Add(indicator))
            {
                deduplicated.Add(indicator);
            }
        }

        return [.. deduplicated];
    }


    /// <summary>
    /// Resolves the effective <see href="https://www.rfc-editor.org/rfc/rfc6749#section-6">RFC 6749
    /// §6</see> scope for a refresh-grant response from the scope carried on the presented
    /// <see cref="ServerRefreshTokenIssuedState"/> and an optional token-request
    /// <c>scope</c>. Mirrors <see cref="ResolveEffectiveResource"/>'s narrowing shape: no
    /// token-request value leaves the full <paramref name="grantedScope"/> in force ("if omitted is
    /// treated as equal to the scope originally granted by the resource owner"); a token-request
    /// value MUST be a subset of the granted set ("The requested scope MUST NOT include any scope
    /// not originally granted"), compared as a case-sensitive SET of space-delimited tokens per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.3">§3.3</see> — order and
    /// repetition carry no meaning (<see cref="DeduplicateOrdinal"/>). Any requested token outside
    /// the granted set fails closed with <see cref="OAuthErrors.InvalidScope"/>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">§5.2</see>: "exceeds the
    /// scope granted by the resource owner"), reachable only after
    /// <see cref="VerifyRefreshClient"/> and the DPoP binding have already passed — the criterion
    /// <see cref="RefreshTokenNotFoundDescription"/>'s remarks state for a refusal that keeps its
    /// own body instead of that constant. A present but blank or all-whitespace token-request
    /// <c>scope</c> is treated the same as an absent one: §3.3's grammar
    /// (<c>scope-token = 1*( ... )</c>) requires at least one character per token, so a blank value
    /// carries no scope-token at all, textually indistinguishable from omission. This method never
    /// narrows the STORED refresh record itself — the caller alone decides what to persist onto
    /// <see cref="ServerRefreshTokenIssuedState.Scope"/>, which §6 requires stay "identical to
    /// that of the refresh token included by the client in the request" across rotation, however
    /// narrow this request was.
    /// </summary>
    /// <param name="grantedScope">The scope stored on the presented refresh record.</param>
    /// <param name="requestedScope">The token request's own <c>scope</c> field, or <see langword="null"/> when absent.</param>
    private static (string EffectiveScope, ServerHttpResponse? Failure) ResolveEffectiveScope(
        string grantedScope, string? requestedScope)
    {
        if(string.IsNullOrWhiteSpace(requestedScope))
        {
            return (grantedScope, null);
        }

        string[] requested = DeduplicateOrdinal(
            requestedScope.Split(' ', StringSplitOptions.RemoveEmptyEntries));
        HashSet<string> grantedTokens = new(
            grantedScope.Split(' ', StringSplitOptions.RemoveEmptyEntries), StringComparer.Ordinal);

        foreach(string token in requested)
        {
            if(!grantedTokens.Contains(token))
            {
                return (string.Empty, ServerHttpResponse.BadRequest(
                    OAuthErrors.InvalidScope,
                    $"The scope parameter must be a subset of the scope originally granted; '{token}' was not granted."));
            }
        }

        return (string.Join(' ', requested), null);
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
        EndpointServer server,
        string authorizationDetailsJson,
        ClientRecord registration,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        var oauth = server.OAuth();
        ParseAuthorizationDetailListDelegate? parse = oauth.ParseAuthorizationDetailsAsync;
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
            oauth.AuthorizationDetailTypes, details, requiredLocation,
            registration.AllowedAuthorizationDetailsTypes);
        if(shapeError is not null)
        {
            return ServerHttpResponse.BadRequest(OAuthErrors.InvalidAuthorizationDetails, shapeError);
        }

        return null;
    }


    /// <summary>
    /// The token-endpoint step's own <c>authorization_details</c> decision — run ONCE, in a step
    /// endpoint's pre-correlation step, after the step has already resolved and carried the
    /// issuer. Unlike <see cref="ValidateAuthorizationDetailsShapeAsync"/> (shared by PAR, direct
    /// authorize and the <c>request_uri</c> completion, none of which ever resolve credential
    /// authorization), this also runs the token endpoint's SUPPORT decision —
    /// <see cref="AuthorizationServerIntegration.ParseAuthorizationDetailsAsync"/> AND
    /// <see cref="AuthorizationServerIntegration.ResolveCredentialAuthorizationAsync"/> both wired
    /// — exactly as <see cref="ResolveGrantedAuthorizationDetailsAsync"/> decides it from
    /// configuration, so a permitted deployment shape (a parser wired for a registered type beyond
    /// the built-in <c>openid_credential</c>, with no credential resolver) answers the SAME
    /// <c>invalid_authorization_details</c> "not supported" refusal for an unknown and a live
    /// grant alike, rather than only for a live one. The <c>locations</c> requirement is resolved
    /// and checked here, once, for this step's own shape refusal; it is not itself carried. On
    /// success, carries the parsed details on <paramref name="context"/> via
    /// <see cref="ExchangeContextAuthorizationDetailsExtensions.SetAuthorizationDetailsStepOutcome"/>
    /// for <see cref="ResolveGrantedAuthorizationDetailsAsync"/> to read instead of re-parsing the
    /// request for the same request.
    /// </summary>
    /// <returns>The refusal to answer with, or <see langword="null"/> to proceed.</returns>
    private static async ValueTask<ServerHttpResponse?> ValidateAndCarryTokenRequestAuthorizationDetailsAsync(
        EndpointServer server,
        string authorizationDetailsJson,
        ClientRecord registration,
        ExchangeContext context,
        Uri issuerUri,
        CancellationToken cancellationToken)
    {
        var oauth = server.OAuth();
        ParseAuthorizationDetailListDelegate? parse = oauth.ParseAuthorizationDetailsAsync;
        ResolveCredentialAuthorizationDelegate? resolve = oauth.ResolveCredentialAuthorizationAsync;
        if(parse is null || resolve is null)
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
            server, registration, context, issuerUri, cancellationToken).ConfigureAwait(false);

        string? shapeError = AuthorizationDetailsShapeError(
            oauth.AuthorizationDetailTypes, details, requiredLocation,
            registration.AllowedAuthorizationDetailsTypes);
        if(shapeError is not null)
        {
            return ServerHttpResponse.BadRequest(OAuthErrors.InvalidAuthorizationDetails, shapeError);
        }

        context.SetAuthorizationDetailsStepOutcome(new AuthorizationDetailsStepOutcome(details));

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
    /// Resolves the OID4VCI 1.0 §5.1.1 / §6.1.1 <c>locations</c> requirement for a caller with no
    /// already-resolved issuer of its own (PAR, direct authorize, the <c>request_uri</c>
    /// completion, and the pre-authorized code grant — none carries an issuer from an earlier
    /// step). Metadata-first: when the deployment declares no
    /// <see cref="AuthorizationServerIntegration.ContributeCredentialIssuerMetadataAsync"/> seam,
    /// or the seam's contribution declares no <c>authorization_servers</c>, returns
    /// <see langword="null"/> WITHOUT resolving an issuer at all — an issuer resolution these
    /// callers do not otherwise need, and, for the pre-authorized code grant, one that would run
    /// AFTER <see cref="AuthorizationServerIntegration.ValidatePreAuthorizedCodeAsync"/> may
    /// already have consumed the code. A step endpoint, which has already resolved and carried an
    /// issuer for the request, calls the
    /// <see cref="ResolveRequiredAuthorizationDetailsLocationAsync(EndpointServer, ClientRecord, ExchangeContext, Uri, CancellationToken)"/>
    /// overload instead, never this one.
    /// </summary>
    private static async ValueTask<string?> ResolveRequiredAuthorizationDetailsLocationAsync(
        EndpointServer server,
        ClientRecord registration,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        var oauth = server.OAuth();
        if(oauth.ContributeCredentialIssuerMetadataAsync is null)
        {
            return null;
        }

        CredentialIssuerMetadataContribution contribution =
            await oauth.ContributeCredentialIssuerMetadataAsync(
                registration, context, cancellationToken).ConfigureAwait(false);
        if(contribution.AuthorizationServers is not { Count: > 0 })
        {
            return null;
        }

        Uri issuer = oauth.ResolveIssuerAsync is not null
            ? (await oauth.ResolveIssuerAsync(registration, context, cancellationToken)
                .ConfigureAwait(false))!
            : await DefaultIssuerResolver.ResolveAsync(registration, context, cancellationToken)
                .ConfigureAwait(false);

        return issuer.OriginalString;
    }


    /// <summary>
    /// Resolves the OID4VCI 1.0 §5.1.1 / §6.1.1 <c>locations</c> requirement against
    /// <paramref name="issuerUri"/>: when the deployment's Credential Issuer metadata declares an
    /// <c>authorization_servers</c> parameter, returns <paramref name="issuerUri"/>'s
    /// <see cref="Uri.OriginalString"/> — the Credential Issuer Identifier value every
    /// <c>openid_credential</c> authorization details object MUST carry in its <c>locations</c>
    /// element; otherwise <see langword="null"/> (the AS is the issuer, so no <c>locations</c> is
    /// required). Never resolves an issuer of its own — a step endpoint's pre-correlation step
    /// passes the issuer it already resolved and carried, so this decision costs no second
    /// resolution for the same request.
    /// </summary>
    private static async ValueTask<string?> ResolveRequiredAuthorizationDetailsLocationAsync(
        EndpointServer server,
        ClientRecord registration,
        ExchangeContext context,
        Uri issuerUri,
        CancellationToken cancellationToken)
    {
        var oauth = server.OAuth();
        if(oauth.ContributeCredentialIssuerMetadataAsync is null)
        {
            return null;
        }

        CredentialIssuerMetadataContribution contribution =
            await oauth.ContributeCredentialIssuerMetadataAsync(
                registration, context, cancellationToken).ConfigureAwait(false);
        if(contribution.AuthorizationServers is not { Count: > 0 })
        {
            return null;
        }

        return issuerUri.OriginalString;
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
        EndpointServer server,
        ClientRecord registration,
        bool isSenderConstrained)
    {
        var oauth = server.OAuth();
        if(isSenderConstrained)
        {
            return null;
        }

        //Mirror the access-token lifetime the Rfc9068AccessTokenProducer will apply: the
        //per-registration override when set, else the one-hour producer default.
        TimeSpan lifetime =
            registration.GetTokenLifetime(WellKnownTokenTypes.AccessToken) ?? TimeSpan.FromHours(1);

        if(lifetime <= oauth.Timings.CredentialAccessTokenSenderConstraintThreshold)
        {
            return null;
        }

        //A long-lived plain bearer Credential token — the §13.10 violation. Surface the detection
        //on the request's trace before failing closed.
        _ = (System.Diagnostics.Activity.Current?.AddEvent(
            new System.Diagnostics.ActivityEvent(
                OAuthEventNames.LongLivedBearerCredentialTokenRefused)));

        return ServerHttpResponse.BadRequest(
            OAuthErrors.InvalidRequest,
            "A long-lived Access Token giving access to Credentials MUST NOT be issued unless "
            + "sender-constrained (OID4VCI 1.0 §13.10). Issue a sender-constrained (DPoP) token, "
            + "or shorten the access-token lifetime to at most "
            + $"{(int)oauth.Timings.CredentialAccessTokenSenderConstraintThreshold.TotalSeconds} seconds.");
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
    /// <remarks>
    /// The trailing <c>stepOutcome</c> argument is the endpoint's pre-correlation step's
    /// already-validated request-only decision
    /// (<see cref="ValidateAndCarryTokenRequestAuthorizationDetailsAsync"/>), when one ran and the
    /// token-request <c>authorization_details</c> value is not <see langword="null"/>: the parse
    /// and shape check below are skipped and <see cref="AuthorizationDetailsStepOutcome.Details"/>
    /// is projected directly. <see langword="null"/> for the callers with no pre-correlation step
    /// (the pre-authorized code grant), which parse and shape-check that value here as before.
    /// </remarks>
    private static async ValueTask<(string? ResponseJson, IReadOnlyList<object>? ClaimDetails, ServerHttpResponse? Failure)> ResolveGrantedAuthorizationDetailsAsync(
        EndpointServer server,
        string? tokenRequestDetailsJson,
        string? authorizedDetailsJson,
        string subject,
        ClientRecord registration,
        ExchangeContext context,
        AuthorizationDetailsStepOutcome? stepOutcome,
        CancellationToken cancellationToken)
    {
        var oauth = server.OAuth();
        if(tokenRequestDetailsJson is null && authorizedDetailsJson is null)
        {
            return (null, null, null);
        }

        ParseAuthorizationDetailListDelegate? parse = oauth.ParseAuthorizationDetailsAsync;
        ResolveCredentialAuthorizationDelegate? resolve = oauth.ResolveCredentialAuthorizationAsync;
        if(parse is null || resolve is null)
        {
            return (null, null, ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidAuthorizationDetails,
                "authorization_details is not supported by this authorization server."));
        }

        IReadOnlyList<CredentialAuthorizationDetail>? requested = null;
        if(tokenRequestDetailsJson is not null)
        {
            IReadOnlyList<AuthorizationDetail> parsedRequested;
            if(stepOutcome is not null)
            {
                //The pre-correlation step already parsed and shape-validated this exact value,
                //against the SAME issuer that step resolved and carried — never re-run either
                //delegate a second time for the same request.
                parsedRequested = stepOutcome.Details;
            }
            else
            {
                //OID4VCI 1.0 §6.1.1: "If the Token Request contains an authorization_details
                //parameter ... of type openid_credential and the Credential Issuer's metadata
                //contains an authorization_servers parameter, the authorization_details object
                //MUST contain the Credential Issuer's identifier in the locations element." No
                //pre-correlation step ran for this caller, so the requirement and the parse both
                //run here, exactly as before.
                string? requiredLocation = await ResolveRequiredAuthorizationDetailsLocationAsync(
                    server, registration, context, cancellationToken).ConfigureAwait(false);

                IReadOnlyList<AuthorizationDetail>? parsed = await parse(
                    tokenRequestDetailsJson, context, cancellationToken).ConfigureAwait(false);
                if(parsed is null)
                {
                    return (null, null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidAuthorizationDetails,
                        "authorization_details could not be parsed."));
                }

                string? shapeError = AuthorizationDetailsShapeError(
                    oauth.AuthorizationDetailTypes, parsed, requiredLocation,
                    registration.AllowedAuthorizationDetailsTypes);
                if(shapeError is not null)
                {
                    return (null, null, ServerHttpResponse.BadRequest(OAuthErrors.InvalidAuthorizationDetails, shapeError));
                }

                parsedRequested = parsed;
            }

            requested = ProjectOpenIdCredentialDetails(parsedRequested);
        }

        IReadOnlyList<CredentialAuthorizationDetail>? authorized = null;
        if(authorizedDetailsJson is not null)
        {
            //The grant-carried value was shape-validated at receipt; a parse failure here
            //means the stored value and the wired parser have diverged — a deployment
            //inconsistency, not a client error. This is a SEPARATE parse of a DIFFERENT value
            //(the stored baseline, not the token-request value the step above may have already
            //parsed and carried) — the "once per request" guarantee upstream is once per request
            //VALUE, not a bound on how many distinct values this function parses.
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
                _ = authorizedConfigurationIds.Add(detail.CredentialConfigurationId!);
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
            _ = (System.Diagnostics.Activity.Current?.AddEvent(
                new System.Diagnostics.ActivityEvent(
                    OAuthEventNames.DuplicateGrantedCredentialConfigurationCollapsed)));
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

            //A denial with no reason set, and an explicit AuthorizationDenied denial, share
            //the same catch-all mapping.
            null => ServerHttpResponse.BadRequest(OAuthErrors.InvalidAuthorizationDetails,
                decision.DenialDescription ?? "The requested authorization details were not granted."),
            CredentialAuthorizationDenialReason.AuthorizationDenied => ServerHttpResponse.BadRequest(OAuthErrors.InvalidAuthorizationDetails,
                decision.DenialDescription ?? "The requested authorization details were not granted."),

            //decision.DenialReason is supplied by the app's own authorization-decision
            //delegate, so an undeclared value shares the AuthorizationDenied mapping rather
            //than being thrown, matching this seam's fail-closed-by-return design.
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
            _ = sb.Append('[');
            bool firstItem = true;
            foreach(GrantedCredentialAuthorization item in granted)
            {
                if(!firstItem)
                {
                    _ = sb.Append(',');
                }

                firstItem = false;
                _ = sb.Append('{');
                bool first = true;
                JsonAppender.AppendStringField(sb, AuthorizationDetailsParameterNames.Type,
                    AuthorizationDetailsTypeValues.OpenIdCredential, ref first);
                JsonAppender.AppendStringField(sb, Oid4VciCredentialParameterNames.CredentialConfigurationId,
                    item.CredentialConfigurationId, ref first);
                JsonAppender.AppendStringArrayField(sb, Oid4VciCredentialParameterNames.CredentialIdentifiers,
                    item.CredentialIdentifiers, ref first);
                _ = sb.Append('}');
            }

            _ = sb.Append(']');

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


    /// <summary>Builds refresh-token redemption using one admitted storage and authentication composition.</summary>
    private static EndpointCandidate BuildRefreshToken() =>
        new()
        {
            Name = WellKnownEndpointNames.AuthCodeRefreshToken,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            StartsNewFlow = false,
            Kind = FlowKind.RefreshToken,
            //DiscoveryMetadataKey null — refresh shares the token endpoint URL.

            //RFC 6749 §5.2: invalid_grant covers "the provided authorization grant ... or refresh
            //token is invalid, expired, revoked ..." — a refresh_token handle miss (unknown,
            //expired, or revoked by a valid authorization-code replay per
            //HandleAuthorizationCodeReplayAsync's DeleteFlowStateAsync call) must answer
            //invalid_grant, not the host-generic invalid_request a correlation-handle miss would
            //otherwise produce.
            HandleNotFoundError = OAuthErrors.InvalidGrant,
            HandleNotFoundErrorDescription = RefreshTokenNotFoundDescription,

            //A present-but-blank refresh_token matches (the acceptance test below only requires the
            //field's presence) then falls through here to null — the parameter this endpoint keys
            //its continuing flow on is known, so the refusal names it rather than falling back to
            //the host's generic "Cannot determine correlation key."
            MissingCorrelationKeyErrorDescription = "Missing refresh_token.",

            BeforeCorrelationAsync = BeforeRefreshCorrelationAsync,

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
                    || !string.Equals(grantType, WellKnownGrantTypes.RefreshToken, StringComparison.Ordinal))
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
                EndpointServer server = context.RequestServer!;
                var oauth = server.OAuth();

                //ResolveCorrelationKeyAsync + LoadFlowStateAsync delivered the persisted
                //refresh-token state; pattern-match to recover its slots. A rotated-out token
                //still maps to a flow id whose current state is the ServerTokenIssuedState
                //BuildRefreshToken's own rotation transition left behind — a retired state
                //carrying SuccessorRefreshFlowId is specifically that rotated-out record, the
                //reuse-detection path per RFC 9700 §4.14.2 (distinct from a code-grant terminal
                //state, whose SuccessorRefreshFlowId is always null and which a refresh_token
                //correlation key can never resolve to, since the two index spaces are disjoint).
                if(currentState is ServerTokenIssuedState { SuccessorRefreshFlowId: not null } retiredState)
                {
                    return await HandleRefreshTokenReuseAsync(
                        oauth, fields, retiredState, context, ct).ConfigureAwait(false);
                }

                if(currentState is not ServerRefreshTokenIssuedState storedRefresh)
                {
                    //A refusal that reads the record answers the endpoint's constant so the answer
                    //never tells whether the record exists — RFC 6749 §5.2's invalid_grant.
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidGrant, RefreshTokenNotFoundDescription));
                }

                ClientRecord? registration = context.ClientRegistration;
                if(registration is null)
                {
                    return (null, ClientAuthenticationFailureResponse(context.IncomingRequest, "Unknown client."));
                }

                ServerHttpResponse? clientFailure = VerifyRefreshClient(
                    fields, registration, storedRefresh.ClientId, context);
                if(clientFailure is not null)
                {
                    return (null, clientFailure);
                }

                //BeforeRefreshCorrelationAsync already resolved the issuer once for this request
                //and carried it; a missing carry means the endpoint's step did not run as the
                //dispatcher requires, and is answered as a server fault rather than silently
                //resolving a second, possibly different, issuer.
                if(context.CorrelationStepIssuer is not Uri issuerUri)
                {
                    return (null, ServerHttpResponse.ServerError(OAuthErrors.ServerError,
                        "The endpoint's pre-correlation step recorded no resolved issuer."));
                }

                //OpenID Connect Core 1.0 §12.2: a refreshed ID Token's iss "MUST be the same as in
                //the ID Token issued when the original authentication occurred" — the mix-up
                //defense of RFC 9700 §4.4 applied to the SECOND issuer resolution a refresh
                //performs. A mismatch is an INVALID presentation: refused before any DPoP check or
                //claim, minting and revoking nothing.
                if(!IsSameIssuerAsIssuance(issuerUri, storedRefresh.ExpectedIssuer))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidGrant, RefreshTokenNotFoundDescription));
                }

                DateTimeOffset now = server.TimeProvider.GetUtcNow();

                //RFC 9449 §5 — when the refresh token was issued under a
                //DPoP-bound flow, the refresh exchange MUST present a proof
                //whose thumbprint matches the stored binding. The request-only half already ran
                //once, in BeforeRefreshCorrelationAsync; this reads the carried outcome and
                //rejects on thumbprint mismatch with invalid_dpop_proof. A missing carry means the
                //step did not run as the dispatcher requires, and is a server fault rather than a
                //silent Bearer fallback.
                ConfirmationMethod? boundConfirmation = storedRefresh.Confirmation;
                if(context.DpopStepOutcome is not DpopValidationOutcome carriedDpopOutcome)
                {
                    return (null, ServerHttpResponse.ServerError(OAuthErrors.ServerError,
                        "The endpoint's pre-correlation step recorded no DPoP outcome."));
                }

                DpopValidationOutcome dpopOutcome = await DpopTokenEndpointValidation.BindValidatedProofAsync(
                    server, context, registration, issuerUri, carriedDpopOutcome,
                    expectedThumbprint: boundConfirmation?.JwkThumbprint,
                    proofRequiredByRecord: boundConfirmation is { IsEmpty: false }, ct).ConfigureAwait(false);

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
                _ = fields.TryGetValue(OAuthRequestParameterNames.AuthorizationDetails, out string? refreshRequestDetails);
                (string? grantedDetailsJson, IReadOnlyList<object>? grantedDetailsClaim, ServerHttpResponse? detailsFailure) =
                    await ResolveGrantedAuthorizationDetailsAsync(
                        server,
                        string.IsNullOrWhiteSpace(refreshRequestDetails) ? null : refreshRequestDetails,
                        storedRefresh.AuthorizationDetails,
                        storedRefresh.SubjectId,
                        registration,
                        context,
                        context.AuthorizationDetailsStepOutcome,
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

                //RFC 6749 §6: resolve the effective scope for the refreshed access token. No
                //refresh-request scope leaves the full grant carried on storedRefresh.Scope in
                //force; a present one MUST be a subset of it (the access token — and every
                //scope-gated token producer — narrows to that subset) or the request fails
                //invalid_scope. The refresh token itself is never narrowed by this — see the Scope
                //assignment on newRefreshState below, carried verbatim from storedRefresh per §6's
                //"the refresh token scope MUST be identical to that of the refresh token included
                //by the client in the request."
                _ = fields.TryGetValue(OAuthRequestParameterNames.Scope, out string? requestedScope);
                (string effectiveScope, ServerHttpResponse? scopeFailure) =
                    ResolveEffectiveScope(storedRefresh.Scope, requestedScope);
                if(scopeFailure is not null)
                {
                    return (null, scopeFailure);
                }

                //RFC 8707 §2.2: resolve the effective resource set for the refreshed access
                //token. No refresh-request resource leaves the full grant carried on
                //storedRefresh.Resource in force; a present one MUST be a subset of it (the
                //access token narrows to that subset) or the request fails invalid_target. The
                //refresh token itself is never narrowed by this — see the Resource assignment on
                //newRefreshState below.
                (IReadOnlyList<string>? effectiveResource, ServerHttpResponse? resourceFailure) =
                    ResolveEffectiveResource(storedRefresh.Resource, ReadResource(fields));
                if(resourceFailure is not null)
                {
                    return (null, resourceFailure);
                }

                //Carried into the response's own BuildResponse step (ExchangeContextRefreshScopeExtensions)
                //so the wire scope member reflects this same effective value rather than the
                //terminal state's own Scope, which stays the record's full stored grant.
                context.SetEffectiveRefreshScope(effectiveScope);

                //OAuth 2.1 draft-16 §4.3.1: "Authorization servers MUST utilize one of these
                //methods to detect refresh token replay by malicious actors for public clients"
                //— rotation being the method this library uses (RFC 9700 §2.2.2 names it as an
                //accepted alternative to sender-constraining). Detecting a REUSE of an
                //already-rotated token, per the same paragraph, requires rotation itself to be
                //exactly-once under concurrency: claiming here — after every verification above
                //has passed, before any effect a second concurrent caller could also perform — is
                //what makes rotation hold when the same refresh token is presented by N
                //concurrent callers. A losing claim means another caller already rotated this
                //exact presentation; this caller performs no effect and mints nothing.
                bool isClaimed = await oauth.ClaimFlowStateAsync!(
                    context.TenantId!.Value, context.FlowId!, context.FlowStepCount ?? 0, context, ct)
                    .ConfigureAwait(false);
                if(!isClaimed)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidGrant, RefreshTokenNotFoundDescription));
                }

                IssuanceContext issuance = new()
                {
                    Registration = registration,
                    Context = context,
                    IssuerUri = issuerUri,
                    Subject = storedRefresh.SubjectId,
                    Scope = effectiveScope,
                    ClientId = storedRefresh.ClientId,
                    GrantType = WellKnownGrantTypes.RefreshToken,
                    IssuedAt = now,
                    AuthTime = storedRefresh.AuthTime,
                    SessionId = storedRefresh.SessionId,
                    Acr = storedRefresh.Acr,
                    Confirmation = confirmation,
                    RefreshTokenOriginatingGrantType = storedRefresh.OriginatingGrantType,
                    Audience = effectiveResource is { Count: > 0 } ? effectiveResource : null
                };

                IReadOnlyList<TokenProducer> producers =
                    oauth.TokenProducers.Count > 0
                        ? oauth.TokenProducers
                        : DefaultTokenProducers;

                //One-time OidcClaims resolution per request — see BuildToken
                //for rationale.
                OidcClaims? preResolvedOidcClaims = await PreResolveOidcClaimsAsync(
                    server, issuance, ct).ConfigureAwait(false);

                (TokenIssuanceResult? issuanceResult, ServerHttpResponse? issuanceFailure) =
                    await IssueTokensAsync(
                        server, registration, context, issuance, producers, preResolvedOidcClaims, now, ct)
                        .ConfigureAwait(false);
                if(issuanceFailure is not null)
                {
                    return (null, issuanceFailure);
                }

                TokenIssuanceResult issued = issuanceResult!;
                Dictionary<string, string> issuedTokens = issued.IssuedTokens;
                Dictionary<string, IssuedTokenAudit> issuedAudits = issued.IssuedAudits;
                DateTimeOffset latestExpiry = issued.LatestExpiry;

                if(issuedTokens.Count == 0)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, "No applicable token producers."));
                }

                //RFC 9700 §2.2.2 rotation: invalidate the presented refresh token by retiring its
                //flow record (see the "No explicit delete" remark below) and issue a fresh refresh
                //token under a new flow id. The value rides the identifier seam so the application
                //owns the entropy source and its provenance tracking.
                string newRefreshToken = await oauth.GenerateIdentifierAsync!(
                    WellKnownIdentifierPurposes.OAuthRefreshToken, context, ct)
                    .ConfigureAwait(false);
                DateTimeOffset newRefreshExpiresAt = now + context.RefreshTokenLifetime;

                //The retired record this transition produces must outlive every token a later
                //reuse of THIS presentation could be asked to revoke — in particular the freshly
                //minted successor refresh token, whose own lifetime can exceed the just-issued
                //access token's. Using the access token's own latestExpiry alone (as the
                //code-grant issuance path does) would let EndpointServer.HandleCoreAsync's expiry
                //gate treat the retired record as gone the moment the access token expires,
                //silently disabling reuse detection for the rest of the successor's lifetime.
                DateTimeOffset retiredRecordExpiresAt =
                    latestExpiry > newRefreshExpiresAt ? latestExpiry : newRefreshExpiresAt;

                //Threaded onto ServerTokenExchangeSucceeded.SuccessorRefreshFlowId below so the
                //retired ServerTokenIssuedState this transition produces carries the family link a
                //later reuse of THIS presentation's refresh token walks (HandleRefreshTokenReuseAsync).
                //Remains null when no new refresh state is saved (oauth.SaveFlowStateAsync unwired),
                //in which case a reuse of the retired token has no successor to revoke.
                string? successorRefreshFlowId = null;

                if(oauth.SaveFlowStateAsync is not null)
                {
                    string newRefreshFlowId = await oauth.GenerateIdentifierAsync!(
                        WellKnownIdentifierPurposes.OAuthRefreshFlowId, context, ct)
                        .ConfigureAwait(false);
                    successorRefreshFlowId = newRefreshFlowId;
                    ServerRefreshTokenIssuedState newRefreshState = new()
                    {
                        FlowId = newRefreshFlowId,

                        //Carried verbatim across rotation, exactly as OriginatingGrantType is, so
                        //the grant this refresh token belongs to never changes.
                        GrantFlowId = storedRefresh.GrantFlowId,
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
                        SessionId = storedRefresh.SessionId,
                        Acr = storedRefresh.Acr,

                        //Propagated verbatim, never re-stamped to refresh_token — the field
                        //tracks the chain's originating grant across every rotation so a later
                        //redemption can still tell whether an End-User authentication backs it.
                        OriginatingGrantType = storedRefresh.OriginatingGrantType,

                        //RFC 9396 §6.1: the authorization details ride rotation unchanged — a
                        //narrowing refresh reduces only the access token it mints, "but the
                        //resource owner's previous authorization is unchanged by such requests" —
                        //exactly as the scope above rides rotation from the stored grant. A
                        //detail-less grant keeps a null slot.
                        AuthorizationDetails = storedRefresh.AuthorizationDetails,

                        //RFC 8707 §2.2: the refresh token stays bound to the FULL original grant
                        //across every rotation — never the effectiveResource this exchange's
                        //access token may have been narrowed to.
                        Resource = storedRefresh.Resource
                    };
                    await oauth.SaveFlowStateAsync(
                        registration.TenantId, newRefreshFlowId, newRefreshState, stepCount: 0, context, ct)
                        .ConfigureAwait(false);
                }

                //No explicit delete of the old refresh state: the dispatcher's own unconditional
                //save (EndpointServer.HandleCoreAsync step 8) overwrites this exact flowId with the
                //ServerTokenIssuedState the PDA transition below produces — carrying
                //SuccessorRefreshFlowId forward — the moment this handler returns. Deleting it here
                //first would be redundant AND would defeat reuse detection: whatever secondary index
                //an application's DeleteServerFlowStateDelegate prunes as a side effect of removing a
                //flow record (see HandleRefreshTokenReuseAsync's remarks) must still resolve THIS
                //flowId so a later presentation of the just-retired token reaches the retired state
                //rather than a generic "not found."

                issuedTokens[WellKnownTokenTypes.RefreshToken] = newRefreshToken;

                IssuedTokenSet tokenSet = new() { Tokens = issuedTokens };
                context.SetIssuedTokens(tokenSet);

                IssuedTokenAuditSet auditSet = new() { Audits = issuedAudits };

                return (new ServerTokenExchangeSucceeded(
                    IssuedTokens: auditSet,
                    IssuedAt: now,
                    ExpiresAt: retiredRecordExpiresAt)
                {
                    Confirmation = confirmation,
                    SuccessorRefreshFlowId = successorRefreshFlowId
                }, null);
            },

            BuildResponse = static (state, flowKindName, context) =>
            {
                if(state is not ServerTokenIssuedState issued)
                {
                    return ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, "Unexpected state after refresh exchange.");
                }

                //A ServerRefreshTokenReuseDetected transition re-enters this same state type
                //with RevokedAt now set and mints no tokens this request — HandleRefreshTokenReuseAsync's
                //VALID-reuse family revocation, mirroring the code-replay marker. The response is
                //invalid_grant per RFC 6749 §5.2, never the success shape below.
                if(issued.RevokedAt is not null)
                {
                    return ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidGrant, RefreshTokenNotFoundDescription);
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
                    _ = sb.Append('{');
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

                    //RFC 6749 §5.1: the response's scope member is the EFFECTIVE scope this
                    //response was minted against (ExchangeContextRefreshScopeExtensions), not the
                    //terminal state's own Scope — which stays the record's full stored grant, per
                    //§6's identical-across-rotation rule for the refresh token itself.
                    string? scope = context.EffectiveRefreshScope ?? issued.Scope;
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

                    _ = sb.Append('}');
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


    /// <summary>Builds token revocation using the admitted authentication and token operations.</summary>
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
                EndpointServer server = context.RequestServer!;
                var oauth = server.OAuth();

                ClientRecord? registration = context.ClientRegistration;
                if(registration is null)
                {
                    return (null, ClientAuthenticationFailureResponse(context.IncomingRequest, "Unknown client."));
                }

                //Identification of an optional client_id form field before authentication:
                //a field that names another registration is refused invalid_client here, never
                //forwarded into the authentication seam.
                ServerHttpResponse? revocationIdentificationFailure =
                    RefuseUnidentifiedClient(registration, fields, context.IncomingRequest);
                if(revocationIdentificationFailure is not null)
                {
                    return (null, revocationIdentificationFailure);
                }

                //RFC 7009 §2.1: the client MUST authenticate using the same method
                //it uses at the token endpoint. The seam owns the method and the
                //credential comparison; the candidate gate guarantees it is wired.
                bool isClientAuthenticated = await oauth.ValidateClientCredentialsAsync!(
                    context.IncomingRequest, fields, registration, context, ct).ConfigureAwait(false);
                if(!isClientAuthenticated)
                {
                    return (null, ClientAuthenticationFailureResponse(
                        context.IncomingRequest, "Client authentication failed."));
                }

                //RFC 7009 §2.1: token is REQUIRED. The matcher already guaranteed
                //its presence; the guard keeps the contract explicit and local.
                if(!fields.TryGetValue(OAuthRequestParameterNames.Token, out string? token)
                    || string.IsNullOrEmpty(token))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "Missing token parameter."));
                }

                _ = fields.TryGetValue(OAuthRequestParameterNames.TokenTypeHint, out string? tokenTypeHint);

                //RFC 7009 §2.1: revoke on behalf of the authenticated client; the
                //application scopes the revocation to that client's tokens and
                //cascades refresh -> access. An unrecognized token_type_hint is a
                //hint, not an error.
                await oauth.RevokeTokenAsync!(
                    token, tokenTypeHint, registration, context, ct).ConfigureAwait(false);

                //RFC 7009 §2.2: HTTP 200 with an empty body whether the token was
                //live, already revoked, or unknown — the response never reveals
                //which, so a probing client learns nothing about token validity.
                return (null, ServerHttpResponse.Ok());
            },
            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    /// <summary>Builds token introspection using the admitted authentication and token operations.</summary>
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
                EndpointServer server = context.RequestServer!;
                var oauth = server.OAuth();

                ClientRecord? registration = context.ClientRegistration;
                if(registration is null)
                {
                    return (null, ClientAuthenticationFailureResponse(context.IncomingRequest, "Unknown client."));
                }

                //Identification of an optional client_id form field before authentication:
                //a field that names another registration is refused invalid_client here, never
                //forwarded into the authentication seam.
                ServerHttpResponse? introspectionIdentificationFailure =
                    RefuseUnidentifiedClient(registration, fields, context.IncomingRequest);
                if(introspectionIdentificationFailure is not null)
                {
                    return (null, introspectionIdentificationFailure);
                }

                //RFC 7662 §2.3: a caller authenticating with client credentials that
                //fail authentication gets HTTP 401. The candidate gate guarantees the
                //seam is wired.
                bool isClientAuthenticated = await oauth.ValidateClientCredentialsAsync!(
                    context.IncomingRequest, fields, registration, context, ct).ConfigureAwait(false);
                if(!isClientAuthenticated)
                {
                    return (null, ClientAuthenticationFailureResponse(
                        context.IncomingRequest, "Client authentication failed."));
                }

                //RFC 7662 §2.1: token is REQUIRED. The matcher already guaranteed its
                //presence; the guard keeps the contract explicit and local.
                if(!fields.TryGetValue(OAuthRequestParameterNames.Token, out string? token)
                    || string.IsNullOrEmpty(token))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "Missing token parameter."));
                }

                _ = fields.TryGetValue(OAuthRequestParameterNames.TokenTypeHint, out string? tokenTypeHint);

                //RFC 7662 §2.2: the application reads its own token store and returns the
                //token's metadata, or an inactive result for an unknown / expired / revoked
                //token (or one this caller may not see). An unrecognized token_type_hint is
                //a hint, not an error. A well-formed, authorized query for an inactive token
                //is NOT an error (RFC 7662 §2.3) — it answers 200 with {"active":false}.
                TokenIntrospectionResult result = await oauth.IntrospectTokenAsync!(
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

        //RFC 7662 §2.2 aud: "string identifier or list of string identifiers" — the array form is
        //permitted, so this projection always emits it, including a single audience, the SAME
        //shape JwtPayload.ForAccessToken uses for the JWT access token's own aud claim (RFC 7519
        //§4.1.3's general representation). One server, one aud wire shape, regardless of which
        //endpoint a Resource Server reads it from.
        if(result.Audience is { Count: > 0 } audience)
        {
            List<object> audiences = [.. audience];

            members["aud"] = audiences;
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
        EndpointServer server,
        ExchangeContext context,
        ClientRecord registration,
        TokenIntrospectionResult result,
        CancellationToken cancellationToken)
    {
        var oauth = server.OAuth();
        if(!registration.SigningKeys.TryGetValue(
                KeyUsageContext.IntrospectionResponseSigning, out SigningKeySet? introspectionKeys)
            || introspectionKeys.Current.IsEmpty)
        {
            return ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidRequest,
                "A JWT introspection response was requested but no introspection-response "
                + "signing key is configured for this caller.");
        }

        if(oauth.Cryptography.SigningKeyResolver is null
            || oauth.Codecs.JwtHeaderSerializer is null
            || oauth.Codecs.JwtPayloadSerializer is null
            || oauth.Codecs.Encoder is null)
        {
            return ServerHttpResponse.ServerError(
                OAuthErrors.ServerError,
                "The introspection-response signing configuration is incomplete.");
        }

        KeyId signingKeyId = introspectionKeys.Current[0];
        PrivateKeyMemory? signingKey = await oauth.Cryptography.SigningKeyResolver(
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
            issuerUri = oauth.ResolveIssuerAsync is not null
                ? (await oauth.ResolveIssuerAsync(registration, context, cancellationToken)
                    .ConfigureAwait(false))!
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
            oauth.Codecs.JwtHeaderSerializer,
            oauth.Codecs.JwtPayloadSerializer,
            oauth.Codecs.Encoder,
            oauth.MemoryPool!,
            cancellationToken).ConfigureAwait(false);
        string responseJwt = JwsSerialization.SerializeCompact(jws, oauth.Codecs.Encoder);

        return ServerHttpResponse.Ok(responseJwt, WellKnownMediaTypes.Application.TokenIntrospectionJwt);
    }


    /// <summary>
    /// Builds the RFC 6749 §4.1.2 success redirect carrying the RAW authorization code — the
    /// value the client must present at the token endpoint — never
    /// <see cref="ServerCodeIssuedState.CodeHash"/>. The raw code was stashed on the request
    /// context by the same <c>BuildInputAsync</c> call that produced <paramref name="code"/>
    /// (<c>ExchangeContextServerExtensions.SetRawAuthorizationCode(string)</c>); the state itself
    /// is hash-only per the class's own contract (see <see cref="ServerCodeIssuedState"/>). Also
    /// appends the RFC 9207 / FAPI 2.0 §5.3.1.2 <c>iss</c> response parameter under
    /// <c>policy.EmitIssOnRedirect</c>.
    /// </summary>
    /// <remarks>
    /// Reads <c>ExchangeContextServerExtensions.ResolvedIssuer</c>, populated by
    /// <see cref="TryResolveRedirectIssuerAsync"/> during
    /// <c>EvaluateAuthenticationRequirementsAsync</c> — the same resolution path
    /// <c>MetadataEndpoints</c> uses for the discovery <c>issuer</c> field
    /// (RFC 9207 §2.3). When resolution found no usable issuer the parameter is omitted
    /// rather than failing the redirect — the strict-default deployment populates
    /// <see cref="ClientRecord.IssuerUri"/> or <c>ExchangeContextServerExtensions.ResolvedIssuer</c>
    /// and the permissive deployment opts out via <c>policy.EmitIssOnRedirect</c>.
    /// </remarks>
    private static ServerHttpResponse BuildAuthorizeRedirect(
        ServerCodeIssuedState code, ExchangeContext context)
    {
        if(context.RawAuthorizationCode is not string rawCode)
        {
            //Structural invariant: every code-issuing BuildInputAsync sets this immediately
            //after generating the code, before this response is ever built. Reaching here
            //without it means that invariant was broken — a library bug, not a runtime
            //condition reachable from client input.
            return ServerHttpResponse.ServerError(
                OAuthErrors.ServerError, "Raw authorization code missing from the request context.");
        }

        return BuildAuthorizeRedirectWithParameters(
            code.RedirectUri,
            $"code={Uri.EscapeDataString(rawCode)}",
            code.State,
            context);
    }


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
    /// the client can bind the redirect to its pending request. The <c>iss</c> value is
    /// <c>ExchangeContextServerExtensions.ResolvedIssuer</c>, resolved once ahead of
    /// both this success path and the error-redirect path by
    /// <see cref="TryResolveRedirectIssuerAsync"/>; the parameter is omitted when resolution
    /// found no usable issuer.
    /// </summary>
    /// <remarks>
    /// The base is <paramref name="redirectUri"/>'s <see cref="Uri.OriginalString"/>, never
    /// <see cref="Uri.ToString()"/>: the token endpoint's RFC 6749 §4.1.3 identical-value check
    /// (see the token-endpoint handler's <c>redirect_uri</c> comparison) binds to that same
    /// <see cref="Uri.OriginalString"/> as persisted on <c>ServerCodeIssuedState.RedirectUri</c>, so
    /// this is a derived invariant of that RFC 6749 §4.1.3 identical-value check: the authorization
    /// server hands the client back exactly the string it will later demand —
    /// <see cref="Uri.ToString()"/> re-canonicalizes (default-port elision, host casing) and a client
    /// that echoes what it actually received rather than what it originally sent would otherwise be
    /// refused a value the AS itself produced.
    /// </remarks>
    private static ServerHttpResponse BuildAuthorizeRedirectWithParameters(
        Uri redirectUri, string parameters, string? state, ExchangeContext context)
    {
        string baseUri = redirectUri.OriginalString;
        char separator = baseUri.Contains('?', StringComparison.Ordinal) ? '&' : '?';
        string location = $"{baseUri}{separator}{parameters}";

        if(!string.IsNullOrEmpty(state))
        {
            location += $"&state={Uri.EscapeDataString(state)}";
        }

        if(context.EmitIssOnRedirect)
        {
            Uri? issuer = context.ResolvedIssuer;
            if(issuer is not null)
            {
                //RFC 9207 §2.3: the iss parameter MUST be identical to the issuer value
                //in the server's metadata document. Discovery emits Uri.OriginalString
                //(see MetadataEndpoints), so the redirect emits the same member —
                //Uri.ToString() re-canonicalizes (e.g. appends a trailing slash to an
                //authority-only URL) and would break the byte-identity a client's
                //RFC 3986 §6.2.1 simple string comparison requires.
                location += $"&iss={Uri.EscapeDataString(issuer.OriginalString)}";
            }
        }

        return ServerHttpResponse.Redirect(location);
    }


    /// <summary>
    /// Composes the RFC 6749 §4.1.2 success response parameters that ride inside a JARM
    /// JWT Response Document: the RAW authorization <paramref name="code"/> — never the
    /// persisted <see cref="ServerCodeIssuedState.CodeHash"/> — plus <c>state</c> when the
    /// request sent one.
    /// </summary>
    private static Dictionary<string, object> BuildAuthorizeSuccessParameters(
        string code, string? state)
    {
        Dictionary<string, object> parameters = new(2, StringComparer.Ordinal)
        {
            ["code"] = code
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
        RequestFields fields, EndpointServer server, ExchangeContext context)
    {
        _ = fields.TryGetValue(OAuthRequestParameterNames.ResponseMode, out string? responseMode);
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
        string responseMode, EndpointServer server, ExchangeContext context)
    {
        var oauth = server.OAuth();
        if(!JarmResponseModes.IsJwtSecuredResponseMode(responseMode))
        {
            return null;
        }

        ClientRecord? registration = context.ClientRegistration;
        bool isJarmServable = registration is not null
            && registration.SigningKeys.TryGetValue(
                KeyUsageContext.AuthorizationResponseSigning, out SigningKeySet? jarmKeys)
            && !jarmKeys.Current.IsEmpty
            && oauth.Cryptography.SigningKeyResolver is not null
            && oauth.Codecs.JwtHeaderSerializer is not null
            && oauth.Codecs.JwtPayloadSerializer is not null
            && oauth.Codecs.Encoder is not null;

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
        EndpointServer server,
        ExchangeContext context,
        string? responseMode,
        string clientId,
        IReadOnlyDictionary<string, object> responseParameters,
        CancellationToken cancellationToken)
    {
        var oauth = server.OAuth();
        if(responseMode is null || !JarmResponseModes.IsJwtSecuredResponseMode(responseMode))
        {
            return (null, null);
        }

        ClientRecord? registration = context.ClientRegistration;
        if(registration is null
            || !registration.SigningKeys.TryGetValue(
                KeyUsageContext.AuthorizationResponseSigning, out SigningKeySet? jarmKeys)
            || jarmKeys.Current.IsEmpty
            || oauth.Cryptography.SigningKeyResolver is null
            || oauth.Codecs.JwtHeaderSerializer is null
            || oauth.Codecs.JwtPayloadSerializer is null
            || oauth.Codecs.Encoder is null)
        {
            return (null, ServerHttpResponse.ServerError(
                OAuthErrors.ServerError,
                "A JWT-secured authorization response was requested but the "
                + "authorization-response signing configuration is incomplete."));
        }

        KeyId signingKeyId = jarmKeys.Current[0];
        PrivateKeyMemory? signingKey = await oauth.Cryptography.SigningKeyResolver(
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
            issuerUri = oauth.ResolveIssuerAsync is not null
                ? (await oauth.ResolveIssuerAsync(registration, context, cancellationToken)
                    .ConfigureAwait(false))!
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
            oauth.Codecs.Encoder,
            oauth.Codecs.JwtHeaderSerializer,
            oauth.Codecs.JwtPayloadSerializer,
            oauth.MemoryPool!,
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
        EndpointServer server,
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
        AuthorizationDenialReason.InvalidTarget => OAuthErrors.InvalidTarget,
        AuthorizationDenialReason.LoginRequired => OAuthErrors.LoginRequired,
        AuthorizationDenialReason.InteractionRequired => OAuthErrors.InteractionRequired,
        AuthorizationDenialReason.ConsentRequired => OAuthErrors.ConsentRequired,
        AuthorizationDenialReason.AccountSelectionRequired => OAuthErrors.AccountSelectionRequired,
        AuthorizationDenialReason.InvalidScope => OAuthErrors.InvalidScope,
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
        AuthorizationDenialReason.InvalidTarget =>
            "The requested resource is invalid, missing, unknown, or malformed.",
        AuthorizationDenialReason.LoginRequired =>
            "The Authorization Server requires End-User authentication.",
        AuthorizationDenialReason.InteractionRequired =>
            "The Authorization Server requires End-User interaction of some form to proceed.",
        AuthorizationDenialReason.ConsentRequired =>
            "The Authorization Server requires End-User consent.",
        AuthorizationDenialReason.AccountSelectionRequired =>
            "The End-User is required to select a session at the Authorization Server.",
        AuthorizationDenialReason.InvalidScope =>
            "The requested scope is invalid, unknown, or excessive.",

        //A denial with no reason set, and an explicit AccessDenied denial, share the same
        //RFC 6749 §4.1.2.1 default description.
        null => "The authorization request was denied.",
        AuthorizationDenialReason.AccessDenied => "The authorization request was denied.",

        _ => "The authorization request was denied."
    };


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


    /// <summary>
    /// Reads the optional <c>max_age</c> request parameter (OIDC Core §3.1.2.1) — the maximum
    /// authentication age in whole seconds, a non-negative integer. Returns the parsed value
    /// (or <see langword="null"/> when the parameter is absent) and whether it was well-formed;
    /// a present-but-malformed value reports <c>IsWellFormed = false</c> so the caller rejects
    /// the request with <c>invalid_request</c>. Shared by the query-parameter authorize paths
    /// (PAR and direct); the JAR path reads the same parameter from the signed request object.
    /// </summary>
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


    /// <summary>
    /// Whether the space-delimited <c>prompt</c> value <paramref name="prompt"/> carries
    /// <see cref="WellKnownPromptValues.None"/> together with any other value — OIDC Core
    /// §3.1.2.1: "If this parameter contains none with any other value, an error is returned."
    /// </summary>
    private static bool HasNoneWithOtherPromptValues(string? prompt)
    {
        if(string.IsNullOrEmpty(prompt))
        {
            return false;
        }

        string[] values = prompt.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        return values.Length > 1 && Array.Exists(values, WellKnownPromptValues.IsNone);
    }


    /// <summary>
    /// Parses the recognized <c>prompt</c> values out of the space-delimited
    /// <paramref name="prompt"/>, per OIDC Core §3.1.2.1. A value this library does not
    /// recognize is silently dropped rather than surfaced: "If an OP receives a prompt value
    /// outside the set defined above that it does not understand, it MAY return an error or it
    /// MAY ignore it" — this library ignores it.
    /// </summary>
    private static ImmutableHashSet<string> ParseRequestedPromptValues(string? prompt)
    {
        if(string.IsNullOrEmpty(prompt))
        {
            return ImmutableHashSet<string>.Empty;
        }

        ImmutableHashSet<string>.Builder builder = ImmutableHashSet.CreateBuilder<string>(StringComparer.Ordinal);
        foreach(string value in prompt.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            if(WellKnownPromptValues.IsNone(value)
                || WellKnownPromptValues.IsLogin(value)
                || WellKnownPromptValues.IsConsent(value)
                || WellKnownPromptValues.IsSelectAccount(value))
            {
                _ = builder.Add(value);
            }
        }

        return builder.ToImmutable();
    }


    /// <summary>
    /// Resolves the issuer URI for the RFC 9207 §2 Authorize-redirect <c>iss</c> parameter
    /// through the identical resolution path
    /// <c>MetadataEndpoints</c> uses for the discovery <c>issuer</c> field —
    /// the application's <see cref="Verifiable.Server.ServerIntegration.ResolveIssuerAsync"/>
    /// delegate when configured, otherwise <see cref="DefaultIssuerResolver"/> — so RFC 9207
    /// §2.3's "the issuer identifier included in the server's metadata value issuer MUST be
    /// identical to the iss parameter's value" holds by construction rather than by two
    /// independently maintained code paths agreeing coincidentally. Returns
    /// <see langword="null"/> when resolution fails — no issuer configured, or the configured
    /// value fails the RFC 9207 §2 https/no-query/no-fragment shape
    /// (<see cref="IssuerIdentifierValidation.IsValidIssuerShape"/>) — so the caller omits the
    /// <c>iss</c> parameter rather than failing the redirect.
    /// </summary>
    private static async ValueTask<Uri?> TryResolveRedirectIssuerAsync(
        EndpointServer server,
        ClientRecord registration,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        var oauth = server.OAuth();
        try
        {
            Uri issuer = oauth.ResolveIssuerAsync is not null
                ? (await oauth.ResolveIssuerAsync(registration, context, cancellationToken).ConfigureAwait(false))!
                : await DefaultIssuerResolver.ResolveAsync(registration, context, cancellationToken).ConfigureAwait(false);

            return issuer;
        }
        catch(InvalidOperationException)
        {
            return null;
        }
    }


    /// <summary>
    /// Evaluates a request's RFC 9470 §5 step-up authentication requirements at the
    /// authorization endpoint, shared across every code-issuing authorize path (PAR-backed,
    /// direct, and JAR). Enforces the temporal <c>max_age</c> recency requirement itself
    /// (OIDC Core §3.1.2.1, using the deployment's <c>ClockSkewTolerance</c>), then invokes
    /// the application's <see cref="EvaluateAuthorizationRequestDelegate"/> for the semantic
    /// decision (<c>acr</c> satisfaction, consent, policy, and RFC 6749 §3.3 scope narrowing via
    /// <see cref="AuthorizationRequestDecision.Permit(string?)"/>).
    /// </summary>
    /// <returns>
    /// <c>Failure</c> carries the OAuth Authorization Error Response redirect to use when a
    /// requirement is unmet or the seam granted an invalid scope, or <see langword="null"/> when
    /// the request may proceed to code issuance — in which case <c>EffectiveScope</c> is the
    /// (possibly narrowed and canonicalized) scope to grant.
    /// </returns>
    private static async ValueTask<(string EffectiveScope, ServerHttpResponse? Failure)>
        EvaluateAuthenticationRequirementsAsync(
        EndpointServer server,
        ExchangeContext context,
        string? requestedAcrValues,
        int? requestedMaxAge,
        string requestedScope,
        string? subjectId,
        DateTimeOffset now,
        Uri redirectUri,
        string? requestState,
        string? requestedAuthorizationDetails = null,
        string? responseMode = null,
        string? clientId = null,
        string? requestedIssuerState = null,
        string? requestedResource = null,
        string? requestedPrompt = null,
        CancellationToken cancellationToken = default)
    {
        var oauth = server.OAuth();

        //Resolved once, ahead of both the requirement checks below and the eventual
        //success redirect, so BuildAuthorizeRedirectWithParameters (read from the sync
        //BuildResponse for the success path, and from the async error path below) sees
        //the identical value regardless of which path emits the RFC 9207 iss parameter.
        if(context.ClientRegistration is { } registrationForIssuer)
        {
            Uri? resolvedIssuer = await TryResolveRedirectIssuerAsync(
                server, registrationForIssuer, context, cancellationToken).ConfigureAwait(false);
            if(resolvedIssuer is not null)
            {
                context.SetResolvedIssuer(resolvedIssuer);
            }
        }

        //RFC 6749 §3.1 / OAuth 2.1 §3.1: "The authorization server MUST first authenticate the
        //resource owner." No established subject answers the RFC 6749 §4.1.2.1 Authorization
        //Error Response redirect with error=login_required (OIDC Core §3.1.2.6: "The
        //Authorization Server requires End-User authentication") rather than a 500 — this is the
        //expected first state under the MUST-authenticate rule, not an unexpected condition
        //(RFC 9110 §15.6.1), so it is never server_error. This runs before max_age (there is no
        //auth_time to measure) and before the decision seam (AuthorizationRequestEvaluation.Subject
        //stays non-null; the seam is never called without an established subject).
        if(subjectId is null)
        {
            return (requestedScope, await BuildAuthorizeErrorResponseAsync(
                server,
                context,
                redirectUri,
                OAuthErrors.LoginRequired,
                "No End-User is authenticated for this request.",
                requestState,
                responseMode,
                clientId,
                cancellationToken).ConfigureAwait(false));
        }

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
                return (requestedScope, await BuildAuthorizeErrorResponseAsync(
                    server,
                    context,
                    redirectUri,
                    OAuthErrors.UnmetAuthenticationRequirements,
                    "The established authentication does not satisfy the requested max_age.",
                    requestState,
                    responseMode,
                    clientId,
                    cancellationToken).ConfigureAwait(false));
            }
        }

        ImmutableHashSet<string> requestedPromptValues = ParseRequestedPromptValues(requestedPrompt);

        //OIDC Core §3.1.2.1: login/consent/select_account each carry a MUST-return-an-error
        //obligation when the requested interaction cannot be confirmed. The library has no UI of
        //its own (it returns a response for the host to send), so it can only proceed past that
        //obligation when a wired seam vouches for the interaction. With no seam wired at all, an
        //explicit interactive prompt fails closed on its own OIDC Core §3.1.2.6 error — silently
        //treating an anonymous "no decision" as permission would let the requested interaction be
        //skipped entirely.
        bool isSeamWired = oauth.EvaluateAuthorizationRequestAsync is not null
            && context.ClientRegistration is not null;
        bool requiresInteractionVouch =
            requestedPromptValues.Contains(WellKnownPromptValues.Login)
            || requestedPromptValues.Contains(WellKnownPromptValues.Consent)
            || requestedPromptValues.Contains(WellKnownPromptValues.SelectAccount);

        if(requiresInteractionVouch && !isSeamWired)
        {
            AuthorizationDenialReason unvouchedReason = requestedPromptValues switch
            {
                var values when values.Contains(WellKnownPromptValues.Login) => AuthorizationDenialReason.LoginRequired,
                var values when values.Contains(WellKnownPromptValues.Consent) => AuthorizationDenialReason.ConsentRequired,
                _ => AuthorizationDenialReason.AccountSelectionRequired
            };

            return (requestedScope, await BuildAuthorizeErrorResponseAsync(
                server,
                context,
                redirectUri,
                MapDenialReasonToError(unvouchedReason),
                DefaultDenialDescription(unvouchedReason),
                requestState,
                responseMode,
                clientId,
                cancellationToken).ConfigureAwait(false));
        }

        if(oauth.EvaluateAuthorizationRequestAsync is { } evaluateRequest
            && context.ClientRegistration is { } registration)
        {
            //RFC 9396 §2: the same request's authorization_details, parsed once through the
            //wired seam so the decision seam observes the typed list beside the verbatim string.
            //A value that failed to parse never reaches this point — it is refused at request
            //receipt (ValidateAuthorizationDetailsShapeAsync), before a flow state carrying it
            //to this authorize step is ever saved.
            IReadOnlyList<AuthorizationDetail>? requestedAuthorizationDetailObjects = null;
            if(requestedAuthorizationDetails is not null
                && oauth.ParseAuthorizationDetailsAsync is { } parseAuthorizationDetails)
            {
                requestedAuthorizationDetailObjects = await parseAuthorizationDetails(
                    requestedAuthorizationDetails, context, cancellationToken).ConfigureAwait(false);
            }

            AuthorizationRequestDecision decision = await evaluateRequest(
                new AuthorizationRequestEvaluation
                {
                    RequestedAcrValues = requestedAcrValues,
                    RequestedMaxAge = requestedMaxAge,
                    RequestedScope = requestedScope,
                    RequestedAuthorizationDetails = requestedAuthorizationDetails,
                    RequestedAuthorizationDetailObjects = requestedAuthorizationDetailObjects,
                    //OID4VCI 1.0 §5.1.3: issuer_state is surfaced UNTRUSTED — the seam owns
                    //correlating it to the Offer; the library validates nothing about it. RFC 8707
                    //resource is surfaced as the parsed indicator list (§5.1.2).
                    RequestedIssuerState = requestedIssuerState,
                    RequestedResource = ParseResourceIndicators(requestedResource),
                    RequestedPromptValues = requestedPromptValues,
                    Subject = subjectId,
                    EstablishedAcr = context.Acr,
                    EstablishedAuthTime = context.AuthTime,
                    //draft-ietf-oauth-client-id-metadata-document-02 §8.5 (CIMD-051/052/053) display
                    //seam: the hostname is populated for any URL-shaped client_id regardless of
                    //whether its document was fetched; the document-derived fields are populated
                    //exactly when the materialized registration overlaid at least one of them.
                    ClientIdHost = ResolveClientIdHost(registration.ClientId),
                    HasFetchedClientMetadata = HasDocumentDerivedMetadata(registration),
                    ClientName = registration.ClientName,
                    ClientUri = registration.ClientUri,
                    LogoUri = registration.LogoUri
                },
                registration, context, cancellationToken).ConfigureAwait(false);

            if(!decision.IsPermitted)
            {
                return (requestedScope, await BuildAuthorizeErrorResponseAsync(
                    server,
                    context,
                    redirectUri,
                    MapDenialReasonToError(decision.DenialReason),
                    decision.DenialDescription ?? DefaultDenialDescription(decision.DenialReason),
                    requestState,
                    responseMode,
                    clientId,
                    cancellationToken).ConfigureAwait(false));
            }

            if(decision.GrantedScope is { } grantedScope)
            {
                (bool isValid, string canonicalScope) = EvaluateGrantedScope(grantedScope, requestedScope);
                if(!isValid)
                {
                    //RFC 6749 §3.3: the seam may only narrow the requested scope, never widen
                    //it, and never to nothing. An empty grant or a granted value outside the
                    //request is a defect in the application's own decision, not a client-facing
                    //condition — refused with server_error (RFC 6749 §4.1.2.1) rather than
                    //issued as a silent widening or an empty grant.
                    _ = System.Diagnostics.Activity.Current?.AddEvent(
                        new System.Diagnostics.ActivityEvent(OAuthEventNames.SeamGrantedScopeExceedsRequest));

                    return (requestedScope, await BuildAuthorizeErrorResponseAsync(
                        server,
                        context,
                        redirectUri,
                        OAuthErrors.ServerError,
                        "The authorization decision seam granted a scope outside the requested scope.",
                        requestState,
                        responseMode,
                        clientId,
                        cancellationToken).ConfigureAwait(false));
                }

                return (canonicalScope, null);
            }
        }

        return (requestedScope, null);
    }


    /// <summary>
    /// Validates that <paramref name="grantedScope"/> — the value an
    /// <see cref="AuthorizationRequestDecision.Permit(string?)"/> narrowed the request to — is a
    /// non-empty subset of <paramref name="requestedScope"/>'s space-delimited tokens per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.3">RFC 6749 §3.3</see>: "The
    /// authorization server MAY fully or partially ignore the scope requested by the client." An
    /// empty or whitespace <paramref name="grantedScope"/> is invalid — an application that wants
    /// to grant nothing denies the request with
    /// <see cref="AuthorizationDenialReason.InvalidScope"/> instead of permitting an empty grant.
    /// A valid grant is canonicalized to the requested tokens' own order, deduplicated, so the
    /// redeemed token response's <c>scope</c> never reflects a seam-supplied ordering.
    /// </summary>
    private static (bool IsValid, string CanonicalScope) EvaluateGrantedScope(
        string grantedScope, string requestedScope)
    {
        string[] grantedTokens = grantedScope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        string[] requestedTokens = requestedScope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        HashSet<string> requestedSet = new(requestedTokens, StringComparer.Ordinal);
        HashSet<string> grantedSet = new(grantedTokens, StringComparer.Ordinal);

        bool isValid = grantedTokens.Length > 0 && Array.TrueForAll(grantedTokens, requestedSet.Contains);
        if(!isValid)
        {
            return (false, string.Empty);
        }

        StringBuilder canonicalScope = new();
        HashSet<string> emitted = new(StringComparer.Ordinal);
        foreach(string token in requestedTokens)
        {
            if(grantedSet.Contains(token) && emitted.Add(token))
            {
                if(canonicalScope.Length > 0)
                {
                    _ = canonicalScope.Append(' ');
                }

                _ = canonicalScope.Append(token);
            }
        }

        return (true, canonicalScope.ToString());
    }


    /// <summary>
    /// Returns the host component of <paramref name="clientId"/> when it parses as an absolute
    /// <c>https</c> URI — draft-ietf-oauth-client-id-metadata-document-02 §8.5's hostname-display
    /// SHOULD applies to any URL-shaped <c>client_id</c>, whether or not it carries a Client ID
    /// Metadata Document (a vanity <c>https://</c> client_id per §7.1 still has a hostname worth
    /// showing). Returns <see langword="null"/> for an opaque (non-URL) client_id.
    /// </summary>
    private static string? ResolveClientIdHost(string clientId) =>
        Uri.TryCreate(clientId, UriKind.Absolute, out Uri? clientIdUri)
            && clientIdUri.Scheme == Uri.UriSchemeHttps
                ? clientIdUri.Host
                : null;


    /// <summary>
    /// Returns whether <paramref name="registration"/> carries at least one client-display field a
    /// Client ID Metadata Document overlays — draft-ietf-oauth-client-id-metadata-document-02 §5
    /// materialization sets <see cref="ClientRecord.IsClientMetadataMaterialized"/> when it overlays a
    /// successfully fetched document — true even for a minimal public-client document that declares only
    /// <c>client_id</c> and <c>redirect_uris</c>. A CIMD-shaped registration whose overlay never ran
    /// (fetch failure, policy denial, a pre-registered client whose document is not fetched at request
    /// time, or a request that never triggered materialization) leaves the flag false — exactly the
    /// §8.5 ¶2 "did not fetch" case.
    /// </summary>
    private static bool HasDocumentDerivedMetadata(ClientRecord registration) =>
        registration.IsClientMetadataMaterialized;


    /// <summary>
    /// RFC 6749 §4.1.2.1 wire error value returned when a request's
    /// <c>response_type</c> requests a grant this authorization server does not
    /// implement. This server issues <see cref="WellKnownResponseTypes.Code"/>
    /// only — the OIDC Core 1.0 §3 implicit (<c>id_token</c>, <c>token</c>,
    /// <c>id_token token</c>) and hybrid (<c>code id_token</c>, <c>code token</c>,
    /// <c>code id_token token</c>) response types are all unsupported.
    /// </summary>
    private const string UnsupportedResponseTypeError = "unsupported_response_type";


    /// <summary>
    /// Returns whether <paramref name="responseType"/> names an OAuth 2.0
    /// <c>response_type</c> other than <see cref="WellKnownResponseTypes.Code"/>.
    /// <see langword="false"/> for <see langword="null"/>: an absent
    /// <c>response_type</c> is a missing required parameter per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1">RFC 6749 §4.1.1</see>,
    /// distinct from a present but unsupported value, and every caller refuses it before
    /// this method runs.
    /// </summary>
    private static bool IsUnsupportedResponseType(string? responseType) =>
        responseType is not null && !WellKnownResponseTypes.IsCode(responseType);


    /// <summary>
    /// Whether the wire method is S256, the sole accepted transformation under
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-7.5.2">OAuth 2.1 §7.5.2</see>:
    /// "The plain code challenge method, defined in [RFC7636], is explicitly forbidden in OAuth 2.1."
    /// An absent method requests plain per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.3">RFC 7636 §4.3</see>:
    /// "OPTIONAL, defaults to "plain" if not present in the request".
    /// An absent method requests plain per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.3">RFC 7636 §4.3</see>:
    /// "OPTIONAL, defaults to "plain" if not present in the request".
    /// Callers return <c>invalid_request</c> for unsupported transformations per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.4.1">RFC 7636 §4.4.1</see>.
    /// </summary>
    private static bool IsAcceptedPkceMethod(string? method) =>
        WellKnownCodeChallengeMethods.IsS256(method ?? string.Empty);


    /// <summary>
    /// Returns whether <paramref name="requested"/> is an acceptable <c>redirect_uri</c> for a
    /// registration whose registered set is <paramref name="registeredRedirectUris"/>: an ordinal
    /// exact match per <see cref="RedirectUriMatching.IsRegisteredExact"/>, or — only for a public
    /// client presenting PKCE <c>S256</c> — a loopback-interface match per
    /// <see cref="RedirectUriMatching.IsRegisteredLoopback"/>.
    /// </summary>
    /// <param name="registeredRedirectUris">The registration's registered redirect URIs.</param>
    /// <param name="requested">The redirect URI presented on the request.</param>
    /// <param name="tokenEndpointAuthMethod">
    /// The registration's declared <see cref="Client.ClientAuthenticationMethod"/>
    /// (<see cref="ClientRecord.TokenEndpointAuthMethod"/>). <see langword="null"/> or
    /// <see cref="ClientAuthenticationMethod.None"/> is the public-client shape the loopback
    /// fallback requires; any other value is a confidential client and the fallback never runs.
    /// </param>
    /// <param name="codeChallengeMethod">
    /// The request's <c>code_challenge_method</c> wire value. The library requires
    /// <see cref="WellKnownCodeChallengeMethods.S256"/> independently for this fallback.
    /// PAR and JAR method gates refuse non-S256 before redirect matching; direct authorization
    /// validates the destination first so its error redirect is safe. This condition holds independently
    /// of those method gates, consistent with
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1">RFC 9700 §2.1.1</see>:
    /// "When using PKCE, clients SHOULD use PKCE code challenge methods that do not expose
    /// the PKCE verifier in the authorization request."
    /// </param>
    /// <param name="context">
    /// The resolved per-request policy bag, read only for
    /// <c>PolicyExchangeContextExtensions.IsLocalhostNameAcceptedForLoopbackRedirects</c> —
    /// see that property's remarks for the RFC 8252 §8.3 / MCP authorization specification citations
    /// behind the default-off <c>localhost</c> allowance.
    /// </param>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8252#section-8.4">RFC 8252 §8.4</see> scopes the
    /// loopback exception to the native-app public-client shape: "native apps are classified as
    /// public clients ... they MUST be registered with the authorization server as such," and
    /// "Authorization servers MUST require clients to register their complete redirect URI
    /// (including the path component) and reject authorization requests that specify a redirect URI
    /// that doesn't exactly match the one that was registered; the exception is loopback redirects,
    /// where an exact match is required except for the port URI component." Widening the exception
    /// to a confidential client or a non-PKCE request would let a party that already holds a client
    /// secret (or presents no proof-of-possession at all) claim the same latitude, so both gates are
    /// required together and neither is optional.
    /// </remarks>
    internal static bool IsAcceptableRedirectUri(
        IReadOnlyCollection<Uri> registeredRedirectUris,
        Uri requested,
        ClientAuthenticationMethod? tokenEndpointAuthMethod,
        string? codeChallengeMethod,
        ExchangeContext context)
    {
        if(RedirectUriMatching.IsRegisteredExact(registeredRedirectUris, requested))
        {
            return true;
        }

        bool isPublicClient = tokenEndpointAuthMethod is null
            || tokenEndpointAuthMethod.Value == ClientAuthenticationMethod.None;
        bool isPkceS256 = WellKnownCodeChallengeMethods.IsS256(codeChallengeMethod ?? string.Empty);

        return isPublicClient
            && isPkceS256
            && RedirectUriMatching.IsRegisteredLoopback(
                registeredRedirectUris, requested, context.IsLocalhostNameAcceptedForLoopbackRedirects);
    }


    /// <summary>
    /// A correlation-key sentinel returned by <see cref="BuildToken"/>'s <c>ExtractCorrelationKey</c>
    /// for a <c>code</c> that fails <see cref="IsValidAuthorizationCodeGrammar"/>. Every genuine
    /// authorization-code correlation key is a SHA-256 digest, base64url-encoded to exactly 43
    /// characters (<see cref="WellKnownHashAlgorithms.Sha256SizeBytes"/> is 32 bytes); this value's
    /// length guarantees it can never equal one, so <c>ResolveCorrelationKeyAsync</c> always reports
    /// it not found and the request fails the SAME invalid_grant handle-miss an unknown code does.
    /// </summary>
    private const string NonExistentAuthorizationCodeCorrelationKey = "not-a-sha256-base64url-digest";


    /// <summary>
    /// Returns whether <paramref name="candidate"/> matches
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A.11">RFC 6749 Appendix A.11</see>'s
    /// <c>code</c> grammar: <c>code = 1*VSCHAR</c>, where <c>VSCHAR = %x20-7E</c>.
    /// </summary>
    /// <remarks>
    /// Checked before <see cref="ComputeDigestBase64Url"/> ever hashes the value: that helper
    /// encodes through <see cref="System.Text.Encoding.ASCII"/>, which folds any byte outside
    /// plain ASCII rather than rejecting it, so a value this grammar rejects must never reach it.
    /// </remarks>
    private static bool IsValidAuthorizationCodeGrammar(string candidate)
    {
        foreach(char c in candidate)
        {
            if(c is < (char)0x20 or > (char)0x7E)
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>
    /// Returns whether <paramref name="candidate"/> matches
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.1">RFC 7636 §4.1</see>'s
    /// <c>code_verifier</c> grammar: <c>code-verifier = 43*128unreserved</c>, where
    /// <c>unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"</c>.
    /// </summary>
    /// <remarks>
    /// Checked in <see cref="BeforeCodeRedemptionCorrelationAsync"/>, before any stored code
    /// state is loaded, so a grammatically malformed verifier fails PKCE verification without
    /// ever being hashed or compared against a stored challenge — the distinction this method
    /// enforces is the request's own grammar, never the stored challenge comparison
    /// <see cref="VerifyCodeGrantPresentation"/> performs once the code state is loaded.
    /// </remarks>
    private static bool IsValidCodeVerifierGrammar(string candidate)
    {
        if(candidate.Length is < 43 or > 128)
        {
            return false;
        }

        foreach(char c in candidate)
        {
            bool isUnreserved = c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9')
                or '-' or '.' or '_' or '~';

            if(!isUnreserved)
            {
                return false;
            }
        }

        return true;
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
        BaseMemoryPool pool)
    {
        //PKCE S256 verification here is a SHA-256 of the presented code verifier — sync by nature, no
        //hardware-async backend — so it hashes through the registered synchronous HashFunctionDelegate seam. The
        //computeDigest parameter is retained for API stability; the registered sync hash is used directly.
        _ = computeDigest;

        int inputByteCount = System.Text.Encoding.ASCII.GetByteCount(input);
        using IMemoryOwner<byte> inputOwner = pool.Rent(inputByteCount);
        Span<byte> inputBytes = inputOwner.Memory.Span[..inputByteCount];
        _ = System.Text.Encoding.ASCII.GetBytes(input, inputBytes);

        using DigestValue digest = CryptographicKeyEvents.ComputeDigest(
            inputBytes, digestByteLength, algorithmTag, pool);

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


/// <summary>
/// The per-request carry for a step endpoint's <c>authorization_details</c> decision: the parsed,
/// shape-validated request-only detail list, decided ONCE by <see cref="AuthCodeEndpoints"/>'s
/// pre-correlation step against the issuer that same step already resolved and carried, and read
/// by <see cref="AuthCodeEndpoints.ResolveGrantedAuthorizationDetailsAsync"/> instead of
/// re-parsing the request for the same request. The OID4VCI 1.0 §5.1.1/§6.1.1 <c>locations</c>
/// requirement is decided ONCE in the step, for the step's own shape refusal, and is not re-made
/// for a carried outcome — it is not itself part of the carry, since nothing downstream of the
/// step re-checks it.
/// </summary>
/// <param name="Details">The parsed, shape-validated <c>authorization_details</c> entries from the token request.</param>
internal sealed record AuthorizationDetailsStepOutcome(
    IReadOnlyList<AuthorizationDetail> Details);


/// <summary>
/// A typed accessor block over <see cref="ExchangeContext"/> fronting one per-request carry: the
/// <see cref="AuthorizationDetailsStepOutcome"/> a pre-correlation step's request-only validation
/// records (<see cref="AuthorizationDetailsStepOutcome"/> property/<see cref="SetAuthorizationDetailsStepOutcome"/>,
/// under <see cref="AuthorizationServerHandlers.AuthorizationDetailsStepOutcomeKey"/>) for a
/// handler's later <see cref="AuthCodeEndpoints.ResolveGrantedAuthorizationDetailsAsync"/> call to
/// read within the same request.
/// </summary>
/// <remarks>
/// Internal — the outcome type it carries (<see cref="AuthorizationDetailsStepOutcome"/>) is
/// itself internal, so nothing here is reachable outside <see cref="Verifiable.OAuth"/>.
/// </remarks>
internal static class ExchangeContextAuthorizationDetailsExtensions
{
    extension(ExchangeContext context)
    {
        /// <summary>
        /// Gets the <see cref="AuthorizationDetailsStepOutcome"/> a pre-correlation step recorded
        /// for this request, or <see langword="null"/> when no step ran, the request carried no
        /// <c>authorization_details</c>, or none has been stored yet.
        /// </summary>
        internal AuthorizationDetailsStepOutcome? AuthorizationDetailsStepOutcome =>
            context.TryGetValue(AuthorizationServerHandlers.AuthorizationDetailsStepOutcomeKey, out object? v)
                && v is AuthorizationDetailsStepOutcome outcome ? outcome : null;

        /// <summary>Sets the <see cref="AuthorizationDetailsStepOutcome"/> a pre-correlation step recorded for this request.</summary>
        /// <param name="outcome">The step's outcome.</param>
        internal void SetAuthorizationDetailsStepOutcome(AuthorizationDetailsStepOutcome outcome)
        {
            ArgumentNullException.ThrowIfNull(outcome);
            context[AuthorizationServerHandlers.AuthorizationDetailsStepOutcomeKey] = outcome;
        }
    }
}


/// <summary>
/// A typed accessor block over <see cref="ExchangeContext"/> fronting one per-request carry: the
/// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-6">RFC 6749 §6</see> effective scope
/// <see cref="AuthCodeEndpoints.BuildRefreshToken"/>'s <c>BuildInputAsync</c> step resolves via
/// <see cref="AuthCodeEndpoints.ResolveEffectiveScope"/>, for that same endpoint's <c>BuildResponse</c>
/// step to echo on the response's <c>scope</c> member — the same narrowed value the access token,
/// and every scope-gated token producer, were issued against, rather than the full scope carried on
/// the presented <see cref="ServerRefreshTokenIssuedState"/>.
/// </summary>
/// <remarks>
/// Internal — this carry moves a value computed in one delegate of the refresh endpoint to another
/// delegate of the SAME endpoint within one request; nothing outside <see cref="Verifiable.OAuth"/>
/// needs it.
/// </remarks>
internal static class ExchangeContextRefreshScopeExtensions
{
    private const string EffectiveRefreshScopeKey = "server.effectiveRefreshScope";

    extension(ExchangeContext context)
    {
        /// <summary>
        /// Gets the effective scope <see cref="AuthCodeEndpoints.BuildRefreshToken"/>'s
        /// <c>BuildInputAsync</c> step resolved for this refresh response, or <see langword="null"/>
        /// when no such step has run yet for this request.
        /// </summary>
        internal string? EffectiveRefreshScope =>
            context.TryGetValue(EffectiveRefreshScopeKey, out object? v) && v is string scope ? scope : null;

        /// <summary>Sets the effective scope resolved for this refresh response.</summary>
        /// <param name="scope">
        /// The <see href="https://www.rfc-editor.org/rfc/rfc6749#section-6">RFC 6749 §6</see>
        /// effective scope this refresh response was issued against.
        /// </param>
        internal void SetEffectiveRefreshScope(string scope)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(scope);
            context[EffectiveRefreshScopeKey] = scope;
        }
    }
}
