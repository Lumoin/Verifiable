using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Siop.Server.States;
using Verifiable.Server;

using static Verifiable.Server.EndpointInput;

namespace Verifiable.OAuth.Siop.Server;

/// <summary>
/// Endpoint builder module for the SIOPv2 Relying-Party (verifier) flow.
/// </summary>
/// <remarks>
/// <para>
/// Produces the request-preparation endpoint (flow creation) and the Self-Issued ID Token response
/// endpoint per
/// <see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html">SIOPv2</see>.
/// The structural mirror of the OID4VP verifier flow: the preparation endpoint is the
/// PAR-equivalent (<see cref="Verifiable.OAuth.Oid4Vp.Oid4VpEndpoints"/>'s <c>BuildOid4VpPar</c>)
/// that starts the flow from context inputs, and the response endpoint is the unencrypted
/// <c>direct_post</c>-equivalent that loads the prior state, emits a pure input, and reads the
/// terminal state in its <see cref="ServerEndpoint.BuildResponse"/>.
/// </para>
/// <para>
/// The §11.1 Self-Issued ID Token validation is NOT performed in the response endpoint's
/// <see cref="ServerEndpoint.BuildInputAsync"/>; it is deferred to the
/// <see cref="ValidateSelfIssuedIdToken"/> action the resulting
/// <see cref="SiopResponseReceivedState"/> declares, which the
/// <see cref="OAuthActionExecutor"/> runs — keeping the automaton pure and deterministic, the same
/// effect-channeling the OID4VP verifier flow uses.
/// </para>
/// <para>
/// Register at startup via <see cref="Verifiable.Server.ServerConfiguration.EndpointBuilders"/>:
/// </para>
/// <code>
/// server.EndpointBuilders.AddRange([
///     SiopVerifierEndpoints.Builder
/// ]);
/// </code>
/// </remarks>
[DebuggerDisplay("SiopVerifierEndpoints")]
public static class SiopVerifierEndpoints
{
    /// <summary>
    /// The endpoint builder delegate. Pass this to
    /// <see cref="Verifiable.Server.ServerConfiguration.EndpointBuilders"/>.
    /// </summary>
    public static readonly EndpointBuilderDelegate Builder = static (registration, context, ct) =>
    {
        if(!((ClientRecord)registration).IsCapabilityAllowed(WellKnownCapabilityIdentifiers.SiopSelfIssuedOp))
        {
            return ValueTask.FromResult<IReadOnlyList<EndpointCandidate>>([]);
        }

        return ValueTask.FromResult<IReadOnlyList<EndpointCandidate>>(
        [
            BuildSiopRequestPreparation(),
            BuildSiopRequestObject(),
            BuildSiopResponse()
        ]);
    };


    /// <summary>
    /// Builds the SIOPv2 request-preparation endpoint — the Relying-Party-internal,
    /// PAR-equivalent trigger that starts the flow. It reads the transaction inputs (nonce,
    /// client_id, accepted algorithms, optional id_token_type) off the
    /// <see cref="ExchangeContext"/>, mints a per-flow request handle, and produces the
    /// <see cref="SiopRequestPrepared"/> input.
    /// </summary>
    /// <remarks>
    /// Like the OID4VP PAR endpoint, this is invoked internally by the RP application rather than
    /// from a wallet HTTP request, so its matcher is context-driven (the <c>siop.nonce</c> slot is
    /// present) and does not path-match. Disjointness against the wire-driven response endpoint is
    /// enforced by inverse signals: the response endpoint requires the <c>id_token</c> form field,
    /// which the preparation trigger never carries.
    /// </remarks>
    private static EndpointCandidate BuildSiopRequestPreparation() =>
        new()
        {
            Name = WellKnownEndpointNames.SiopRequestObject,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownCapabilityIdentifiers.SiopSelfIssuedOp,
            StartsNewFlow = true,
            Kind = FlowKind.SiopVerifierServer,

            //Context-state driven: the RP sets the transaction nonce on context before dispatch.
            //This crossing is RP-internal, not a wallet HTTP request, so it does not path-match.
            //Disjointness vs the wire-driven response endpoint holds because that one requires the
            //id_token form field, which this trigger never carries.
            MatchesRequest = static (fields, context, endpoint, ct) =>
            {
                if(context.SiopNonce is null)
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
            },

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.Server!;
                var oauth = server.OAuth();

                ClientRecord? registration = context.ClientRegistration;
                if(registration is null)
                {
                    return Respond(ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "Client registration not found in context."));
                }

                string? nonce = context.SiopNonce;
                if(nonce is null)
                {
                    return Respond(ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "Missing SIOP transaction nonce in context."));
                }

                IReadOnlyList<string>? allowedAlgorithms = context.SiopAllowedAlgorithms;
                if(allowedAlgorithms is null || allowedAlgorithms.Count == 0)
                {
                    return Respond(ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        "Missing accepted ID Token signing algorithms in context."));
                }

                //An explicit client_id wins; otherwise the resolved registration's client id is
                //the RP audience. Either way the Self-Issued ID Token's aud must equal this value.
                string clientId = context.SiopClientId ?? registration.ClientId;

                //The dispatcher placed flowId on context for new flows. Read it; do not generate it.
                string flowId = context.FlowId
                    ?? throw new InvalidOperationException(
                        "FlowId not on context. The dispatcher must place it before " +
                        "invoking BuildInputAsync on a StartsNewFlow endpoint.");

                //Generate the external opaque request handle. A distinct random value from flowId
                //per the architecture rule "flowId never leaves the server process." The handle is
                //carried in the request_uri and echoed by the Wallet as the state on its response.
                string requestHandle = await oauth.GenerateIdentifierAsync!(
                    WellKnownIdentifierPurposes.SiopRequestHandle, context, ct)
                    .ConfigureAwait(false);

                //Place the handle on context so the application can read it after dispatch to echo
                //as the state the Wallet returns on the response POST, and so ResolveEndpointUriAsync
                //can read it when composing the by-reference request_uri.
                context.SetSiopRequestHandle(requestHandle);

                //The signing key for the §9 Request Object. Resolve the JarSigning key when the
                //deployment configured a signing-key resolver; this enables the by-reference
                //(request_uri) flow. Absent a resolver the flow still works same-device (by-value)
                //and the handle alone is returned.
                KeyId? signingKeyId = null;
                if(oauth.Cryptography.SigningKeyResolver is not null)
                {
                    signingKeyId = await SigningKeySelection.ResolveSigningKeyIdAsync(
                        server,
                        registration,
                        KeyUsageContext.JarSigning,
                        context,
                        ct).ConfigureAwait(false);
                }

                //Ask the application to compose the absolute request_uri for the by-reference flow.
                //The library does not compose URLs. Best-effort: when ResolveEndpointUriAsync is not
                //configured (or returns null) the same-device by-value path is still available.
                if(oauth.ResolveEndpointUriAsync is not null)
                {
                    Uri? requestUri = await oauth.ResolveEndpointUriAsync(
                        SiopVerifierEndpointKeys.RequestUri,
                        registration,
                        context,
                        ct).ConfigureAwait(false);

                    if(requestUri is not null)
                    {
                        context.SetSiopGeneratedRequestUri(requestUri);
                    }
                }

                DateTimeOffset now = server.TimeProvider.GetUtcNow();
                DateTimeOffset expiresAt = now + oauth.Timings.Oid4VpRequestUriLifetime;

                //When the RP advertises an encryption key (and its accepted enc set), the Wallet MAY
                //return the Self-Issued ID Token as a compact JWE encrypted to that key's public half.
                //Both are threaded forward so the response endpoint can drive the decrypt action; an
                //RP that advertises neither only accepts the bare-JWS id_token. PURE: these are read
                //off context exactly like the other transaction inputs above.
                string? encryptionKeyId = context.SiopEncryptionKeyId;
                IReadOnlyList<string>? allowedEncAlgorithms = context.SiopAllowedEncAlgorithms;

                //The §9 Request Object and the OID4VP JAR are the same RFC 9101 oauth-authz-req+jwt
                //artifact, so the same client-id trust material the wallet resolves the RP key from
                //(x5c, trust_chain, verifier_attestation jwt, kid) is carried onto the prepared state
                //and merged into the signed header at sign time — PURE: read off context exactly like
                //the other transaction inputs above, the mirror of OID4VP threading
                //JarAdditionalHeaderClaims. Null on the bespoke direct-key path.
                JCose.JwtHeader? requestObjectAdditionalHeaderClaims =
                    context.SiopRequestObjectAdditionalHeaderClaims;

                return Advance(new SiopRequestPrepared
                {
                    FlowId = flowId,
                    ClientId = clientId,
                    Nonce = nonce,
                    IdTokenType = context.SiopIdTokenType,
                    AllowedAlgorithms = allowedAlgorithms,
                    RequestHandle = requestHandle,
                    SigningKeyId = signingKeyId,
                    DecryptionKeyId = encryptionKeyId,
                    AllowedEncAlgorithms = allowedEncAlgorithms,
                    UseStaticDiscoveryAudience = context.SiopUseStaticDiscoveryAudience,
                    RequestObjectAdditionalHeaderClaims = requestObjectAdditionalHeaderClaims,
                    PreparedAt = now,
                    ExpiresAt = expiresAt
                });
            },

            BuildResponse = static (state, _, context) =>
            {
                if(state is not SiopRequestPreparedState prepared)
                {
                    return ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        $"Unexpected state after SIOP request preparation: {state.GetType().Name}.");
                }

                //The caller learns the handle to echo as state, plus the by-reference request_uri
                //when the deployment composed one. Both are stable well-known fields carrying
                //primitive string values — hand-built per the serialization firewall, the same
                //convention the OID4VP PAR response uses.
                string body = context.SiopGeneratedRequestUri is { } requestUri
                    ? $"{{\"{OAuthRequestParameterNames.State}\":\"{prepared.RequestHandle}\"," +
                      $"\"{OAuthRequestParameterNames.RequestUri}\":\"{requestUri}\"}}"
                    : $"{{\"{OAuthRequestParameterNames.State}\":\"{prepared.RequestHandle}\"}}";

                //RFC 9126 §2.2 shape: a successful preparation response uses HTTP 201 Created.
                return ServerHttpResponse.Created(body, WellKnownMediaTypes.Application.Json);
            }
        };


    /// <summary>
    /// Builds the SIOPv2 §9 Request Object endpoint served at the per-flow <c>request_uri</c>. The
    /// Wallet dereferences the URL with HTTP GET; the endpoint loads the prior
    /// <see cref="SiopRequestPreparedState"/>, decides the §9.1 <c>aud</c>, and drives the
    /// <see cref="SignSiopRequestObject"/> action — signing is an EFFECT run by the
    /// <see cref="OAuthActionExecutor"/>, so the endpoint's <see cref="ServerEndpoint.BuildInputAsync"/>
    /// stays pure (it only invokes the executor and forwards the emitted input). The structural
    /// mirror of the OID4VP JAR-fetch endpoint
    /// (<see cref="Verifiable.OAuth.Oid4Vp.Oid4VpEndpoints"/>'s <c>BuildOid4VpJarRequest</c>).
    /// </summary>
    /// <remarks>
    /// The §9.1 <c>aud</c> is decided here from
    /// <see cref="SiopRequestPreparedState.UseStaticDiscoveryAudience"/>: the static-discovery value
    /// <see cref="SiopAuthorizationRequestParameterValues.StaticDiscoveryRequestObjectAudience"/>
    /// (<c>https://self-issued.me/v2</c>) when static discovery is in effect, else the dynamically
    /// discovered issuer — the RP deployment's own issuer in this server-side flow. The signed
    /// compact JWS rides the <see cref="ExchangeContext"/> (set by the action handler via
    /// <see cref="SiopVerifierExchangeContextExtensions.SetSiopRequestObject"/>); the
    /// <see cref="ServerEndpoint.BuildResponse"/> reads it and serves it with media type
    /// <see cref="WellKnownMediaTypes.Application.OauthAuthzReqJwt"/>.
    /// </remarks>
    private static EndpointCandidate BuildSiopRequestObject() =>
        new()
        {
            Name = WellKnownEndpointNames.SiopRequestObjectByReference,
            HttpMethod = WellKnownHttpMethods.Get,
            Capability = WellKnownCapabilityIdentifiers.SiopSelfIssuedOp,
            StartsNewFlow = false,
            Kind = FlowKind.SiopVerifierServer,

            //GET to the per-flow request_uri with the application's CorrelationKey populated on
            //context. The skin extracts the {handle} path segment into CorrelationKey before dispatch
            //since the request_uri mount point is not fixed across deployments. Mirrors the OID4VP
            //JAR-fetch matcher.
            MatchesRequest = static (fields, context, endpoint, ct) =>
            {
                IncomingRequest? req = context.IncomingRequest;
                if(req is null)
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                if(!WellKnownHttpMethods.IsGet(req.Method))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                if(string.IsNullOrWhiteSpace(context.CorrelationKey))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
            },

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.Server!;
                var oauth = server.OAuth();

                if(currentState is not SiopRequestPreparedState prepared)
                {
                    return Respond(ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        "Flow not in expected state for SIOP §9 Request Object request."));
                }

                if(oauth.ActionExecutor is null)
                {
                    return Respond(ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, "Action executor not configured."));
                }

                if(prepared.SigningKeyId is not { } signingKeyId)
                {
                    return Respond(ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "The SIOP flow was prepared without a §9 Request Object signing key; the "
                        + "by-reference request_uri path requires a configured SigningKeyResolver."));
                }

                ClientRecord? registration = context.ClientRegistration;
                if(registration is null)
                {
                    return Respond(ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, "Client registration not found in context."));
                }

                Uri? redirectUri = registration.ResponseUri ?? registration.IssuerUri;
                if(redirectUri is null)
                {
                    return Respond(ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "The Relying Party registration carries neither a ResponseUri nor an "
                        + "IssuerUri to use as the §9 Request Object redirect_uri."));
                }

                //SIOPv2 §9.1: aud is the static-discovery value https://self-issued.me/v2 under
                //Static Self-Issued OP Discovery, else the dynamically discovered issuer — the RP
                //deployment's own issuer in this server-side flow.
                string audience = prepared.UseStaticDiscoveryAudience
                    ? SiopAuthorizationRequestParameterValues.StaticDiscoveryRequestObjectAudience
                    : registration.IssuerUri?.OriginalString ?? prepared.ClientId;

                //Signing is an EFFECT. Invoke it through the executor inline (the no-wallet-nonce
                //GET path mirrors how the OID4VP JAR-fetch endpoint runs SignJarAction inline); the
                //handler signs, parks the compact JWS on the context, and emits the served input
                //that steps the PDA into SiopRequestObjectServedState.
                FlowInput signed = await oauth.ActionExecutor.ExecuteAsync(
                    new SignSiopRequestObject(
                        RequestHandle: prepared.RequestHandle,
                        ClientId: prepared.ClientId,
                        Nonce: prepared.Nonce,
                        RedirectUri: redirectUri,
                        Audience: audience,
                        SigningKeyId: signingKeyId,
                        IdTokenType: prepared.IdTokenType,
                        AllowedAlgorithms: prepared.AllowedAlgorithms,
                        AdditionalHeaderClaims: prepared.RequestObjectAdditionalHeaderClaims),
                    context,
                    ct).ConfigureAwait(false);

                return Advance(signed);
            },

            BuildResponse = static (state, _, context) =>
            {
                if(state is not SiopRequestObjectServedState)
                {
                    return ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        $"Unexpected state after SIOP §9 Request Object request: {state.GetType().Name}.");
                }

                //The signed compact JWS was parked on the context by the SignSiopRequestObject
                //handler. Serve it with the RFC 9101 §5 media type, the same the OID4VP JAR endpoint
                //uses for its served Request Object.
                string requestObject = context.SiopRequestObject
                    ?? throw new InvalidOperationException(
                        "The signed §9 Request Object was not set on the context after the signing action.");

                return ServerHttpResponse.Ok(
                    requestObject, WellKnownMediaTypes.Application.OauthAuthzReqJwt);
            }
        };


    /// <summary>
    /// Builds the SIOPv2 Self-Issued ID Token response endpoint per
    /// <see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html">SIOPv2</see>.
    /// The Wallet POSTs its <c>id_token</c> together with the <c>state</c> handle the RP issued at
    /// preparation. Structurally the unencrypted OID4VP <c>direct_post</c>: load the prior state,
    /// emit a PURE input, and read the terminal state in <see cref="ServerEndpoint.BuildResponse"/>.
    /// </summary>
    /// <remarks>
    /// <see cref="ServerEndpoint.BuildInputAsync"/> performs NO cryptographic validation — it emits
    /// the pure <see cref="SiopResponsePosted"/> input, and the §11.1 validation runs in the
    /// <see cref="OAuthActionExecutor"/> via the action the resulting
    /// <see cref="SiopResponseReceivedState"/> declares.
    /// </remarks>
    private static EndpointCandidate BuildSiopResponse() =>
        new()
        {
            Name = WellKnownEndpointNames.SiopResponse,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownCapabilityIdentifiers.SiopSelfIssuedOp,
            StartsNewFlow = false,
            Kind = FlowKind.SiopVerifierServer,

            //POST to the response URL with both id_token (the Self-Issued ID Token) and state (the
            //preparation handle echo) present in the body.
            MatchesRequest = static (fields, context, endpoint, ct) =>
            {
                IncomingRequest? req = context.IncomingRequest;
                if(req is null)
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                if(!WellKnownHttpMethods.IsPost(req.Method))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                if(!PathEquals.Equals(req.Path, endpoint.ResolvedUri.AbsolutePath))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                if(!fields.ContainsKey(OAuthRequestParameterNames.IdToken))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                if(!fields.ContainsKey(OAuthRequestParameterNames.State))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
            },

            //The Wallet echoes the preparation handle as the state form field; the value equals the
            //per-flow request handle, which the application's ResolveCorrelationKeyAsync maps back
            //to the internal flow identifier.
            ExtractCorrelationKey = static (path, fields, context) =>
                fields.TryGetValue(OAuthRequestParameterNames.State, out string? state)
                    && !string.IsNullOrWhiteSpace(state) ? state : null,

            BuildInputAsync = static (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.Server!;
                var oauth = server.OAuth();

                //SiopRequestPreparedState is the same-device (by-value) path; SiopRequestObjectServedState
                //is the by-reference path where the RP served a signed §9 Request Object at request_uri.
                //Both carry the transaction values, so the response endpoint accepts the id_token POST
                //from either — the mirror of OID4VP direct_post accepting from VerifierJarServed or
                //VerifierParReceived.
                if(currentState is not SiopRequestPreparedState
                    and not SiopRequestObjectServedState)
                {
                    return ValueTask.FromResult(Respond(ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        "Flow not in expected state for SIOP response.")));
                }

                if(!fields.TryGetValue(OAuthRequestParameterNames.IdToken, out string? idToken)
                    || string.IsNullOrWhiteSpace(idToken))
                {
                    return ValueTask.FromResult(Respond(ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "Missing id_token parameter.")));
                }

                //Discriminate a compact JWE from a bare-JWS id_token by segment count, the same way
                //OID4VP tells direct_post.jwt from direct_post: a JWE is five dot-separated segments
                //(four dots), a JWS is three (two dots). When the id_token is a JWE the Wallet returned
                //an ENCRYPTED Self-Issued ID Token; emit the encrypted-response input so the executor
                //decrypts (with the enc allow-list check) before the §11.1 validation. The combined
                //§12 path and the bare-JWS path below are left exactly as they are.
                if(IsCompactJwe(idToken))
                {
                    //The encrypted response requires the RP to have advertised an encryption key and
                    //its accepted enc set at preparation; without them there is nothing to decrypt to,
                    //so fail closed rather than emit an input the transition cannot satisfy.
                    (string? decryptionKeyId, IReadOnlyList<string>? allowedEnc) = currentState switch
                    {
                        SiopRequestPreparedState prepared =>
                            (prepared.DecryptionKeyId, prepared.AllowedEncAlgorithms),
                        SiopRequestObjectServedState served =>
                            (served.DecryptionKeyId, served.AllowedEncAlgorithms),
                        _ => (null, null)
                    };

                    if(decryptionKeyId is null || allowedEnc is null || allowedEnc.Count == 0)
                    {
                        return ValueTask.FromResult(Respond(ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidRequest,
                            "The id_token is a compact JWE but the Relying Party did not advertise an "
                            + "encryption key and accepted enc algorithms for this transaction; only a "
                            + "bare-JWS id_token can be accepted.")));
                    }

                    //PURE: emit the raw compact JWE with no validation. The executor resolves the
                    //decryption key, validates the JWE enc header against the advertised set, decrypts,
                    //and runs the §11.1 validation the SiopEncryptedResponseReceivedState declares.
                    return ValueTask.FromResult(Advance(new SiopEncryptedResponsePosted
                    {
                        EncryptedIdToken = idToken,
                        ReceivedAt = server.TimeProvider.GetUtcNow()
                    }));
                }

                //SIOPv2 §12: when the Wallet answered with BOTH an id_token AND a vp_token in one
                //Authorization Response, emit the combined input so the executor validates both
                //artifacts against the same transaction (the §12 nonce / Client ID binding). The
                //id_token-only POST keeps emitting SiopResponsePosted exactly as before — the
                //by-value / by-reference id_token-only path is untouched.
                if(fields.TryGetValue(Oid4Vp.AuthorizationResponseParameters.VpToken, out string? vpToken)
                    && !string.IsNullOrWhiteSpace(vpToken))
                {
                    //PURE: emit the two raw artifacts with no validation. The executor runs the §11.1
                    //id_token validation, the vp_token presentation verification, and the §12 binding
                    //checks the SiopCombinedResponseReceivedState declares as its NextAction.
                    return ValueTask.FromResult(Advance(new SiopCombinedResponsePosted
                    {
                        IdToken = idToken,
                        VpToken = vpToken,
                        ReceivedAt = server.TimeProvider.GetUtcNow()
                    }));
                }

                //PURE: emit the received id_token with no validation. The executor runs the §11.1
                //validation the SiopResponseReceivedState declares as its NextAction.
                return ValueTask.FromResult(Advance(new SiopResponsePosted
                {
                    IdToken = idToken,
                    ReceivedAt = server.TimeProvider.GetUtcNow()
                }));
            },

            BuildResponse = static (state, _, _) =>
            {
                if(state is not SelfIssuedAuthenticationVerifiedState)
                {
                    return ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        $"Unexpected state after SIOP response: {state.GetType().Name}.");
                }

                return ServerHttpResponse.Ok("{}", WellKnownMediaTypes.Application.Json);
            }
        };


    /// <summary>
    /// Whether <paramref name="compactToken"/> is a compact JWE rather than a bare compact JWS,
    /// decided by segment count: a compact JWE has five dot-separated segments (four dots) — protected
    /// header, encrypted key, IV, ciphertext, and authentication tag — whereas a compact JWS has three
    /// (two dots). This is the SIOP parallel of how OID4VP distinguishes <c>direct_post.jwt</c> from
    /// <c>direct_post</c>; it is a structural shape check only, performed before any cryptographic
    /// operation.
    /// </summary>
    private static bool IsCompactJwe(string compactToken)
    {
        int dots = 0;
        foreach(char c in compactToken)
        {
            if(c == '.')
            {
                dots++;
            }
        }

        return dots == 4;
    }
}
