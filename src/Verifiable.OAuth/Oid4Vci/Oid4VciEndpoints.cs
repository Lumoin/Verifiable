using System.Buffers;
using System.Text;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.Server;
using static Verifiable.Server.EndpointInput;

namespace Verifiable.OAuth.Oid4Vci;

/// <summary>
/// Endpoint builder module for OpenID for Verifiable Credential Issuance
/// (<see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html">OID4VCI 1.0</see>).
/// Register at startup via <see cref="Verifiable.Server.ServerConfiguration.EndpointBuilders"/>.
/// </summary>
/// <remarks>
/// The Credential Issuer is, in OAuth terms, a resource server that MAY also be the
/// Authorization Server; its endpoints dispatch through the same capability + candidate +
/// integration-seam pipeline as the rest of the server. This module currently contributes the
/// <b>Nonce Endpoint</b> (OID4VCI 1.0 §7); the Credential, Deferred, Notification, and
/// Credential Offer endpoints land here as the issuance loop is built out.
/// </remarks>
public static class Oid4VciEndpoints
{
    /// <summary>
    /// The endpoint builder delegate. Pass this to
    /// <see cref="Verifiable.Server.ServerConfiguration.EndpointBuilders"/>.
    /// </summary>
    public static readonly EndpointBuilderDelegate Builder = static (registration, context, ct) =>
    {
        List<EndpointCandidate> candidates = [];

        //OID4VCI 1.0 §7 Nonce Endpoint materializes only when the capability is allowed AND
        //the nonce-issuance seam is wired — fail-closed: an advertised Nonce Endpoint that
        //cannot mint a c_nonce would break every key-bound Credential Request.
        EndpointServer? server = context.Server;
        if(((ClientRecord)registration).IsCapabilityAllowed(WellKnownCapabilityIdentifiers.Oid4VciNonceEndpoint)
            && server?.OAuth().IssueCredentialNonceAsync is not null)
        {
            candidates.Add(BuildNonceEndpoint());
        }

        //OID4VCI 1.0 §8 Credential Endpoint materializes only when the capability is allowed
        //AND both the request-parse seam and the issuance seam are wired — fail-closed: an
        //advertised Credential Endpoint that cannot parse the request or cannot mint would be
        //a fail-open authorization boundary that 200s without issuing.
        if(((ClientRecord)registration).IsCapabilityAllowed(WellKnownCapabilityIdentifiers.Oid4VciCredentialEndpoint)
            && server?.OAuth().ParseCredentialRequestAsync is not null
            && server?.OAuth().IssueCredentialAsync is not null)
        {
            candidates.Add(BuildCredentialEndpoint());
        }

        //OID4VCI 1.0 §9 Deferred Credential Endpoint materializes only when the capability is
        //allowed AND the resolution seam is wired — fail-closed: only the application's
        //deferred-transaction store can tell an unknown transaction_id from an issuance still
        //in flight.
        if(((ClientRecord)registration).IsCapabilityAllowed(WellKnownCapabilityIdentifiers.Oid4VciDeferredCredentialEndpoint)
            && server?.OAuth().ResolveDeferredCredentialAsync is not null)
        {
            candidates.Add(BuildDeferredCredentialEndpoint());
        }

        //OID4VCI 1.0 §11 Notification Endpoint materializes only when the capability is allowed
        //AND the processing seam is wired — fail-closed: only the application's notification_id
        //store can validate the identifier and act on the event.
        if(((ClientRecord)registration).IsCapabilityAllowed(WellKnownCapabilityIdentifiers.Oid4VciNotificationEndpoint)
            && server?.OAuth().ProcessCredentialNotificationAsync is not null)
        {
            candidates.Add(BuildNotificationEndpoint());
        }

        //OID4VCI 1.0 §12.2 Credential Issuer Metadata materializes only when the capability is
        //allowed AND the contribution seam is wired — fail-closed: the document's REQUIRED
        //credential_configurations_supported is application data the library cannot derive, so
        //an advertised metadata endpoint without it could only emit a non-conformant document.
        if(((ClientRecord)registration).IsCapabilityAllowed(WellKnownCapabilityIdentifiers.Oid4VciCredentialIssuerMetadata)
            && server?.OAuth().ContributeCredentialIssuerMetadataAsync is not null)
        {
            candidates.Add(BuildCredentialIssuerMetadata());
        }

        //OID4VCI 1.0 §4.1.3 Credential Offer Endpoint materializes only when the capability is
        //allowed AND the resolve seam is wired — fail-closed: only the application's offer store
        //can produce the offer the credential_offer_uri points at, so an advertised endpoint
        //without it could only 404 every fetch.
        if(((ClientRecord)registration).IsCapabilityAllowed(WellKnownCapabilityIdentifiers.Oid4VciCredentialOfferEndpoint)
            && server?.OAuth().ResolveCredentialOfferAsync is not null)
        {
            candidates.Add(BuildCredentialOfferEndpoint());
        }

        return ValueTask.FromResult<IReadOnlyList<EndpointCandidate>>(candidates);
    };


    /// <summary>
    /// Builds the OID4VCI 1.0 §7 Nonce Endpoint candidate. Stateless and <b>unprotected</b>
    /// (§7.1: the Wallet supplies no access token): a single POST that returns a fresh
    /// <c>c_nonce</c> challenge for proof-of-possession in a subsequent Credential Request.
    /// </summary>
    private static EndpointCandidate BuildNonceEndpoint() =>
        new()
        {
            Name = WellKnownEndpointNames.Oid4VciNonce,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownCapabilityIdentifiers.Oid4VciNonceEndpoint,
            //§7.1 is a single unprotected POST that returns and is done — no multi-step flow
            //and no correlation key, the same stateless shape as revocation / introspection.
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,
            //The Nonce Endpoint is advertised in the Credential Issuer Metadata
            //(nonce_endpoint, §12.2.4), not in the OAuth Authorization Server Metadata.
            DiscoveryMetadataKey = null,

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
                EndpointServer server = context.Server!;
                var oauth = server.OAuth();

                //OID4VCI 1.0 §7.2: c_nonce is a server-chosen, unpredictable challenge the
                //application mints (and later validates at the Credential Endpoint). The
                //library owns only the wire shape; the gate guarantees the seam is wired.
                string credentialNonce = await oauth.IssueCredentialNonceAsync!(
                    context, ct).ConfigureAwait(false);

                StringBuilder sb = JsonAppender.Rent();
                string responseJson;
                try
                {
                    sb.Append('{');
                    bool first = true;
                    JsonAppender.AppendStringField(sb, "c_nonce", credentialNonce, ref first);
                    sb.Append('}');
                    responseJson = sb.ToString();
                }
                finally
                {
                    JsonAppender.Return(sb);
                }

                //§7.2: the c_nonce is temporal — the response MUST be uncacheable.
                return Respond(ServerHttpResponse
                    .Ok(responseJson, WellKnownMediaTypes.Application.Json)
                    .WithHeader(WellKnownHttpHeaderNames.CacheControl, WellKnownCacheControlValues.NoStore));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    /// <summary>
    /// Builds the OID4VCI 1.0 §4.1.3 Credential Offer Endpoint candidate. Stateless and
    /// <b>unprotected</b> (§4.1.3: the resource is fetched without an access token and is never
    /// signed): a single GET that serves a stored <see cref="CredentialOffer"/> by the
    /// <c>id</c> the <c>credential_offer_uri</c> carries. The library reads the id from the
    /// request, hands it to the
    /// <see cref="AuthorizationServerIntegration.ResolveCredentialOfferAsync"/> seam, answers
    /// HTTP 404 when no live offer matches, and otherwise serializes the resolved offer to its
    /// §4.1.1 <c>application/json</c> object via <see cref="CredentialOfferSerializer"/>.
    /// </summary>
    private static EndpointCandidate BuildCredentialOfferEndpoint() =>
        new()
        {
            Name = WellKnownEndpointNames.Oid4VciCredentialOffer,
            HttpMethod = WellKnownHttpMethods.Get,
            Capability = WellKnownCapabilityIdentifiers.Oid4VciCredentialOfferEndpoint,
            //§4.1.3 is a single unprotected GET that returns the offer and is done — no
            //multi-step flow and no correlation key, the same stateless shape as the
            //Nonce Endpoint and the Credential Issuer Metadata endpoint.
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,
            //The credential_offer_uri is carried in the §4.1.3 deep link the Issuer composes,
            //not advertised in the OAuth Authorization Server Metadata.
            DiscoveryMetadataKey = null,

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

                return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
            },

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.Server!;
                var oauth = server.OAuth();

                //§4.1.3: the offer is addressed by the id the credential_offer_uri carries. The
                //test fixture passes it as the "id" request field; a production deployment that
                //embeds it in the path projects it into the same field at routing.
                if(!fields.TryGetValue(CredentialOfferParameterNames.Id, out string? offerId)
                    || string.IsNullOrWhiteSpace(offerId))
                {
                    return Respond(ServerHttpResponse.NotFound());
                }

                //The application owns the offer store; the gate guarantees the seam is wired. An
                //unknown or expired id resolves to null and is answered 404 — there is no offer
                //to serve.
                CredentialOffer? offer = await oauth.ResolveCredentialOfferAsync!(
                    offerId, context, ct).ConfigureAwait(false);
                if(offer is null)
                {
                    return Respond(ServerHttpResponse.NotFound());
                }

                //§4.1.3: the by-reference resource MUST be the §4.1.1 JSON object as
                //application/json (and is never signed).
                string offerJson = CredentialOfferSerializer.ToJson(offer);

                return Respond(ServerHttpResponse.Ok(offerJson, WellKnownMediaTypes.Application.Json));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    /// <summary>
    /// Builds the OID4VCI 1.0 §8 Credential Endpoint candidate. Stateless and <b>protected</b>
    /// (§8.3.1.1: the Wallet presents the access token the grant minted): the library validates
    /// the bearer token, parses the §8.2 request, enforces the credential-identifier shape, and
    /// hands the request plus the validated access-token claims to the
    /// <see cref="AuthorizationServerIntegration.IssueCredentialAsync"/> seam, which verifies
    /// the holder proofs and mints the Credential. The library maps the returned decision to
    /// the §8.3 Credential Response or a §8.3.1.2 Credential Error Response.
    /// </summary>
    private static EndpointCandidate BuildCredentialEndpoint() =>
        new()
        {
            Name = WellKnownEndpointNames.Oid4VciCredential,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownCapabilityIdentifiers.Oid4VciCredentialEndpoint,
            //One protected POST that issues and is done — no multi-step flow and no
            //correlation key, the same stateless shape as the Nonce Endpoint.
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,
            //Advertised in the Credential Issuer Metadata (credential_endpoint, §12.2.4),
            //not in the OAuth Authorization Server Metadata.
            DiscoveryMetadataKey = null,

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
                EndpointServer server = context.Server!;
                var oauth = server.OAuth();

                ClientRecord? registration = context.ClientRegistration;
                if(registration is null)
                {
                    return Respond(ServerHttpResponse.Unauthorized(
                        OAuthErrors.InvalidClient, "Unknown client."));
                }

                //§8.3.1.1: the Credential Request must carry an Access Token that enables
                //issuance. The library validates the AS-issued token (signature, iss, exp) —
                //the same protected-resource boundary UserInfo applies — before any minting.
                if(!BearerTokenValidation.TryExtractAccessToken(
                    context, out string? bearerToken, out bool isDpopPresentation))
                {
                    return Respond(ServerHttpResponse.Unauthorized(
                        OAuthErrors.InvalidToken, "Missing or malformed Authorization header."));
                }

                (JwtPayload? accessToken, ServerHttpResponse? validationFailure) =
                    await BearerTokenValidation.ValidateAsync(bearerToken!, server, registration, context, ct)
                        .ConfigureAwait(false);
                if(validationFailure is not null)
                {
                    return Respond(validationFailure);
                }

                //RFC 9449 §7.1: when the Access Token carries a cnf.jkt binding, a DPoP proof
                //bound to the same key MUST accompany it — the sender constraint the token
                //endpoint minted is verified here, never silently dropped to bearer.
                ServerHttpResponse? dpopFailure = await CredentialEndpointDpopValidation.EnforceAsync(
                    server, context, registration, accessToken!, bearerToken!, isDpopPresentation,
                    server.TimeProvider.GetUtcNow(), ct).ConfigureAwait(false);
                if(dpopFailure is not null)
                {
                    return Respond(dpopFailure);
                }

                //§8.2: the Credential Request body is application/json. An absent body is malformed.
                IncomingRequest? req = context.IncomingRequest;
                if(req is null || req.Body.IsEmpty || req.Body.Bytes.IsEmpty)
                {
                    return Respond(CredentialError(
                        Oid4VciCredentialErrors.InvalidCredentialRequest,
                        "The Credential Request body is missing."));
                }

                string requestBody = Encoding.UTF8.GetString(req.Body.Bytes.Span);

                //§10: an encrypted Credential Request arrives as a compact JWE
                //(application/jwt). The application's decryption seam owns the JWE; the
                //endpoint owns the fail-closed refusal when the seam is unwired.
                (string? decryptedBody, ServerHttpResponse? decryptFailure) =
                    await DecryptCredentialRequestBodyAsync(server, registration, requestBody, context, ct)
                        .ConfigureAwait(false);
                if(decryptFailure is not null)
                {
                    return Respond(decryptFailure);
                }

                bool wasRequestEncrypted = decryptedBody is not null;
                requestBody = decryptedBody ?? requestBody;

                CredentialRequest? request = await oauth.ParseCredentialRequestAsync!(
                    requestBody, context, ct).ConfigureAwait(false);
                if(request is null)
                {
                    return Respond(CredentialError(
                        Oid4VciCredentialErrors.InvalidCredentialRequest,
                        "The Credential Request could not be parsed."));
                }

                //§10 / §12.2.4: the gate enforces what the issuer metadata promises — an
                //advertised encryption_required:true makes a plain request, or one without
                //response-encryption keys, a downgrade rather than a choice.
                (bool isRequestEncryptionRequired, bool isResponseEncryptionRequired) =
                    await ReadEncryptionRequirementsAsync(server, registration, context, ct)
                        .ConfigureAwait(false);

                //§8.2: "Credential Request encryption MUST be used if the
                //credential_response_encryption parameter is included, to prevent it being
                //substituted by an attacker." This MUST is unconditional: it holds independent of
                //encryption_required. A plaintext request that carries credential_response_encryption
                //is a response-key substitution opportunity — an attacker who can rewrite the
                //plaintext request swaps in its own response-encryption JWK and reads the response.
                //So ANY plaintext request carrying credential_response_encryption is refused, even
                //when the issuer's encryption_required is false, with the encryption-specific error
                //so the cause is unambiguous.
                if(!wasRequestEncrypted && request.ResponseEncryption is not null)
                {
                    return Respond(CredentialError(
                        Oid4VciCredentialErrors.InvalidEncryptionParameters,
                        "A Credential Request carrying credential_response_encryption MUST itself be "
                        + "encrypted, to prevent the response key being substituted by an attacker (§8.2)."));
                }

                if(isRequestEncryptionRequired && !wasRequestEncrypted)
                {
                    return Respond(CredentialError(
                        Oid4VciCredentialErrors.InvalidCredentialRequest,
                        "This Credential Issuer requires encrypted Credential Requests (§10)."));
                }

                if(isResponseEncryptionRequired && request.ResponseEncryption is null)
                {
                    return Respond(CredentialError(
                        Oid4VciCredentialErrors.InvalidEncryptionParameters,
                        "This Credential Issuer requires encrypted Credential Responses; the "
                        + "request must carry credential_response_encryption (§12.2.4)."));
                }

                //§10 / §12.2.4: the requested JWE alg and enc MUST be ones the issuer advertised,
                //and the JWE alg MUST equal the chosen JWK's alg member. Enforced as a library
                //guarantee BEFORE the application's composition seam, so the §10 alg MUST cannot
                //be skipped by an unguarded seam.
                ServerHttpResponse? responseEncryptionFailure = await ValidateResponseEncryptionParametersAsync(
                    server, registration, request.ResponseEncryption, context, ct).ConfigureAwait(false);
                if(responseEncryptionFailure is not null)
                {
                    return Respond(responseEncryptionFailure);
                }

                //§8.2: credential_configuration_id and credential_identifier are mutually
                //exclusive, and exactly one identifies what is requested.
                bool hasConfigurationId = !string.IsNullOrWhiteSpace(request.CredentialConfigurationId);
                bool hasIdentifier = !string.IsNullOrWhiteSpace(request.CredentialIdentifier);
                if(hasConfigurationId == hasIdentifier)
                {
                    return Respond(CredentialError(
                        Oid4VciCredentialErrors.InvalidCredentialRequest,
                        "Exactly one of credential_configuration_id or credential_identifier is required."));
                }

                //§8.2 scope binding + §12.2.4 batch ceiling — both enforced off the same issuer
                //metadata contribution the document advertises, so the request cannot draw a
                //configuration the token was not scoped for or exceed the advertised batch_size.
                ServerHttpResponse? constraintFailure = await ValidateConfigurationConstraintsAsync(
                    server, registration, request, accessToken!, context, ct).ConfigureAwait(false);
                if(constraintFailure is not null)
                {
                    return Respond(constraintFailure);
                }

                //Appendix F.4: when the deployment wires the proof-expectation seam, the library
                //runs the holder-key-proof checks (typ/alg/jwk/signature/aud/iat/nonce) over the
                //§8.2 proofs.jwt batch BEFORE minting, mapping a failure to the §8.3.1.2
                //invalid_proof / invalid_nonce error. Unwired, this is a no-op and the §F.4 check
                //stays with IssueCredentialAsync — the established default.
                ServerHttpResponse? proofFailure = await CredentialEndpointProofValidation.EnforceAsync(
                    server, context, registration, request, accessToken!, ct).ConfigureAwait(false);
                if(proofFailure is not null)
                {
                    return Respond(proofFailure);
                }

                //The application owns proof verification (its c_nonce store), the supported
                //Credential Configurations, and the signing key; the gate guarantees the seam
                //is wired. accessToken carries the subject the grant bound issuance to.
                CredentialIssuanceDecision decision = await oauth.IssueCredentialAsync!(
                    request, accessToken!, registration, context, ct).ConfigureAwait(false);

                //§8.3: a deferral answers 202 with transaction_id + interval; the Wallet later
                //polls the §9 Deferred Credential Endpoint. Encrypted when requested —
                //§8.3 applies regardless of the response content.
                if(decision.IsDeferred)
                {
                    if(string.IsNullOrWhiteSpace(decision.TransactionId))
                    {
                        return Respond(ServerHttpResponse.ServerError(
                            OAuthErrors.ServerError,
                            "Issuance was deferred but no transaction_id was supplied."));
                    }

                    string pendingJson = BuildDeferredPendingBody(
                        decision.TransactionId!, decision.IntervalSeconds);
                    ServerHttpResponse deferredResponse = await FinishCredentialResponseAsync(
                        server, registration, request.ResponseEncryption, pendingJson,
                        isDeferredPending: true, context, ct).ConfigureAwait(false);

                    return Respond(deferredResponse);
                }

                if(!decision.IsIssued)
                {
                    return Respond(MapCredentialError(decision));
                }

                if(decision.Credentials.Count == 0)
                {
                    return Respond(ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "Credential issuance was granted but produced no Credentials."));
                }

                //§8.3: 200 with the credentials array; the response is uncacheable, and
                //encrypted per §10 when the request asked for it.
                string responseJson = BuildCredentialsResponseBody(
                    decision.Credentials, decision.NotificationId);
                ServerHttpResponse issuedResponse = await FinishCredentialResponseAsync(
                    server, registration, request.ResponseEncryption, responseJson,
                    isDeferredPending: false, context, ct).ConfigureAwait(false);

                return Respond(issuedResponse);
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    /// <summary>
    /// Composes the §8.3 / §9.2 Credentials response body — <c>{"credentials":
    /// [{"credential":...}], "notification_id"?:...}</c> — shared by the Credential Endpoint
    /// and the Deferred Credential Endpoint, whose issued responses carry the same shape.
    /// </summary>
    private static string BuildCredentialsResponseBody(
        IReadOnlyList<string> credentials, string? notificationId)
    {
        StringBuilder sb = JsonAppender.Rent();
        try
        {
            sb.Append('{');
            sb.Append('"');
            JsonAppender.AppendEscapedString(sb, Oid4VciCredentialParameterNames.Credentials);
            sb.Append("\":[");

            bool firstCredential = true;
            foreach(string credential in credentials)
            {
                if(!firstCredential)
                {
                    sb.Append(',');
                }

                firstCredential = false;
                sb.Append('{');
                bool credentialFieldFirst = true;
                JsonAppender.AppendStringField(
                    sb, Oid4VciCredentialParameterNames.Credential, credential, ref credentialFieldFirst);
                sb.Append('}');
            }

            sb.Append(']');

            //credentials is already written, so the notification_id field (when present) is
            //not the first member and carries a leading comma.
            bool first = false;
            if(!string.IsNullOrEmpty(notificationId))
            {
                JsonAppender.AppendStringField(
                    sb, Oid4VciCredentialParameterNames.NotificationId, notificationId, ref first);
            }

            sb.Append('}');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    /// <summary>
    /// Builds the OID4VCI 1.0 §9 Deferred Credential Endpoint candidate. Stateless and
    /// <b>protected</b>: the library validates the bearer token and the §9.1 request shape
    /// (a JSON body whose <c>transaction_id</c> is REQUIRED), hands the transaction to the
    /// <see cref="AuthorizationServerIntegration.ResolveDeferredCredentialAsync"/> seam, and
    /// maps the verdict to the §9.2 200-with-<c>credentials</c> / 202-with-<c>interval</c>
    /// responses or a §9.3 error.
    /// </summary>
    private static EndpointCandidate BuildDeferredCredentialEndpoint() =>
        new()
        {
            Name = WellKnownEndpointNames.Oid4VciDeferredCredential,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownCapabilityIdentifiers.Oid4VciDeferredCredentialEndpoint,
            //One protected POST that answers and is done — the deferred-transaction state
            //lives in the application store, not in a library flow.
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,
            //Advertised in the Credential Issuer Metadata (deferred_credential_endpoint,
            //§12.2.4), not in the OAuth Authorization Server Metadata.
            DiscoveryMetadataKey = null,

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
                EndpointServer server = context.Server!;
                var oauth = server.OAuth();

                ClientRecord? registration = context.ClientRegistration;
                if(registration is null)
                {
                    return Respond(ServerHttpResponse.Unauthorized(
                        OAuthErrors.InvalidClient, "Unknown client."));
                }

                //§9: the Wallet presents an access token valid for the issuance previously
                //requested at the Credential Endpoint — the same protected-resource boundary.
                if(!BearerTokenValidation.TryExtractAccessToken(
                    context, out string? bearerToken, out bool isDpopPresentation))
                {
                    return Respond(ServerHttpResponse.Unauthorized(
                        OAuthErrors.InvalidToken, "Missing or malformed Authorization header."));
                }

                (JwtPayload? accessToken, ServerHttpResponse? validationFailure) =
                    await BearerTokenValidation.ValidateAsync(bearerToken!, server, registration, context, ct)
                        .ConfigureAwait(false);
                if(validationFailure is not null)
                {
                    return Respond(validationFailure);
                }

                //RFC 9449 §7.1: when the Access Token carries a cnf.jkt binding, a DPoP proof
                //bound to the same key MUST accompany it — the sender constraint the token
                //endpoint minted is verified here, never silently dropped to bearer.
                ServerHttpResponse? dpopFailure = await CredentialEndpointDpopValidation.EnforceAsync(
                    server, context, registration, accessToken!, bearerToken!, isDpopPresentation,
                    server.TimeProvider.GetUtcNow(), ct).ConfigureAwait(false);
                if(dpopFailure is not null)
                {
                    return Respond(dpopFailure);
                }

                //§9.1: the request body is application/json carrying the REQUIRED
                //transaction_id; unrecognized parameters are ignored. An encrypted request
                //arrives as a compact JWE (§10) and is routed to the decryption seam first.
                //The members are read with the span scanner, keeping the serialization
                //firewall without a parse seam.
                IncomingRequest? req = context.IncomingRequest;
                string? transactionId = null;
                CredentialResponseEncryption? responseEncryption = null;
                bool wasRequestEncrypted = false;
                if(req is not null && !req.Body.IsEmpty && !req.Body.Bytes.IsEmpty)
                {
                    string deferredBody = Encoding.UTF8.GetString(req.Body.Bytes.Span);

                    (string? decryptedBody, ServerHttpResponse? decryptFailure) =
                        await DecryptCredentialRequestBodyAsync(
                            server, registration, deferredBody, context, ct).ConfigureAwait(false);
                    if(decryptFailure is not null)
                    {
                        return Respond(decryptFailure);
                    }

                    wasRequestEncrypted = decryptedBody is not null;
                    deferredBody = decryptedBody ?? deferredBody;

                    byte[] bodyBytes = Encoding.UTF8.GetBytes(deferredBody);
                    transactionId = JwkJsonReader.ExtractStringValue(
                        bodyBytes, Oid4VciCredentialParameterNames.TransactionIdUtf8);
                    responseEncryption = ReadDeferredResponseEncryption(bodyBytes);
                }

                if(string.IsNullOrWhiteSpace(transactionId))
                {
                    return Respond(CredentialError(
                        Oid4VciCredentialErrors.InvalidCredentialRequest,
                        "The Deferred Credential Request must carry a transaction_id."));
                }

                //§10 / §12.2.4: the same metadata-promised gate the Credential Endpoint runs —
                //the deferred leg is not a downgrade path around it.
                (bool isRequestEncryptionRequired, bool isResponseEncryptionRequired) =
                    await ReadEncryptionRequirementsAsync(server, registration, context, ct)
                        .ConfigureAwait(false);

                //§9.1: "Deferred Credential Request encryption MUST [be] used if the
                //credential_response_encryption parameter is included, to prevent it being
                //substituted by an attacker." Unconditional, like §8.2: ANY plaintext deferred
                //request carrying credential_response_encryption is a response-key substitution
                //opportunity and is refused, even when the issuer's encryption_required is false,
                //with the encryption-specific error.
                if(!wasRequestEncrypted && responseEncryption is not null)
                {
                    return Respond(CredentialError(
                        Oid4VciCredentialErrors.InvalidEncryptionParameters,
                        "A Deferred Credential Request carrying credential_response_encryption MUST itself "
                        + "be encrypted, to prevent the response key being substituted by an attacker (§9.1)."));
                }

                if(isRequestEncryptionRequired && !wasRequestEncrypted)
                {
                    return Respond(CredentialError(
                        Oid4VciCredentialErrors.InvalidCredentialRequest,
                        "This Credential Issuer requires encrypted Credential Requests (§10)."));
                }

                if(isResponseEncryptionRequired && responseEncryption is null)
                {
                    return Respond(CredentialError(
                        Oid4VciCredentialErrors.InvalidEncryptionParameters,
                        "This Credential Issuer requires encrypted Credential Responses; the "
                        + "request must carry credential_response_encryption (§12.2.4)."));
                }

                //§10 / §12.2.4: the requested JWE alg and enc MUST be advertised, and the JWE alg
                //MUST equal the chosen JWK's alg — the same library guarantee the Credential
                //Endpoint enforces, applied to the §9.1 newly-provided object.
                ServerHttpResponse? responseEncryptionFailure = await ValidateResponseEncryptionParametersAsync(
                    server, registration, responseEncryption, context, ct).ConfigureAwait(false);
                if(responseEncryptionFailure is not null)
                {
                    return Respond(responseEncryptionFailure);
                }

                //The application owns the deferred-transaction store; the gate guarantees the
                //seam is wired.
                DeferredCredentialDecision decision = await oauth.ResolveDeferredCredentialAsync!(
                    transactionId!, accessToken!, registration, context, ct).ConfigureAwait(false);

                if(decision.IsIssued)
                {
                    if(decision.Credentials.Count == 0)
                    {
                        return Respond(ServerHttpResponse.ServerError(
                            OAuthErrors.ServerError,
                            "Deferred issuance was reported complete but produced no Credentials."));
                    }

                    //§9.2: HTTP 200 with the §8.3 credentials array, encrypted per §10 when
                    //the request asked for it.
                    string responseJson = BuildCredentialsResponseBody(
                        decision.Credentials, decision.NotificationId);
                    ServerHttpResponse issuedResponse = await FinishCredentialResponseAsync(
                        server, registration, responseEncryption, responseJson,
                        isDeferredPending: false, context, ct).ConfigureAwait(false);

                    return Respond(issuedResponse);
                }

                if(decision.IsPending)
                {
                    //§9.2: HTTP 202 echoing the SAME transaction_id with the interval to
                    //wait — encrypted too when requested, regardless of the content.
                    string pendingJson = BuildDeferredPendingBody(transactionId!, decision.IntervalSeconds);
                    ServerHttpResponse pendingResponse = await FinishCredentialResponseAsync(
                        server, registration, responseEncryption, pendingJson,
                        isDeferredPending: true, context, ct).ConfigureAwait(false);

                    return Respond(pendingResponse);
                }

                //§9.3: invalid_transaction_id, or credential_request_denied when the Issuer
                //can no longer issue (the Wallet then stops polling).
                return Respond((decision.ErrorReason switch
                {
                    DeferredCredentialError.CredentialRequestDenied =>
                        CredentialError(Oid4VciCredentialErrors.CredentialRequestDenied,
                            decision.ErrorDescription ?? "The Credential Issuer can no longer issue the credential(s)."),
                    _ => CredentialError(Oid4VciCredentialErrors.InvalidTransactionId,
                        decision.ErrorDescription ?? "The transaction_id was not issued by this Credential Issuer or was already used.")
                }));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    /// <summary>
    /// Composes the §9.2 pending body — <c>{"transaction_id":...,"interval":...}</c> — echoing
    /// the request's <c>transaction_id</c> as §9.2 requires.
    /// </summary>
    private static string BuildDeferredPendingBody(string transactionId, int intervalSeconds)
    {
        StringBuilder sb = JsonAppender.Rent();
        try
        {
            sb.Append('{');
            bool first = true;
            JsonAppender.AppendStringField(
                sb, Oid4VciCredentialParameterNames.TransactionId, transactionId, ref first);
            JsonAppender.AppendInt64Field(
                sb, Oid4VciCredentialParameterNames.Interval, intervalSeconds, ref first);
            sb.Append('}');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    /// <summary>
    /// Reads the issuer's §12.2.4 encryption-requirement flags off the metadata contribution —
    /// the same application data the metadata endpoint advertises, so the gate enforces
    /// exactly what the document promises. An unwired contribution seam (or absent objects)
    /// requires nothing.
    /// </summary>
    private static async ValueTask<(bool IsRequestEncryptionRequired, bool IsResponseEncryptionRequired)>
        ReadEncryptionRequirementsAsync(
            EndpointServer server,
            ClientRecord registration,
            ExchangeContext context,
            CancellationToken cancellationToken)
    {
        var oauth = server.OAuth();
        if(oauth.ContributeCredentialIssuerMetadataAsync is null)
        {
            return (false, false);
        }

        CredentialIssuerMetadataContribution contribution =
            await oauth.ContributeCredentialIssuerMetadataAsync(
                registration, context, cancellationToken).ConfigureAwait(false);

        return (
            ReadEncryptionRequiredFlag(contribution.CredentialRequestEncryption),
            ReadEncryptionRequiredFlag(contribution.CredentialResponseEncryption));
    }


    private static bool ReadEncryptionRequiredFlag(IReadOnlyDictionary<string, object>? encryptionObject) =>
        encryptionObject is not null
            && encryptionObject.TryGetValue("encryption_required", out object? value)
            && value is bool isRequired
            && isRequired;


    /// <summary>
    /// §10 / §12.2.4 response-encryption parameter validation, run as a library guarantee BEFORE
    /// the application's <see cref="AuthorizationServerIntegration.EncryptCredentialResponseAsync"/>
    /// composition seam. The JWE composition is a deployment seam (a post-quantum KEM needs no
    /// library change), so the §10 algorithm MUSTs are enforced here rather than inside the seam:
    /// <list type="bullet">
    /// <item>§10 "The alg parameter MUST be present." — the JWK MUST carry an <c>alg</c> member.</item>
    /// <item>§12.2.4 — the requested <c>alg</c> MUST be among the advertised
    /// <c>alg_values_supported</c>, and the <c>enc</c> among <c>enc_values_supported</c>, when the
    /// issuer advertises them.</item>
    /// </list>
    /// Returns the <c>invalid_encryption_parameters</c> refusal on any violation, or
    /// <see langword="null"/> when the request asks for no encryption or the parameters pass. The
    /// §10 "JWE alg MUST equal the chosen JWK's alg" consistency is structural: the library reads
    /// the alg only from the JWK (<see cref="CredentialResponseEncryption.Alg"/>), so the value the
    /// seam composes into the JWE header and the JWK's alg are the same string.
    /// </summary>
    private static async ValueTask<ServerHttpResponse?> ValidateResponseEncryptionParametersAsync(
        EndpointServer server,
        ClientRecord registration,
        CredentialResponseEncryption? encryption,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        var oauth = server.OAuth();
        if(encryption is null)
        {
            return null;
        }

        //§10: "The alg parameter MUST be present." A response-encryption object whose JWK omits
        //alg (or whose enc/jwk is missing) cannot satisfy the §10 composition.
        if(!encryption.IsShapeValid)
        {
            return CredentialError(
                Oid4VciCredentialErrors.InvalidEncryptionParameters,
                "credential_response_encryption must carry jwk (with a §10 alg member) and enc.");
        }

        if(oauth.ContributeCredentialIssuerMetadataAsync is null)
        {
            return null;
        }

        CredentialIssuerMetadataContribution contribution =
            await oauth.ContributeCredentialIssuerMetadataAsync(
                registration, context, cancellationToken).ConfigureAwait(false);

        IReadOnlyDictionary<string, object>? responseEncryption = contribution.CredentialResponseEncryption;
        if(responseEncryption is null)
        {
            return null;
        }

        //§12.2.4: a requested alg / enc the issuer did not advertise is unsupported — refused
        //fail-closed rather than handed to the seam.
        if(IsAdvertised(responseEncryption, "alg_values_supported") && !ValueIsAdvertised(
            responseEncryption, "alg_values_supported", encryption.Alg!))
        {
            return CredentialError(
                Oid4VciCredentialErrors.InvalidEncryptionParameters,
                $"The requested response-encryption alg '{encryption.Alg}' is not among the issuer's "
                + "advertised alg_values_supported (§12.2.4).");
        }

        if(IsAdvertised(responseEncryption, "enc_values_supported") && !ValueIsAdvertised(
            responseEncryption, "enc_values_supported", encryption.Enc!))
        {
            return CredentialError(
                Oid4VciCredentialErrors.InvalidEncryptionParameters,
                $"The requested response-encryption enc '{encryption.Enc}' is not among the issuer's "
                + "advertised enc_values_supported (§12.2.4).");
        }

        return null;
    }


    /// <summary>Whether the response-encryption object advertises a non-empty list under <paramref name="member"/>.</summary>
    private static bool IsAdvertised(IReadOnlyDictionary<string, object> responseEncryption, string member) =>
        responseEncryption.TryGetValue(member, out object? value)
            && value is System.Collections.IEnumerable enumerable
            && enumerable is not string
            && EnumerableHasAny(enumerable);


    /// <summary>Whether <paramref name="candidate"/> appears as a string entry in the advertised <paramref name="member"/> list.</summary>
    private static bool ValueIsAdvertised(
        IReadOnlyDictionary<string, object> responseEncryption, string member, string candidate)
    {
        if(!responseEncryption.TryGetValue(member, out object? value)
            || value is not System.Collections.IEnumerable enumerable
            || value is string)
        {
            return false;
        }

        foreach(object? entry in enumerable)
        {
            if(entry is string advertised && string.Equals(advertised, candidate, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>Whether the (already non-string) enumerable yields at least one element.</summary>
    private static bool EnumerableHasAny(System.Collections.IEnumerable enumerable)
    {
        foreach(object? _ in enumerable)
        {
            return true;
        }

        return false;
    }


    /// <summary>
    /// Enforces the two Credential Issuer Metadata constraints the document promises, read off
    /// the same <see cref="AuthorizationServerIntegration.ContributeCredentialIssuerMetadataAsync"/>
    /// contribution that advertises them: §8.2 scope binding (a request naming a
    /// <c>credential_configuration_id</c> whose configuration declares a <c>scope</c> MUST present
    /// an Access Token granted that scope) and the §12.2.4 batch ceiling (the proof count MUST NOT
    /// exceed <c>batch_credential_issuance.batch_size</c>, and may exceed one only when batch
    /// issuance is advertised). An unwired contribution advertises neither, so neither is enforced.
    /// </summary>
    private static async ValueTask<ServerHttpResponse?> ValidateConfigurationConstraintsAsync(
        EndpointServer server,
        ClientRecord registration,
        CredentialRequest request,
        JwtPayload accessToken,
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

        IReadOnlyDictionary<string, object>? configuration = LookupRequestedConfiguration(contribution, request);

        ServerHttpResponse? scopeFailure = ValidateScopeConfigurationBinding(configuration, accessToken);
        if(scopeFailure is not null)
        {
            return scopeFailure;
        }

        ServerHttpResponse? attestationFailure = ValidateKeyAttestationRequirement(
            configuration, request, oauth.Codecs.Decoder);
        if(attestationFailure is not null)
        {
            return attestationFailure;
        }

        return ValidateBatchCeiling(contribution, request);
    }


    /// <summary>
    /// Returns the advertised configuration object for the request's
    /// <c>credential_configuration_id</c>, or <see langword="null"/> when the request uses a
    /// <c>credential_identifier</c> or the configuration is not in the advertised catalog.
    /// </summary>
    private static IReadOnlyDictionary<string, object>? LookupRequestedConfiguration(
        CredentialIssuerMetadataContribution contribution, CredentialRequest request)
    {
        if(string.IsNullOrWhiteSpace(request.CredentialConfigurationId)
            || contribution.CredentialConfigurationsSupported is null
            || !contribution.CredentialConfigurationsSupported.TryGetValue(
                request.CredentialConfigurationId!, out object? configurationObject)
            || configurationObject is not IReadOnlyDictionary<string, object> configuration)
        {
            return null;
        }

        return configuration;
    }


    /// <summary>
    /// §8.2: when the requested configuration declares a <c>scope</c>, that scope MUST be among the
    /// scopes the Access Token was granted. The check applies only on the scope-authorization path —
    /// when the token carries no scope, or the configuration declares none, the binding is via
    /// authorization_details / credential_identifier and is left to <c>IssueCredentialAsync</c>.
    /// </summary>
    private static ServerHttpResponse? ValidateScopeConfigurationBinding(
        IReadOnlyDictionary<string, object>? configuration,
        JwtPayload accessToken)
    {
        if(configuration is null
            || !configuration.TryGetValue(CredentialIssuerMetadataParameterNames.Scope, out object? scopeValue)
            || scopeValue is not string configurationScope
            || string.IsNullOrWhiteSpace(configurationScope))
        {
            return null;
        }

        if(!accessToken.TryGetValue(WellKnownJwtClaimNames.Scope, out object? grantedValue)
            || grantedValue is not string grantedScopes
            || string.IsNullOrWhiteSpace(grantedScopes))
        {
            return null;
        }

        foreach(string grantedScope in grantedScopes.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            if(string.Equals(grantedScope, configurationScope, StringComparison.Ordinal))
            {
                return null;
            }
        }

        return CredentialError(
            Oid4VciCredentialErrors.InvalidCredentialRequest,
            "The requested credential_configuration_id is not authorized by the Access Token's scope (§8.2).");
    }


    /// <summary>
    /// Appendix D / §12.2.4: when the requested configuration declares <c>key_attestations_required</c>
    /// for a proof type, the request MUST carry a key attestation — either a standalone
    /// <c>attestation</c> proof or a <c>jwt</c> proof bearing a <c>key_attestation</c> JOSE header.
    /// The library enforces PRESENCE; the application verifies the attestation's signature and
    /// Wallet-Provider trust inside <c>IssueCredentialAsync</c>, where its trust anchors live.
    /// </summary>
    private static ServerHttpResponse? ValidateKeyAttestationRequirement(
        IReadOnlyDictionary<string, object>? configuration,
        CredentialRequest request,
        DecodeDelegate? decoder)
    {
        if(configuration is null || !ConfigurationRequiresKeyAttestation(configuration))
        {
            return null;
        }

        if(RequestCarriesKeyAttestation(request, decoder))
        {
            return null;
        }

        return CredentialError(
            Oid4VciCredentialErrors.InvalidProof,
            "The requested credential configuration requires a key attestation (Appendix D); the "
            + "request carries none.");
    }


    /// <summary>Whether any of the configuration's <c>proof_types_supported</c> entries declares <c>key_attestations_required</c>.</summary>
    private static bool ConfigurationRequiresKeyAttestation(IReadOnlyDictionary<string, object> configuration)
    {
        if(!configuration.TryGetValue(AttestationProofParameterNames.ProofTypesSupported, out object? proofTypesObject)
            || proofTypesObject is not IReadOnlyDictionary<string, object> proofTypes)
        {
            return false;
        }

        foreach(object proofTypeEntry in proofTypes.Values)
        {
            if(proofTypeEntry is IReadOnlyDictionary<string, object> proofTypeConfig
                && proofTypeConfig.ContainsKey(AttestationProofParameterNames.KeyAttestationsRequired))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>Whether the request supplies attestation evidence — a standalone <c>attestation</c> proof or a <c>key_attestation</c>-headed <c>jwt</c> proof.</summary>
    private static bool RequestCarriesKeyAttestation(CredentialRequest request, DecodeDelegate? decoder)
    {
        if(request.Proofs.TryGetValue(
                AttestationProofParameterNames.AttestationProofType, out IReadOnlyList<string>? attestations)
            && attestations.Count > 0)
        {
            return true;
        }

        if(decoder is not null
            && request.Proofs.TryGetValue(
                Oid4VciCredentialParameterNames.JwtProofType, out IReadOnlyList<string>? jwtProofs))
        {
            foreach(string jwtProof in jwtProofs)
            {
                if(JwtProofHasKeyAttestationHeader(jwtProof, decoder))
                {
                    return true;
                }
            }
        }

        return false;
    }


    /// <summary>Whether a compact <c>jwt</c> proof's JOSE header carries a <c>key_attestation</c> member.</summary>
    private static bool JwtProofHasKeyAttestationHeader(string jwtProof, DecodeDelegate decoder)
    {
        int firstDot = jwtProof.IndexOf('.', StringComparison.Ordinal);
        if(firstDot <= 0)
        {
            return false;
        }

        string headerSegment = jwtProof.AsSpan(0, firstDot).ToString();
        using IMemoryOwner<byte> headerOwner = decoder(headerSegment, BaseMemoryPool.Shared);

        return JwkJsonReader.ContainsKey(
            headerOwner.Memory.Span, AttestationProofParameterNames.KeyAttestationUtf8);
    }


    /// <summary>
    /// §12.2.4: more than one CREDENTIAL-bearing proof is batch issuance, permitted only when the
    /// Issuer advertises <c>batch_credential_issuance</c> and only up to its <c>batch_size</c>. A
    /// single proof is always allowed; an over-size or unadvertised batch is refused with
    /// <c>invalid_proof</c>. The <c>attestation</c> proof type is key-attestation EVIDENCE, not a
    /// credential-bearing proof, so it does not count toward the ceiling.
    /// </summary>
    private static ServerHttpResponse? ValidateBatchCeiling(
        CredentialIssuerMetadataContribution contribution,
        CredentialRequest request)
    {
        int proofCount = 0;
        foreach(KeyValuePair<string, IReadOnlyList<string>> proofsOfType in request.Proofs)
        {
            if(string.Equals(
                proofsOfType.Key, AttestationProofParameterNames.AttestationProofType, StringComparison.Ordinal))
            {
                continue;
            }

            proofCount += proofsOfType.Value.Count;
        }

        //Appendix F.2: di_vp presentations are credential-bearing key proofs, so they count toward
        //the batch ceiling alongside the jwt proofs.
        proofCount += request.DiVpProofs.Count;

        if(proofCount <= 1)
        {
            return null;
        }

        if(contribution.BatchCredentialIssuance is null
            || !contribution.BatchCredentialIssuance.TryGetValue(
                CredentialIssuerMetadataParameterNames.BatchSize, out object? batchSizeValue)
            || !TryReadInt(batchSizeValue, out int batchSize))
        {
            return CredentialError(
                Oid4VciCredentialErrors.InvalidProof,
                "This Credential Issuer does not support batch issuance; a single proof is required (§12.2.4).");
        }

        if(proofCount > batchSize)
        {
            return CredentialError(
                Oid4VciCredentialErrors.InvalidProof,
                $"The Credential Request carries {proofCount} proofs, exceeding the issuer's "
                + $"batch_size of {batchSize} (§12.2.4).");
        }

        return null;
    }


    /// <summary>Reads an integer from a contribution value supplied as an <see cref="int"/>, <see cref="long"/>, or numeric string.</summary>
    private static bool TryReadInt(object? value, out int result)
    {
        switch(value)
        {
            case int intValue:
            {
                result = intValue;

                return true;
            }
            case long longValue when longValue is >= int.MinValue and <= int.MaxValue:
            {
                result = (int)longValue;

                return true;
            }
            case string stringValue when int.TryParse(
                stringValue, System.Globalization.NumberStyles.Integer,
                System.Globalization.CultureInfo.InvariantCulture, out int parsed):
            {
                result = parsed;

                return true;
            }
            default:
            {
                result = 0;

                return false;
            }
        }
    }


    /// <summary>
    /// Routes a compact-JWE request body to the §10 decryption seam. Returns
    /// <c>(null, null)</c> when the body is plain JSON, the decrypted JSON on success, and the
    /// fail-closed refusal when the body is a JWE the deployment cannot (seam unwired) or could
    /// not (seam returned <see langword="null"/>) decrypt.
    /// </summary>
    private static async ValueTask<(string? DecryptedBody, ServerHttpResponse? Failure)>
        DecryptCredentialRequestBodyAsync(
            EndpointServer server,
            ClientRecord registration,
            string requestBody,
            ExchangeContext context,
            CancellationToken cancellationToken)
    {
        var oauth = server.OAuth();
        if(!IsCompactJwe(requestBody))
        {
            return (null, null);
        }

        if(oauth.DecryptCredentialRequestAsync is null)
        {
            return (null, CredentialError(
                Oid4VciCredentialErrors.InvalidCredentialRequest,
                "The request is encrypted but this Credential Issuer does not accept encrypted requests."));
        }

        string? decrypted = await oauth.DecryptCredentialRequestAsync(
            requestBody, registration, context, cancellationToken).ConfigureAwait(false);
        if(decrypted is null)
        {
            return (null, CredentialError(
                Oid4VciCredentialErrors.InvalidCredentialRequest,
                "The encrypted request could not be decrypted."));
        }

        return (decrypted, null);
    }


    /// <summary>
    /// Whether <paramref name="body"/> has the five-part shape of a compact JWE — the §10
    /// encrypted-request wire form — rather than a JSON object.
    /// </summary>
    private static bool IsCompactJwe(string body)
    {
        ReadOnlySpan<char> trimmed = body.AsSpan().TrimStart();

        return trimmed.Length > 0 && trimmed[0] != '{' && trimmed.Count('.') == 4;
    }


    /// <summary>
    /// Finishes a (Deferred) Credential Response: plain <c>application/json</c> when the
    /// request asked for no encryption; otherwise the §10 JWE via the application's
    /// <see cref="AuthorizationServerIntegration.EncryptCredentialResponseAsync"/> seam with
    /// media type <c>application/jwt</c>. Fails closed with
    /// <c>invalid_encryption_parameters</c> when encryption was requested but the parameters
    /// are malformed, the seam is unwired, or the seam refuses them — §8.3 forbids answering
    /// such a request in clear.
    /// </summary>
    private static async ValueTask<ServerHttpResponse> FinishCredentialResponseAsync(
        EndpointServer server,
        ClientRecord registration,
        CredentialResponseEncryption? encryption,
        string responseJson,
        bool isDeferredPending,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        var oauth = server.OAuth();
        if(encryption is null)
        {
            ServerHttpResponse plain = isDeferredPending
                ? ServerHttpResponse.Accepted(responseJson, WellKnownMediaTypes.Application.Json)
                : ServerHttpResponse.Ok(responseJson, WellKnownMediaTypes.Application.Json);

            return plain.WithHeader(WellKnownHttpHeaderNames.CacheControl, WellKnownCacheControlValues.NoStore);
        }

        if(!encryption.IsShapeValid)
        {
            return CredentialError(
                Oid4VciCredentialErrors.InvalidEncryptionParameters,
                "credential_response_encryption must carry the jwk and enc members.");
        }

        if(oauth.EncryptCredentialResponseAsync is null)
        {
            return CredentialError(
                Oid4VciCredentialErrors.InvalidEncryptionParameters,
                "This Credential Issuer does not support encrypted Credential Responses.");
        }

        string? encrypted = await oauth.EncryptCredentialResponseAsync(
            responseJson, encryption, registration, context, cancellationToken).ConfigureAwait(false);
        if(encrypted is null)
        {
            return CredentialError(
                Oid4VciCredentialErrors.InvalidEncryptionParameters,
                "The requested Credential Response encryption parameters are not supported.");
        }

        ServerHttpResponse response = isDeferredPending
            ? ServerHttpResponse.Accepted(encrypted, WellKnownMediaTypes.Application.Jwt)
            : ServerHttpResponse.Ok(encrypted, WellKnownMediaTypes.Application.Jwt);

        return response.WithHeader(WellKnownHttpHeaderNames.CacheControl, WellKnownCacheControlValues.NoStore);
    }


    /// <summary>
    /// Reads the §9.1 <c>credential_response_encryption</c> object off the Deferred Credential
    /// Request body with the span scanner — <c>jwk</c> as its string members, <c>enc</c>, the
    /// optional <c>zip</c>.
    /// </summary>
    private static CredentialResponseEncryption? ReadDeferredResponseEncryption(byte[] bodyBytes)
    {
        string? encryptionObject = JwkJsonReader.ExtractObjectAsString(
            bodyBytes, Oid4VciCredentialParameterNames.CredentialResponseEncryptionUtf8);
        if(encryptionObject is null)
        {
            return null;
        }

        byte[] encryptionBytes = Encoding.UTF8.GetBytes(encryptionObject);
        Dictionary<string, object>? jwk = JwkJsonReader.ExtractObjectProperties(
            encryptionBytes, Oid4VciCredentialParameterNames.JwkUtf8);

        return new CredentialResponseEncryption
        {
            Jwk = jwk,
            Enc = JwkJsonReader.ExtractStringValue(encryptionBytes, Oid4VciCredentialParameterNames.EncUtf8),
            Zip = JwkJsonReader.ExtractStringValue(encryptionBytes, Oid4VciCredentialParameterNames.ZipUtf8)
        };
    }


    /// <summary>
    /// Builds the OID4VCI 1.0 §11 Notification Endpoint candidate. Stateless and
    /// <b>protected</b>: the library validates the bearer token and the §11.1 request shape
    /// (REQUIRED <c>notification_id</c>, REQUIRED case-sensitive <c>event</c>, optional
    /// <c>event_description</c>), hands the notification to the
    /// <see cref="AuthorizationServerIntegration.ProcessCredentialNotificationAsync"/> seam,
    /// and answers the §11.2 204 No Content or a §11.3 error.
    /// </summary>
    private static EndpointCandidate BuildNotificationEndpoint() =>
        new()
        {
            Name = WellKnownEndpointNames.Oid4VciNotification,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownCapabilityIdentifiers.Oid4VciNotificationEndpoint,
            //One protected POST that acknowledges and is done; §11 makes the notification
            //idempotent, so there is no flow to correlate.
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,
            //Advertised in the Credential Issuer Metadata (notification_endpoint, §12.2.4),
            //not in the OAuth Authorization Server Metadata.
            DiscoveryMetadataKey = null,

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
                EndpointServer server = context.Server!;
                var oauth = server.OAuth();

                ClientRecord? registration = context.ClientRegistration;
                if(registration is null)
                {
                    return Respond(ServerHttpResponse.Unauthorized(
                        OAuthErrors.InvalidClient, "Unknown client."));
                }

                //§11.3: a missing or invalid access token answers an RFC 6750 §3
                //Authorization Error Response.
                if(!BearerTokenValidation.TryExtractAccessToken(
                    context, out string? bearerToken, out bool isDpopPresentation))
                {
                    return Respond(ServerHttpResponse.Unauthorized(
                        OAuthErrors.InvalidToken, "Missing or malformed Authorization header."));
                }

                (JwtPayload? accessToken, ServerHttpResponse? validationFailure) =
                    await BearerTokenValidation.ValidateAsync(bearerToken!, server, registration, context, ct)
                        .ConfigureAwait(false);
                if(validationFailure is not null)
                {
                    return Respond(validationFailure);
                }

                //RFC 9449 §7.1: when the Access Token carries a cnf.jkt binding, a DPoP proof
                //bound to the same key MUST accompany it — the sender constraint the token
                //endpoint minted is verified here, never silently dropped to bearer.
                ServerHttpResponse? dpopFailure = await CredentialEndpointDpopValidation.EnforceAsync(
                    server, context, registration, accessToken!, bearerToken!, isDpopPresentation,
                    server.TimeProvider.GetUtcNow(), ct).ConfigureAwait(false);
                if(dpopFailure is not null)
                {
                    return Respond(dpopFailure);
                }

                //§11.1: an application/json body with the REQUIRED notification_id and event;
                //unrecognized parameters are ignored. The string members are read with the
                //span scanner, keeping the serialization firewall without a parse seam.
                IncomingRequest? req = context.IncomingRequest;
                string? notificationId = null;
                string? notificationEvent = null;
                string? eventDescription = null;
                if(req is not null && !req.Body.IsEmpty && !req.Body.Bytes.IsEmpty)
                {
                    notificationId = JwkJsonReader.ExtractStringValue(
                        req.Body.Bytes.Span, Oid4VciCredentialParameterNames.NotificationIdUtf8);
                    notificationEvent = JwkJsonReader.ExtractStringValue(
                        req.Body.Bytes.Span, Oid4VciCredentialParameterNames.EventUtf8);
                    eventDescription = JwkJsonReader.ExtractStringValue(
                        req.Body.Bytes.Span, Oid4VciCredentialParameterNames.EventDescriptionUtf8);
                }

                if(string.IsNullOrWhiteSpace(notificationId) || string.IsNullOrWhiteSpace(notificationEvent))
                {
                    return Respond(CredentialError(
                        Oid4VciCredentialErrors.InvalidNotificationRequest,
                        "The Notification Request must carry notification_id and event."));
                }

                //§11.1: event is a case-sensitive string limited to the three defined values.
                if(!Oid4VciNotificationEvents.IsKnownEvent(notificationEvent!))
                {
                    return Respond(CredentialError(
                        Oid4VciCredentialErrors.InvalidNotificationRequest,
                        $"The event '{notificationEvent}' is not a defined notification event."));
                }

                //§11.1: "Values for the event_description parameter MUST NOT include characters
                //outside the set %x20-21 / %x23-5B / %x5D-7E." Sanitize the consumed value to that
                //set before it reaches the application seam, so the library never propagates a
                //non-conformant event_description.
                CredentialNotification notification = new()
                {
                    NotificationId = notificationId!,
                    Event = notificationEvent!,
                    EventDescription = ErrorDescriptionCharset.Sanitize(eventDescription)
                };

                //The application owns the notification_id store; the gate guarantees the seam
                //is wired.
                CredentialNotificationDecision decision = await oauth.ProcessCredentialNotificationAsync!(
                    notification, accessToken!, registration, context, ct).ConfigureAwait(false);

                if(!decision.IsAccepted)
                {
                    return Respond(CredentialError(
                        Oid4VciCredentialErrors.InvalidNotificationId,
                        decision.ErrorDescription ?? "The notification_id in the Notification Request was invalid."));
                }

                //§11.2: success conveys everything in the status code — 204 is RECOMMENDED.
                return Respond(ServerHttpResponse.NoContent());
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    /// <summary>
    /// Maps a refused <see cref="CredentialIssuanceDecision"/> to its §8.3.1.2 Credential Error
    /// Response (HTTP 400, <c>Cache-Control: no-store</c>). A refusal with no reason set
    /// defaults to <c>invalid_credential_request</c>.
    /// </summary>
    private static ServerHttpResponse MapCredentialError(CredentialIssuanceDecision decision) =>
        decision.ErrorReason switch
        {
            CredentialRequestError.UnknownCredentialConfiguration =>
                CredentialError(Oid4VciCredentialErrors.UnknownCredentialConfiguration,
                    decision.ErrorDescription ?? "The requested Credential Configuration is unknown."),
            CredentialRequestError.UnknownCredentialIdentifier =>
                CredentialError(Oid4VciCredentialErrors.UnknownCredentialIdentifier,
                    decision.ErrorDescription ?? "The requested Credential identifier is unknown."),
            CredentialRequestError.InvalidProof =>
                CredentialError(Oid4VciCredentialErrors.InvalidProof,
                    decision.ErrorDescription ?? "A key proof in the proofs parameter is missing or invalid."),
            CredentialRequestError.InvalidNonce =>
                CredentialError(Oid4VciCredentialErrors.InvalidNonce,
                    decision.ErrorDescription ?? "A key proof carries an invalid c_nonce; retrieve a fresh one."),
            CredentialRequestError.InvalidEncryptionParameters =>
                CredentialError(Oid4VciCredentialErrors.InvalidEncryptionParameters,
                    decision.ErrorDescription ?? "The Credential Response encryption parameters are invalid or missing."),
            CredentialRequestError.CredentialRequestDenied =>
                CredentialError(Oid4VciCredentialErrors.CredentialRequestDenied,
                    decision.ErrorDescription ?? "The Credential Request was not accepted."),
            _ => CredentialError(Oid4VciCredentialErrors.InvalidCredentialRequest,
                decision.ErrorDescription ?? "The Credential Request is invalid.")
        };


    /// <summary>
    /// A §8.3.1 Credential Error Response: HTTP 400 with the error JSON body and the
    /// <c>Cache-Control: no-store</c> the §8.3.1 examples carry.
    /// </summary>
    private static ServerHttpResponse CredentialError(string error, string description) =>
        ServerHttpResponse.BadRequest(error, description)
            .WithHeader(WellKnownHttpHeaderNames.CacheControl, WellKnownCacheControlValues.NoStore);


    /// <summary>
    /// Builds the OID4VCI 1.0 §12.2 Credential Issuer Metadata endpoint candidate. Stateless
    /// <c>GET</c> served from the §12.2.2 well-known location: the library derives
    /// <c>credential_issuer</c> (the resolved issuer identity the well-known URL inserts into),
    /// <c>credential_endpoint</c> (REQUIRED, read off the chain), and <c>nonce_endpoint</c>
    /// (read off the chain when present), merges the application's
    /// <see cref="AuthorizationServerIntegration.ContributeCredentialIssuerMetadataAsync"/>
    /// catalog over them, and optionally embeds <c>signed_metadata</c> from the signer seam.
    /// Mirrors <c>ProtectedResourceMetadataEndpoints</c>.
    /// </summary>
    private static EndpointCandidate BuildCredentialIssuerMetadata() =>
        new()
        {
            Name = WellKnownEndpointNames.Oid4VciCredentialIssuerMetadata,
            HttpMethod = WellKnownHttpMethods.Get,
            Capability = WellKnownCapabilityIdentifiers.Oid4VciCredentialIssuerMetadata,
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,
            //§12.2.2 well-known URL is a path INSERTION into the Credential Issuer Identifier,
            //resolved by the application's ResolveEndpointUriAsync — not an AS-metadata key.
            DiscoveryMetadataKey = null,

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
                        OAuthErrors.ServerError, "Client registration not found in context."));
                }

                EndpointChain? chain = context.EndpointChain;
                if(chain is null)
                {
                    return Respond(ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "EndpointChain not on context for Credential Issuer Metadata emission."));
                }

                //§12.2.4 credential_issuer (REQUIRED) — the resolved issuer identity, the same
                //identifier the §12.2.2 well-known URL is inserted into.
                Uri issuer;
                try
                {
                    issuer = oauth.ResolveIssuerAsync is not null
                        ? (await oauth.ResolveIssuerAsync(registration, context, ct)
                            .ConfigureAwait(false))!
                        : await DefaultIssuerResolver.ResolveAsync(registration, context, ct)
                            .ConfigureAwait(false);
                }
                catch(InvalidOperationException)
                {
                    return Respond(ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "Credential Issuer identifier not found in context."));
                }

                //§12.2.4 credential_endpoint (REQUIRED) + nonce_endpoint (OPTIONAL) — read off the
                //chain the dispatcher built, so the advertised URLs are the ones the matchers bind.
                string? credentialEndpoint = null;
                string? nonceEndpoint = null;
                string? deferredCredentialEndpoint = null;
                string? notificationEndpoint = null;
                foreach(ServerEndpoint chainEndpoint in chain)
                {
                    if(string.Equals(chainEndpoint.Name, WellKnownEndpointNames.Oid4VciCredential, StringComparison.Ordinal))
                    {
                        credentialEndpoint = chainEndpoint.ResolvedUri.ToString();
                    }
                    else if(string.Equals(chainEndpoint.Name, WellKnownEndpointNames.Oid4VciNonce, StringComparison.Ordinal))
                    {
                        nonceEndpoint = chainEndpoint.ResolvedUri.ToString();
                    }
                    else if(string.Equals(chainEndpoint.Name, WellKnownEndpointNames.Oid4VciDeferredCredential, StringComparison.Ordinal))
                    {
                        deferredCredentialEndpoint = chainEndpoint.ResolvedUri.ToString();
                    }
                    else if(string.Equals(chainEndpoint.Name, WellKnownEndpointNames.Oid4VciNotification, StringComparison.Ordinal))
                    {
                        notificationEndpoint = chainEndpoint.ResolvedUri.ToString();
                    }
                }

                if(credentialEndpoint is null)
                {
                    return Respond(ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "credential_endpoint is REQUIRED in Credential Issuer Metadata but the "
                        + "Credential Endpoint is not on the chain; wire its capability and seams."));
                }

                //Application-supplied catalog the library cannot derive; the gate guarantees the
                //seam is wired.
                CredentialIssuerMetadataContribution contribution =
                    oauth.ContributeCredentialIssuerMetadataAsync is null
                        ? CredentialIssuerMetadataContribution.Empty
                        : await oauth.ContributeCredentialIssuerMetadataAsync(
                            registration, context, ct).ConfigureAwait(false);

                //§12.2.4 inner-REQUIRED members the library understands are a LIBRARY GUARANTEE: a
                //misconfigured deployment (a configuration without format, a proof type without
                //proof_signing_alg_values_supported, batch_size below 2, an encryption object
                //missing a REQUIRED member, a malformed display entry) fails LOUD here rather than
                //serving a non-conformant document — the same fail-loud posture as a missing
                //credential_endpoint. Format-specific REQUIRED members stay with the deployment.
                string? metadataFault = CredentialIssuerMetadataValidation.Validate(contribution);
                if(metadataFault is not null)
                {
                    return Respond(ServerHttpResponse.ServerError(OAuthErrors.ServerError, metadataFault));
                }

                //§12.2.2 Accept-Language: when the Wallet indicates preferred display language(s)
                //and the contribution carries matching internationalized display data, filter the
                //human-readable display values to the best-matching language and echo it as
                //Content-Language. No header (or no match) keeps all languages — the §12.2.2
                //"ignore the Accept-Language Header and send all supported languages" option.
                string? acceptLanguage = ReadSingleHeader(
                    context, WellKnownHttpHeaderNames.AcceptLanguage);
                string? servedLanguage = CredentialIssuerMetadataLanguageNegotiation.SelectServedLanguage(
                    acceptLanguage, EnumerateDisplayArrays(contribution));
                contribution = ApplyLanguageNegotiation(contribution, servedLanguage);

                //§12.2.2 Accept: serve the WHOLE document as the signed JWS (application/jwt) when
                //the Wallet prefers it AND the signing seam is wired; otherwise the unsigned
                //application/json document (the MUST-support default). The same library-assembled
                //claim set backs both, so the signed and unsigned forms cannot diverge.
                bool prefersSignedMetadata = PrefersSignedMetadata(
                    ReadSingleHeader(context, WellKnownHttpHeaderNames.Accept));
                bool canSignMetadata = oauth.SignCredentialIssuerMetadataAsync is not null;

                string? signedMetadata = null;
                if(canSignMetadata)
                {
                    JwtPayload claims = BuildIssuerMetadataClaims(
                        issuer, credentialEndpoint, nonceEndpoint,
                        deferredCredentialEndpoint, notificationEndpoint, contribution);
                    signedMetadata = await oauth.SignCredentialIssuerMetadataAsync!(
                        claims, registration, context, ct).ConfigureAwait(false);
                }

                if(prefersSignedMetadata && !string.IsNullOrEmpty(signedMetadata))
                {
                    //§12.2.2: the signed form IS the JWT, served as application/jwt — not a JSON
                    //document carrying a signed_metadata field.
                    ServerHttpResponse signedResponse = ServerHttpResponse.Ok(
                        signedMetadata!, WellKnownMediaTypes.Application.Jwt);

                    return Respond(WithContentLanguage(signedResponse, servedLanguage));
                }

                string metadataJson = BuildIssuerMetadataJson(
                    issuer, credentialEndpoint, nonceEndpoint,
                    deferredCredentialEndpoint, notificationEndpoint, contribution, signedMetadata);

                ServerHttpResponse jsonResponse = ServerHttpResponse.Ok(
                    metadataJson, WellKnownMediaTypes.Application.Json);

                return Respond(WithContentLanguage(jsonResponse, servedLanguage));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    /// <summary>
    /// Serialises the §12.2.4 Credential Issuer Metadata document via <see cref="JsonAppender"/>
    /// (honouring the serialization firewall). Optional members with no value are omitted;
    /// <c>credential_configurations_supported</c> is REQUIRED and emitted as an empty object when
    /// the contribution leaves it unset.
    /// </summary>
    private static string BuildIssuerMetadataJson(
        Uri issuer,
        string credentialEndpoint,
        string? nonceEndpoint,
        string? deferredCredentialEndpoint,
        string? notificationEndpoint,
        CredentialIssuerMetadataContribution contribution,
        string? signedMetadata)
    {
        StringBuilder sb = JsonAppender.Rent();
        try
        {
            sb.Append('{');

            bool first = true;
            JsonAppender.AppendStringField(
                sb, CredentialIssuerMetadataParameterNames.CredentialIssuer, issuer.OriginalString, ref first);

            if(contribution.AuthorizationServers is { Count: > 0 } authorizationServers)
            {
                JsonAppender.AppendStringArrayField(
                    sb, CredentialIssuerMetadataParameterNames.AuthorizationServers, authorizationServers, ref first);
            }

            JsonAppender.AppendStringField(
                sb, CredentialIssuerMetadataParameterNames.CredentialEndpoint, credentialEndpoint, ref first);

            if(!string.IsNullOrEmpty(nonceEndpoint))
            {
                JsonAppender.AppendStringField(
                    sb, CredentialIssuerMetadataParameterNames.NonceEndpoint, nonceEndpoint, ref first);
            }

            if(!string.IsNullOrEmpty(deferredCredentialEndpoint))
            {
                JsonAppender.AppendStringField(
                    sb, CredentialIssuerMetadataParameterNames.DeferredCredentialEndpoint,
                    deferredCredentialEndpoint, ref first);
            }

            if(!string.IsNullOrEmpty(notificationEndpoint))
            {
                JsonAppender.AppendStringField(
                    sb, CredentialIssuerMetadataParameterNames.NotificationEndpoint,
                    notificationEndpoint, ref first);
            }

            //REQUIRED — emit an empty object rather than omit when the contribution is unset.
            object configurations = contribution.CredentialConfigurationsSupported
                ?? new Dictionary<string, object>(StringComparer.Ordinal);
            AppendValueField(
                sb, CredentialIssuerMetadataParameterNames.CredentialConfigurationsSupported, configurations, ref first);

            if(contribution.BatchCredentialIssuance is { Count: > 0 } batch)
            {
                AppendValueField(
                    sb, CredentialIssuerMetadataParameterNames.BatchCredentialIssuance, batch, ref first);
            }

            if(contribution.CredentialRequestEncryption is { Count: > 0 } requestEncryption)
            {
                AppendValueField(
                    sb, CredentialIssuerMetadataParameterNames.CredentialRequestEncryption,
                    requestEncryption, ref first);
            }

            if(contribution.CredentialResponseEncryption is { Count: > 0 } responseEncryption)
            {
                AppendValueField(
                    sb, CredentialIssuerMetadataParameterNames.CredentialResponseEncryption,
                    responseEncryption, ref first);
            }

            if(contribution.Display is { Count: > 0 } display)
            {
                AppendValueField(sb, CredentialIssuerMetadataParameterNames.Display, display, ref first);
            }

            if(!string.IsNullOrEmpty(signedMetadata))
            {
                JsonAppender.AppendStringField(
                    sb, CredentialIssuerMetadataParameterNames.SignedMetadata, signedMetadata, ref first);
            }

            sb.Append('}');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    /// <summary>
    /// Assembles the §12.2.3 metadata claim set handed to the application's signer — the same
    /// values the plain document carries, so the signed JWT cannot diverge. The signer adds the
    /// §12.2.3 structural claims (<c>typ</c>, <c>sub</c>, <c>iat</c>). A <c>signed_metadata</c>
    /// claim is never part of the set.
    /// </summary>
    private static JwtPayload BuildIssuerMetadataClaims(
        Uri issuer,
        string credentialEndpoint,
        string? nonceEndpoint,
        string? deferredCredentialEndpoint,
        string? notificationEndpoint,
        CredentialIssuerMetadataContribution contribution)
    {
        JwtPayload claims = new()
        {
            [CredentialIssuerMetadataParameterNames.CredentialIssuer] = issuer.OriginalString
        };

        if(contribution.AuthorizationServers is { Count: > 0 } authorizationServers)
        {
            claims[CredentialIssuerMetadataParameterNames.AuthorizationServers] = authorizationServers;
        }

        claims[CredentialIssuerMetadataParameterNames.CredentialEndpoint] = credentialEndpoint;

        if(!string.IsNullOrEmpty(nonceEndpoint))
        {
            claims[CredentialIssuerMetadataParameterNames.NonceEndpoint] = nonceEndpoint;
        }

        if(!string.IsNullOrEmpty(deferredCredentialEndpoint))
        {
            claims[CredentialIssuerMetadataParameterNames.DeferredCredentialEndpoint] = deferredCredentialEndpoint;
        }

        if(!string.IsNullOrEmpty(notificationEndpoint))
        {
            claims[CredentialIssuerMetadataParameterNames.NotificationEndpoint] = notificationEndpoint;
        }

        claims[CredentialIssuerMetadataParameterNames.CredentialConfigurationsSupported] =
            contribution.CredentialConfigurationsSupported
            ?? new Dictionary<string, object>(StringComparer.Ordinal);

        if(contribution.BatchCredentialIssuance is { Count: > 0 } batch)
        {
            claims[CredentialIssuerMetadataParameterNames.BatchCredentialIssuance] = batch;
        }

        if(contribution.CredentialRequestEncryption is { Count: > 0 } requestEncryption)
        {
            claims[CredentialIssuerMetadataParameterNames.CredentialRequestEncryption] = requestEncryption;
        }

        if(contribution.CredentialResponseEncryption is { Count: > 0 } responseEncryption)
        {
            claims[CredentialIssuerMetadataParameterNames.CredentialResponseEncryption] = responseEncryption;
        }

        if(contribution.Display is { Count: > 0 } display)
        {
            claims[CredentialIssuerMetadataParameterNames.Display] = display;
        }

        return claims;
    }


    /// <summary>
    /// Reads the single value of <paramref name="headerName"/> from the inbound request, or
    /// <see langword="null"/> when absent. A header repeated as a comma-joined single value
    /// (the common shape for <c>Accept</c> / <c>Accept-Language</c>) is read here; a truly
    /// multi-valued header is joined so the field grammar's own comma splitting still applies.
    /// </summary>
    private static string? ReadSingleHeader(ExchangeContext context, string headerName)
    {
        IncomingRequest? req = context.IncomingRequest;
        if(req is null)
        {
            return null;
        }

        if(req.Headers.TryGetSingle(headerName, out string? single))
        {
            return single;
        }

        if(req.Headers.TryGetAll(headerName, out IReadOnlyList<string>? all) && all is { Count: > 0 })
        {
            return string.Join(',', all);
        }

        return null;
    }


    /// <summary>
    /// §12.2.2: whether the <c>Accept</c> field signals a preference for the signed
    /// <c>application/jwt</c> metadata form. A field naming <c>application/jwt</c> (and not
    /// out-ranking it with a higher-weighted <c>application/json</c>) selects the signed form.
    /// </summary>
    private static bool PrefersSignedMetadata(string? accept)
    {
        if(string.IsNullOrWhiteSpace(accept))
        {
            return false;
        }

        double jwtQuality = double.NegativeInfinity;
        double jsonQuality = double.NegativeInfinity;
        foreach(string rawElement in accept.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            string[] parts = rawElement.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if(parts.Length == 0)
            {
                continue;
            }

            string mediaType = parts[0];
            double quality = ReadAcceptQuality(parts);
            if(WellKnownMediaTypes.Application.Equals(mediaType, WellKnownMediaTypes.Application.Jwt))
            {
                jwtQuality = Math.Max(jwtQuality, quality);
            }
            else if(WellKnownMediaTypes.Application.IsJson(mediaType))
            {
                jsonQuality = Math.Max(jsonQuality, quality);
            }
        }

        //application/jwt is preferred only when it is named with a positive weight and not
        //out-ranked by an equally-or-higher-weighted application/json.
        return jwtQuality > 0.0 && jwtQuality >= jsonQuality;
    }


    /// <summary>Reads the <c>q=</c> weight from an <c>Accept</c> element's parameters, defaulting to <c>1.0</c>.</summary>
    private static double ReadAcceptQuality(string[] parts)
    {
        for(int i = 1; i < parts.Length; i++)
        {
            string parameter = parts[i];
            if(!parameter.StartsWith("q=", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            return double.TryParse(
                parameter.AsSpan(2), System.Globalization.NumberStyles.Float,
                System.Globalization.CultureInfo.InvariantCulture, out double parsed)
                    ? Math.Clamp(parsed, 0.0, 1.0)
                    : 1.0;
        }

        return 1.0;
    }


    /// <summary>
    /// The §12.2.2 <c>display</c> arrays that carry internationalized values: the Credential
    /// Issuer's own <c>display</c> and each configuration's <c>credential_metadata.display</c>.
    /// These are the candidate locales the Accept-Language negotiation ranks.
    /// </summary>
    private static IEnumerable<IReadOnlyList<object>?> EnumerateDisplayArrays(
        CredentialIssuerMetadataContribution contribution)
    {
        yield return contribution.Display;

        if(contribution.CredentialConfigurationsSupported is null)
        {
            yield break;
        }

        foreach(object configurationValue in contribution.CredentialConfigurationsSupported.Values)
        {
            yield return ReadConfigurationDisplay(configurationValue);
        }
    }


    /// <summary>Reads a configuration's <c>credential_metadata.display</c> array, or <see langword="null"/> when absent.</summary>
    private static IReadOnlyList<object>? ReadConfigurationDisplay(object configurationValue)
    {
        if(configurationValue is IReadOnlyDictionary<string, object> configuration
            && configuration.TryGetValue(
                CredentialIssuerMetadataParameterNames.CredentialMetadata, out object? credentialMetadataValue)
            && credentialMetadataValue is IReadOnlyDictionary<string, object> credentialMetadata
            && credentialMetadata.TryGetValue(
                CredentialIssuerMetadataParameterNames.Display, out object? displayValue)
            && displayValue is IReadOnlyList<object> display)
        {
            return display;
        }

        return null;
    }


    /// <summary>
    /// §12.2.2: returns a contribution whose <c>display</c> arrays (issuer-level and each
    /// configuration's <c>credential_metadata.display</c>) are filtered to
    /// <paramref name="servedLanguage"/>. A <see langword="null"/> served language is the
    /// "send all supported languages" path and returns the contribution unchanged.
    /// </summary>
    private static CredentialIssuerMetadataContribution ApplyLanguageNegotiation(
        CredentialIssuerMetadataContribution contribution, string? servedLanguage)
    {
        if(servedLanguage is null)
        {
            return contribution;
        }

        IReadOnlyList<object>? filteredIssuerDisplay = contribution.Display is { Count: > 0 } issuerDisplay
            ? CredentialIssuerMetadataLanguageNegotiation.FilterDisplay(issuerDisplay, servedLanguage)
            : contribution.Display;

        IReadOnlyDictionary<string, object>? filteredConfigurations =
            FilterConfigurationsDisplay(contribution.CredentialConfigurationsSupported, servedLanguage);

        return contribution with
        {
            Display = filteredIssuerDisplay,
            CredentialConfigurationsSupported = filteredConfigurations
        };
    }


    /// <summary>
    /// Rebuilds <paramref name="configurations"/> with each configuration's
    /// <c>credential_metadata.display</c> filtered to <paramref name="servedLanguage"/>, leaving
    /// every other member untouched.
    /// </summary>
    private static Dictionary<string, object>? FilterConfigurationsDisplay(
        IReadOnlyDictionary<string, object>? configurations, string servedLanguage)
    {
        if(configurations is null)
        {
            return null;
        }

        Dictionary<string, object> filtered = new(configurations.Count, StringComparer.Ordinal);
        foreach(KeyValuePair<string, object> entry in configurations)
        {
            filtered[entry.Key] = FilterConfigurationDisplay(entry.Value, servedLanguage);
        }

        return filtered;
    }


    /// <summary>
    /// Returns a configuration value with its <c>credential_metadata.display</c> filtered to
    /// <paramref name="servedLanguage"/>, or the value unchanged when it carries no such array.
    /// </summary>
    private static object FilterConfigurationDisplay(object configurationValue, string servedLanguage)
    {
        if(configurationValue is not IReadOnlyDictionary<string, object> configuration
            || !configuration.TryGetValue(
                CredentialIssuerMetadataParameterNames.CredentialMetadata, out object? credentialMetadataValue)
            || credentialMetadataValue is not IReadOnlyDictionary<string, object> credentialMetadata
            || !credentialMetadata.TryGetValue(
                CredentialIssuerMetadataParameterNames.Display, out object? displayValue)
            || displayValue is not IReadOnlyList<object> display)
        {
            return configurationValue;
        }

        IReadOnlyList<object> filteredDisplay =
            CredentialIssuerMetadataLanguageNegotiation.FilterDisplay(display, servedLanguage);

        Dictionary<string, object> filteredCredentialMetadata =
            new(credentialMetadata, StringComparer.Ordinal)
            {
                [CredentialIssuerMetadataParameterNames.Display] = filteredDisplay
            };

        return new Dictionary<string, object>(configuration, StringComparer.Ordinal)
        {
            [CredentialIssuerMetadataParameterNames.CredentialMetadata] = filteredCredentialMetadata
        };
    }


    /// <summary>
    /// §12.2.2: sets the <c>Content-Language</c> response header to the negotiated
    /// <paramref name="servedLanguage"/> when one was chosen, leaving the response unchanged when
    /// all languages are served.
    /// </summary>
    private static ServerHttpResponse WithContentLanguage(ServerHttpResponse response, string? servedLanguage)
    {
        if(servedLanguage is null)
        {
            return response;
        }

        return response.WithHeader(WellKnownHttpHeaderNames.ContentLanguage, servedLanguage);
    }


    /// <summary>
    /// Appends a <c>"key":&lt;value&gt;</c> field whose value is a structured object tree
    /// (dictionary or list), dispatched through <see cref="JsonAppender.AppendValue"/>.
    /// </summary>
    private static void AppendValueField(StringBuilder sb, string key, object value, ref bool first)
    {
        if(!first)
        {
            sb.Append(',');
        }

        first = false;
        sb.Append('"');
        JsonAppender.AppendEscapedString(sb, key);
        sb.Append("\":");
        JsonAppender.AppendValue(sb, value);
    }
}
