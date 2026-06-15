using System.Collections.Immutable;
using System.Diagnostics;
using Verifiable.Core;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oid4Vp.Server;
using Verifiable.OAuth.Oid4Vp.Server.States;
using Verifiable.OAuth.Oid4Vp.States;

using Verifiable.OAuth.Server;

using Verifiable.OAuth.Server.Audit;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.Server;
namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Endpoint builder module for the OID4VP Verifiable Presentation flow.
/// </summary>
/// <remarks>
/// <para>
/// Produces PAR (flow creation), JAR-fetch (on-demand signing), and direct_post
/// (encrypted VP response) endpoints per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OID4VP 1.0</see>
/// and
/// <see href="https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html">HAIP 1.0</see>.
/// </para>
/// <para>
/// The library does not compose URLs. The PAR endpoint generates a fresh
/// per-flow opaque token, places it on
/// <see cref="ExchangeContext"/> via
/// <see cref="Oid4VpServerExchangeContextExtensions.SetParHandle"/>, and asks the
/// application's
/// <see cref="AuthorizationServerIntegration.ResolveEndpointUriAsync"/> delegate
/// to compose the absolute <c>request_uri</c> URL using key
/// <see cref="Oid4VpEndpointKeys.RequestUri"/>. The internal flow identifier
/// minted by the dispatcher never crosses a process boundary; the application's
/// <see cref="AuthorizationServerIntegration.ResolveCorrelationKeyAsync"/> maps
/// the inbound token back to the flow identifier on the JAR-fetch and direct_post
/// endpoints.
/// </para>
/// <para>
/// Register at startup via <see cref="EndpointServer.EndpointBuilders"/>:
/// </para>
/// <code>
/// server.EndpointBuilders.AddRange([
///     Oid4VpEndpoints.Builder,
///     MetadataEndpoints.Builder
/// ]);
/// </code>
/// <para>
/// <strong>JSON wire format and the serialization firewall.</strong> The
/// JSON response bodies this module emits — the PAR response and the
/// direct_post response — are written by hand using
/// <see cref="System.Text.StringBuilder"/> rather than through a serializer.
/// This is deliberate. <c>Verifiable.OAuth</c> takes no dependency on
/// <c>Verifiable.Json</c>, on <c>System.Text.Json</c>, or on any other JSON
/// library, and the project's banned-symbol analyzer enforces this. The
/// library does not impose a JSON implementation on the application.
/// </para>
/// <para>
/// The wire shapes here are RFC-defined and stable: a handful of well-known
/// field names per
/// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.2">RFC 9126 §2.2</see>
/// for the PAR response and
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.2">OID4VP 1.0 §8.2</see>
/// for the direct_post response, all primitive values (strings), no nested
/// or schema-variable structure. For shapes like that, manual
/// <see cref="System.Text.StringBuilder"/> construction is the simplest
/// path that respects the firewall and stays AOT-safe without
/// source-generator context maintenance.
/// </para>
/// <para>
/// The JAR-fetch endpoint emits a compact JWS string (
/// <see cref="WellKnownMediaTypes.Application.OauthAuthzReqJwt"/>) which is
/// already serialized by the signing pipeline; nothing in this module
/// constructs JSON from a JCose payload directly. The corresponding parsing
/// direction lives behind delegate slots so the application chooses the
/// parser; default implementations live in <c>Verifiable.Json</c> and a
/// CBOR-speaking or otherwise custom deployment supplies its own.
/// </para>
/// </remarks>
[DebuggerDisplay("Oid4VpEndpoints")]
public static class Oid4VpEndpoints
{
    //HTTP method names are compile-time string literals scoped to this file.
    //Per CA1802, declared const so the value is computed at compile time.
    //The library's cross-assembly well-known string values use static readonly
    //elsewhere; the distinction is whether the value benefits from data-block
    //sharing across the assembly boundary, which these internal route markers
    //do not.


    /// <summary>
    /// The endpoint builder delegate. Pass this to
    /// <see cref="EndpointServer.EndpointBuilders"/>.
    /// </summary>
    public static readonly EndpointBuilderDelegate Builder = static (registration, context, ct) =>
    {
        if(!((ClientRecord)registration).IsCapabilityAllowed(WellKnownCapabilityIdentifiers.VcVerifiablePresentation))
        {
            return ValueTask.FromResult<IReadOnlyList<EndpointCandidate>>([]);
        }

        return ValueTask.FromResult<IReadOnlyList<EndpointCandidate>>(
        [
            BuildOid4VpPar(),
            BuildOid4VpJarRequest(),
            BuildOid4VpDirectPost(),
            BuildOid4VpDirectPostUnencrypted()
        ]);
    };


    /// <summary>
    /// Builds the OID4VP PAR endpoint per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.2">OID4VP 1.0 §5.2</see>
    /// and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126">RFC 9126</see>.
    /// </summary>
    /// <remarks>
    /// <see cref="ServerEndpoint.BuildResponse"/> writes the response body —
    /// <c>request_uri</c> and <c>expires_in</c> — directly with
    /// <see cref="System.Text.StringBuilder"/>. See the serialization-firewall
    /// paragraph in the remarks on <see cref="Oid4VpEndpoints"/> for the
    /// rationale.
    /// </remarks>
    private static EndpointCandidate BuildOid4VpPar() =>
        new()
        {
            Name = WellKnownEndpointNames.Oid4VpPar,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownCapabilityIdentifiers.VcVerifiablePresentation,
            StartsNewFlow = true,
            Kind = FlowKind.Oid4VpVerifierServer,
            //DiscoveryMetadataKey null per v2 MD Step 12 table — OID4VP
            //endpoints aren't advertised in the OAuth discovery document.

            //Acceptance test: context-state driven (TransactionNonce +
            //PreparedQuery + DecryptionKeyId). This endpoint is invoked
            //internally by the verifier application, not from a wire HTTP
            //request, so it does not path-match against ResolvedUri.
            //Disjointness vs the wire-driven AuthCode PAR matcher is enforced
            //by inverse signals (AuthCode PAR requires CodeChallenge in the
            //body and TransactionNonce absent from context).
            MatchesRequest = static (fields, context, endpoint, ct) =>
            {
                if(context.TransactionNonce is null) { return ValueTask.FromResult<MatchPayload?>(null); }
                if(context.PreparedQuery is null) { return ValueTask.FromResult<MatchPayload?>(null); }
                if(context.DecryptionKeyId is null) { return ValueTask.FromResult<MatchPayload?>(null); }
                return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
            },

            BuildInputAsync = async (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.Server!;
                var oauth = server.OAuth();

                ClientRecord? registration = context.ClientRegistration;
                if(registration is null)
                {
                    return (null,
                        ServerHttpResponse.ServerError(
                            OAuthErrors.ServerError,
                            "Client registration not found in context."));
                }

                PreparedDcqlQuery? preparedQuery = context.PreparedQuery;
                if(preparedQuery is null)
                {
                    return (null,
                        ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidRequest, "Missing DCQL query in context."));
                }

                TransactionNonce? nonce = context.TransactionNonce;
                if(nonce is null)
                {
                    return (null,
                        ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidRequest, "Missing transaction nonce in context."));
                }

                KeyId? decryptionKeyId = context.DecryptionKeyId;
                if(decryptionKeyId is null)
                {
                    return (null,
                        ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidRequest,
                            "Missing decryption key identifier in context."));
                }

                //The dispatcher generated and placed flowId on context for new flows.
                //Read it; do not generate it here.
                string flowId = context.FlowId
                    ?? throw new InvalidOperationException(
                        "FlowId not on context. The dispatcher must place it before " +
                        "invoking BuildInputAsync on a StartsNewFlow endpoint.");

                //Generate the external opaque token. Distinct random value from flowId
                //per the architecture rule "flowId never leaves the server process."
                string parHandle = await oauth.GenerateIdentifierAsync!(
                    WellKnownIdentifierPurposes.Oid4VpParHandle, context, ct)
                    .ConfigureAwait(false);

                //Place the token on context so the application's ResolveEndpointUriAsync
                //delegate can read it when composing the URL.
                context.SetParHandle(parHandle);

                //Ask the application to compose the absolute request_uri URL using the
                //deployment's routing scheme. The library does not compose URLs.
                if(oauth.ResolveEndpointUriAsync is null)
                {
                    return (null,
                        ServerHttpResponse.ServerError(
                            OAuthErrors.ServerError,
                            "Integration.ResolveEndpointUriAsync delegate is not configured. " +
                            "The OID4VP PAR endpoint requires it to compose the request_uri URL."));
                }

                Uri? requestUri = await oauth.ResolveEndpointUriAsync(
                    Oid4VpEndpointKeys.RequestUri,
                    registration,
                    context,
                    ct).ConfigureAwait(false);

                if(requestUri is null)
                {
                    return (null,
                        ServerHttpResponse.ServerError(
                            OAuthErrors.ServerError,
                            $"Application did not produce a URL for endpoint key " +
                            $"'{Oid4VpEndpointKeys.RequestUri}'."));
                }

                //Output: place the composed URL on context so the application can read it
                //after dispatch returns to encode the URL into a QR code or deep link.
                context.SetGeneratedRequestUri(requestUri);

                //Pull the request_uri lifetime from policy per RFC 9126 §2.2.
                int expiresIn = (int)oauth.Timings.Oid4VpRequestUriLifetime.TotalSeconds;

                DateTimeOffset now = server.TimeProvider.GetUtcNow();

                IReadOnlyList<string> allowedEncAlgorithms =
                    registration.ClientMetadata?.EncryptedResponseEncValuesSupported
                    ?? ImmutableArray.Create(
                        WellKnownJweEncryptionAlgorithms.A128Gcm,
                        WellKnownJweEncryptionAlgorithms.A256Gcm);

                KeyId signingKeyId = await SigningKeySelection.ResolveSigningKeyIdAsync(
                    server,
                    registration,
                    KeyUsageContext.JarSigning,
                    context,
                    ct).ConfigureAwait(false);

                return ((FlowInput?)new ServerParReceived(
                    FlowId: flowId,
                    ParHandle: parHandle,
                    Par: new ParResponse(requestUri, expiresIn),
                    Nonce: nonce,
                    Query: preparedQuery,
                    DecryptionKeyId: decryptionKeyId.Value,
                    SigningKeyId: signingKeyId,
                    AllowedEncAlgorithms: allowedEncAlgorithms,
                    ReceivedAt: now,
                    TransactionData: context.TransactionData,
                    JarAdditionalHeaderClaims: context.JarAdditionalHeaderClaims,
                    ResponseMode: context.Oid4VpResponseMode), null);
            },

            BuildResponse = static (state, _, _) =>
            {
                if(state is not VerifierParReceivedState par)
                {
                    return ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        $"Unexpected state after OID4VP PAR: {state.GetType().Name}.");
                }

                string body =
                    $"{{\"request_uri\":\"{par.Par.RequestUri}\"," +
                    $"\"expires_in\":{par.Par.ExpiresIn}}}";

                //RFC 9126 §2.2: a successful PAR response MUST use HTTP 201 Created.
                return ServerHttpResponse.Created(body, WellKnownMediaTypes.Application.Json);
            }
        };


    private static EndpointCandidate BuildOid4VpJarRequest() =>
        new()
        {
            Name = WellKnownEndpointNames.Oid4VpJarRequest,
            HttpMethod = WellKnownHttpMethods.Get,
            Capability = WellKnownCapabilityIdentifiers.VcVerifiablePresentation,
            StartsNewFlow = false,
            Kind = FlowKind.Oid4VpVerifierServer,
            //DiscoveryMetadataKey null per v2 MD Step 12 table.

            //Acceptance test: GET or POST to the JAR fetch URL with the
            //application's CorrelationKey populated on context. The skin
            //extracts the {flowId} path segment into CorrelationKey before
            //dispatch since the JAR-URL mount point is not fixed across
            //deployments. GET corresponds to the request_uri_method=get
            //default (OID4VP 1.0 §5.10); POST corresponds to
            //request_uri_method=post with wallet_nonce in the form body.
            MatchesRequest = static (fields, context, endpoint, ct) =>
            {
                IncomingRequest? req = context.IncomingRequest;
                if(req is null) { return ValueTask.FromResult<MatchPayload?>(null); }
                if(!WellKnownHttpMethods.IsGet(req.Method)
                    && !WellKnownHttpMethods.IsPost(req.Method))
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

                if(currentState is not VerifierParReceivedState parReceived)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        "Flow not in expected state for JAR request."));
                }

                if(oauth.ActionExecutor is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, "Action executor not configured."));
                }

                //POST path — request_uri_method=post per OID4VP 1.0 §5.10.
                //The Wallet's wallet_nonce drives the PDA into
                //VerifierWalletPostReceivedState whose NextAction is the
                //wallet_nonce-bearing SignJarAction; the effect loop then
                //runs it and steps PDA into VerifierJarServedState.
                IncomingRequest? req = context.IncomingRequest;
                if(req is not null && WellKnownHttpMethods.IsPost(req.Method))
                {
                    if(!fields.TryGetValue(
                            Oid4VpAuthorizationRequestParameterNames.WalletNonce,
                            out string? walletNonce)
                        || string.IsNullOrWhiteSpace(walletNonce))
                    {
                        return (null, ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidRequest,
                            "POST to request_uri must carry the wallet_nonce form parameter " +
                            "per OID4VP 1.0 §5.10."));
                    }

                    string? walletMetadataJson = null;
                    if(fields.TryGetValue(
                            Oid4VpAuthorizationRequestParameterNames.WalletMetadata,
                            out string? maybeMetadata)
                        && !string.IsNullOrWhiteSpace(maybeMetadata))
                    {
                        walletMetadataJson = maybeMetadata;
                    }

                    //Strict wallet_metadata validation: when the Wallet POSTs
                    //metadata it is the Wallet's Authorization Server metadata
                    //(OID4VP 1.0 §10, layered on RFC 8414) and must be a complete
                    //document. Rejecting an incomplete one here (rather than
                    //ignoring the absent members) is what makes a conformant
                    //counterparty's behaviour reproducible in-house instead of
                    //only surfacing against an external verifier.
                    string? walletMetadataDefect =
                        WalletMetadataReader.DescribeWalletPostDefect(walletMetadataJson);
                    if(walletMetadataDefect is not null)
                    {
                        return (null, ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidRequest,
                            $"POST to request_uri carried incompatible wallet metadata: " +
                            $"{walletMetadataDefect}. wallet_metadata is the Wallet's Authorization " +
                            "Server metadata (OID4VP 1.0 §10) and must be a complete document."));
                    }

                    DateTimeOffset postNow = server.TimeProvider.GetUtcNow();

                    return ((FlowInput?)new ServerWalletPostReceived(
                        walletNonce,
                        walletMetadataJson,
                        postNow), null);
                }

                //OID4VP 1.0 §5.9.3 redirect_uri prefix: the Authorization
                //Request MUST NOT be signed. Emit an unsigned compact JAR
                //(alg=none) directly and early-exit without advancing the
                //PDA — the wallet's response POST triggers the existing
                //VerifierParReceivedState + ResponsePosted transition.
                TenantId? tenantId = context.TenantId;
                if(tenantId.HasValue
                    && oauth.LoadClientRegistrationAsync is { } loadAsync
                    && oauth.Codecs.DcqlQuerySerializer is { } dcqlSerializer
                    && oauth.Codecs.ClientMetadataSerializer is { } clientMetadataSerializer
                    && oauth.Codecs.JwtHeaderSerializer is { } headerSerializer
                    && oauth.Codecs.JwtPayloadSerializer is { } payloadSerializer)
                {
                    ClientRecord? registration = (ClientRecord?)await loadAsync(
                        tenantId.Value, context, ct).ConfigureAwait(false);

                    if(registration is not null
                        && WellKnownClientIdPrefixes.IsRedirectUri(registration.ClientId))
                    {
                        string unsignedJar = await BuildUnsignedJarForRedirectUriPrefixAsync(
                            parReceived,
                            registration,
                            server,
                            headerSerializer,
                            payloadSerializer,
                            dcqlSerializer,
                            clientMetadataSerializer,
                            ct).ConfigureAwait(false);

                        return (null, ServerHttpResponse.Ok(
                            unsignedJar, WellKnownMediaTypes.Application.OauthAuthzReqJwt));
                    }
                }

                //GET path — request_uri_method=get default. SignJarAction is
                //invoked inline rather than via effect chain because
                //VerifierParReceivedState carries no wallet_nonce; the
                //transition is straight to VerifierJarServedState. transaction_data
                //is threaded from the PAR state so the JAR carries the
                //descriptors and the response-verification step can recompute
                //expected hashes.
                FlowInput signed = await oauth.ActionExecutor.ExecuteAsync(
                    new SignJarAction(
                        parReceived.ParHandle,
                        parReceived.Nonce,
                        parReceived.Query,
                        parReceived.SigningKeyId,
                        WalletNonce: null,
                        TransactionData: parReceived.TransactionData,
                        AdditionalHeaderClaims: parReceived.JarAdditionalHeaderClaims,
                        ResponseMode: parReceived.ResponseMode),
                    context,
                    ct).ConfigureAwait(false);

                return (signed, null);
            },

            BuildResponse = static (state, _, _) =>
            {
                if(state is not VerifierJarServedState)
                {
                    return ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        $"Unexpected state after JAR request: {state.GetType().Name}.");
                }

                return ServerHttpResponse.Ok(
                    string.Empty, WellKnownMediaTypes.Application.OauthAuthzReqJwt);
            }
        };


    //Composes the unsigned compact JAR for the OID4VP 1.0 §5.9.3
    //redirect_uri client identifier prefix path. The verifier emits the
    //request inline-equivalent over the request_uri channel — no signing
    //key is involved; the wallet validates the prefix value matches
    //response_uri.
    private static async ValueTask<string> BuildUnsignedJarForRedirectUriPrefixAsync(
        VerifierParReceivedState parReceived,
        ClientRecord registration,
        EndpointServer server,
        JwtHeaderSerializer headerSerializer,
        JwtPayloadSerializer payloadSerializer,
        JarClaimSerializer<DcqlQuery> dcqlQuerySerializer,
        JarClaimSerializer<VerifierClientMetadata> clientMetadataSerializer,
        CancellationToken cancellationToken)
    {
        var oauth = server.OAuth();
        if(registration.ResponseUri is null)
        {
            throw new InvalidOperationException(
                $"ClientRecord for tenant '{registration.TenantId.Value}' " +
                "has no ResponseUri — required for the redirect_uri prefix path.");
        }

        if(registration.ClientMetadata is null)
        {
            throw new InvalidOperationException(
                $"ClientRecord for tenant '{registration.TenantId.Value}' " +
                "has no ClientMetadata.");
        }

        DateTimeOffset now = server.TimeProvider.GetUtcNow();
        TimeSpan lifetime = oauth.Timings.Oid4VpRequestObjectLifetime;

        return await HaipProfile.BuildUnsignedJarAsync(
            now: now,
            requestObjectLifetime: lifetime,
            state: parReceived.ParHandle,
            nonce: parReceived.Nonce,
            dcqlQuery: parReceived.Query,
            clientId: registration.ClientId,
            responseUri: registration.ResponseUri,
            clientMetadata: registration.ClientMetadata,
            headerSerializer: headerSerializer,
            payloadSerializer: payloadSerializer,
            dcqlQuerySerializer: dcqlQuerySerializer,
            clientMetadataSerializer: clientMetadataSerializer,
            encoder: oauth.Codecs.Encoder!,
            transactionData: parReceived.TransactionData,
            walletNonce: null,
            additionalHeaderClaims: parReceived.JarAdditionalHeaderClaims,
            responseMode: parReceived.ResponseMode,
            cancellationToken: cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Builds the OID4VP direct_post endpoint per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.2">OID4VP 1.0 §8.2</see>.
    /// </summary>
    /// <remarks>
    /// <see cref="ServerEndpoint.BuildResponse"/> writes the response body —
    /// <c>redirect_uri</c> for same-device flows or an empty object for
    /// cross-device flows — directly with
    /// <see cref="System.Text.StringBuilder"/>. See the serialization-firewall
    /// paragraph in the remarks on <see cref="Oid4VpEndpoints"/> for the
    /// rationale.
    /// </remarks>
    private static EndpointCandidate BuildOid4VpDirectPost() =>
        new()
        {
            Name = WellKnownEndpointNames.Oid4VpDirectPost,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownCapabilityIdentifiers.VcVerifiablePresentation,
            StartsNewFlow = false,
            Kind = FlowKind.Oid4VpVerifierServer,
            //DiscoveryMetadataKey null per v2 MD Step 12 table.

            //Acceptance test: POST to /cb for this registration with response
            //(encrypted JWE per HAIP) and state (the request_uri token echo
            //per OID4VP §6.1) both present in the body.
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
                if(!fields.ContainsKey(OAuthRequestParameterNames.Response))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                if(!fields.ContainsKey(OAuthRequestParameterNames.State))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
            },

            //The Wallet echoes the JAR's state claim as the state form field per
            //OID4VP 1.0 §6.1 and RFC 6749 §4.1.1. The state value equals the
            //per-flow request_uri token; the application's ResolveCorrelationKeyAsync
            //maps it back to the internal flow identifier.
            ExtractCorrelationKey = static (path, fields, context) =>
                fields.TryGetValue(OAuthRequestParameterNames.State, out string? state)
                    && !string.IsNullOrWhiteSpace(state) ? state : null,

            BuildInputAsync = static (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.Server!;
                var oauth = server.OAuth();

                //VerifierJarServedState is the JAR-served path; VerifierParReceivedState
                //is the inline (no-JAR) path for the redirect_uri prefix per
                //OID4VP 1.0 §5.9.3, where the verifier never serves a JAR.
                if(currentState is not VerifierJarServedState
                    and not VerifierParReceivedState)
                {
                    return ValueTask.FromResult<(FlowInput?, ServerHttpResponse?)>((null,
                        ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidRequest,
                            "Flow not in expected state for direct_post.")));
                }

                if(!fields.TryGetValue(OAuthRequestParameterNames.Response,
                    out string? compactJwe)
                    || string.IsNullOrWhiteSpace(compactJwe))
                {
                    return ValueTask.FromResult<(FlowInput?, ServerHttpResponse?)>((null,
                        ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidRequest, "Missing response parameter.")));
                }

                return ValueTask.FromResult<(FlowInput?, ServerHttpResponse?)>(
                    (new ResponsePosted(compactJwe, server.TimeProvider.GetUtcNow()), null));
            },

            BuildResponse = static (state, _, _) =>
            {
                if(state is not PresentationVerifiedState verified)
                {
                    return ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        $"Unexpected state after direct_post: {state.GetType().Name}.");
                }

                string body = verified.RedirectUri is not null
                    ? $"{{\"redirect_uri\":\"{verified.RedirectUri}\"}}"
                    : "{}";

                return ServerHttpResponse.Ok(body, WellKnownMediaTypes.Application.Json);
            }
        };


    /// <summary>
    /// Builds the OID4VP unencrypted <c>direct_post</c> endpoint per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.2">OID4VP 1.0 §8.2</see>.
    /// Shares the path and HTTP method with <see cref="BuildOid4VpDirectPost"/>;
    /// the matcher distinguishes the unencrypted shape by the presence of
    /// the <c>vp_token</c> form field instead of <c>response</c>. Used when
    /// the Verifier advertised <c>response_mode=direct_post</c> rather than
    /// <c>direct_post.jwt</c>.
    /// </summary>
    /// <remarks>
    /// HAIP 1.0 §5.1 mandates encrypted responses; this endpoint is for
    /// non-HAIP profiles or deployments that explicitly opt into plaintext
    /// responses. Capability-gated like the encrypted sibling — only
    /// registrations with
    /// <see cref="WellKnownCapabilityIdentifiers.VcVerifiablePresentation"/>
    /// expose it.
    /// </remarks>
    private static EndpointCandidate BuildOid4VpDirectPostUnencrypted() =>
        new()
        {
            Name = WellKnownEndpointNames.Oid4VpDirectPost,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownCapabilityIdentifiers.VcVerifiablePresentation,
            StartsNewFlow = false,
            Kind = FlowKind.Oid4VpVerifierServer,

            //Same path + method as the encrypted sibling; the distinguishing
            //field is vp_token (plaintext JSON) instead of response (JWE).
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
                if(!fields.ContainsKey(AuthorizationResponseParameters.VpToken))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                if(!fields.ContainsKey(OAuthRequestParameterNames.State))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
            },

            //State carries the per-flow request_uri token in the same form
            //field as the encrypted path.
            ExtractCorrelationKey = static (path, fields, context) =>
                fields.TryGetValue(OAuthRequestParameterNames.State, out string? state)
                    && !string.IsNullOrWhiteSpace(state) ? state : null,

            BuildInputAsync = static (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.Server!;
                var oauth = server.OAuth();

                //VerifierJarServedState is the JAR-served path; VerifierParReceivedState
                //is the inline (no-JAR) path for the redirect_uri prefix per
                //OID4VP 1.0 §5.9.3, where the verifier never serves a JAR.
                if(currentState is not VerifierJarServedState
                    and not VerifierParReceivedState)
                {
                    return ValueTask.FromResult<(FlowInput?, ServerHttpResponse?)>((null,
                        ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidRequest,
                            "Flow not in expected state for direct_post.")));
                }

                if(!fields.TryGetValue(AuthorizationResponseParameters.VpToken,
                        out string? vpTokenJson)
                    || string.IsNullOrWhiteSpace(vpTokenJson))
                {
                    return ValueTask.FromResult<(FlowInput?, ServerHttpResponse?)>((null,
                        ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidRequest, "Missing vp_token parameter.")));
                }

                return ValueTask.FromResult<(FlowInput?, ServerHttpResponse?)>(
                    (new ResponsePostedUnencrypted(vpTokenJson, server.TimeProvider.GetUtcNow()), null));
            },

            BuildResponse = static (state, _, _) =>
            {
                if(state is not PresentationVerifiedState verified)
                {
                    return ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        $"Unexpected state after direct_post: {state.GetType().Name}.");
                }

                string body = verified.RedirectUri is not null
                    ? $"{{\"redirect_uri\":\"{verified.RedirectUri}\"}}"
                    : "{}";

                return ServerHttpResponse.Ok(body, WellKnownMediaTypes.Application.Json);
            }
        };
}
