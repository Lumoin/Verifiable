using System.Collections.Immutable;
using System.Diagnostics;
using Verifiable.Core.Dcql;
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
using Verifiable.OAuth.Server.Routing;
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
/// <see cref="RequestContext"/> via
/// <see cref="Oid4VpRequestContextExtensions.SetParHandle"/>, and asks the
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
/// Register at startup via <see cref="AuthorizationServer.EndpointBuilders"/>:
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
    /// <see cref="AuthorizationServer.EndpointBuilders"/>.
    /// </summary>
    public static readonly EndpointBuilderDelegate Builder = static (registration, context, ct) =>
    {
        if(!registration.IsCapabilityAllowed(ServerCapabilityName.VerifiablePresentation))
        {
            return ValueTask.FromResult<IReadOnlyList<EndpointCandidate>>([]);
        }

        return ValueTask.FromResult<IReadOnlyList<EndpointCandidate>>(
        [
            BuildOid4VpPar(),
            BuildOid4VpJarRequest(),
            BuildOid4VpDirectPost()
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
            Capability = ServerCapabilityName.VerifiablePresentation,
            StartsNewFlow = true,
            Kind = FlowKind.Oid4VpVerifierServer,
            //DiscoveryMetadataKey null per v2 MD Step 12 table — OID4VP
            //endpoints aren't advertised in the OAuth discovery document.

            //Stub matcher — real port lands in chunk 7. The original
            //acceptance test was context-state-driven (TransactionNonce,
            //PreparedQuery, DecryptionKeyId presence) and survives the
            //port intact.
            MatchesRequest = static (fields, context, endpoint, ct) =>
                ValueTask.FromResult<MatchPayload?>(null),

            BuildInputAsync = async (fields, context, currentState, ct) =>
            {
                AuthorizationServer server = context.Server!;

                ClientRecord? registration = context.Registration;
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
                string parHandle = Guid.NewGuid().ToString("N");

                //Place the token on context so the application's ResolveEndpointUriAsync
                //delegate can read it when composing the URL.
                context.SetParHandle(parHandle);

                //Ask the application to compose the absolute request_uri URL using the
                //deployment's routing scheme. The library does not compose URLs.
                if(server.Integration.ResolveEndpointUriAsync is null)
                {
                    return (null,
                        ServerHttpResponse.ServerError(
                            OAuthErrors.ServerError,
                            "Integration.ResolveEndpointUriAsync delegate is not configured. " +
                            "The OID4VP PAR endpoint requires it to compose the request_uri URL."));
                }

                Uri? requestUri = await server.Integration.ResolveEndpointUriAsync(
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
                int expiresIn = (int)server.Timings.Oid4VpRequestUriLifetime.TotalSeconds;

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

                return ((OAuthFlowInput?)new ServerParReceived(
                    FlowId: flowId,
                    ParHandle: parHandle,
                    Par: new ParResponse(requestUri, expiresIn),
                    Nonce: nonce,
                    Query: preparedQuery,
                    DecryptionKeyId: decryptionKeyId.Value,
                    SigningKeyId: signingKeyId,
                    AllowedEncAlgorithms: allowedEncAlgorithms,
                    ReceivedAt: now), null);
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

                return ServerHttpResponse.Ok(body, WellKnownMediaTypes.Application.Json);
            }
        };


    private static EndpointCandidate BuildOid4VpJarRequest() =>
        new()
        {
            Name = WellKnownEndpointNames.Oid4VpJarRequest,
            HttpMethod = WellKnownHttpMethods.Get,
            Capability = ServerCapabilityName.VerifiablePresentation,
            StartsNewFlow = false,
            Kind = FlowKind.Oid4VpVerifierServer,
            //DiscoveryMetadataKey null per v2 MD Step 12 table.

            //Stub matcher — real port lands in chunk 7.
            MatchesRequest = static (fields, context, endpoint, ct) =>
                ValueTask.FromResult<MatchPayload?>(null),

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                AuthorizationServer server = context.Server!;

                if(currentState is not VerifierParReceivedState parReceived)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        "Flow not in expected state for JAR request."));
                }

                if(server.ActionExecutor is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, "Action executor not configured."));
                }

                OAuthFlowInput signed = await server.ActionExecutor.ExecuteAsync(
                    new SignJarAction(
                        parReceived.ParHandle,
                        parReceived.Nonce,
                        parReceived.Query,
                        parReceived.SigningKeyId),
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
            Capability = ServerCapabilityName.VerifiablePresentation,
            StartsNewFlow = false,
            Kind = FlowKind.Oid4VpVerifierServer,
            //DiscoveryMetadataKey null per v2 MD Step 12 table.

            //Stub matcher — real port lands in chunk 7.
            MatchesRequest = static (fields, context, endpoint, ct) =>
                ValueTask.FromResult<MatchPayload?>(null),

            //The Wallet echoes the JAR's state claim as the state form field per
            //OID4VP 1.0 §6.1 and RFC 6749 §4.1.1. The state value equals the
            //per-flow request_uri token; the application's ResolveCorrelationKeyAsync
            //maps it back to the internal flow identifier.
            ExtractCorrelationKey = static (path, fields, context) =>
                fields.TryGetValue(OAuthRequestParameterNames.State, out string? state)
                    && !string.IsNullOrWhiteSpace(state) ? state : null,

            BuildInputAsync = static (fields, context, currentState, ct) =>
            {
                AuthorizationServer server = context.Server!;

                if(currentState is not VerifierJarServedState)
                {
                    return ValueTask.FromResult<(OAuthFlowInput?, ServerHttpResponse?)>((null,
                        ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidRequest,
                            "Flow not in expected state for direct_post.")));
                }

                if(!fields.TryGetValue(OAuthRequestParameterNames.Response,
                    out string? compactJwe)
                    || string.IsNullOrWhiteSpace(compactJwe))
                {
                    return ValueTask.FromResult<(OAuthFlowInput?, ServerHttpResponse?)>((null,
                        ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidRequest, "Missing response parameter.")));
                }

                return ValueTask.FromResult<(OAuthFlowInput?, ServerHttpResponse?)>(
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
}
