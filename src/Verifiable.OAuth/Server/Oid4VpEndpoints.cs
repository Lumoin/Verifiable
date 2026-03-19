using System.Collections.Immutable;
using System.Diagnostics;
using Verifiable.Core.Dcql;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oid4Vp.Server;
using Verifiable.OAuth.Oid4Vp.Server.States;
using Verifiable.OAuth.Oid4Vp.States;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Endpoint builder module for the OID4VP Verifiable Presentation flow.
/// </summary>
/// <remarks>
/// <para>
/// Produces PAR (flow creation), JAR request (on-demand signing), and
/// direct_post (encrypted VP response) endpoints per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OID4VP 1.0</see>
/// and
/// <see href="https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html">HAIP 1.0</see>.
/// </para>
/// <para>
/// Register at startup via <see cref="AuthorizationServerOptions.EndpointBuilders"/>:
/// </para>
/// <code>
/// options.EndpointBuilders =
/// [
///     Oid4VpEndpoints.Builder,
///     MetadataEndpoints.Builder
/// ];
/// </code>
/// </remarks>
[DebuggerDisplay("Oid4VpEndpoints")]
public static class Oid4VpEndpoints
{
    private const string Get = "GET";
    private const string Post = "POST";


    /// <summary>
    /// The endpoint builder delegate. Pass this to
    /// <see cref="AuthorizationServerOptions.EndpointBuilders"/>.
    /// </summary>
    public static readonly EndpointBuilderDelegate Builder = static (registration, options) =>
    {
        if(!registration.IsCapabilityAllowed(ServerCapabilityName.VerifiablePresentation))
        {
            return [];
        }

        return
        [
            BuildOid4VpPar(),
            BuildOid4VpJarRequest(),
            BuildOid4VpDirectPost()
        ];
    };


    private static ServerEndpoint BuildOid4VpPar() =>
        new()
        {
            HttpMethod = Post,
            PathTemplate = ServerEndpointPaths.Par,
            Capability = ServerCapabilityName.VerifiablePresentation,
            StartsNewFlow = true,
            Kind = FlowKind.Oid4VpVerifierServer,
            BuildInputAsync = async (fields, context, currentState, options, ct) =>
            {
                ClientRegistration? registration = context.Registration;
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

                Uri? requestUriBase = context.RequestUriBase;
                if(requestUriBase is null)
                {
                    return (null,
                        ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidRequest,
                            "Missing request_uri base URI in context."));
                }

                //The flowId is the internal correlation key generated for this flow.
                //It is kept server-side only and placed in context for dispatcher
                //bookkeeping.
                //
                //TODO (flowId/request_uri separation): the current implementation uses
                //the same random token as both the internal flowId and the external
                //request_uri path segment. The documented design principle states
                //they must be distinct: flowId never leaves the server, request_uri
                //tokens are external handles, and ResolveCorrelationKeyDelegate maps
                //the handle back to the flowId. Separating them requires adding an
                //ExtractCorrelationKey to the request-object endpoint and registering
                //the mapping here. Deferred to a dedicated session.
                string requestUriToken = Guid.NewGuid().ToString("N");
                string flowId = requestUriToken;
                string authority = requestUriBase.GetLeftPart(UriPartial.Authority);
                Uri requestUri = new(
                    $"{authority}/connect/{requestUriToken}/request/{requestUriToken}");
                const int expiresIn = 300;

                DateTimeOffset now = options.TimeProvider.GetUtcNow();

                IReadOnlyList<string> allowedEncAlgorithms =
                    registration.ClientMetadata?.EncryptedResponseEncValuesSupported
                    ?? ImmutableArray.Create(
                        WellKnownJweEncryptionAlgorithms.A128Gcm,
                        WellKnownJweEncryptionAlgorithms.A256Gcm);

                context.SetGeneratedFlowId(flowId);
                context.SetGeneratedRequestUri(requestUri);

                KeyId signingKeyId = await SigningKeySelection.ResolveSigningKeyIdAsync(
                    options,
                    registration,
                    Verifiable.Cryptography.Context.KeyUsageContext.JarSigning,
                    context,
                    ct).ConfigureAwait(false);

                return ((OAuthFlowInput?)new ServerParReceived(
                    FlowId: flowId,
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

                return ServerHttpResponse.Ok(body, "application/json");
            }
        };


    private static ServerEndpoint BuildOid4VpJarRequest() =>
        new()
        {
            HttpMethod = Get,
            PathTemplate = ServerEndpointPaths.JarRequest,
            Capability = ServerCapabilityName.VerifiablePresentation,
            StartsNewFlow = false,
            Kind = FlowKind.Oid4VpVerifierServer,

            BuildInputAsync = static async (fields, context, currentState, options, ct) =>
            {
                if(currentState is not VerifierParReceivedState parReceived)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        "Flow not in expected state for JAR request."));
                }

                if(options.ActionExecutor is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, "Action executor not configured."));
                }

                OAuthFlowInput signed = await options.ActionExecutor.ExecuteAsync(
                    new SignJarAction(
                        parReceived.Nonce,
                        parReceived.Query,
                        parReceived.SigningKeyId),
                    context,
                    options,
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


    private static ServerEndpoint BuildOid4VpDirectPost() =>
        new()
        {
            HttpMethod = Post,
            PathTemplate = ServerEndpointPaths.DirectPost,
            Capability = ServerCapabilityName.VerifiablePresentation,
            StartsNewFlow = false,
            Kind = FlowKind.Oid4VpVerifierServer,
            ExtractCorrelationKey = static (path, fields, context) =>
                fields.TryGetValue(OAuthRequestParameters.State, out string? state)
                    && !string.IsNullOrWhiteSpace(state) ? state : null,

            BuildInputAsync = static (fields, context, currentState, options, ct) =>
            {
                if(currentState is not VerifierJarServedState)
                {
                    return ValueTask.FromResult<(OAuthFlowInput?, ServerHttpResponse?)>((null,
                        ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidRequest,
                            "Flow not in expected state for direct_post.")));
                }

                if(!fields.TryGetValue(OAuthRequestParameters.Response,
                    out string? compactJwe)
                    || string.IsNullOrWhiteSpace(compactJwe))
                {
                    return ValueTask.FromResult<(OAuthFlowInput?, ServerHttpResponse?)>((null,
                        ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidRequest, "Missing response parameter.")));
                }

                return ValueTask.FromResult<(OAuthFlowInput?, ServerHttpResponse?)>(
                    (new ResponsePosted(compactJwe, options.TimeProvider.GetUtcNow()), null));
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

                return ServerHttpResponse.Ok(body, "application/json");
            }
        };
}
