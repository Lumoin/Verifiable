using System.Collections.Frozen;
using System.Diagnostics;
using Verifiable.Core;
using Verifiable.OAuth.Client;

namespace Verifiable.OAuth.Server.Pipeline;

/// <summary>
/// The library-owned <see cref="MaterializeRegistrationDelegate"/> for Client ID Metadata
/// Document (CIMD) clients: the dispatch-stage hook that resolves a matched client's document
/// through <see cref="AuthorizationServerIntegration.ResolveClientMetadataAsync"/> and overlays
/// the client-data-dependent fields onto the effective registration, per
/// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html#section-5">
/// draft-ietf-oauth-client-id-metadata-document-02 Section 5</see> and
/// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html#section-4">
/// Section 4</see>.
/// </summary>
[DebuggerDisplay("ClientIdMetadataMaterialization")]
public static class ClientIdMetadataMaterialization
{
    /// <summary>The span event name for a resolver-side policy denial.</summary>
    public const string PolicyDeniedEventName = "oauth.cimd.materialize.policy_denied";

    /// <summary>The span event name for a resolver-side fetch failure.</summary>
    public const string FetchFailedEventName = "oauth.cimd.materialize.fetch_failed";

    /// <summary>The span event name for a resolver-side invalid-document rejection.</summary>
    public const string InvalidDocumentEventName = "oauth.cimd.materialize.invalid_document";

    /// <summary>The span event name for a wire <c>client_id</c> that does not match the registered client.</summary>
    public const string ClientIdMismatchEventName = "oauth.cimd.materialize.client_id_mismatch";

    /// <summary>
    /// Capabilities that identify a request as belonging to the token endpoint family
    /// unambiguously by capability alone — <see cref="WellKnownCapabilityIdentifiers.OAuthAuthorizationCode"/>
    /// is deliberately excluded here because the authorization-code grant shares that single
    /// capability across both the front-channel authorize/PAR endpoints and the token/refresh
    /// endpoints; <see cref="IsTokenEndpointRequest"/> distinguishes those by the wire shape
    /// instead (the presence of <c>grant_type</c>).
    /// </summary>
    private static readonly FrozenSet<CapabilityIdentifier> UnambiguousTokenEndpointCapabilities = new[]
    {
        WellKnownCapabilityIdentifiers.OAuthClientCredentials,
        WellKnownCapabilityIdentifiers.OAuthTokenExchange,
        WellKnownCapabilityIdentifiers.OAuthJwtBearer,
        WellKnownCapabilityIdentifiers.Oid4VciPreAuthorizedCodeGrant,
        WellKnownCapabilityIdentifiers.OAuthTokenRevocation,
        WellKnownCapabilityIdentifiers.OAuthTokenIntrospection
    }.ToFrozenSet();


    /// <summary>
    /// Builds the CIMD <see cref="MaterializeRegistrationDelegate"/>. Assign the result to
    /// <see cref="ServerIntegration.MaterializeRegistrationAsync"/> to activate CIMD
    /// materialization for every registered protocol family sharing the host.
    /// </summary>
    public static MaterializeRegistrationDelegate Build() =>
        async (registration, context, cancellationToken) =>
        {
            ArgumentNullException.ThrowIfNull(registration);
            ArgumentNullException.ThrowIfNull(context);

            if(registration is not ClientRecord record || record.ClientMetadataUri is null)
            {
                return Passthrough(registration);
            }

            if(!record.IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OAuthClientIdMetadataDocument))
            {
                return Passthrough(registration);
            }

            AuthorizationServerIntegration oauth = context.Server!.OAuth();
            if(oauth.ResolveClientMetadataAsync is null)
            {
                return Passthrough(registration);
            }

            RequestFields? fields = context.IncomingRequest?.Fields;
            if(fields is null || !fields.TryGetValue(OAuthRequestParameterNames.ClientId, out string? wireClientId))
            {
                return Passthrough(registration);
            }

            if(!ClientIdentifierUrl.IsMatch(wireClientId, record.ClientId))
            {
                Activity.Current?.AddEvent(new ActivityEvent(ClientIdMismatchEventName));

                return Fail(context, fields);
            }

            ClientIdMetadataResolution resolution = await oauth.ResolveClientMetadataAsync(
                record.ClientMetadataUri, context, cancellationToken).ConfigureAwait(false);

            if(!resolution.IsResolved || resolution.Document is null)
            {
                Activity.Current?.AddEvent(new ActivityEvent(ResolutionFailureEventName(resolution.Outcome)));

                return Fail(context, fields);
            }

            ClientMetadata document = resolution.Document;
            ClientRecord materialized = record with
            {
                IsClientMetadataMaterialized = true,
                AllowedRedirectUris = [.. document.RedirectUris],
                TokenEndpointAuthMethod = document.TokenEndpointAuthMethod,
                ClientJwks = document.Jwks,
                ClientJwksUri = document.JwksUri,
                ClientName = document.ClientName,
                ClientUri = document.ClientUri,
                LogoUri = document.LogoUri,
                SoftwareStatement = document.SoftwareStatement
            };

            return new RegistrationMaterialization { Registration = materialized };
        };


    private static RegistrationMaterialization Passthrough(IRegistrationRecord registration) =>
        new() { Registration = registration };


    //CIMD-035 abort mapping: a direct 400 (no redirect is attempted before materialization has
    //even established a usable registration) for the general case, and 401 invalid_client for
    //the token endpoint family, mirroring how AuthCodeEndpoints answers client-authentication
    //failures at the token endpoint. Neither the client_id-mismatch reason nor the resolver's
    //internal Defect ever reaches the wire body.
    private static RegistrationMaterialization Fail(ExchangeContext context, RequestFields fields) =>
        new()
        {
            Failure = IsTokenEndpointRequest(context, fields)
                ? ServerHttpResponse.Unauthorized(OAuthErrors.InvalidClient, "Client authentication failed.")
                : ServerHttpResponse.BadRequest(OAuthErrors.InvalidRequest, "The request could not be processed.")
        };


    //A request is token-endpoint-shaped when it carries grant_type (every token/refresh/
    //client_credentials/token_exchange/jwt_bearer/pre-authorized_code candidate requires it to
    //match), or when the matched capability is one that is exclusively a token/management
    //endpoint (see UnambiguousTokenEndpointCapabilities).
    private static bool IsTokenEndpointRequest(ExchangeContext context, RequestFields fields) =>
        fields.ContainsKey(OAuthRequestParameterNames.GrantType)
            || (context.Capability is CapabilityIdentifier capability
                && UnambiguousTokenEndpointCapabilities.Contains(capability));


    private static string ResolutionFailureEventName(ClientIdMetadataResolutionOutcome outcome) => outcome switch
    {
        ClientIdMetadataResolutionOutcome.PolicyDenied => PolicyDeniedEventName,
        ClientIdMetadataResolutionOutcome.FetchFailed => FetchFailedEventName,
        _ => InvalidDocumentEventName
    };
}
