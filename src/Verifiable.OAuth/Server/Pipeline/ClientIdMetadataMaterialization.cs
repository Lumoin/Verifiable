using System.Collections.Frozen;
using System.Diagnostics;
using Verifiable.Core;
using Verifiable.Cryptography.Text;
using Verifiable.OAuth.AuthCode;
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
public static class ClientIdMetadataMaterialization
{
    /// <summary>The UTF-8 source literal of <see cref="PolicyDeniedEventName"/>.</summary>
    public static ReadOnlySpan<byte> PolicyDeniedEventNameUtf8 => "oauth.cimd.materialize.policy_denied"u8;

    /// <summary>The span event name for a resolver-side policy denial.</summary>
    public static string PolicyDeniedEventName { get; } = Utf8Constants.ToInternedString(PolicyDeniedEventNameUtf8);

    /// <summary>The UTF-8 source literal of <see cref="FetchFailedEventName"/>.</summary>
    public static ReadOnlySpan<byte> FetchFailedEventNameUtf8 => "oauth.cimd.materialize.fetch_failed"u8;

    /// <summary>The span event name for a resolver-side fetch failure.</summary>
    public static string FetchFailedEventName { get; } = Utf8Constants.ToInternedString(FetchFailedEventNameUtf8);

    /// <summary>The UTF-8 source literal of <see cref="InvalidDocumentEventName"/>.</summary>
    public static ReadOnlySpan<byte> InvalidDocumentEventNameUtf8 => "oauth.cimd.materialize.invalid_document"u8;

    /// <summary>The span event name for a resolver-side invalid-document rejection.</summary>
    public static string InvalidDocumentEventName { get; } = Utf8Constants.ToInternedString(InvalidDocumentEventNameUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ClientIdMismatchEventName"/>.</summary>
    public static ReadOnlySpan<byte> ClientIdMismatchEventNameUtf8 => "oauth.cimd.materialize.client_id_mismatch"u8;

    /// <summary>The span event name for a wire <c>client_id</c> that does not match the registered client.</summary>
    public static string ClientIdMismatchEventName { get; } = Utf8Constants.ToInternedString(ClientIdMismatchEventNameUtf8);

    /// <summary>
    /// Capabilities that identify a request as belonging to the token endpoint family
    /// unambiguously by capability alone — <see cref="WellKnownCapabilityIdentifiers.OAuthAuthorizationCode"/>
    /// is deliberately excluded here because the authorization-code grant shares that single
    /// capability across both the front-channel authorize/PAR endpoints and the token/refresh
    /// endpoints; <see cref="IsTokenEndpointRequest"/> distinguishes those by the wire shape
    /// instead (a <c>grant_type</c> with a value).
    /// </summary>
    private static FrozenSet<CapabilityIdentifier> UnambiguousTokenEndpointCapabilities { get; } = new[]
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

            AuthorizationServerIntegration oauth = context.RequestServer!.OAuth();
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
                _ = (Activity.Current?.AddEvent(new ActivityEvent(ClientIdMismatchEventName)));

                return Refuse(context);
            }

            ClientIdMetadataResolution resolution = await oauth.ResolveClientMetadataAsync(
                record.ClientMetadataUri, context, cancellationToken).ConfigureAwait(false);

            if(!resolution.IsResolved || resolution.Document is null)
            {
                _ = (Activity.Current?.AddEvent(new ActivityEvent(ResolutionFailureEventName(resolution.Outcome))));

                return Refuse(context);
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


    /// <summary>
    /// The materialization that leaves <paramref name="registration"/> as it is. <see cref="Build"/>
    /// answers with it where no document is to be resolved: the registration names no metadata
    /// document, the document capability is not allowed for it, no resolver is wired, or the
    /// request carries no <c>client_id</c>. The request then proceeds on the stored registration
    /// and no document is fetched.
    /// </summary>
    /// <param name="registration">The registration the request proceeds with.</param>
    /// <returns>A materialization whose registration is <paramref name="registration"/>.</returns>
    private static RegistrationMaterialization Passthrough(IRegistrationRecord registration) =>
        new() { Registration = registration };


    /// <summary>
    /// The refusal shape the library's own materialization answers with, offered so an
    /// application rule composed after <see cref="Build"/> refuses in the same shape.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A fetch of the document that fails aborts the authorization request
    /// (<see href="https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html#section-5.1">
    /// draft-ietf-oauth-client-id-metadata-document-02 Section 5.1</see>), and the library's own
    /// materialization refuses in this shape when the fetch fails. An application rule that refuses
    /// a document that was fetched rests on the specification's sentence "Other specifications MAY
    /// place additional restrictions on the contents of the Client ID Metadata Document accepted by
    /// authorization servers implementing their specification"
    /// (<see href="https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html#section-4">
    /// Section 4</see>); the shape of that refusal is the library's, so it is the same as the
    /// library's own: the same status, the same body and the same challenge.
    /// </para>
    /// <para>
    /// A token-endpoint request (see <see cref="IsTokenEndpointRequest"/>) is answered 401 with
    /// <see cref="OAuthErrors.InvalidClient"/> and
    /// <see cref="WellKnownOAuthErrorDescriptions.ClientAuthenticationFailed"/>, the
    /// <c>invalid_client</c> code of
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>,
    /// and carries <c>WWW-Authenticate: Basic</c> when the request attempted
    /// <c>Authorization: Basic</c> (<see cref="AuthCodeEndpoints.AddBasicChallengeIfAttempted"/>),
    /// as the library's client authentication failure does; any other request is answered 400 with
    /// <see cref="OAuthErrors.InvalidRequest"/> and
    /// <see cref="WellKnownOAuthErrorDescriptions.RequestNotProcessed"/>, a direct answer because
    /// no redirect is attempted before a usable registration exists.
    /// </para>
    /// <para>
    /// The reason for the refusal, a client identifier mismatch or a resolver defect, never
    /// reaches the wire body.
    /// </para>
    /// </remarks>
    /// <param name="context">The per-request context the refusal is shaped for.</param>
    /// <returns>A materialization whose failure is the refusal response.</returns>
    public static RegistrationMaterialization Refuse(ExchangeContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return new RegistrationMaterialization
        {
            Failure = IsTokenEndpointRequest(context)
                ? AuthCodeEndpoints.AddBasicChallengeIfAttempted(
                    ServerHttpResponse.Unauthorized(
                        OAuthErrors.InvalidClient, WellKnownOAuthErrorDescriptions.ClientAuthenticationFailed),
                    context.IncomingRequest)
                : ServerHttpResponse.BadRequest(
                    OAuthErrors.InvalidRequest, WellKnownOAuthErrorDescriptions.RequestNotProcessed)
        };
    }


    /// <summary>
    /// Whether <paramref name="context"/> carries a token-endpoint-shaped request: one whose
    /// wire fields carry a <c>grant_type</c> with a value, or whose matched capability is one that
    /// belongs exclusively to the token and management endpoints (see
    /// <see cref="UnambiguousTokenEndpointCapabilities"/>). A request with no wire fields is not
    /// token-endpoint-shaped. The classification reads the request's own <c>grant_type</c> and
    /// selects only the status and the error code of the refusal in <see cref="Refuse"/>; it is
    /// no authorization input.
    /// </summary>
    /// <remarks>
    /// "Parameters sent without a value MUST be treated as if they were omitted from the request"
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 Section 3.1</see>),
    /// so <c>grant_type=</c> with an empty value counts as absent.
    /// </remarks>
    /// <param name="context">The per-request context to classify.</param>
    /// <returns><see langword="true"/> when the request is token-endpoint-shaped.</returns>
    public static bool IsTokenEndpointRequest(ExchangeContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return context.IncomingRequest?.Fields is { } fields
            && ((fields.TryGetValue(OAuthRequestParameterNames.GrantType, out string? grantType)
                    && !string.IsNullOrEmpty(grantType))
                || (context.Capability is CapabilityIdentifier capability
                    && UnambiguousTokenEndpointCapabilities.Contains(capability)));
    }


    /// <summary>
    /// The span event name that records why a document resolution did not yield a usable
    /// document, so a refusal whose wire body names no cause leaves its cause on the request's
    /// trace.
    /// </summary>
    /// <param name="outcome">The outcome the resolver reported.</param>
    /// <returns>The event name for <paramref name="outcome"/>.</returns>
    private static string ResolutionFailureEventName(ClientIdMetadataResolutionOutcome outcome) => outcome switch
    {
        ClientIdMetadataResolutionOutcome.PolicyDenied => PolicyDeniedEventName,
        ClientIdMetadataResolutionOutcome.FetchFailed => FetchFailedEventName,
        ClientIdMetadataResolutionOutcome.InvalidDocument => InvalidDocumentEventName,
        ClientIdMetadataResolutionOutcome.Resolved => InvalidDocumentEventName,

        _ => InvalidDocumentEventName
    };
}
