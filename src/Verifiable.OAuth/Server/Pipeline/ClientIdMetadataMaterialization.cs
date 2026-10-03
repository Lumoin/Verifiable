using System.Collections.Frozen;
using System.Diagnostics;
using Verifiable.Core;
using Verifiable.Cryptography.Text;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Logout;

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
/// <remarks>
/// <para>
/// The materialization judges a request by one classification of the request the dispatcher matched
/// (<see cref="Classify"/>), decided by the matched capability first, and one table of what each class does:
/// </para>
/// <list type="number">
///   <item><description>
///     A protected resource (<see cref="ProtectedResourceCapabilities"/>): an endpoint that authenticates a request by
///     an access token, or the resource side's endpoint that serves without a client. It is never judged: nothing is
///     read, fetched or refused, whatever fields it carries, and the endpoint answers it as at a tenant without a
///     metadata document.
///   </description></item>
///   <item><description>
///     Global Token Revocation, which authenticates the client
///     (<see href="https://datatracker.ietf.org/doc/html/draft-parecki-oauth-global-token-revocation-06#section-3.2">draft-parecki-oauth-global-token-revocation-06 Section 3.2</see>:
///     "The request MUST also be authenticated."). A reading that presents a credential is judged against the
///     document of its <c>client_id</c>, else of the registration's own identifier; a malformed reading, an empty
///     <c>Authorization</c> line included, and a reading without a credential pass through to the endpoint, which
///     answers them itself. A <c>client_id</c> naming another client and a failed fetch are answered by the endpoint's
///     own refusal of an unauthenticated request.
///   </description></item>
///   <item><description>
///     A pushed authorization request, which authenticates the client as the token endpoint does
///     (<see href="https://www.rfc-editor.org/rfc/rfc9126#section-2">RFC 9126 Section 2</see>). A malformed reading
///     is refused; the document fetched is the one its <c>client_id</c> names, and a request without one passes
///     through to the endpoint. A <c>client_id</c> naming another client and a failed fetch are answered in the shape
///     of the token endpoint's client authentication failure.
///   </description></item>
///   <item><description>
///     The token endpoint family (<see cref="IsTokenEndpointRequest"/>), the device authorization endpoint among
///     them, whose requests authenticate as the token endpoint's do
///     (<see href="https://www.rfc-editor.org/rfc/rfc8628#section-3.1">RFC 8628 Section 3.1</see>: "The client
///     authentication requirements of Section 3.2.1 of [RFC6749] apply to requests on this endpoint, which means that
///     confidential clients (those that have established client credentials) authenticate in the same manner as when
///     making requests to the token endpoint, and public clients provide the "client_id" parameter to identify
///     themselves."); no builder of the library serves it, and an application's builder may, under
///     <see cref="WellKnownCapabilityIdentifiers.OAuthDeviceAuthorization"/>. A malformed reading is refused; the
///     document fetched is the one its <c>client_id</c> names, else the registration's own, with a credential or with
///     none, so every token-family request is judged against the document. A <c>client_id</c> naming another client
///     and a failed fetch are answered in the shape of the client authentication failure.
///   </description></item>
///   <item><description>
///     Every other request (the authorization endpoint family, end-session, discovery, the federation endpoints and
///     the rest). The library's endpoints of this class authenticate no client of the tenant: the reading's
///     malformation is not judged here, and the document fetched is the one its <c>client_id</c> names by the field's
///     own rule (<see cref="ClientCredentialReading.ReadClientIdentifier"/>); a request without one passes through. A
///     <c>client_id</c> naming another client and a failed fetch are answered 400
///     <see cref="OAuthErrors.InvalidRequest"/> with <see cref="WellKnownOAuthErrorDescriptions.RequestNotProcessed"/>.
///     The federation endpoints' gate authenticates a federation requester, not the tenant's OAuth client, through the
///     application's seam (<see cref="Verifiable.OAuth.Federation.AuthenticateFederationClientDelegate"/>), which is handed the
///     registration as the dispatcher holds it: the stored one unless the request's <c>client_id</c> names the client
///     and the document materialized it, or the request carries a <c>grant_type</c> with a value, which makes it a
///     token request of the fourth class (the document fetched on the registration's own identifier, and a failed
///     fetch refused as a client authentication failure). An application's own endpoint under a capability of its own is judged as a
///     token request when its request carries a <c>grant_type</c> with a value, and otherwise by <c>client_id</c>
///     alone, so one that authenticates the client on a request carrying neither is served on the stored registration.
///   </description></item>
/// </list>
/// <para>
/// For the endpoints the library builds: whenever an endpoint identifies or authenticates the client of a tenant whose
/// registration names a metadata document, the record it judges is the document's; a request the materialization does
/// not judge is answered by its endpoint as at a tenant without a metadata document. The bound is that set of
/// endpoints: the federation gate's requester and an application's endpoint under a capability of its own are judged
/// as the fifth item says.
/// </para>
/// </remarks>
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
    /// The capabilities of the protected resources, whose requests the materialization never judges: the endpoints
    /// that authenticate a request by an access token and answer through the
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3">RFC 6750 Section 3</see> challenge (UserInfo, the
    /// OID4VCI Credential, Deferred Credential and Notification endpoints, the client configuration endpoint of
    /// <see href="https://www.rfc-editor.org/rfc/rfc7592#section-2">RFC 7592 Section 2</see>, the Shared Signals
    /// transmitter's endpoints), and the resource side's endpoints that serve without a client (the OID4VCI Nonce,
    /// Credential Offer and Credential Issuer Metadata endpoints, the Protected Resource Metadata endpoint and the
    /// AuthZEN policy decision point's endpoints). None of them identifies an OAuth client by a request field.
    /// </summary>
    private static FrozenSet<CapabilityIdentifier> ProtectedResourceCapabilities { get; } = new[]
    {
        WellKnownCapabilityIdentifiers.OidcUserInfo,
        WellKnownCapabilityIdentifiers.Oid4VciCredentialEndpoint,
        WellKnownCapabilityIdentifiers.Oid4VciDeferredCredentialEndpoint,
        WellKnownCapabilityIdentifiers.Oid4VciNotificationEndpoint,
        WellKnownCapabilityIdentifiers.Oid4VciNonceEndpoint,
        WellKnownCapabilityIdentifiers.Oid4VciCredentialOfferEndpoint,
        WellKnownCapabilityIdentifiers.Oid4VciCredentialIssuerMetadata,
        WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata,
        WellKnownCapabilityIdentifiers.OAuthDynamicClientRegistration,
        WellKnownCapabilityIdentifiers.SsfTransmitter,
        WellKnownCapabilityIdentifiers.AuthZenAuthorizationApi
    }.ToFrozenSet();

    /// <summary>
    /// The capabilities that tag token-family endpoints alone: the client credentials, token exchange (the
    /// identity assertion grant's minting included), jwt-bearer (its redemption included), pre-authorized code,
    /// revocation and introspection endpoints, and the device authorization endpoint
    /// (<see cref="WellKnownCapabilityIdentifiers.OAuthDeviceAuthorization"/>), whose requests authenticate as the
    /// token endpoint's do
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8628#section-3.1">RFC 8628 Section 3.1</see>: "The client
    /// authentication requirements of Section 3.2.1 of [RFC6749] apply to requests on this endpoint, which means that
    /// confidential clients (those that have established client credentials) authenticate in the same manner as when
    /// making requests to the token endpoint, and public clients provide the "client_id" parameter to identify
    /// themselves."); no builder of the library serves that endpoint, and every candidate an application's builder
    /// serves under that capability is judged as the device authorization endpoint, which the capability is in the set
    /// for although the grant has an endpoint of user interaction too
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8628#section-3.3">RFC 8628 Section 3.3</see>), one an application
    /// tags with a capability of its own.
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthAuthorizationCode"/> is not among them, since it tags the
    /// authorization endpoint and the token endpoint both; a request matched under any capability outside the
    /// protected resources, Global Token Revocation and the pushed request is a token request when it carries a
    /// <c>grant_type</c> with a value (<see cref="Classify"/>).
    /// </summary>
    private static FrozenSet<CapabilityIdentifier> UnambiguousTokenEndpointCapabilities { get; } = new[]
    {
        WellKnownCapabilityIdentifiers.OAuthClientCredentials,
        WellKnownCapabilityIdentifiers.OAuthTokenExchange,
        WellKnownCapabilityIdentifiers.OAuthJwtBearer,
        WellKnownCapabilityIdentifiers.Oid4VciPreAuthorizedCodeGrant,
        WellKnownCapabilityIdentifiers.OAuthTokenRevocation,
        WellKnownCapabilityIdentifiers.OAuthTokenIntrospection,
        WellKnownCapabilityIdentifiers.OAuthDeviceAuthorization
    }.ToFrozenSet();


    /// <summary>
    /// The class of a request the dispatcher matched, which decides what the materialization reads, which document
    /// it fetches and how it refuses (see the type's remarks).
    /// </summary>
    private enum MatchedRequestClass
    {
        /// <summary>A protected resource request (<see cref="ProtectedResourceCapabilities"/>), never judged.</summary>
        ProtectedResource,

        /// <summary>A Global Token Revocation request, judged when its reading presents a credential.</summary>
        GlobalTokenRevocation,

        /// <summary>A pushed authorization request, judged by its <c>client_id</c>.</summary>
        PushedRequest,

        /// <summary>A token-family request, always judged.</summary>
        TokenRequest,

        /// <summary>Any other request, judged by its <c>client_id</c> field alone.</summary>
        Other
    }


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

            //A protected resource request is not read at all: its endpoint answers it as at a tenant
            //without a metadata document.
            MatchedRequestClass requestClass = Classify(context);
            if(requestClass == MatchedRequestClass.ProtectedResource)
            {
                return Passthrough(registration);
            }

            IncomingRequest? request = context.IncomingRequest;
            if(request?.Fields is not { } fields)
            {
                return Passthrough(registration);
            }

            //The request's client credentials are read once, through the one reading every endpoint of the
            //library reads them through, and the reading is carried on the context for the endpoint. The table
            //of the classes: a pushed request and a token request refuse a malformed reading here, before any
            //fetch; the identifier fetched on is client_id at a pushed request, client_id else the registration's
            //own at a token request, the same at Global Token Revocation when the reading presents a credential
            //(any other revocation reading passes through to the endpoint, which answers it), and client_id by
            //its own field rule at every other request, whose endpoints of the library authenticate no client of
            //the tenant (the federation gate authenticates a federation requester through the application's seam).
            //No identifier: the request passes through.
            ClientCredentialReading reading = AuthCodeEndpoints.CarriedClientCredentials(context, fields);
            if(requestClass is MatchedRequestClass.PushedRequest or MatchedRequestClass.TokenRequest
                && AuthCodeEndpoints.RefuseMalformedClientCredentials(reading) is { } malformedRefusal)
            {
                return new RegistrationMaterialization { Failure = malformedRefusal };
            }

            string? wireClientId = requestClass switch
            {
                MatchedRequestClass.GlobalTokenRevocation when reading is { IsMalformed: false, HasCredentials: true } =>
                    reading.ClientId ?? record.ClientId,
                MatchedRequestClass.GlobalTokenRevocation => null,
                MatchedRequestClass.PushedRequest => reading.ClientId,
                MatchedRequestClass.TokenRequest => reading.ClientId ?? record.ClientId,
                MatchedRequestClass.ProtectedResource => null,

                _ => ClientCredentialReading.ReadClientIdentifier(fields)
            };
            if(wireClientId is null)
            {
                return Passthrough(registration);
            }

            if(!ClientIdentifierUrl.IsMatch(wireClientId, record.ClientId))
            {
                _ = (Activity.Current?.AddEvent(new ActivityEvent(ClientIdMismatchEventName)));

                return await RefuseAsync(context, record, reading, requestClass, cancellationToken).ConfigureAwait(false);
            }

            ClientIdMetadataResolution resolution = await oauth.ResolveClientMetadataAsync(
                record.ClientMetadataUri, context, cancellationToken).ConfigureAwait(false);

            if(!resolution.IsResolved || resolution.Document is null)
            {
                _ = (Activity.Current?.AddEvent(new ActivityEvent(ResolutionFailureEventName(resolution.Outcome))));

                return await RefuseAsync(context, record, reading, requestClass, cancellationToken).ConfigureAwait(false);
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
    /// document, the document capability is not allowed for it, no resolver is wired, the request is a protected
    /// resource request (<see cref="ProtectedResourceCapabilities"/>), or the request names no identifier to fetch
    /// on by its class (see the type's remarks): a pushed request or another request without <c>client_id</c>, and a
    /// Global Token Revocation request whose reading is malformed or presents no credential. It also answers a context
    /// that carries no incoming request, so no request fields to read: the dispatcher places the request on the
    /// context before it asks for the materialization, so a request it dispatches always carries its fields (an empty
    /// set included, which a token-family request is judged on as any other), and a context without one reaches no
    /// endpoint through the dispatcher. Every endpoint of the library reads its credentials from the fields the
    /// dispatcher hands it, the same request's fields, so the stored registration is never judged in place of a
    /// document for a token-family request on that path. The request then proceeds on the stored registration, no
    /// document is fetched, and its endpoint answers it as at a tenant without a metadata document.
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
    /// A pushed request and a token request (<see cref="IsTokenEndpointRequest"/>) have their client credentials
    /// read once through <see cref="AuthCodeEndpoints.CarriedClientCredentials"/>. A malformed reading is answered 400
    /// <see cref="OAuthErrors.InvalidRequest"/> with the description of its reason, as every client-authenticating
    /// endpoint of the library answers it. Any other reading is answered with <see cref="OAuthErrors.InvalidClient"/>
    /// and <see cref="WellKnownOAuthErrorDescriptions.ClientAuthenticationFailed"/>, the <c>invalid_client</c> code of
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>, in the
    /// shape of the library's client authentication failure: 401 with the challenge
    /// <c>&lt;scheme&gt; realm="&lt;issuer&gt;"</c> of the scheme the request attempted in its
    /// <c>Authorization</c> field, or of <c>Basic</c> when <c>client_secret_basic</c> is advertised, and
    /// otherwise 400, so no 401 leaves without a challenge
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.5.2">RFC 9110 Section 15.5.2</see>).
    /// This method is synchronous, so its realm is the issuer <see cref="DispatchedIssuer"/> names: with the
    /// application's issuer resolver wired, the context's issuer as the dispatcher left it, a value placed on the
    /// context before a resolution the resolver declined included; with none wired, the issuer the library's default
    /// resolution accepts. With no issuer the answer is 400. Any other request is answered 400 with
    /// <see cref="OAuthErrors.InvalidRequest"/> and <see cref="WellKnownOAuthErrorDescriptions.RequestNotProcessed"/>,
    /// a direct answer because no redirect is attempted before a usable registration exists.
    /// </para>
    /// <para>
    /// The library's own materialization refuses through <see cref="RefuseAsync"/>, which resolves the realm as the
    /// token endpoint resolves it, refuses nothing at a protected resource, and answers Global Token Revocation through
    /// that endpoint's own refusal of an unauthenticated request, which a synchronous method cannot compose.
    /// </para>
    /// <para>
    /// <see cref="Build"/> passes a protected resource request and a request that names no identifier through with the
    /// stored registration (<see cref="ClientRecord.IsClientMetadataMaterialized"/> <see langword="false"/>), so a rule
    /// over its outcome refuses only a materialized registration. This method answers a protected resource and Global
    /// Token Revocation 400 without the challenge their endpoints give, so an application rule leaves those requests to
    /// their endpoints.
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

        if(Classify(context) is not (MatchedRequestClass.PushedRequest or MatchedRequestClass.TokenRequest))
        {
            return new RegistrationMaterialization
            {
                Failure = ServerHttpResponse.BadRequest(
                    OAuthErrors.InvalidRequest, WellKnownOAuthErrorDescriptions.RequestNotProcessed)
            };
        }

        IncomingRequest? request = context.IncomingRequest;
        ClientCredentialReading reading = AuthCodeEndpoints.CarriedClientCredentials(context, request?.Fields ?? new RequestFields());

        return new RegistrationMaterialization
        {
            Failure = AuthCodeEndpoints.RefuseMalformedClientCredentials(reading)
                ?? AuthCodeEndpoints.ClientAuthenticationRefusal(
                    reading,
                    WellKnownOAuthErrorDescriptions.ClientAuthenticationFailed,
                    AuthCodeEndpoints.IsBasicAdvertised(context.RequestServer),
                    DispatchedIssuer(context))
        };
    }


    /// <summary>
    /// The refusal the library's own materialization (<see cref="Build"/>) answers a client identifier mismatch
    /// or a failed document fetch with, by the request's class (see the type's remarks), judged on the
    /// <paramref name="reading"/> <see cref="Build"/> took. A pushed request and a token request are answered by the
    /// body the token endpoint answers a failed client authentication with,
    /// <see cref="AuthCodeEndpoints.ClientAuthenticationFailureResponseAsync"/>, so the realm of its challenge is
    /// the issuer the token endpoint resolves for <paramref name="registration"/>, through the application's issuer
    /// resolver when one is wired and the library's default resolution otherwise, and a request whose issuer does
    /// not resolve is answered 400 with no challenge, as the token endpoint answers it. A Global Token Revocation
    /// request is answered by that endpoint's own refusal of an unauthenticated request
    /// (<see cref="GlobalTokenRevocationEndpoints.RefuseUnauthenticatedAsync"/>), the same answer the endpoint gives
    /// the same reading when its client authentication seam refuses it. Any other request is answered 400
    /// <see cref="OAuthErrors.InvalidRequest"/> with <see cref="WellKnownOAuthErrorDescriptions.RequestNotProcessed"/>.
    /// </summary>
    /// <param name="context">The per-request context.</param>
    /// <param name="registration">The registration the request is served for.</param>
    /// <param name="reading">The request's one reading of its client credentials.</param>
    /// <param name="requestClass">The request's class.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A materialization whose failure is the refusal response.</returns>
    private static async ValueTask<RegistrationMaterialization> RefuseAsync(
        ExchangeContext context,
        ClientRecord registration,
        ClientCredentialReading reading,
        MatchedRequestClass requestClass,
        CancellationToken cancellationToken)
    {
        ServerHttpResponse failure = requestClass switch
        {
            MatchedRequestClass.PushedRequest or MatchedRequestClass.TokenRequest =>
                await AuthCodeEndpoints.ClientAuthenticationFailureResponseAsync(
                    reading, WellKnownOAuthErrorDescriptions.ClientAuthenticationFailed, registration, context, cancellationToken)
                    .ConfigureAwait(false),
            MatchedRequestClass.GlobalTokenRevocation =>
                await GlobalTokenRevocationEndpoints.RefuseUnauthenticatedAsync(
                    reading, context.RequestServer!, registration, context, cancellationToken).ConfigureAwait(false),

            _ => ServerHttpResponse.BadRequest(OAuthErrors.InvalidRequest, WellKnownOAuthErrorDescriptions.RequestNotProcessed)
        };

        return new RegistrationMaterialization { Failure = failure };
    }


    /// <summary>
    /// The issuer the request is served under, for the synchronous <see cref="Refuse"/> alone, an application
    /// rule's refusal composed without waiting. With the application's issuer resolver wired, it is the context's
    /// issuer as the dispatcher left it, read without a second resolution: the issuer the resolver named, or, when the
    /// resolver declined, a value an earlier step placed on the context, which the dispatcher leaves in place. With
    /// none wired the dispatcher places nothing, and the library's default resolution
    /// (<see cref="DefaultIssuerResolver.Resolve"/>, the registration's issuer, else the context's, checked by
    /// <see cref="IssuerIdentifierValidation.IsValidIssuerShape"/>) names it, as it does for every other refusal
    /// of the library; <see langword="null"/> when it names no valid issuer. The library's own materialization
    /// resolves its realm through <see cref="RefuseAsync"/>.
    /// </summary>
    /// <param name="context">The per-request context.</param>
    /// <returns>The issuer, or <see langword="null"/>.</returns>
    private static Uri? DispatchedIssuer(ExchangeContext context)
    {
        if(context.RequestServer?.OAuth().ResolveIssuerAsync is not null || context.ClientRegistration is not { } registration)
        {
            return context.Issuer;
        }

        try
        {
            return DefaultIssuerResolver.Resolve(registration, context);
        }
        catch(InvalidOperationException)
        {
            //No issuer the default resolution accepts: no realm, so the refusal is a 400 with no challenge.
            return null;
        }
    }


    /// <summary>
    /// Whether <paramref name="context"/> carries a request the materialization judges as a token request. The token
    /// family is the requests that authenticate the client as the token endpoint's requests do: those matched under a
    /// capability that tags token-family endpoints alone (client credentials, token exchange, jwt-bearer,
    /// pre-authorized code, revocation, introspection, and the device authorization endpoint of
    /// <see href="https://www.rfc-editor.org/rfc/rfc8628#section-3.1">RFC 8628 Section 3.1</see>, which no builder of
    /// the library serves, so that every candidate under its capability is judged as that endpoint and the endpoint of
    /// the user interaction of <see href="https://www.rfc-editor.org/rfc/rfc8628#section-3.3">RFC 8628 Section 3.3</see>,
    /// which a user agent reaches, carries a capability of the application's own), and those matched under any
    /// capability other than a protected resource's, Global Token
    /// Revocation's or the pushed request's when their fields carry a <c>grant_type</c> with a value. An application's
    /// endpoint under a capability of its own is a token request by that <c>grant_type</c> alone. Such a request is
    /// judged against the client's document whether or not it carries <c>client_id</c> or a credential, its malformed
    /// reading is refused before any fetch, and a client identifier mismatch or a failed fetch is refused in the shape
    /// of the client authentication failure (<see cref="Refuse"/>).
    /// </summary>
    /// <remarks>
    /// "Parameters sent without a value MUST be treated as if they were omitted from the request"
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 Section 3.1</see>),
    /// so <c>grant_type=</c> with an empty value counts as absent.
    /// </remarks>
    /// <param name="context">The per-request context to classify.</param>
    /// <returns><see langword="true"/> when the request is judged as a token request.</returns>
    public static bool IsTokenEndpointRequest(ExchangeContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return Classify(context) == MatchedRequestClass.TokenRequest;
    }


    /// <summary>
    /// The class of the request the dispatcher matched (see the type's remarks), decided in this order: the matched
    /// capability of a protected resource (<see cref="ProtectedResourceCapabilities"/>), so a protected resource request
    /// that carries a <c>grant_type</c> stays one; Global Token Revocation
    /// (<see cref="WellKnownCapabilityIdentifiers.OAuthGlobalTokenRevocation"/>); the pushed request
    /// (<see cref="WellKnownCapabilityIdentifiers.OAuthPushedAuthorization"/>, its request object form included); a
    /// capability that tags token-family endpoints alone (<see cref="UnambiguousTokenEndpointCapabilities"/>); any other
    /// request whose fields carry a <c>grant_type</c> with a value, a token request; and every other request.
    /// </summary>
    /// <param name="context">The per-request context to classify.</param>
    /// <returns>The request's class.</returns>
    private static MatchedRequestClass Classify(ExchangeContext context) => context.Capability switch
    {
        CapabilityIdentifier capability when ProtectedResourceCapabilities.Contains(capability) =>
            MatchedRequestClass.ProtectedResource,
        CapabilityIdentifier capability when capability.Equals(WellKnownCapabilityIdentifiers.OAuthGlobalTokenRevocation) =>
            MatchedRequestClass.GlobalTokenRevocation,
        CapabilityIdentifier capability when capability.Equals(WellKnownCapabilityIdentifiers.OAuthPushedAuthorization) =>
            MatchedRequestClass.PushedRequest,
        CapabilityIdentifier capability when UnambiguousTokenEndpointCapabilities.Contains(capability) =>
            MatchedRequestClass.TokenRequest,
        _ when context.IncomingRequest?.Fields is { } fields
            && fields.TryGetValue(OAuthRequestParameterNames.GrantType, out string? grantType)
            && !string.IsNullOrEmpty(grantType) =>
            MatchedRequestClass.TokenRequest,

        _ => MatchedRequestClass.Other
    };


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
