using System.Collections.Immutable;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using Verifiable.Core;
using Verifiable.Core.Assessment;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Validation;

namespace Verifiable.OAuth.AuthCode;

/// <summary>
/// Pure static handler functions for the OAuth 2.0 Authorization Code flow.
/// </summary>
/// <remarks>
/// <para>
/// Each handler takes the inbound request fields, the long-lived
/// <see cref="OAuthClientInfrastructure"/>, the per-call
/// <see cref="ClientRegistration"/>, and a cancellation token. No instance
/// state is held. The application author wires these to HTTP routes and
/// supplies the infrastructure constructed at startup plus the registration
/// loaded for the current request.
/// </para>
/// <para>
/// Typical ASP.NET wiring (application code, not part of this library):
/// </para>
/// <code>
/// OAuthClientInfrastructure infrastructure = OAuthClientInfrastructure.Create( ... );
/// ClientRegistration registration = LoadFromStore(clientId);
/// var group = app.MapGroup("/oauth");
/// group.MapPost(AuthCodeFlowRoutes.Par,
///     (IReadOnlyDictionary&lt;string, string&gt; fields, CancellationToken ct) =>
///         AuthCodeFlowHandlers.HandleParAsync(fields, infrastructure, registration, ct));
/// group.MapGet(AuthCodeFlowRoutes.Callback,
///     (IReadOnlyDictionary&lt;string, string&gt; fields, CancellationToken ct) =>
///         AuthCodeFlowHandlers.HandleCallbackAsync(fields, infrastructure, registration, ct));
/// group.MapPost(AuthCodeFlowRoutes.Token,
///     (IReadOnlyDictionary&lt;string, string&gt; fields, CancellationToken ct) =>
///         AuthCodeFlowHandlers.HandleTokenAsync(fields, infrastructure, registration, ct));
/// group.MapPost(AuthCodeFlowRoutes.Revocation,
///     (IReadOnlyDictionary&lt;string, string&gt; fields, CancellationToken ct) =>
///         AuthCodeFlowHandlers.HandleRevocationAsync(fields, infrastructure, registration, ct));
/// </code>
/// <para>
/// In-memory state store for development and testing:
/// </para>
/// <code>
/// var store = new Dictionary&lt;string, FlowState&gt;();
/// OAuthClientInfrastructure infrastructure = OAuthClientInfrastructure.Create(
///     ...
///     saveStateAsync: (state, _) => { store[state.FlowId] = state; return ValueTask.CompletedTask; },
///     loadStateAsync: (id, _)    => ValueTask.FromResult(store.GetValueOrDefault(id)),
///     ...);
/// </code>
/// </remarks>
[SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of disposable state records is transferred to SaveStateAsync on success. The nullable-with-finally pattern ensures disposal on all failure paths.")]
public static class AuthCodeFlowHandlers
{
    //Convenience overloads for single-tenant callers that ignore tenancy: each
    //drives its handler over a fresh empty ExchangeContext. Multi-tenant
    //deployments call the ExchangeContext-bearing overloads directly so the
    //transport and flow-state delegates can scope per tenant.

    /// <inheritdoc cref="HandleParAsync(IReadOnlyDictionary{string, string}, Uri, OAuthClientInfrastructure, ClientRegistration, ExchangeContext, CancellationToken)"/>
    public static ValueTask<AuthCodeFlowEndpointResult> HandleParAsync(
        IReadOnlyDictionary<string, string> fields,
        Uri redirectUri,
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        CancellationToken cancellationToken) =>
        HandleParAsync(fields, redirectUri, infrastructure, registration, [], cancellationToken);


    /// <inheritdoc cref="HandleCallbackAsync(IReadOnlyDictionary{string, string}, OAuthClientInfrastructure, ClientRegistration, ExchangeContext, CancellationToken)"/>
    public static ValueTask<AuthCodeFlowEndpointResult> HandleCallbackAsync(
        IReadOnlyDictionary<string, string> fields,
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        CancellationToken cancellationToken) =>
        HandleCallbackAsync(fields, infrastructure, registration, [], cancellationToken);


    /// <inheritdoc cref="HandleTokenAsync(IReadOnlyDictionary{string, string}, OAuthClientInfrastructure, ClientRegistration, ExchangeContext, CancellationToken)"/>
    public static ValueTask<AuthCodeFlowEndpointResult> HandleTokenAsync(
        IReadOnlyDictionary<string, string> fields,
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        CancellationToken cancellationToken) =>
        HandleTokenAsync(fields, infrastructure, registration, [], cancellationToken);


    /// <inheritdoc cref="HandleRevocationAsync(IReadOnlyDictionary{string, string}, OAuthClientInfrastructure, ClientRegistration, ExchangeContext, CancellationToken)"/>
    public static ValueTask<AuthCodeFlowEndpointResult> HandleRevocationAsync(
        IReadOnlyDictionary<string, string> fields,
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        CancellationToken cancellationToken) =>
        HandleRevocationAsync(fields, infrastructure, registration, [], cancellationToken);


    /// <inheritdoc cref="RefreshAsync(RefreshTokenRequest, OAuthClientInfrastructure, ClientRegistration, ExchangeContext, CancellationToken)"/>
    public static ValueTask<AuthCodeFlowEndpointResult> RefreshAsync(
        RefreshTokenRequest request,
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        CancellationToken cancellationToken) =>
        RefreshAsync(request, infrastructure, registration, [], cancellationToken);


    /// <inheritdoc cref="HandleJarParAsync(AuthCodeStartJarParOptions, OAuthClientInfrastructure, ClientRegistration, ExchangeContext, CancellationToken)"/>
    public static ValueTask<AuthCodeFlowEndpointResult> HandleJarParAsync(
        AuthCodeStartJarParOptions jarOptions,
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        CancellationToken cancellationToken) =>
        HandleJarParAsync(jarOptions, infrastructure, registration, [], cancellationToken);


    /// <inheritdoc cref="HandleJarAuthorizeAsync(AuthCodeStartJarAuthorizeOptions, OAuthClientInfrastructure, ClientRegistration, ExchangeContext, CancellationToken)"/>
    public static ValueTask<AuthCodeFlowEndpointResult> HandleJarAuthorizeAsync(
        AuthCodeStartJarAuthorizeOptions jarOptions,
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        CancellationToken cancellationToken) =>
        HandleJarAuthorizeAsync(jarOptions, infrastructure, registration, [], cancellationToken);


    /// <summary>
    /// Handles a pushed authorization request. Generates PKCE parameters, POSTs to
    /// the PAR endpoint, persists <see cref="ParCompletedState"/> state, and returns a
    /// redirect URI for the caller to forward to the user agent.
    /// </summary>
    /// <remarks>
    /// The send attaches no client authentication: the request carries no <c>client_assertion</c>
    /// field and no authorization header. A confidential client's pushed request is authenticated by
    /// the application's own push built on
    /// <see cref="ClientTokenEndpointAuthentication.AttachClientAssertionAsync"/>, following
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.1">RFC 9126 Section 2.1</see>: "If
    /// applicable, the client also adds its authentication credentials to the request header or the
    /// request body using the same rules as for token endpoint requests."
    /// </remarks>
    /// <param name="fields">
    /// Inbound form fields. A <c>scope</c> field names the requested scope values (RFC 6749 §3.3,
    /// space-delimited) and is sent as given; without one, or with a blank one, the pushed request
    /// carries no <c>scope</c> parameter and the authorization server applies its own default or
    /// refuses (RFC 6749 §3.3). An OpenID Connect request names <c>openid</c> in this field itself
    /// (OpenID Connect Core 1.0 §3.1.2.1). Other required values are taken from
    /// <paramref name="registration"/>.
    /// </param>
    /// <param name="redirectUri">The client's redirect URI to which the authorization response is returned.</param>
    /// <param name="infrastructure">The long-lived infrastructure carrying transport, parsing, persistence, and time delegates.</param>
    /// <param name="registration">The registration identifying the authorization server this call targets.</param>
    /// <param name="context">The per-operation exchange context threaded into the transport and flow-state delegates.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// <see cref="AuthCodeFlowEndpointOutcome.Redirect"/> on success with
    /// <see cref="AuthCodeFlowEndpointResult.RedirectUri"/> set to the authorization
    /// endpoint URI including the PAR <c>request_uri</c>.
    /// </returns>
    public static ValueTask<AuthCodeFlowEndpointResult> HandleParAsync(
        IReadOnlyDictionary<string, string> fields,
        Uri redirectUri,
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        ExchangeContext context,
        CancellationToken cancellationToken) =>
        HandleParAsync(fields, redirectUri, infrastructure, registration, context, resource: null, cancellationToken);


    /// <inheritdoc cref="HandleParAsync(IReadOnlyDictionary{string, string}, Uri, OAuthClientInfrastructure, ClientRegistration, ExchangeContext, CancellationToken)"/>
    /// <param name="fields">
    /// Inbound form fields. A <c>scope</c> field names the requested scope values (RFC 6749 §3.3,
    /// space-delimited) and is sent as given; without one, or with a blank one, the pushed request
    /// carries no <c>scope</c> parameter and the authorization server applies its own default or
    /// refuses (RFC 6749 §3.3). An OpenID Connect request names <c>openid</c> in this field itself
    /// (OpenID Connect Core 1.0 §3.1.2.1). Other required values are taken from
    /// <paramref name="registration"/>.
    /// </param>
    /// <param name="redirectUri">The client's redirect URI to which the authorization response is returned.</param>
    /// <param name="infrastructure">The long-lived infrastructure carrying transport, parsing, persistence, and time delegates.</param>
    /// <param name="registration">The registration identifying the authorization server this call targets.</param>
    /// <param name="context">The per-operation exchange context threaded into the transport and flow-state delegates.</param>
    /// <param name="resource">
    /// The RFC 8707 §2 <c>resource</c> indicator(s) to request (RFC 9126 §2.1 pushes them
    /// alongside the rest of the PAR body). Each entry MUST be one absolute URI — a caller with
    /// several indicators supplies several list entries, which become that many REPEATED
    /// <c>resource</c> occurrences on the wire (<see cref="OutgoingFormFields.Add"/>); a single
    /// entry that itself packs several URIs separated by spaces is a malformed indicator, not a
    /// shorthand for repetition. <see langword="null"/> or empty omits the parameter entirely.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async ValueTask<AuthCodeFlowEndpointResult> HandleParAsync(
        IReadOnlyDictionary<string, string> fields,
        Uri redirectUri,
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        ExchangeContext context,
        IReadOnlyList<string>? resource,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(fields);
        ArgumentNullException.ThrowIfNull(redirectUri);
        ArgumentNullException.ThrowIfNull(infrastructure);
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);

        Result<AuthorizationServerMetadata, AuthCodeFlowEndpointResult> metadataResult =
            await TokenEndpointClientOperations.ResolveValidatedAuthorizationServerMetadataAsync(
                infrastructure, registration, context, cancellationToken).ConfigureAwait(false);
        if(!metadataResult.IsSuccess)
        {
            return metadataResult.Error;
        }

        AuthorizationServerMetadata metadata = metadataResult.Value;

        DateTimeOffset now = infrastructure.TimeProvider.GetUtcNow();
        string state = GenerateEntropyHexString(infrastructure);

        PkceParameters pkce = GeneratePkceParameters(infrastructure.Base64UrlEncoder, infrastructure.MemoryPool);

        ImmutableArray<string> scopes = ReadRequestedScopes(fields);
        ImmutableArray<string> requestedResource = ReadNamedResource(resource);

        var parBody = new ParRequestBody
        {
            ClientId = registration.ClientId.Value,
            CodeChallenge = pkce.EncodedChallenge,
            CodeChallengeMethod = pkce.Method,
            RedirectUri = redirectUri,
            Scopes = scopes,
            State = state
        };

        OutgoingFormFields formFields = EncodeParRequestBody(parBody);

        //RFC 8707 §2 / RFC 9126 §2.1: each resource indicator becomes its OWN occurrence of the
        //resource key on the wire — the genuine multi-resource wire form — never several
        //indicators joined by a space into one occurrence.
        TokenEndpointClientOperations.AddResourceOccurrences(formFields, resource);

        //RFC 9126 section 2: the pushed request carries the whole authorization request, so fields
        //this handler does not own - OID4VCI's authorization_details and issuer_state among them -
        //ride verbatim, exactly as the JAR path already carries them. The flow-owned parameters
        //above always win: an additional field cannot override the client identity, PKCE material,
        //or state this handler just minted, and scope was already folded in.
        AddAdditionalAuthorizationFields(formFields, fields);

        if(TokenEndpointClientOperations.EvaluateOutboundPolicy(metadata.PushedAuthorizationRequestEndpoint!, context, infrastructure) is AuthCodeFlowEndpointResult parPolicyDenial)
        {
            return parPolicyDenial;
        }

        HttpResponseData parHttpResponse;
        try
        {
            parHttpResponse = await infrastructure.SendFormPostAsync(
                metadata.PushedAuthorizationRequestEndpoint!,
                formFields,
                OutgoingHeaders.Empty,
                context,
                cancellationToken).ConfigureAwait(false);
        }
        catch(OperationCanceledException)
        {
            throw;
        }
        catch(Exception ex)
        {
            //The HTTP transport is a caller-registered delegate whose failure vocabulary this handler
            //cannot enumerate; any fault sending the PAR request surfaces as this endpoint's own server
            //error, cancellation excepted above. The transport exception's own text is not part of an
            //OAuth error response, so the description is this fixed sentence; the exception itself is
            //recorded on the current Activity for diagnostics rather than echoed to the caller.
            _ = (Activity.Current?.AddException(ex));

            return AuthCodeFlowEndpointResult.Refused(
                AuthCodeFlowEndpointOutcome.InternalError,
                AuthCodeFlowRefusalOrigin.ClientJudgement,
                OAuthErrors.ServerError,
                "The pushed authorization request could not be sent.");
        }

        Result<ParResponse, OAuthParseError> parResult =
            infrastructure.ParseParResponseAsync(parHttpResponse);

        if(!parResult.IsSuccess)
        {
            return TokenEndpointClientOperations.BuildEndpointResultFromParseError(parResult.Error!);
        }

        ParResponse parResponse = parResult.Value;
        ParCompletedState parCompleted = new()
        {
            FlowId = state,
            ExpectedIssuer = registration.AuthorizationServerIssuer.OriginalString,
            EnteredAt = now,
            ExpiresAt = now.AddSeconds(parResponse.ExpiresIn),
            Kind = FlowKind.AuthCodeClient,
            Pkce = pkce,
            RedirectUri = redirectUri,
            Scopes = scopes,
            Resource = requestedResource,
            Par = parResponse
        };

        await infrastructure.SaveStateAsync(parCompleted, context, cancellationToken).ConfigureAwait(false);

        Uri authorizationUri = BuildAuthorizationRedirectUri(
            metadata.AuthorizationEndpoint!,
            registration.ClientId.Value,
            parResponse.RequestUri);

        return AuthCodeFlowEndpointResult.Redirected(authorizationUri);
    }


    /// <summary>
    /// Starts a plain (non-PAR, non-JAR) authorization request per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1">RFC 6749 §4.1.1</see>:
    /// resolves and validates the authorization server metadata exactly as
    /// <see cref="HandleParAsync(IReadOnlyDictionary{string, string}, Uri, OAuthClientInfrastructure, ClientRegistration, ExchangeContext, IReadOnlyList{string}?, CancellationToken)"/>
    /// does, refuses before building anything when the metadata requires pushed authorization
    /// requests, mints <c>state</c> and a fresh PKCE pair through the same private helpers PAR uses,
    /// and returns a redirect straight to the authorization endpoint carrying the request on the
    /// front channel instead of a <c>request_uri</c>.
    /// </summary>
    /// <remarks>
    /// This leg has no PAR response of its own, so — following the precedent
    /// <see cref="HandleJarAuthorizeAsync(AuthCodeStartJarAuthorizeOptions, OAuthClientInfrastructure, ClientRegistration, ExchangeContext, CancellationToken)"/>
    /// sets for the other request-object-by-value start — the persisted
    /// <see cref="ParCompletedState"/> carries a synthesised <see cref="ParResponse"/> whose
    /// <see cref="ParResponse.RequestUri"/> is the authorization redirect URI itself and whose
    /// <see cref="ParResponse.ExpiresIn"/> is <paramref name="requestLifetime"/> in seconds; the rest
    /// of the flow (callback, token) never reads <see cref="ParCompletedState.Par"/> again.
    /// </remarks>
    /// <param name="fields">
    /// Inbound form fields. A <c>scope</c> field names the requested scope values (RFC 6749 §3.3,
    /// space-delimited) and is sent as given; without one, or with a blank one, the redirect's query
    /// carries no <c>scope</c> parameter and the authorization server applies its own default or
    /// refuses (RFC 6749 §3.3). An OpenID Connect request names <c>openid</c> in this field itself
    /// (OpenID Connect Core 1.0 §3.1.2.1). Other required values are taken from
    /// <paramref name="registration"/>. Any field outside
    /// <see cref="AuthorizationFlowOwnedFieldNames"/> rides onto the authorization redirect's query
    /// verbatim, but never overrides a value this handler mints (RFC 6749 §4.1.1's
    /// <c>response_type</c>/<c>client_id</c>/<c>redirect_uri</c>/<c>state</c>, or RFC 7636 §4.3's
    /// <c>code_challenge</c>/<c>code_challenge_method</c>).
    /// </param>
    /// <param name="redirectUri">The client's redirect URI to which the authorization response is returned.</param>
    /// <param name="infrastructure">The long-lived infrastructure carrying transport, parsing, persistence, and time delegates.</param>
    /// <param name="registration">The registration identifying the authorization server this call targets.</param>
    /// <param name="context">The per-operation exchange context threaded into the flow-state delegates.</param>
    /// <param name="resource">
    /// The RFC 8707 §2 <c>resource</c> indicator(s) to request, each becoming its own repeated
    /// occurrence on the redirect query (<see cref="TokenEndpointClientOperations.AddResourceOccurrences"/>) — the same convention
    /// <see cref="HandleParAsync(IReadOnlyDictionary{string, string}, Uri, OAuthClientInfrastructure, ClientRegistration, ExchangeContext, IReadOnlyList{string}?, CancellationToken)"/>
    /// uses. <see langword="null"/> or empty omits the parameter entirely.
    /// </param>
    /// <param name="requestLifetime">
    /// How long this pending authorization stays redeemable at
    /// <see cref="HandleCallbackAsync(IReadOnlyDictionary{string, string}, OAuthClientInfrastructure, ClientRegistration, ExchangeContext, CancellationToken)"/>
    /// before it expires. RFC 6749 §4.1.1 defines no lifetime for this leg — unlike RFC 9126 §2.2's
    /// PAR <c>expires_in</c> — so the caller decides.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// <see cref="AuthCodeFlowEndpointOutcome.Redirect"/> on success with
    /// <see cref="AuthCodeFlowEndpointResult.RedirectUri"/> set to the authorization endpoint URI
    /// carrying the request parameters directly; <see cref="AuthCodeFlowEndpointOutcome.BadRequest"/>
    /// with <c>ErrorCode</c> <c>invalid_request</c> when the resolved metadata's
    /// <see cref="AuthorizationServerMetadata.RequirePushedAuthorizationRequests"/> is set
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9126#section-5">RFC 9126 §5</see>).
    /// </returns>
    internal static ValueTask<AuthCodeFlowEndpointResult> HandleDirectAuthorizeStartAsync(
        IReadOnlyDictionary<string, string> fields,
        Uri redirectUri,
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        ExchangeContext context,
        IReadOnlyList<string>? resource,
        TimeSpan requestLifetime,
        CancellationToken cancellationToken) =>
        StartDirectAuthorizationAsync(
            fields, redirectUri, infrastructure, registration, context, resource, requestLifetime, mintsNonce: false, cancellationToken);


    /// <summary>
    /// Starts an OpenID Connect authentication request of the authorization code flow
    /// (<see href="https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest">OpenID Connect Core 1.0 §3.1.2.1</see>)
    /// as <see cref="HandleDirectAuthorizeStartAsync"/> starts a plain one, and mints beside its <c>state</c> and PKCE pair a
    /// fresh <c>nonce</c> from <see cref="OAuthClientInfrastructure.FillEntropy"/>, sent on the redirect's query and held in
    /// the persisted <see cref="ParCompletedState.Nonce"/>, so the ID Token the code is exchanged for is held to it
    /// (<see cref="OpenIdSignInHandlers.ExchangeOpenIdTokenAsync"/>; §3.1.3.7 item 11). A caller's additional field named <c>nonce</c> is dropped:
    /// the flow mints its own.
    /// </summary>
    /// <param name="fields">
    /// Inbound form fields. Its <c>scope</c> field names the requested scope values, <c>openid</c> among them (§3.1.2.1:
    /// "OpenID Connect requests MUST contain the openid scope value."), sent as given.
    /// </param>
    /// <param name="redirectUri">The client's redirect URI to which the authorization response is returned.</param>
    /// <param name="infrastructure">The long-lived infrastructure carrying transport, parsing, persistence, and time delegates.</param>
    /// <param name="registration">The registration identifying the OpenID Provider this call targets.</param>
    /// <param name="context">The per-operation exchange context threaded into the flow-state delegates.</param>
    /// <param name="resource">The RFC 8707 §2 <c>resource</c> indicator(s) to request; <see langword="null"/> or empty omits the parameter.</param>
    /// <param name="requestLifetime">How long this pending authentication request stays redeemable at the callback.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>As <see cref="HandleDirectAuthorizeStartAsync"/> returns.</returns>
    internal static ValueTask<AuthCodeFlowEndpointResult> HandleOpenIdAuthorizeStartAsync(
        IReadOnlyDictionary<string, string> fields,
        Uri redirectUri,
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        ExchangeContext context,
        IReadOnlyList<string>? resource,
        TimeSpan requestLifetime,
        CancellationToken cancellationToken) =>
        StartDirectAuthorizationAsync(
            fields, redirectUri, infrastructure, registration, context, resource, requestLifetime, mintsNonce: true, cancellationToken);


    /// <summary>
    /// The one start of a direct authorization request, plain or OpenID Connect: the metadata resolved and validated, a
    /// pushed-only server refused, <c>state</c> and the PKCE pair minted, and the <c>nonce</c> where the request is an
    /// OpenID Connect one, each held in the persisted <see cref="ParCompletedState"/>.
    /// </summary>
    /// <param name="fields">Inbound form fields.</param>
    /// <param name="redirectUri">The client's redirect URI.</param>
    /// <param name="infrastructure">The long-lived infrastructure.</param>
    /// <param name="registration">The registration identifying the authorization server.</param>
    /// <param name="context">The per-operation exchange context.</param>
    /// <param name="resource">The RFC 8707 §2 <c>resource</c> indicator(s) to request.</param>
    /// <param name="requestLifetime">How long the pending request stays redeemable.</param>
    /// <param name="mintsNonce">Whether the request is an OpenID Connect one, minting and holding a <c>nonce</c>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The redirect, or the refusal.</returns>
    private static async ValueTask<AuthCodeFlowEndpointResult> StartDirectAuthorizationAsync(
        IReadOnlyDictionary<string, string> fields,
        Uri redirectUri,
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        ExchangeContext context,
        IReadOnlyList<string>? resource,
        TimeSpan requestLifetime,
        bool mintsNonce,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(fields);
        ArgumentNullException.ThrowIfNull(redirectUri);
        ArgumentNullException.ThrowIfNull(infrastructure);
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);

        Result<AuthorizationServerMetadata, AuthCodeFlowEndpointResult> metadataResult =
            await TokenEndpointClientOperations.ResolveValidatedAuthorizationServerMetadataAsync(
                infrastructure, registration, context, cancellationToken).ConfigureAwait(false);
        if(!metadataResult.IsSuccess)
        {
            return metadataResult.Error;
        }

        AuthorizationServerMetadata metadata = metadataResult.Value;

        //RFC 9126 §5: "require_pushed_authorization_requests: Boolean parameter indicating whether
        //the authorization server accepts authorization request data only via PAR. If omitted, the
        //default value is 'false'." Refused before state, PKCE, or the redirect URI are built.
        if(metadata.RequirePushedAuthorizationRequests)
        {
            return AuthCodeFlowEndpointResult.Refused(
                AuthCodeFlowEndpointOutcome.BadRequest,
                AuthCodeFlowRefusalOrigin.ClientJudgement,
                OAuthErrors.InvalidRequest,
                "The authorization server requires Pushed Authorization Requests " +
                "(RFC 9126 §5 require_pushed_authorization_requests); a direct authorization " +
                "request is not accepted.");
        }

        DateTimeOffset now = infrastructure.TimeProvider.GetUtcNow();
        string state = GenerateEntropyHexString(infrastructure);
        PkceParameters pkce = GeneratePkceParameters(infrastructure.Base64UrlEncoder, infrastructure.MemoryPool);
        var nonce = mintsNonce ? GenerateEntropyHexString(infrastructure) : null;

        ImmutableArray<string> scopes = ReadRequestedScopes(fields);
        ImmutableArray<string> requestedResource = ReadNamedResource(resource);

        Uri authorizationUri = BuildDirectAuthorizeRedirectUri(
            metadata.AuthorizationEndpoint!, registration.ClientId.Value, redirectUri, scopes, state, nonce, pkce, resource, fields);

        ParCompletedState parCompleted = new()
        {
            FlowId = state,
            ExpectedIssuer = registration.AuthorizationServerIssuer.OriginalString,
            EnteredAt = now,
            ExpiresAt = now.Add(requestLifetime),
            Kind = FlowKind.AuthCodeClient,
            Pkce = pkce,
            RedirectUri = redirectUri,
            Scopes = scopes,
            Resource = requestedResource,
            Nonce = nonce,
            Par = new ParResponse(authorizationUri, (int)requestLifetime.TotalSeconds)
        };

        await infrastructure.SaveStateAsync(parCompleted, context, cancellationToken).ConfigureAwait(false);

        return AuthCodeFlowEndpointResult.Redirected(authorizationUri);
    }


    /// <summary>
    /// Builds the direct authorization redirect URI per RFC 6749 §4.1.1: <c>response_type=code</c>,
    /// <c>client_id</c>, <c>redirect_uri</c>, <c>scope</c> when <paramref name="scopes"/> names at
    /// least one value (<see cref="AddScopeWhenNamed"/>), and <c>state</c>, plus the PKCE pair per
    /// RFC 7636 §4.3, each <paramref name="resource"/> entry as its own repeated occurrence, and the
    /// caller's <paramref name="additionalFields"/> that are not one of
    /// <see cref="AuthorizationFlowOwnedFieldNames"/>.
    /// </summary>
    /// <param name="authorizationEndpoint">The authorization endpoint the redirect targets.</param>
    /// <param name="clientId">The client identifier sent as <c>client_id</c>.</param>
    /// <param name="redirectUri">The redirect URI sent as <c>redirect_uri</c>.</param>
    /// <param name="scopes">The scope values the caller named; empty sends no <c>scope</c> parameter.</param>
    /// <param name="state">The <c>state</c> value this start minted.</param>
    /// <param name="nonce">The <c>nonce</c> an OpenID Connect start minted, or <see langword="null"/> for a plain request.</param>
    /// <param name="pkce">The PKCE pair whose challenge and method are sent.</param>
    /// <param name="resource">The RFC 8707 resource indicators, each sent as its own occurrence.</param>
    /// <param name="additionalFields">The caller's further fields, flow-owned names skipped.</param>
    /// <returns>The authorization endpoint URI carrying the request on its query.</returns>
    private static Uri BuildDirectAuthorizeRedirectUri(
        Uri authorizationEndpoint,
        string clientId,
        Uri redirectUri,
        ImmutableArray<string> scopes,
        string state,
        string? nonce,
        PkceParameters pkce,
        IReadOnlyList<string>? resource,
        IReadOnlyDictionary<string, string> additionalFields)
    {
        OutgoingFormFields query = new()
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.ClientId] = clientId,
            [OAuthRequestParameterNames.RedirectUri] = redirectUri.ToString()
        };

        AddScopeWhenNamed(query, scopes);
        query[OAuthRequestParameterNames.State] = state;

        if(nonce is not null)
        {
            query[OAuthRequestParameterNames.Nonce] = nonce;
        }

        query[OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge;
        query[OAuthRequestParameterNames.CodeChallengeMethod] = pkce.Method.ToString().ToUpperInvariant();

        TokenEndpointClientOperations.AddResourceOccurrences(query, resource);

        //The nonce an OpenID Connect start minted is the flow's own, so a caller's field of that name is dropped as every other
        //flow-owned name is.
        AddAdditionalAuthorizationFields(
            query,
            nonce is null
                ? additionalFields
                : additionalFields.Where(static field => !string.Equals(field.Key, OAuthRequestParameterNames.Nonce, StringComparison.Ordinal))
                    .ToDictionary(static field => field.Key, static field => field.Value, StringComparer.Ordinal));

        StringBuilder builder = new();
        _ = builder.Append(authorizationEndpoint);
        char separator = '?';
        foreach((string key, string value) in query)
        {
            _ = builder.Append(separator);
            _ = builder.Append(Uri.EscapeDataString(key));
            _ = builder.Append('=');
            _ = builder.Append(Uri.EscapeDataString(value));

            separator = '&';
        }

        return new Uri(builder.ToString());
    }


    /// <summary>
    /// Handles the authorization server callback. Loads the flow state by the
    /// <c>state</c> parameter, runs the profile-specific validation rules, and
    /// persists <see cref="AuthorizationCodeReceivedState"/> state ready for token exchange.
    /// </summary>
    /// <param name="fields">
    /// The callback query parameters. Must include <c>code</c> and <c>state</c>.
    /// HAIP 1.0 additionally requires <c>iss</c>.
    /// </param>
    /// <param name="infrastructure">The long-lived infrastructure carrying transport, parsing, persistence, and time delegates.</param>
    /// <param name="registration">The registration identifying the authorization server this call targets.</param>
    /// <param name="context">The per-operation exchange context threaded into the transport and flow-state delegates.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async ValueTask<AuthCodeFlowEndpointResult> HandleCallbackAsync(
        IReadOnlyDictionary<string, string> fields,
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(fields);
        ArgumentNullException.ThrowIfNull(infrastructure);
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);

        Result<AuthorizationServerMetadata, AuthCodeFlowEndpointResult> metadataResult =
            await TokenEndpointClientOperations.ResolveValidatedAuthorizationServerMetadataAsync(
                infrastructure, registration, context, cancellationToken).ConfigureAwait(false);
        if(!metadataResult.IsSuccess)
        {
            return metadataResult.Error;
        }

        //RFC 6749 §4.1.2.1 Authorization Error Response — error is present instead of code.
        //RFC 9207 §2.4/§4: "clients MUST NOT assume that the error originates from the
        //intended authorization server," so the error response is judged by the callback rules the
        //registration's profile holds a success response to before the error is trusted.
        if(fields.TryGetValue(OAuthRequestParameterNames.Error, out string? errorCode))
        {
            return await BuildCallbackErrorResultAsync(
                fields, infrastructure, registration, context, errorCode, cancellationToken).ConfigureAwait(false);
        }

        if(!fields.TryGetValue(OAuthRequestParameterNames.Code, out string? code) ||
           !fields.TryGetValue(OAuthRequestParameterNames.State, out string? state))
        {
            return AuthCodeFlowEndpointResult.Refused(
                AuthCodeFlowEndpointOutcome.BadRequest,
                AuthCodeFlowRefusalOrigin.ClientJudgement,
                OAuthErrors.InvalidRequest,
                "Missing required callback parameters.");
        }

        FlowState? loaded = await infrastructure.LoadStateAsync(
            state, context, cancellationToken).ConfigureAwait(false);

        if(loaded is not ParCompletedState parCompleted)
        {
            return AuthCodeFlowEndpointResult.Refused(
                AuthCodeFlowEndpointOutcome.BadRequest,
                AuthCodeFlowRefusalOrigin.ClientJudgement,
                OAuthErrors.InvalidRequest,
                "No active flow found for the supplied state value.");
        }

        //Client-side flow does not sit inside server dispatch, so there is no
        //resolved per-request policy context to thread in. An empty
        //ExchangeContext satisfies the required-field contract and keeps
        //policy reads on the client-side validators returning library
        //defaults (the strict reading) — which is the intended behaviour for
        //out-of-dispatch validators.
        ValidationContext validationContext = new()
        {
            Context = [],
            Fields = fields,
            FlowState = parCompleted,
            TimeProvider = infrastructure.TimeProvider,
            Now = infrastructure.TimeProvider.GetUtcNow()
        };

        ClaimIssuer<ValidationContext> callbackValidator =
            infrastructure.ResolveCallbackValidator(registration, infrastructure.TimeProvider);

        ClaimIssueResult validationResult = await callbackValidator.GenerateClaimsAsync(
            validationContext, parCompleted.FlowId, cancellationToken).ConfigureAwait(false);

        if(!validationResult.IsComplete
            || validationResult.Claims.Any(static c => c.Outcome != ClaimOutcome.Success))
        {
            return AuthCodeFlowEndpointResult.Refused(
                AuthCodeFlowEndpointOutcome.BadRequest,
                AuthCodeFlowRefusalOrigin.ClientJudgement,
                OAuthErrors.InvalidRequest,
                "Callback validation failed.",
                (IReadOnlyList<Claim>)validationResult.Claims);
        }

        string? iss = fields.TryGetValue(OAuthRequestParameterNames.Iss, out string? issValue)
            ? issValue
            : null;

        //RFC 9207 §2.4 / §4 — when the application supplies a known-authorization-server
        //resolver, a PRESENT iss must additionally resolve to a positively known,
        //uniquely-configured authorization server that ordinally matches this
        //registration's pinned issuer. This closes the mix-up case the per-flow issuer
        //check cannot: an iss that string-matches the flow's expected issuer yet does not
        //correspond to a known, uniquely-claimed authorization server in the application's
        //own configuration. An absent iss is out of scope here — the callback profile
        //governs whether iss presence is required — and a null resolver opts out entirely.
        if(iss is not null
            && infrastructure.IsKnownAuthorizationServerIssuer is not null
            && !AuthorizationServerIssuerValidation.IsAuthorizationResponseIssuerValid(
                iss, registration.AuthorizationServerIssuer, infrastructure.IsKnownAuthorizationServerIssuer))
        {
            return AuthCodeFlowEndpointResult.Refused(
                AuthCodeFlowEndpointOutcome.BadRequest,
                AuthCodeFlowRefusalOrigin.ClientJudgement,
                OAuthErrors.InvalidRequest,
                "The iss parameter does not resolve to a known, uniquely-configured authorization " +
                "server matching this registration (RFC 9207 §2.4, §4).");
        }

        DateTimeOffset now = infrastructure.TimeProvider.GetUtcNow();

        AuthorizationCodeReceivedState codeReceived = new()
        {
            FlowId = parCompleted.FlowId,
            ExpectedIssuer = parCompleted.ExpectedIssuer,
            EnteredAt = now,
            ExpiresAt = parCompleted.ExpiresAt,
            Kind = FlowKind.AuthCodeClient,
            Code = code,
            State = state,
            IssuerId = iss,
            Pkce = parCompleted.Pkce,
            RedirectUri = parCompleted.RedirectUri,
            Resource = parCompleted.Resource,
            Nonce = parCompleted.Nonce
        };

        await infrastructure.SaveStateAsync(codeReceived, context, cancellationToken).ConfigureAwait(false);

        return AuthCodeFlowEndpointResult.Succeeded(new Dictionary<string, object> { [AuthCodeFlowRoutes.FlowIdField] = codeReceived.FlowId });
    }


    /// <inheritdoc cref="HandleTokenAsync(IReadOnlyDictionary{string, string}, OAuthClientInfrastructure, ClientRegistration, ExchangeContext, ClientAssertionOptions?, CancellationToken)"/>
    public static ValueTask<AuthCodeFlowEndpointResult> HandleTokenAsync(
        IReadOnlyDictionary<string, string> fields,
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        ExchangeContext context,
        CancellationToken cancellationToken) =>
        HandleTokenAsync(fields, infrastructure, registration, context, clientAssertionOptions: null, cancellationToken);


    /// <summary>
    /// Handles a token exchange request. Loads the <see cref="AuthorizationCodeReceivedState"/>
    /// state by <c>flow_id</c>, POSTs to the token endpoint with the code, the PKCE verifier, and
    /// the confidential-client authentication <see cref="ClientRegistration.AuthenticationMethod"/>
    /// selects (RFC 6749 §3.2.1 / RFC 7523 §2.2), and persists <see cref="TokenReceivedState"/> state.
    /// </summary>
    /// <param name="fields">
    /// Inbound form fields. Must include <c>flow_id</c> to locate the pending state.
    /// </param>
    /// <param name="infrastructure">The long-lived infrastructure carrying transport, parsing, persistence, and time delegates.</param>
    /// <param name="registration">The registration identifying the authorization server this call targets.</param>
    /// <param name="context">The per-operation exchange context threaded into the transport and flow-state delegates.</param>
    /// <param name="clientAssertionOptions">
    /// The <c>private_key_jwt</c> client-assertion signing inputs (RFC 7523 §2.2): the <c>kid</c>,
    /// the header/payload serialisers, and the assertion lifetime. Required when
    /// <see cref="ClientRegistration.AuthenticationMethod"/> is
    /// <see cref="ClientAuthenticationMethod.PrivateKeyJwt"/> or <see cref="ClientAuthenticationMethod.ClientSecretJwt"/>
    /// — the signing key or the client secret itself is read from
    /// <see cref="ClientRegistration.AuthenticationKeyMaterial"/>. Ignored for every other method.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static ValueTask<AuthCodeFlowEndpointResult> HandleTokenAsync(
        IReadOnlyDictionary<string, string> fields,
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        ExchangeContext context,
        ClientAssertionOptions? clientAssertionOptions,
        CancellationToken cancellationToken) =>
        HandleTokenAsync(fields, infrastructure, registration, context, clientAssertionOptions, resource: null, cancellationToken);


    /// <inheritdoc cref="HandleTokenAsync(IReadOnlyDictionary{string, string}, OAuthClientInfrastructure, ClientRegistration, ExchangeContext, ClientAssertionOptions?, CancellationToken)"/>
    /// <param name="fields">
    /// Inbound form fields. Must include <c>flow_id</c> to locate the pending state.
    /// </param>
    /// <param name="infrastructure">The long-lived infrastructure carrying transport, parsing, persistence, and time delegates.</param>
    /// <param name="registration">The registration identifying the authorization server this call targets.</param>
    /// <param name="context">The per-operation exchange context threaded into the transport and flow-state delegates.</param>
    /// <param name="clientAssertionOptions">
    /// The <c>private_key_jwt</c> client-assertion signing inputs (RFC 7523 §2.2): the <c>kid</c>,
    /// the header/payload serialisers, and the assertion lifetime. Required when
    /// <see cref="ClientRegistration.AuthenticationMethod"/> is
    /// <see cref="ClientAuthenticationMethod.PrivateKeyJwt"/> or <see cref="ClientAuthenticationMethod.ClientSecretJwt"/>
    /// — the signing key or the client secret itself is read from
    /// <see cref="ClientRegistration.AuthenticationKeyMaterial"/>. Ignored for every other method.
    /// </param>
    /// <param name="resource">
    /// The RFC 8707 §2.2 Figure 3 code-redemption <c>resource</c> indicator(s) narrowing the
    /// minted access token to a subset of what PAR/authorize granted. Each entry MUST be one
    /// absolute URI — a caller with several indicators supplies several list entries, which
    /// become that many REPEATED <c>resource</c> occurrences on the wire
    /// (<see cref="OutgoingFormFields.Add"/>); a single entry that itself packs several URIs
    /// separated by spaces is a malformed indicator, not a shorthand for repetition.
    /// <see langword="null"/>, or a list naming no non-blank entry, names the indicators the
    /// authorization request of this flow named (<see cref="AuthorizationCodeReceivedState.Resource"/>):
    /// the MCP authorization specification says the parameter "MUST be included in both
    /// authorization requests and token requests". A flow whose authorization request named none
    /// sends none, leaving the full granted set in force.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async ValueTask<AuthCodeFlowEndpointResult> HandleTokenAsync(
        IReadOnlyDictionary<string, string> fields,
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        ExchangeContext context,
        ClientAssertionOptions? clientAssertionOptions,
        IReadOnlyList<string>? resource,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(fields);
        ArgumentNullException.ThrowIfNull(infrastructure);
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);

        var assertionKey = TokenEndpointClientOperations.ResolveClientAssertionKey(registration, clientAssertionOptions);

        if(!assertionKey.IsSuccess)
        {
            return assertionKey.Error;
        }

        Result<AuthorizationServerMetadata, AuthCodeFlowEndpointResult> metadataResult =
            await TokenEndpointClientOperations.ResolveValidatedAuthorizationServerMetadataAsync(
                infrastructure, registration, context, cancellationToken).ConfigureAwait(false);
        if(!metadataResult.IsSuccess)
        {
            return metadataResult.Error;
        }

        AuthorizationServerMetadata metadata = metadataResult.Value;

        if(!fields.TryGetValue(AuthCodeFlowRoutes.FlowIdField, out string? flowId))
        {
            return AuthCodeFlowEndpointResult.Refused(
                AuthCodeFlowEndpointOutcome.BadRequest,
                AuthCodeFlowRefusalOrigin.ClientJudgement,
                OAuthErrors.InvalidRequest,
                $"Missing required parameter: {AuthCodeFlowRoutes.FlowIdField}.");
        }

        FlowState? loaded = await infrastructure.LoadStateAsync(
            flowId, context, cancellationToken).ConfigureAwait(false);

        if(loaded is not AuthorizationCodeReceivedState codeState)
        {
            return AuthCodeFlowEndpointResult.Refused(
                AuthCodeFlowEndpointOutcome.BadRequest,
                AuthCodeFlowRefusalOrigin.ClientJudgement,
                OAuthErrors.InvalidRequest,
                $"No code pending token exchange for the supplied {AuthCodeFlowRoutes.FlowIdField}.");
        }

        DateTimeOffset now = infrastructure.TimeProvider.GetUtcNow();
        if(now > codeState.ExpiresAt)
        {
            return AuthCodeFlowEndpointResult.Refused(
                AuthCodeFlowEndpointOutcome.BadRequest,
                AuthCodeFlowRefusalOrigin.ClientJudgement,
                OAuthErrors.InvalidRequest,
                "Flow has expired.");
        }

        //RFC 8707 §2.2 Figure 3: a resource named at code redemption narrows the minted access
        //token to a subset of what PAR/authorize granted — each entry becomes its OWN repeated
        //resource occurrence on the wire, the same convention HandleParAsync (resource) and
        //RefreshAsync (RefreshTokenRequest.Resource) use on their legs. A caller naming none
        //sends the set the authorization request named (MCP authorization: "MUST be included in
        //both authorization requests and token requests").
        OutgoingFormFields tokenFields = EncodeTokenRequest(
            registration.ClientId.Value,
            codeState.Code,
            codeState.RedirectUri,
            codeState.Pkce,
            SelectTokenRequestResource(ReadNamedResource(resource), codeState.Resource));

        Result<HttpResponseData, AuthCodeFlowEndpointResult> tokenSendResult = await TokenEndpointClientOperations.SendTokenRequestWithDpopRetryAsync(
            infrastructure, metadata.TokenEndpoint!, tokenFields,
            (attemptNow, ct) => TokenEndpointClientOperations.AttachClientAuthenticationAsync(
                tokenFields, registration, metadata.TokenEndpoint!, assertionKey.Value, clientAssertionOptions,
                infrastructure, attemptNow, context, ct),
            context, cancellationToken)
            .ConfigureAwait(false);
        if(!tokenSendResult.IsSuccess)
        {
            return tokenSendResult.Error!;
        }

        Result<TokenResponse, OAuthParseError> tokenResult =
            infrastructure.ParseTokenResponseAsync(tokenSendResult.Value, now);

        if(!tokenResult.IsSuccess)
        {
            return TokenEndpointClientOperations.BuildEndpointResultFromParseError(tokenResult.Error!);
        }

        TokenResponse tokenResponse = tokenResult.Value;
        var tokenReceived = new TokenReceivedState
        {
            FlowId = codeState.FlowId,
            ExpectedIssuer = codeState.ExpectedIssuer,
            EnteredAt = now,
            ExpiresAt = codeState.ExpiresAt,
            Kind = FlowKind.AuthCodeClient,
            AccessToken = tokenResponse.AccessToken,
            TokenType = tokenResponse.TokenType,
            ExpiresIn = tokenResponse.ExpiresIn,
            RefreshToken = tokenResponse.RefreshToken,
            Scope = tokenResponse.Scope,
            IdToken = tokenResponse.IdToken,
            ReceivedAt = now
        };

        await infrastructure.SaveStateAsync(tokenReceived, context, cancellationToken).ConfigureAwait(false);

        var body = new Dictionary<string, object>
        {
            [OAuthRequestParameterNames.AccessToken] = tokenResponse.AccessToken,
            [OAuthRequestParameterNames.TokenType] = tokenResponse.TokenType,
            [OAuthRequestParameterNames.ExpiresIn] = tokenResponse.ExpiresIn ?? 0,
            [OAuthRequestParameterNames.Scope] = tokenResponse.Scope ?? string.Empty
        };

        //A refresh token MAY be issued on the auth-code exchange (RFC 6749 §5.1, e.g.
        //when offline access is granted). It is parsed and persisted, so surface it to
        //the caller too — mirroring the refresh response below.
        if(tokenResponse.RefreshToken is not null)
        {
            body[OAuthRequestParameterNames.RefreshToken] = tokenResponse.RefreshToken;
        }

        //An OpenID Connect token response carries an ID Token alongside the access
        //token (OpenID Connect Core 1.0 §3.1.3.3). Surface it so an OIDC relying party
        //can read it — e.g. to later pass it as id_token_hint to the end_session endpoint.
        if(tokenResponse.IdToken is not null)
        {
            body[OAuthRequestParameterNames.IdToken] = tokenResponse.IdToken;
        }

        return AuthCodeFlowEndpointResult.Succeeded(body);
    }


    /// <summary>
    /// Handles a token revocation request. POSTs to the revocation endpoint per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7009">RFC 7009</see>.
    /// </summary>
    /// <param name="fields">
    /// Inbound form fields. Must include <c>token</c>; optionally <c>token_type_hint</c>.
    /// </param>
    /// <param name="infrastructure">The long-lived infrastructure carrying transport, parsing, persistence, and time delegates.</param>
    /// <param name="registration">The registration identifying the authorization server this call targets.</param>
    /// <param name="context">The per-operation exchange context threaded into the transport and flow-state delegates.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async ValueTask<AuthCodeFlowEndpointResult> HandleRevocationAsync(
        IReadOnlyDictionary<string, string> fields,
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(fields);
        ArgumentNullException.ThrowIfNull(infrastructure);
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);

        Result<AuthorizationServerMetadata, AuthCodeFlowEndpointResult> metadataResult =
            await TokenEndpointClientOperations.ResolveValidatedAuthorizationServerMetadataAsync(
                infrastructure, registration, context, cancellationToken).ConfigureAwait(false);
        if(!metadataResult.IsSuccess)
        {
            return metadataResult.Error;
        }

        AuthorizationServerMetadata metadata = metadataResult.Value;

        if(metadata.RevocationEndpoint is null)
        {
            return AuthCodeFlowEndpointResult.Refused(
                AuthCodeFlowEndpointOutcome.BadRequest,
                AuthCodeFlowRefusalOrigin.ClientJudgement,
                OAuthErrors.UnsupportedTokenType,
                "This authorization server does not support token revocation.");
        }

        if(!fields.TryGetValue(OAuthRequestParameterNames.Token, out string? token))
        {
            return AuthCodeFlowEndpointResult.Refused(
                AuthCodeFlowEndpointOutcome.BadRequest,
                AuthCodeFlowRefusalOrigin.ClientJudgement,
                OAuthErrors.InvalidRequest,
                $"Missing required parameter: {OAuthRequestParameterNames.Token}.");
        }

        var revocationFields = new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.ClientId] = registration.ClientId.Value,
            [OAuthRequestParameterNames.Token] = token
        };

        if(fields.TryGetValue(OAuthRequestParameterNames.TokenTypeHint, out string? hint))
        {
            revocationFields[OAuthRequestParameterNames.TokenTypeHint] = hint;
        }

        if(TokenEndpointClientOperations.EvaluateOutboundPolicy(metadata.RevocationEndpoint, context, infrastructure) is AuthCodeFlowEndpointResult revocationPolicyDenial)
        {
            return revocationPolicyDenial;
        }

        //RFC 7009 §2.2 — the revocation endpoint returns 200 with an empty body on
        //success. The response body is not parsed; transport errors are surfaced via
        //exception from the delegate.
        _ = await infrastructure.SendFormPostAsync(
            metadata.RevocationEndpoint,
            revocationFields,
            OutgoingHeaders.Empty,
            context,
            cancellationToken).ConfigureAwait(false);

        return AuthCodeFlowEndpointResult.Succeeded(null);
    }


    /// <inheritdoc cref="RefreshAsync(RefreshTokenRequest, OAuthClientInfrastructure, ClientRegistration, ExchangeContext, ClientAssertionOptions?, CancellationToken)"/>
    public static ValueTask<AuthCodeFlowEndpointResult> RefreshAsync(
        RefreshTokenRequest request,
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        ExchangeContext context,
        CancellationToken cancellationToken) =>
        RefreshAsync(request, infrastructure, registration, context, clientAssertionOptions: null, cancellationToken);


    /// <summary>
    /// Refreshes an access token using a refresh token. Independent of the state
    /// machine — call this when the stored access token has expired. Attaches
    /// confidential-client authentication per <see cref="ClientRegistration.AuthenticationMethod"/>
    /// the same way the code-exchange leg does (<see cref="TokenEndpointClientOperations.AttachClientAuthenticationAsync"/>,
    /// RFC 6749 §6, §3.2.1), and — the same way the code-exchange leg does — attaches a DPoP proof
    /// and honours a <c>use_dpop_nonce</c> retry (<see cref="TokenEndpointClientOperations.SendTokenRequestWithDpopRetryAsync"/>,
    /// RFC 9449 §8.1) whenever <paramref name="infrastructure"/> is wired for DPoP, so a
    /// DPoP-sender-constrained refresh token redeems the same way a fresh access token does.
    /// </summary>
    /// <param name="request">The refresh request parameters.</param>
    /// <param name="infrastructure">The long-lived infrastructure carrying transport, parsing, persistence, and time delegates.</param>
    /// <param name="registration">The registration identifying the authorization server this call targets.</param>
    /// <param name="context">The per-operation exchange context threaded into the transport and flow-state delegates.</param>
    /// <param name="clientAssertionOptions">
    /// The <c>private_key_jwt</c> client-assertion signing inputs (RFC 7523 §2.2). Required when
    /// <see cref="ClientRegistration.AuthenticationMethod"/> is
    /// <see cref="ClientAuthenticationMethod.PrivateKeyJwt"/> or <see cref="ClientAuthenticationMethod.ClientSecretJwt"/>,
    /// whose assertion is MACed under the client secret with no <c>kid</c>; ignored for every other method.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async ValueTask<AuthCodeFlowEndpointResult> RefreshAsync(
        RefreshTokenRequest request,
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        ExchangeContext context,
        ClientAssertionOptions? clientAssertionOptions,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(infrastructure);
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);

        var assertionKey = TokenEndpointClientOperations.ResolveClientAssertionKey(registration, clientAssertionOptions);

        if(!assertionKey.IsSuccess)
        {
            return assertionKey.Error;
        }

        Result<AuthorizationServerMetadata, AuthCodeFlowEndpointResult> metadataResult =
            await TokenEndpointClientOperations.ResolveValidatedAuthorizationServerMetadataAsync(
                infrastructure, registration, context, cancellationToken).ConfigureAwait(false);
        if(!metadataResult.IsSuccess)
        {
            return metadataResult.Error;
        }

        AuthorizationServerMetadata metadata = metadataResult.Value;

        OutgoingFormFields refreshFields = EncodeRefreshRequest(registration.ClientId.Value, request);

        DateTimeOffset now = infrastructure.TimeProvider.GetUtcNow();
        Result<HttpResponseData, AuthCodeFlowEndpointResult> refreshSendResult = await TokenEndpointClientOperations.SendTokenRequestWithDpopRetryAsync(
            infrastructure, metadata.TokenEndpoint!, refreshFields,
            (attemptNow, ct) => TokenEndpointClientOperations.AttachClientAuthenticationAsync(
                refreshFields, registration, metadata.TokenEndpoint!, assertionKey.Value, clientAssertionOptions,
                infrastructure, attemptNow, context, ct),
            context, cancellationToken)
            .ConfigureAwait(false);
        if(!refreshSendResult.IsSuccess)
        {
            return refreshSendResult.Error!;
        }

        Result<TokenResponse, OAuthParseError> refreshResult =
            infrastructure.ParseTokenResponseAsync(refreshSendResult.Value, now);

        if(!refreshResult.IsSuccess)
        {
            return TokenEndpointClientOperations.BuildEndpointResultFromParseError(refreshResult.Error!);
        }

        TokenResponse tokenResponse = refreshResult.Value;
        var body = new Dictionary<string, object>
        {
            [OAuthRequestParameterNames.AccessToken] = tokenResponse.AccessToken,
            [OAuthRequestParameterNames.TokenType] = tokenResponse.TokenType,
            [OAuthRequestParameterNames.ExpiresIn] = tokenResponse.ExpiresIn ?? 0,
            [OAuthRequestParameterNames.RefreshToken] = tokenResponse.RefreshToken ?? string.Empty,
            [OAuthRequestParameterNames.Scope] = tokenResponse.Scope ?? string.Empty
        };

        //A refresh response MAY carry a new ID Token (OpenID Connect Core 1.0 §12.1);
        //surface it when present.
        if(tokenResponse.IdToken is not null)
        {
            body[OAuthRequestParameterNames.IdToken] = tokenResponse.IdToken;
        }

        return AuthCodeFlowEndpointResult.Succeeded(body);
    }


    /// <summary>
    /// Handles a JAR-bearing Pushed Authorization Request per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101">RFC 9101</see> +
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126">RFC 9126</see>. The client signs a request
    /// object whose claims are <c>client_id</c>, <c>response_type</c>, <c>redirect_uri</c>,
    /// <c>scope</c> only when <see cref="AuthCodeStartJarParOptions.Scope"/> names a value (RFC 6749
    /// §3.1), <c>resource</c> only when <see cref="AuthCodeStartJarParOptions.Resource"/> names an
    /// indicator (a JSON string for one and an array for several, RFC 8707 §2.1), <c>state</c>,
    /// <c>nonce</c>, the PKCE challenge and its method, <c>iat</c>, <c>nbf</c>, <c>exp</c>,
    /// <c>iss</c> and <c>aud</c> (<see cref="AuthCodeJarSigning"/>), and POSTs it to the PAR endpoint
    /// with the outer <c>client_id</c> + <c>request</c> body fields. Persists
    /// <see cref="ParCompletedState"/> with the PKCE verifier and the same resource indicators the
    /// object signs, and returns the authorize redirect URI carrying the issued <c>request_uri</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A resource entry holding any white-space character is refused before anything is signed,
    /// sent or stored (<see cref="HasResourceEntryHoldingWhiteSpace"/>): an RFC 8707 §2 indicator is
    /// one absolute URI, and the entries the object signs are exactly the entries the flow state
    /// keeps and the code redemption sends.
    /// </para>
    /// <para>
    /// The send attaches no client authentication: the request carries no <c>client_assertion</c>
    /// field and no authorization header. A confidential client's pushed request is authenticated by
    /// the application's own push built on
    /// <see cref="ClientTokenEndpointAuthentication.AttachClientAssertionAsync"/>, following
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.1">RFC 9126 Section 2.1</see>: "If
    /// applicable, the client also adds its authentication credentials to the request header or the
    /// request body using the same rules as for token endpoint requests."
    /// </para>
    /// </remarks>
    /// <param name="jarOptions">The caller's per-call inputs: the scope, the resource indicators, the signing key and the serializers.</param>
    /// <param name="infrastructure">The long-lived infrastructure carrying transport, parsing, persistence, and time delegates.</param>
    /// <param name="registration">The registration identifying the authorization server this call targets.</param>
    /// <param name="context">The per-operation exchange context threaded into the transport and flow-state delegates.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// <see cref="AuthCodeFlowEndpointOutcome.Redirect"/> with the authorize redirect URI on success;
    /// <see cref="AuthCodeFlowEndpointOutcome.BadRequest"/> with <c>ErrorCode</c>
    /// <c>invalid_request</c> when a resource entry holds white space.
    /// </returns>
    public static async ValueTask<AuthCodeFlowEndpointResult> HandleJarParAsync(
        AuthCodeStartJarParOptions jarOptions,
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(jarOptions);
        ArgumentNullException.ThrowIfNull(infrastructure);
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);

        if(HasResourceEntryHoldingWhiteSpace(jarOptions.Resource))
        {
            return BuildResourceEntryHoldingWhiteSpaceRefusal();
        }

        Result<AuthorizationServerMetadata, AuthCodeFlowEndpointResult> metadataResult =
            await TokenEndpointClientOperations.ResolveValidatedAuthorizationServerMetadataAsync(
                infrastructure, registration, context, cancellationToken).ConfigureAwait(false);
        if(!metadataResult.IsSuccess)
        {
            return metadataResult.Error;
        }

        AuthorizationServerMetadata metadata = metadataResult.Value;

        cancellationToken.ThrowIfCancellationRequested();

        DateTimeOffset now = infrastructure.TimeProvider.GetUtcNow();
        string state = GenerateEntropyHexString(infrastructure);
        string nonce = jarOptions.Nonce ?? GenerateEntropyHexString(infrastructure);
        PkceParameters pkce = GeneratePkceParameters(infrastructure.Base64UrlEncoder, infrastructure.MemoryPool);
        ImmutableArray<string> requestedResource = ReadNamedResource(jarOptions.Resource);

        AuthCodeRequestObject requestObject = BuildJarRequestObject(
            registration, jarOptions, pkce, state, nonce, now, requestedResource);

        string compactJar = await AuthCodeJarSigning.SignAsync(
            requestObject,
            jarOptions.SigningKey,
            jarOptions.SigningKeyId,
            jarOptions.HeaderSerializer,
            jarOptions.PayloadSerializer,
            infrastructure.Base64UrlEncoder,
            jarOptions.MemoryPool,
            cancellationToken).ConfigureAwait(false);

        OutgoingFormFields parBody = new()
        {
            [OAuthRequestParameterNames.ClientId] = registration.ClientId.Value,
            [OAuthRequestParameterNames.Request] = compactJar
        };
        foreach((string key, string value) in jarOptions.AdditionalFields.Fields)
        {
            parBody[key] = value;
        }

        if(TokenEndpointClientOperations.EvaluateOutboundPolicy(metadata.PushedAuthorizationRequestEndpoint!, context, infrastructure) is AuthCodeFlowEndpointResult jarParPolicyDenial)
        {
            return jarParPolicyDenial;
        }

        HttpResponseData parHttpResponse;
        try
        {
            parHttpResponse = await infrastructure.SendFormPostAsync(
                metadata.PushedAuthorizationRequestEndpoint!,
                parBody,
                OutgoingHeaders.Empty,
                context,
                cancellationToken).ConfigureAwait(false);
        }
        catch(OperationCanceledException)
        {
            throw;
        }
        catch(Exception ex)
        {
            //Same rationale as the non-JAR PAR send site in this file: the transport delegate's failure
            //vocabulary is not enumerable here, so any fault surfaces as this endpoint's own server error,
            //cancellation excepted above. The transport exception's own text is not part of an OAuth error
            //response, so the description is this fixed sentence; the exception itself is recorded on the
            //current Activity for diagnostics rather than echoed to the caller.
            _ = (Activity.Current?.AddException(ex));

            return AuthCodeFlowEndpointResult.Refused(
                AuthCodeFlowEndpointOutcome.InternalError,
                AuthCodeFlowRefusalOrigin.ClientJudgement,
                OAuthErrors.ServerError,
                "The pushed authorization request could not be sent.");
        }

        Result<ParResponse, OAuthParseError> parResult =
            infrastructure.ParseParResponseAsync(parHttpResponse);

        if(!parResult.IsSuccess)
        {
            return TokenEndpointClientOperations.BuildEndpointResultFromParseError(parResult.Error!);
        }

        ParResponse parResponse = parResult.Value;
        ImmutableArray<string> scopes = [.. jarOptions.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries)];
        ParCompletedState parCompleted = new()
        {
            FlowId = state,
            ExpectedIssuer = registration.AuthorizationServerIssuer.OriginalString,
            EnteredAt = now,
            ExpiresAt = now.AddSeconds(parResponse.ExpiresIn),
            Kind = FlowKind.AuthCodeClient,
            Pkce = pkce,
            RedirectUri = jarOptions.RedirectUri,
            Scopes = scopes,
            Resource = requestedResource,
            Nonce = nonce,
            Par = parResponse
        };

        await infrastructure.SaveStateAsync(parCompleted, context, cancellationToken).ConfigureAwait(false);

        Uri authorizationUri = BuildAuthorizationRedirectUri(
            metadata.AuthorizationEndpoint!,
            registration.ClientId.Value,
            parResponse.RequestUri);

        return AuthCodeFlowEndpointResult.Redirected(authorizationUri);
    }


    /// <summary>
    /// Handles a JAR-by-value direct authorization per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-6.1">RFC 9101 §6.1</see>. The client
    /// signs a request object whose claims are <c>client_id</c>, <c>response_type</c>,
    /// <c>redirect_uri</c>, <c>scope</c> only when <see cref="AuthCodeStartJarAuthorizeOptions.Scope"/>
    /// names a value (RFC 6749 §3.1), <c>resource</c> only when
    /// <see cref="AuthCodeStartJarAuthorizeOptions.Resource"/> names an indicator (a JSON string for
    /// one and an array for several, RFC 8707 §2.1), <c>state</c>, <c>nonce</c>, the PKCE challenge
    /// and its method, <c>iat</c>, <c>nbf</c>, <c>exp</c>, <c>iss</c> and <c>aud</c>
    /// (<see cref="AuthCodeJarSigning"/>), and the handler builds a redirect URL carrying
    /// <c>request=&lt;compact-jws&gt;</c> alongside the outer <c>client_id</c>. The PKCE verifier and
    /// the same resource indicators the object signs are persisted so the eventual token exchange can
    /// complete and name them.
    /// </summary>
    /// <remarks>
    /// A resource entry holding any white-space character is refused before anything is signed or
    /// stored (<see cref="HasResourceEntryHoldingWhiteSpace"/>): an RFC 8707 §2 indicator is one
    /// absolute URI, and the entries the object signs are exactly the entries the flow state keeps
    /// and the code redemption sends.
    /// </remarks>
    /// <param name="jarOptions">The caller's per-call inputs: the scope, the resource indicators, the signing key and the serializers.</param>
    /// <param name="infrastructure">The long-lived infrastructure carrying transport, parsing, persistence, and time delegates: it resolves the authorization server metadata before anything is signed.</param>
    /// <param name="registration">The registration identifying the authorization server this call targets.</param>
    /// <param name="context">The per-operation exchange context threaded into the transport and flow-state delegates.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// <see cref="AuthCodeFlowEndpointOutcome.Redirect"/> with the authorization redirect URI on
    /// success; <see cref="AuthCodeFlowEndpointOutcome.BadRequest"/> with <c>ErrorCode</c>
    /// <c>invalid_request</c> when a resource entry holds white space; or the outcome of a failed
    /// authorization server metadata resolution.
    /// </returns>
    public static async ValueTask<AuthCodeFlowEndpointResult> HandleJarAuthorizeAsync(
        AuthCodeStartJarAuthorizeOptions jarOptions,
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(jarOptions);
        ArgumentNullException.ThrowIfNull(infrastructure);
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);

        if(HasResourceEntryHoldingWhiteSpace(jarOptions.Resource))
        {
            return BuildResourceEntryHoldingWhiteSpaceRefusal();
        }

        Result<AuthorizationServerMetadata, AuthCodeFlowEndpointResult> metadataResult =
            await TokenEndpointClientOperations.ResolveValidatedAuthorizationServerMetadataAsync(
                infrastructure, registration, context, cancellationToken).ConfigureAwait(false);
        if(!metadataResult.IsSuccess)
        {
            return metadataResult.Error;
        }

        AuthorizationServerMetadata metadata = metadataResult.Value;

        cancellationToken.ThrowIfCancellationRequested();

        DateTimeOffset now = infrastructure.TimeProvider.GetUtcNow();
        string state = GenerateEntropyHexString(infrastructure);
        string nonce = jarOptions.Nonce ?? GenerateEntropyHexString(infrastructure);
        PkceParameters pkce = GeneratePkceParameters(infrastructure.Base64UrlEncoder, infrastructure.MemoryPool);
        ImmutableArray<string> requestedResource = ReadNamedResource(jarOptions.Resource);

        AuthCodeRequestObject requestObject = new()
        {
            ClientId = registration.ClientId.Value,
            ResponseType = WellKnownResponseTypes.Code,
            RedirectUri = jarOptions.RedirectUri,
            Scope = jarOptions.Scope,
            State = state,
            Nonce = nonce,
            CodeChallenge = pkce.EncodedChallenge,
            CodeChallengeMethod = pkce.Method.ToString().ToUpperInvariant(),
            //The request object's dates are written to the whole second, the integers most authorization servers read.
            Iat = NumericDate.WholeSecondAtOrBefore(now),
            Nbf = NumericDate.WholeSecondAtOrBefore(now),
            Exp = NumericDate.WholeSecondAtOrBefore(now.Add(jarOptions.JarLifetime)),
            Iss = registration.ClientId.Value,
            Aud = registration.AuthorizationServerIssuer.OriginalString,
            Resource = JoinRequestObjectResource(requestedResource)
        };

        string compactJar = await AuthCodeJarSigning.SignAsync(
            requestObject,
            jarOptions.SigningKey,
            jarOptions.SigningKeyId,
            jarOptions.HeaderSerializer,
            jarOptions.PayloadSerializer,
            infrastructure.Base64UrlEncoder,
            jarOptions.MemoryPool,
            cancellationToken).ConfigureAwait(false);

        Uri authorizationUri = BuildJarAuthorizeRedirectUri(
            metadata.AuthorizationEndpoint!,
            registration.ClientId.Value,
            compactJar,
            jarOptions.AdditionalFields);

        ImmutableArray<string> scopes = [.. jarOptions.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries)];
        ParCompletedState parCompleted = new()
        {
            FlowId = state,
            ExpectedIssuer = registration.AuthorizationServerIssuer.OriginalString,
            EnteredAt = now,
            ExpiresAt = now.Add(jarOptions.JarLifetime),
            Kind = FlowKind.AuthCodeClient,
            Pkce = pkce,
            RedirectUri = jarOptions.RedirectUri,
            Scopes = scopes,
            Resource = requestedResource,
            Nonce = nonce,
            Par = new ParResponse(authorizationUri, (int)jarOptions.JarLifetime.TotalSeconds)
        };

        await infrastructure.SaveStateAsync(parCompleted, context, cancellationToken).ConfigureAwait(false);

        return AuthCodeFlowEndpointResult.Redirected(authorizationUri);
    }


    /// <summary>
    /// Builds the claims of the request object a pushed start signs
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9101#section-4">RFC 9101 §4</see>: "The
    /// parameters are represented as the JWT Claims of the object."), the RFC 8707
    /// <c>resource</c> indicators among them.
    /// </summary>
    /// <param name="registration">The registration naming the client and the authorization server.</param>
    /// <param name="jarOptions">The caller's per-call inputs.</param>
    /// <param name="pkce">The PKCE pair whose challenge and method are signed.</param>
    /// <param name="state">The <c>state</c> value this start minted.</param>
    /// <param name="nonce">The <c>nonce</c> value this start signs.</param>
    /// <param name="now">The instant the object is issued at.</param>
    /// <param name="resource">The resource indicators the request names, empty when none.</param>
    /// <returns>The request object to sign.</returns>
    private static AuthCodeRequestObject BuildJarRequestObject(
        ClientRegistration registration,
        AuthCodeStartJarParOptions jarOptions,
        PkceParameters pkce,
        string state,
        string nonce,
        DateTimeOffset now,
        ImmutableArray<string> resource) => new()
        {
            ClientId = registration.ClientId.Value,
            ResponseType = WellKnownResponseTypes.Code,
            RedirectUri = jarOptions.RedirectUri,
            Scope = jarOptions.Scope,
            State = state,
            Nonce = nonce,
            CodeChallenge = pkce.EncodedChallenge,
            CodeChallengeMethod = pkce.Method.ToString().ToUpperInvariant(),
            //The request object's dates are written to the whole second, the integers most authorization servers read.
            Iat = NumericDate.WholeSecondAtOrBefore(now),
            Nbf = NumericDate.WholeSecondAtOrBefore(now),
            Exp = NumericDate.WholeSecondAtOrBefore(now.Add(jarOptions.JarLifetime)),
            Iss = registration.ClientId.Value,
            Aud = registration.AuthorizationServerIssuer.OriginalString,
            Resource = JoinRequestObjectResource(resource)
        };


    /// <summary>
    /// The RFC 8707 <c>resource</c> indicators a caller names: its non-blank entries, in its order
    /// and as given, and empty for <see langword="null"/> or a list naming none. These are exactly the
    /// entries <see cref="TokenEndpointClientOperations.AddResourceOccurrences"/> sends, so the set a
    /// flow state keeps is the set its authorization request carried. No entry is folded or
    /// rewritten: the canonical form of each URI is the caller's to give (the MCP authorization
    /// specification: the parameter "MUST use the canonical URI of the MCP server").
    /// </summary>
    /// <param name="resource">The caller's resource indicators, or <see langword="null"/>.</param>
    /// <returns>The named indicators; empty when the caller names none.</returns>
    private static ImmutableArray<string> ReadNamedResource(IReadOnlyList<string>? resource) =>
        resource is null
            ? []
            : [.. resource.Where(static indicator => !string.IsNullOrWhiteSpace(indicator))];


    /// <summary>
    /// The resource indicators a token request of the authorization-code grant names: the ones its
    /// caller names, and otherwise the ones the authorization request of the flow named. The MCP
    /// authorization specification says the parameter "MUST be included in both authorization
    /// requests and token requests"; <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.2">RFC
    /// 8707 §2.2</see> lets a caller name a subset of the granted set on this request, to which "the
    /// authorization server will issue an access token based on that subset of requested
    /// resources".
    /// </summary>
    /// <param name="callerResource">The indicators the caller of the code redemption names.</param>
    /// <param name="requestedResource">The indicators the authorization request named.</param>
    /// <returns>The indicators the token request names; empty when neither names one.</returns>
    private static ImmutableArray<string> SelectTokenRequestResource(
        ImmutableArray<string> callerResource, ImmutableArray<string> requestedResource) =>
        (callerResource.IsDefaultOrEmpty, requestedResource.IsDefaultOrEmpty) switch
        {
            (false, _) => callerResource,
            (true, false) => requestedResource,
            (true, true) => []
        };


    /// <summary>
    /// The <see cref="AuthCodeRequestObject.Resource"/> value of a request object naming
    /// <paramref name="resource"/>: the indicators space-joined, the form that property carries, or
    /// <see langword="null"/> when the request names none, so the object then carries no
    /// <c>resource</c> claim. The join is undone exactly by the signing's split on the space, entry
    /// for entry and in order, because both request-object starts refuse an entry holding white space
    /// before they get here (<see cref="HasResourceEntryHoldingWhiteSpace"/>).
    /// </summary>
    /// <param name="resource">The resource indicators the request names, none of them holding white space.</param>
    /// <returns>The space-joined indicators, or <see langword="null"/> when there are none.</returns>
    private static string? JoinRequestObjectResource(ImmutableArray<string> resource) =>
        resource.IsDefaultOrEmpty ? null : string.Join(' ', resource);


    /// <summary>
    /// Whether any entry of the caller's resource list holds a white-space character
    /// (<see cref="char.IsWhiteSpace(char)"/>) anywhere in it, an entry of white space only included;
    /// an empty entry names no indicator and is dropped by <see cref="ReadNamedResource"/> instead.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 §2</see>: the value "MUST
    /// be an absolute URI, as specified by Section 4.3 of [RFC3986]", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-2">RFC 3986 §2</see>: "A URI is
    /// composed from a limited set of characters consisting of digits, letters, and a few graphic
    /// symbols.", so such an entry is no indicator. A request object signs its indicators through the
    /// space-joined <see cref="AuthCodeRequestObject.Resource"/>, which would sign an entry holding a
    /// space as several indicators and a padded entry trimmed while the flow state and the code
    /// redemption keep the entry as given; the request-object starts refuse it instead.
    /// </summary>
    /// <param name="resource">The caller's resource indicators, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when an entry holds white space.</returns>
    private static bool HasResourceEntryHoldingWhiteSpace(IReadOnlyList<string>? resource) =>
        resource is not null
        && resource.Any(static entry => entry is not null && entry.Any(char.IsWhiteSpace));


    /// <summary>
    /// The answer of a request-object start whose resource list holds an entry with white space
    /// (<see cref="HasResourceEntryHoldingWhiteSpace"/>): the same shape the client gives any start it
    /// cannot compose, <see cref="AuthCodeFlowEndpointOutcome.BadRequest"/> with
    /// <c>invalid_request</c> and a fixed description, given before anything is signed, sent or
    /// stored.
    /// </summary>
    /// <returns>The refusal of the start.</returns>
    private static AuthCodeFlowEndpointResult BuildResourceEntryHoldingWhiteSpaceRefusal() => AuthCodeFlowEndpointResult.Refused(
        AuthCodeFlowEndpointOutcome.BadRequest,
        AuthCodeFlowRefusalOrigin.ClientJudgement,
        OAuthErrors.InvalidRequest,
        "A resource entry holds white space; each entry must be one absolute URI " +
        "(RFC 8707 §2), so the request object is not signed and nothing is sent.");


    private static Uri BuildJarAuthorizeRedirectUri(
        Uri authorizationEndpoint,
        string clientId,
        string compactJar,
        OAuthFormEncodedFields additionalFields)
    {
        StringBuilder builder = new();
        _ = builder.Append(authorizationEndpoint);
        _ = builder.Append('?');
        _ = builder.Append(OAuthRequestParameterNames.ClientId);
        _ = builder.Append('=');
        _ = builder.Append(Uri.EscapeDataString(clientId));
        _ = builder.Append('&');
        _ = builder.Append(OAuthRequestParameterNames.Request);
        _ = builder.Append('=');
        _ = builder.Append(Uri.EscapeDataString(compactJar));

        foreach((string key, string value) in additionalFields.Fields)
        {
            _ = builder.Append('&');
            _ = builder.Append(Uri.EscapeDataString(key));
            _ = builder.Append('=');
            _ = builder.Append(Uri.EscapeDataString(value));
        }

        return new Uri(builder.ToString());
    }


    private static PkceParameters GeneratePkceParameters(EncodeDelegate base64UrlEncoder, BaseMemoryPool pool)
    {
        return PkceGeneration.Generate(base64UrlEncoder, pool);
    }

    /// <summary>
    /// Encodes the pushed authorization request body of RFC 9126 §2.1: <c>client_id</c>,
    /// <c>response_type</c>, <c>redirect_uri</c>, <c>scope</c> when <see cref="ParRequestBody.Scopes"/>
    /// names at least one value (<see cref="AddScopeWhenNamed"/>), <c>state</c>, and the PKCE pair of
    /// RFC 7636 §4.3.
    /// </summary>
    /// <param name="body">The typed parameters of the pushed request.</param>
    /// <returns>The form fields to post to the pushed authorization request endpoint.</returns>
    private static OutgoingFormFields EncodeParRequestBody(ParRequestBody body)
    {
        OutgoingFormFields fields = new()
        {
            [OAuthRequestParameterNames.ClientId] = body.ClientId,
            [OAuthRequestParameterNames.ResponseType] = body.ResponseType,
            [OAuthRequestParameterNames.RedirectUri] = body.RedirectUri.ToString()
        };

        AddScopeWhenNamed(fields, body.Scopes);
        fields[OAuthRequestParameterNames.State] = body.State;
        fields[OAuthRequestParameterNames.CodeChallenge] = body.CodeChallenge;
        fields[OAuthRequestParameterNames.CodeChallengeMethod] = body.CodeChallengeMethod.ToString().ToUpperInvariant();

        return fields;
    }


    /// <summary>
    /// The scope values the caller names in its <c>scope</c> field, split on the space delimiter of
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.3">RFC 6749 §3.3</see>, and empty
    /// when the field is absent, empty or made only of white space of any kind: §3.3's
    /// "scope-token = 1*( %x21 / %x23-5B / %x5D-7E )" admits no white space, so such a value names no
    /// scope token, and §3.1 reads "Parameters sent without a value MUST be treated as if they were
    /// omitted from the request.", the reading the request-object and refresh encoders give a blank
    /// scope as well. RFC 6749 §4.1.1 makes <c>scope</c> "OPTIONAL" and §3.3
    /// leaves the default for an omitted scope to the authorization server ("If the client omits the
    /// scope parameter when requesting authorization, the authorization server MUST either process the
    /// request using a pre-defined default value or fail the request indicating an invalid scope."),
    /// so the client adds no value of its own; an OpenID Connect caller names <c>openid</c> itself
    /// (OpenID Connect Core 1.0 §3.1.2.1: "OpenID Connect requests MUST contain the openid scope
    /// value.").
    /// </summary>
    /// <param name="fields">The caller's inbound fields.</param>
    /// <returns>The named scope values, in the caller's order; empty when the caller names none.</returns>
    private static ImmutableArray<string> ReadRequestedScopes(IReadOnlyDictionary<string, string> fields) =>
        fields.TryGetValue(OAuthRequestParameterNames.Scope, out string? scopeValue)
            && !string.IsNullOrWhiteSpace(scopeValue)
                ? [.. scopeValue.Split(' ', StringSplitOptions.RemoveEmptyEntries)]
                : [];


    /// <summary>
    /// Writes the <c>scope</c> parameter as the space-delimited list of
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.3">RFC 6749 §3.3</see> when
    /// <paramref name="scopes"/> names at least one value, and writes nothing otherwise. RFC 6749 §3.1
    /// reads "Parameters sent without a value MUST be treated as if they were omitted from the
    /// request.", so a request naming no scope omits the parameter instead of sending <c>scope=</c>.
    /// </summary>
    /// <param name="fields">The request fields composed so far.</param>
    /// <param name="scopes">The scope values the caller named.</param>
    private static void AddScopeWhenNamed(OutgoingFormFields fields, ImmutableArray<string> scopes)
    {
        if(!scopes.IsDefaultOrEmpty)
        {
            fields[OAuthRequestParameterNames.Scope] = string.Join(' ', scopes);
        }
    }

    private static OutgoingFormFields EncodeTokenRequest(
        string clientId,
        string code,
        Uri redirectUri,
        PkceParameters pkce,
        IReadOnlyList<string>? resource = null)
    {
        OutgoingFormFields fields = new()
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.AuthorizationCode,
            [OAuthRequestParameterNames.ClientId] = clientId,
            [OAuthRequestParameterNames.Code] = code,
            [OAuthRequestParameterNames.RedirectUri] = redirectUri.ToString(),
            [OAuthRequestParameterNames.CodeVerifier] = pkce.EncodedVerifier
        };

        TokenEndpointClientOperations.AddResourceOccurrences(fields, resource);

        return fields;
    }

    /// <summary>
    /// Encodes the refresh request of
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-6">RFC 6749 §6</see>:
    /// <c>grant_type=refresh_token</c>, <c>client_id</c>, <c>refresh_token</c>, <c>scope</c> only when
    /// <see cref="RefreshTokenRequest.Scope"/> names a value, and each RFC 8707 <c>resource</c>
    /// occurrence. A blank scope is not sent: RFC 6749 §3.1 treats a parameter sent without a value as
    /// omitted, and §6 treats an omitted scope "as equal to the scope originally granted by the
    /// resource owner".
    /// </summary>
    /// <param name="clientId">The client identifier sent as <c>client_id</c>.</param>
    /// <param name="request">The caller's refresh parameters.</param>
    /// <returns>The form fields to post to the token endpoint.</returns>
    private static OutgoingFormFields EncodeRefreshRequest(string clientId, RefreshTokenRequest request)
    {
        var fields = new OutgoingFormFields
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.RefreshToken,
            [OAuthRequestParameterNames.ClientId] = clientId,
            [OAuthRequestParameterNames.RefreshToken] = request.RefreshToken
        };

        if(!string.IsNullOrWhiteSpace(request.Scope))
        {
            fields[OAuthRequestParameterNames.Scope] = request.Scope;
        }

        TokenEndpointClientOperations.AddResourceOccurrences(fields, request.Resource);

        return fields;
    }


    /// <summary>
    /// The parameter names <c>HandleParAsync</c> and <c>HandleDirectAuthorizeStartAsync</c> compose
    /// themselves. An additional field arriving under one of these names is dropped rather than
    /// allowed to override what the flow minted - the caller extends the request, never the flow's
    /// own identity, PKCE, or state.
    /// </summary>
    private static ImmutableHashSet<string> AuthorizationFlowOwnedFieldNames { get; } = ImmutableHashSet.Create(
        StringComparer.Ordinal,
        OAuthRequestParameterNames.ClientId,
        OAuthRequestParameterNames.ResponseType,
        OAuthRequestParameterNames.RedirectUri,
        OAuthRequestParameterNames.Scope,
        OAuthRequestParameterNames.State,
        OAuthRequestParameterNames.CodeChallenge,
        OAuthRequestParameterNames.CodeChallengeMethod,
        OAuthRequestParameterNames.Resource);


    /// <summary>
    /// Appends the caller's additional fields to the pushed request body or the direct authorization
    /// redirect's query, each under its own name, skipping the flow-owned names so the composed
    /// request stays the flow's.
    /// </summary>
    /// <param name="formFields">The request fields the flow has composed so far.</param>
    /// <param name="fields">The caller's inbound fields, of which the flow-owned names are skipped.</param>
    private static void AddAdditionalAuthorizationFields(OutgoingFormFields formFields, IReadOnlyDictionary<string, string> fields)
    {
        foreach((string key, string value) in fields)
        {
            if(!AuthorizationFlowOwnedFieldNames.Contains(key))
            {
                formFields.Add(key, value);
            }
        }
    }


    private static Uri BuildAuthorizationRedirectUri(
        Uri authorizationEndpoint,
        string clientId,
        Uri requestUri)
    {
        string uri = $"{authorizationEndpoint}?{OAuthRequestParameterNames.ClientId}={Uri.EscapeDataString(clientId)}" +
                     $"&{OAuthRequestParameterNames.RequestUri}={Uri.EscapeDataString(requestUri.ToString())}";
        return new Uri(uri);
    }


    /// <summary>
    /// Builds the result for an OAuth 2.0 Authorization Error Response callback
    /// (<paramref name="errorCode"/> present per RFC 6749 §4.1.2.1). RFC 9207 §2.4 says a client
    /// must not assume the error originates from the intended authorization server, so the error
    /// is attributed to that server only once the callback is tied to it: its <c>state</c> names a
    /// pending <see cref="ParCompletedState"/> of this client, and the callback validator the
    /// registration's profile selects (<see cref="OAuthClientInfrastructure.ResolveCallbackValidator"/>)
    /// accepted it by every rule it holds a success response to but the presence of a <c>code</c> —
    /// the state matches the flow, the <c>iss</c> matches the flow's recorded issuer and is present
    /// where the profile requires it (<see cref="ValidationChecks.CheckCallbackIssPresent"/>), the flow
    /// has not expired — and a present <c>iss</c> resolves to a known authorization server when the
    /// application supplies that resolver. A callback with no <c>state</c>, with a <c>state</c>
    /// naming no flow, or with one naming a flow of another kind or step, establishes no
    /// authorization server as its author; it is refused as the library's own judgement, as is a
    /// callback one of the checks refused — an attacker able to inject <c>iss</c> on a forged
    /// success response is equally able to inject <c>error</c> and <c>iss</c> together, and
    /// RFC 9207 §4 draws no distinction between success and error responses for this defense.
    /// </summary>
    /// <param name="fields">The callback parameters, carrying <c>error</c>.</param>
    /// <param name="infrastructure">The infrastructure carrying flow-state persistence, time and the known-issuer resolver.</param>
    /// <param name="registration">The registration whose pinned issuer a present <c>iss</c> resolves against.</param>
    /// <param name="context">The per-operation exchange context threaded into the flow-state delegate.</param>
    /// <param name="errorCode">The <c>error</c> value the callback carries.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The authorization server's error when the callback is tied to it, else the library's refusal.</returns>
    private static async ValueTask<AuthCodeFlowEndpointResult> BuildCallbackErrorResultAsync(
        IReadOnlyDictionary<string, string> fields,
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        ExchangeContext context,
        string errorCode,
        CancellationToken cancellationToken)
    {
        _ = fields.TryGetValue(OAuthRequestParameterNames.ErrorDescription, out string? errorDescription);

        //Every authorization request this flow composes carries state, and RFC 6749 §4.1.2.1 has the error
        //response return it, so an error without one cannot be tied to any request of this client.
        if(!fields.TryGetValue(OAuthRequestParameterNames.State, out string? errorState))
        {
            return AuthCodeFlowEndpointResult.Refused(
                AuthCodeFlowEndpointOutcome.BadRequest,
                AuthCodeFlowRefusalOrigin.ClientJudgement,
                OAuthErrors.InvalidRequest,
                "The error callback carries no state, so it cannot be tied to an authorization request " +
                "of this client and no authorization server is established as its author " +
                "(RFC 6749 §4.1.2.1, RFC 9207 §2.4).");
        }

        FlowState? errorFlowState = await infrastructure.LoadStateAsync(
            errorState, context, cancellationToken).ConfigureAwait(false);

        if(errorFlowState is not ParCompletedState errorParCompleted)
        {
            return AuthCodeFlowEndpointResult.Refused(
                AuthCodeFlowEndpointOutcome.BadRequest,
                AuthCodeFlowRefusalOrigin.ClientJudgement,
                OAuthErrors.InvalidRequest,
                "The error callback's state names no pending authorization request of this client, so " +
                "no authorization server is established as its author (RFC 9207 §2.4).");
        }

        ValidationContext correlationContext = new()
        {
            Context = [],
            Fields = fields,
            FlowState = errorParCompleted,
            TimeProvider = infrastructure.TimeProvider,
            Now = infrastructure.TimeProvider.GetUtcNow()
        };

        //The registration's profile judges an error response by the rules it judges a success response by (RFC 9207 §2.4: a
        //client "MUST NOT assume that the error originates from the intended authorization server"), so a profile requiring iss
        //refuses an error answering none; the code a success response carries is the one rule an error response has no part in.
        var callbackValidator = infrastructure.ResolveCallbackValidator(registration, infrastructure.TimeProvider);
        var validation = await callbackValidator.GenerateClaimsAsync(
            correlationContext, errorParCompleted.FlowId, cancellationToken).ConfigureAwait(false);
        var correlationClaims = validation.Claims
            .Where(static claim => claim.Id.Code != ValidationClaimIds.CallbackCodePresent.Code)
            .ToList();

        if(!validation.IsComplete || correlationClaims.Exists(static c => c.Outcome != ClaimOutcome.Success))
        {
            return AuthCodeFlowEndpointResult.Refused(
                AuthCodeFlowEndpointOutcome.BadRequest,
                AuthCodeFlowRefusalOrigin.ClientJudgement,
                OAuthErrors.InvalidRequest,
                "The error callback failed a check that ties it to this client's authorization request; " +
                "the response is not trusted as originating from the intended authorization " +
                "server (RFC 9207 §2.4, RFC 9700 §4.4).",
                correlationClaims);
        }

        string? iss = fields.TryGetValue(OAuthRequestParameterNames.Iss, out string? issValue)
            ? issValue
            : null;

        if(iss is not null
            && infrastructure.IsKnownAuthorizationServerIssuer is not null
            && !AuthorizationServerIssuerValidation.IsAuthorizationResponseIssuerValid(
                iss, registration.AuthorizationServerIssuer, infrastructure.IsKnownAuthorizationServerIssuer))
        {
            return AuthCodeFlowEndpointResult.Refused(
                AuthCodeFlowEndpointOutcome.BadRequest,
                AuthCodeFlowRefusalOrigin.ClientJudgement,
                OAuthErrors.InvalidRequest,
                "The iss parameter on the error callback does not resolve to a known, uniquely-configured " +
                "authorization server matching this registration (RFC 9207 §2.4, §4).",
                correlationClaims);
        }

        //The error names this client's pending request and every callback check that request holds it to accepted it,
        //so it is the authorization server's answer.
        return AuthCodeFlowEndpointResult.Refused(
            AuthCodeFlowEndpointOutcome.BadRequest,
            AuthCodeFlowRefusalOrigin.AuthorizationServerAnswer,
            errorCode,
            errorDescription,
            correlationClaims);
    }


    /// <summary>
    /// Produces a 32-character lowercase-hex string from 16 CSPRNG-sourced
    /// random bytes via <see cref="OAuthClientInfrastructure.FillEntropy"/>.
    /// Wire-format-compatible with the prior <c>Guid.NewGuid().ToString("N")</c>
    /// shape — same length, same character set, same expected entropy.
    /// </summary>
    private static string GenerateEntropyHexString(OAuthClientInfrastructure infrastructure)
    {
        Span<byte> buffer = stackalloc byte[16];
        infrastructure.FillEntropy(buffer);
        return Convert.ToHexStringLower(buffer);
    }
}
