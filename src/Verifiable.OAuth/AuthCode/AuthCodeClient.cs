using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Core;
using Verifiable.OAuth.Client;

namespace Verifiable.OAuth.AuthCode;

/// <summary>
/// The Authorization Code sub-client of <see cref="OAuthClient"/>. A
/// per-call handle over an <see cref="OAuthClientInfrastructure"/> that
/// drives PAR, callback handling, token exchange, refresh, revocation, and
/// the JAR-bearing variants of PAR and direct authorization.
/// </summary>
/// <remarks>
/// <para>
/// Constructed via the <see cref="OAuthClient.AuthCode"/> extension property
/// on <see cref="OAuthClient"/>. The struct is cheap to materialise (one
/// reference field) and carries no per-AS state — every protocol method
/// takes a <see cref="ClientRegistration"/> as its first parameter,
/// describing which authorization server this call targets.
/// </para>
/// <para>
/// Every protocol method has two overloads: one that takes an explicit
/// <see cref="ExchangeContext"/> (threaded into the transport and flow-state
/// delegates so a multi-tenant deployment can scope per-tenant
/// <c>HttpClient</c> selection and storage), and a convenience overload that
/// defaults a fresh empty context — the right call for a single-tenant client
/// that ignores tenancy.
/// </para>
/// <para>
/// <strong>Usage.</strong>
/// </para>
/// <code>
/// OAuthClient client = new(infrastructure);
/// ClientRegistration registration = LoadFromStore(clientId);
///
/// AuthCodeFlowEndpointResult redirect = await client.AuthCode.StartParAsync(
///     registration, redirectUri, OAuthFormEncodedFields.Empty, ct);
/// </code>
/// </remarks>
[DebuggerDisplay("AuthCodeClient")]
[SuppressMessage("Performance", "CA1815:Override equals and operator equals on value types", Justification = "AuthCodeClient is a service-shaped wrapper around a single reference; value equality would compare reference identity of the underlying infrastructure, which is not a meaningful operation for callers.")]
public readonly struct AuthCodeClient
{
    /// <summary>The long-lived infrastructure this client reads delegates from.</summary>
    public OAuthClientInfrastructure Infrastructure { get; }


    /// <summary>
    /// Creates a new Authorization Code client over the supplied
    /// infrastructure. Internal — use <see cref="OAuthClient.AuthCode"/>
    /// to access an instance.
    /// </summary>
    internal AuthCodeClient(OAuthClientInfrastructure infrastructure)
    {
        ArgumentNullException.ThrowIfNull(infrastructure);

        Infrastructure = infrastructure;
    }


    /// <summary>
    /// Starts a PAR+PKCE flow: generates a fresh PKCE verifier and challenge,
    /// sends a Pushed Authorization Request, and returns a redirect to the
    /// authorization endpoint with the <c>request_uri</c>.
    /// </summary>
    /// <param name="registration">The registration identifying the authorization server.</param>
    /// <param name="redirectUri">
    /// The redirect URI to use for this call. Per RFC 6749 §3.1.2.3, the
    /// client picks one of the AS's allow-listed URIs at request time; this
    /// value is sent in the PAR body and persisted into the
    /// <see cref="Verifiable.OAuth.AuthCode.States.ParCompletedState"/> for
    /// later use at token exchange. The library does not validate the URI
    /// against <see cref="ClientRegistration.RedirectUris"/> — that is the
    /// AS's responsibility.
    /// </param>
    /// <param name="additionalFields">
    /// Additional fields to include in the PAR request body (for example
    /// <c>scope</c>, <c>acr_values</c>). May be
    /// <see cref="OAuthFormEncodedFields.Empty"/>.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public ValueTask<AuthCodeFlowEndpointResult> StartParAsync(
        ClientRegistration registration,
        Uri redirectUri,
        OAuthFormEncodedFields additionalFields,
        CancellationToken cancellationToken) =>
        StartParAsync(registration, redirectUri, additionalFields, new ExchangeContext(), cancellationToken);


    /// <inheritdoc cref="StartParAsync(ClientRegistration, Uri, OAuthFormEncodedFields, CancellationToken)"/>
    /// <param name="context">The per-operation exchange context threaded into the transport and flow-state delegates.</param>
    public ValueTask<AuthCodeFlowEndpointResult> StartParAsync(
        ClientRegistration registration,
        Uri redirectUri,
        OAuthFormEncodedFields additionalFields,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(redirectUri);
        ArgumentNullException.ThrowIfNull(context);

        return AuthCodeFlowHandlers.HandleParAsync(
            additionalFields.Fields, redirectUri, Infrastructure, registration, context, cancellationToken);
    }


    /// <summary>
    /// Handles the authorization callback: validates the <c>iss</c> parameter
    /// (when HAIP / RFC 9207 is active), extracts the authorization <c>code</c>,
    /// and persists the code-received state.
    /// </summary>
    /// <param name="registration">The registration identifying the authorization server.</param>
    /// <param name="callbackParams">
    /// The query parameters from the authorization callback redirect.
    /// Must include <c>code</c>, <c>state</c>, and (for HAIP) <c>iss</c>.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public ValueTask<AuthCodeFlowEndpointResult> HandleCallbackAsync(
        ClientRegistration registration,
        OAuthFormEncodedFields callbackParams,
        CancellationToken cancellationToken) =>
        HandleCallbackAsync(registration, callbackParams, new ExchangeContext(), cancellationToken);


    /// <inheritdoc cref="HandleCallbackAsync(ClientRegistration, OAuthFormEncodedFields, CancellationToken)"/>
    /// <param name="context">The per-operation exchange context threaded into the transport and flow-state delegates.</param>
    public ValueTask<AuthCodeFlowEndpointResult> HandleCallbackAsync(
        ClientRegistration registration,
        OAuthFormEncodedFields callbackParams,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);

        return AuthCodeFlowHandlers.HandleCallbackAsync(
            callbackParams.Fields, Infrastructure, registration, context, cancellationToken);
    }


    /// <summary>
    /// Exchanges the authorization code and PKCE verifier for tokens at the
    /// token endpoint, attaching confidential-client authentication per
    /// <see cref="ClientRegistration.AuthenticationMethod"/> (RFC 6749 §3.2.1). Covers
    /// <see cref="ClientAuthenticationMethod.None"/>, <see cref="ClientAuthenticationMethod.ClientSecretPost"/>,
    /// and <see cref="ClientAuthenticationMethod.ClientSecretBasic"/> — none of which need a signed
    /// assertion. A <see cref="ClientAuthenticationMethod.PrivateKeyJwt"/> registration needs the
    /// <see cref="ExchangeTokenAsync(ClientRegistration, string, ExchangeContext, ClientAssertionOptions?, CancellationToken)"/>
    /// overload instead, so the caller can supply the client-assertion signing inputs
    /// (RFC 7523 §2.2) the AS-declared method requires.
    /// </summary>
    /// <param name="registration">The registration identifying the authorization server.</param>
    /// <param name="flowId">
    /// The flow identifier (the <c>state</c> value) that correlates this token
    /// request with the original PAR.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public ValueTask<AuthCodeFlowEndpointResult> ExchangeTokenAsync(
        ClientRegistration registration,
        string flowId,
        CancellationToken cancellationToken) =>
        ExchangeTokenAsync(registration, flowId, new ExchangeContext(), cancellationToken);


    /// <inheritdoc cref="ExchangeTokenAsync(ClientRegistration, string, CancellationToken)"/>
    /// <param name="context">The per-operation exchange context threaded into the transport and flow-state delegates.</param>
    public ValueTask<AuthCodeFlowEndpointResult> ExchangeTokenAsync(
        ClientRegistration registration,
        string flowId,
        ExchangeContext context,
        CancellationToken cancellationToken) =>
        ExchangeTokenAsync(registration, flowId, context, clientAssertionOptions: null, cancellationToken);


    /// <summary>
    /// Exchanges the authorization code and PKCE verifier for tokens at the
    /// token endpoint, attaching confidential-client authentication per
    /// <see cref="ClientRegistration.AuthenticationMethod"/> (RFC 6749 §3.2.1 / RFC 7523 §2.2) —
    /// the overload that reaches <see cref="ClientAuthenticationMethod.PrivateKeyJwt"/>.
    /// </summary>
    /// <remarks>
    /// The signed <c>client_assertion</c>'s <c>iss</c>/<c>sub</c> (the client identifier), <c>aud</c>
    /// (the resolved token endpoint), <c>iat</c>/<c>exp</c> (<see cref="OAuthClientInfrastructure.TimeProvider"/>),
    /// and <c>jti</c> (<see cref="OAuthClientInfrastructure.GenerateIdentifierAsync"/> — the same
    /// generator the <see cref="Verifiable.OAuth.IdJag.IdJagFlowHandlers"/> client path uses) all come
    /// from <paramref name="registration"/> and <see cref="Infrastructure"/>; the signing key comes from
    /// <see cref="ClientRegistration.AuthenticationKeyMaterial"/>. <paramref name="clientAssertionOptions"/>
    /// supplies only what the application must still choose: the <c>kid</c> and the header/payload
    /// serialisers.
    /// </remarks>
    /// <param name="registration">The registration identifying the authorization server.</param>
    /// <param name="flowId">
    /// The flow identifier (the <c>state</c> value) that correlates this token
    /// request with the original PAR.
    /// </param>
    /// <param name="context">The per-operation exchange context threaded into the transport and flow-state delegates.</param>
    /// <param name="clientAssertionOptions">
    /// The <c>private_key_jwt</c> client-assertion signing inputs (RFC 7523 §2.2). Required when
    /// <see cref="ClientRegistration.AuthenticationMethod"/> is
    /// <see cref="ClientAuthenticationMethod.PrivateKeyJwt"/>; ignored for every other method.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public ValueTask<AuthCodeFlowEndpointResult> ExchangeTokenAsync(
        ClientRegistration registration,
        string flowId,
        ExchangeContext context,
        ClientAssertionOptions? clientAssertionOptions,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentException.ThrowIfNullOrWhiteSpace(flowId);
        ArgumentNullException.ThrowIfNull(context);

        return AuthCodeFlowHandlers.HandleTokenAsync(
            new Dictionary<string, string> { [AuthCodeFlowRoutes.FlowIdField] = flowId },
            Infrastructure,
            registration,
            context,
            clientAssertionOptions,
            cancellationToken);
    }


    /// <summary>
    /// Refreshes an access token using a refresh token, attaching confidential-client
    /// authentication per <see cref="ClientRegistration.AuthenticationMethod"/> (RFC 6749 §6, §3.2.1). Covers
    /// <see cref="ClientAuthenticationMethod.None"/>, <see cref="ClientAuthenticationMethod.ClientSecretPost"/>,
    /// and <see cref="ClientAuthenticationMethod.ClientSecretBasic"/> — none of which need a signed
    /// assertion. A <see cref="ClientAuthenticationMethod.PrivateKeyJwt"/> registration needs the
    /// <see cref="RefreshAsync(ClientRegistration, RefreshTokenRequest, ExchangeContext, ClientAssertionOptions?, CancellationToken)"/>
    /// overload instead, so the caller can supply the client-assertion signing inputs
    /// (RFC 7523 §2.2) the AS-declared method requires.
    /// </summary>
    /// <param name="registration">The registration identifying the authorization server.</param>
    /// <param name="request">The refresh token request.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public ValueTask<AuthCodeFlowEndpointResult> RefreshAsync(
        ClientRegistration registration,
        RefreshTokenRequest request,
        CancellationToken cancellationToken) =>
        RefreshAsync(registration, request, new ExchangeContext(), cancellationToken);


    /// <inheritdoc cref="RefreshAsync(ClientRegistration, RefreshTokenRequest, CancellationToken)"/>
    /// <param name="context">The per-operation exchange context threaded into the transport and flow-state delegates.</param>
    public ValueTask<AuthCodeFlowEndpointResult> RefreshAsync(
        ClientRegistration registration,
        RefreshTokenRequest request,
        ExchangeContext context,
        CancellationToken cancellationToken) =>
        RefreshAsync(registration, request, context, clientAssertionOptions: null, cancellationToken);


    /// <summary>
    /// Refreshes an access token using a refresh token, attaching confidential-client
    /// authentication per <see cref="ClientRegistration.AuthenticationMethod"/> (RFC 6749 §6 /
    /// RFC 7523 §2.2) — the overload that reaches <see cref="ClientAuthenticationMethod.PrivateKeyJwt"/>.
    /// </summary>
    /// <param name="registration">The registration identifying the authorization server.</param>
    /// <param name="request">The refresh token request.</param>
    /// <param name="context">The per-operation exchange context threaded into the transport and flow-state delegates.</param>
    /// <param name="clientAssertionOptions">
    /// The <c>private_key_jwt</c> client-assertion signing inputs (RFC 7523 §2.2). Required when
    /// <see cref="ClientRegistration.AuthenticationMethod"/> is
    /// <see cref="ClientAuthenticationMethod.PrivateKeyJwt"/>; ignored for every other method.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public ValueTask<AuthCodeFlowEndpointResult> RefreshAsync(
        ClientRegistration registration,
        RefreshTokenRequest request,
        ExchangeContext context,
        ClientAssertionOptions? clientAssertionOptions,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);

        return AuthCodeFlowHandlers.RefreshAsync(
            request, Infrastructure, registration, context, clientAssertionOptions, cancellationToken);
    }


    /// <summary>
    /// Revokes a token at the revocation endpoint.
    /// </summary>
    /// <param name="registration">The registration identifying the authorization server.</param>
    /// <param name="fields">
    /// The revocation request fields. Must include <c>token</c>.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public ValueTask<AuthCodeFlowEndpointResult> RevokeAsync(
        ClientRegistration registration,
        OAuthFormEncodedFields fields,
        CancellationToken cancellationToken) =>
        RevokeAsync(registration, fields, new ExchangeContext(), cancellationToken);


    /// <inheritdoc cref="RevokeAsync(ClientRegistration, OAuthFormEncodedFields, CancellationToken)"/>
    /// <param name="context">The per-operation exchange context threaded into the transport and flow-state delegates.</param>
    public ValueTask<AuthCodeFlowEndpointResult> RevokeAsync(
        ClientRegistration registration,
        OAuthFormEncodedFields fields,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);

        return AuthCodeFlowHandlers.HandleRevocationAsync(
            fields.Fields, Infrastructure, registration, context, cancellationToken);
    }


    /// <summary>
    /// Starts a JAR-bearing PAR+PKCE flow per RFC 9101 + RFC 9126: signs an
    /// AuthCode JAR carrying the PKCE challenge and the AuthCode claims, POSTs
    /// to the PAR endpoint with the outer <c>client_id</c> + <c>request</c>
    /// body, and returns the authorize redirect URI carrying the issued
    /// <c>request_uri</c>.
    /// </summary>
    /// <param name="registration">The registration identifying the authorization server.</param>
    /// <param name="jarOptions">Per-call inputs including signing key and serialisers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public ValueTask<AuthCodeFlowEndpointResult> StartJarParAsync(
        ClientRegistration registration,
        AuthCodeStartJarParOptions jarOptions,
        CancellationToken cancellationToken) =>
        StartJarParAsync(registration, jarOptions, new ExchangeContext(), cancellationToken);


    /// <inheritdoc cref="StartJarParAsync(ClientRegistration, AuthCodeStartJarParOptions, CancellationToken)"/>
    /// <param name="context">The per-operation exchange context threaded into the transport and flow-state delegates.</param>
    public ValueTask<AuthCodeFlowEndpointResult> StartJarParAsync(
        ClientRegistration registration,
        AuthCodeStartJarParOptions jarOptions,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(jarOptions);
        ArgumentNullException.ThrowIfNull(context);

        return AuthCodeFlowHandlers.HandleJarParAsync(
            jarOptions, Infrastructure, registration, context, cancellationToken);
    }


    /// <summary>
    /// Starts a JAR-by-value direct authorization per RFC 9101 §6.1: signs an
    /// AuthCode JAR and returns a redirect URL whose query carries
    /// <c>request=&lt;compact-jws&gt;</c> alongside the outer <c>client_id</c>.
    /// </summary>
    /// <param name="registration">The registration identifying the authorization server.</param>
    /// <param name="jarOptions">Per-call inputs including signing key and serialisers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public ValueTask<AuthCodeFlowEndpointResult> StartJarAuthorizeAsync(
        ClientRegistration registration,
        AuthCodeStartJarAuthorizeOptions jarOptions,
        CancellationToken cancellationToken) =>
        StartJarAuthorizeAsync(registration, jarOptions, new ExchangeContext(), cancellationToken);


    /// <inheritdoc cref="StartJarAuthorizeAsync(ClientRegistration, AuthCodeStartJarAuthorizeOptions, CancellationToken)"/>
    /// <param name="context">The per-operation exchange context threaded into the transport and flow-state delegates.</param>
    public ValueTask<AuthCodeFlowEndpointResult> StartJarAuthorizeAsync(
        ClientRegistration registration,
        AuthCodeStartJarAuthorizeOptions jarOptions,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(jarOptions);
        ArgumentNullException.ThrowIfNull(context);

        return AuthCodeFlowHandlers.HandleJarAuthorizeAsync(
            jarOptions, Infrastructure, registration, context, cancellationToken);
    }
}
