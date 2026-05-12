using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
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
/// <strong>Usage.</strong>
/// </para>
/// <code>
/// OAuthClient client = new(infrastructure);
/// ClientRegistration registration = LoadFromStore(clientId);
///
/// AuthCodeFlowEndpointResult redirect = await client.AuthCode.StartParAsync(
///     registration, OAuthFormEncodedFields.Empty, ct);
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
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(redirectUri);

        return AuthCodeFlowHandlers.HandleParAsync(
            additionalFields.Fields, redirectUri, Infrastructure, registration, cancellationToken);
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
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registration);

        return AuthCodeFlowHandlers.HandleCallbackAsync(
            callbackParams.Fields, Infrastructure, registration, cancellationToken);
    }


    /// <summary>
    /// Exchanges the authorization code and PKCE verifier for tokens at the
    /// token endpoint.
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
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentException.ThrowIfNullOrWhiteSpace(flowId);

        return AuthCodeFlowHandlers.HandleTokenAsync(
            new Dictionary<string, string> { [AuthCodeFlowRoutes.FlowIdField] = flowId },
            Infrastructure,
            registration,
            cancellationToken);
    }


    /// <summary>
    /// Refreshes an access token using a refresh token.
    /// </summary>
    /// <param name="registration">The registration identifying the authorization server.</param>
    /// <param name="request">The refresh token request.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public ValueTask<AuthCodeFlowEndpointResult> RefreshAsync(
        ClientRegistration registration,
        RefreshTokenRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(request);

        return AuthCodeFlowHandlers.RefreshAsync(request, Infrastructure, registration, cancellationToken);
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
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registration);

        return AuthCodeFlowHandlers.HandleRevocationAsync(
            fields.Fields, Infrastructure, registration, cancellationToken);
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
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(jarOptions);

        return AuthCodeFlowHandlers.HandleJarParAsync(
            jarOptions, Infrastructure, registration, cancellationToken);
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
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(jarOptions);

        return AuthCodeFlowHandlers.HandleJarAuthorizeAsync(
            jarOptions, Infrastructure, registration, cancellationToken);
    }
}
