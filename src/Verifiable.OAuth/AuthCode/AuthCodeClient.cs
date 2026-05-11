using System.Diagnostics;
using Verifiable.OAuth.Client;

namespace Verifiable.OAuth.AuthCode;

/// <summary>
/// The Authorization Code sub-client of <see cref="OAuthClient"/>. Drives
/// PKCE-protected flows from PAR through token exchange, refresh, and
/// revocation.
/// </summary>
/// <remarks>
/// <para>
/// Constructed by <see cref="OAuthClient"/>; not directly constructible
/// from application code. Application authors construct an
/// <see cref="OAuthClient"/> at startup and access this sub-client via
/// <see cref="OAuthClient.AuthCode"/>.
/// </para>
/// <code>
/// var client = new OAuthClient(OAuthClientOptions.Create(...));
/// var redirect = await client.AuthCode.StartParAsync(
///     OAuthFormEncodedFields.Empty, ct);
/// </code>
/// </remarks>
[DebuggerDisplay("AuthCodeClient ClientId={Options.ClientId}")]
public sealed class AuthCodeClient
{
    /// <summary>The validated client options carrying all delegates.</summary>
    public OAuthClientOptions Options { get; }


    /// <summary>
    /// Creates a new Authorization Code client. Internal — use
    /// <see cref="OAuthClient.AuthCode"/> to access an instance.
    /// </summary>
    /// <param name="options">
    /// The client options carrying transport, persistence, and validation delegates.
    /// </param>
    internal AuthCodeClient(OAuthClientOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        Options = options;
    }


    /// <summary>
    /// Starts a PAR+PKCE flow: generates a fresh PKCE verifier and challenge,
    /// sends a Pushed Authorization Request, and returns a redirect to the
    /// authorization endpoint with the <c>request_uri</c>.
    /// </summary>
    /// <param name="additionalFields">
    /// Additional fields to include in the PAR request body (e.g., <c>scope</c>,
    /// <c>acr_values</c>). May be <see cref="OAuthFormEncodedFields.Empty"/>.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public ValueTask<AuthCodeFlowEndpointResult> StartParAsync(
        OAuthFormEncodedFields additionalFields,
        CancellationToken cancellationToken)
    {
        return AuthCodeFlowHandlers.HandleParAsync(additionalFields.Fields, Options, cancellationToken);
    }


    /// <summary>
    /// Handles the authorization callback: validates the <c>iss</c> parameter
    /// (when HAIP/RFC 9207 is active), extracts the authorization <c>code</c>,
    /// and persists the code-received state.
    /// </summary>
    /// <param name="callbackParams">
    /// The query parameters from the authorization callback redirect.
    /// Must include <c>code</c>, <c>state</c>, and (for HAIP) <c>iss</c>.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public ValueTask<AuthCodeFlowEndpointResult> HandleCallbackAsync(
        OAuthFormEncodedFields callbackParams,
        CancellationToken cancellationToken)
    {
        return AuthCodeFlowHandlers.HandleCallbackAsync(callbackParams.Fields, Options, cancellationToken);
    }


    /// <summary>
    /// Exchanges the authorization code and PKCE verifier for tokens at the
    /// token endpoint.
    /// </summary>
    /// <param name="flowId">
    /// The flow identifier (the <c>state</c> value) that correlates this token
    /// request with the original PAR.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public ValueTask<AuthCodeFlowEndpointResult> ExchangeTokenAsync(
        string flowId,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(flowId);

        return AuthCodeFlowHandlers.HandleTokenAsync(
                new Dictionary<string, string> { [AuthCodeFlowRoutes.FlowIdField] = flowId },
                Options,
                cancellationToken);
    }


    /// <summary>
    /// Refreshes an access token using a refresh token.
    /// </summary>
    /// <param name="request">The refresh token request.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public ValueTask<AuthCodeFlowEndpointResult> RefreshAsync(
        RefreshTokenRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        return AuthCodeFlowHandlers.RefreshAsync(request, Options, cancellationToken);
    }


    /// <summary>
    /// Revokes a token at the revocation endpoint.
    /// </summary>
    /// <param name="fields">
    /// The revocation request fields. Must include <c>token</c>.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public ValueTask<AuthCodeFlowEndpointResult> RevokeAsync(
        OAuthFormEncodedFields fields,
        CancellationToken cancellationToken)
    {
        return AuthCodeFlowHandlers.HandleRevocationAsync(fields.Fields, Options, cancellationToken);
    }


    /// <summary>
    /// Starts a JAR-bearing PAR+PKCE flow per RFC 9101 + RFC 9126: signs an
    /// AuthCode JAR carrying the PKCE challenge and the AuthCode claims, POSTs
    /// to the PAR endpoint with the outer <c>client_id</c> + <c>request</c>
    /// body, and returns the authorize redirect URI carrying the issued
    /// <c>request_uri</c>.
    /// </summary>
    /// <param name="jarOptions">Per-call inputs including signing key and serialisers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public ValueTask<AuthCodeFlowEndpointResult> StartJarParAsync(
        AuthCodeStartJarParOptions jarOptions,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(jarOptions);

        return AuthCodeFlowHandlers.HandleJarParAsync(jarOptions, Options, cancellationToken);
    }


    /// <summary>
    /// Starts a JAR-by-value direct authorization per RFC 9101 §6.1: signs an
    /// AuthCode JAR and returns a redirect URL whose query carries
    /// <c>request=&lt;compact-jws&gt;</c> alongside the outer <c>client_id</c>.
    /// </summary>
    /// <param name="jarOptions">Per-call inputs including signing key and serialisers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public ValueTask<AuthCodeFlowEndpointResult> StartJarAuthorizeAsync(
        AuthCodeStartJarAuthorizeOptions jarOptions,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(jarOptions);

        return AuthCodeFlowHandlers.HandleJarAuthorizeAsync(jarOptions, Options, cancellationToken);
    }
}
