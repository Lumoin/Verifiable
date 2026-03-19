using System.Diagnostics;
using Verifiable.OAuth.AuthCode;

namespace Verifiable.OAuth;

/// <summary>
/// An OAuth 2.0 Authorization Code client that drives PKCE-protected flows
/// from PAR through token exchange.
/// </summary>
/// <remarks>
/// <para>
/// This is the primary client type an application developer constructs at startup
/// and registers in the dependency injection container:
/// </para>
/// <code>
/// var client = new AuthCodeClient(AuthCodeFlowOptions.Create(
///     clientId: "my-app",
///     endpoints: discoveredEndpoints,
///     sendFormPostAsync: async (endpoint, fields, ct) =>
///     {
///         //Any transport: HttpClient, named pipe, in-process, gRPC.
///         var content = new FormUrlEncodedContent(fields);
///         var response = await httpClient.PostAsync(endpoint, content, ct);
///         return new HttpResponseData
///         {
///             Body = await response.Content.ReadAsStringAsync(ct),
///             StatusCode = (int)response.StatusCode
///         };
///     },
///     ...));
/// </code>
/// <para>
/// The transport is a delegate. The client never knows whether it talks to the
/// authorization server over HTTP, a named pipe, an in-process method call, or
/// any other channel. OAuth is an HTTP protocol — the URIs and status codes are
/// protocol-level, not transport-level — so the delegate shape fits all backends.
/// </para>
/// </remarks>
[DebuggerDisplay("AuthCodeClient ClientId={Options.ClientId}")]
public sealed class AuthCodeClient
{
    /// <summary>The validated client options carrying all delegates.</summary>
    public AuthCodeFlowOptions Options { get; }


    /// <summary>
    /// Creates a new Authorization Code client with the given options.
    /// </summary>
    /// <param name="options">
    /// The client options carrying transport, persistence, and validation delegates.
    /// </param>
    public AuthCodeClient(AuthCodeFlowOptions options)
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
    /// <c>acr_values</c>). May be empty.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public ValueTask<AuthCodeFlowEndpointResult> StartParAsync(
        IReadOnlyDictionary<string, string> additionalFields,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(additionalFields);

        return AuthCodeFlowHandlers.HandleParAsync(additionalFields, Options, cancellationToken);
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
        IReadOnlyDictionary<string, string> callbackParams,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(callbackParams);

        return AuthCodeFlowHandlers.HandleCallbackAsync(callbackParams, Options, cancellationToken);
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
        IReadOnlyDictionary<string, string> fields,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(fields);

        return AuthCodeFlowHandlers.HandleRevocationAsync(fields, Options, cancellationToken);
    }
}