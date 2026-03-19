using Verifiable.Core.Assessment;
using Verifiable.OAuth.Validation;
using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.OAuth.AuthCode;

/// <summary>
/// Configuration and I/O delegates for the Authorization Code flow handlers.
/// </summary>
/// <remarks>
/// <para>
/// All I/O — storage, HTTP, time, parsing, validation — is supplied via delegates.
/// The static handlers in <see cref="AuthCodeFlowHandlers"/> perform no I/O themselves.
/// </para>
/// <para>
/// Construct via <see cref="Create"/> to ensure all mandatory parameters are
/// validated at construction time. The same instance is safe to share across
/// concurrent requests.
/// </para>
/// </remarks>
[DebuggerDisplay("AuthCodeFlowOptions ClientId={ClientId}")]
public sealed class AuthCodeFlowOptions
{
    private AuthCodeFlowOptions() { }


    /// <summary>The client identifier registered with the authorization server.</summary>
    public string ClientId { get; private init; } = string.Empty;

    /// <summary>
    /// The resolved authorization server endpoints. Constructed by the caller after
    /// fetching and validating the well-known metadata document.
    /// </summary>
    public AuthorizationServerEndpoints Endpoints { get; private init; } = null!;

    /// <summary>
    /// The redirect URI registered for this client. Used in the PAR request body
    /// and the token exchange request.
    /// </summary>
    public Uri RedirectUri { get; private init; } = null!;

    /// <summary>
    /// Persists a flow state to durable storage at each state transition point.
    /// </summary>
    public SaveFlowStateDelegate SaveStateAsync { get; private init; } = null!;

    /// <summary>
    /// Loads a flow state from durable storage by flow identifier.
    /// </summary>
    public LoadFlowStateDelegate LoadStateAsync { get; private init; } = null!;

    /// <summary>
    /// Loads a flow state from durable storage by PAR <c>request_uri</c>.
    /// </summary>
    public LoadFlowStateByRequestUriDelegate LoadStateByRequestUriAsync { get; private init; } = null!;

    /// <summary>
    /// Sends an HTTP POST with a form-encoded body and returns the full HTTP response.
    /// Used for PAR, token exchange, refresh, and revocation requests.
    /// </summary>
    public SendFormPostDelegate SendFormPostAsync { get; private init; } = null!;

    /// <summary>
    /// Parses a PAR endpoint response. The default implementation is
    /// <see cref="OAuthResponseParsers.ParseParResponse"/>.
    /// </summary>
    public ParseParResponseDelegate ParseParResponseAsync { get; private init; } = null!;

    /// <summary>
    /// Parses a token endpoint response. The default implementation is
    /// <see cref="OAuthResponseParsers.ParseTokenResponse"/>.
    /// </summary>
    public ParseTokenResponseDelegate ParseTokenResponseAsync { get; private init; } = null!;

    /// <summary>
    /// Validates the inbound callback fields against the loaded flow state.
    /// Supply <see cref="ValidationProfiles.CallbackHaip10Rules"/> for HAIP 1.0 / FAPI 2.0,
    /// or <see cref="ValidationProfiles.CallbackRfc6749WithPkceRules"/> for plain RFC 6749.
    /// </summary>
    public ClaimIssuer<ValidationContext> CallbackValidator { get; private init; } = null!;

    /// <summary>
    /// Base64url encoder without padding. Required for PKCE verifier and
    /// challenge encoding per RFC 7636 §4.1–4.2.
    /// </summary>
    public EncodeDelegate Base64UrlEncoder { get; private init; } = null!;

    /// <summary>
    /// UTC time source. Defaults to <see cref="TimeProvider.System"/>.
    /// Inject <c>FakeTimeProvider</c> in tests for deterministic time control.
    /// </summary>
    public TimeProvider TimeProvider { get; private init; } = TimeProvider.System;


    /// <summary>
    /// Creates a fully validated <see cref="AuthCodeFlowOptions"/> instance.
    /// </summary>
    /// <param name="clientId">The client identifier registered with the authorization server.</param>
    /// <param name="endpoints">The resolved authorization server endpoints.</param>
    /// <param name="redirectUri">The redirect URI registered for this client.</param>
    /// <param name="saveStateAsync">Persists a flow state to durable storage.</param>
    /// <param name="loadStateAsync">Loads a flow state by flow identifier.</param>
    /// <param name="loadStateByRequestUriAsync">Loads a flow state by PAR request_uri.</param>
    /// <param name="sendFormPostAsync">Sends an HTTP form POST and returns the response.</param>
    /// <param name="parseParResponseAsync">Parses a PAR endpoint response.</param>
    /// <param name="parseTokenResponseAsync">Parses a token endpoint response.</param>
    /// <param name="callbackValidator">Validates the inbound authorization callback.</param>
    /// <param name="base64UrlEncoder">Base64url encoder without padding.</param>
    /// <param name="timeProvider">
    /// UTC time source. Defaults to <see cref="TimeProvider.System"/> when
    /// <see langword="null"/>.
    /// </param>
    /// <returns>A fully validated <see cref="AuthCodeFlowOptions"/> instance.</returns>
    public static AuthCodeFlowOptions Create(
        string clientId,
        AuthorizationServerEndpoints endpoints,
        Uri redirectUri,
        SaveFlowStateDelegate saveStateAsync,
        LoadFlowStateDelegate loadStateAsync,
        LoadFlowStateByRequestUriDelegate loadStateByRequestUriAsync,
        SendFormPostDelegate sendFormPostAsync,
        ParseParResponseDelegate parseParResponseAsync,
        ParseTokenResponseDelegate parseTokenResponseAsync,
        ClaimIssuer<ValidationContext> callbackValidator,
        EncodeDelegate base64UrlEncoder,
        TimeProvider? timeProvider = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentNullException.ThrowIfNull(redirectUri);
        ArgumentNullException.ThrowIfNull(saveStateAsync);
        ArgumentNullException.ThrowIfNull(loadStateAsync);
        ArgumentNullException.ThrowIfNull(loadStateByRequestUriAsync);
        ArgumentNullException.ThrowIfNull(sendFormPostAsync);
        ArgumentNullException.ThrowIfNull(parseParResponseAsync);
        ArgumentNullException.ThrowIfNull(parseTokenResponseAsync);
        ArgumentNullException.ThrowIfNull(callbackValidator);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);

        return new AuthCodeFlowOptions
        {
            ClientId = clientId,
            Endpoints = endpoints,
            RedirectUri = redirectUri,
            SaveStateAsync = saveStateAsync,
            LoadStateAsync = loadStateAsync,
            LoadStateByRequestUriAsync = loadStateByRequestUriAsync,
            SendFormPostAsync = sendFormPostAsync,
            ParseParResponseAsync = parseParResponseAsync,
            ParseTokenResponseAsync = parseTokenResponseAsync,
            CallbackValidator = callbackValidator,
            Base64UrlEncoder = base64UrlEncoder,
            TimeProvider = timeProvider ?? TimeProvider.System
        };
    }
}
