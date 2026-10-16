using System.Diagnostics;
using Verifiable.Core.Assessment;
using Verifiable.OAuth.Client;

namespace Verifiable.OAuth.AuthCode;

/// <summary>
/// The outcome kind returned by an <c>AuthCodeFlowEndpoint</c> handler.
/// </summary>
public enum AuthCodeFlowEndpointOutcome
{
    /// <summary>
    /// The request was processed successfully. The caller should return an HTTP 200
    /// response with <see cref="AuthCodeFlowEndpointResult.Body"/> as the response body.
    /// </summary>
    Ok,

    /// <summary>
    /// The request was processed and the caller should redirect the user agent.
    /// <see cref="AuthCodeFlowEndpointResult.RedirectUri"/> carries the target URI.
    /// </summary>
    Redirect,

    /// <summary>
    /// The request contained invalid parameters. The caller should return HTTP 400.
    /// <see cref="AuthCodeFlowEndpointResult.ErrorCode"/> and
    /// <see cref="AuthCodeFlowEndpointResult.ErrorDescription"/> carry the OAuth error.
    /// </summary>
    BadRequest,

    /// <summary>
    /// An internal error occurred. The caller should return HTTP 500.
    /// </summary>
    InternalError
}


/// <summary>
/// Where a refusal the flow answers came from, stated by the flow where it constructs the refusal: the authorization server's
/// own answer, or the client library's judgement made without one.
/// </summary>
/// <remarks>
/// The default value of the type is <see cref="None"/>, never an origin: a refusal constructed with an origin never set is
/// refused by <see cref="AuthCodeFlowEndpointResult.Refused(AuthCodeFlowEndpointOutcome, AuthCodeFlowRefusalOrigin, string?, string?)"/>
/// rather than read as the authorization server's answer.
/// </remarks>
public enum AuthCodeFlowRefusalOrigin
{
    /// <summary>
    /// No origin: the type's default value, which states neither origin. No result carries it: a success or a redirect carries
    /// no origin at all, and every refusal factory refuses it.
    /// </summary>
    None = 0,

    /// <summary>
    /// The authorization server answered with the error the refusal carries: an error response of its token or pushed
    /// authorization request endpoint (RFC 6749 section 5.2, RFC 9126 section 2.3), or the error of its authorization
    /// response whose state names this client's pending authorization request and which passed every callback check that
    /// request holds it to (RFC 6749 section 4.1.2.1, RFC 9207 section 2.4).
    /// </summary>
    AuthorizationServerAnswer = 1,

    /// <summary>
    /// The library refused on its own judgement: a request it would not compose or send, an answer it could not read as the
    /// specification shapes one, an authorization response one of its checks refused, or an authorization error response
    /// that names no pending authorization request of this client, so no authorization server is established as its author.
    /// </summary>
    ClientJudgement = 2
}


/// <summary>
/// The framework-agnostic result returned by an <c>AuthCodeFlowEndpoint</c> handler.
/// </summary>
/// <remarks>
/// The caller inspects <see cref="Outcome"/> and maps to the appropriate HTTP response.
/// No HTTP framework types are referenced here, keeping <c>Verifiable.OAuth</c> free
/// of framework dependencies.
/// A result is constructed only through its factories: <see cref="Succeeded"/> and <see cref="Redirected"/> carry no
/// refusal origin, and every refusal is constructed by <see cref="Refused(AuthCodeFlowEndpointOutcome, AuthCodeFlowRefusalOrigin, string?, string?)"/>
/// or its overloads, which take the origin as a value of the type and refuse an outcome that is no refusal and an origin
/// that is neither of the two the flow defines. A <see cref="AuthCodeFlowEndpointOutcome.BadRequest"/> or
/// <see cref="AuthCodeFlowEndpointOutcome.InternalError"/> result without an established origin therefore cannot exist.
/// </remarks>
[DebuggerDisplay("AuthCodeFlowEndpointResult Outcome={Outcome}")]
public sealed class AuthCodeFlowEndpointResult
{
    /// <summary>Constructs a result from the values one of the factories has established.</summary>
    /// <param name="outcome">The outcome.</param>
    /// <param name="body">The response body of a successful result.</param>
    /// <param name="redirectUri">The redirect target of a redirecting result.</param>
    /// <param name="errorCode">The error code of a refusal.</param>
    /// <param name="errorDescription">The error description of a refusal.</param>
    /// <param name="refusalOrigin">The origin of a refusal.</param>
    /// <param name="clientAssertionCredentialRefusal">The client assertion credential refusal a refusal carries.</param>
    /// <param name="validationClaims">The callback validation claims.</param>
    private AuthCodeFlowEndpointResult(
        AuthCodeFlowEndpointOutcome outcome,
        IReadOnlyDictionary<string, object>? body,
        Uri? redirectUri,
        string? errorCode,
        string? errorDescription,
        AuthCodeFlowRefusalOrigin? refusalOrigin,
        ClientAssertionCredentialRefusal? clientAssertionCredentialRefusal,
        IReadOnlyList<Claim> validationClaims)
    {
        Outcome = outcome;
        Body = body;
        RedirectUri = redirectUri;
        ErrorCode = errorCode;
        ErrorDescription = errorDescription;
        RefusalOrigin = refusalOrigin;
        ClientAssertionCredentialRefusal = clientAssertionCredentialRefusal;
        ValidationClaims = validationClaims;
    }


    /// <summary>The outcome of the handler invocation.</summary>
    public AuthCodeFlowEndpointOutcome Outcome { get; }

    /// <summary>
    /// The response body to return for <see cref="AuthCodeFlowEndpointOutcome.Ok"/> outcomes.
    /// <see langword="null"/> for other outcomes.
    /// </summary>
    public IReadOnlyDictionary<string, object>? Body { get; }

    /// <summary>
    /// The redirect target URI for <see cref="AuthCodeFlowEndpointOutcome.Redirect"/> outcomes.
    /// <see langword="null"/> for other outcomes.
    /// </summary>
    public Uri? RedirectUri { get; }

    /// <summary>
    /// The OAuth error code for <see cref="AuthCodeFlowEndpointOutcome.BadRequest"/> outcomes,
    /// e.g. <c>invalid_request</c> or <c>invalid_client</c>.
    /// <see langword="null"/> for other outcomes.
    /// </summary>
    public string? ErrorCode { get; }

    /// <summary>
    /// A human-readable description of the error for
    /// <see cref="AuthCodeFlowEndpointOutcome.BadRequest"/> outcomes.
    /// <see langword="null"/> for other outcomes.
    /// </summary>
    public string? ErrorDescription { get; }

    /// <summary>
    /// Where the refusal came from, stated where the flow constructs it, for
    /// <see cref="AuthCodeFlowEndpointOutcome.BadRequest"/> and <see cref="AuthCodeFlowEndpointOutcome.InternalError"/>
    /// outcomes: the authorization server's own answer, whose code <see cref="ErrorCode"/> is, or the library's judgement,
    /// whose reason it is. Every refusal carries one of the two, since the refusal factories accept no other value;
    /// <see langword="null"/> for <see cref="AuthCodeFlowEndpointOutcome.Ok"/> and
    /// <see cref="AuthCodeFlowEndpointOutcome.Redirect"/> outcomes.
    /// </summary>
    public AuthCodeFlowRefusalOrigin? RefusalOrigin { get; }

    /// <summary>
    /// The refusal of the client authentication assertion the request was to present, judged before anything was composed
    /// or sent (<see cref="ClientAssertionCredential.Of"/>): the rule broken and the values it was judged
    /// on, from which <see cref="ErrorDescription"/> was rendered. <see langword="null"/> for every other outcome.
    /// </summary>
    public ClientAssertionCredentialRefusal? ClientAssertionCredentialRefusal { get; }

    /// <summary>
    /// The individual validation claims produced during callback validation.
    /// Populated when the callback <see cref="ClaimIssuer{TInput}"/> was invoked — i.e., for
    /// all outcomes of <see cref="AuthCodeClient.HandleCallbackAsync(Verifiable.OAuth.Client.ClientRegistration, OAuthFormEncodedFields, CancellationToken)"/>. Empty for other handlers.
    /// </summary>
    /// <remarks>
    /// Callers can inspect this list to feed per-check outcomes into monitoring,
    /// distributed tracing, or audit logs, identifying which specific security check
    /// failed without parsing the <see cref="ErrorDescription"/> string.
    /// </remarks>
    public IReadOnlyList<Claim> ValidationClaims { get; }


    /// <summary>A successful result, carrying no refusal origin.</summary>
    /// <param name="body">The response body, or <see langword="null"/> for a success that answers none.</param>
    /// <returns>The <see cref="AuthCodeFlowEndpointOutcome.Ok"/> result.</returns>
    public static AuthCodeFlowEndpointResult Succeeded(IReadOnlyDictionary<string, object>? body) =>
        new(AuthCodeFlowEndpointOutcome.Ok, body, redirectUri: null, errorCode: null, errorDescription: null,
            refusalOrigin: null, clientAssertionCredentialRefusal: null, validationClaims: []);


    /// <summary>A result redirecting the user agent, carrying no refusal origin.</summary>
    /// <param name="redirectUri">The redirect target.</param>
    /// <returns>The <see cref="AuthCodeFlowEndpointOutcome.Redirect"/> result.</returns>
    public static AuthCodeFlowEndpointResult Redirected(Uri redirectUri)
    {
        ArgumentNullException.ThrowIfNull(redirectUri);

        return new(AuthCodeFlowEndpointOutcome.Redirect, body: null, redirectUri, errorCode: null, errorDescription: null,
            refusalOrigin: null, clientAssertionCredentialRefusal: null, validationClaims: []);
    }


    /// <summary>A refusal stating where it came from.</summary>
    /// <param name="outcome">The refusal's outcome: <see cref="AuthCodeFlowEndpointOutcome.BadRequest"/> or <see cref="AuthCodeFlowEndpointOutcome.InternalError"/>.</param>
    /// <param name="origin">Where the refusal came from: one of the two origins the flow defines.</param>
    /// <param name="errorCode">The OAuth error code.</param>
    /// <param name="errorDescription">The error description.</param>
    /// <returns>The refusal.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The outcome is no refusal, or the origin is neither origin the flow defines.</exception>
    public static AuthCodeFlowEndpointResult Refused(
        AuthCodeFlowEndpointOutcome outcome, AuthCodeFlowRefusalOrigin origin, string? errorCode, string? errorDescription) =>
        Refusal(outcome, origin, errorCode, errorDescription, clientAssertionCredentialRefusal: null, validationClaims: []);


    /// <summary>A refusal of the callback, stating where it came from and carrying the claims its validation produced.</summary>
    /// <param name="outcome">The refusal's outcome: <see cref="AuthCodeFlowEndpointOutcome.BadRequest"/> or <see cref="AuthCodeFlowEndpointOutcome.InternalError"/>.</param>
    /// <param name="origin">Where the refusal came from: one of the two origins the flow defines.</param>
    /// <param name="errorCode">The OAuth error code.</param>
    /// <param name="errorDescription">The error description.</param>
    /// <param name="validationClaims">The claims the callback validation produced.</param>
    /// <returns>The refusal.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The outcome is no refusal, or the origin is neither origin the flow defines.</exception>
    public static AuthCodeFlowEndpointResult Refused(
        AuthCodeFlowEndpointOutcome outcome,
        AuthCodeFlowRefusalOrigin origin,
        string? errorCode,
        string? errorDescription,
        IReadOnlyList<Claim> validationClaims)
    {
        ArgumentNullException.ThrowIfNull(validationClaims);

        return Refusal(outcome, origin, errorCode, errorDescription, clientAssertionCredentialRefusal: null, validationClaims);
    }


    /// <summary>A refusal of the client assertion credential, stating where it came from and carrying the credential's typed refusal.</summary>
    /// <param name="outcome">The refusal's outcome: <see cref="AuthCodeFlowEndpointOutcome.BadRequest"/> or <see cref="AuthCodeFlowEndpointOutcome.InternalError"/>.</param>
    /// <param name="origin">Where the refusal came from: one of the two origins the flow defines.</param>
    /// <param name="errorCode">The OAuth error code.</param>
    /// <param name="errorDescription">The error description, rendered from the credential's refusal.</param>
    /// <param name="clientAssertionCredentialRefusal">The credential's typed refusal.</param>
    /// <returns>The refusal.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The outcome is no refusal, or the origin is neither origin the flow defines.</exception>
    public static AuthCodeFlowEndpointResult Refused(
        AuthCodeFlowEndpointOutcome outcome,
        AuthCodeFlowRefusalOrigin origin,
        string? errorCode,
        string? errorDescription,
        ClientAssertionCredentialRefusal clientAssertionCredentialRefusal)
    {
        ArgumentNullException.ThrowIfNull(clientAssertionCredentialRefusal);

        return Refusal(outcome, origin, errorCode, errorDescription, clientAssertionCredentialRefusal, validationClaims: []);
    }


    /// <summary>The one construction of every refusal, which establishes its outcome and its origin before it constructs it.</summary>
    /// <param name="outcome">The refusal's outcome.</param>
    /// <param name="origin">Where the refusal came from.</param>
    /// <param name="errorCode">The OAuth error code.</param>
    /// <param name="errorDescription">The error description.</param>
    /// <param name="clientAssertionCredentialRefusal">The credential's typed refusal, or <see langword="null"/> for none.</param>
    /// <param name="validationClaims">The claims the callback validation produced.</param>
    /// <returns>The refusal.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The outcome is no refusal, or the origin is neither origin the flow defines.</exception>
    private static AuthCodeFlowEndpointResult Refusal(
        AuthCodeFlowEndpointOutcome outcome,
        AuthCodeFlowRefusalOrigin origin,
        string? errorCode,
        string? errorDescription,
        ClientAssertionCredentialRefusal? clientAssertionCredentialRefusal,
        IReadOnlyList<Claim> validationClaims)
    {
        if(outcome is not (AuthCodeFlowEndpointOutcome.BadRequest or AuthCodeFlowEndpointOutcome.InternalError))
        {
            throw new ArgumentOutOfRangeException(nameof(outcome), outcome,
                "A refusal is a BadRequest or an InternalError outcome; a success or a redirect is constructed by its own factory and carries no refusal origin.");
        }

        //A value of neither origin, the default None among them, would let a refusal state no author of its error.
        if(origin is not (AuthCodeFlowRefusalOrigin.AuthorizationServerAnswer or AuthCodeFlowRefusalOrigin.ClientJudgement))
        {
            throw new ArgumentOutOfRangeException(nameof(origin), origin,
                "A refusal states where it came from: the authorization server's answer or the client's judgement, and no other value.");
        }

        return new(outcome, body: null, redirectUri: null, errorCode, errorDescription, origin, clientAssertionCredentialRefusal, validationClaims);
    }
}
