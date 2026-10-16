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
public enum AuthCodeFlowRefusalOrigin
{
    /// <summary>
    /// The authorization server answered with the error the refusal carries: an error response of its token or pushed
    /// authorization request endpoint (RFC 6749 section 5.2, RFC 9126 section 2.3), or the error of its authorization
    /// response whose state names this client's pending authorization request and which passed every callback check that
    /// request holds it to (RFC 6749 section 4.1.2.1, RFC 9207 section 2.4).
    /// </summary>
    AuthorizationServerAnswer,

    /// <summary>
    /// The library refused on its own judgement: a request it would not compose or send, an answer it could not read as the
    /// specification shapes one, an authorization response one of its checks refused, or an authorization error response
    /// that names no pending authorization request of this client, so no authorization server is established as its author.
    /// </summary>
    ClientJudgement
}


/// <summary>
/// The framework-agnostic result returned by an <c>AuthCodeFlowEndpoint</c> handler.
/// </summary>
/// <remarks>
/// The caller inspects <see cref="Outcome"/> and maps to the appropriate HTTP response.
/// No HTTP framework types are referenced here, keeping <c>Verifiable.OAuth</c> free
/// of framework dependencies.
/// </remarks>
[DebuggerDisplay("AuthCodeFlowEndpointResult Outcome={Outcome}")]
public sealed class AuthCodeFlowEndpointResult
{
    /// <summary>The outcome of the handler invocation.</summary>
    public required AuthCodeFlowEndpointOutcome Outcome { get; init; }

    /// <summary>
    /// The response body to return for <see cref="AuthCodeFlowEndpointOutcome.Ok"/> outcomes.
    /// <see langword="null"/> for other outcomes.
    /// </summary>
    public IReadOnlyDictionary<string, object>? Body { get; init; }

    /// <summary>
    /// The redirect target URI for <see cref="AuthCodeFlowEndpointOutcome.Redirect"/> outcomes.
    /// <see langword="null"/> for other outcomes.
    /// </summary>
    public Uri? RedirectUri { get; init; }

    /// <summary>
    /// The OAuth error code for <see cref="AuthCodeFlowEndpointOutcome.BadRequest"/> outcomes,
    /// e.g. <c>invalid_request</c> or <c>invalid_client</c>.
    /// <see langword="null"/> for other outcomes.
    /// </summary>
    public string? ErrorCode { get; init; }

    /// <summary>
    /// A human-readable description of the error for
    /// <see cref="AuthCodeFlowEndpointOutcome.BadRequest"/> outcomes.
    /// <see langword="null"/> for other outcomes.
    /// </summary>
    public string? ErrorDescription { get; init; }

    /// <summary>
    /// Where the refusal came from, stated where the flow constructs it, for
    /// <see cref="AuthCodeFlowEndpointOutcome.BadRequest"/> and <see cref="AuthCodeFlowEndpointOutcome.InternalError"/>
    /// outcomes: the authorization server's own answer, whose code <see cref="ErrorCode"/> is, or the library's judgement,
    /// whose reason it is. <see langword="null"/> for <see cref="AuthCodeFlowEndpointOutcome.Ok"/> and
    /// <see cref="AuthCodeFlowEndpointOutcome.Redirect"/> outcomes.
    /// </summary>
    public AuthCodeFlowRefusalOrigin? RefusalOrigin { get; init; }

    /// <summary>
    /// The refusal of the client authentication assertion the request was to present, judged before anything was composed
    /// or sent (<see cref="ClientAssertionCredential.Of"/>): the rule broken and the values it was judged
    /// on, from which <see cref="ErrorDescription"/> was rendered. <see langword="null"/> for every other outcome.
    /// </summary>
    public ClientAssertionCredentialRefusal? ClientAssertionCredentialRefusal { get; init; }

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
    public IReadOnlyList<Claim> ValidationClaims { get; init; } = [];
}
