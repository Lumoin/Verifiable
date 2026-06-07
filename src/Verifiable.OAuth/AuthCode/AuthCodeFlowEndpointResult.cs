using System;
using System.Collections.Generic;
using System.Diagnostics;
using Verifiable.Core.Assessment;

namespace Verifiable.OAuth.AuthCode;

/// <summary>
/// The outcome kind returned by an <see cref="AuthCodeFlowEndpoint"/> handler.
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
/// The framework-agnostic result returned by an <see cref="AuthCodeFlowEndpoint"/> handler.
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
    /// The individual validation claims produced during callback validation.
    /// Populated when <see cref="ValidateCallbackDelegate"/> was invoked — i.e., for
    /// all outcomes of <see cref="HandleCallbackAsync"/>. Empty for other handlers.
    /// </summary>
    /// <remarks>
    /// Callers can inspect this list to feed per-check outcomes into monitoring,
    /// distributed tracing, or audit logs, identifying which specific security check
    /// failed without parsing the <see cref="ErrorDescription"/> string.
    /// </remarks>
    public IReadOnlyList<Claim> ValidationClaims { get; init; } = [];
}