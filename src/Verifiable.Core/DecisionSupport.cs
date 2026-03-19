using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Core;

/// <summary>
/// Carries human-readable diagnostic information alongside a result or error,
/// enabling actionable guidance for developers debugging protocol failures.
/// </summary>
/// <remarks>
/// <para>
/// Protocol errors in OAuth, DID resolution, and credential verification are
/// notoriously opaque. An error code such as <c>invalid_request</c> from a PAR
/// endpoint could have a dozen distinct causes depending on context. This type
/// surfaces what the library knows about the likely cause, what the developer
/// should check, and where in the specification the relevant rules are defined.
/// </para>
/// <para>
/// <see cref="DecisionSupport"/> is carried by error cases in discriminated union
/// hierarchies — for example on <c>OAuthParseError</c> subtypes — rather than
/// on <see cref="Result{TValue, TError}"/> directly, so that the general-purpose
/// result type remains minimal and the diagnostic information is colocated with
/// the error that needs explaining.
/// </para>
/// <para>
/// The <see cref="Context"/> dictionary accumulates information from multiple
/// layers. The parser populates it with what the server returned. The flow handler
/// adds what the client sent. Transport metadata (OTel trace IDs, RFC 9457
/// <c>instance</c> URIs, server request IDs) may also be included. All of this
/// travels together so that a log entry or diagnostic tool has everything needed
/// to correlate the failure with server-side records.
/// </para>
/// </remarks>
[DebuggerDisplay("DecisionSupport Summary={Summary}")]
public sealed record DecisionSupport(string Summary)
{
    /// <summary>
    /// The most likely reason this error occurred, based on the library's
    /// knowledge of the specification and common implementation patterns.
    /// <see langword="null"/> when the cause cannot be inferred.
    /// </summary>
    public string? LikelyCause { get; init; }

    /// <summary>
    /// Concrete steps the developer should take to resolve the issue.
    /// <see langword="null"/> when no actionable guidance is available.
    /// </summary>
    public string? ActionableGuidance { get; init; }

    /// <summary>
    /// The specification section that defines the relevant rule or behaviour.
    /// For example: <c>RFC 9126 §2.3</c>, <c>RFC 6749 §5.2</c>,
    /// <c>RFC 9700 §4.4</c>. <see langword="null"/> when not applicable.
    /// </summary>
    public string? SpecificationReference { get; init; }

    /// <summary>
    /// An identifier that can be used to correlate this event with records in
    /// external systems. Sources include: W3C TraceContext <c>traceparent</c>
    /// captured from an HTTP response header, RFC 9457 <c>instance</c> URI
    /// from a problem+json response body, or a server-supplied request ID.
    /// <see langword="null"/> when no correlation identifier is available.
    /// </summary>
    public string? CorrelationId { get; init; }

    /// <summary>
    /// Accumulated context from all layers that handled this operation.
    /// Keys follow a <c>layer.field</c> naming convention, for example:
    /// <c>server.error_code</c>, <c>client.redirect_uri</c>,
    /// <c>transport.status_code</c>, <c>transport.traceparent</c>.
    /// <see langword="null"/> when no context was recorded.
    /// </summary>
    public IReadOnlyDictionary<string, string>? Context { get; init; }


    /// <summary>
    /// Returns a new <see cref="DecisionSupport"/> with additional context entries
    /// merged into <see cref="Context"/>. Existing keys are overwritten by
    /// <paramref name="additionalContext"/> entries.
    /// </summary>
    public DecisionSupport WithContext(IReadOnlyDictionary<string, string> additionalContext)
    {
        ArgumentNullException.ThrowIfNull(additionalContext);

        if(additionalContext.Count == 0)
        {
            return this;
        }

        var merged = new Dictionary<string, string>(
            Context?.Count ?? 0 + additionalContext.Count);

        if(Context is not null)
        {
            foreach(KeyValuePair<string, string> entry in Context)
            {
                merged[entry.Key] = entry.Value;
            }
        }

        foreach(KeyValuePair<string, string> entry in additionalContext)
        {
            merged[entry.Key] = entry.Value;
        }

        return this with { Context = merged };
    }


    /// <summary>
    /// Returns a new <see cref="DecisionSupport"/> with a single additional
    /// context entry. If the key already exists it is overwritten.
    /// </summary>
    public DecisionSupport WithContext(string key, string value)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(value);

        var merged = new Dictionary<string, string>(
            (Context?.Count ?? 0) + 1);

        if(Context is not null)
        {
            foreach(KeyValuePair<string, string> entry in Context)
            {
                merged[entry.Key] = entry.Value;
            }
        }

        merged[key] = value;
        return this with { Context = merged };
    }


    /// <summary>
    /// Returns a new <see cref="DecisionSupport"/> with the supplied
    /// correlation identifier set.
    /// </summary>
    public DecisionSupport WithCorrelationId(string correlationId)
    {
        ArgumentNullException.ThrowIfNull(correlationId);
        return this with { CorrelationId = correlationId };
    }
}