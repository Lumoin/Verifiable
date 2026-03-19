using System;
using System.Globalization;
using Verifiable.Core;

namespace Verifiable.OAuth;

/// <summary>
/// Discriminated union base for errors produced when parsing OAuth protocol
/// endpoint responses.
/// </summary>
/// <remarks>
/// <para>
/// Three distinct failure modes exist when parsing a PAR or token endpoint
/// response. Callers must distinguish between them to respond appropriately:
/// </para>
/// <list type="bullet">
///   <item>
///     <description>
///       <see cref="OAuthProtocolError"/> — the server returned a well-formed
///       OAuth error response. The request reached the server and was understood.
///       Retry may be possible after fixing the request.
///     </description>
///   </item>
///   <item>
///     <description>
///       <see cref="OAuthMalformedResponse"/> — the response body could not be
///       parsed as a valid OAuth response. The server may have returned an HTML
///       error page, a proxy may have intercepted the request, or the wrong
///       endpoint was called.
///     </description>
///   </item>
///   <item>
///     <description>
///       <see cref="OAuthInvalidFieldValue"/> — a required field was present but
///       its value failed validation per the relevant specification.
///     </description>
///   </item>
/// </list>
/// <para>
/// Each case carries a <see cref="DecisionSupport"/> record with the library's
/// assessment of the likely cause, actionable guidance, and any correlation
/// identifiers available from the transport layer.
/// </para>
/// </remarks>
public abstract record OAuthParseError(DecisionSupport Support)
{
    /// <summary>
    /// Returns a new <see cref="OAuthParseError"/> of the same derived type
    /// with <see cref="DecisionSupport"/> enriched by the supplied transport
    /// metadata from <see cref="HttpResponseData"/>.
    /// </summary>
    public OAuthParseError WithTransportMetadata(HttpResponseData response)
    {
        DecisionSupport enriched = Support;

        string? traceParent = response.GetMetadata(HttpResponseDataKeys.TraceParent);
        if(traceParent is not null)
        {
            enriched = enriched.WithCorrelationId(traceParent);
        }

        string? requestId = response.GetMetadata(HttpResponseDataKeys.RequestId);
        if(requestId is not null)
        {
            enriched = enriched.WithContext(HttpResponseDataKeys.RequestId, requestId);
        }

        enriched = enriched.WithContext(
            HttpResponseDataKeys.StatusCode,
            response.StatusCode.ToString(CultureInfo.InvariantCulture));

        return this with { Support = enriched };
    }
}


/// <summary>
/// The server returned a well-formed OAuth error response per
/// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 §5.2</see>
/// or
/// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.3">RFC 9126 §2.3</see>.
/// </summary>
/// <remarks>
/// This is a protocol-level error, not a parse failure. The request reached the
/// server and was understood; the server rejected it for a protocol reason.
/// Common error codes and their meanings:
/// <list type="bullet">
///   <item><description>
///     <c>invalid_request</c> — a required parameter is missing, malformed, or repeated.
///     In HAIP 1.0 contexts this frequently means <c>code_challenge</c> is absent
///     or <c>redirect_uri</c> does not exactly match the registered value.
///   </description></item>
///   <item><description>
///     <c>invalid_client</c> — client authentication failed. Check client credentials
///     and registration status.
///   </description></item>
///   <item><description>
///     <c>access_denied</c> — the resource owner or authorization server denied the request.
///   </description></item>
///   <item><description>
///     <c>unauthorized_client</c> — the client is not authorised to use this grant type
///     or request type.
///   </description></item>
/// </list>
/// </remarks>
public sealed record OAuthProtocolError(
    string ErrorCode,
    DecisionSupport Support,
    string? ErrorDescription = null,
    Uri? ErrorUri = null): OAuthParseError(Support);


/// <summary>
/// The response body could not be recognised as a valid OAuth protocol
/// response or RFC 9457 problem+json document.
/// </summary>
/// <remarks>
/// Common causes: the wrong endpoint was called, a reverse proxy or firewall
/// returned an HTML error page, the connection was truncated, or the server
/// has a bug. The raw <see cref="Body"/> is preserved for logging and diagnostic
/// purposes.
/// </remarks>
public sealed record OAuthMalformedResponse(
    string Body,
    DecisionSupport Support): OAuthParseError(Support);


/// <summary>
/// A required field was present in the response but its value failed validation
/// according to the specification.
/// </summary>
/// <remarks>
/// Examples: <c>expires_in</c> was zero or negative (RFC 9126 §2.2 requires a
/// positive integer), <c>request_uri</c> was a relative URI rather than an
/// absolute one, or <c>access_token</c> was an empty string.
/// </remarks>
public sealed record OAuthInvalidFieldValue(
    string FieldName,
    string ReceivedValue,
    string Reason,
    DecisionSupport Support): OAuthParseError(Support);