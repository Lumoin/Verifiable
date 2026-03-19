namespace Verifiable.OAuth.Server;

/// <summary>
/// Extracts the protocol correlation key from the inbound request for a specific
/// endpoint.
/// </summary>
/// <remarks>
/// <para>
/// When set on <see cref="ServerEndpoint.ExtractCorrelationKey"/>, the dispatcher
/// calls this delegate instead of the built-in cascade for endpoints whose
/// correlation key pattern differs from the standard OAuth handles (<c>request_uri</c>,
/// <c>code</c>, <c>state</c>, <c>device_code</c>).
/// </para>
/// <para>
/// Custom flows — CIBA (<c>auth_req_id</c>), OpenID Federation, or
/// application-specific protocols — set this delegate on their
/// <see cref="ServerEndpoint"/> records so the dispatcher can locate persisted
/// state without any change to the core correlation logic.
/// </para>
/// </remarks>
/// <param name="path">
/// The path suffix after <c>/connect/{segment}/</c>, e.g. <c>bc-authorize</c>,
/// <c>request/abc123</c>.
/// </param>
/// <param name="fields">The parsed request fields from the HTTP form body or query string.</param>
/// <param name="context">The per-request context bag.</param>
/// <returns>
/// The correlation key, or <see langword="null"/> when the key cannot be extracted.
/// Returning <see langword="null"/> causes the dispatcher to return a
/// <c>400 invalid_request</c> response.
/// </returns>
public delegate string? ExtractCorrelationKeyDelegate(
    string path,
    RequestFields fields,
    RequestContext context);
