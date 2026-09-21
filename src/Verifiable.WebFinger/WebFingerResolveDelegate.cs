using Verifiable.Core;

namespace Verifiable.WebFinger;

/// <summary>
/// Resolves a WebFinger query target to a <see cref="WebFingerResolutionResult"/> by issuing an HTTPS query
/// to <paramref name="host"/> per <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4">RFC 7033
/// §4</see>. Built by <see cref="WebFingerClient.BuildResolving"/>.
/// </summary>
/// <param name="resource">
/// The query target (a URI, e.g. an <c>acct:</c> URI). Carried verbatim in the <c>resource</c> parameter.
/// </param>
/// <param name="host">
/// The host the query is issued to. Per §4 this SHOULD be the host portion of <paramref name="resource"/>,
/// unless an out-of-band mechanism directs otherwise — hence it is a separate argument.
/// </param>
/// <param name="relFilters">
/// The relation types to request via the <c>rel</c> parameter (§4.3). Empty requests the full descriptor.
/// </param>
/// <param name="context">The per-operation context carrying the guarded-fetch (SSRF) policy.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <remarks>
/// The library's fetch reports the JRD response's
/// <see cref="Verifiable.Core.Outbound.HttpCacheFreshness"/> on <see cref="WebFingerResolutionResult.Freshness"/>.
/// An application that stores the resolved descriptor stores it for that reported lifetime: "A cache MUST NOT
/// generate a stale response unless it is disconnected or doing so is explicitly permitted by the client or
/// origin server" (<see href="https://www.rfc-editor.org/rfc/rfc9111#section-4.2.4">RFC 9111 §4.2.4</see>).
/// This library stores nothing itself.
/// </remarks>
public delegate ValueTask<WebFingerResolutionResult> WebFingerResolveDelegate(
    string resource,
    string host,
    IReadOnlyList<string> relFilters,
    ExchangeContext context,
    CancellationToken cancellationToken);
