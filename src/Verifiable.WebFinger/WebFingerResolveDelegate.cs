using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
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
public delegate ValueTask<WebFingerResolutionResult> WebFingerResolveDelegate(
    string resource,
    string host,
    IReadOnlyList<string> relFilters,
    ExchangeContext context,
    CancellationToken cancellationToken);
