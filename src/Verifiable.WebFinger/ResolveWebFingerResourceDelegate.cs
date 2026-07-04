using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core;

namespace Verifiable.WebFinger;

/// <summary>
/// Resolves a WebFinger query target to a <see cref="JsonResourceDescriptor"/> for the registration the
/// request was dispatched to, per
/// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.2">RFC 7033 §4.2</see>. The ONE required
/// application seam <see cref="WebFingerEndpoints"/> composes over — only the application knows its
/// resource / user store, so the library cannot supply a default.
/// </summary>
/// <param name="resource">
/// The query target carried in the <c>resource</c> parameter, per
/// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.1">RFC 7033 §4.1</see>. The endpoint has
/// already enforced the §4.2 "exactly once" MUST before calling this delegate.
/// </param>
/// <param name="relFilters">
/// The requested relation types from the <c>rel</c> parameter, per
/// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.3">RFC 7033 §4.3</see>; empty requests the
/// full descriptor. Filtering the returned descriptor's <see cref="JsonResourceDescriptor.Links"/> by
/// these values is this delegate's responsibility — the endpoint passes them through unfiltered.
/// </param>
/// <param name="registration">The registration the current request was dispatched to.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// The resolved descriptor, or <see langword="null"/> when the resource carries no information the
/// resolver can vouch for — the endpoint answers <see langword="null"/> with the
/// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.2">RFC 7033 §4.2</see> 404 (no information
/// for the requested resource).
/// </returns>
public delegate ValueTask<JsonResourceDescriptor?> ResolveWebFingerResourceDelegate(
    string resource,
    IReadOnlyList<string> relFilters,
    IRegistrationRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);
