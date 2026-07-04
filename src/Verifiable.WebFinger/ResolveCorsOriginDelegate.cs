using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core;

namespace Verifiable.WebFinger;

/// <summary>
/// Resolves the <c>Access-Control-Allow-Origin</c> value the WebFinger endpoint emits on every response,
/// per <see href="https://www.rfc-editor.org/rfc/rfc7033#section-5">RFC 7033 §5</see>. Optional —
/// <see cref="WebFingerEndpoints"/> defaults to
/// <see cref="WellKnownWebFingerValues.AccessControlAllowOriginWildcard"/> when this seam is unwired, per
/// §5's SHOULD-support-<c>*</c> guidance.
/// </summary>
/// <remarks>
/// A deployment that must not open access to any origin (§5: "This should be avoided ... on an intranet,
/// or when the WebFinger resource contains information intended to be private") wires this seam to a
/// value scoped to its trusted origins, resolved per registration and per request so different tenants or
/// request contexts can carry different origins (§6).
/// </remarks>
/// <param name="registration">The registration the current request was dispatched to.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The <c>Access-Control-Allow-Origin</c> header value for this request.</returns>
public delegate ValueTask<string> ResolveCorsOriginDelegate(
    IRegistrationRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);
