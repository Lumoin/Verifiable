using System.Threading;
using System.Threading.Tasks;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Dpop;

/// <summary>
/// Validates a presented DPoP nonce string against the expected audience.
/// Application-level integration delegate paired with
/// <see cref="IssueDpopNonceDelegate"/> — issuance and validation must
/// agree on the wire format.
/// </summary>
/// <param name="presentedNonce">The nonce string from the proof's <c>nonce</c> claim.</param>
/// <param name="expectedAudience">
/// The URI the nonce was issued for — typically the inbound request URI
/// origin + path.
/// </param>
/// <param name="tenantId">Tenant scoping for HMAC key resolution.</param>
/// <param name="context">Request context.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<DpopNonceValidationResult> ValidateDpopNonceDelegate(
    string presentedNonce,
    Uri expectedAudience,
    TenantId tenantId,
    RequestContext context,
    CancellationToken cancellationToken);
