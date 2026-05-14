using System.Threading;
using System.Threading.Tasks;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Dpop;

/// <summary>
/// Issues a DPoP nonce string. Application-level integration delegate that
/// composes lower-layer primitives (the registered <c>ComputeHmacAsync</c>
/// dispatcher, the <see cref="ResolveServerHmacKeyDelegate"/>, CSPRNG, time
/// provider) to produce the wire artefact. The library ships
/// <see cref="DefaultDpopNonceIssuance.IssueAsync"/> as the default backing;
/// applications wire their own when they need a different wire format
/// (HTTP-signing binding, attestation-bound nonces, JWT shape).
/// </summary>
/// <param name="audience">
/// The URI the nonce is valid for — typically the inbound request URI
/// origin + path. Encoded into the nonce as a hash and re-verified on
/// receipt.
/// </param>
/// <param name="tenantId">Tenant scoping for the HMAC key resolution.</param>
/// <param name="context">Request context; passed through to lower delegates.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<string> IssueDpopNonceDelegate(
    Uri audience,
    TenantId tenantId,
    RequestContext context,
    CancellationToken cancellationToken);
