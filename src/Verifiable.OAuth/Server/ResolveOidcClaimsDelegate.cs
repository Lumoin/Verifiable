using Verifiable.OAuth.Oidc;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Resolves the OpenID Connect claims for an authenticated subject at
/// token-issuance or UserInfo-call time. The library carries the typed
/// result into the ID Token payload (during token issuance via
/// <see cref="Oidc10IdTokenProducer"/>) and into the UserInfo response
/// (via the UserInfo endpoint handler).
/// </summary>
/// <remarks>
/// Returning <see langword="null"/> indicates the subject is not recognised.
/// At the token endpoint this is a hard error — the library shouldn't be
/// asking for claims for a subject it didn't authenticate. At the UserInfo
/// endpoint it surfaces as a <c>500 server_error</c>.
/// </remarks>
/// <param name="subject">
/// The Subject Identifier the application established at authentication
/// (the <c>sub</c> claim value). The library carries it through flow
/// state into this delegate.
/// </param>
/// <param name="grantedScope">
/// Space-separated scope string from the authorization grant. Determines
/// which claim sub-records the application populates per OIDC Core §5.4.
/// </param>
/// <param name="tenantId">Tenant scoping for the lookup.</param>
/// <param name="context">Per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<OidcClaims?> ResolveOidcClaimsDelegate(
    string subject,
    string grantedScope,
    TenantId tenantId,
    RequestContext context,
    CancellationToken cancellationToken);
