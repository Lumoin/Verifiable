using Verifiable.Core;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth;

/// <summary>
/// Supplies the claim names a registration's OpenID Provider may supply values for, as its discovery names them in
/// <c>claims_supported</c> (OpenID Connect Discovery 1.0 Section 3: "JSON array containing a list of the Claim Names of the Claims
/// that the OpenID Provider MAY be able to supply values for").
/// </summary>
/// <param name="registration">The registration whose metadata is being composed.</param>
/// <param name="context">The per-request context passed to discovery composition.</param>
/// <param name="cancellationToken">Cancellation token for the resolution operation.</param>
/// <returns>The claim names in publication order: at least one, each a name holding a character other than white space, none repeated.</returns>
/// <remarks>
/// <para>
/// Set <see cref="AuthorizationServerIntegration.ResolveClaimsSupportedAsync"/> where the claims a provider supplies differ by
/// registration - a realm that answers profile claims, or whose terms allow disclosing an address, supplies claims another realm
/// of the same deployment never does - so the member every reader of the document is served is composed with the registration's
/// own list before the document is serialized, and never conformed afterwards. A resolved list naming no claim, naming a claim by
/// white space alone, or naming one claim twice is a composition defect, answered as a server error rather than advertised.
/// </para>
/// <para>
/// When no delegate is supplied, discovery names the claims the library's standard claim contributors can emit.
/// </para>
/// </remarks>
public delegate ValueTask<IReadOnlyList<string>> ResolveClaimsSupportedDelegate(
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);
