using Verifiable.Core;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth;

/// <summary>
/// Supplies the client authentication methods a registration's token endpoint takes, as its discovery names them in
/// <c>token_endpoint_auth_methods_supported</c> (RFC 8414 Section 2: "JSON array containing a list of client authentication methods
/// supported by this token endpoint").
/// </summary>
/// <param name="registration">The registration whose metadata is being composed.</param>
/// <param name="context">The per-request context passed to discovery composition.</param>
/// <param name="cancellationToken">Cancellation token for the resolution operation.</param>
/// <returns>
/// The methods in publication order: every one of them among the deployment's declaration
/// (<see cref="AuthorizationServerIntegration.ClientAuthenticationMethodsSupported"/>), and at least one.
/// </returns>
/// <remarks>
/// <para>
/// Set <see cref="AuthorizationServerIntegration.ResolveClientAuthenticationMethodsAsync"/> where the methods a token endpoint
/// takes differ by registration - a realm that admits client secrets takes methods another realm of the same deployment refuses -
/// so the member every reader of the document is served is composed with the registration's own list before the document is
/// serialized, and never conformed afterwards. The deployment's declaration stays the set every registration's declared method is
/// held to; a resolved list naming a method outside it, or naming none, is a composition defect, answered as a server error rather
/// than advertised.
/// </para>
/// <para>
/// When no delegate is supplied, discovery names the deployment's declaration itself.
/// </para>
/// </remarks>
public delegate ValueTask<IReadOnlyList<ClientAuthenticationMethod>> ResolveClientAuthenticationMethodsDelegate(
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);
