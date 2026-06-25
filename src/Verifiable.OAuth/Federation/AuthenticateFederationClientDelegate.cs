using Verifiable.Core;
using Verifiable.OAuth.Server;
using Verifiable.Server;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Gates a federation endpoint on OpenID Federation 1.0 §8.8 client
/// authentication. The library invokes this — when wired — at the start of each
/// federation endpoint it serves, before producing the response, so a
/// deployment can require an authenticated requester at the endpoints its
/// <c>*_auth_methods</c> metadata (§8.8.1) declares.
/// </summary>
/// <param name="endpointName">
/// The <see cref="Server.WellKnownEndpointNames"/> value of the endpoint being
/// served, so the application can apply its per-endpoint
/// <c>*_auth_methods</c> policy.
/// </param>
/// <param name="fields">The request parameters (query and/or form body).</param>
/// <param name="registration">The serving entity's <see cref="ClientRecord"/>.</param>
/// <param name="context">The per-request exchange context.</param>
/// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
/// <returns>
/// <see langword="null"/> when client authentication is not required at this
/// endpoint — the request proceeds. A
/// <see cref="FederationClientAuthenticationResult"/> whose
/// <see cref="FederationClientAuthenticationResult.IsValid"/> is
/// <see langword="false"/> rejects the request with HTTP 401
/// <c>invalid_client</c>; a valid result lets it proceed. The application
/// resolves the requester's Federation Entity Key, verifies the client
/// authentication JWT's signature, and validates its claims via
/// <see cref="FederationClientAuthentication.Validate"/>.
/// </returns>
public delegate ValueTask<FederationClientAuthenticationResult?> AuthenticateFederationClientDelegate(
    string endpointName,
    RequestFields fields,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);
