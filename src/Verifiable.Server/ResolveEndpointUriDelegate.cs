using Verifiable.Core;

namespace Verifiable.Server;

/// <summary>
/// Resolves the absolute <see cref="Uri"/> at which a named endpoint is reachable
/// for a given registration in the current request.
/// </summary>
/// <remarks>
/// <para>
/// The dispatch host does not own URL composition. URLs that a protocol family
/// has to embed in produced artifacts — the <c>iss</c> claim of issued tokens, the
/// <c>jwks_uri</c>/<c>token_endpoint</c>/<c>authorization_endpoint</c> fields of a
/// discovery document, the <c>request_uri</c> value returned from PAR, the
/// <c>response_uri</c> for OID4VP — must match the URLs the application actually
/// serves. Only the application knows that, because only the application chose the
/// routing scheme: a <c>/connect/{segment}/...</c> path family, a per-tenant
/// sub-domain, a flat path with header-based tenant routing, or anything else.
/// </para>
/// <para>
/// The <paramref name="endpointKey"/> is a stable string identifier for the
/// endpoint role being asked about. An endpoint-role identifier rather than a
/// capability identifier, because one capability can expose several endpoints
/// (an authorization-code capability exposes both the authorize and token
/// endpoints, which need distinct URLs).
/// </para>
/// <para>
/// The delegate receives the resolved registration and the full per-request
/// context bag. Implementations typically read
/// <see cref="ExchangeContextServerExtensions.Issuer"/> for the scheme/authority and
/// compose the path themselves; deployments that resolve issuer per request
/// (e.g., from <c>Forwarded</c> headers) construct the authority from whatever
/// the skin placed on the context.
/// </para>
/// <para>
/// Returning <see langword="null"/> indicates the application does not expose
/// this endpoint at any URL — the library treats this as "do not advertise" at
/// discovery composition sites and as an authoring error at sites that strictly
/// require a URL (token <c>iss</c>).
/// </para>
/// </remarks>
/// <param name="endpointKey">
/// The endpoint-role identifier whose URL is being requested. Library call
/// sites pass the metadata field names for discovery-document fields; application
/// code may pass custom identifiers for non-discovery endpoint URLs.
/// </param>
/// <param name="registration">
/// The resolved registration for the current request.
/// </param>
/// <param name="context">
/// The per-request context bag carrying whatever request data the application
/// skin chose to surface.
/// </param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// The absolute URL at which the endpoint is served for this registration in
/// this request, or <see langword="null"/> when the application does not expose
/// the endpoint.
/// </returns>
public delegate ValueTask<Uri?> ResolveEndpointUriDelegate(
    string endpointKey,
    IRegistrationRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);
