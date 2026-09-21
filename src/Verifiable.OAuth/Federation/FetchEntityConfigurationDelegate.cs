using Verifiable.Core;
using Verifiable.Core.Outbound;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Fetches a federation entity's self-issued Entity Configuration from its
/// <c>/.well-known/openid-federation</c> document per OpenID Federation 1.0
/// §9. Returns the parsed statement plus the unverified header and raw compact
/// JWS that downstream signature verification consumes, or
/// <see langword="null"/> when the fetch fails or the endpoint returns an
/// unparseable artefact.
/// </summary>
/// <param name="entity">
/// The Entity Identifier whose Entity Configuration is requested. The
/// <c>/.well-known/openid-federation</c> URL is derived from it.
/// </param>
/// <param name="context">
/// The per-call exchange context. Carries the outbound-fetch (SSRF) policy
/// that governs which derived URL may be contacted, since the entity
/// identifier is discovered while walking another entity's
/// <c>authority_hints</c> and is therefore untrusted.
/// </param>
/// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
/// <remarks>
/// <para>
/// The §9 Entity Configuration fetch (no <c>sub</c> query parameter, a
/// well-known URL) is distinct from the §8.1 Subordinate Statement fetch
/// (<see cref="FetchEntityStatementDelegate"/>, a superior's fetch endpoint
/// with the subject in the <c>sub</c> parameter); the trust-chain builder uses
/// both as it climbs the <c>authority_hints</c> graph.
/// </para>
/// <para>
/// <see cref="Verifiable.OAuth.Federation.FederationHttpTransport"/>'s composition reports the fetch's
/// <see cref="HttpCacheFreshness"/> on <see cref="FetchedEntityStatement.Freshness"/>. An application
/// that stores the returned configuration stores it for that reported lifetime: "A cache MUST NOT
/// generate a stale response unless it is disconnected or doing so is explicitly permitted by the client
/// or origin server" (<see href="https://www.rfc-editor.org/rfc/rfc9111#section-4.2.4">RFC 9111
/// §4.2.4</see>). The library stores nothing itself.
/// </para>
/// </remarks>
public delegate ValueTask<FetchedEntityStatement?> FetchEntityConfigurationDelegate(
    EntityIdentifier entity,
    ExchangeContext context,
    CancellationToken cancellationToken);
