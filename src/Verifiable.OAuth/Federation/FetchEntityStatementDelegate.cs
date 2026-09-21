using Verifiable.Core;
using Verifiable.Core.OutboundFetch;
using Verifiable.JCose;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Fetches an Entity Statement from a federation entity's
/// <c>federation_fetch_endpoint</c> per OpenID Federation 1.0 §8.1. Returns
/// the parsed statement plus the unverified header and raw compact JWS
/// that downstream signature verification consumes; returns
/// <see langword="null"/> when the fetch fails or the endpoint returns
/// an unparseable artefact.
/// </summary>
/// <param name="subject">
/// The Entity Identifier of the subject being asked about (the
/// <c>sub</c> query parameter on §8.1's HTTP request).
/// </param>
/// <param name="fetchEndpoint">The full URL of the issuer's fetch endpoint.</param>
/// <param name="context">
/// The per-call exchange context. Carried so an implementation can make
/// per-call decisions from request-scoped data — capability/functionality
/// gating, and the outbound-fetch (SSRF) policy that governs which
/// <paramref name="fetchEndpoint"/> URLs may be contacted.
/// </param>
/// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
/// <remarks>
/// <para>
/// Deployments implement this over their HTTP infrastructure — typically an
/// <c>HttpClient</c>-backed fetch carrying whatever retry, caching,
/// observability, and authentication policies their environment requires —
/// subject to the outbound-fetch (SSRF) policy the <see cref="ExchangeContext"/>
/// carries.
/// </para>
/// <para>
/// <see cref="Verifiable.OAuth.Federation.FederationHttpTransport"/>'s composition reports the fetch's
/// <see cref="HttpCacheFreshness"/> on <see cref="FetchedEntityStatement.Freshness"/>. An application
/// that stores the returned statement stores it for that reported lifetime: "A cache MUST NOT generate a
/// stale response unless it is disconnected or doing so is explicitly permitted by the client or origin
/// server" (<see href="https://www.rfc-editor.org/rfc/rfc9111#section-4.2.4">RFC 9111 §4.2.4</see>). The
/// library stores nothing itself.
/// </para>
/// </remarks>
public delegate ValueTask<FetchedEntityStatement?> FetchEntityStatementDelegate(
    EntityIdentifier subject,
    Uri fetchEndpoint,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Output of a successful <see cref="FetchEntityStatementDelegate"/> call.
/// Carries the parsed statement alongside the unverified header and raw
/// compact JWS needed for downstream signature verification.
/// </summary>
public sealed record FetchedEntityStatement(
    EntityStatement Statement,
    UnverifiedJwtHeader Header,
    string CompactJws)
{
    /// <summary>
    /// The freshness the fetch's response headers imply, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9111#section-5.2">RFC 9111 §5.2</see>, when this
    /// statement was reached over the wire by <see cref="FederationHttpTransport"/>. Left at its default
    /// value — not storable, zero lifetime — when parsed from an inline compact JWS
    /// (<see cref="TrustChainValidation.BuildInlineValidator"/>) that carried no HTTP response to compute
    /// freshness from.
    /// </summary>
    public HttpCacheFreshness Freshness { get; init; }
}
