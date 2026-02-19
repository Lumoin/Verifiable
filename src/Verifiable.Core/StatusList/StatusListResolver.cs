using System;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Core.StatusList;

/// <summary>
/// Resolves a Status List Token from the URI provided in a Referenced Token's <c>status_list</c> claim.
/// </summary>
/// <remarks>
/// <para>
/// Per Section 8.1 of the specification, the Relying Party sends an HTTP GET request to the
/// URI provided in the Referenced Token. The response body contains the raw Status List Token
/// (JWS Compact Serialization for JWT, binary encoding for CWT).
/// </para>
/// <para>
/// Content negotiation uses the <c>Accept</c> header with
/// <c>application/statuslist+jwt</c> or <c>application/statuslist+cwt</c>.
/// </para>
/// <para>
/// Implementations may add caching, redirect handling, and rate limiting as appropriate.
/// The specification requires clients to follow HTTP redirects and to respect <c>exp</c>
/// and <c>ttl</c> claims over HTTP caching headers.
/// </para>
/// </remarks>
/// <param name="uri">The URI of the Status List Token to resolve.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The raw Status List Token bytes.</returns>
public delegate ValueTask<byte[]> ResolveStatusListTokenDelegate(string uri, CancellationToken cancellationToken = default);


/// <summary>
/// Resolves a Status List Token with support for the historical resolution <c>time</c>
/// query parameter defined in Section 8.4 of the specification.
/// </summary>
/// <remarks>
/// <para>
/// When <paramref name="asOf"/> is provided, the resolver appends <c>?time=&lt;timestamp&gt;</c>
/// to the request URI. The response should contain a Status List Token that was valid at
/// the specified time. Servers that do not support this return 501 (Not Implemented).
/// </para>
/// <para>
/// Clients must verify the returned token's <c>iat</c> and <c>exp</c> claims encompass the
/// requested timestamp.
/// </para>
/// </remarks>
/// <param name="uri">The URI of the Status List Token to resolve.</param>
/// <param name="asOf">
/// Optional Unix timestamp for historical resolution. When <see langword="null"/>,
/// the current Status List Token is returned.
/// </param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The raw Status List Token bytes.</returns>
public delegate ValueTask<byte[]> ResolveHistoricalStatusListTokenDelegate(string uri, DateTimeOffset? asOf, CancellationToken cancellationToken = default);