using Verifiable.Core;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Resolves the entities holding a given Trust Mark type the issuing entity
/// lists at its <c>federation_trust_mark_list_endpoint</c> per
/// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.5">Federation §8.5</see>
/// when an inbound GET arrives. The library matches the request, parses the
/// REQUIRED <c>trust_mark_type</c> and the OPTIONAL <c>sub</c> filter, serialises
/// the returned identifiers as the unsigned JSON array §8.5 mandates, and
/// short-circuits the response; the application's response to this delegate is
/// the membership list itself.
/// </summary>
/// <remarks>
/// <para>
/// The §8.5 response is an unsigned JSON array of Entity Identifier strings —
/// the subjects the issuer has issued a Trust Mark of the queried type to. It
/// states only <em>who</em> holds the mark; the marks themselves come from the
/// <see cref="ResolveTrustMarkDelegate"/>.
/// </para>
/// <para>
/// The library passes the parsed <paramref name="subjectFilter"/> — the §8.5
/// <c>sub</c> query parameter — when present, narrowing the answer to whether a
/// single named subject holds the mark. An empty list is valid (no entity holds
/// the queried Trust Mark type, or the filtered subject does not).
/// </para>
/// </remarks>
/// <param name="trustMarkType">The Trust Mark type queried via the <c>trust_mark_type</c> parameter.</param>
/// <param name="subjectFilter">
/// The <c>sub</c> filter from the request, or <see langword="null"/> when the
/// requester asked for every entity holding the Trust Mark type.
/// </param>
/// <param name="registration">The issuing entity's <see cref="ClientRecord"/>.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// The Entity Identifiers holding the queried Trust Mark type, in the order they
/// should appear in the §8.5 response array, or <see langword="null"/> when the
/// issuer does not know the queried Trust Mark type.
/// </returns>
public delegate ValueTask<IReadOnlyList<EntityIdentifier>?> ResolveTrustMarkedListDelegate(
    EntityTypeIdentifier trustMarkType,
    EntityIdentifier? subjectFilter,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);
