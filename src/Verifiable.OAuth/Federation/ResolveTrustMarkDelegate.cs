using Verifiable.Core;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Resolves the Trust Mark JWT the issuing entity serves at its
/// <c>federation_trust_mark_endpoint</c> per
/// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.6">Federation §8.6</see>
/// when an inbound GET arrives carrying <c>trust_mark_type</c> and <c>sub</c>.
/// The library matches the request, parses the two parameters, and short-circuits
/// the response with the returned JWT served as
/// <c>application/trust-mark+jwt</c>; the application's response to this delegate
/// is the Trust Mark JWT itself.
/// </summary>
/// <remarks>
/// <para>
/// The library serves the application-provided compact JWS verbatim — it signs
/// nothing here (the Trust Mark was signed when it was issued), preserving the
/// <c>Verifiable.OAuth</c> serialization firewall. Which Trust Marks the entity
/// has issued, and for which subjects, is the entity application's bookkeeping;
/// the library neither stores nor invents them.
/// </para>
/// <para>
/// Returning <see langword="null"/> tells the library the entity has no Trust
/// Mark of the queried type for the queried subject; the endpoint then responds
/// with HTTP 404.
/// </para>
/// </remarks>
/// <param name="trustMarkType">The Trust Mark type queried via the <c>trust_mark_type</c> parameter.</param>
/// <param name="subject">The Entity Identifier queried via the <c>sub</c> parameter.</param>
/// <param name="registration">The issuing entity's <see cref="ClientRecord"/>.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// The Trust Mark compact JWS for the queried (trust_mark_type, subject) pair,
/// or <see langword="null"/> when the entity has no such Trust Mark.
/// </returns>
public delegate ValueTask<string?> ResolveTrustMarkDelegate(
    EntityTypeIdentifier trustMarkType,
    EntityIdentifier subject,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);
