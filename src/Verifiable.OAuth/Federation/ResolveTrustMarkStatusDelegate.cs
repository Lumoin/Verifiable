using Verifiable.Core;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Resolves the status of a Trust Mark the issuing entity reports at its
/// <c>federation_trust_mark_status_endpoint</c> per
/// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.4">Federation §8.4</see>
/// when an inbound POST arrives carrying a <c>trust_mark</c> form parameter. The
/// library matches the request, reads the parameter, assembles the §8.4 status
/// payload (<c>iss</c>, <c>iat</c>, <c>trust_mark</c>, <c>status</c>) from the
/// returned status string, and signs it with the entity's federation signing
/// key; the application's response to this delegate is the status string itself.
/// </summary>
/// <remarks>
/// <para>
/// Which Trust Marks the entity has issued, and whether each remains active, is
/// the entity application's bookkeeping; the library neither stores nor invents
/// it. It only wraps the supplied status in the signed envelope so a requester
/// can verify the issuer's answer.
/// </para>
/// <para>
/// Returning <see langword="null"/> tells the library the issuer does not know
/// the queried Trust Mark; the endpoint then responds with HTTP 404, mirroring
/// the resolve and historical-keys null-contribution contract. A non-null status
/// string is signed into the §8.4 response.
/// </para>
/// </remarks>
/// <param name="trustMark">
/// The Trust Mark JWT whose status is being checked, exactly as presented in the
/// <c>trust_mark</c> form parameter.
/// </param>
/// <param name="registration">The issuing entity's <see cref="ClientRecord"/>.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// The status string for the queried Trust Mark, or <see langword="null"/> when
/// the issuer does not know it.
/// </returns>
public delegate ValueTask<string?> ResolveTrustMarkStatusDelegate(
    string trustMark,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);
