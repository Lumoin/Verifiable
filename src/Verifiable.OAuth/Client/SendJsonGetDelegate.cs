using Verifiable.Core;

namespace Verifiable.OAuth.Client;

/// <summary>
/// Issues a JSON GET request to <paramref name="endpoint"/> with the
/// composed <paramref name="headers"/> in a <strong>single hop</strong> and returns the server's
/// response; the implementation <strong>must not follow a redirect</strong>.
/// Used by RFC 7592 §2.1 read-client-metadata calls.
/// </summary>
/// <remarks>
/// <para>
/// The transport implementation attaches every entry in
/// <see cref="OutgoingHeaders.Values"/> to the outbound request and sets
/// <c>Accept</c> to <c>application/json</c>. The library composes the
/// <c>Authorization</c> header (typically <c>Bearer</c> with the
/// registration access token) before calling this delegate; the transport
/// stays auth-scheme-naive.
/// </para>
/// <para>
/// <strong>Single hop.</strong> The implementation performs exactly one request and response and
/// returns a 3xx answer as received, the contract <see cref="Verifiable.OAuth.AuthCode.SendFormPostDelegate"/>
/// states: the request carries the registration access token, and the flow refuses a 3xx answer as an
/// <see cref="OAuthRedirectRefused"/> and sends nothing further.
/// </para>
/// </remarks>
/// <param name="endpoint">The URI to GET from.</param>
/// <param name="headers">Composed request headers.</param>
/// <param name="context">The threaded per-operation <see cref="ExchangeContext"/> for per-tenant transport selection.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The single-hop HTTP response (a 3xx is returned, not followed) carrying body, status code, and response headers.</returns>
public delegate ValueTask<HttpResponseData> SendJsonGetDelegate(
    Uri endpoint,
    OutgoingHeaders headers,
    ExchangeContext context,
    CancellationToken cancellationToken);
