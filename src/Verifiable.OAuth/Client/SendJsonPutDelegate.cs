using Verifiable.Core;

namespace Verifiable.OAuth.Client;

/// <summary>
/// Issues a JSON PUT request to <paramref name="endpoint"/> with the given
/// body and composed headers in a <strong>single hop</strong>, and returns the server's response; the
/// implementation <strong>must not follow a redirect</strong>. Used by
/// RFC 7592 §2.2 update-client-metadata calls.
/// </summary>
/// <remarks>
/// <para>
/// The transport implementation sets <c>Content-Type</c> to
/// <c>application/json</c> and attaches every entry in
/// <see cref="OutgoingHeaders.Values"/> to the outbound request. The
/// library composes the <c>Authorization</c> header before calling.
/// </para>
/// <para>
/// <strong>Single hop.</strong> The implementation performs exactly one request and response and
/// returns a 3xx answer as received, the contract <see cref="Verifiable.OAuth.AuthCode.SendFormPostDelegate"/>
/// states: the request carries the registration access token and the client's metadata, and a handler
/// that follows a 307 or 308 re-sends both to whatever origin the <c>Location</c> field names
/// (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.4.8">RFC 9110 §15.4.8</see>). The flow
/// refuses a 3xx answer as an <see cref="OAuthRedirectRefused"/> and sends nothing further.
/// </para>
/// </remarks>
/// <param name="endpoint">The URI to PUT to.</param>
/// <param name="jsonBody">The serialised JSON body.</param>
/// <param name="headers">Composed request headers.</param>
/// <param name="context">The threaded per-operation <see cref="ExchangeContext"/> for per-tenant transport selection.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The single-hop HTTP response (a 3xx is returned, not followed) carrying body, status code, and response headers.</returns>
public delegate ValueTask<HttpResponseData> SendJsonPutDelegate(
    Uri endpoint,
    string jsonBody,
    OutgoingHeaders headers,
    ExchangeContext context,
    CancellationToken cancellationToken);
