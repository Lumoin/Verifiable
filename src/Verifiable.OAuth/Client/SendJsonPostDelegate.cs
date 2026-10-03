using Verifiable.Core;

namespace Verifiable.OAuth.Client;

/// <summary>
/// POSTs a JSON body to <paramref name="endpoint"/> in a <strong>single hop</strong> and returns the
/// server's response; the implementation <strong>must not follow a redirect</strong>. The
/// implementation is responsible for setting the <c>Content-Type</c> header to <c>application/json</c>
/// (or an equivalent per the application's transport conventions) and for surfacing any transport
/// metadata back through <see cref="HttpResponseData"/>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Single hop.</strong> The implementation performs exactly one request and response and
/// returns a 3xx answer as received, the contract <see cref="Verifiable.OAuth.AuthCode.SendFormPostDelegate"/>
/// states: the body carries the client's metadata, its keys or their location among them, and a
/// handler that follows a 307 or 308 re-sends it to whatever origin the <c>Location</c> field names
/// (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.4.8">RFC 9110 §15.4.8</see>). The flow
/// refuses a 3xx answer as an <see cref="OAuthRedirectRefused"/> and sends nothing further.
/// </para>
/// <para>
/// Used by RFC 7591 §3 dynamic client registration. The initial registration
/// POST is unauthenticated per the spec — bearer-token-protected variants
/// for RFC 7592 §2 management calls (read / update / delete) are
/// separate delegates that include the bearer in the request.
/// </para>
/// <para>
/// In the in-process development configuration the implementation dispatches
/// directly into
/// <see cref="Verifiable.OAuth.Server.Registration.RegistrationEndpoints.HandleCreateAsync"/>;
/// in production it issues an HTTP request via the application's HTTP client.
/// Both implementations should populate
/// <see cref="HttpResponseData.TransportMetadata"/> with whatever
/// correlation information the deployment exposes.
/// </para>
/// </remarks>
/// <param name="endpoint">The URI to POST the JSON body to.</param>
/// <param name="jsonBody">The serialised JSON body. The implementation sets the content type.</param>
/// <param name="headers">Composed request headers. RFC 7591 §3 registration is
/// unauthenticated, so this is typically <see cref="OutgoingHeaders.Empty"/>; the
/// parameter is required so the four JSON-transport delegates have a uniform shape
/// and so production wiring can add optional headers (User-Agent, X-Request-Id)
/// without a signature change.</param>
/// <param name="context">The threaded per-operation <see cref="ExchangeContext"/> for per-tenant transport selection.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The single-hop HTTP response (a 3xx is returned, not followed) carrying body, status code, and optional transport metadata.</returns>
public delegate ValueTask<HttpResponseData> SendJsonPostDelegate(
    Uri endpoint,
    string jsonBody,
    OutgoingHeaders headers,
    ExchangeContext context,
    CancellationToken cancellationToken);
