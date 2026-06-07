using Verifiable.Core;

namespace Verifiable.OAuth.Client;

/// <summary>
/// POSTs a JSON body to <paramref name="endpoint"/> and returns the server's
/// response. The implementation is responsible for setting the
/// <c>Content-Type</c> header to <c>application/json</c> (or an equivalent
/// per the application's transport conventions) and for surfacing any
/// transport metadata back through <see cref="HttpResponseData"/>.
/// </summary>
/// <remarks>
/// <para>
/// Used by RFC 7591 §3 dynamic client registration. The initial registration
/// POST is unauthenticated per the spec — bearer-token-protected variants
/// for RFC 7592 §2 management calls (read / update / delete) ship in phase 5
/// as separate delegates that include the bearer in the request.
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
/// <returns>The HTTP response carrying body, status code, and optional transport metadata.</returns>
public delegate ValueTask<HttpResponseData> SendJsonPostDelegate(
    Uri endpoint,
    string jsonBody,
    OutgoingHeaders headers,
    ExchangeContext context,
    CancellationToken cancellationToken);
