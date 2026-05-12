namespace Verifiable.OAuth.Client;

/// <summary>
/// Parses an RFC 7591 §3.2.1 dynamic client registration response body into
/// a typed <see cref="RegistrationResponse"/>.
/// </summary>
/// <remarks>
/// <para>
/// The serialization-boundary delegate
/// <c>OAuthDynamicRegistrationClient.RegisterAsync</c> invokes after the
/// HTTP POST against the AS's registration endpoint. The library does not
/// pick a JSON library; the default implementation lives in
/// <c>Verifiable.OAuth.Json</c>.
/// </para>
/// </remarks>
/// <param name="documentBody">The response body the AS returned.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<RegistrationResponse> ParseRegistrationResponseDelegate(
    string documentBody,
    CancellationToken cancellationToken);
