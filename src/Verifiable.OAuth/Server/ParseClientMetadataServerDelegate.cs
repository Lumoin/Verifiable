using Verifiable.OAuth.Client;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Parses an incoming RFC 7591 §2 client metadata document body into a
/// typed <see cref="ClientMetadata"/>. Invoked by the registration handlers
/// on the POST and PUT bodies.
/// </summary>
/// <remarks>
/// The library does not pick a JSON serializer. The default implementation
/// lives in <c>Verifiable.OAuth.Json</c>; applications supplying a
/// different JSON layer wire their own delegate. The <c>Server</c> suffix
/// distinguishes this from a future client-side
/// <c>ParseClientMetadataDelegate</c> used by RFC 7592 read responses; the
/// two have the same shape but live in different namespaces.
/// </remarks>
/// <param name="documentBody">The JSON body of the registration request.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<ClientMetadata> ParseClientMetadataServerDelegate(
    string documentBody,
    CancellationToken cancellationToken);
