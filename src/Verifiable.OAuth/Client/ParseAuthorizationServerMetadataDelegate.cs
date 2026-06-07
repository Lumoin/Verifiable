namespace Verifiable.OAuth.Client;

/// <summary>
/// Parses an AS metadata document body into a typed
/// <see cref="AuthorizationServerMetadata"/>. The serialization-boundary
/// delegate the default
/// <see cref="ResolveAuthorizationServerMetadataDelegate"/> implementation
/// invokes after fetching the document body via the transport.
/// </summary>
/// <remarks>
/// <para>
/// The library does not pick a JSON library. The default implementation an
/// application wires up lives in <c>Verifiable.OAuth.Json</c> and uses
/// <c>System.Text.Json</c>; applications wanting a different serializer
/// supply their own delegate. The split keeps <c>Verifiable.OAuth</c> free
/// of any direct JSON dependency.
/// </para>
/// </remarks>
/// <param name="documentBody">
/// The metadata document body — JSON text fetched from
/// <c>/.well-known/oauth-authorization-server</c> or
/// <c>/.well-known/openid-configuration</c>.
/// </param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<AuthorizationServerMetadata> ParseAuthorizationServerMetadataDelegate(
    string documentBody,
    CancellationToken cancellationToken);
