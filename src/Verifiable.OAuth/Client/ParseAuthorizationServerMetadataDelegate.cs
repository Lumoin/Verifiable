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
/// The library does not pick a JSON library, and no default implementation
/// of this delegate is shipped. The application supplies it. Follow the
/// shape of <see cref="Verifiable.OAuth.OAuthResponseParsers.ParseParResponse"/>
/// and <see cref="Verifiable.OAuth.OAuthResponseParsers.ParseTokenResponse"/>
/// — the library's own hand-written, dependency-free response parsers —
/// as the pattern to compose against.
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
