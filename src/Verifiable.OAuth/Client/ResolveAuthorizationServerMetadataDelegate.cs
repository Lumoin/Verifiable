namespace Verifiable.OAuth.Client;

/// <summary>
/// Resolves the AS metadata for a given issuer, fetching and parsing the
/// <c>/.well-known/oauth-authorization-server</c> or
/// <c>/.well-known/openid-configuration</c> document on first use and
/// returning a typed <see cref="AuthorizationServerMetadata"/>.
/// </summary>
/// <remarks>
/// <para>
/// The library does not pick a fetch strategy or a caching policy. The
/// default implementation an application wires up typically performs a
/// one-shot HTTP GET via the same transport the application uses for other
/// AS calls, parses the JSON body via
/// <see cref="ParseAuthorizationServerMetadataDelegate"/>, and caches the
/// result for the duration the application deems appropriate.
/// </para>
/// <para>
/// Tests wire an in-process resolver that returns a pre-built
/// <see cref="AuthorizationServerMetadata"/> without any HTTP at all,
/// exactly as an application developer would when running against a stub
/// AS.
/// </para>
/// </remarks>
/// <param name="issuer">The AS issuer URL to resolve.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The resolved metadata.</returns>
public delegate ValueTask<AuthorizationServerMetadata> ResolveAuthorizationServerMetadataDelegate(
    Uri issuer,
    CancellationToken cancellationToken);
