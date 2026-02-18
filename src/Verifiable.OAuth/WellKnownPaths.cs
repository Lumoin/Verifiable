using System;
using Verifiable.Core.Resolvers;

namespace Verifiable.OAuth;

/// <summary>
/// Catalog of well-known URI paths used in OAuth, OpenID, and related identity specifications.
/// </summary>
/// <remarks>
/// <para>
/// Each entry provides a pure function that computes the metadata document URL
/// from a base identifier. Consumers fetch the document using their own HTTP infrastructure
/// and extract endpoint URIs using the metadata key constants such as
/// <see cref="AuthorizationServerMetadataKeys"/>.
/// </para>
/// <para>
/// This catalog corresponds to a subset of the IANA Well-Known URIs registry,
/// filtered to entries relevant for identity infrastructure.
/// </para>
/// </remarks>
public static class WellKnownPaths
{
    /// <summary>
    /// OAuth 2.0 Authorization Server Metadata (RFC 8414).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Computes <c>{issuer}/.well-known/oauth-authorization-server</c>.
    /// For issuers with path components, the well-known suffix is inserted
    /// after the host: <c>{host}/.well-known/oauth-authorization-server{path}</c>.
    /// </para>
    /// </remarks>
    public static WellKnownPath OAuthAuthorizationServer { get; } = new(
        "oauth-authorization-server",
        "RFC 8414",
        identifier => ComputeWellKnownWithPathInsertion(identifier, "oauth-authorization-server"));

    /// <summary>
    /// OpenID Connect Discovery 1.0 (OpenID.Discovery).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Computes <c>{issuer}/.well-known/openid-configuration</c>.
    /// Unlike OAuth AS metadata, the well-known suffix is always appended
    /// at the end of the issuer URL.
    /// </para>
    /// </remarks>
    public static WellKnownPath OpenIdConfiguration { get; } = new(
        "openid-configuration",
        "OpenID Connect Discovery 1.0",
        identifier => ComputeWellKnownSuffix(identifier, "openid-configuration"));

    /// <summary>
    /// OpenID Federation 1.0 entity configuration.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Computes <c>{entityId}/.well-known/openid-federation</c>.
    /// The response is a signed JWT (Entity Configuration) containing metadata
    /// for one or more entity types (OpenID Provider, Relying Party, OAuth AS, etc.).
    /// </para>
    /// </remarks>
    public static WellKnownPath OpenIdFederation { get; } = new(
        "openid-federation",
        "OpenID Federation 1.0",
        identifier => ComputeWellKnownSuffix(identifier, "openid-federation"));

    /// <summary>
    /// AuthZEN Authorization API 1.0 PDP metadata.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Computes <c>{baseUri}/.well-known/authzen-configuration</c>.
    /// The response contains PDP endpoint URIs and capability declarations.
    /// </para>
    /// </remarks>
    public static WellKnownPath AuthZenConfiguration { get; } = new(
        "authzen-configuration",
        "Authorization API 1.0",
        identifier => ComputeWellKnownSuffix(identifier, "authzen-configuration"));

    /// <summary>
    /// DID Web resolution (did:web method specification).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Delegates to <see cref="WebDidResolver.Resolve"/> for URL computation.
    /// </para>
    /// <list type="bullet">
    ///   <item><description><c>did:web:example.com</c> resolves to <c>https://example.com/.well-known/did.json</c>.</description></item>
    ///   <item><description><c>did:web:example.com:users:alice</c> resolves to <c>https://example.com/users/alice/did.json</c>.</description></item>
    ///   <item><description><c>did:web:example.com%3A3000:user:alice</c> resolves to <c>https://example.com:3000/user/alice/did.json</c>.</description></item>
    /// </list>
    /// </remarks>
    public static WellKnownPath DidWeb { get; } = new(
        "did-web",
        "did:web Method Specification",
        identifier => new Uri(WebDidResolver.Resolve(identifier)));

    /// <summary>
    /// Computes a well-known URI by appending the suffix to the base.
    /// Used by OpenID Configuration, OpenID Federation, and AuthZEN.
    /// </summary>
    private static Uri ComputeWellKnownSuffix(string identifier, string suffix)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identifier);

        string baseUrl = identifier.TrimEnd('/');
        return new Uri($"{baseUrl}/.well-known/{suffix}");
    }

    /// <summary>
    /// Computes a well-known URI with path insertion per RFC 8414.
    /// The well-known component is inserted after the host, before the path.
    /// </summary>
    /// <remarks>
    /// <para>
    /// For <c>https://example.com</c>, produces <c>https://example.com/.well-known/oauth-authorization-server</c>.
    /// For <c>https://example.com/tenant1</c>, produces <c>https://example.com/.well-known/oauth-authorization-server/tenant1</c>.
    /// </para>
    /// </remarks>
    private static Uri ComputeWellKnownWithPathInsertion(string identifier, string suffix)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identifier);

        var baseUri = new Uri(identifier.TrimEnd('/'));
        string path = baseUri.AbsolutePath;

        if(path == "/")
        {
            return new Uri($"{baseUri.Scheme}://{baseUri.Authority}/.well-known/{suffix}");
        }

        return new Uri($"{baseUri.Scheme}://{baseUri.Authority}/.well-known/{suffix}{path}");
    }

}