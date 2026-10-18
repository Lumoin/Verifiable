using System.Runtime.CompilerServices;

namespace Verifiable.OAuth.ProtectedResource;

/// <summary>
/// The rule a resolved protected resource metadata document's <c>resource</c> satisfied
/// (<see cref="ProtectedResourceMetadataResolved.Identity"/>): exactly one of its three case types, each carrying the
/// values the document's <c>resource</c> was compared with. <c>default(ProtectedResourceIdentity)</c> holds no case; the
/// library never answers it.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.3">RFC 9728 Section 3.3</see> states two rules for the
/// document's <c>resource</c>: "The resource value returned MUST be identical to the protected resource's resource
/// identifier value into which the well-known URI path suffix was inserted to create the URL used to retrieve the
/// metadata." and "If the protected resource metadata was retrieved from a URL returned by the protected resource via
/// the WWW-Authenticate resource_metadata parameter, then the resource value returned MUST be identical to the URL that
/// the client used to make the request to the resource server." A document at the location formed from the request URL
/// satisfies both (<see cref="ResourceNamesTheRequestUrl"/>). The MCP authorization specification names a second
/// location an MCP server hosts its metadata at
/// (<see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery#protected-resource-metadata-discovery-requirements">MCP
/// 2026-07-28, Protected Resource Metadata Discovery Requirements</see>: "At the root:
/// <c>https://example.com/.well-known/oauth-protected-resource</c>"), the location of an identifier with no path
/// component (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.1">RFC 9728 Section 3.1</see>), and a document
/// there at an endpoint with a path satisfies one of the two rules and departs from the other: naming the request URL
/// (<see cref="ResourceNamesTheRequestUrlAtTheRootLocation"/>) or naming the origin
/// (<see cref="ResourceNamesTheOrigin"/>). The library decides nothing about which rule an application accepts: the
/// application reads this value with a switch expression over the case types and applies its own policy.
/// </para>
/// <para>
/// A union over sealed case classes: the compiler holds a switch over it to every case, a missing arm drawing the
/// warning <c>CS8509</c> naming the case not covered. The set of cases is the resolution's own and is not closed
/// forever: a case added later draws <c>CS8509</c> at every switch a consumer recompiles, an error under
/// <c>TreatWarningsAsErrors</c>.
/// </para>
/// <para>
/// The union is a value type holding its case as <c>Value</c>; two identities are equal when they hold the same case
/// instance, the equality of the case classes, which are sealed reference types without value equality.
/// </para>
/// </remarks>
public readonly union ProtectedResourceIdentity(
    ResourceNamesTheRequestUrl,
    ResourceNamesTheRequestUrlAtTheRootLocation,
    ResourceNamesTheOrigin): IEquatable<ProtectedResourceIdentity>
{
    /// <summary>Whether <paramref name="other"/> holds the same case instance as this identity.</summary>
    /// <param name="other">The identity compared with.</param>
    /// <returns><see langword="true"/> when both hold the same case instance, or neither holds one.</returns>
    public bool Equals(ProtectedResourceIdentity other) => ReferenceEquals(Value, other.Value);


    /// <summary>Whether <paramref name="obj"/> is an identity holding the same case instance as this one.</summary>
    /// <param name="obj">The object compared with.</param>
    /// <returns><see langword="true"/> when <paramref name="obj"/> is an equal identity.</returns>
    public override bool Equals(object? obj) => obj is ProtectedResourceIdentity other && Equals(other);


    /// <summary>The hash code of the case instance held, consistent with <see cref="Equals(ProtectedResourceIdentity)"/>.</summary>
    /// <returns>The hash code.</returns>
    public override int GetHashCode() => Value is null ? 0 : RuntimeHelpers.GetHashCode(Value);


    /// <summary>Whether <paramref name="left"/> and <paramref name="right"/> hold the same case instance.</summary>
    /// <param name="left">The first identity.</param>
    /// <param name="right">The second identity.</param>
    /// <returns><see langword="true"/> when they are equal.</returns>
    public static bool operator ==(ProtectedResourceIdentity left, ProtectedResourceIdentity right) => left.Equals(right);


    /// <summary>Whether <paramref name="left"/> and <paramref name="right"/> hold different case instances.</summary>
    /// <param name="left">The first identity.</param>
    /// <param name="right">The second identity.</param>
    /// <returns><see langword="true"/> when they are not equal.</returns>
    public static bool operator !=(ProtectedResourceIdentity left, ProtectedResourceIdentity right) => !left.Equals(right);
}


/// <summary>
/// The document's <c>resource</c> is the URL the client used to make the request, code point for code point
/// (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-6">RFC 9728 Section 6</see>), and the document was read at
/// the location formed from that URL. It meets both paragraphs of
/// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.3">RFC 9728 Section 3.3</see>: "The resource value
/// returned MUST be identical to the protected resource's resource identifier value into which the well-known URI path
/// suffix was inserted to create the URL used to retrieve the metadata." and "the resource value returned MUST be
/// identical to the URL that the client used to make the request to the resource server", and departs from neither. For
/// a request URL with no path and no query the location formed from it is the root location
/// (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.1">RFC 9728 Section 3.1</see>: "since the resource
/// identifier contains no path component: GET /.well-known/oauth-protected-resource"), and a document there naming that
/// URL is this case too.
/// </summary>
public sealed class ResourceNamesTheRequestUrl
{
    /// <summary>The URL the client used to make the request, as the caller passed it; the document's <c>resource</c> is its <see cref="Uri.OriginalString"/>.</summary>
    public required Uri RequestUri { get; init; }
}


/// <summary>
/// The document was read at the root location of the request URL's origin, the request URL has a path or a query, and
/// the document's <c>resource</c> is the request URL, code point for code point
/// (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-6">RFC 9728 Section 6</see>). It meets the paragraph of
/// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.3">RFC 9728 Section 3.3</see> for a URL a challenge
/// returned: "the resource value returned MUST be identical to the URL that the client used to make the request to the
/// resource server"; it departs from the paragraph "The resource value returned MUST be identical to the protected
/// resource's resource identifier value into which the well-known URI path suffix was inserted to create the URL used
/// to retrieve the metadata.", since the identifier the suffix was inserted into to form the root location is the
/// origin. The location is the one the MCP authorization specification names
/// (<see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery#protected-resource-metadata-discovery-requirements">MCP
/// 2026-07-28, Protected Resource Metadata Discovery Requirements</see>: "At the root:
/// <c>https://example.com/.well-known/oauth-protected-resource</c>"); no sentence of that specification names the
/// <c>resource</c> a document there carries.
/// </summary>
/// <remarks>
/// The document departs as well from
/// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-7.3">RFC 9728 Section 7.3</see>: "the client MUST ensure
/// that the resource identifier URL it is using as the prefix for the metadata request exactly matches the value of the
/// resource metadata parameter in the protected resource metadata document received by the client": the root location
/// is formed from <see cref="Origin"/>, not from <see cref="RequestUri"/>, so the URL used as the prefix of the metadata
/// request is not the document's <c>resource</c>. Whether a deployment accepts that departure is the application's
/// policy.
/// </remarks>
public sealed class ResourceNamesTheRequestUrlAtTheRootLocation
{
    /// <summary>The URL the client used to make the request, as the caller passed it; the document's <c>resource</c> is its <see cref="Uri.OriginalString"/>.</summary>
    public required Uri RequestUri { get; init; }

    /// <summary>
    /// The origin of <see cref="RequestUri"/> the root location was formed from: its scheme, host and port as the
    /// well-known location reads them (the scheme and host in lower case, an internationalized host in its IDNA ASCII
    /// form, no default port), its <see cref="Uri.OriginalString"/> written without a trailing slash.
    /// </summary>
    public required Uri Origin { get; init; }
}


/// <summary>
/// The document was read at the root location of the request URL's origin and its <c>resource</c> is that origin,
/// spelled without a trailing slash or with one, each spelling compared code point for code point
/// (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-6">RFC 9728 Section 6</see>). It meets the paragraph of
/// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.3">RFC 9728 Section 3.3</see> "The resource value
/// returned MUST be identical to the protected resource's resource identifier value into which the well-known URI path
/// suffix was inserted to create the URL used to retrieve the metadata.", since the root location is formed from the
/// origin (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.1">RFC 9728 Section 3.1</see>: "since the
/// resource identifier contains no path component: GET /.well-known/oauth-protected-resource"); where the request URL
/// is not the origin as published, it departs from the paragraph for a URL a challenge returned: "the resource value
/// returned MUST be identical to the URL that the client used to make the request to the resource server". The
/// departure is the one the MCP authorization specification sanctions by naming the location
/// (<see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery#protected-resource-metadata-discovery-requirements">MCP
/// 2026-07-28, Protected Resource Metadata Discovery Requirements</see>: "At the root:
/// <c>https://example.com/.well-known/oauth-protected-resource</c>").
/// </summary>
/// <remarks>
/// <para>
/// Both spellings are accepted because both name the origin
/// (<see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#canonical-server-uri">MCP
/// 2026-07-28, Canonical Server URI</see>: "While both <c>https://mcp.example.com/</c> (with trailing slash) and
/// <c>https://mcp.example.com</c> (without trailing slash) are technically valid absolute URIs according to RFC 3986,
/// implementations SHOULD consistently use the form without the trailing slash for better interoperability unless the
/// trailing slash is semantically significant for the specific resource."); that SHOULD binds the spelling a server
/// publishes, and <see cref="PublishedResource"/> carries the spelling the document used.
/// </para>
/// <para>
/// The root document is served by the origin's owner and speaks for every path endpoint on the origin: its
/// <c>authorization_servers</c> become the client's authorities for <see cref="RequestUri"/>, and a tenant scoped to a
/// path on the origin cannot serve it. <see cref="RequestUri"/> is the most specific URI the client has for the resource
/// (<see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#canonical-server-uri">MCP
/// 2026-07-28, Canonical Server URI</see>: "MCP clients SHOULD provide the most specific URI that they can for the MCP
/// server they intend to access"). An application that names <see cref="PublishedResource"/> as the
/// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707</see> <c>resource</c> is issued a token whose
/// audience is the whole origin, every resource on it, the exposure
/// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-7.4">RFC 9728 Section 7.4</see> states: "Without
/// audience-restricted access tokens, a malicious resource server (RS1) may be able to use the WWW-Authenticate header
/// to get a client to request an access token with a scope used by a legitimate resource server (RS2), and after the
/// client sends a request to RS1, then RS1 could reuse the access token at RS2."
/// </para>
/// </remarks>
public sealed class ResourceNamesTheOrigin
{
    /// <summary>The URL the client used to make the request, as the caller passed it.</summary>
    public required Uri RequestUri { get; init; }

    /// <summary>
    /// The origin of <see cref="RequestUri"/> the root location was formed from: its scheme, host and port as the
    /// well-known location reads them (the scheme and host in lower case, an internationalized host in its IDNA ASCII
    /// form, no default port), its <see cref="Uri.OriginalString"/> written without a trailing slash.
    /// </summary>
    public required Uri Origin { get; init; }

    /// <summary>The JSON-decoded <c>resource</c> the document published: the <see cref="Origin"/>'s text, without a trailing slash or with one.</summary>
    public required string PublishedResource { get; init; }
}
