using System.Runtime.CompilerServices;
using Verifiable.Core.Outbound;
using Verifiable.OAuth.Client;

namespace Verifiable.OAuth.ProtectedResource;

/// <summary>
/// The outcome of resolving a protected resource metadata document from the <c>resource_metadata</c> pointer a
/// <c>WWW-Authenticate</c> challenge named, or from a candidate of
/// <see cref="ProtectedResourceMetadataDocuments.CandidateLocationsOf"/>
/// (<see cref="ProtectedResourceMetadataDocuments.ResolveFromChallengeAsync"/>): exactly one of its ten case types.
/// <c>default(ProtectedResourceMetadataResolution)</c> holds no case; the library never answers it. Only
/// <see cref="ProtectedResourceMetadataResolved"/> carries a document, and that document's <c>resource</c> satisfied the
/// identity rule of the location it was read at, named by <see cref="ProtectedResourceMetadataResolved.Identity"/>: at
/// the location formed from the request URL both paragraphs of
/// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.3">RFC 9728 Section 3.3</see> are met; at the root
/// location of an endpoint with a path or a query one is met and the other departed from, and the application's switch
/// over <see cref="ProtectedResourceMetadataResolved.Identity"/> decides whether a departure is accepted. A document
/// whose <c>resource</c> satisfies no rule is <see cref="ProtectedResourceMetadataResourceMismatch"/>, the case that
/// holds Section 3.3's "If these values are not identical, the data contained in the response MUST NOT be used."; every
/// other case carries the evidence of why no document is usable.
/// </summary>
/// <remarks>
/// <para>
/// A union over sealed case classes: a consumer reads the outcome with a switch expression over the case types, and the
/// compiler holds that switch to every case, a missing arm drawing the warning <c>CS8509</c> naming the case not
/// covered. The set of cases is the resolution's own and is not closed forever: a case added later draws <c>CS8509</c>
/// at every switch a consumer recompiles, an error under <c>TreatWarningsAsErrors</c>.
/// </para>
/// <para>
/// Four cases are this resolution's own: <see cref="ProtectedResourceMetadataResolved"/>,
/// <see cref="ProtectedResourceMetadataPointerNotDerivedFromRequest"/>, <see cref="ProtectedResourceMetadataUnreadable"/>
/// and <see cref="ProtectedResourceMetadataResourceMismatch"/>. Six are fetch outcomes declared in
/// <see cref="Verifiable.OAuth.Client"/> for any metadata document resolution: <see cref="MetadataDocumentPolicyDenied"/>,
/// <see cref="MetadataDocumentUnreachable"/>, <see cref="MetadataDocumentRedirectRefused"/>,
/// <see cref="MetadataDocumentTooLarge"/>, <see cref="MetadataDocumentNotAnswered"/> and
/// <see cref="MetadataDocumentUnsupportedMediaType"/>.
/// </para>
/// <para>
/// The union is a value type holding its case as <c>Value</c>; two resolutions are equal when they hold the same case
/// instance, the equality of the case classes, which are sealed reference types without value equality.
/// </para>
/// </remarks>
public readonly union ProtectedResourceMetadataResolution(
    ProtectedResourceMetadataResolved,
    ProtectedResourceMetadataPointerNotDerivedFromRequest,
    MetadataDocumentPolicyDenied,
    MetadataDocumentUnreachable,
    MetadataDocumentRedirectRefused,
    MetadataDocumentTooLarge,
    MetadataDocumentNotAnswered,
    MetadataDocumentUnsupportedMediaType,
    ProtectedResourceMetadataUnreadable,
    ProtectedResourceMetadataResourceMismatch): IEquatable<ProtectedResourceMetadataResolution>
{
    /// <summary>Whether <paramref name="other"/> holds the same case instance as this resolution.</summary>
    /// <param name="other">The resolution compared with.</param>
    /// <returns><see langword="true"/> when both hold the same case instance, or neither holds one.</returns>
    public bool Equals(ProtectedResourceMetadataResolution other) => ReferenceEquals(Value, other.Value);


    /// <summary>Whether <paramref name="obj"/> is a resolution holding the same case instance as this one.</summary>
    /// <param name="obj">The object compared with.</param>
    /// <returns><see langword="true"/> when <paramref name="obj"/> is an equal resolution.</returns>
    public override bool Equals(object? obj) => obj is ProtectedResourceMetadataResolution other && Equals(other);


    /// <summary>The hash code of the case instance held, consistent with <see cref="Equals(ProtectedResourceMetadataResolution)"/>.</summary>
    /// <returns>The hash code.</returns>
    public override int GetHashCode() => Value is null ? 0 : RuntimeHelpers.GetHashCode(Value);


    /// <summary>Whether <paramref name="left"/> and <paramref name="right"/> hold the same case instance.</summary>
    /// <param name="left">The first resolution.</param>
    /// <param name="right">The second resolution.</param>
    /// <returns><see langword="true"/> when they are equal.</returns>
    public static bool operator ==(ProtectedResourceMetadataResolution left, ProtectedResourceMetadataResolution right) => left.Equals(right);


    /// <summary>Whether <paramref name="left"/> and <paramref name="right"/> hold different case instances.</summary>
    /// <param name="left">The first resolution.</param>
    /// <param name="right">The second resolution.</param>
    /// <returns><see langword="true"/> when they are not equal.</returns>
    public static bool operator !=(ProtectedResourceMetadataResolution left, ProtectedResourceMetadataResolution right) => !left.Equals(right);
}


/// <summary>
/// A protected resource metadata document fetched from a pointer the resolution admits, read, and whose <c>resource</c>
/// satisfies the identity rule of the location it was read at, the rule named by <see cref="Identity"/>
/// (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.3">RFC 9728 Section 3.3</see>: "If these values are not
/// identical, the data contained in the response MUST NOT be used.").
/// </summary>
public sealed class ProtectedResourceMetadataResolved
{
    /// <summary>
    /// The rule the document's <c>resource</c> satisfied and the values it was compared with: the request URL at the
    /// location formed from it, which meets both paragraphs of
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.3">RFC 9728 Section 3.3</see>; or, at the root
    /// location of the request URL's origin, the request URL or the origin, each meeting one paragraph and departing from
    /// the other. Which rule a deployment accepts is the application's policy, read with a switch over
    /// <see cref="ProtectedResourceIdentity"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The rule is judged at the location the pointer was admitted at. <see cref="MetadataLocation"/> is the final URL
    /// under the application's redirect policy, so an application whose outbound policy follows a redirect compares
    /// <see cref="MetadataLocation"/> with the admitted location before it accepts the document.
    /// </para>
    /// <para>
    /// Under <see cref="ResourceNamesTheOrigin"/> the document is the origin's root document, served by the origin's
    /// owner, and it speaks for every path endpoint on the origin: its <c>authorization_servers</c> become the client's
    /// authorities for the request URL, and a tenant scoped to a path on the origin cannot serve it;
    /// <see cref="ResourceNamesTheOrigin.RequestUri"/> is the most specific URI, and an
    /// application that names <see cref="ResourceNamesTheOrigin.PublishedResource"/> as the RFC 8707 <c>resource</c> is
    /// issued a token whose audience is the whole origin, as the case's remarks state.
    /// </para>
    /// </remarks>
    public required ProtectedResourceIdentity Identity { get; init; }

    /// <summary>
    /// The document as read. Its <see cref="ProtectedResourceMetadata.SignedMetadata"/> is carried as the unverified
    /// string the document holds: <see href="https://www.rfc-editor.org/rfc/rfc9728#section-2.2">RFC 9728 Section
    /// 2.2</see>, "Consumers of the metadata MAY ignore the signed metadata if they do not support this feature."
    /// </summary>
    public required ProtectedResourceMetadata Metadata { get; init; }

    /// <summary>The location that supplied the document, after any permitted redirects.</summary>
    public required Uri MetadataLocation { get; init; }

    /// <summary>
    /// The storage permission and lifetime implied by the response headers, reported for the application's cache and
    /// never applied by the library
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-7.10">RFC 9728 Section 7.10</see>: "Normal HTTP
    /// caching behaviors apply").
    /// </summary>
    public required HttpCacheFreshness Freshness { get; init; }
}


/// <summary>
/// The challenge's pointer is neither of the two locations the resolution admits for the URL the client used to make the
/// request, so no document it names can be used, and no request was sent to it
/// (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-7.7">RFC 9728 Section 7.7</see>: "Clients SHOULD take
/// appropriate precautions against SSRF attacks").
/// </summary>
/// <remarks>
/// <para>
/// The first location, <see cref="ExpectedPointer"/>, is formed from the request URL:
/// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.3">RFC 9728 Section 3.3</see> holds the document's
/// <c>resource</c> to both "the protected resource's resource identifier value into which the well-known URI path suffix
/// was inserted to create the URL used to retrieve the metadata" and "the URL that the client used to make the request to
/// the resource server", and a document there can satisfy both.
/// </para>
/// <para>
/// The second, <see cref="RootFormPointer"/>, is the root location of the request URL's own origin, the location of an
/// identifier with no path component (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.1">RFC 9728 Section
/// 3.1</see>: "since the resource identifier contains no path component: GET /.well-known/oauth-protected-resource"),
/// which the MCP authorization specification names as a location an MCP server hosts its metadata at
/// (<see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery#protected-resource-metadata-discovery-requirements">MCP
/// 2026-07-28, Protected Resource Metadata Discovery Requirements</see>: "At the root:
/// <c>https://example.com/.well-known/oauth-protected-resource</c>"); a document there at an endpoint with a path or a
/// query satisfies one paragraph of Section 3.3 and departs from the other, and
/// <see cref="ProtectedResourceMetadataResolved.Identity"/> names which. For a request URL with no path and no query the
/// two locations are the same text.
/// </para>
/// </remarks>
public sealed class ProtectedResourceMetadataPointerNotDerivedFromRequest
{
    /// <summary>The URL the client used to make the request, as the caller passed it.</summary>
    public required Uri RequestUri { get; init; }

    /// <summary>The pointer the challenge named, as read.</summary>
    public required Uri Pointer { get; init; }

    /// <summary>The location formed from <see cref="RequestUri"/> under the application's well-known suffix.</summary>
    public required Uri ExpectedPointer { get; init; }

    /// <summary>
    /// The root location of <see cref="RequestUri"/>'s origin under the application's well-known suffix: the same
    /// scheme, host and port, the path exactly <c>/.well-known/</c> and the suffix, no query and no fragment.
    /// </summary>
    public required Uri RootFormPointer { get; init; }
}


/// <summary>
/// The application's parser read no protected resource metadata document from the response body. The JSON leaf's strict
/// reading, <c>ProtectedResourceMetadataJsonParsing.ParseProtectedResourceMetadata</c>, refuses a body that is not valid
/// UTF-8 (<see href="https://www.rfc-editor.org/rfc/rfc8259#section-8.1">RFC 8259 Section 8.1</see>: "JSON text
/// exchanged between systems that are not part of a closed ecosystem MUST be encoded using UTF-8"); a body that is no
/// JSON text at all: an empty body, a byte order mark, a comment, a trailing comma or a nesting deeper than 32; a JSON
/// text whose root is not an object (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.2">RFC 9728 Section
/// 3.2</see>: "return a JSON object"); an object with no non-empty <c>resource</c>; and a known member of the wrong type.
/// </summary>
public sealed class ProtectedResourceMetadataUnreadable
{
    /// <summary>The location that supplied the body.</summary>
    public required Uri MetadataLocation { get; init; }
}


/// <summary>
/// A readable document whose <c>resource</c> satisfies no identity rule of the location it was read at; its metadata
/// must not be used (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.3">RFC 9728 Section 3.3</see>: "If
/// these values are not identical, the data contained in the response MUST NOT be used.").
/// </summary>
/// <remarks>
/// The values compared with, each code point for code point
/// (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-6">RFC 9728 Section 6</see>): at the location formed from
/// the request URL, the request URL alone; at the root location of the request URL's origin, the request URL, then the
/// origin spelled without a trailing slash, then the origin spelled with one, the origin as the well-known location
/// reads it (the scheme and host in lower case, an internationalized host in its IDNA ASCII form, no default port).
/// </remarks>
public sealed class ProtectedResourceMetadataResourceMismatch
{
    /// <summary>
    /// The URL the client used to make the request, as the caller passed it; its <see cref="Uri.OriginalString"/> is the
    /// text the document's <c>resource</c> was compared with.
    /// </summary>
    public required Uri RequestUri { get; init; }

    /// <summary>The JSON-decoded <c>resource</c> the document published, without normalization.</summary>
    public required string PublishedResource { get; init; }

    /// <summary>The location that supplied the document.</summary>
    public required Uri MetadataLocation { get; init; }
}
