using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.StatusList;

/// <summary>
/// A reference from a Referenced Token to an entry in a Status List Token.
/// </summary>
/// <remarks>
/// <para>
/// This structure is embedded in the <c>status_list</c> member of a Referenced Token's
/// <c>status</c> claim. It identifies a specific entry in a Status List by combining
/// a zero-based index with the URI of the Status List Token.
/// </para>
/// <para>
/// For JOSE-based Referenced Tokens, the members are encoded as JSON:
/// </para>
/// <code>
/// {
///   "status": {
///     "status_list": {
///       "idx": 0,
///       "uri": "https://example.com/statuslists/1"
///     }
///   }
/// }
/// </code>
/// <para>
/// For COSE-based Referenced Tokens, the structure uses a CBOR map with text string keys.
/// </para>
/// </remarks>
[DebuggerDisplay("StatusListReference[idx={Index}, uri={Uri}]")]
public readonly struct StatusListReference: IEquatable<StatusListReference>
{
    /// <summary>
    /// Gets the zero-based index within the Status List.
    /// </summary>
    public int Index { get; }

    /// <summary>
    /// Gets the URI identifying the Status List Token that contains the status
    /// information for the Referenced Token.
    /// </summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings", Justification = "The specification defines this as a string claim value that is compared and serialized as a string in both JWT and CWT formats.")]
    public string Uri { get; }

    /// <summary>
    /// Creates a new Status List reference.
    /// </summary>
    /// <param name="index">The zero-based index within the Status List. Must not be negative.</param>
    /// <param name="uri">The URI of the Status List Token. Must conform to RFC 3986.</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="index"/> is negative.</exception>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="uri"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="uri"/> does not satisfy <see cref="IsConformingUri(string?)"/> — empty,
    /// all-whitespace, or not an RFC 3986 URI proper.
    /// </exception>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings", Justification = "The specification defines this as a string claim value that is compared and serialized as a string in both JWT and CWT formats.")]
    public StatusListReference(int index, string uri)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        ArgumentNullException.ThrowIfNull(uri);

        if(!IsConformingUri(uri))
        {
            throw new ArgumentException(
                "The uri must be a URI conforming to RFC 3986, per Token Status List Section 6.2/6.3's " +
                "\"The value of uri MUST be a URI conforming to [RFC3986].\"",
                nameof(uri));
        }

        Index = index;
        Uri = uri;
    }


    /// <summary>
    /// Determines whether <paramref name="value"/> is an RFC 3986 URI proper — an absolute URI carrying an
    /// explicit scheme.
    /// </summary>
    /// <remarks>
    /// <see langword="false"/> for <see langword="null"/>, empty, or all-whitespace text; for a relative
    /// reference such as <c>/statuslists/1</c>; and for a scheme-less string such as
    /// <c>example.com/list</c>. <see cref="System.Uri.TryCreate(string?, UriKind, out System.Uri)"/> with
    /// <see cref="UriKind.Absolute"/> alone is not sufficient cross-platform — on Unix a bare rooted path
    /// parses as an absolute <c>file:</c> URI — so this predicate additionally requires the raw text to
    /// carry a scheme delimiter (<c>:</c>) before its first <c>/</c>, giving identical behaviour on Windows
    /// and Unix. This predicate polices only RFC 3986 syntax; it never restricts scheme, fragment, or
    /// userinfo — where the resolver may actually connect is the deployment's outbound-fetch policy
    /// concern, not this type's.
    /// </remarks>
    /// <param name="value">The candidate URI text.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> conforms to RFC 3986.</returns>
    public static bool IsConformingUri(string? value)
    {
        if(string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        if(!System.Uri.TryCreate(value, UriKind.Absolute, out System.Uri? parsed) || !parsed.IsAbsoluteUri)
        {
            return false;
        }

        int schemeDelimiterIndex = value.IndexOf(':', StringComparison.Ordinal);
        int firstSlashIndex = value.IndexOf('/', StringComparison.Ordinal);

        return schemeDelimiterIndex >= 0 && (firstSlashIndex < 0 || schemeDelimiterIndex < firstSlashIndex);
    }

    /// <inheritdoc/>
    public bool Equals(StatusListReference other)
    {
        return Index == other.Index && string.Equals(Uri, other.Uri, StringComparison.Ordinal);
    }

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals(object? obj)
    {
        return obj is StatusListReference other && Equals(other);
    }

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        return HashCode.Combine(Index, Uri);
    }

    /// <summary>
    /// Returns a human-readable representation of this reference.
    /// </summary>
    /// <returns>A string in the format <c>StatusListReference[idx=N, uri=...]</c>.</returns>
    public override string ToString()
    {
        return $"StatusListReference[idx={Index}, uri={Uri}]";
    }

    /// <summary>
    /// Determines whether two <see cref="StatusListReference"/> values are equal.
    /// </summary>
    public static bool operator ==(StatusListReference left, StatusListReference right)
    {
        return left.Equals(right);
    }

    /// <summary>
    /// Determines whether two <see cref="StatusListReference"/> values are not equal.
    /// </summary>
    public static bool operator !=(StatusListReference left, StatusListReference right)
    {
        return !left.Equals(right);
    }
}
