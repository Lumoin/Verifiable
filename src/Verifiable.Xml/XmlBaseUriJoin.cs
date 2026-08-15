using System.Buffers;

namespace Verifiable.Xml;

/// <summary>
/// The <c>join-URI-References</c> function of
/// <see href="https://www.w3.org/TR/2008/REC-xml-c14n11-20080502/">Canonical XML 1.1</see> section 2.4:
/// the reference-resolution steps of
/// <see href="https://www.rfc-editor.org/rfc/rfc3986">IETF RFC 3986</see> sections 5.2.1, 5.2.2 and 5.2.4
/// with the modifications section 2.4 lists — the base needs no scheme, a trailing <c>..</c> segment of
/// the base becomes <c>../</c> before processing, the reference's fragment is dropped, and remove-dot-
/// segments keeps leading <c>../</c> segments, collapses consecutive <c>/</c> characters and appends a
/// <c>/</c> to a trailing <c>..</c> segment so a combination of relative path components stays a relative
/// path component. Values are exact octet sequences; nothing beyond the specified steps is normalized.
/// </summary>
internal static class XmlBaseUriJoin
{
    /// <summary>
    /// The URI reference split into the components of
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986">IETF RFC 3986</see> section 3, with the fragment
    /// already dropped. Absent components are distinguished from empty ones so section 5.2.2's defined-ness
    /// tests apply exactly.
    /// </summary>
    private readonly ref struct UriComponents
    {
        /// <summary>The scheme, without the trailing colon; meaningful only when <see cref="HasScheme"/>.</summary>
        public ReadOnlySpan<byte> Scheme { get; }

        /// <summary>Whether the reference carries a scheme.</summary>
        public bool HasScheme { get; }

        /// <summary>The authority, without the leading <c>//</c>; meaningful only when <see cref="HasAuthority"/>.</summary>
        public ReadOnlySpan<byte> Authority { get; }

        /// <summary>Whether the reference carries an authority.</summary>
        public bool HasAuthority { get; }

        /// <summary>The path; possibly empty.</summary>
        public ReadOnlySpan<byte> Path { get; }

        /// <summary>The query, without the leading <c>?</c>; meaningful only when <see cref="HasQuery"/>.</summary>
        public ReadOnlySpan<byte> Query { get; }

        /// <summary>Whether the reference carries a query.</summary>
        public bool HasQuery { get; }


        /// <summary>
        /// Creates the component view.
        /// </summary>
        /// <param name="scheme">The scheme span.</param>
        /// <param name="hasScheme">Whether the scheme is present.</param>
        /// <param name="authority">The authority span.</param>
        /// <param name="hasAuthority">Whether the authority is present.</param>
        /// <param name="path">The path span.</param>
        /// <param name="query">The query span.</param>
        /// <param name="hasQuery">Whether the query is present.</param>
        public UriComponents(ReadOnlySpan<byte> scheme, bool hasScheme, ReadOnlySpan<byte> authority, bool hasAuthority, ReadOnlySpan<byte> path, ReadOnlySpan<byte> query, bool hasQuery)
        {
            Scheme = scheme;
            HasScheme = hasScheme;
            Authority = authority;
            HasAuthority = hasAuthority;
            Path = path;
            Query = query;
            HasQuery = hasQuery;
        }
    }


    /// <summary>
    /// Joins a reference against a base value per the modified sections 5.2.1 and 5.2.2 of
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986">IETF RFC 3986</see> and appends the joined value
    /// to the destination. The reference's fragment is ignored per
    /// <see href="https://www.w3.org/TR/2008/REC-xml-c14n11-20080502/">Canonical XML 1.1</see>
    /// section 2.4; the result may be empty, in which case nothing is appended.
    /// </summary>
    /// <param name="baseValue">The base <c>xml:base</c> value.</param>
    /// <param name="referenceValue">The reference <c>xml:base</c> value joined against the base.</param>
    /// <param name="pool">The pool scratch buffers are rented from.</param>
    /// <param name="destination">The list the joined octets are appended to.</param>
    public static void Join(ReadOnlySpan<byte> baseValue, ReadOnlySpan<byte> referenceValue, MemoryPool<byte> pool, PooledStructList<byte> destination)
    {
        UriComponents baseComponents = Parse(baseValue);
        UriComponents reference = Parse(referenceValue);
        bool isBaseTrailingDotDot = baseComponents.Path.SequenceEqual(".."u8) || baseComponents.Path.EndsWith("/.."u8);
        if(reference.HasScheme)
        {
            destination.AddRange(reference.Scheme);
            destination.Add((byte)':');
            AppendAuthority(reference, destination);
            RemoveDotSegments(reference.Path, pool, destination);
            AppendQuery(reference.Query, reference.HasQuery, destination);

            return;
        }

        if(baseComponents.HasScheme)
        {
            destination.AddRange(baseComponents.Scheme);
            destination.Add((byte)':');
        }

        if(reference.HasAuthority)
        {
            AppendAuthority(reference, destination);
            RemoveDotSegments(reference.Path, pool, destination);
            AppendQuery(reference.Query, reference.HasQuery, destination);

            return;
        }

        AppendAuthority(baseComponents, destination);
        if(reference.Path.IsEmpty)
        {
            destination.AddRange(baseComponents.Path);
            if(isBaseTrailingDotDot)
            {
                destination.Add((byte)'/');
            }

            bool isQueryFromReference = reference.HasQuery;
            AppendQuery(
                isQueryFromReference ? reference.Query : baseComponents.Query,
                isQueryFromReference || baseComponents.HasQuery,
                destination);

            return;
        }

        if(reference.Path[0] == (byte)'/')
        {
            RemoveDotSegments(reference.Path, pool, destination);
            AppendQuery(reference.Query, reference.HasQuery, destination);

            return;
        }

        using var merged = new PooledStructList<byte>(pool, baseValue.Length + referenceValue.Length + 2);
        if(baseComponents.HasAuthority && baseComponents.Path.IsEmpty)
        {
            merged.Add((byte)'/');
        }
        else if(isBaseTrailingDotDot)
        {
            merged.AddRange(baseComponents.Path);
            merged.Add((byte)'/');
        }
        else
        {
            int lastSeparator = baseComponents.Path.LastIndexOf((byte)'/');
            if(lastSeparator >= 0)
            {
                merged.AddRange(baseComponents.Path[..(lastSeparator + 1)]);
            }
        }

        merged.AddRange(reference.Path);
        RemoveDotSegments(merged.AsSpan(), pool, destination);
        AppendQuery(reference.Query, reference.HasQuery, destination);
    }


    /// <summary>
    /// Applies the modified remove-dot-segments algorithm of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-c14n11-20080502/">Canonical XML 1.1</see>
    /// section 2.4 to a path and appends the result to the destination: relative to
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986">IETF RFC 3986</see> section 5.2.4, leading
    /// <c>../</c> segments of a relative path are kept, consecutive <c>/</c> characters collapse into one,
    /// and a trailing <c>..</c> segment receives a trailing <c>/</c>. The result may be empty, in which
    /// case nothing is appended.
    /// </summary>
    /// <param name="path">The path octets.</param>
    /// <param name="pool">The pool the segment scratch buffer is rented from.</param>
    /// <param name="destination">The list the result octets are appended to.</param>
    public static void RemoveDotSegments(ReadOnlySpan<byte> path, MemoryPool<byte> pool, PooledStructList<byte> destination)
    {
        if(path.IsEmpty)
        {
            return;
        }

        bool isAbsolute = path[0] == (byte)'/';
        bool isEndingWithSeparator = path[^1] == (byte)'/';
        using var retained = new PooledStructList<byte>(pool, path.Length);
        int upCount = 0;
        int index = 0;
        bool isLastSegmentDotSegment = false;
        while(index < path.Length)
        {
            while(index < path.Length && path[index] == (byte)'/')
            {
                index++;
            }

            if(index >= path.Length)
            {
                break;
            }

            int start = index;
            while(index < path.Length && path[index] != (byte)'/')
            {
                index++;
            }

            ReadOnlySpan<byte> segment = path[start..index];
            if(segment.SequenceEqual("."u8))
            {
                isLastSegmentDotSegment = true;

                continue;
            }

            if(segment.SequenceEqual(".."u8))
            {
                isLastSegmentDotSegment = true;
                if(retained.Count > 0)
                {
                    int lastSeparator = retained.AsSpan().LastIndexOf((byte)'/');
                    retained.Truncate(lastSeparator < 0 ? 0 : lastSeparator);
                }
                else if(!isAbsolute)
                {
                    upCount++;
                }

                continue;
            }

            isLastSegmentDotSegment = false;
            if(retained.Count > 0)
            {
                retained.Add((byte)'/');
            }

            retained.AddRange(segment);
        }

        bool hasTrailingSeparator = isEndingWithSeparator || isLastSegmentDotSegment;
        if(isAbsolute)
        {
            destination.Add((byte)'/');
        }

        for(int i = 0; i < upCount; ++i)
        {
            destination.AddRange("../"u8);
        }

        if(retained.Count > 0)
        {
            destination.AddRange(retained.AsSpan());
            if(hasTrailingSeparator)
            {
                destination.Add((byte)'/');
            }
        }
    }


    /// <summary>
    /// Splits a URI reference into its components per the grammar of
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986">IETF RFC 3986</see> section 3, dropping any
    /// fragment.
    /// </summary>
    /// <param name="value">The URI reference octets.</param>
    /// <returns>The component view.</returns>
    private static UriComponents Parse(ReadOnlySpan<byte> value)
    {
        ReadOnlySpan<byte> scheme = default;
        bool hasScheme = XmlCharacters.IsAbsoluteUri(value);
        ReadOnlySpan<byte> remainder = value;
        if(hasScheme)
        {
            int colonIndex = value.IndexOf((byte)':');
            scheme = value[..colonIndex];
            remainder = value[(colonIndex + 1)..];
        }

        int fragmentIndex = remainder.IndexOf((byte)'#');
        if(fragmentIndex >= 0)
        {
            remainder = remainder[..fragmentIndex];
        }

        ReadOnlySpan<byte> authority = default;
        bool hasAuthority = remainder.StartsWith("//"u8);
        if(hasAuthority)
        {
            remainder = remainder[2..];
            int authorityEnd = remainder.IndexOfAny("/?"u8);
            if(authorityEnd < 0)
            {
                authority = remainder;
                remainder = default;
            }
            else
            {
                authority = remainder[..authorityEnd];
                remainder = remainder[authorityEnd..];
            }
        }

        int queryIndex = remainder.IndexOf((byte)'?');
        bool hasQuery = queryIndex >= 0;
        ReadOnlySpan<byte> path = hasQuery ? remainder[..queryIndex] : remainder;
        ReadOnlySpan<byte> query = hasQuery ? remainder[(queryIndex + 1)..] : default;

        return new UriComponents(scheme, hasScheme, authority, hasAuthority, path, query, hasQuery);
    }


    /// <summary>
    /// Appends the authority component with its <c>//</c> marker when present.
    /// </summary>
    /// <param name="components">The component view whose authority is appended.</param>
    /// <param name="destination">The list the octets are appended to.</param>
    private static void AppendAuthority(in UriComponents components, PooledStructList<byte> destination)
    {
        if(components.HasAuthority)
        {
            destination.AddRange("//"u8);
            destination.AddRange(components.Authority);
        }
    }


    /// <summary>
    /// Appends the query component with its <c>?</c> marker when present.
    /// </summary>
    /// <param name="query">The query octets.</param>
    /// <param name="hasQuery">Whether the query is present.</param>
    /// <param name="destination">The list the octets are appended to.</param>
    private static void AppendQuery(ReadOnlySpan<byte> query, bool hasQuery, PooledStructList<byte> destination)
    {
        if(hasQuery)
        {
            destination.Add((byte)'?');
            destination.AddRange(query);
        }
    }
}
