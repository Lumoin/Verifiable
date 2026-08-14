using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using Lumoin.Base;
using Verifiable.Foundation;

namespace Verifiable.Xml;

/// <summary>
/// Canonicalizes an <see cref="XmlNodeSet"/> over an <see cref="XmlNodeTable"/> into the canonical form of
/// <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> or
/// <see href="https://www.w3.org/TR/2008/REC-xml-c14n11-20080502/">Canonical XML 1.1</see> — UTF-8 octets
/// without a byte order mark, produced by the section 2.3 processing model with the section 2.4
/// document-subsets enhancement of the selected specification — or into the exclusive canonical form of
/// <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
/// 1.0</see> section 3.
/// </summary>
/// <remarks>
/// The surface is result-shaped: a refused request reports an <see cref="XmlCanonicalizationError"/>,
/// never an exception over input content. Every working buffer is rented from the caller-supplied pool and
/// returned before the call completes; the canonical octets are materialized once into the returned
/// <see cref="PooledMemory"/> carrying <see cref="BufferTags.XmlCanonical"/>, whose pooled lease the caller
/// owns and disposes. An internal tag-parameterized overload of each public entry point lets
/// <c>Verifiable.Xml.XmlReferenceProcessing</c> request a different <see cref="Tag"/> directly — avoiding a
/// copy-to-retag when canonicalization itself is that engine's final chain output — without duplicating
/// either method's body. The exclusive family of
/// <see cref="XmlCanonicalizationAlgorithm"/> takes the <c>InclusiveNamespaces PrefixList</c> parameter of
/// <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
/// 1.0</see> section 4 through <see cref="TryCanonicalizeExclusive"/>;
/// <see cref="TryCanonicalize"/> serves the exclusive algorithm members by delegating there with an empty
/// prefix list, which section 3 item 2 permits ("an additional, possibly null, parameter").
/// </remarks>
public static class XmlCanonicalization
{
    /// <summary>
    /// Canonicalizes the node-set with the given canonicalization algorithm. The exclusive members of
    /// <see cref="XmlCanonicalizationAlgorithm"/> delegate to <see cref="TryCanonicalizeExclusive"/> with
    /// an empty <c>InclusiveNamespaces PrefixList</c>.
    /// </summary>
    /// <param name="table">The node table the node-set marks nodes of.</param>
    /// <param name="nodeSet">The node-set to canonicalize.</param>
    /// <param name="algorithm">The canonicalization algorithm.</param>
    /// <param name="pool">The pool every working buffer and the returned octets are rented from.</param>
    /// <param name="canonicalOctets">The canonical octets on success, tagged
    /// <see cref="BufferTags.XmlCanonical"/>; the caller owns and must dispose them.</param>
    /// <param name="error">The refusal on failure.</param>
    /// <returns><see langword="true"/> when the canonical form was produced.</returns>
    public static bool TryCanonicalize(XmlNodeTable table, XmlNodeSet nodeSet, XmlCanonicalizationAlgorithm algorithm, BaseMemoryPool pool, [NotNullWhen(true)] out PooledMemory? canonicalOctets, out XmlCanonicalizationError error)
    {
        return TryCanonicalize(table, nodeSet, algorithm, pool, BufferTags.XmlCanonical, out canonicalOctets, out error);
    }


    /// <summary>
    /// <see cref="TryCanonicalize"/>, with the returned octets tagged <paramref name="tag"/> instead of the
    /// fixed <see cref="BufferTags.XmlCanonical"/> — the reference-processing engine's own implicit section
    /// 4.3.3.2 default node-set-to-octets conversion uses this to produce
    /// <see cref="BufferTags.XmlDigestInput"/>-tagged octets directly: when canonicalization itself IS the
    /// engine's final chain output, there is no reason to rent, copy into and tag a second buffer just to
    /// change the tag.
    /// </summary>
    /// <param name="tag">The tag the returned octets carry.</param>
    internal static bool TryCanonicalize(XmlNodeTable table, XmlNodeSet nodeSet, XmlCanonicalizationAlgorithm algorithm, BaseMemoryPool pool, Tag tag, [NotNullWhen(true)] out PooledMemory? canonicalOctets, out XmlCanonicalizationError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(pool);
        if(algorithm is XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10 or XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10WithComments)
        {
            return TryCanonicalizeExclusive(table, nodeSet, algorithm == XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10WithComments, [], pool, tag, out canonicalOctets, out error);
        }

        canonicalOctets = null;
        if(!nodeSet.IsOver(table))
        {
            error = new XmlCanonicalizationError(XmlCanonicalizationFailure.UnsupportedNodeSet, 0);

            return false;
        }

        if(!TryValidateNodeSet(table, nodeSet, out error))
        {
            return false;
        }

        XmlCanonicalVariant variant = algorithm switch
        {
            XmlCanonicalizationAlgorithm.CanonicalXml10 or XmlCanonicalizationAlgorithm.CanonicalXml10WithComments => XmlCanonicalVariant.Inclusive10,
            XmlCanonicalizationAlgorithm.CanonicalXml11 or XmlCanonicalizationAlgorithm.CanonicalXml11WithComments => XmlCanonicalVariant.Inclusive11,
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm))
        };
        bool isWithComments = algorithm is XmlCanonicalizationAlgorithm.CanonicalXml10WithComments
            or XmlCanonicalizationAlgorithm.CanonicalXml11WithComments;
        using var output = new PooledStructList<byte>(pool, 256);
        XmlCanonicalRenderer.Render(table, in nodeSet, variant, isWithComments, default, pool, output);
        canonicalOctets = PooledMemory.FromBytes(output.AsSpan(), pool, tag);
        error = default;

        return true;
    }


    /// <summary>
    /// Canonicalizes the node-set into the exclusive canonical form of
    /// <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
    /// 1.0</see> section 3, with the <c>InclusiveNamespaces PrefixList</c> parameter of section 4.
    /// </summary>
    /// <param name="table">The node table the node-set marks nodes of.</param>
    /// <param name="nodeSet">The node-set to canonicalize.</param>
    /// <param name="isWithComments">Whether comment nodes render, per the <c>#WithComments</c> identifier
    /// of section 4.</param>
    /// <param name="inclusivePrefixes">The <c>PrefixList</c> entries in the NMTOKENS format of section 4,
    /// "a white space separated list": every entry splits on XML white space into tokens, where a token is
    /// either a namespace prefix of the <c>NCName</c> production, whose namespace nodes "are handled as
    /// provided in Canonical XML" per section 3 item 2, or the <c>#default</c> token selecting that
    /// handling for the default namespace per section 3 item 4. Any other token is refused as
    /// <see cref="XmlCanonicalizationFailure.InvalidPrefixList"/>.</param>
    /// <param name="pool">The pool every working buffer and the returned octets are rented from.</param>
    /// <param name="canonicalOctets">The canonical octets on success, tagged
    /// <see cref="BufferTags.XmlCanonical"/>; the caller owns and must dispose them.</param>
    /// <param name="error">The refusal on failure.</param>
    /// <returns><see langword="true"/> when the exclusive canonical form was produced.</returns>
    public static bool TryCanonicalizeExclusive(XmlNodeTable table, XmlNodeSet nodeSet, bool isWithComments, ReadOnlySpan<string> inclusivePrefixes, BaseMemoryPool pool, [NotNullWhen(true)] out PooledMemory? canonicalOctets, out XmlCanonicalizationError error)
    {
        return TryCanonicalizeExclusive(table, nodeSet, isWithComments, inclusivePrefixes, pool, BufferTags.XmlCanonical, out canonicalOctets, out error);
    }


    /// <summary>
    /// <see cref="TryCanonicalizeExclusive"/>, with the returned octets tagged <paramref name="tag"/>
    /// instead of the fixed <see cref="BufferTags.XmlCanonical"/> — see the tag-parameterized overload of
    /// <see cref="TryCanonicalize"/> for why.
    /// </summary>
    /// <param name="tag">The tag the returned octets carry.</param>
    internal static bool TryCanonicalizeExclusive(XmlNodeTable table, XmlNodeSet nodeSet, bool isWithComments, ReadOnlySpan<string> inclusivePrefixes, BaseMemoryPool pool, Tag tag, [NotNullWhen(true)] out PooledMemory? canonicalOctets, out XmlCanonicalizationError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(pool);
        canonicalOctets = null;
        if(!nodeSet.IsOver(table))
        {
            error = new XmlCanonicalizationError(XmlCanonicalizationFailure.UnsupportedNodeSet, 0);

            return false;
        }

        if(!TryValidateNodeSet(table, nodeSet, out error))
        {
            return false;
        }

        using var tokenOctets = new PooledStructList<byte>(pool, 16);
        using var tokenRanges = new PooledStructList<int>(pool, 8);
        if(!TryParsePrefixList(inclusivePrefixes, pool, tokenOctets, tokenRanges, out bool hasDefaultToken))
        {
            error = new XmlCanonicalizationError(XmlCanonicalizationFailure.InvalidPrefixList, 0);

            return false;
        }

        var prefixSet = new ExclusivePrefixSet(tokenOctets.AsSpan(), tokenRanges.AsSpan(), hasDefaultToken);
        using var output = new PooledStructList<byte>(pool, 256);
        XmlCanonicalRenderer.Render(table, in nodeSet, XmlCanonicalVariant.Exclusive10, isWithComments, prefixSet, pool, output);
        canonicalOctets = PooledMemory.FromBytes(output.AsSpan(), pool, tag);
        error = default;

        return true;
    }


    /// <summary>
    /// Parses the <c>InclusiveNamespaces PrefixList</c> entries into UTF-8 prefix tokens: every entry
    /// splits on the XML white space of production <c>S</c> into NMTOKENS-format tokens per section 4 of
    /// <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
    /// 1.0</see>; the <c>#default</c> token sets its flag, every other token must be an <c>NCName</c>.
    /// </summary>
    /// <param name="inclusivePrefixes">The prefix-list entries.</param>
    /// <param name="pool">The pool the transcoding scratch buffer is rented from.</param>
    /// <param name="tokenOctets">The list the UTF-8 octets of the prefix tokens are appended to.</param>
    /// <param name="tokenRanges">The list the start and length pairs are appended to.</param>
    /// <param name="hasDefaultToken">Whether the <c>#default</c> token is present.</param>
    /// <returns><see langword="true"/> when every token is a namespace prefix or <c>#default</c>.</returns>
    private static bool TryParsePrefixList(ReadOnlySpan<string> inclusivePrefixes, MemoryPool<byte> pool, PooledStructList<byte> tokenOctets, PooledStructList<int> tokenRanges, out bool hasDefaultToken)
    {
        hasDefaultToken = false;
        foreach(string entry in inclusivePrefixes)
        {
            ReadOnlySpan<char> remaining = entry;
            while(!remaining.IsEmpty)
            {
                int start = 0;
                while(start < remaining.Length && IsXmlWhitespace(remaining[start]))
                {
                    ++start;
                }

                remaining = remaining[start..];
                if(remaining.IsEmpty)
                {
                    break;
                }

                int end = 0;
                while(end < remaining.Length && !IsXmlWhitespace(remaining[end]))
                {
                    ++end;
                }

                ReadOnlySpan<char> token = remaining[..end];
                remaining = remaining[end..];
                if(token.SequenceEqual("#default"))
                {
                    hasDefaultToken = true;

                    continue;
                }

                if(!IsNcName(token))
                {
                    return false;
                }

                int byteCount = Encoding.UTF8.GetByteCount(token);
                using IMemoryOwner<byte> scratch = pool.Rent(byteCount);
                int written = Encoding.UTF8.GetBytes(token, scratch.Memory.Span);
                int rangeStart = tokenOctets.AddRange(scratch.Memory.Span[..written]);
                tokenRanges.Add(rangeStart);
                tokenRanges.Add(written);
            }
        }

        return true;
    }


    /// <summary>
    /// Tells whether the character is XML white space per production <c>S</c> of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 2.3:
    /// <c>(#x20 | #x9 | #xD | #xA)</c>.
    /// </summary>
    /// <param name="character">The character to classify.</param>
    /// <returns><see langword="true"/> when the character is XML white space.</returns>
    private static bool IsXmlWhitespace(char character)
    {
        return character is ' ' or '\t' or '\r' or '\n';
    }


    /// <summary>
    /// Tells whether the token matches production <c>NCName</c> of
    /// <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third
    /// Edition)</see> section 3: a colon-free name start character followed by colon-free name characters.
    /// </summary>
    /// <param name="token">The token to validate.</param>
    /// <returns><see langword="true"/> when the token is an <c>NCName</c>.</returns>
    private static bool IsNcName(ReadOnlySpan<char> token)
    {
        if(token.IsEmpty)
        {
            return false;
        }

        bool isFirst = true;
        ReadOnlySpan<char> remaining = token;
        while(!remaining.IsEmpty)
        {
            if(Rune.DecodeFromUtf16(remaining, out Rune rune, out int consumed) != OperationStatus.Done)
            {
                return false;
            }

            bool isValid = isFirst ? XmlCharacters.IsNameStartCharacter(rune.Value) : XmlCharacters.IsNameCharacter(rune.Value);
            if(!isValid)
            {
                return false;
            }

            isFirst = false;
            remaining = remaining[consumed..];
        }

        return true;
    }


    /// <summary>
    /// Validates that every node index the set was composed over — the subtree apex, every
    /// ancestor-context index and every exclusion index, under every set shape — names an element node of
    /// the table, and that in the element-subtree shape every ancestor-context index names a proper
    /// ancestor of the subtree apex.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="nodeSet">The node-set to validate.</param>
    /// <param name="error">The refusal when validation fails.</param>
    /// <returns><see langword="true"/> when the set is valid over the table.</returns>
    private static bool TryValidateNodeSet(XmlNodeTable table, in XmlNodeSet nodeSet, out XmlCanonicalizationError error)
    {
        error = default;
        if(!nodeSet.IsWholeDocument && !IsElementIndex(table, nodeSet.ApexElementIndex))
        {
            error = new XmlCanonicalizationError(XmlCanonicalizationFailure.InvalidNodeIndex, 0);

            return false;
        }

        for(int i = 0; i < nodeSet.AncestorContextCount; ++i)
        {
            int ancestorIndex = nodeSet.AncestorContextAt(i);
            bool isValidAncestorContext = IsElementIndex(table, ancestorIndex)
                && (nodeSet.IsWholeDocument || IsProperAncestor(table, ancestorIndex, nodeSet.ApexElementIndex));
            if(!isValidAncestorContext)
            {
                error = new XmlCanonicalizationError(XmlCanonicalizationFailure.InvalidNodeIndex, 0);

                return false;
            }
        }

        for(int i = 0; i < nodeSet.ExclusionCount; ++i)
        {
            if(!IsElementIndex(table, nodeSet.ExclusionAt(i)))
            {
                error = new XmlCanonicalizationError(XmlCanonicalizationFailure.InvalidNodeIndex, 0);

                return false;
            }
        }

        return true;
    }


    /// <summary>
    /// Tells whether the index names an element node of the table.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="nodeIndex">The index to test.</param>
    /// <returns><see langword="true"/> when the index names an element.</returns>
    private static bool IsElementIndex(XmlNodeTable table, int nodeIndex)
    {
        return nodeIndex >= 0 && nodeIndex < table.Count && table.KindOf(nodeIndex) == XmlNodeKind.Element;
    }


    /// <summary>
    /// Tells whether one element is a proper ancestor of another.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="ancestorIndex">The candidate ancestor element.</param>
    /// <param name="descendantIndex">The candidate descendant element.</param>
    /// <returns><see langword="true"/> when the ancestry holds.</returns>
    private static bool IsProperAncestor(XmlNodeTable table, int ancestorIndex, int descendantIndex)
    {
        for(int current = table.ParentOf(descendantIndex); current > 0; current = table.ParentOf(current))
        {
            if(current == ancestorIndex)
            {
                return true;
            }
        }

        return false;
    }
}
