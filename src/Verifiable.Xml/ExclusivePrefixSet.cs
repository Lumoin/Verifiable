namespace Verifiable.Xml;

/// <summary>
/// The parsed <c>InclusiveNamespaces PrefixList</c> parameter of
/// <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
/// 1.0</see> section 4: the UTF-8 octets of the listed namespace prefixes and whether the <c>#default</c>
/// token is present. Namespace nodes whose prefix appears on the list "are handled as provided in
/// Canonical XML" per section 3 item 2; the <c>#default</c> token selects that handling for the default
/// namespace per section 3 item 4. The spans reference caller-owned pooled buffers, so the set is valid
/// only within the canonicalization call that composed it.
/// </summary>
internal readonly ref struct ExclusivePrefixSet
{
    /// <summary>The concatenated UTF-8 octets of the listed prefixes.</summary>
    private ReadOnlySpan<byte> TokenOctets { get; }

    /// <summary>Start and length pairs into <see cref="TokenOctets"/>, one pair per listed prefix.</summary>
    private ReadOnlySpan<int> TokenRanges { get; }

    /// <summary>Whether the <c>#default</c> token is present on the list.</summary>
    public bool HasDefaultToken { get; }


    /// <summary>
    /// Creates the set over its parsed parts.
    /// </summary>
    /// <param name="tokenOctets">The concatenated UTF-8 octets of the listed prefixes.</param>
    /// <param name="tokenRanges">Start and length pairs into the octets, one pair per listed prefix.</param>
    /// <param name="hasDefaultToken">Whether the <c>#default</c> token is present.</param>
    public ExclusivePrefixSet(ReadOnlySpan<byte> tokenOctets, ReadOnlySpan<int> tokenRanges, bool hasDefaultToken)
    {
        TokenOctets = tokenOctets;
        TokenRanges = tokenRanges;
        HasDefaultToken = hasDefaultToken;
    }


    /// <summary>
    /// Tells whether a namespace prefix appears on the list.
    /// </summary>
    /// <param name="prefix">The prefix octets to look for.</param>
    /// <returns><see langword="true"/> when the prefix is listed.</returns>
    public bool Contains(ReadOnlySpan<byte> prefix)
    {
        for(int i = 0; i + 1 < TokenRanges.Length; i += 2)
        {
            if(TokenOctets.Slice(TokenRanges[i], TokenRanges[i + 1]).SequenceEqual(prefix))
            {
                return true;
            }
        }

        return false;
    }
}
