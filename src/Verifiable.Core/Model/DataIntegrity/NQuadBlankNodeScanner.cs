namespace Verifiable.Core.Model.DataIntegrity;

/// <summary>
/// Locates blank node terms in N-Quad statements by term position rather than by substring
/// search.
/// </summary>
/// <remarks>
/// <para>
/// An N-Quad statement is a whitespace-separated sequence of terms: an IRI reference
/// (<c>&lt;...&gt;</c>), a blank node (<c>_:label</c>), or a literal (a quoted string, optionally
/// followed by a language tag or datatype IRI), per
/// <see href="https://www.w3.org/TR/n-quads/#sec-grammar">N-Quads, §2 Grammar</see>. A literal's
/// quoted content can contain the characters <c>"_:"</c> followed by letters and digits, which
/// looks identical to a blank node label under plain substring search, and the literal can itself
/// contain backslash escapes, including an escaped quote that does not end it. This scanner
/// tracks quoted and angle-bracketed spans while walking the statement and reports a blank node
/// only when <c>"_:"</c> begins a term -- at the start of the statement or immediately after
/// whitespace, outside any such span -- so a <c>"_:"</c>-looking sequence inside a literal or an
/// IRI is never mistaken for one.
/// </para>
/// </remarks>
internal static class NQuadBlankNodeScanner
{
    /// <summary>
    /// Finds the next blank node term in <paramref name="statement"/> at or after
    /// <paramref name="searchStart"/>.
    /// </summary>
    /// <param name="statement">The N-Quad statement to scan.</param>
    /// <param name="searchStart">The index at which to resume scanning.</param>
    /// <returns>
    /// The index of the term's leading <c>"_:"</c> and the exclusive end index of its identifier
    /// body, or <see langword="null"/> when no further blank node term begins at or after
    /// <paramref name="searchStart"/>.
    /// </returns>
    public static (int MarkerStart, int IdentifierEnd)? FindNext(string statement, int searchStart)
    {
        ArgumentNullException.ThrowIfNull(statement);

        var index = searchStart;
        var isAtTermStart = index == 0 || char.IsWhiteSpace(statement[index - 1]);

        while(index < statement.Length)
        {
            var current = statement[index];
            if(current == '"')
            {
                index = SkipQuotedLiteral(statement, index);
                isAtTermStart = false;

                continue;
            }

            if(current == '<')
            {
                index = SkipIriReference(statement, index);
                isAtTermStart = false;

                continue;
            }

            if(isAtTermStart && current == '_' && index + 1 < statement.Length && statement[index + 1] == ':')
            {
                var identifierEnd = index + 2;
                while(identifierEnd < statement.Length && IsIdentifierCharacter(statement[identifierEnd]))
                {
                    identifierEnd++;
                }

                return (index, identifierEnd);
            }

            isAtTermStart = char.IsWhiteSpace(current);
            index++;
        }

        return null;
    }


    /// <summary>
    /// Advances past a quoted literal's closing quote, honoring backslash escapes so an escaped
    /// quote does not end the literal early.
    /// </summary>
    private static int SkipQuotedLiteral(string statement, int quoteStart)
    {
        var index = quoteStart + 1;
        while(index < statement.Length && statement[index] != '"')
        {
            index += statement[index] == '\\' && index + 1 < statement.Length ? 2 : 1;
        }

        return Math.Min(index + 1, statement.Length);
    }


    /// <summary>
    /// Advances past an IRI reference's closing angle bracket.
    /// </summary>
    private static int SkipIriReference(string statement, int bracketStart)
    {
        var index = bracketStart + 1;
        while(index < statement.Length && statement[index] != '>')
        {
            index++;
        }

        return Math.Min(index + 1, statement.Length);
    }


    /// <summary>
    /// Determines whether a character can appear in a blank node identifier body, matching the
    /// alphabet this library's own canonical (<c>c14nN</c>), HMAC-derived (base64url), and
    /// shuffled (<c>bN</c>) blank node labels are drawn from.
    /// </summary>
    private static bool IsIdentifierCharacter(char c) =>
        char.IsAsciiLetterOrDigit(c) || c == '_' || c == '-';
}
