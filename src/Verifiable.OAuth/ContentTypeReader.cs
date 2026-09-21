namespace Verifiable.OAuth;

/// <summary>
/// Reads the media type out of an HTTP <c>Content-Type</c> header value per
/// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-8.3.1">RFC 9110 §8.3.1</see>: the
/// header's grammar is <c>media-type = type "/" subtype parameters</c>, so the media type is the
/// type/subtype token that precedes any semicolon-delimited parameter. Shared by the document-fetch
/// gates across this assembly so each keeps only its own accepted-media-type verdict.
/// </summary>
internal static class ContentTypeReader
{
    /// <summary>
    /// Reads the media type out of <paramref name="contentType"/>: the type/subtype token before the
    /// first <c>;</c> parameter delimiter, trimmed of surrounding whitespace.
    /// </summary>
    /// <param name="contentType">A <c>Content-Type</c> header value, or <see langword="null"/>.</param>
    /// <returns>
    /// The trimmed media type, or an empty span when <paramref name="contentType"/> is
    /// <see langword="null"/> or blank.
    /// </returns>
    internal static ReadOnlySpan<char> ReadMediaType(string? contentType)
    {
        if(string.IsNullOrWhiteSpace(contentType))
        {
            return ReadOnlySpan<char>.Empty;
        }

        ReadOnlySpan<char> value = contentType.AsSpan().Trim();
        int parameterDelimiter = value.IndexOf(';');

        return (parameterDelimiter >= 0 ? value[..parameterDelimiter] : value).Trim();
    }
}
