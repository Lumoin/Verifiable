using System;
using System.Text;
using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.ProtectedResource;

/// <summary>
/// The RFC 9728 §5 <c>WWW-Authenticate</c> linkage: a protected resource
/// returns the URL of its metadata document through the
/// <c>resource_metadata</c> challenge parameter (§5.1), and the client reads
/// it back to start the §5 discovery flow — fetch the metadata, validate it
/// per §3.3, and learn the authorization servers and scopes to use.
/// </summary>
/// <remarks>
/// <para>
/// The parameter rides any authentication scheme — <c>Bearer</c> (RFC 6750)
/// or <c>DPoP</c> (RFC 9449) — and MAY be combined with other challenge
/// parameters (§5.1). Parsing follows the RFC 9110 §11.2 <c>auth-param</c>
/// grammar: parameter names compare case-insensitively, values are tokens or
/// quoted strings with backslash escaping.
/// </para>
/// <para>
/// §3.3: when the metadata URL came from this parameter, the fetched
/// document's <c>resource</c> value MUST be identical to the URL the client
/// used to make the resource request — run
/// <see cref="ProtectedResourceMetadataValidation.IsResourceMatch"/> with
/// that URL before using the document.
/// </para>
/// </remarks>
public static class ProtectedResourceChallenge
{
    /// <summary>The UTF-8 source literal of <see cref="ResourceMetadataParameter"/>.</summary>
    public static ReadOnlySpan<byte> ResourceMetadataParameterUtf8 => "resource_metadata"u8;

    /// <summary>The <c>resource_metadata</c> challenge parameter name (RFC 9728 §5.1).</summary>
    public static readonly string ResourceMetadataParameter = Utf8Constants.ToInternedString(ResourceMetadataParameterUtf8);


    /// <summary>
    /// Builds a <c>WWW-Authenticate</c> header value carrying the metadata
    /// URL: <c>{scheme} resource_metadata="{url}"</c>.
    /// </summary>
    /// <param name="scheme">The authentication scheme, e.g. <see cref="WellKnownAuthenticationSchemes.Bearer"/>.</param>
    /// <param name="metadataUrl">The protected resource metadata URL (§3).</param>
    /// <exception cref="ArgumentException">
    /// The URL's <see cref="Uri.OriginalString"/> carries a control character
    /// (a header-field-value MUST NOT contain CR, LF, or other CTLs per RFC 9110
    /// §5.5) — a quoted-string cannot represent it, and emitting it verbatim
    /// would split the header.
    /// </exception>
    public static string BuildChallenge(string scheme, Uri metadataUrl)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(scheme);
        ArgumentNullException.ThrowIfNull(metadataUrl);

        if(ContainsControlCharacter(metadataUrl.OriginalString))
        {
            throw new ArgumentException(
                "The metadata URL carries a control character and cannot be represented in a header field value (RFC 9110 §5.5).",
                nameof(metadataUrl));
        }

        //Quoted-string per RFC 9110 §5.6.4 — URLs do not ordinarily carry
        //'"' or '\', but escape faithfully rather than assume.
        string url = metadataUrl.OriginalString
            .Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("\"", "\\\"", StringComparison.Ordinal);

        return $"{scheme} {ResourceMetadataParameter}=\"{url}\"";
    }


    /// <summary>
    /// Whether the value carries a C0 control character or DEL — RFC 9110 §5.5
    /// forbids these in a field value, and CR/LF would split the header.
    /// </summary>
    private static bool ContainsControlCharacter(string value)
    {
        foreach(char c in value)
        {
            if(c is (< ' ') or '\x7f')
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Reads the <c>resource_metadata</c> parameter out of a
    /// <c>WWW-Authenticate</c> header value, or <see langword="null"/> when
    /// the parameter is absent or malformed. Scheme-agnostic: the parameter
    /// is found wherever it appears in the challenge's auth-params (§5.1
    /// allows any scheme and additional parameters).
    /// </summary>
    /// <param name="headerValue">The <c>WWW-Authenticate</c> header value.</param>
    public static string? TryReadResourceMetadata(string headerValue)
    {
        ArgumentNullException.ThrowIfNull(headerValue);

        int position = 0;
        while(position < headerValue.Length)
        {
            int nameStart = headerValue.IndexOf(
                ResourceMetadataParameter, position, StringComparison.OrdinalIgnoreCase);
            if(nameStart < 0)
            {
                return null;
            }

            int afterName = nameStart + ResourceMetadataParameter.Length;

            //The match must be a whole auth-param name: preceded by a
            //delimiter (start, space, comma) and followed by '=' modulo
            //optional whitespace (RFC 9110 §11.2 BWS).
            bool boundedBefore = nameStart == 0
                || headerValue[nameStart - 1] == ' '
                || headerValue[nameStart - 1] == ','
                || headerValue[nameStart - 1] == '\t';
            int equalsIndex = SkipWhitespace(headerValue, afterName);
            if(!boundedBefore || equalsIndex >= headerValue.Length || headerValue[equalsIndex] != '=')
            {
                position = afterName;
                continue;
            }

            int valueStart = SkipWhitespace(headerValue, equalsIndex + 1);
            if(valueStart >= headerValue.Length)
            {
                return null;
            }

            return headerValue[valueStart] == '"'
                ? ReadQuotedString(headerValue, valueStart)
                : ReadToken(headerValue, valueStart);
        }

        return null;
    }


    private static int SkipWhitespace(string value, int position)
    {
        while(position < value.Length && (value[position] == ' ' || value[position] == '\t'))
        {
            position++;
        }

        return position;
    }


    private static string? ReadQuotedString(string value, int openingQuote)
    {
        StringBuilder sb = new();
        for(int i = openingQuote + 1; i < value.Length; ++i)
        {
            char c = value[i];
            if(c == '\\' && i + 1 < value.Length)
            {
                sb.Append(value[i + 1]);
                ++i;
                continue;
            }

            if(c == '"')
            {
                return sb.ToString();
            }

            sb.Append(c);
        }

        //Unterminated quoted string — malformed challenge.
        return null;
    }


    private static string ReadToken(string value, int start)
    {
        int end = start;
        while(end < value.Length && value[end] != ',' && value[end] != ' ' && value[end] != '\t')
        {
            end++;
        }

        return value[start..end];
    }
}
