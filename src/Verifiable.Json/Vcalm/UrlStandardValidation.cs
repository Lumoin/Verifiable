using System.Globalization;

namespace Verifiable.Json;

/// <summary>
/// Decides whether a string is a valid absolute URL string under the
/// <see href="https://url.spec.whatwg.org/#url-writing">URL Standard §4.3 URL writing</see>, the [URL]
/// reference a W3C VCALM 1.0 verifiable presentation request names its issuer and list identifiers by: "A valid
/// URL string defines what input would not trigger a validation error or failure when parsed by the URL parser."
/// </summary>
/// <remarks>
/// <para>
/// The grammar is the standard's own: "An absolute-URL string must be one of the following: a URL-scheme string
/// that is an ASCII case-insensitive match for a special scheme and not an ASCII case-insensitive match for "file",
/// followed by U+003A (:) and a scheme-relative-special-URL string; a URL-scheme string that is not an ASCII
/// case-insensitive match for a special scheme, followed by U+003A (:) and one of: a scheme-relative-URL string, a
/// path-absolute-non-authority-URL string, or an opaque-path-URL string; a URL-scheme string that is an ASCII
/// case-insensitive match for "file", followed by U+003A (:) and a scheme-relative-file-URL string; any optionally
/// followed by U+003F (?) and a URL-query string", optionally followed by "U+0023 (#) and a URL-fragment string".
/// A DID such as <c>did:web:issuer.example</c> is an opaque-path URL under this grammar.
/// </para>
/// <para>
/// A host of a special URL is a valid host string: "a valid domain string, a valid IPv4-address string, or: U+005B
/// ([), followed by a valid IPv6-address string, followed by U+005D (])". A domain is valid when the UTS #46
/// ToASCII the standard's domain parser runs with <c>beStrict</c> set succeeds (here
/// <see cref="IdnMapping"/> with <see cref="IdnMapping.UseStd3AsciiRules"/> set, the platform's UTS #46
/// implementation) and it does not end in a number, so <c>https://test.42/</c> is refused. Leading or trailing
/// white space, an ASCII tab or newline, user information, a malformed percent-encoding and a port above 65535
/// are each a validation error or failure under the standard and are refused.
/// </para>
/// <para>
/// This decides syntax only. Whether any such URL may be dereferenced, and over which schemes and hosts, is the
/// outbound-fetch policy of whoever retrieves it.
/// </para>
/// </remarks>
internal static class UrlStandardValidation
{
    /// <summary>The largest decimal value a URL-port string may represent: "a 16-bit unsigned integer".</summary>
    private const int MaximumPort = ushort.MaxValue;

    /// <summary>The largest value a component of a valid IPv4-address string may represent: "in the range 0 to 255".</summary>
    private const int MaximumIPv4Component = byte.MaxValue;

    /// <summary>The number of components a valid IPv4-address string has: "four shortest possible strings of ASCII digits".</summary>
    private const int IPv4ComponentCount = 4;

    /// <summary>The effective piece length a valid IPv6-address string without compression has: "effective piece length 8".</summary>
    private const int IPv6PieceCount = 8;

    /// <summary>The largest number of ASCII hex digits in a shortest possible IPv6 piece of at most 0xFFFF.</summary>
    private const int MaximumIPv6PieceLength = 4;

    /// <summary>The effective piece length an IPv4 address contributes inside an IPv6 address: "plus 2".</summary>
    private const int IPv4EffectivePieceLength = 2;


    /// <summary>
    /// Whether <paramref name="value"/> is a valid absolute URL string, with an optional query and fragment.
    /// </summary>
    /// <param name="value">The candidate text.</param>
    /// <returns><see langword="true"/> when the text is a valid absolute-URL-with-fragment string.</returns>
    public static bool IsValidAbsoluteUrl(string? value)
    {
        if(string.IsNullOrEmpty(value) || !char.IsAsciiLetter(value[0]))
        {
            return false;
        }

        //"A URL-scheme string must be one ASCII alpha, followed by zero or more of ASCII alphanumeric, U+002B (+),
        //U+002D (-), and U+002E (.)."
        int schemeEnd = 1;
        while(schemeEnd < value.Length && IsSchemeCodePoint(value[schemeEnd]))
        {
            ++schemeEnd;
        }

        if(schemeEnd == value.Length || value[schemeEnd] != ':')
        {
            return false;
        }

        ReadOnlySpan<char> scheme = value.AsSpan(0, schemeEnd);
        ReadOnlySpan<char> remainder = value.AsSpan(schemeEnd + 1);

        int fragmentStart = remainder.IndexOf('#');
        if(fragmentStart >= 0)
        {
            if(!AreUrlUnits(remainder[(fragmentStart + 1)..]))
            {
                return false;
            }

            remainder = remainder[..fragmentStart];
        }

        int queryStart = remainder.IndexOf('?');
        if(queryStart >= 0)
        {
            if(!AreUrlUnits(remainder[(queryStart + 1)..]))
            {
                return false;
            }

            remainder = remainder[..queryStart];
        }

        bool isFileScheme = scheme.Equals("file", StringComparison.OrdinalIgnoreCase);

        return (IsSpecialScheme(scheme), isFileScheme) switch
        {
            (true, false) => IsSchemeRelativeSpecialUrl(remainder),
            (true, true) => IsSchemeRelativeFileUrl(remainder),
            _ => IsSchemeRelativeUrl(remainder) || IsPathAbsoluteNonAuthorityUrl(remainder) || IsOpaquePathUrl(remainder)
        };
    }


    /// <summary>Whether <paramref name="character"/> may follow the first letter of a URL-scheme string.</summary>
    /// <param name="character">The character.</param>
    /// <returns><see langword="true"/> for an ASCII alphanumeric, <c>+</c>, <c>-</c> or <c>.</c>.</returns>
    private static bool IsSchemeCodePoint(char character) =>
        char.IsAsciiLetterOrDigit(character) || character is '+' or '-' or '.';


    /// <summary>
    /// Whether <paramref name="scheme"/> is one of the URL Standard's special schemes: <c>ftp</c>, <c>file</c>,
    /// <c>http</c>, <c>https</c>, <c>ws</c> and <c>wss</c>, compared ASCII case-insensitively.
    /// </summary>
    /// <param name="scheme">The scheme.</param>
    /// <returns><see langword="true"/> for a special scheme.</returns>
    private static bool IsSpecialScheme(ReadOnlySpan<char> scheme) =>
        scheme.Equals("ftp", StringComparison.OrdinalIgnoreCase)
        || scheme.Equals("file", StringComparison.OrdinalIgnoreCase)
        || scheme.Equals("http", StringComparison.OrdinalIgnoreCase)
        || scheme.Equals("https", StringComparison.OrdinalIgnoreCase)
        || scheme.Equals("ws", StringComparison.OrdinalIgnoreCase)
        || scheme.Equals("wss", StringComparison.OrdinalIgnoreCase);


    /// <summary>
    /// "A scheme-relative-special-URL string must be "//", followed by a valid host string, optionally followed by
    /// U+003A (:) and a URL-port string, optionally followed by a path-absolute-URL string."
    /// </summary>
    /// <param name="text">The text after the scheme's colon, without query or fragment.</param>
    /// <returns><see langword="true"/> when the text has that shape.</returns>
    private static bool IsSchemeRelativeSpecialUrl(ReadOnlySpan<char> text)
    {
        if(!text.StartsWith("//", StringComparison.Ordinal))
        {
            return false;
        }

        ReadOnlySpan<char> afterSlashes = text[2..];
        int authorityLength = AuthorityLength(afterSlashes);
        ReadOnlySpan<char> path = afterSlashes[authorityLength..];

        return IsHostAndPort(afterSlashes[..authorityLength], isOpaque: false) && (path.IsEmpty || IsPathAbsoluteUrl(path));
    }


    /// <summary>
    /// "A scheme-relative-file-URL string must be "//", optionally followed by one of the following: a valid host
    /// string, optionally followed by a path-absolute-URL string; a path-absolute-URL string."
    /// </summary>
    /// <param name="text">The text after the scheme's colon, without query or fragment.</param>
    /// <returns><see langword="true"/> when the text has that shape.</returns>
    private static bool IsSchemeRelativeFileUrl(ReadOnlySpan<char> text)
    {
        if(!text.StartsWith("//", StringComparison.Ordinal))
        {
            return false;
        }

        ReadOnlySpan<char> afterSlashes = text[2..];
        if(afterSlashes.IsEmpty)
        {
            return true;
        }

        if(afterSlashes[0] == '/')
        {
            return IsPathAbsoluteUrl(afterSlashes);
        }

        int hostLength = AuthorityLength(afterSlashes);
        ReadOnlySpan<char> path = afterSlashes[hostLength..];

        return IsValidHost(afterSlashes[..hostLength]) && (path.IsEmpty || IsPathAbsoluteUrl(path));
    }


    /// <summary>
    /// "A scheme-relative-URL string must be "//", followed by an opaque-host-and-port string, optionally followed
    /// by a path-absolute-URL string."
    /// </summary>
    /// <param name="text">The text after the scheme's colon, without query or fragment.</param>
    /// <returns><see langword="true"/> when the text has that shape.</returns>
    private static bool IsSchemeRelativeUrl(ReadOnlySpan<char> text)
    {
        if(!text.StartsWith("//", StringComparison.Ordinal))
        {
            return false;
        }

        ReadOnlySpan<char> afterSlashes = text[2..];
        int authorityLength = AuthorityLength(afterSlashes);
        ReadOnlySpan<char> path = afterSlashes[authorityLength..];

        return IsHostAndPort(afterSlashes[..authorityLength], isOpaque: true) && (path.IsEmpty || IsPathAbsoluteUrl(path));
    }


    /// <summary>
    /// "A path-absolute-non-authority-URL string must be a path-absolute-URL string that does not start with two
    /// U+002F (/) code points."
    /// </summary>
    /// <param name="text">The text after the scheme's colon, without query or fragment.</param>
    /// <returns><see langword="true"/> when the text has that shape.</returns>
    private static bool IsPathAbsoluteNonAuthorityUrl(ReadOnlySpan<char> text) =>
        !text.StartsWith("//", StringComparison.Ordinal) && IsPathAbsoluteUrl(text);


    /// <summary>
    /// "An opaque-path-URL string must be zero or more URL units excluding U+003F (?), the first of which (if any)
    /// is not U+002F (/)."
    /// </summary>
    /// <param name="text">The text after the scheme's colon, without query or fragment.</param>
    /// <returns><see langword="true"/> when the text has that shape.</returns>
    private static bool IsOpaquePathUrl(ReadOnlySpan<char> text) =>
        (text.IsEmpty || text[0] != '/') && AreUrlUnits(text);


    /// <summary>
    /// "A path-absolute-URL string must be U+002F (/), followed by zero or more URL-path-segment strings, separated
    /// from each other by U+002F (/)", each segment being URL units other than <c>/</c> and <c>?</c>. The query is
    /// split off before this runs, and <c>/</c> is itself a URL code point, so the whole path is checked as URL
    /// units.
    /// </summary>
    /// <param name="path">The path, starting at its first <c>/</c>.</param>
    /// <returns><see langword="true"/> when the path has that shape.</returns>
    private static bool IsPathAbsoluteUrl(ReadOnlySpan<char> path) =>
        !path.IsEmpty && path[0] == '/' && AreUrlUnits(path);


    /// <summary>
    /// The length of the authority at the start of the text after <c>//</c>: everything up to the next
    /// <c>/</c>, where the path starts, or the whole text when there is no path.
    /// </summary>
    /// <param name="text">The text after <c>//</c>.</param>
    /// <returns>The authority's length; the path, if any, starts there.</returns>
    private static int AuthorityLength(ReadOnlySpan<char> text)
    {
        int pathStart = text.IndexOf('/');

        return pathStart < 0 ? text.Length : pathStart;
    }


    /// <summary>
    /// Whether <paramref name="authority"/> is a host optionally followed by <c>:</c> and a URL-port string: a valid
    /// host string for a special URL, or an opaque-host-and-port string ("either the empty string or: a valid
    /// opaque-host string, optionally followed by U+003A (:) and a URL-port string") otherwise. There is no way to
    /// carry user information in a valid URL string, so an <c>@</c> never passes.
    /// </summary>
    /// <param name="authority">The text between <c>//</c> and the path.</param>
    /// <param name="isOpaque">Whether the host is an opaque host of a non-special URL.</param>
    /// <returns><see langword="true"/> when the authority has that shape.</returns>
    private static bool IsHostAndPort(ReadOnlySpan<char> authority, bool isOpaque)
    {
        if(isOpaque && authority.IsEmpty)
        {
            return true;
        }

        ReadOnlySpan<char> host;
        ReadOnlySpan<char> portPart;
        if(!authority.IsEmpty && authority[0] == '[')
        {
            int close = authority.IndexOf(']');
            if(close < 0)
            {
                return false;
            }

            host = authority[..(close + 1)];
            portPart = authority[(close + 1)..];
        }
        else
        {
            int colon = authority.IndexOf(':');
            host = colon < 0 ? authority : authority[..colon];
            portPart = colon < 0 ? ReadOnlySpan<char>.Empty : authority[colon..];
        }

        if(!portPart.IsEmpty && (portPart[0] != ':' || !IsUrlPort(portPart[1..])))
        {
            return false;
        }

        return isOpaque ? IsValidOpaqueHost(host) : IsValidHost(host);
    }


    /// <summary>
    /// "A URL-port string must be one of the following: the empty string; one or more ASCII digits representing a
    /// decimal number that is a 16-bit unsigned integer."
    /// </summary>
    /// <param name="port">The text after the host's <c>:</c>.</param>
    /// <returns><see langword="true"/> when the text is a URL-port string.</returns>
    private static bool IsUrlPort(ReadOnlySpan<char> port)
    {
        int value = 0;
        foreach(char character in port)
        {
            if(!char.IsAsciiDigit(character))
            {
                return false;
            }

            value = (value * 10) + (character - '0');
            if(value > MaximumPort)
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>
    /// "A valid host string must be a valid domain string, a valid IPv4-address string, or: U+005B ([), followed
    /// by a valid IPv6-address string, followed by U+005D (])."
    /// </summary>
    /// <param name="host">The host text.</param>
    /// <returns><see langword="true"/> when the text is a valid host string.</returns>
    private static bool IsValidHost(ReadOnlySpan<char> host)
    {
        if(host.IsEmpty)
        {
            return false;
        }

        if(host[0] == '[')
        {
            return host.Length >= 2 && host[^1] == ']' && IsValidIPv6(host[1..^1]);
        }

        return IsValidIPv4(host) || IsValidDomain(host);
    }


    /// <summary>
    /// "A valid opaque-host string must be one of the following: one or more URL units excluding forbidden host code
    /// points; U+005B ([), followed by a valid IPv6-address string, followed by U+005D (])."
    /// </summary>
    /// <param name="host">The host text, non-empty.</param>
    /// <returns><see langword="true"/> when the text is a valid opaque-host string.</returns>
    private static bool IsValidOpaqueHost(ReadOnlySpan<char> host)
    {
        if(host.IsEmpty)
        {
            return false;
        }

        if(host[0] == '[')
        {
            return host.Length >= 2 && host[^1] == ']' && IsValidIPv6(host[1..^1]);
        }

        foreach(char character in host)
        {
            if(IsForbiddenHostCodePoint(character))
            {
                return false;
            }
        }

        return AreUrlUnits(host);
    }


    /// <summary>
    /// "A forbidden host code point is U+0000 NULL, U+0009 TAB, U+000A LF, U+000D CR, U+0020 SPACE, U+0023 (#),
    /// U+002F (/), U+003A (:), U+003C (&lt;), U+003E (&gt;), U+003F (?), U+0040 (@), U+005B ([), U+005C (\),
    /// U+005D (]), U+005E (^), or U+007C (|)."
    /// </summary>
    /// <param name="character">The character.</param>
    /// <returns><see langword="true"/> for a forbidden host code point.</returns>
    private static bool IsForbiddenHostCodePoint(char character) => character is
        '\0' or '\t' or '\n' or '\r' or ' ' or '#' or '/' or ':' or '<' or '>' or '?' or '@' or '[' or '\\' or ']' or '^' or '|';


    /// <summary>
    /// "A string input is a valid domain if these steps return true: Let domain be the result of running domain
    /// parser with input and true. If domain is failure, then return false. If running the ends in a number checker
    /// on domain returns true, then return false. Return true." The domain parser with <c>beStrict</c> runs UTS #46
    /// ToASCII with STD3 ASCII rules; <see cref="IdnMapping"/> with <see cref="IdnMapping.UseStd3AsciiRules"/> set
    /// is the platform's implementation of it, and it throws <see cref="ArgumentException"/> on failure.
    /// </summary>
    /// <param name="host">The host text.</param>
    /// <returns><see langword="true"/> when the text is a valid domain.</returns>
    private static bool IsValidDomain(ReadOnlySpan<char> host)
    {
        IdnMapping mapping = new() { UseStd3AsciiRules = true, AllowUnassigned = false };
        string asciiDomain;
        try
        {
            asciiDomain = mapping.GetAscii(host.ToString());
        }
        catch(ArgumentException)
        {
            return false;
        }

        return asciiDomain.Length > 0 && !EndsInANumber(asciiDomain);
    }


    /// <summary>
    /// The URL Standard's ends in a number checker: "Let parts be the result of strictly splitting input on U+002E
    /// (.). If the last item in parts is the empty string, then remove the last item from parts. Let last be the
    /// last item in parts. If last is not the empty string and contains only ASCII digits, then return true. If
    /// parsing last as an IPv4 number does not return failure, then return true", the latter being "equivalent to
    /// checking that last is "0X" or "0x", followed by zero or more ASCII hex digits".
    /// </summary>
    /// <param name="asciiDomain">The ASCII domain.</param>
    /// <returns><see langword="true"/> when the domain ends in a number.</returns>
    private static bool EndsInANumber(ReadOnlySpan<char> asciiDomain)
    {
        ReadOnlySpan<char> parts = asciiDomain.EndsWith('.') ? asciiDomain[..^1] : asciiDomain;
        ReadOnlySpan<char> last = parts[(parts.LastIndexOf('.') + 1)..];

        if(!last.IsEmpty && !last.ContainsAnyExceptInRange('0', '9'))
        {
            return true;
        }

        return last.Length >= 2
            && last[0] == '0'
            && last[1] is 'x' or 'X'
            && IsAllAsciiHexDigits(last[2..]);
    }


    /// <summary>
    /// "A valid IPv4-address string must be four shortest possible strings of ASCII digits, representing a decimal
    /// number in the range 0 to 255, inclusive, separated from each other by U+002E (.)."
    /// </summary>
    /// <param name="address">The candidate address text.</param>
    /// <returns><see langword="true"/> when the text is a valid IPv4-address string.</returns>
    private static bool IsValidIPv4(ReadOnlySpan<char> address)
    {
        int componentCount = 0;
        while(true)
        {
            int dot = address.IndexOf('.');
            ReadOnlySpan<char> component = dot < 0 ? address : address[..dot];
            if(!IsShortestDecimalAtMost(component, MaximumIPv4Component))
            {
                return false;
            }

            ++componentCount;
            if(dot < 0)
            {
                return componentCount == IPv4ComponentCount;
            }

            if(componentCount == IPv4ComponentCount)
            {
                return false;
            }

            address = address[(dot + 1)..];
        }
    }


    /// <summary>
    /// Whether <paramref name="digits"/> is the shortest possible ASCII decimal representation of a number no larger
    /// than <paramref name="maximum"/>: non-empty, digits only, and no leading zero unless it is <c>0</c> itself.
    /// </summary>
    /// <param name="digits">The candidate digits.</param>
    /// <param name="maximum">The largest value allowed.</param>
    /// <returns><see langword="true"/> when the digits have that shape.</returns>
    private static bool IsShortestDecimalAtMost(ReadOnlySpan<char> digits, int maximum)
    {
        if(digits.IsEmpty || (digits.Length > 1 && digits[0] == '0'))
        {
            return false;
        }

        int value = 0;
        foreach(char character in digits)
        {
            if(!char.IsAsciiDigit(character))
            {
                return false;
            }

            value = (value * 10) + (character - '0');
            if(value > maximum)
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>
    /// "A valid IPv6-address string must be one of the following: a valid IPv6-pieces string with effective piece
    /// length 8; a valid IPv6-pieces-and-IPv4 string with effective piece length 8; U+003A U+003A (::), optionally
    /// preceded by a valid IPv6-pieces string, and optionally followed by either a valid IPv6-pieces string or a
    /// valid IPv6-pieces-and-IPv4 string, such that the sum of the effective piece lengths of the preceding and
    /// following strings is at most 7."
    /// </summary>
    /// <param name="address">The text between the brackets.</param>
    /// <returns><see langword="true"/> when the text is a valid IPv6-address string.</returns>
    private static bool IsValidIPv6(ReadOnlySpan<char> address)
    {
        int compression = address.IndexOf("::", StringComparison.Ordinal);
        if(compression < 0)
        {
            return CountIPv6Pieces(address, isIPv4Allowed: true) == IPv6PieceCount;
        }

        ReadOnlySpan<char> before = address[..compression];
        ReadOnlySpan<char> after = address[(compression + 2)..];
        int beforeCount = before.IsEmpty ? 0 : CountIPv6Pieces(before, isIPv4Allowed: false);
        int afterCount = after.IsEmpty ? 0 : CountIPv6Pieces(after, isIPv4Allowed: true);

        return beforeCount >= 0 && afterCount >= 0 && beforeCount + afterCount <= IPv6PieceCount - 1;
    }


    /// <summary>
    /// The effective piece length of a valid IPv6-pieces string ("one or more valid IPv6-piece strings, separated
    /// from each other by U+003A (:)") or, when <paramref name="isIPv4Allowed"/>, of a valid IPv6-pieces-and-IPv4
    /// string, whose trailing IPv4 address counts as two pieces.
    /// </summary>
    /// <param name="pieces">The candidate pieces.</param>
    /// <param name="isIPv4Allowed">Whether a trailing IPv4 address may stand for the last two pieces.</param>
    /// <returns>The effective piece length, or -1 when the text has neither shape.</returns>
    private static int CountIPv6Pieces(ReadOnlySpan<char> pieces, bool isIPv4Allowed)
    {
        int count = 0;
        while(true)
        {
            int colon = pieces.IndexOf(':');
            ReadOnlySpan<char> piece = colon < 0 ? pieces : pieces[..colon];
            if(colon < 0 && isIPv4Allowed && piece.Contains('.'))
            {
                return IsValidIPv4(piece) ? count + IPv4EffectivePieceLength : -1;
            }

            if(!IsValidIPv6Piece(piece))
            {
                return -1;
            }

            ++count;
            if(colon < 0)
            {
                return count;
            }

            pieces = pieces[(colon + 1)..];
        }
    }


    /// <summary>
    /// "A valid IPv6-piece string is a shortest possible string of ASCII hex digits, representing a hexadecimal
    /// number in the range 0 to 0xFFFF, inclusive."
    /// </summary>
    /// <param name="piece">The candidate piece.</param>
    /// <returns><see langword="true"/> when the text is a valid IPv6-piece string.</returns>
    private static bool IsValidIPv6Piece(ReadOnlySpan<char> piece) =>
        piece.Length is >= 1 and <= MaximumIPv6PieceLength
        && (piece.Length == 1 || piece[0] != '0')
        && IsAllAsciiHexDigits(piece);


    /// <summary>Whether every character of <paramref name="text"/> is an ASCII hex digit; <see langword="true"/> for empty text.</summary>
    /// <param name="text">The text.</param>
    /// <returns><see langword="true"/> when the text holds ASCII hex digits only.</returns>
    private static bool IsAllAsciiHexDigits(ReadOnlySpan<char> text)
    {
        foreach(char character in text)
        {
            if(!char.IsAsciiHexDigit(character))
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>
    /// Whether <paramref name="text"/> is zero or more URL units: "The URL units are URL code points and
    /// percent-encoded bytes." The URL code points are "ASCII alphanumeric, U+0021 (!), U+0024 ($), U+0026 (&amp;),
    /// U+0027 ('), U+0028 LEFT PARENTHESIS, U+0029 RIGHT PARENTHESIS, U+002A (*), U+002B (+), U+002C (,), U+002D
    /// (-), U+002E (.), U+002F (/), U+003A (:), U+003B (;), U+003D (=), U+003F (?), U+0040 (@), U+005F (_), U+007E
    /// (~), and code points in the range U+00A0 to U+10FFFD, inclusive, excluding surrogates and noncharacters"; a
    /// percent-encoded byte is <c>%</c> followed by two ASCII hex digits. The range's lower bound U+00A0 is what
    /// refuses the C1 control code points U+0080 to U+009F: they are neither listed ASCII code points nor inside
    /// "the range U+00A0 to U+10FFFD, inclusive", so a character above the ASCII range is a URL code point only
    /// from U+00A0 upwards, and a surrogate only as half of a well-formed pair whose scalar is no noncharacter.
    /// </summary>
    /// <param name="text">The text.</param>
    /// <returns><see langword="true"/> when the text is URL units only.</returns>
    private static bool AreUrlUnits(ReadOnlySpan<char> text)
    {
        for(int index = 0; index < text.Length; ++index)
        {
            char character = text[index];
            if(character == '%')
            {
                if(index + 2 >= text.Length || !char.IsAsciiHexDigit(text[index + 1]) || !char.IsAsciiHexDigit(text[index + 2]))
                {
                    return false;
                }

                index += 2;

                continue;
            }

            if(character < '\u0080')
            {
                if(!IsAsciiUrlCodePoint(character))
                {
                    return false;
                }

                continue;
            }

            if(character < '\u00A0' || char.IsLowSurrogate(character))
            {
                return false;
            }

            int scalar = character;
            if(char.IsHighSurrogate(character))
            {
                if(index + 1 >= text.Length || !char.IsLowSurrogate(text[index + 1]))
                {
                    return false;
                }

                scalar = char.ConvertToUtf32(character, text[index + 1]);
                ++index;
            }

            if(IsNoncharacter(scalar))
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>Whether an ASCII <paramref name="character"/> is a URL code point.</summary>
    /// <param name="character">The ASCII character.</param>
    /// <returns><see langword="true"/> for an ASCII URL code point.</returns>
    private static bool IsAsciiUrlCodePoint(char character) =>
        char.IsAsciiLetterOrDigit(character)
        || character is '!' or '$' or '&' or '\'' or '(' or ')' or '*' or '+' or ',' or '-' or '.' or '/' or ':' or ';'
            or '=' or '?' or '@' or '_' or '~';


    /// <summary>
    /// Whether <paramref name="scalar"/> is a noncharacter: U+FDD0 to U+FDEF, or a code point whose low sixteen bits
    /// are 0xFFFE or 0xFFFF.
    /// </summary>
    /// <param name="scalar">The scalar value.</param>
    /// <returns><see langword="true"/> for a noncharacter.</returns>
    private static bool IsNoncharacter(int scalar) =>
        scalar is >= 0xFDD0 and <= 0xFDEF || (scalar & 0xFFFE) == 0xFFFE;
}
