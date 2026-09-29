using System.Text;

namespace Verifiable.OAuth;

/// <summary>
/// Checks a <c>resource</c> indicator against the ASCII
/// <see href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A"><c>absolute-URI</c></see>
/// grammar (<c>scheme ":" hier-part [ "?" query ]</c>, no fragment) in its original spelling,
/// folds an accepted indicator's case-insensitive parts to lowercase, and derives the comparison
/// key a stored grant is matched by. Every rule is read from RFC 3986 Appendix A and, for
/// <c>http</c>/<c>https</c>, RFC 9110 section 4.2.1/section 4.2.2/section 4.2.4; RFC 8707 section 2 forbids a fragment component.
/// <see cref="System.Uri"/> is never consulted for an indicator's validity or spelling: it accepts
/// a non-ASCII host and path, lowers the ASCII scheme and host, maps U+212A to <c>k</c> in
/// <c>Host</c>, drops a default port and decodes <c>%41</c> in userinfo, none of which this class
/// reproduces. The forbidden case-folding members are also never used: <c>string.ToLower</c>,
/// <c>ToUpper</c> and their culture overloads map an ASCII <c>I</c> to U+0131 under the Turkish
/// culture; <c>ToLowerInvariant</c> maps U+212A (Kelvin sign) to <c>k</c>; <c>ToUpperInvariant</c>
/// maps U+017F (long s) to <c>S</c>; <see cref="System.StringComparison.OrdinalIgnoreCase"/> and
/// <see cref="System.StringComparison.InvariantCultureIgnoreCase"/> fold non-ASCII letters together
/// (U+00E9 with U+00C9, and U+212A with <c>k</c>).
/// </summary>
internal static class ResourceIndicatorSyntax
{
    /// <summary>
    /// The character classes this reader validates a run of characters against, each the
    /// admissible-character set of one <c>absolute-URI</c> component
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">RFC 3986 Appendix A</see>).
    /// </summary>
    private enum CharacterClass
    {
        /// <summary><c>userinfo = *( unreserved / pct-encoded / sub-delims / ":" )</c>.</summary>
        Userinfo,

        /// <summary><c>reg-name = *( unreserved / pct-encoded / sub-delims )</c>.</summary>
        RegName,

        /// <summary>
        /// A path's <c>pchar</c> alphabet plus the <c>"/"</c> that separates its segments
        /// (<c>path-abempty</c>, <c>path-absolute</c> and <c>path-rootless</c> each interleave
        /// <c>segment</c>s with a literal <c>/</c>).
        /// </summary>
        Path,

        /// <summary><c>query = *( pchar / "/" / "?" )</c>.</summary>
        Query,
    }

    /// <summary>
    /// Names the first part of <paramref name="indicator"/> that fails the
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A"><c>absolute-URI</c></see>
    /// grammar, or <see cref="ResourceIndicatorFault.None"/> when every part admits it. An
    /// <c>http</c> or <c>https</c> indicator whose authority carries a <c>userinfo</c> is
    /// <see cref="ResourceIndicatorFault.HttpUserInfo"/>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-4.2.4">RFC 9110 section 4.2.4</see>:
    /// "a recipient SHOULD parse for userinfo and treat its presence as an error"); every other
    /// scheme keeps <c>userinfo</c> as RFC 3986 Appendix A's <c>authority</c> production admits it,
    /// the deprecated <c>user:password</c> form included: a deviation from
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-3.2.1">RFC 3986 section 3.2.1</see>'s
    /// "should reject the storage of such data in unencrypted form", because the generic grammar
    /// admits it and no rule of RFC 8707 forbids it, with the look-alike hazard of
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-7.6">section 7.6</see> (a
    /// <c>userinfo</c> that appears to identify one naming authority while another is hidden behind
    /// it) left to the application's policy.
    /// The scheme is <c>ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3986#section-3.1">RFC 3986 section 3.1</see>:
    /// "Scheme names consist of a sequence of characters beginning with a letter and followed by any
    /// combination of letters, digits, plus (&quot;+&quot;), period (&quot;.&quot;), or hyphen
    /// (&quot;-&quot;)."), so a value that begins with <c>:</c>, or has no <c>:</c> after a
    /// well-formed scheme, is <see cref="ResourceIndicatorFault.Scheme"/>.
    /// Reads the original spelling in one left-to-right pass, allocates nothing, and never throws.
    /// </summary>
    /// <param name="indicator">The indicator's original spelling.</param>
    /// <returns>The fault of the first part that fails, or <see cref="ResourceIndicatorFault.None"/>.</returns>
    internal static ResourceIndicatorFault Check(ReadOnlySpan<char> indicator)
    {
        return Check(indicator, out _, out _, out _, out _);
    }

    /// <summary>
    /// <see langword="true"/> when <see cref="Check(ReadOnlySpan{char})"/> answers
    /// <see cref="ResourceIndicatorFault.None"/> for <paramref name="indicator"/>.
    /// </summary>
    /// <param name="indicator">The indicator's original spelling.</param>
    /// <returns><see langword="true"/> when <paramref name="indicator"/> is an accepted <c>absolute-URI</c>.</returns>
    internal static bool IsAbsoluteResourceIndicator(ReadOnlySpan<char> indicator)
    {
        return Check(indicator) == ResourceIndicatorFault.None;
    }

    /// <summary>
    /// Lowers <paramref name="indicator"/>'s scheme letters
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3986#section-3.1">RFC 3986 section 3.1</see>) and,
    /// when it has an authority, its host letters outside percent triplets
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3986#section-3.2.2">section 3.2.2</see>,
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-6.2.2.1">section 6.2.2.1</see>), leaving
    /// userinfo, port, path and query as sent: the <c>userinfo</c> of a scheme other than <c>http</c>
    /// and <c>https</c>, the deprecated <c>user:password</c> form included, is accepted by
    /// <see cref="Check(ReadOnlySpan{char})"/> and kept as sent
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3986#section-3.2.1">RFC 3986 section 3.2.1</see>).
    /// An indicator <see cref="Check(ReadOnlySpan{char})"/> refuses, an <c>http</c> or <c>https</c> indicator
    /// carrying a <c>userinfo</c> included
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-4.2.4">RFC 9110 section 4.2.4</see>),
    /// is returned unchanged: the method is total, so a caller folds only what it accepts or compares.
    /// </summary>
    /// <param name="indicator">The indicator to fold.</param>
    /// <returns>The folded indicator, or <paramref name="indicator"/> itself when refused.</returns>
    internal static string Fold(string indicator)
    {
        ArgumentNullException.ThrowIfNull(indicator);

        ResourceIndicatorFault fault = Check(indicator, out int schemeEnd, out bool hasAuthority, out int hostStart, out int hostEnd);

        if(fault != ResourceIndicatorFault.None)
        {
            return indicator;
        }

        return string.Create(indicator.Length, (indicator, schemeEnd, hasAuthority, hostStart, hostEnd), static (destination, state) =>
        {
            ReadOnlySpan<char> source = state.indicator;
            source.CopyTo(destination);

            _ = Ascii.ToLower(source[..state.schemeEnd], destination[..state.schemeEnd], out _);

            if(state.hasAuthority)
            {
                LowerHostOutsideTriplets(source, destination, state.hostStart, state.hostEnd);
            }
        });
    }

    /// <summary>
    /// The key a stored grant's <c>resource</c> value is matched by
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3986#section-6.2.1">RFC 3986 section 6.2.1</see>):
    /// <see cref="Fold(string)"/> when <paramref name="value"/> is an accepted indicator,
    /// <paramref name="value"/> itself otherwise, so a value the grammar refuses (an IRI, or any
    /// other value outside the ASCII grammar) compares by simple string identity.
    /// </summary>
    /// <param name="value">The stored or requested indicator.</param>
    /// <returns>The comparison key for <paramref name="value"/>.</returns>
    internal static string ComparisonKey(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        return IsAbsoluteResourceIndicator(value) ? Fold(value) : value;
    }

    /// <summary>
    /// The shared implementation of <see cref="Check(ReadOnlySpan{char})"/>, additionally
    /// reporting the scheme and host ranges <see cref="Fold(string)"/> needs so the two methods
    /// never parse the indicator twice. <paramref name="schemeEnd"/> is the exclusive end of the
    /// scheme; <paramref name="hasAuthority"/> is whether <c>"//"</c> followed the scheme's
    /// <c>:</c>; <paramref name="hostStart"/>/<paramref name="hostEnd"/> bound the host (including
    /// its brackets for an IP-literal) when <paramref name="hasAuthority"/> is <see langword="true"/>.
    /// </summary>
    /// <param name="indicator">The indicator's original spelling.</param>
    /// <param name="schemeEnd">The exclusive end of the scheme, valid only when the result is <see cref="ResourceIndicatorFault.None"/>.</param>
    /// <param name="hasAuthority">Whether an authority followed the scheme, valid only when the result is <see cref="ResourceIndicatorFault.None"/>.</param>
    /// <param name="hostStart">The inclusive start of the host, valid only when <paramref name="hasAuthority"/> is <see langword="true"/> and the result is <see cref="ResourceIndicatorFault.None"/>.</param>
    /// <param name="hostEnd">The exclusive end of the host, valid only when <paramref name="hasAuthority"/> is <see langword="true"/> and the result is <see cref="ResourceIndicatorFault.None"/>.</param>
    /// <returns>The fault of the first part that fails, or <see cref="ResourceIndicatorFault.None"/>.</returns>
    private static ResourceIndicatorFault Check(ReadOnlySpan<char> indicator, out int schemeEnd, out bool hasAuthority, out int hostStart, out int hostEnd)
    {
        schemeEnd = 0;
        hasAuthority = false;
        hostStart = 0;
        hostEnd = 0;

        if(indicator.IsEmpty)
        {
            return ResourceIndicatorFault.Empty;
        }

        if(!Ascii.IsValid(indicator))
        {
            return ResourceIndicatorFault.NonAscii;
        }

        int length = indicator.Length;

        int colonIndex = -1;

        for(int i = 0; i < length; i++)
        {
            char c = indicator[i];

            if(c == '#')
            {
                return ResourceIndicatorFault.Fragment;
            }

            if(c == ':')
            {
                if(i == 0)
                {
                    //A scheme begins with an ALPHA, so a colon at index 0 ends an empty scheme.
                    return ResourceIndicatorFault.Scheme;
                }

                colonIndex = i;

                break;
            }

            if(c == '%')
            {
                return HasWellFormedTriplet(indicator, i) ? ResourceIndicatorFault.Scheme : ResourceIndicatorFault.PercentEncoding;
            }

            bool isSchemeChar = i == 0
                ? char.IsAsciiLetter(c)
                : char.IsAsciiLetter(c) || char.IsAsciiDigit(c) || c is '+' or '-' or '.';

            if(!isSchemeChar)
            {
                return ResourceIndicatorFault.Scheme;
            }
        }

        if(colonIndex < 0)
        {
            return ResourceIndicatorFault.Scheme;
        }

        schemeEnd = colonIndex;

        ReadOnlySpan<char> scheme = indicator[..colonIndex];
        bool isHttpScheme = Ascii.EqualsIgnoreCase(scheme, "http") || Ascii.EqualsIgnoreCase(scheme, "https");

        int cursor = colonIndex + 1;
        bool isHostEmpty = true;

        if(cursor + 1 < length && indicator[cursor] == '/' && indicator[cursor + 1] == '/')
        {
            hasAuthority = true;

            int authorityStart = cursor + 2;
            int authorityEnd = authorityStart;

            while(authorityEnd < length && indicator[authorityEnd] is not ('/' or '?' or '#'))
            {
                authorityEnd++;
            }

            ResourceIndicatorFault authorityFault = CheckAuthority(indicator[authorityStart..authorityEnd], out isHostEmpty, out int relativeHostStart, out int relativeHostEnd);

            if(authorityFault != ResourceIndicatorFault.None)
            {
                return authorityFault;
            }

            if(isHttpScheme && indicator[authorityStart..authorityEnd].Contains('@'))
            {
                return ResourceIndicatorFault.HttpUserInfo;
            }

            hostStart = authorityStart + relativeHostStart;
            hostEnd = authorityStart + relativeHostEnd;
            cursor = authorityEnd;
        }

        int pathEnd = cursor;

        while(pathEnd < length && indicator[pathEnd] is not ('?' or '#'))
        {
            pathEnd++;
        }

        ResourceIndicatorFault pathFault = ValidateCharSet(indicator[cursor..pathEnd], CharacterClass.Path, ResourceIndicatorFault.Path);

        if(pathFault != ResourceIndicatorFault.None)
        {
            return pathFault;
        }

        cursor = pathEnd;

        if(cursor < length && indicator[cursor] == '?')
        {
            int queryStart = cursor + 1;
            int queryEnd = queryStart;

            while(queryEnd < length && indicator[queryEnd] != '#')
            {
                queryEnd++;
            }

            ResourceIndicatorFault queryFault = ValidateCharSet(indicator[queryStart..queryEnd], CharacterClass.Query, ResourceIndicatorFault.Query);

            if(queryFault != ResourceIndicatorFault.None)
            {
                return queryFault;
            }

            cursor = queryEnd;
        }

        if(cursor < length && indicator[cursor] == '#')
        {
            return ResourceIndicatorFault.Fragment;
        }

        if(isHttpScheme)
        {
            if(!hasAuthority)
            {
                return ResourceIndicatorFault.HttpAuthority;
            }

            if(isHostEmpty)
            {
                return ResourceIndicatorFault.HttpHost;
            }
        }

        return ResourceIndicatorFault.None;
    }

    /// <summary>
    /// Validates <c>authority = [ userinfo "@" ] host [ ":" port ]</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">RFC 3986 Appendix A</see>)
    /// over the substring between the authority's <c>"//"</c> and its terminator, reporting the
    /// host's range within that substring so the caller can translate it into the whole
    /// indicator's coordinates.
    /// </summary>
    /// <param name="authority">The authority substring, excluding the leading <c>"//"</c>.</param>
    /// <param name="isHostEmpty">Whether the host is zero-length.</param>
    /// <param name="hostStart">The inclusive start of the host within <paramref name="authority"/>.</param>
    /// <param name="hostEnd">The exclusive end of the host within <paramref name="authority"/>.</param>
    /// <returns><see cref="ResourceIndicatorFault.Authority"/>, <see cref="ResourceIndicatorFault.PercentEncoding"/>, or <see cref="ResourceIndicatorFault.None"/>.</returns>
    private static ResourceIndicatorFault CheckAuthority(ReadOnlySpan<char> authority, out bool isHostEmpty, out int hostStart, out int hostEnd)
    {
        isHostEmpty = true;
        hostStart = 0;
        hostEnd = 0;

        int atCount = 0;
        int lastAt = -1;

        for(int i = 0; i < authority.Length; i++)
        {
            if(authority[i] == '@')
            {
                atCount++;
                lastAt = i;
            }
        }

        if(atCount > 1)
        {
            return ResourceIndicatorFault.Authority;
        }

        ReadOnlySpan<char> userinfo = lastAt >= 0 ? authority[..lastAt] : ReadOnlySpan<char>.Empty;
        ReadOnlySpan<char> hostAndPort = lastAt >= 0 ? authority[(lastAt + 1)..] : authority;
        int hostAndPortOffset = lastAt >= 0 ? lastAt + 1 : 0;

        ResourceIndicatorFault userinfoFault = ValidateCharSet(userinfo, CharacterClass.Userinfo, ResourceIndicatorFault.Authority);

        if(userinfoFault != ResourceIndicatorFault.None)
        {
            return userinfoFault;
        }

        ReadOnlySpan<char> port;

        if(!hostAndPort.IsEmpty && hostAndPort[0] == '[')
        {
            int closeIndex = hostAndPort.IndexOf(']');

            if(closeIndex < 0)
            {
                return ResourceIndicatorFault.Authority;
            }

            ReadOnlySpan<char> ipLiteralContent = hostAndPort[1..closeIndex];
            bool isFuture = ipLiteralContent.Length > 0 && ipLiteralContent[0] is 'v' or 'V';
            bool isIpLiteralValid = isFuture ? IsIPvFuture(ipLiteralContent) : IsIPv6Address(ipLiteralContent);

            if(!isIpLiteralValid)
            {
                return ResourceIndicatorFault.Authority;
            }

            hostStart = hostAndPortOffset;
            hostEnd = hostAndPortOffset + closeIndex + 1;
            isHostEmpty = false;

            int afterClose = closeIndex + 1;

            if(afterClose == hostAndPort.Length)
            {
                port = ReadOnlySpan<char>.Empty;
            }
            else if(hostAndPort[afterClose] == ':')
            {
                port = hostAndPort[(afterClose + 1)..];
            }
            else
            {
                return ResourceIndicatorFault.Authority;
            }
        }
        else
        {
            int colonIndex = hostAndPort.IndexOf(':');
            ReadOnlySpan<char> host = colonIndex >= 0 ? hostAndPort[..colonIndex] : hostAndPort;
            port = colonIndex >= 0 ? hostAndPort[(colonIndex + 1)..] : ReadOnlySpan<char>.Empty;

            hostStart = hostAndPortOffset;
            hostEnd = hostAndPortOffset + host.Length;
            isHostEmpty = host.IsEmpty;

            if(!host.IsEmpty && !IsIPv4Address(host))
            {
                ResourceIndicatorFault hostFault = ValidateCharSet(host, CharacterClass.RegName, ResourceIndicatorFault.Authority);

                if(hostFault != ResourceIndicatorFault.None)
                {
                    return hostFault;
                }
            }
        }

        foreach(char c in port)
        {
            if(!char.IsAsciiDigit(c))
            {
                return ResourceIndicatorFault.Authority;
            }
        }

        return ResourceIndicatorFault.None;
    }

    /// <summary>
    /// Validates every character of <paramref name="value"/> against <paramref name="characterClass"/>'s
    /// admissible-character set, treating a <c>%</c> as the start of a
    /// <c>pct-encoded = "%" HEXDIG HEXDIG</c> triplet
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">RFC 3986 Appendix A</see>): a
    /// malformed triplet is <see cref="ResourceIndicatorFault.PercentEncoding"/> wherever it stands,
    /// a well-formed one is admitted only where <paramref name="characterClass"/> allows <c>pct-encoded</c>.
    /// </summary>
    /// <param name="value">The component's substring.</param>
    /// <param name="characterClass">The component's admissible-character set.</param>
    /// <param name="componentFault">The fault to report for an inadmissible character that is not a malformed triplet.</param>
    /// <returns><paramref name="componentFault"/>, <see cref="ResourceIndicatorFault.PercentEncoding"/>, or <see cref="ResourceIndicatorFault.None"/>.</returns>
    private static ResourceIndicatorFault ValidateCharSet(ReadOnlySpan<char> value, CharacterClass characterClass, ResourceIndicatorFault componentFault)
    {
        for(int i = 0; i < value.Length; i++)
        {
            char c = value[i];

            if(c == '%')
            {
                if(HasWellFormedTriplet(value, i))
                {
                    i += 2;

                    continue;
                }

                return ResourceIndicatorFault.PercentEncoding;
            }

            bool isAdmitted = characterClass switch
            {
                CharacterClass.Userinfo => IsUnreserved(c) || IsSubDelim(c) || c == ':',
                CharacterClass.RegName => IsUnreserved(c) || IsSubDelim(c),
                CharacterClass.Path => IsUnreserved(c) || IsSubDelim(c) || c is ':' or '@' or '/',
                CharacterClass.Query => IsUnreserved(c) || IsSubDelim(c) || c is ':' or '@' or '/' or '?',
                _ => false,
            };

            if(!isAdmitted)
            {
                return componentFault;
            }
        }

        return ResourceIndicatorFault.None;
    }

    /// <summary>
    /// <see langword="true"/> when <paramref name="value"/> holds <c>%</c> at index
    /// <paramref name="at"/> and the next two characters are both
    /// <see cref="char.IsAsciiHexDigit(char)"/> - a well-formed
    /// <c>pct-encoded = "%" HEXDIG HEXDIG</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">RFC 3986 Appendix A</see>).
    /// </summary>
    /// <param name="value">The span containing the candidate triplet.</param>
    /// <param name="at">The index of the <c>%</c>.</param>
    /// <returns><see langword="true"/> for a well-formed triplet.</returns>
    private static bool HasWellFormedTriplet(ReadOnlySpan<char> value, int at)
    {
        return at + 2 < value.Length && char.IsAsciiHexDigit(value[at + 1]) && char.IsAsciiHexDigit(value[at + 2]);
    }

    /// <summary><c>unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"</c>.</summary>
    /// <param name="c">The character to classify.</param>
    /// <returns><see langword="true"/> when <paramref name="c"/> is <c>unreserved</c>.</returns>
    private static bool IsUnreserved(char c)
    {
        return char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or '_' or '~';
    }

    /// <summary><c>sub-delims = "!" / "$" / "&amp;" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="</c>.</summary>
    /// <param name="c">The character to classify.</param>
    /// <returns><see langword="true"/> when <paramref name="c"/> is <c>sub-delims</c>.</returns>
    private static bool IsSubDelim(char c)
    {
        return c is '!' or '$' or '&' or '\'' or '(' or ')' or '*' or '+' or ',' or ';' or '=';
    }

    /// <summary>
    /// <c>IPv4address = dec-octet "." dec-octet "." dec-octet "." dec-octet</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">RFC 3986 Appendix A</see>).
    /// Used both to recognise a host's <c>IPv4address</c> alternative and, inside an IP-literal's
    /// <c>ls32</c>, its trailing <c>IPv4address</c> form.
    /// </summary>
    /// <param name="value">The candidate dotted-decimal address.</param>
    /// <returns><see langword="true"/> when every one of exactly four dot-separated segments is a valid <c>dec-octet</c>.</returns>
    private static bool IsIPv4Address(ReadOnlySpan<char> value)
    {
        int dotCount = 0;
        int start = 0;

        for(int i = 0; i <= value.Length; i++)
        {
            if(i == value.Length || value[i] == '.')
            {
                if(!IsDecOctet(value[start..i]))
                {
                    return false;
                }

                dotCount++;
                start = i + 1;
            }
        }

        return dotCount == 4;
    }

    /// <summary>
    /// <c>dec-octet</c>'s five forms
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">RFC 3986 Appendix A</see>):
    /// one to three ASCII digits, numeric value 0-255, no leading zero unless the octet is
    /// exactly <c>"0"</c>.
    /// </summary>
    /// <param name="token">One dot-separated segment of an <c>IPv4address</c>.</param>
    /// <returns><see langword="true"/> when <paramref name="token"/> is a valid <c>dec-octet</c>.</returns>
    private static bool IsDecOctet(ReadOnlySpan<char> token)
    {
        if(token.Length is < 1 or > 3)
        {
            return false;
        }

        foreach(char c in token)
        {
            if(!char.IsAsciiDigit(c))
            {
                return false;
            }
        }

        if(token.Length > 1 && token[0] == '0')
        {
            return false;
        }

        int value = 0;

        foreach(char c in token)
        {
            value = (value * 10) + (c - '0');
        }

        return value <= 255;
    }

    /// <summary>
    /// <c>IPvFuture = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">RFC 3986 Appendix A</see>),
    /// read from the content between an IP-literal's brackets.
    /// </summary>
    /// <param name="content">The IP-literal's content, without its brackets.</param>
    /// <returns><see langword="true"/> when <paramref name="content"/> is a valid <c>IPvFuture</c>.</returns>
    private static bool IsIPvFuture(ReadOnlySpan<char> content)
    {
        if(content.Length < 4 || content[0] is not ('v' or 'V'))
        {
            return false;
        }

        int i = 1;
        int hexDigitCount = 0;

        while(i < content.Length && char.IsAsciiHexDigit(content[i]))
        {
            i++;
            hexDigitCount++;
        }

        if(hexDigitCount == 0 || i == content.Length || content[i] != '.')
        {
            return false;
        }

        i++;

        int tailCount = 0;

        for(; i < content.Length; i++)
        {
            if(!(IsUnreserved(content[i]) || IsSubDelim(content[i]) || content[i] == ':'))
            {
                return false;
            }

            tailCount++;
        }

        return tailCount > 0;
    }

    /// <summary>
    /// The nine <c>IPv6address</c> forms over <c>h16 = 1*4HEXDIG</c> and
    /// <c>ls32 = ( h16 ":" h16 ) / IPv4address</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">RFC 3986 Appendix A</see>),
    /// read from the content between an IP-literal's brackets by locating at most one <c>"::"</c>
    /// compression and counting the 16-bit words on each side (an <c>IPv4address</c> tail, valid
    /// only as the address's last group, counting as two).
    /// </summary>
    /// <param name="content">The IP-literal's content, without its brackets.</param>
    /// <returns><see langword="true"/> when <paramref name="content"/> is a valid <c>IPv6address</c>.</returns>
    private static bool IsIPv6Address(ReadOnlySpan<char> content)
    {
        int firstDouble = content.IndexOf("::", StringComparison.Ordinal);

        if(firstDouble < 0)
        {
            if(content.Length == 0 || content[0] == ':' || content[^1] == ':')
            {
                return false;
            }

            return TryCountWords(content, allowIPv4Last: true, out int words) && words == 8;
        }

        if(content[(firstDouble + 2)..].IndexOf("::", StringComparison.Ordinal) >= 0)
        {
            return false;
        }

        ReadOnlySpan<char> left = content[..firstDouble];
        ReadOnlySpan<char> right = content[(firstDouble + 2)..];

        if((!left.IsEmpty && (left[0] == ':' || left[^1] == ':')) || (!right.IsEmpty && (right[0] == ':' || right[^1] == ':')))
        {
            return false;
        }

        if(!TryCountWords(left, allowIPv4Last: false, out int leftWords) || !TryCountWords(right, allowIPv4Last: true, out int rightWords))
        {
            return false;
        }

        return leftWords + rightWords <= 7;
    }

    /// <summary>
    /// Splits <paramref name="part"/> on <c>:</c> and validates each token as <c>h16</c>, except
    /// the last token when <paramref name="allowIPv4Last"/> permits it to be an <c>IPv4address</c>
    /// (worth two 16-bit words); an empty <paramref name="part"/> is zero groups.
    /// </summary>
    /// <param name="part">One side of an <c>IPv6address</c>, relative to any <c>"::"</c>.</param>
    /// <param name="allowIPv4Last">Whether the last token may be an <c>IPv4address</c> (only the address's own tail, never before a <c>"::"</c>).</param>
    /// <param name="words">The number of 16-bit words <paramref name="part"/> accounts for.</param>
    /// <returns><see langword="true"/> when every token is valid.</returns>
    private static bool TryCountWords(ReadOnlySpan<char> part, bool allowIPv4Last, out int words)
    {
        words = 0;

        if(part.IsEmpty)
        {
            return true;
        }

        int start = 0;

        for(int i = 0; i <= part.Length; i++)
        {
            if(i == part.Length || part[i] == ':')
            {
                ReadOnlySpan<char> token = part[start..i];

                if(token.IsEmpty)
                {
                    return false;
                }

                bool isLastToken = i == part.Length;

                if(isLastToken && allowIPv4Last && token.IndexOf('.') >= 0)
                {
                    if(!IsIPv4Address(token))
                    {
                        return false;
                    }

                    words += 2;
                }
                else
                {
                    if(token.Length is < 1 or > 4)
                    {
                        return false;
                    }

                    foreach(char c in token)
                    {
                        if(!char.IsAsciiHexDigit(c))
                        {
                            return false;
                        }
                    }

                    words += 1;
                }

                start = i + 1;
            }
        }

        return true;
    }

    /// <summary>
    /// Lowers <paramref name="source"/>'s host range [<paramref name="hostStart"/>,
    /// <paramref name="hostEnd"/>) into <paramref name="destination"/> with the copying
    /// <see cref="Ascii.ToLower(ReadOnlySpan{char}, Span{char}, out int)"/>, one call per
    /// contiguous run, skipping the two hexadecimal digits of every percent triplet so they keep
    /// the spelling sent: a deviation from
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-6.2.2.1">RFC 3986 section
    /// 6.2.2.1</see>'s "should be normalized to use uppercase letters for the digits A-F" that the
    /// authorization server design document names.
    /// </summary>
    /// <param name="source">The original indicator.</param>
    /// <param name="destination">The buffer already carrying a verbatim copy of <paramref name="source"/>.</param>
    /// <param name="hostStart">The inclusive start of the host range.</param>
    /// <param name="hostEnd">The exclusive end of the host range.</param>
    private static void LowerHostOutsideTriplets(ReadOnlySpan<char> source, Span<char> destination, int hostStart, int hostEnd)
    {
        int segmentStart = hostStart;
        int i = hostStart;

        while(i < hostEnd)
        {
            if(source[i] == '%' && HasWellFormedTriplet(source, i))
            {
                _ = Ascii.ToLower(source[segmentStart..(i + 1)], destination[segmentStart..(i + 1)], out _);
                i += 3;
                segmentStart = i;

                continue;
            }

            i++;
        }

        if(segmentStart < hostEnd)
        {
            _ = Ascii.ToLower(source[segmentStart..hostEnd], destination[segmentStart..hostEnd], out _);
        }
    }
}
