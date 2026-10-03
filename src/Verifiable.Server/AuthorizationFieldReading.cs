using System.Diagnostics;
using System.Text;

namespace Verifiable.Server;

/// <summary>
/// The one reading of a request's <c>Authorization</c> field: the field is absent, repeated, or one field
/// line whose value is split into its authentication scheme and its credentials and judged against the
/// <c>credentials</c> grammar. The library's readers of the field read it through <see cref="Read"/>, so a
/// field sent twice reads the same way at every endpoint of the library and never as the first or the last of
/// its values.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.6.2">RFC 9110 Section 11.6.2</see> defines the
/// field as one credential, "Authorization = credentials", not a list, so
/// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.3">RFC 9110 Section 5.3</see> forbids a second
/// field line: "This means that, aside from the well-known exception noted below, a sender MUST NOT generate
/// multiple field lines with the same name in a message (whether in the headers or trailers) or append a field
/// line when a field line of the same name already exists in the message, unless that field's definition allows
/// multiple field line values to be recombined as a comma-separated list (i.e., at least one alternative of the
/// field's definition allows a comma-separated list, such as an ABNF rule of #(values) defined in Section
/// 5.6.1)." Two or more field lines read as <see cref="IsRepeated"/>, with no scheme and no credentials.
/// </para>
/// <para>
/// One field line is read by the grammar of
/// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.4">RFC 9110 Section 11.4</see>,
/// "credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]", with "auth-scheme    = token"
/// (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.1">Section 11.1</see>), and the token68 and
/// auth-param rules of <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.2">Section 11.2</see>.
/// The value is read without the whitespace around it, which
/// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.5">RFC 9110 Section 5.5</see> excludes from a
/// field value. <see cref="Scheme"/> is the text before the first SP, <see cref="Credentials"/> the text after
/// the SP run that follows it, and <see cref="IsWellFormed"/> tells whether the whole value matches the
/// grammar. The scheme compares case-insensitively through <see cref="IsScheme"/>: "It uses a
/// case-insensitive token to identify the authentication scheme:" (Section 11.1), followed by the rule
/// "auth-scheme    = token".
/// </para>
/// <para>
/// A field line that is empty, or holds white space only, carries no scheme token and is present and not
/// well-formed, as any other value outside the grammar is: one grammar reading with no exception. The rule of
/// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">RFC 6749 Section 3.2</see> for a parameter
/// sent without a value governs request parameters, not header fields.
/// </para>
/// <para>
/// A scheme longer than 20 characters is read as not well-formed, a policy of this library: a scheme a client
/// sends is written back in the challenge of a refused attempt, so the reading bounds it, and the longest name
/// in the <see href="https://www.iana.org/assignments/http-authschemes/http-authschemes.xhtml">IANA HTTP
/// Authentication Scheme Registry</see> is <c>SCRAM-SHA-256</c>, 13 characters.
/// </para>
/// <para>
/// The text of a reading (<see cref="ToString"/> and the debugger display) names the scheme of a well-formed
/// line only; a line that is not well-formed is named so with a fixed word and no part of its value, since
/// the text before its first SP may hold the credential itself.
/// </para>
/// <para>
/// The default value is the absent field.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct AuthorizationFieldReading
{
    /// <summary>
    /// Whether the request carries no <c>Authorization</c> field line.
    /// </summary>
    public bool IsAbsent => !IsRepeated && Scheme is null;

    /// <summary>
    /// Whether the request carries two or more <c>Authorization</c> field lines, which
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.3">RFC 9110 Section 5.3</see> forbids for a
    /// field that is not a list. A repeated field has no <see cref="Scheme"/> and no <see cref="Credentials"/>.
    /// </summary>
    public bool IsRepeated { get; }

    /// <summary>
    /// The authentication scheme of the one field line, the text before its first SP, as sent; empty for
    /// an empty field line; <see langword="null"/> when the field is absent or repeated.
    /// </summary>
    public string? Scheme { get; }

    /// <summary>
    /// The credentials of the one field line, the text after the SP run that follows the scheme, as sent;
    /// empty when the line carries the scheme alone; <see langword="null"/> when the field is absent or
    /// repeated.
    /// </summary>
    public string? Credentials { get; }

    /// <summary>
    /// Whether the one field line's value matches
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.4">RFC 9110 Section 11.4</see>'s
    /// "credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]". <see langword="false"/> when the field
    /// is absent or repeated.
    /// </summary>
    public bool IsWellFormed { get; }

    /// <summary>
    /// Whether the one field line is well-formed and its credentials are a token68 of
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.2">RFC 9110 Section 11.2</see>,
    /// "token68        = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="", rather than a list of
    /// auth-param or nothing. The access token schemes carry their token in this form:
    /// "credentials = "Bearer" 1*SP b64token"
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6750#section-2.1">RFC 6750 Section 2.1</see>) and
    /// "credentials = "DPoP" 1*SP token68"
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>).
    /// <see langword="false"/> when the field is absent or repeated.
    /// </summary>
    public bool HasToken68Credentials { get; }

    /// <summary>
    /// The longest scheme the reading accepts, 20 characters, a policy of this library: a scheme a client
    /// sends is written back in the challenge of a refused attempt, and the longest name in the
    /// <see href="https://www.iana.org/assignments/http-authschemes/http-authschemes.xhtml">IANA HTTP
    /// Authentication Scheme Registry</see> is <c>SCRAM-SHA-256</c>, 13 characters.
    /// </summary>
    private static int MaximumSchemeLength { get; } = 20;

    /// <summary>
    /// The text the debugger shows for the reading: the scheme of a well-formed line, and of a line that is not
    /// well-formed the fixed word <c>NotWellFormed</c> and no part of its value. The credentials are never shown.
    /// </summary>
    private string DebuggerDisplay => this switch
    {
        { IsRepeated: true } => "AuthorizationFieldReading(Repeated)",
        { Scheme: null } => "AuthorizationFieldReading(Absent)",
        { IsWellFormed: true } => $"AuthorizationFieldReading(Scheme={Scheme})",

        _ => "AuthorizationFieldReading(NotWellFormed)"
    };


    /// <summary>
    /// The scheme of a well-formed reading, or the word that names its state, never its credentials and never
    /// any part of a line that is not well-formed, so a reading written to a log or a trace carries no secret.
    /// </summary>
    /// <returns>The reading's text.</returns>
    public override string ToString() => DebuggerDisplay;


    /// <summary>Creates a reading from its parts; <see cref="Read"/> is the one caller.</summary>
    /// <param name="isRepeated">Whether two or more field lines were sent.</param>
    /// <param name="scheme">The scheme of the one field line.</param>
    /// <param name="credentials">The credentials of the one field line.</param>
    /// <param name="isWellFormed">Whether the one field line matches the grammar.</param>
    /// <param name="hasToken68Credentials">Whether the one well-formed field line's credentials are a token68.</param>
    private AuthorizationFieldReading(
        bool isRepeated, string? scheme, string? credentials, bool isWellFormed, bool hasToken68Credentials)
    {
        IsRepeated = isRepeated;
        Scheme = scheme;
        Credentials = credentials;
        IsWellFormed = isWellFormed;
        HasToken68Credentials = hasToken68Credentials;
    }


    /// <summary>
    /// Reads the <c>Authorization</c> field of <paramref name="headers"/>: absent when it carries no field
    /// line, repeated when it carries two or more, and otherwise the one line's scheme, credentials and
    /// grammar judgment.
    /// </summary>
    /// <param name="headers">The request headers as received.</param>
    /// <returns>The reading.</returns>
    public static AuthorizationFieldReading Read(RequestHeaders headers)
    {
        ArgumentNullException.ThrowIfNull(headers);

        if(!headers.TryGetAll(WellKnownHttpHeaderNames.Authorization, out IReadOnlyList<string>? values)
            || values is null
            || values.Count == 0)
        {
            return default;
        }

        if(values.Count > 1)
        {
            return new AuthorizationFieldReading(
                isRepeated: true, scheme: null, credentials: null, isWellFormed: false, hasToken68Credentials: false);
        }

        string value = values[0].Trim(' ', '\t');
        int separator = value.IndexOf(' ', StringComparison.Ordinal);
        string scheme = separator < 0 ? value : value[..separator];
        string credentials = separator < 0 ? string.Empty : value[separator..].TrimStart(' ');
        bool isSchemeAccepted = scheme.Length <= MaximumSchemeLength && IsToken(scheme);
        bool isToken68 = credentials.Length > 0 && IsToken68(credentials);
        bool isWellFormed = isSchemeAccepted
            && (credentials.Length == 0 || isToken68 || IsAuthParamList(credentials));

        return new AuthorizationFieldReading(
            isRepeated: false, scheme, credentials, isWellFormed, hasToken68Credentials: isWellFormed && isToken68);
    }


    /// <summary>
    /// Whether the one field line's scheme is <paramref name="scheme"/>, compared ASCII case-insensitively:
    /// "It uses a case-insensitive token to identify the authentication scheme:"
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.1">RFC 9110 Section 11.1</see>), followed by
    /// the rule "auth-scheme    = token".
    /// <see langword="false"/> when the field is absent or repeated.
    /// </summary>
    /// <param name="scheme">The scheme name, such as <c>Basic</c> or <c>Bearer</c>.</param>
    /// <returns><see langword="true"/> when the one field line names <paramref name="scheme"/>.</returns>
    public bool IsScheme(string scheme)
    {
        ArgumentException.ThrowIfNullOrEmpty(scheme);

        return Scheme is not null && Ascii.EqualsIgnoreCase(Scheme, scheme);
    }


    /// <summary>
    /// Whether <paramref name="text"/> is an
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.6.2">RFC 9110 Section 5.6.2</see> token,
    /// "token          = 1*tchar".
    /// </summary>
    /// <param name="text">The candidate.</param>
    /// <returns><see langword="true"/> when the text is one or more tchar.</returns>
    private static bool IsToken(ReadOnlySpan<char> text)
    {
        if(text.IsEmpty)
        {
            return false;
        }

        foreach(char c in text)
        {
            if(!IsTokenCharacter(c))
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>
    /// Whether <paramref name="c"/> is a tchar of
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.6.2">RFC 9110 Section 5.6.2</see>:
    /// "!" / "#" / "$" / "%" / "&amp;" / "'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA.
    /// </summary>
    /// <param name="c">The character.</param>
    /// <returns><see langword="true"/> for a tchar.</returns>
    private static bool IsTokenCharacter(char c) =>
        char.IsAsciiLetterOrDigit(c)
        || c is '!' or '#' or '$' or '%' or '&' or '\'' or '*' or '+' or '-' or '.' or '^' or '_' or '`' or '|' or '~';


    /// <summary>
    /// Whether <paramref name="text"/> is a token68 of
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.2">RFC 9110 Section 11.2</see>:
    /// "token68        = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="".
    /// </summary>
    /// <param name="text">The candidate credentials.</param>
    /// <returns><see langword="true"/> when the text is a token68.</returns>
    private static bool IsToken68(ReadOnlySpan<char> text)
    {
        int position = 0;
        while(position < text.Length && (char.IsAsciiLetterOrDigit(text[position]) || text[position] is '-' or '.' or '_' or '~' or '+' or '/'))
        {
            position++;
        }

        if(position == 0)
        {
            return false;
        }

        while(position < text.Length && text[position] == '=')
        {
            position++;
        }

        return position == text.Length;
    }


    /// <summary>
    /// Whether <paramref name="text"/> is a list of auth-param: the recipient list rule of
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.6.1.2">RFC 9110 Section 5.6.1.2</see>,
    /// "#element => [ element ] *( OWS "," OWS [ element ] )", over "auth-param     = token BWS "=" BWS (
    /// token / quoted-string )" of <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.2">Section
    /// 11.2</see>. An empty first element may be followed by OWS before its comma; the SP run after the scheme
    /// is read by <see cref="Read"/> before the list starts, so the list itself is not relaxed.
    /// </summary>
    /// <param name="text">The candidate credentials.</param>
    /// <returns><see langword="true"/> when the whole text is such a list.</returns>
    private static bool IsAuthParamList(ReadOnlySpan<char> text)
    {
        int position = 0;
        int firstComma = SkipWhitespace(text, 0);
        if(firstComma < text.Length && text[firstComma] == ',')
        {
            //An empty first element: OWS, then its comma.
            position = firstComma;
        }

        while(true)
        {
            if(position < text.Length && text[position] != ',' && !TryReadAuthParam(text, ref position))
            {
                return false;
            }

            position = SkipWhitespace(text, position);
            if(position == text.Length)
            {
                return true;
            }

            if(text[position] != ',')
            {
                return false;
            }

            position = SkipWhitespace(text, position + 1);
        }
    }


    /// <summary>
    /// Reads one auth-param at <paramref name="position"/>, "token BWS "=" BWS ( token / quoted-string )",
    /// and advances past it.
    /// </summary>
    /// <param name="text">The credentials.</param>
    /// <param name="position">The position of the parameter's name; past its value when the read succeeds.</param>
    /// <returns><see langword="true"/> when an auth-param starts at the position.</returns>
    private static bool TryReadAuthParam(ReadOnlySpan<char> text, ref int position)
    {
        int nameEnd = position;
        while(nameEnd < text.Length && IsTokenCharacter(text[nameEnd]))
        {
            nameEnd++;
        }

        if(nameEnd == position)
        {
            return false;
        }

        int equals = SkipWhitespace(text, nameEnd);
        if(equals == text.Length || text[equals] != '=')
        {
            return false;
        }

        int valueStart = SkipWhitespace(text, equals + 1);
        if(valueStart == text.Length)
        {
            return false;
        }

        if(text[valueStart] == '"')
        {
            return TryReadQuotedString(text, valueStart, out position);
        }

        int valueEnd = valueStart;
        while(valueEnd < text.Length && IsTokenCharacter(text[valueEnd]))
        {
            valueEnd++;
        }

        position = valueEnd;

        return valueEnd > valueStart;
    }


    /// <summary>
    /// Reads a quoted-string of <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.6.4">RFC 9110
    /// Section 5.6.4</see> starting at its opening DQUOTE: "quoted-string  = DQUOTE *( qdtext / quoted-pair )
    /// DQUOTE", "qdtext         = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text" and "quoted-pair    = "\" (
    /// HTAB / SP / VCHAR / obs-text )", obs-text being %x80-FF.
    /// </summary>
    /// <param name="text">The credentials.</param>
    /// <param name="openingQuote">The position of the opening DQUOTE.</param>
    /// <param name="end">The position after the closing DQUOTE when the read succeeds.</param>
    /// <returns><see langword="true"/> when a complete quoted-string starts at the position.</returns>
    private static bool TryReadQuotedString(ReadOnlySpan<char> text, int openingQuote, out int end)
    {
        int position = openingQuote + 1;
        while(position < text.Length)
        {
            char c = text[position];
            if(c == '"')
            {
                end = position + 1;

                return true;
            }

            if(c == '\\')
            {
                if(position + 1 == text.Length || !IsQuotedPairCharacter(text[position + 1]))
                {
                    break;
                }

                position += 2;

                continue;
            }

            if(!IsQuotedTextCharacter(c))
            {
                break;
            }

            position++;
        }

        end = openingQuote;

        return false;
    }


    /// <summary>
    /// Whether <paramref name="c"/> is a qdtext: HTAB, SP, %x21, %x23-5B, %x5D-7E or obs-text %x80-FF.
    /// </summary>
    /// <param name="c">The character.</param>
    /// <returns><see langword="true"/> for a qdtext character.</returns>
    private static bool IsQuotedTextCharacter(char c) =>
        c is '\t' or ' ' or '!' or (>= '#' and <= '[') or (>= ']' and <= '~') or (>= '\u0080' and <= '\u00FF');


    /// <summary>
    /// Whether <paramref name="c"/> may follow the backslash of a quoted-pair: HTAB, SP, a VCHAR (%x21-7E)
    /// or obs-text %x80-FF.
    /// </summary>
    /// <param name="c">The character.</param>
    /// <returns><see langword="true"/> for a quoted-pair character.</returns>
    private static bool IsQuotedPairCharacter(char c) =>
        c is '\t' or (>= ' ' and <= '~') or (>= '\u0080' and <= '\u00FF');


    /// <summary>
    /// The first position at or after <paramref name="position"/> that is not OWS, "OWS            = *( SP /
    /// HTAB )" (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.6.3">RFC 9110 Section 5.6.3</see>);
    /// BWS has the same form.
    /// </summary>
    /// <param name="text">The credentials.</param>
    /// <param name="position">The position to start from.</param>
    /// <returns>The first position holding no SP or HTAB, or the text's length.</returns>
    private static int SkipWhitespace(ReadOnlySpan<char> text, int position)
    {
        while(position < text.Length && text[position] is ' ' or '\t')
        {
            position++;
        }

        return position;
    }
}
