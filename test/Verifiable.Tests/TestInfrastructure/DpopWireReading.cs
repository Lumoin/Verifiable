using System.Buffers;
using System.Text;
using System.Text.Json;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Reads what a DPoP exchange put on the wire against the grammar the specifications define for it: the
/// token68 syntax of a <c>DPoP</c> field value
/// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.1">RFC 9449 Section 4.1</see>, Figure 3), the
/// nonce syntax of a <c>DPoP-Nonce</c> field value
/// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-8.1">RFC 9449 Section 8.1</see>, Figure 22), the
/// auth-params of one challenge of a <c>WWW-Authenticate</c> field value
/// (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.2">RFC 9110 Section 11.2</see>), whether a
/// cache may store a response (<see href="https://www.rfc-editor.org/rfc/rfc9111#section-3">RFC 9111 Section
/// 3</see>), and a claim of a proof's payload. Each reading is written here from the grammar it names and never
/// through the library's own readers, so a row's expectation comes from the specification text.
/// </summary>
internal static class DpopWireReading
{
    /// <summary>
    /// The status codes <see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.1">RFC 9110 Section
    /// 15.1</see> names heuristically cacheable: "Responses with status codes that are defined as heuristically
    /// cacheable (e.g., 200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, and 501 in this specification) can
    /// be reused by a cache with heuristic expiration".
    /// </summary>
    private static HashSet<int> HeuristicallyCacheableStatusCodes { get; } =
        [200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, 501];


    /// <summary>
    /// Whether <paramref name="value"/> is written in the token68 syntax RFC 9449 Section 4.1 repeats from
    /// RFC 9110 Section 11.2: <c>token68 = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="</c>.
    /// </summary>
    /// <param name="value">The field value as received.</param>
    /// <returns><see langword="true"/> when the value is one token68.</returns>
    public static bool IsToken68(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        int end = value.Length;
        while(end > 0 && value[end - 1] == '=')
        {
            end--;
        }

        if(end == 0)
        {
            return false;
        }

        for(int i = 0; i < end; i++)
        {
            if(!IsToken68Character(value[i]))
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>
    /// Whether <paramref name="value"/> is written in the nonce syntax of RFC 9449 Section 8.1,
    /// <c>nonce = 1*NQCHAR</c>, with <c>NQCHAR = %x21 / %x23-5B / %x5D-7E</c> as RFC 6749 Appendix A defines it.
    /// </summary>
    /// <param name="value">The field value as received.</param>
    /// <returns><see langword="true"/> when the value is one or more NQCHAR.</returns>
    public static bool IsNonceSyntax(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        if(value.Length == 0)
        {
            return false;
        }

        foreach(char c in value)
        {
            bool isNqChar = c is '\x21' or (>= '\x23' and <= '\x5B') or (>= '\x5D' and <= '\x7E');
            if(!isNqChar)
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>
    /// Whether a cache may store the response with <paramref name="statusCode"/> and <paramref name="headers"/> to a
    /// request of <paramref name="requestMethod"/> to <paramref name="requestTarget"/>, read from
    /// <see href="https://www.rfc-editor.org/rfc/rfc9111#section-3">RFC 9111 Section 3</see>: "A cache MUST NOT store a
    /// response to a request unless: the request method is understood by the cache; ... the no-store cache directive
    /// is not present in the response ... and the response contains at least one of the following: a public response
    /// directive ...; a private response directive, if the cache is not shared ...; an Expires header field ...; a
    /// max-age response directive ...; if the cache is shared: an s-maxage response directive ...; a cache extension
    /// that allows it to be cached ...; or a status code that is defined as heuristically cacheable". The methods a
    /// cache can understand are those
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-9.2.3">RFC 9110 Section 9.2.3</see> defines caching
    /// for: "This specification defines caching semantics for GET, HEAD, and POST"; any other method's response is
    /// stored by no cache. For POST,
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-9.3.3">RFC 9110 Section 9.3.3</see> adds: "Responses to
    /// POST requests are only cacheable when they include explicit freshness information (see Section 4.2.1 of
    /// [CACHING]) and a Content-Location header field that has the same value as the POST's target URI", the explicit
    /// freshness of <see href="https://www.rfc-editor.org/rfc/rfc9111#section-4.2.1">RFC 9111 Section 4.2.1</see> being
    /// an <c>s-maxage</c> or <c>max-age</c> directive or an <c>Expires</c> field. A cache that is not shared is one such
    /// cache, so the shared-cache conditions on the <c>Authorization</c> request field do not hold every cache back. No
    /// cache extension is known here, so none is read as allowing storage.
    /// </summary>
    /// <param name="requestMethod">The method of the request the response answered.</param>
    /// <param name="requestTarget">The target URI of the request the response answered.</param>
    /// <param name="statusCode">The response status code.</param>
    /// <param name="headers">Every field line of the response, as received.</param>
    /// <returns><see langword="true"/> when some cache may store the response.</returns>
    public static bool IsStorableByACache(string requestMethod, Uri requestTarget, int statusCode, HttpHeaderSet headers)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(requestMethod);
        ArgumentNullException.ThrowIfNull(requestTarget);
        ArgumentNullException.ThrowIfNull(headers);

        bool isGetOrHead = requestMethod is "GET" or "HEAD";
        bool isPost = requestMethod is "POST";
        if(!isGetOrHead && !isPost)
        {
            return false;
        }

        HashSet<string> directives = new(StringComparer.OrdinalIgnoreCase);
        foreach(string line in headers.GetValues("Cache-Control"))
        {
            foreach(string member in line.Split(','))
            {
                string trimmed = member.Trim(' ', '\t');
                int equals = trimmed.IndexOf('=', StringComparison.Ordinal);
                _ = directives.Add(equals < 0 ? trimmed : trimmed[..equals]);
            }
        }

        if(directives.Contains("no-store"))
        {
            return false;
        }

        bool hasExplicitFreshness = directives.Contains("max-age")
            || directives.Contains("s-maxage")
            || headers.Contains("Expires");
        if(isPost)
        {
            return hasExplicitFreshness && IsContentLocationOf(requestTarget, headers);
        }

        bool isExplicitlyStorable = hasExplicitFreshness
            || directives.Contains("public")
            || directives.Contains("private");

        return isExplicitlyStorable || HeuristicallyCacheableStatusCodes.Contains(statusCode);
    }


    /// <summary>
    /// Whether the response's one <c>Content-Location</c> field names <paramref name="requestTarget"/>:
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-8.7">RFC 9110 Section 8.7</see> makes the value an
    /// absolute-URI or a partial-URI "relative to the target URI", so the value is resolved against the target URI
    /// before the two are compared.
    /// </summary>
    /// <param name="requestTarget">The POST's target URI.</param>
    /// <param name="headers">Every field line of the response, as received.</param>
    /// <returns><see langword="true"/> when one <c>Content-Location</c> field has the target URI's value.</returns>
    private static bool IsContentLocationOf(Uri requestTarget, HttpHeaderSet headers)
    {
        IReadOnlyList<string> contentLocations = headers.GetValues("Content-Location");

        return contentLocations.Count == 1
            && Uri.TryCreate(requestTarget, contentLocations[0].Trim(' ', '\t'), out Uri? resolved)
            && string.Equals(resolved.AbsoluteUri, requestTarget.AbsoluteUri, StringComparison.Ordinal);
    }


    /// <summary>
    /// Reads the auth-params of the one challenge named <paramref name="scheme"/> out of a
    /// <c>WWW-Authenticate</c> field value held to its grammar:
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.6.1">RFC 9110 Section 11.6.1</see>,
    /// "WWW-Authenticate = #challenge";
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.3">Section 11.3</see>, "challenge = auth-scheme [
    /// 1*SP ( token68 / #auth-param ) ]";
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.2">Section 11.2</see>, "auth-param = token BWS "="
    /// BWS ( token / quoted-string )" and "each parameter name MUST only occur once per challenge"; and the list rule a
    /// sender is held to, <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.6.1.1">Section 5.6.1.1</see>: "In
    /// any production that uses the list construct, a sender MUST NOT generate empty list elements", the list being
    /// "1#element => element *( OWS "," OWS element )". The value read is a server's output, so an empty element (a
    /// leading or a trailing comma, or two commas with only whitespace between them) fails the reading; the recipient
    /// rule of <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.6.1.2">Section 5.6.1.2</see>, "A recipient MUST
    /// parse and ignore a reasonable number of empty list elements", is what the library's own client reader accepts,
    /// never what a server row is read by. Only SP opens a challenge's content and only SP stands between the scheme and
    /// the content (a horizontal tab there fails the reading), no whitespace stands on either side of an auth-param's
    /// <c>=</c> (the BWS of Section 11.2, which
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.6.3">Section 5.6.3</see> forbids a sender: "A sender
    /// MUST NOT generate BWS in messages"; <see cref="ReadAuthParam"/>), list elements are separated by one comma
    /// with optional whitespace around it, a quoted-string holds qdtext and quoted-pairs alone
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.6.4">Section 5.6.4</see>), and after a comma an
    /// element that is a token followed by <c>=</c> continues the challenge's auth-params while any other element starts
    /// the next challenge. A value outside that grammar, a parameter named twice in one challenge, and a field value
    /// holding no challenge of the scheme or more than one fail the reading with the place the grammar is left.
    /// </summary>
    /// <param name="fieldValue">The field value as received.</param>
    /// <param name="scheme">The authentication scheme whose challenge is read, compared case-insensitively.</param>
    /// <returns>The challenge's parameters, their names compared case-insensitively.</returns>
    public static IReadOnlyDictionary<string, string> ReadChallengeParameters(string fieldValue, string scheme)
    {
        ArgumentNullException.ThrowIfNull(fieldValue);
        ArgumentException.ThrowIfNullOrWhiteSpace(scheme);

        List<(string Scheme, Dictionary<string, string> Parameters)> challenges = ReadChallenges(fieldValue);
        List<Dictionary<string, string>> named = [.. challenges
            .Where(challenge => string.Equals(challenge.Scheme, scheme, StringComparison.OrdinalIgnoreCase))
            .Select(challenge => challenge.Parameters)];
        if(named.Count != 1)
        {
            throw new AssertFailedException($"The field value holds {named.Count} {scheme} challenges where one is read: '{fieldValue}'.");
        }

        return named[0];
    }


    /// <summary>
    /// Reads every challenge of a <c>WWW-Authenticate</c> field value, the <c>#challenge</c> list of RFC 9110 Section
    /// 11.6.1 as a sender writes it (Section 5.6.1.1, no empty element): each challenge starts with its scheme token,
    /// and the scheme is followed by the end of the value, by optional whitespace and the comma before the next
    /// element (no content), or by a run of SP alone and the content of <see cref="ReadChallengeContent"/>,
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.3">RFC 9110 Section 11.3</see>: "challenge =
    /// auth-scheme [ 1*SP ( token68 / #auth-param ) ]", so a horizontal tab among the whitespace before the content
    /// fails the reading with its place; the elements are separated by <see cref="ReadListSeparator"/>.
    /// </summary>
    /// <param name="text">The field value.</param>
    /// <returns>Each challenge's scheme and auth-params, in the order written.</returns>
    private static List<(string Scheme, Dictionary<string, string> Parameters)> ReadChallenges(string text)
    {
        List<(string Scheme, Dictionary<string, string> Parameters)> challenges = [];
        if(text.Length == 0)
        {
            return challenges;
        }

        int position = 0;
        if(text[position] == ',')
        {
            throw new AssertFailedException(
                $"An empty list element stands at position {position}, where Section 5.6.1.1 says a sender MUST NOT generate empty list elements: '{text}'.");
        }

        while(true)
        {
            string challengeScheme = ReadToken(text, ref position);
            if(challengeScheme.Length == 0)
            {
                throw new AssertFailedException($"No auth-scheme token starts at position {position}: '{text}'.");
            }

            Dictionary<string, string> parameters = new(StringComparer.OrdinalIgnoreCase);
            challenges.Add((challengeScheme, parameters));
            if(position < text.Length && text[position] == ' ')
            {
                int afterListWhitespace = SkipWhitespace(text, position);
                if(afterListWhitespace >= text.Length)
                {
                    return challenges;
                }

                if(text[afterListWhitespace] == ',')
                {
                    position = ReadListSeparator(text, afterListWhitespace);

                    continue;
                }

                int afterSpaces = SkipSpaces(text, position);
                if(afterSpaces != afterListWhitespace)
                {
                    throw new AssertFailedException(
                        $"U+{(int)text[afterSpaces]:X4} at position {afterSpaces} stands between the auth-scheme '{challengeScheme}' and its content, where Section 11.3 requires 1*SP alone: '{text}'.");
                }

                position = ReadChallengeContent(text, afterSpaces, parameters);
                if(position >= text.Length)
                {
                    return challenges;
                }

                continue;
            }

            int afterWhitespace = SkipWhitespace(text, position);
            if(afterWhitespace >= text.Length)
            {
                return challenges;
            }

            if(text[afterWhitespace] != ',')
            {
                throw new AssertFailedException(
                    $"The auth-scheme '{challengeScheme}' is followed by U+{(int)text[position]:X4} where Section 11.3 requires SP before content: '{text}'.");
            }

            position = ReadListSeparator(text, afterWhitespace);
        }
    }


    /// <summary>
    /// Reads the content that follows a challenge's SP: a token68 that ends its list element, or the
    /// <c>#auth-param</c> list, whose first element is an auth-param (a sender generates no empty element, Section
    /// 5.6.1.1). Each auth-param is followed by optional whitespace and then a comma or the end of the value; after the
    /// separator (<see cref="ReadListSeparator"/>), the next element that is no auth-param is the next challenge, where
    /// the reading stops.
    /// </summary>
    /// <param name="text">The field value.</param>
    /// <param name="position">The position after the SP run.</param>
    /// <param name="parameters">The challenge's auth-params, filled as they are read.</param>
    /// <returns>The position of the next challenge or the end of the value.</returns>
    private static int ReadChallengeContent(string text, int position, Dictionary<string, string> parameters)
    {
        int token68End = position;
        while(token68End < text.Length && IsToken68Character(text[token68End]))
        {
            token68End++;
        }

        if(token68End > position)
        {
            while(token68End < text.Length && text[token68End] == '=')
            {
                token68End++;
            }

            int afterToken68 = SkipWhitespace(text, token68End);
            if(afterToken68 >= text.Length)
            {
                return afterToken68;
            }

            if(text[afterToken68] == ',')
            {
                return ReadListSeparator(text, afterToken68);
            }
        }

        if(!IsAuthParamAt(text, position))
        {
            throw new AssertFailedException(
                $"No token68 or auth-param follows the auth-scheme's SP at position {position}: '{text}'.");
        }

        while(true)
        {
            (string name, string value) = ReadAuthParam(text, ref position);
            if(!parameters.TryAdd(name, value))
            {
                throw new AssertFailedException($"A challenge names the parameter '{name}' twice: '{text}'.");
            }

            int afterWhitespace = SkipWhitespace(text, position);
            if(afterWhitespace >= text.Length)
            {
                return afterWhitespace;
            }

            if(text[afterWhitespace] != ',')
            {
                throw new AssertFailedException(
                    $"U+{(int)text[afterWhitespace]:X4} at position {afterWhitespace} stands where a comma separates the list elements: '{text}'.");
            }

            position = ReadListSeparator(text, afterWhitespace);
            if(!IsAuthParamAt(text, position))
            {
                return position;
            }
        }
    }


    /// <summary>
    /// Moves past one list separator as a sender writes it,
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.6.1.1">RFC 9110 Section 5.6.1.1</see>: "1#element =>
    /// element *( OWS "," OWS element )", so the comma at <paramref name="commaPosition"/> and the optional whitespace
    /// after it are followed by an element. A further comma or the end of the value there is an empty list element,
    /// which "a sender MUST NOT generate", and fails the reading with its place.
    /// </summary>
    /// <param name="text">The field value.</param>
    /// <param name="commaPosition">The position of the comma.</param>
    /// <returns>The position of the element after the separator.</returns>
    private static int ReadListSeparator(string text, int commaPosition)
    {
        int position = SkipWhitespace(text, commaPosition + 1);
        if(position >= text.Length || text[position] == ',')
        {
            throw new AssertFailedException(
                $"An empty list element follows the comma at position {commaPosition}, where Section 5.6.1.1 says a sender MUST NOT generate empty list elements: '{text}'.");
        }

        return position;
    }


    /// <summary>
    /// Whether the list element at <paramref name="position"/> is an auth-param: a token, optional whitespace, then
    /// <c>=</c>. The whitespace is passed over here so that <see cref="ReadAuthParam"/> reads the element and fails it
    /// with its place, rather than the element being taken for the next challenge.
    /// </summary>
    /// <param name="text">The field value.</param>
    /// <param name="position">The position of the element.</param>
    /// <returns><see langword="true"/> when an auth-param starts there.</returns>
    private static bool IsAuthParamAt(string text, int position)
    {
        int afterToken = position;
        string token = ReadToken(text, ref afterToken);
        int afterWhitespace = SkipWhitespace(text, afterToken);

        return token.Length > 0 && afterWhitespace < text.Length && text[afterWhitespace] == '=';
    }


    /// <summary>
    /// Reads one auth-param as a sender writes it, a name token, <c>=</c> and a value that is a token or a
    /// quoted-string read by <see cref="ReadQuotedString"/>, with nothing between them. The grammar of
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.2">RFC 9110 Section 11.2</see>, "auth-param = token
    /// BWS "=" BWS ( token / quoted-string )", names the whitespace on either side of <c>=</c> BWS, and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.6.3">RFC 9110 Section 5.6.3</see> holds the sender
    /// to none of it: "A sender MUST NOT generate BWS in messages." The value read is a server's output, so an SP or a
    /// horizontal tab before or after the <c>=</c> fails the reading with the character, its position and the
    /// parameter's name; the recipient half of Section 5.6.3, "A recipient MUST parse for such bad whitespace and
    /// remove it before interpreting the protocol element", is what the library's own client reader accepts, never
    /// what a server row is read by.
    /// </summary>
    /// <param name="text">The field value.</param>
    /// <param name="position">The position of the name; left after the value.</param>
    /// <returns>The name as written and the value.</returns>
    private static (string Name, string Value) ReadAuthParam(string text, ref int position)
    {
        string name = ReadToken(text, ref position);
        int equalsPosition = SkipWhitespace(text, position);
        if(equalsPosition != position)
        {
            throw new AssertFailedException(
                $"U+{(int)text[position]:X4} at position {position} stands between the auth-param name '{name}' and its '=', where Section 5.6.3 says a sender MUST NOT generate BWS: '{text}'.");
        }

        position = equalsPosition + 1;
        int valuePosition = SkipWhitespace(text, position);
        if(valuePosition != position)
        {
            throw new AssertFailedException(
                $"U+{(int)text[position]:X4} at position {position} stands between the '=' of the auth-param '{name}' and its value, where Section 5.6.3 says a sender MUST NOT generate BWS: '{text}'.");
        }

        bool isQuotedString = position < text.Length && text[position] == '"';
        string value = isQuotedString
            ? ReadQuotedString(text, ref position)
            : ReadToken(text, ref position);
        if(!isQuotedString && value.Length == 0)
        {
            throw new AssertFailedException($"The auth-param '{name}' carries no token or quoted-string value: '{text}'.");
        }

        return (name, value);
    }


    /// <summary>
    /// Reads the claim <paramref name="claimName"/> of a compact JWS's payload: the second segment decoded from
    /// base64url and read as a JSON object. A string claim is returned as its value, any other claim as its JSON
    /// text.
    /// </summary>
    /// <param name="compactJws">The compact JWS, a DPoP proof as sent.</param>
    /// <param name="claimName">The claim to read.</param>
    /// <param name="pool">The pool the decoded payload is rented from.</param>
    /// <returns>The claim's value, or <see langword="null"/> when the payload carries no such claim.</returns>
    public static string? ReadPayloadClaim(string compactJws, string claimName, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(compactJws);
        ArgumentException.ThrowIfNullOrWhiteSpace(claimName);
        ArgumentNullException.ThrowIfNull(pool);

        string[] segments = compactJws.Split('.');
        if(segments.Length != 3)
        {
            throw new AssertFailedException($"The value is no compact JWS of three segments: '{compactJws}'.");
        }

        using IMemoryOwner<byte> payload = TestSetup.Base64UrlDecoder(segments[1], pool);
        using JsonDocument document = JsonDocument.Parse(payload.Memory);
        if(!document.RootElement.TryGetProperty(claimName, out JsonElement claim))
        {
            return null;
        }

        return claim.ValueKind == JsonValueKind.String ? claim.GetString() : claim.GetRawText();
    }


    /// <summary>
    /// Swaps the case of every ASCII letter of a compact JWS's first segment, leaving the other segments as they
    /// are: the same characters in another case, which RFC 9449 Section 4.1 makes another field value ("case is
    /// significant in the header field value").
    /// </summary>
    /// <param name="compactJws">The compact JWS.</param>
    /// <returns>The compact JWS with its first segment's letters in the other case.</returns>
    public static string SwapLetterCaseOfFirstSegment(string compactJws)
    {
        ArgumentNullException.ThrowIfNull(compactJws);

        int firstDot = compactJws.IndexOf('.', StringComparison.Ordinal);
        StringBuilder swapped = new(compactJws.Length);
        for(int i = 0; i < compactJws.Length; i++)
        {
            char c = compactJws[i];
            char written = i >= firstDot
                ? c
                : c switch
                {
                    >= 'a' and <= 'z' => char.ToUpperInvariant(c),
                    >= 'A' and <= 'Z' => char.ToLowerInvariant(c),
                    _ => c
                };
            _ = swapped.Append(written);
        }

        return swapped.ToString();
    }


    /// <summary>Whether <paramref name="c"/> is one of the token68 characters before its trailing <c>=</c> run.</summary>
    /// <param name="c">The character.</param>
    /// <returns><see langword="true"/> for ALPHA, DIGIT, <c>-</c>, <c>.</c>, <c>_</c>, <c>~</c>, <c>+</c> and <c>/</c>.</returns>
    private static bool IsToken68Character(char c) =>
        c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '.' or '_' or '~' or '+' or '/';


    /// <summary>
    /// Whether <paramref name="c"/> is a <c>tchar</c> of
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.6.2">RFC 9110 Section 5.6.2</see>.
    /// </summary>
    /// <param name="c">The character.</param>
    /// <returns><see langword="true"/> for a token character.</returns>
    private static bool IsTokenCharacter(char c) =>
        c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9')
            or '!' or '#' or '$' or '%' or '&' or '\'' or '*' or '+' or '-' or '.' or '^' or '_' or '`' or '|' or '~';


    /// <summary>Skips optional whitespace (<c>OWS</c>/<c>BWS</c>, spaces and tabs).</summary>
    /// <param name="text">The field value.</param>
    /// <param name="position">The position to start at.</param>
    /// <returns>The position of the next character that is not whitespace.</returns>
    private static int SkipWhitespace(string text, int position)
    {
        while(position < text.Length && text[position] is ' ' or '\t')
        {
            position++;
        }

        return position;
    }


    /// <summary>
    /// Skips the run of SP that <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.3">RFC 9110 Section
    /// 11.3</see> places between a challenge's scheme and its content, "1*SP"; a horizontal tab ends the run.
    /// </summary>
    /// <param name="text">The field value.</param>
    /// <param name="position">The position to start at.</param>
    /// <returns>The position of the next character that is no SP.</returns>
    private static int SkipSpaces(string text, int position)
    {
        while(position < text.Length && text[position] == ' ')
        {
            position++;
        }

        return position;
    }


    /// <summary>Reads the run of <c>tchar</c> starting at <paramref name="position"/> and moves past it.</summary>
    /// <param name="text">The field value.</param>
    /// <param name="position">The position to read from; left after the token.</param>
    /// <returns>The token, empty when no token starts at the position.</returns>
    private static string ReadToken(string text, ref int position)
    {
        int start = position;
        while(position < text.Length && IsTokenCharacter(text[position]))
        {
            position++;
        }

        return text[start..position];
    }


    /// <summary>
    /// Reads the quoted-string of <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.6.4">RFC 9110
    /// Section 5.6.4</see> starting at the opening <c>"</c> and moves past its closing <c>"</c>: "quoted-string = DQUOTE
    /// *( qdtext / quoted-pair ) DQUOTE", "qdtext = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text" and "quoted-pair =
    /// "\" ( HTAB / SP / VCHAR / obs-text )", each quoted-pair read as the octet it quotes. A character outside qdtext,
    /// a quoted-pair outside its grammar, or a missing closing <c>"</c> fails the reading.
    /// </summary>
    /// <param name="text">The field value.</param>
    /// <param name="position">The position of the opening quote; left after the closing quote.</param>
    /// <returns>The unescaped value.</returns>
    private static string ReadQuotedString(string text, ref int position)
    {
        StringBuilder value = new();
        position++;
        while(position < text.Length)
        {
            char c = text[position];
            if(c == '"')
            {
                position++;

                return value.ToString();
            }

            bool isQuotedPair = c == '\\'
                && position + 1 < text.Length
                && text[position + 1] is '\t' or ' ' or (>= '\x21' and <= '\x7E') or (>= '\x80' and <= '\xFF');
            bool isQdText = c is '\t' or ' ' or '\x21' or (>= '\x23' and <= '\x5B') or (>= '\x5D' and <= '\x7E') or (>= '\x80' and <= '\xFF');
            if(isQuotedPair)
            {
                _ = value.Append(text[position + 1]);
                position += 2;
            }
            else if(isQdText)
            {
                _ = value.Append(c);
                position++;
            }
            else
            {
                throw new AssertFailedException($"U+{(int)c:X4} at position {position} is neither qdtext nor a quoted-pair: '{text}'.");
            }
        }

        throw new AssertFailedException($"The quoted-string is not closed: '{text}'.");
    }
}
