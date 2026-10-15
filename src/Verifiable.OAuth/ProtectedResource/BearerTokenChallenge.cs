using System.Text;
using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.ProtectedResource;

/// <summary>
/// The RFC 6750 §3 <c>WWW-Authenticate: Bearer</c> challenge: builds and parses
/// the header value a protected resource returns when a request lacks a valid
/// bearer token, over the RFC 9110 §11.2 <c>auth-param</c> grammar
/// (<see href="https://www.rfc-editor.org/rfc/rfc6750#section-3">RFC 6750 §3</see>).
/// </summary>
/// <remarks>
/// <para>
/// Each attribute is optional but §3 requires at least one auth-param after the
/// scheme: <c>realm</c> scopes the protection space, <c>error</c> and
/// <c>error_description</c> report why the request was declined (§3.1),
/// <c>scope</c> is the space-delimited list of scopes the resource requires
/// (RFC 6749 §3.3), and <c>resource_metadata</c> composes the RFC 9728 §5.1
/// metadata pointer into the same challenge — one header, one scheme, both
/// parameters. Its value formatting is delegated to
/// <see cref="ProtectedResourceChallenge"/>, and it reads back through both
/// <see cref="TryParse"/> and
/// <see cref="ProtectedResourceChallenge.TryReadResourceMetadata"/>.
/// </para>
/// <para>
/// §3.1 pairs the error codes with HTTP status codes the caller chooses — this
/// class owns the header value only, never the response status:
/// <c>invalid_request</c> → 400 Bad Request, <c>invalid_token</c>
/// (<see cref="OAuthErrors.InvalidToken"/>) → 401 Unauthorized, and
/// <c>insufficient_scope</c> (<see cref="OAuthErrors.InsufficientScope"/>) →
/// 403 Forbidden, where the challenge MAY carry the <c>scope</c> attribute
/// naming the scopes needed. When the request carried no authentication
/// information at all, §3.1 says the server SHOULD NOT include error
/// information — omit <c>error</c> and <c>error_description</c> then.
/// </para>
/// <para>
/// §3 restricts the representable values: <c>error</c> and
/// <c>error_description</c> to %x20-21 / %x23-5B / %x5D-7E, and <c>scope</c>
/// to space-delimited scope-tokens of %x21 / %x23-5B / %x5D-7E.
/// <see cref="BuildChallenge"/> rejects values outside those sets rather than
/// emit a non-conformant challenge.
/// </para>
/// </remarks>
public static class BearerTokenChallenge
{
    /// <summary>The UTF-8 source literal of <see cref="RealmParameter"/>.</summary>
    public static ReadOnlySpan<byte> RealmParameterUtf8 => "realm"u8;

    /// <summary>The <c>realm</c> challenge attribute name (RFC 6750 §3).</summary>
    public static string RealmParameter { get; } = Utf8Constants.ToInternedString(RealmParameterUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ErrorParameter"/>.</summary>
    public static ReadOnlySpan<byte> ErrorParameterUtf8 => "error"u8;

    /// <summary>The <c>error</c> challenge attribute name (RFC 6750 §3).</summary>
    public static string ErrorParameter { get; } = Utf8Constants.ToInternedString(ErrorParameterUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ErrorDescriptionParameter"/>.</summary>
    public static ReadOnlySpan<byte> ErrorDescriptionParameterUtf8 => "error_description"u8;

    /// <summary>The <c>error_description</c> challenge attribute name (RFC 6750 §3).</summary>
    public static string ErrorDescriptionParameter { get; } = Utf8Constants.ToInternedString(ErrorDescriptionParameterUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ScopeParameter"/>.</summary>
    public static ReadOnlySpan<byte> ScopeParameterUtf8 => "scope"u8;

    /// <summary>The <c>scope</c> challenge attribute name (RFC 6750 §3).</summary>
    public static string ScopeParameter { get; } = Utf8Constants.ToInternedString(ScopeParameterUtf8);

    /// <summary>The all-absent instance <see cref="TryParse"/> yields when parsing fails.</summary>
    private static BearerTokenChallengeParameters EmptyParameters { get; } = new(
        Realm: null, Error: null, ErrorDescription: null, Scope: null, ResourceMetadata: null);

    /// <summary>The all-absent instance <see cref="TryReadDpopChallenge"/> yields when the reading fails.</summary>
    private static DpopChallengeParameters EmptyDpopParameters { get; } = new(
        Realm: null, Error: null, ErrorDescription: null, Scope: null, Algorithms: null, ResourceMetadata: null);


    /// <summary>
    /// Builds a <c>WWW-Authenticate</c> Bearer challenge value from the
    /// supplied attributes, emitted in signature order:
    /// <c>Bearer realm="…", error="…", error_description="…", scope="…", resource_metadata="…"</c>.
    /// A <see langword="null"/> or empty string is treated as absent.
    /// </summary>
    /// <remarks>
    /// A caller that names an issuer as the <paramref name="realm"/> derives the realm from the issuer
    /// first, since an issuer may hold text outside the HTAB, SP and visible US-ASCII an
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.6.4">RFC 9110 Section 5.6.4</see>
    /// quoted-string carries: it writes the issuer in its URI form as
    /// <see href="https://www.rfc-editor.org/rfc/rfc3987#section-3.1">RFC 3987 Section 3.1</see> maps an
    /// IRI. The host is written in its IDNA ASCII form (<see cref="Uri.IdnHost"/>), the conversion of the
    /// ireg-name the section permits a system accepting IRIs to apply before its step 2: "Replace the
    /// ireg-name part of the IRI by the part converted using the ToASCII operation specified in section 4.1
    /// of [RFC3490] on each dot-separated label, and by using U+002E (FULL STOP) as a label separator, with
    /// the flag UseSTD3ASCIIRules set to TRUE, and with the flag AllowUnassigned set to FALSE for creating
    /// IRIs and set to TRUE otherwise." Every other character outside ASCII is written as the
    /// percent-encoding of its UTF-8 octets, the section's steps 2.1 and 2.2: "Convert the character to a
    /// sequence of one or more octets using UTF-8 [RFC3629]." and "Convert each octet to %HH, where HH is
    /// the hexadecimal notation of the octet value." The library's own
    /// realms are derived by that mapping, so no refusal the library composes reaches the throw below; the
    /// throw stays for a value the caller supplies, a defect of the caller's composition that this method
    /// refuses rather than emit a challenge a client cannot read.
    /// </remarks>
    /// <param name="realm">The protection-space identifier (§3); any content representable in an RFC 9110 §5.6.4 quoted-string.</param>
    /// <param name="error">The §3.1 error code, e.g. <see cref="OAuthErrors.InvalidToken"/>; characters in %x20-21 / %x23-5B / %x5D-7E.</param>
    /// <param name="errorDescription">The developer-readable explanation (§3); characters in %x20-21 / %x23-5B / %x5D-7E.</param>
    /// <param name="scope">The space-delimited scopes the resource requires (§3, RFC 6749 §3.3); scope-tokens of %x21 / %x23-5B / %x5D-7E.</param>
    /// <param name="resourceMetadata">The RFC 9728 §3 protected resource metadata URL, composed as the §5.1 <c>resource_metadata</c> auth-param.</param>
    /// <returns>The <c>WWW-Authenticate</c> header value.</returns>
    /// <exception cref="ArgumentException">
    /// Every attribute is absent (§3: the scheme MUST be followed by one or
    /// more auth-param values), or a value contains characters outside its §3
    /// charset and cannot be represented.
    /// </exception>
    public static string BuildChallenge(
        string? realm = null,
        string? error = null,
        string? errorDescription = null,
        string? scope = null,
        Uri? resourceMetadata = null)
    {
        bool hasRealm = !string.IsNullOrEmpty(realm);
        bool hasError = !string.IsNullOrEmpty(error);
        bool hasErrorDescription = !string.IsNullOrEmpty(errorDescription);
        bool hasScope = !string.IsNullOrEmpty(scope);

        if(!hasRealm && !hasError && !hasErrorDescription && !hasScope && resourceMetadata is null)
        {
            throw new ArgumentException(
                "At least one attribute is required: the Bearer scheme MUST be followed by one or more auth-param values (RFC 6750 §3).");
        }

        if(hasRealm && !IsQuotedStringRepresentable(realm!))
        {
            throw new ArgumentException(
                "realm contains characters that cannot be represented in an RFC 9110 §5.6.4 quoted-string.", nameof(realm));
        }

        if(hasError && !IsWithinNqsCharset(error!))
        {
            throw new ArgumentException(
                "error contains characters outside %x20-21 / %x23-5B / %x5D-7E (RFC 6750 §3).", nameof(error));
        }

        if(hasErrorDescription && !IsWithinNqsCharset(errorDescription!))
        {
            throw new ArgumentException(
                "error_description contains characters outside %x20-21 / %x23-5B / %x5D-7E (RFC 6750 §3).", nameof(errorDescription));
        }

        if(hasScope && !ScopeTokenSyntax.IsScopeList(scope!))
        {
            throw new ArgumentException(
                "scope must be single-space-delimited scope-tokens of %x21 / %x23-5B / %x5D-7E characters (RFC 6750 §3).", nameof(scope));
        }

        StringBuilder builder = new();
        _ = builder.Append(WellKnownAuthenticationSchemes.Bearer);
        bool isFirstParameter = true;

        if(hasRealm)
        {
            AppendQuotedParameter(builder, RealmParameter, realm!, ref isFirstParameter);
        }

        if(hasError)
        {
            AppendQuotedParameter(builder, ErrorParameter, error!, ref isFirstParameter);
        }

        if(hasErrorDescription)
        {
            AppendQuotedParameter(builder, ErrorDescriptionParameter, errorDescription!, ref isFirstParameter);
        }

        if(hasScope)
        {
            AppendQuotedParameter(builder, ScopeParameter, scope!, ref isFirstParameter);
        }

        if(resourceMetadata is not null)
        {
            //The RFC 9728 §5.1 value formatting (quoted-string escaping of the
            //URL) stays with ProtectedResourceChallenge — the scheme prefix its
            //challenge carries is sliced off so the auth-param joins this
            //challenge's list instead of duplicating the quoting rules here.
            string composed = ProtectedResourceChallenge.BuildChallenge(
                WellKnownAuthenticationSchemes.Bearer, resourceMetadata);
            _ = builder.Append(isFirstParameter ? " " : ", ");
            _ = builder.Append(composed.AsSpan(WellKnownAuthenticationSchemes.Bearer.Length + 1));
        }

        return builder.ToString();
    }


    /// <summary>
    /// Parses the <c>Bearer</c> challenge of a <c>WWW-Authenticate</c> field value into its
    /// RFC 6750 Section 3 attributes. The value is read as the challenge list of
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.6.1">RFC 9110 Section 11.6.1</see>,
    /// "WWW-Authenticate = #challenge", whose value "might contain more than one challenge", and
    /// the one challenge of the <c>Bearer</c> scheme among them is parsed, so a value naming
    /// <c>Bearer</c> beside another scheme, as a resource serving both <c>Bearer</c> and
    /// <c>DPoP</c> answers (RFC 9449 Section 7.2), yields its <c>Bearer</c> attributes.
    /// Attribute names compare case-insensitively and values may
    /// be tokens or quoted strings per the RFC 9110 §11.2 <c>auth-param</c>
    /// grammar; attributes beyond the five recognized here are ignored (§3
    /// allows other auth-params).
    /// </summary>
    /// <param name="challengeValue">The header value, e.g. <c>Bearer realm="example", error="invalid_token"</c>.</param>
    /// <param name="parameters">The parsed attributes; all absent when parsing fails.</param>
    /// <returns>
    /// <see langword="false"/> when the value holds no <c>Bearer</c> challenge or more than one
    /// (two are no one challenge, as <see cref="TryReadChallenge"/> states), no
    /// auth-param follows the scheme (RFC 6750 Section 3: one or more required), the challenge
    /// grammar is violated, a parameter name repeats (RFC 9110 Section 11.2: each
    /// parameter name "MUST only occur once per challenge"), or
    /// <c>resource_metadata</c> is not an absolute URI.
    /// </returns>
    public static bool TryParse(string challengeValue, out BearerTokenChallengeParameters parameters) =>
        TryParseChallenge(challengeValue, WellKnownAuthenticationSchemes.Bearer, out parameters);


    /// <summary>
    /// Parses the challenge of the scheme <paramref name="scheme"/> in a <c>WWW-Authenticate</c> field value into the
    /// RFC 6750 Section 3 attributes, by the grammar and refusals <see cref="TryParse"/> states for <c>Bearer</c>:
    /// the value is read as a challenge list, as one field line of <see cref="TryReadChallenge"/>, and exactly one of
    /// its challenges is of the scheme.
    /// </summary>
    /// <param name="challengeValue">The header value, e.g. <c>DPoP error="use_dpop_nonce", algs="ES256"</c>.</param>
    /// <param name="scheme">The authentication scheme the challenge names, compared case-insensitively (RFC 9110 Section 11.1).</param>
    /// <param name="parameters">The parsed attributes; all absent when parsing fails.</param>
    /// <returns><see langword="false"/> when the value holds no challenge of <paramref name="scheme"/>, more than one, or is refused as <see cref="TryParse"/> states.</returns>
    internal static bool TryParseChallenge(string challengeValue, string scheme, out BearerTokenChallengeParameters parameters)
    {
        ArgumentNullException.ThrowIfNull(challengeValue);
        ArgumentException.ThrowIfNullOrEmpty(scheme);

        return TryReadChallenge([challengeValue], scheme, out parameters);
    }


    /// <summary>
    /// Reads the one challenge of the scheme <paramref name="scheme"/> out of every <c>WWW-Authenticate</c> field
    /// line of a response, into the RFC 6750 Section 3 attributes.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.6.1">RFC 9110 Section 11.6.1</see>:
    /// "WWW-Authenticate = #challenge", and "User agents are advised to take special care in parsing the field value,
    /// as it might contain more than one challenge, and each challenge can contain a comma-separated list of
    /// authentication parameters. Furthermore, the header field itself can occur multiple times." The field lines are
    /// one field value: <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.3">RFC 9110 Section 5.3</see>, "A
    /// recipient MAY combine multiple field lines within a field section that have the same field name into one field
    /// line, without changing the semantics of the message, by appending each subsequent field line value to the initial
    /// field line value in order, separated by a comma (",") and optional whitespace", so the lines are joined in the
    /// order they were received with a comma and SP and the combined value is read once as a challenge list
    /// (<see cref="TryReadChallengeList"/>); a challenge's auth-params may continue on the next field line. Any
    /// challenge of the value outside the grammar fails the whole reading, a well-formed challenge of
    /// <paramref name="scheme"/> beside it included: that is the library's own rule. RFC 9110 gives no recovery rule for
    /// a list outside its grammar, and an element-wise recovery could not tell where a malformed element ends, so a
    /// challenge read past it could be the tail of the malformed one. The challenges of <paramref name="scheme"/>, its name compared
    /// case-insensitively as <see cref="WellKnownAuthenticationSchemes"/> compares a scheme, are selected; exactly one
    /// must be present.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.5">RFC 9110 Section 11.5</see> lets a response
    /// carry "multiple challenges with the same auth-scheme but with different realms", and reading two of them as no
    /// one challenge is the library's own rule: neither states which of them the caller is to act on. The
    /// <c>DPoP</c> challenge carries the attributes the <c>Bearer</c> one does:
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see> names its
    /// <c>realm</c>, <c>scope</c>, <c>error</c> and <c>error_description</c> parameters by
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3">RFC 6750 Section 3</see>, and "unknown
    /// parameters MUST be ignored by recipients", as this reader ignores every parameter it does not read.
    /// </summary>
    /// <param name="fieldLines">Every <c>WWW-Authenticate</c> field line of the response, in received order.</param>
    /// <param name="scheme">The authentication scheme whose challenge is read.</param>
    /// <param name="parameters">The attributes of that challenge; all absent when the reading fails.</param>
    /// <returns><see langword="true"/> when the lines hold exactly one challenge of <paramref name="scheme"/>, read as <see cref="TryParse"/> states.</returns>
    internal static bool TryReadChallenge(IReadOnlyList<string> fieldLines, string scheme, out BearerTokenChallengeParameters parameters)
    {
        ArgumentNullException.ThrowIfNull(fieldLines);
        ArgumentException.ThrowIfNullOrEmpty(scheme);

        parameters = EmptyParameters;
        if(!TryReadOneChallengeOf(fieldLines, scheme, out ParsedChallenge? challenge))
        {
            return false;
        }

        return TryReadAttributes(challenge!, out parameters);
    }


    /// <summary>
    /// Reads the one <c>DPoP</c> challenge out of every <c>WWW-Authenticate</c> field line of a response, into the
    /// parameters <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see> names for
    /// the scheme, by the challenge-list reading <see cref="TryReadChallenge"/> states: the lines are combined as one
    /// field value, any challenge outside the grammar fails the reading, and exactly one challenge of the scheme must be
    /// present (<see cref="TryReadOneChallengeOf"/>). The challenge carries its parameters as auth-params; a token68 is
    /// refused. A challenge of the scheme alone, with no auth-param, is read with every parameter absent:
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.3">RFC 9110 Section 11.3</see> writes "challenge
    /// = auth-scheme [ 1*SP ( token68 / #auth-param ) ]", and RFC 9449 requires no parameter of the <c>DPoP</c>
    /// scheme. <c>realm</c>, <c>error</c>, <c>error_description</c>, <c>scope</c> and <c>resource_metadata</c> are read
    /// as <see cref="TryReadAttributes"/> reads them, an unusable <c>resource_metadata</c> refusing the reading;
    /// <c>algs</c> is read by <see cref="FindParameter"/> and split into its names at each SP, an empty name passed
    /// over, so a malformed <c>algs</c> never hides the <c>error</c> a client acts on. Section 7.1: "unknown parameters
    /// MUST be ignored by recipients"; a parameter of any other name is ignored.
    /// </summary>
    /// <param name="fieldLines">Every <c>WWW-Authenticate</c> field line of the response, in received order.</param>
    /// <param name="parameters">The parameters of the one <c>DPoP</c> challenge; all absent when the reading fails.</param>
    /// <returns><see langword="true"/> when the lines hold exactly one <c>DPoP</c> challenge, read as stated.</returns>
    internal static bool TryReadDpopChallenge(IReadOnlyList<string> fieldLines, out DpopChallengeParameters parameters)
    {
        ArgumentNullException.ThrowIfNull(fieldLines);

        parameters = EmptyDpopParameters;
        if(!TryReadOneChallengeOf(fieldLines, WellKnownAuthenticationSchemes.DPoP, out ParsedChallenge? challenge)
            || challenge!.Token68 is not null
            || !TryReadResourceMetadata(challenge, out Uri? resourceMetadata))
        {
            return false;
        }

        string? algorithmsValue = FindParameter(challenge, DpopChallenge.AlgorithmsParameter);
        IReadOnlyList<string>? algorithms = algorithmsValue?.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        parameters = new DpopChallengeParameters(
            FindParameter(challenge, RealmParameter),
            FindParameter(challenge, ErrorParameter),
            FindParameter(challenge, ErrorDescriptionParameter),
            FindParameter(challenge, ScopeParameter),
            algorithms,
            resourceMetadata);

        return true;
    }


    /// <summary>
    /// Selects the one challenge of the scheme <paramref name="scheme"/> from every <c>WWW-Authenticate</c> field line
    /// of a response: the lines are joined in received order with a comma and SP and read once as a challenge list
    /// (<see cref="TryReadChallengeList"/>), and the challenges whose scheme equals <paramref name="scheme"/>, compared
    /// case-insensitively as <see cref="WellKnownAuthenticationSchemes"/> compares a scheme, are selected. Exactly one
    /// must be present; two of one scheme are no one challenge, the library's own rule <see cref="TryReadChallenge"/>
    /// states. The one selection both <see cref="TryReadChallenge"/> and <see cref="TryReadDpopChallenge"/> read
    /// through, so either scheme is read by one grammar.
    /// </summary>
    /// <param name="fieldLines">Every <c>WWW-Authenticate</c> field line of the response, in received order.</param>
    /// <param name="scheme">The authentication scheme whose challenge is selected.</param>
    /// <param name="challenge">The one challenge of <paramref name="scheme"/>, or <see langword="null"/> when the selection fails.</param>
    /// <returns><see langword="true"/> when the lines are within the grammar and hold exactly one challenge of <paramref name="scheme"/>.</returns>
    private static bool TryReadOneChallengeOf(IReadOnlyList<string> fieldLines, string scheme, out ParsedChallenge? challenge)
    {
        challenge = null;
        List<ParsedChallenge> challenges = [];
        if(!TryReadChallengeList(string.Join(", ", fieldLines), challenges))
        {
            return false;
        }

        List<ParsedChallenge> ofScheme = [.. challenges.Where(candidate => WellKnownAuthenticationSchemes.Equals(candidate.Scheme, scheme))];
        if(ofScheme.Count != 1)
        {
            return false;
        }

        challenge = ofScheme[0];

        return true;
    }


    /// <summary>
    /// Reads every challenge of a field value, one field line or the field lines combined by
    /// <see cref="TryReadChallenge"/>, into <paramref name="challenges"/>, by the grammar of
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.6.1">RFC 9110 Section 11.6.1</see>,
    /// "WWW-Authenticate = #challenge", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.3">Section 11.3</see>, "challenge = auth-scheme
    /// [ 1*SP ( token68 / #auth-param ) ]". The list elements are separated by commas and optional whitespace, and an
    /// empty element is skipped (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.6.1.2">Section
    /// 5.6.1.2</see>: "A recipient MUST parse and ignore a reasonable number of empty list elements", the list being
    /// "#element => [ element ] *( OWS "," OWS [ element ] )"). A challenge starts with its scheme token. Optional
    /// whitespace (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.6.3">Section 5.6.3</see>, "OWS = *( SP /
    /// HTAB )") followed by a comma or the end is the list's whitespace and ends the challenge without content, unless
    /// the whitespace opens with SP and, past the empty elements, an auth-param follows: that auth-param begins the
    /// challenge's <c>#auth-param</c> list, whose first elements are empty (<see cref="TryReadAuthParams"/>). Otherwise the
    /// scheme is followed by at least one SP and then its content (<see cref="TryReadChallengeContent"/>); any other
    /// character after the scheme, a horizontal tab among them, fails the reading.
    /// </summary>
    /// <param name="fieldLine">The field value.</param>
    /// <param name="challenges">The list the challenges read are appended to.</param>
    /// <returns><see langword="false"/> when the value is outside the grammar.</returns>
    private static bool TryReadChallengeList(string fieldLine, List<ParsedChallenge> challenges)
    {
        int position = 0;
        while(true)
        {
            position = SkipListSeparators(fieldLine, position);
            if(position >= fieldLine.Length)
            {
                return true;
            }

            int schemeStart = position;
            position = SkipToken(fieldLine, position);
            if(position == schemeStart)
            {
                return false;
            }

            ParsedChallenge challenge = new(fieldLine[schemeStart..position]);
            challenges.Add(challenge);
            bool isSpaceAfterScheme = position < fieldLine.Length && fieldLine[position] == ' ';
            int afterWhitespace = SkipOptionalWhitespace(fieldLine, position);
            if(afterWhitespace >= fieldLine.Length || fieldLine[afterWhitespace] == ',')
            {
                //Whitespace then a comma or the end: the list's OWS (Section 5.6.1.2), and the challenge has no
                //content, unless SP opened its #auth-param and an auth-param follows the empty elements.
                int nextElement = SkipListSeparators(fieldLine, afterWhitespace);
                if(isSpaceAfterScheme && nextElement < fieldLine.Length && IsAuthParamAt(fieldLine, nextElement))
                {
                    position = nextElement;
                    if(!TryReadAuthParams(fieldLine, ref position, challenge))
                    {
                        return false;
                    }

                    continue;
                }

                position = afterWhitespace;

                continue;
            }

            //RFC 9110 Section 11.3: the scheme and its content are separated by 1*SP.
            if(!isSpaceAfterScheme)
            {
                return false;
            }

            position = SkipSpaces(fieldLine, position);
            if(!TryReadChallengeContent(fieldLine, ref position, challenge))
            {
                return false;
            }
        }
    }


    /// <summary>
    /// Reads the content of one challenge starting at <paramref name="position"/>, the first character after the
    /// scheme's SP: either one token68
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.2">RFC 9110 Section 11.2</see>, "token68 = 1*(
    /// ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"=""), which ends the element, or its comma-separated
    /// auth-params (<see cref="TryReadAuthParams"/>), so a token68 and auth-params never mix in one challenge.
    /// </summary>
    /// <param name="fieldLine">The field line.</param>
    /// <param name="position">The position of the content; left at the next challenge or the end of the line.</param>
    /// <param name="challenge">The challenge the content is read into.</param>
    /// <returns><see langword="false"/> when the content is outside the grammar.</returns>
    private static bool TryReadChallengeContent(string fieldLine, ref int position, ParsedChallenge challenge)
    {
        int token68End = SkipToken68(fieldLine, position);
        if(token68End > position)
        {
            int afterToken68 = SkipOptionalWhitespace(fieldLine, token68End);
            if(afterToken68 >= fieldLine.Length || fieldLine[afterToken68] == ',')
            {
                challenge.Token68 = fieldLine[position..token68End];
                position = afterToken68;

                return true;
            }
        }

        return TryReadAuthParams(fieldLine, ref position, challenge);
    }


    /// <summary>
    /// Reads the comma-separated auth-params of one challenge starting at the auth-param at <paramref name="position"/>
    /// (<see cref="TryReadAuthParam"/>). After an auth-param, the list elements that are empty are passed over, an
    /// element that is a token followed by <c>=</c> is the next auth-param of this challenge, and any other element
    /// starts the next challenge. Section 11.2: "Authentication parameters are name/value pairs, where the name token
    /// is matched case-insensitively and each parameter name MUST only occur once per challenge."; a name repeated in
    /// any case fails the reading. The names read are kept in the challenge's
    /// <see cref="ParsedChallenge.ParameterNames"/>, a set compared case-insensitively, so each name is checked against
    /// those before it in one lookup and the reading of a challenge stays linear in its length.
    /// </summary>
    /// <param name="fieldLine">The field line.</param>
    /// <param name="position">The position of the first auth-param; left at the next challenge or the end of the line.</param>
    /// <param name="challenge">The challenge the auth-params are read into.</param>
    /// <returns><see langword="false"/> when the auth-params are outside the grammar.</returns>
    private static bool TryReadAuthParams(string fieldLine, ref int position, ParsedChallenge challenge)
    {
        while(true)
        {
            if(!TryReadAuthParam(fieldLine, ref position, out string name, out string value))
            {
                return false;
            }

            if(!challenge.ParameterNames.Add(name))
            {
                return false;
            }

            challenge.Parameters.Add((name, value));

            position = SkipOptionalWhitespace(fieldLine, position);
            if(position >= fieldLine.Length)
            {
                return true;
            }

            if(fieldLine[position] != ',')
            {
                return false;
            }

            position = SkipListSeparators(fieldLine, position);
            if(position >= fieldLine.Length || !IsAuthParamAt(fieldLine, position))
            {
                return true;
            }
        }
    }


    /// <summary>
    /// Reads one auth-param starting at <paramref name="position"/>:
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.2">RFC 9110 Section 11.2</see>, "auth-param =
    /// token BWS "=" BWS ( token / quoted-string )". A quoted-string value is read by
    /// <see cref="ReadQuotedString"/>; any other value is a token.
    /// </summary>
    /// <param name="fieldLine">The field line.</param>
    /// <param name="position">The position of the name; left after the value.</param>
    /// <param name="name">The parameter name as written.</param>
    /// <param name="value">The parameter value, a quoted-string's quoted-pairs replaced by the octets they quote.</param>
    /// <returns><see langword="false"/> when the auth-param is outside the grammar.</returns>
    private static bool TryReadAuthParam(string fieldLine, ref int position, out string name, out string value)
    {
        name = string.Empty;
        value = string.Empty;

        int nameStart = position;
        position = SkipToken(fieldLine, position);
        if(position == nameStart)
        {
            return false;
        }

        name = fieldLine[nameStart..position];

        position = SkipOptionalWhitespace(fieldLine, position);
        if(position >= fieldLine.Length || fieldLine[position] != '=')
        {
            return false;
        }

        position = SkipOptionalWhitespace(fieldLine, position + 1);
        if(position >= fieldLine.Length)
        {
            return false;
        }

        string? read = fieldLine[position] == '"'
            ? ReadQuotedString(fieldLine, ref position)
            : ReadToken(fieldLine, ref position);
        if(read is null)
        {
            return false;
        }

        value = read;

        return true;
    }


    /// <summary>
    /// Reads the RFC 6750 Section 3 attributes of <paramref name="challenge"/>. The scheme "MUST be followed by one or
    /// more auth-param values", so a challenge carrying a token68 or nothing is refused. Each attribute is read by its
    /// name (<see cref="FindParameter"/>); a parameter of another name is ignored. <c>resource_metadata</c> is held to
    /// an absolute http or https URL, the library's own reading <see cref="TryReadResourceMetadata"/> states.
    /// </summary>
    /// <param name="challenge">The challenge read from the field line.</param>
    /// <param name="parameters">The attributes; all absent when the challenge is refused.</param>
    /// <returns><see langword="false"/> when the challenge carries no auth-param or an unusable <c>resource_metadata</c>.</returns>
    private static bool TryReadAttributes(ParsedChallenge challenge, out BearerTokenChallengeParameters parameters)
    {
        parameters = EmptyParameters;

        if(challenge.Token68 is not null || challenge.Parameters.Count == 0)
        {
            return false;
        }

        if(!TryReadResourceMetadata(challenge, out Uri? resourceMetadata))
        {
            return false;
        }

        parameters = new BearerTokenChallengeParameters(
            FindParameter(challenge, RealmParameter),
            FindParameter(challenge, ErrorParameter),
            FindParameter(challenge, ErrorDescriptionParameter),
            FindParameter(challenge, ScopeParameter),
            resourceMetadata);

        return true;
    }


    /// <summary>
    /// Reads the <c>resource_metadata</c> auth-param of <paramref name="challenge"/>, which the library's own reading
    /// holds to an absolute http or https URL. <see href="https://www.rfc-editor.org/rfc/rfc9728#section-5.1">RFC 9728
    /// Section 5.1</see> says only "resource_metadata: The URL of the protected resource metadata."; the https half
    /// rests on <see href="https://www.rfc-editor.org/rfc/rfc9728#section-1.2">Section 1.2</see>, "Resource Identifier:
    /// The protected resource's resource identifier, which is a URL that uses the https scheme", from which
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3">Section 3</see> forms the metadata URL "by inserting
    /// a well-known URI string into the protected resource's resource identifier". An http URL is read as the
    /// parameter carries it, and the application's fetch policy decides what is fetched.
    /// </summary>
    /// <param name="challenge">The challenge read from the field line.</param>
    /// <param name="resourceMetadata">The URL, or <see langword="null"/> when the challenge carries no such parameter or it is unusable.</param>
    /// <returns><see langword="false"/> when the parameter is present and not an absolute http or https URL.</returns>
    private static bool TryReadResourceMetadata(ParsedChallenge challenge, out Uri? resourceMetadata)
    {
        resourceMetadata = null;
        string? resourceMetadataValue = FindParameter(challenge, ProtectedResourceChallenge.ResourceMetadataParameter);
        if(resourceMetadataValue is null)
        {
            return true;
        }

        if(!Uri.TryCreate(resourceMetadataValue, UriKind.Absolute, out Uri? candidate)
            || (candidate.Scheme != Uri.UriSchemeHttps && candidate.Scheme != Uri.UriSchemeHttp))
        {
            return false;
        }

        resourceMetadata = candidate;

        return true;
    }


    /// <summary>
    /// The value of the auth-param of <paramref name="challenge"/> named <paramref name="parameterName"/>, the names
    /// compared by <see cref="IsParameterName"/>. The names of one challenge are unique, which
    /// <see cref="TryReadAuthParams"/> holds, so at most one parameter matches.
    /// </summary>
    /// <param name="challenge">The challenge.</param>
    /// <param name="parameterName">The parameter name sought.</param>
    /// <returns>The value, or <see langword="null"/> when the challenge carries no such parameter.</returns>
    private static string? FindParameter(ParsedChallenge challenge, string parameterName)
    {
        string? found = null;
        foreach((string name, string value) in challenge.Parameters)
        {
            if(IsParameterName(name, parameterName))
            {
                found = value;
            }
        }

        return found;
    }


    /// <summary>
    /// Appends <c>{name}="{value}"</c> preceded by the scheme separator (one SP, RFC 9110 Section 11.3: "challenge =
    /// auth-scheme [ 1*SP ( token68 / #auth-param ) ]") or the auth-param list separator (<c>, </c>), with the
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.6.4">RFC 9110 Section 5.6.4</see> quoted-string
    /// escaping of <c>"</c> and <c>\</c> in <paramref name="value"/> ("quoted-pair = "\" ( HTAB / SP / VCHAR / obs-text
    /// )"). The one place an auth-param is written for <see cref="BuildChallenge"/> and <see cref="DpopChallenge.BuildChallenge"/>,
    /// so both schemes write a parameter the same way; the caller has checked the value against its character set.
    /// </summary>
    /// <param name="builder">The challenge being written.</param>
    /// <param name="name">The auth-param name.</param>
    /// <param name="value">The value, written as a quoted-string.</param>
    /// <param name="isFirstParameter">Whether no parameter has been written yet; set to <see langword="false"/> once this one is.</param>
    internal static void AppendQuotedParameter(StringBuilder builder, string name, string value, ref bool isFirstParameter)
    {
        string escaped = value
            .Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("\"", "\\\"", StringComparison.Ordinal);
        _ = builder.Append(isFirstParameter ? " " : ", ");
        _ = builder.Append(name).Append("=\"").Append(escaped).Append('"');
        isFirstParameter = false;
    }


    /// <summary>
    /// Compares auth-param names per RFC 9110 §11.2: case-insensitively.
    /// </summary>
    private static bool IsParameterName(string name, string parameterName) =>
        string.Equals(name, parameterName, StringComparison.OrdinalIgnoreCase);


    /// <summary>
    /// The RFC 6749 Appendix A NQSCHAR set restated by RFC 6750 §3 for
    /// <c>error</c> and <c>error_description</c>: %x20-21 / %x23-5B / %x5D-7E.
    /// </summary>
    private static bool IsNqsChar(char c) =>
        c is (>= ' ' and <= '!') or (>= '#' and <= '[') or (>= ']' and <= '~');


    /// <summary>
    /// Whether every character of <paramref name="value"/> is within the set
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3">RFC 6750 Section 3</see> gives the <c>error</c> and
    /// <c>error_description</c> attributes: "Values for the "error" and "error_description" attributes ... MUST NOT
    /// include characters outside the set %x20-21 / %x23-5B / %x5D-7E." The one check of that set for
    /// <see cref="BuildChallenge"/> and <see cref="DpopChallenge.BuildChallenge"/>, the <c>DPoP</c> challenge naming its
    /// <c>error</c> by RFC 6750 Section 3 (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449
    /// Section 7.1</see>).
    /// </summary>
    /// <param name="value">The attribute value.</param>
    /// <returns><see langword="true"/> when every character is within the set.</returns>
    internal static bool IsWithinNqsCharset(string value)
    {
        foreach(char c in value)
        {
            if(!IsNqsChar(c))
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>
    /// Whether every character is representable in an
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.6.4">RFC 9110 Section 5.6.4</see> quoted-string as
    /// the library writes one: HTAB, SP, or a visible ASCII character, <c>"</c> and <c>\</c> being representable through
    /// quoted-pair escaping ("qdtext = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text"). The one check of a
    /// <c>realm</c> value for <see cref="BuildChallenge"/> and <see cref="DpopChallenge.BuildChallenge"/>; RFC 9110
    /// Section 11.5 says of the realm: "For historical reasons, a sender MUST only generate the quoted-string syntax."
    /// </summary>
    /// <param name="value">The value.</param>
    /// <returns><see langword="true"/> when every character is HTAB, SP or visible ASCII.</returns>
    internal static bool IsQuotedStringRepresentable(string value)
    {
        foreach(char c in value)
        {
            bool isRepresentable = c is '\t' or (>= ' ' and <= '~');
            if(!isRepresentable)
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>
    /// Whether <paramref name="c"/> is a tchar of <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.6.2">RFC
    /// 9110 Section 5.6.2</see>: "!" / "#" / "$" / "%" / "&amp;" / "'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" /
    /// "~" / DIGIT / ALPHA, visible ASCII except delimiters. The one check of a token for the challenge-list reader and
    /// for <see cref="DpopChallenge.BuildChallenge"/>, which holds each name of its <c>algs</c> value to it.
    /// </summary>
    /// <param name="c">The character.</param>
    /// <returns><see langword="true"/> for a tchar.</returns>
    internal static bool IsTokenChar(char c) =>
        c is (>= '0' and <= '9') or (>= 'a' and <= 'z') or (>= 'A' and <= 'Z')
        or '!' or '#' or '$' or '%' or '&' or '\'' or '*' or '+' or '-' or '.'
        or '^' or '_' or '`' or '|' or '~';


    /// <summary>Skips optional whitespace, <c>OWS</c> and <c>BWS</c> of RFC 9110 Section 5.6.3: spaces and horizontal tabs.</summary>
    /// <param name="value">The field line.</param>
    /// <param name="position">The position to start at.</param>
    /// <returns>The position of the next character that is neither.</returns>
    private static int SkipOptionalWhitespace(string value, int position)
    {
        while(position < value.Length && (value[position] == ' ' || value[position] == '\t'))
        {
            position++;
        }

        return position;
    }


    /// <summary>Skips the run of SP that RFC 9110 Section 11.3 places between a challenge's scheme and its content.</summary>
    /// <param name="value">The field line.</param>
    /// <param name="position">The position to start at.</param>
    /// <returns>The position of the next character that is no SP.</returns>
    private static int SkipSpaces(string value, int position)
    {
        while(position < value.Length && value[position] == ' ')
        {
            position++;
        }

        return position;
    }


    /// <summary>
    /// Skips the separators between list elements, optional whitespace and commas, so that an empty element is
    /// passed over (RFC 9110 Section 5.6.1.2).
    /// </summary>
    /// <param name="value">The field line.</param>
    /// <param name="position">The position to start at.</param>
    /// <returns>The position of the next character that is no separator.</returns>
    private static int SkipListSeparators(string value, int position)
    {
        while(position < value.Length && (value[position] == ' ' || value[position] == '\t' || value[position] == ','))
        {
            position++;
        }

        return position;
    }


    /// <summary>Skips the run of RFC 9110 Section 5.6.2 tchar starting at <paramref name="position"/>.</summary>
    /// <param name="value">The field line.</param>
    /// <param name="position">The position to start at.</param>
    /// <returns>The position after the token; equal to <paramref name="position"/> when no token starts there.</returns>
    private static int SkipToken(string value, int position)
    {
        while(position < value.Length && IsTokenChar(value[position]))
        {
            position++;
        }

        return position;
    }


    /// <summary>
    /// Skips a token68 starting at <paramref name="position"/>, RFC 9110 Section 11.2: "token68 = 1*( ALPHA / DIGIT /
    /// "-" / "." / "_" / "~" / "+" / "/" ) *"="".
    /// </summary>
    /// <param name="value">The field line.</param>
    /// <param name="position">The position to start at.</param>
    /// <returns>The position after the token68; equal to <paramref name="position"/> when none starts there.</returns>
    private static int SkipToken68(string value, int position)
    {
        int end = position;
        while(end < value.Length && IsToken68Char(value[end]))
        {
            end++;
        }

        if(end == position)
        {
            return position;
        }

        while(end < value.Length && value[end] == '=')
        {
            end++;
        }

        return end;
    }


    /// <summary>
    /// Whether the list element at <paramref name="position"/> is an auth-param: a token followed, after optional
    /// whitespace, by <c>=</c>. RFC 9110 Section 11.6.1: a challenge "can contain a comma-separated list of
    /// authentication parameters", and an element that is not one starts the next challenge.
    /// </summary>
    /// <param name="value">The field line.</param>
    /// <param name="position">The position of the element.</param>
    /// <returns><see langword="true"/> when the element is an auth-param.</returns>
    private static bool IsAuthParamAt(string value, int position)
    {
        int afterToken = SkipToken(value, position);
        if(afterToken == position)
        {
            return false;
        }

        int afterWhitespace = SkipOptionalWhitespace(value, afterToken);

        return afterWhitespace < value.Length && value[afterWhitespace] == '=';
    }


    /// <summary>
    /// Reads the quoted-string of <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.6.4">RFC 9110 Section
    /// 5.6.4</see> starting at the DQUOTE at <paramref name="position"/>: "quoted-string = DQUOTE *( qdtext /
    /// quoted-pair ) DQUOTE", "qdtext = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text" and "quoted-pair = "\" (
    /// HTAB / SP / VCHAR / obs-text )". "Recipients that process the value of a quoted-string MUST handle a
    /// quoted-pair as if it were replaced by the octet following the backslash." A character outside qdtext, a
    /// quoted-pair outside its grammar, or a missing closing DQUOTE makes the value malformed.
    /// </summary>
    /// <param name="value">The field line.</param>
    /// <param name="position">The position of the opening DQUOTE; left after the closing DQUOTE.</param>
    /// <returns>The value, or <see langword="null"/> when the quoted-string is malformed.</returns>
    private static string? ReadQuotedString(string value, ref int position)
    {
        StringBuilder builder = new();
        int index = position + 1;
        while(index < value.Length)
        {
            char c = value[index];
            if(c == '"')
            {
                position = index + 1;

                return builder.ToString();
            }

            if(c == '\\')
            {
                if(index + 1 >= value.Length || !IsQuotedPairOctet(value[index + 1]))
                {
                    return null;
                }

                _ = builder.Append(value[index + 1]);
                index += 2;

                continue;
            }

            if(!IsQdText(c))
            {
                return null;
            }

            _ = builder.Append(c);
            index++;
        }

        return null;
    }


    /// <summary>
    /// Reads a token value starting at <paramref name="position"/> and advances past it, RFC 9110 Section 11.2 letting
    /// a parameter value be a token as well as a quoted-string.
    /// </summary>
    /// <param name="value">The field line.</param>
    /// <param name="position">The position of the value; left after it.</param>
    /// <returns>The token, or <see langword="null"/> when no token starts there.</returns>
    private static string? ReadToken(string value, ref int position)
    {
        int start = position;
        position = SkipToken(value, position);

        return position > start ? value[start..position] : null;
    }


    /// <summary>Whether <paramref name="c"/> is a qdtext of RFC 9110 Section 5.6.4: HTAB, SP, %x21, %x23-5B, %x5D-7E or obs-text (%x80-FF).</summary>
    /// <param name="c">The character.</param>
    /// <returns><see langword="true"/> for a qdtext character.</returns>
    private static bool IsQdText(char c) =>
        c is '\t' or ' ' or '!' or (>= '#' and <= '[') or (>= ']' and <= '~') or (>= (char)0x80 and <= (char)0xFF);


    /// <summary>Whether <paramref name="c"/> may follow the backslash of a quoted-pair, RFC 9110 Section 5.6.4: HTAB, SP, VCHAR (%x21-7E) or obs-text (%x80-FF).</summary>
    /// <param name="c">The character.</param>
    /// <returns><see langword="true"/> for an octet a quoted-pair quotes.</returns>
    private static bool IsQuotedPairOctet(char c) =>
        c is '\t' or ' ' or (>= '!' and <= '~') or (>= (char)0x80 and <= (char)0xFF);


    /// <summary>Whether <paramref name="c"/> is a token68 character before its trailing <c>=</c> run, RFC 9110 Section 11.2.</summary>
    /// <param name="c">The character.</param>
    /// <returns><see langword="true"/> for ALPHA, DIGIT, <c>-</c>, <c>.</c>, <c>_</c>, <c>~</c>, <c>+</c> and <c>/</c>.</returns>
    private static bool IsToken68Char(char c) =>
        c is (>= '0' and <= '9') or (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or '-' or '.' or '_' or '~' or '+' or '/';


    /// <summary>
    /// One challenge read from a <c>WWW-Authenticate</c> field line: its scheme, and either the token68 or the
    /// auth-params it carries, in the order written.
    /// </summary>
    /// <param name="scheme">The auth-scheme as written.</param>
    private sealed class ParsedChallenge(string scheme)
    {
        /// <summary>The auth-scheme as written.</summary>
        public string Scheme { get; } = scheme;

        /// <summary>The token68 the challenge carries, or <see langword="null"/> when it carries auth-params or nothing.</summary>
        public string? Token68 { get; set; }

        /// <summary>The auth-params, each name as written with its value, in the order written.</summary>
        public List<(string Name, string Value)> Parameters { get; } = [];

        /// <summary>
        /// The names of <see cref="Parameters"/>, compared case-insensitively as RFC 9110 Section 11.2 matches a name, so
        /// a name added a second time in any case is found in one lookup.
        /// </summary>
        public HashSet<string> ParameterNames { get; } = new(StringComparer.OrdinalIgnoreCase);
    }
}
