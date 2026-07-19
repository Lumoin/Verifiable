using System;
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
    public static readonly string RealmParameter = Utf8Constants.ToInternedString(RealmParameterUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ErrorParameter"/>.</summary>
    public static ReadOnlySpan<byte> ErrorParameterUtf8 => "error"u8;

    /// <summary>The <c>error</c> challenge attribute name (RFC 6750 §3).</summary>
    public static readonly string ErrorParameter = Utf8Constants.ToInternedString(ErrorParameterUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ErrorDescriptionParameter"/>.</summary>
    public static ReadOnlySpan<byte> ErrorDescriptionParameterUtf8 => "error_description"u8;

    /// <summary>The <c>error_description</c> challenge attribute name (RFC 6750 §3).</summary>
    public static readonly string ErrorDescriptionParameter = Utf8Constants.ToInternedString(ErrorDescriptionParameterUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ScopeParameter"/>.</summary>
    public static ReadOnlySpan<byte> ScopeParameterUtf8 => "scope"u8;

    /// <summary>The <c>scope</c> challenge attribute name (RFC 6750 §3).</summary>
    public static readonly string ScopeParameter = Utf8Constants.ToInternedString(ScopeParameterUtf8);

    /// <summary>The all-absent instance <see cref="TryParse"/> yields when parsing fails.</summary>
    private static readonly BearerTokenChallengeParameters EmptyParameters = new(
        Realm: null, Error: null, ErrorDescription: null, Scope: null, ResourceMetadata: null);


    /// <summary>
    /// Builds a <c>WWW-Authenticate</c> Bearer challenge value from the
    /// supplied attributes, emitted in signature order:
    /// <c>Bearer realm="…", error="…", error_description="…", scope="…", resource_metadata="…"</c>.
    /// A <see langword="null"/> or empty string is treated as absent.
    /// </summary>
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

        if(hasScope && !IsScopeList(scope!))
        {
            throw new ArgumentException(
                "scope must be single-space-delimited scope-tokens of %x21 / %x23-5B / %x5D-7E characters (RFC 6750 §3).", nameof(scope));
        }

        StringBuilder builder = new();
        builder.Append(WellKnownAuthenticationSchemes.Bearer);
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
            builder.Append(isFirstParameter ? " " : ", ");
            builder.Append(composed.AsSpan(WellKnownAuthenticationSchemes.Bearer.Length + 1));
        }

        return builder.ToString();
    }


    /// <summary>
    /// Parses a single <c>WWW-Authenticate</c> Bearer challenge value into its
    /// §3 attributes. Attribute names compare case-insensitively and values may
    /// be tokens or quoted strings per the RFC 9110 §11.2 <c>auth-param</c>
    /// grammar; attributes beyond the five recognized here are ignored (§3
    /// allows other auth-params).
    /// </summary>
    /// <param name="challengeValue">The header value, e.g. <c>Bearer realm="example", error="invalid_token"</c>.</param>
    /// <param name="parameters">The parsed attributes; all absent when parsing fails.</param>
    /// <returns>
    /// <see langword="false"/> when the scheme is not <c>Bearer</c>, no
    /// auth-param follows the scheme (§3: one or more required), the auth-param
    /// grammar is violated, a recognized attribute repeats (§3: MUST NOT appear
    /// more than once), or <c>resource_metadata</c> is not an absolute URI.
    /// </returns>
    public static bool TryParse(string challengeValue, out BearerTokenChallengeParameters parameters)
    {
        ArgumentNullException.ThrowIfNull(challengeValue);

        parameters = EmptyParameters;

        int position = SkipWhitespace(challengeValue, 0);
        int schemeStart = position;
        while(position < challengeValue.Length && challengeValue[position] != ' ' && challengeValue[position] != '\t')
        {
            position++;
        }

        if(!WellKnownAuthenticationSchemes.IsBearer(challengeValue[schemeStart..position]))
        {
            return false;
        }

        string? realm = null;
        string? error = null;
        string? errorDescription = null;
        string? scope = null;
        string? resourceMetadataValue = null;
        bool hasParsedParameter = false;

        while(position < challengeValue.Length)
        {
            //Element separators: OWS and commas — the RFC 9110 #rule permits
            //empty list elements between commas.
            while(position < challengeValue.Length
                && (challengeValue[position] == ' ' || challengeValue[position] == '\t' || challengeValue[position] == ','))
            {
                position++;
            }

            if(position >= challengeValue.Length)
            {
                break;
            }

            int nameStart = position;
            while(position < challengeValue.Length && IsTokenChar(challengeValue[position]))
            {
                position++;
            }

            if(position == nameStart)
            {
                return false;
            }

            string name = challengeValue[nameStart..position];

            position = SkipWhitespace(challengeValue, position);
            if(position >= challengeValue.Length || challengeValue[position] != '=')
            {
                return false;
            }

            position = SkipWhitespace(challengeValue, position + 1);
            if(position >= challengeValue.Length)
            {
                return false;
            }

            string? value = challengeValue[position] == '"'
                ? ReadQuotedString(challengeValue, position, out position)
                : ReadToken(challengeValue, ref position);
            if(value is null)
            {
                return false;
            }

            bool isStored = name switch
            {
                _ when IsParameterName(name, RealmParameter) => TryStore(ref realm, value),
                _ when IsParameterName(name, ErrorParameter) => TryStore(ref error, value),
                _ when IsParameterName(name, ErrorDescriptionParameter) => TryStore(ref errorDescription, value),
                _ when IsParameterName(name, ScopeParameter) => TryStore(ref scope, value),
                _ when IsParameterName(name, ProtectedResourceChallenge.ResourceMetadataParameter) => TryStore(ref resourceMetadataValue, value),
                _ => true
            };

            if(!isStored)
            {
                return false;
            }

            hasParsedParameter = true;

            position = SkipWhitespace(challengeValue, position);
            if(position < challengeValue.Length && challengeValue[position] != ',')
            {
                return false;
            }
        }

        if(!hasParsedParameter)
        {
            return false;
        }

        //resource_metadata must be an absolute http(s) URL (RFC 9728): both an absolute URI and an
        //http or https scheme are required.
        Uri? resourceMetadata = null;
        if(resourceMetadataValue is not null
            && (!Uri.TryCreate(resourceMetadataValue, UriKind.Absolute, out resourceMetadata)
                || (resourceMetadata.Scheme != Uri.UriSchemeHttps && resourceMetadata.Scheme != Uri.UriSchemeHttp)))
        {
            return false;
        }

        parameters = new BearerTokenChallengeParameters(realm, error, errorDescription, scope, resourceMetadata);

        return true;
    }


    /// <summary>
    /// Appends <c>{name}="{value}"</c> preceded by the scheme separator or the
    /// auth-param list separator, with RFC 9110 §5.6.4 quoted-string escaping
    /// of <c>"</c> and <c>\</c> in <paramref name="value"/>.
    /// </summary>
    private static void AppendQuotedParameter(StringBuilder builder, string name, string value, ref bool isFirstParameter)
    {
        string escaped = value
            .Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("\"", "\\\"", StringComparison.Ordinal);
        builder.Append(isFirstParameter ? " " : ", ");
        builder.Append(name).Append("=\"").Append(escaped).Append('"');
        isFirstParameter = false;
    }


    /// <summary>
    /// Stores <paramref name="value"/> into <paramref name="slot"/>, or returns
    /// <see langword="false"/> when the attribute already appeared — §3: the
    /// recognized attributes MUST NOT appear more than once.
    /// </summary>
    private static bool TryStore(ref string? slot, string value)
    {
        if(slot is not null)
        {
            return false;
        }

        slot = value;

        return true;
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
    /// The RFC 6749 Appendix A NQCHAR set restated by RFC 6750 §3 for scope
    /// values: %x21 / %x23-5B / %x5D-7E.
    /// </summary>
    private static bool IsNqChar(char c) =>
        c is '!' or (>= '#' and <= '[') or (>= ']' and <= '~');


    private static bool IsWithinNqsCharset(string value)
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
    /// Validates the RFC 6750 §3 scope shape restated from RFC 6749 §3.3:
    /// scope-tokens of NQCHAR characters delimited by single %x20 spaces, with
    /// no leading, trailing, or consecutive delimiters.
    /// </summary>
    private static bool IsScopeList(string value)
    {
        bool isPreviousDelimiter = true;
        foreach(char c in value)
        {
            if(c == ' ')
            {
                if(isPreviousDelimiter)
                {
                    return false;
                }

                isPreviousDelimiter = true;
                continue;
            }

            if(!IsNqChar(c))
            {
                return false;
            }

            isPreviousDelimiter = false;
        }

        return !isPreviousDelimiter;
    }


    /// <summary>
    /// Whether every character is representable in an RFC 9110 §5.6.4
    /// quoted-string: HTAB, SP, or a visible ASCII character — <c>"</c> and
    /// <c>\</c> are representable through quoted-pair escaping.
    /// </summary>
    private static bool IsQuotedStringRepresentable(string value)
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
    /// An RFC 9110 §5.6.2 tchar: visible ASCII except delimiters.
    /// </summary>
    private static bool IsTokenChar(char c) =>
        c is (>= '0' and <= '9') or (>= 'a' and <= 'z') or (>= 'A' and <= 'Z')
        or '!' or '#' or '$' or '%' or '&' or '\'' or '*' or '+' or '-' or '.'
        or '^' or '_' or '`' or '|' or '~';


    private static int SkipWhitespace(string value, int position)
    {
        while(position < value.Length && (value[position] == ' ' || value[position] == '\t'))
        {
            position++;
        }

        return position;
    }


    /// <summary>
    /// Reads an RFC 9110 §5.6.4 quoted-string starting at
    /// <paramref name="openingQuote"/>, unescaping quoted-pairs, and advances
    /// <paramref name="position"/> past the closing quote. An unterminated
    /// quoted-string yields <see langword="null"/>.
    /// </summary>
    private static string? ReadQuotedString(string value, int openingQuote, out int position)
    {
        StringBuilder builder = new();
        for(int i = openingQuote + 1; i < value.Length; ++i)
        {
            char c = value[i];
            if(c == '\\' && i + 1 < value.Length)
            {
                builder.Append(value[i + 1]);
                ++i;
                continue;
            }

            if(c == '"')
            {
                position = i + 1;

                return builder.ToString();
            }

            builder.Append(c);
        }

        position = value.Length;

        return null;
    }


    /// <summary>
    /// Reads a token value and advances <paramref name="position"/> past it; an
    /// empty token yields <see langword="null"/>.
    /// </summary>
    private static string? ReadToken(string value, ref int position)
    {
        int start = position;
        while(position < value.Length && IsTokenChar(value[position]))
        {
            position++;
        }

        return position > start ? value[start..position] : null;
    }
}
