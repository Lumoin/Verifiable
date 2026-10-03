namespace Verifiable.OAuth;

/// <summary>
/// The part of a <c>resource</c> indicator that
/// <see cref="ResourceIndicator.Parse"/> found unusable, in the
/// order the reader inspects the value. Only the first part that fails is named; later parts are
/// never inspected once one has already failed.
/// </summary>
public enum ResourceIndicatorFault
{
    /// <summary>
    /// Every part admitted the value: it is an ASCII
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A"><c>absolute-URI</c></see>
    /// with no fragment, and, when its scheme is <c>http</c> or <c>https</c>, a non-empty authority
    /// with no <c>userinfo</c>. This is the reader's success marker, never a refusal returned by
    /// <see cref="ResourceIndicator.Parse"/>.
    /// </summary>
    None,

    /// <summary>The original indicator is null or empty; there is no scheme for
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A"><c>absolute-URI</c></see>
    /// to begin with.</summary>
    Empty,

    /// <summary>
    /// A code point above U+007F is present. RFC 3986's ABNF "defines its terminal values to be
    /// non-negative integers (codepoints) based on the US-ASCII coded character set"
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3986#section-2">RFC 3986 section 2</see>).
    /// </summary>
    NonAscii,

    /// <summary>
    /// The <c>scheme</c> production
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">RFC 3986 Appendix A</see>,
    /// <c>scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )</c>) is not satisfied: there is no
    /// <c>:</c>, the scheme is empty, or its first character is not an ASCII letter.
    /// </summary>
    Scheme,

    /// <summary>
    /// The <c>authority</c> production
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">RFC 3986 Appendix A</see>,
    /// <c>authority = [ userinfo "@" ] host [ ":" port ]</c>) is not satisfied: more than one
    /// <c>@</c>, an inadmissible <c>userinfo</c>, <c>port</c> or <c>reg-name</c> character, an
    /// unterminated or malformed IP-literal, or a <c>]</c> not followed by <c>:</c> or the end.
    /// </summary>
    Authority,

    /// <summary>
    /// The path is not a well-formed
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A"><c>path-abempty</c>,
    /// <c>path-absolute</c> or <c>path-rootless</c></see>: an inadmissible <c>pchar</c>, or, with
    /// no authority, a second <c>/</c> immediately after the leading one where
    /// <c>path-absolute</c> requires a non-empty first segment.
    /// </summary>
    Path,

    /// <summary>
    /// The <c>query</c> production
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">RFC 3986 Appendix A</see>,
    /// <c>query = *( pchar / "/" / "?" )</c>) is not satisfied by a character after the <c>?</c>.
    /// </summary>
    Query,

    /// <summary>
    /// A <c>#</c> is present. No component of <c>absolute-URI</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">RFC 3986 Appendix A</see>)
    /// admits it, and RFC 8707 forbids a fragment component outright
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 section 2</see>).
    /// </summary>
    Fragment,

    /// <summary>
    /// A <c>%</c> is not followed by two hexadecimal digits, so it is not a well-formed
    /// <c>pct-encoded</c> triplet
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3986#section-2.1">RFC 3986 section 2.1</see>;
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">Appendix A</see>,
    /// <c>pct-encoded = "%" HEXDIG HEXDIG</c>).
    /// </summary>
    PercentEncoding,

    /// <summary>
    /// The scheme is <c>http</c> or <c>https</c> but the value has no authority: both
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-4.2.1"><c>http-URI</c></see> and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-4.2.2"><c>https-URI</c></see>
    /// require <c>"://" authority</c>.
    /// </summary>
    HttpAuthority,

    /// <summary>
    /// The scheme is <c>http</c> or <c>https</c> and the authority carries a <c>userinfo</c>
    /// subcomponent, an <c>"@"</c> after which the host begins. RFC 9110 treats its presence as an
    /// error (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-4.2.4">RFC 9110 section
    /// 4.2.4</see>): "Before making use of an &quot;http&quot; or &quot;https&quot; URI reference
    /// received from an untrusted source, a recipient SHOULD parse for userinfo and treat its
    /// presence as an error; it is likely being used to obscure the authority for the sake of
    /// phishing attacks."
    /// </summary>
    HttpUserInfo,

    /// <summary>
    /// The scheme is <c>http</c> or <c>https</c> but the authority's host is empty: RFC 9110
    /// requires a sender not generate, and a recipient reject, an
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-4.2.1"><c>http</c></see> or
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-4.2.2"><c>https</c></see>
    /// URI with an empty host identifier.
    /// </summary>
    HttpHost,
}
