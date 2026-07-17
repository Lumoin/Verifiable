using System.Diagnostics;
using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth;

/// <summary>
/// HTTP authentication scheme names used in the <c>Authorization</c> request
/// header and as <c>token_type</c> values in token endpoint responses, plus
/// per-scheme <c>IsXxx</c> predicates and a central <see cref="Equals"/>
/// method anchoring the comparison rule.
/// </summary>
/// <remarks>
/// <para>
/// Scheme names are <strong>case-insensitive</strong> in the
/// <c>Authorization</c> header per
/// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.1">RFC 9110 §11.1</see>,
/// but interoperability practice treats the canonical spellings
/// (<c>Bearer</c> per RFC 6750 §2.1, <c>DPoP</c> per RFC 9449 §7.1) as
/// authoritative and case-sensitive consumers exist in the wild. Comparisons
/// here are case-insensitive per the spec rule, centralised in
/// <see cref="Equals"/>.
/// </para>
/// <para>
/// Only schemes the library currently composes or recognises are listed.
/// Other schemes (<c>Digest</c>, <c>Negotiate</c>, …) are not added
/// speculatively — they appear here when a call site actually needs them.
/// </para>
/// </remarks>
[DebuggerDisplay("WellKnownAuthenticationSchemes")]
public static class WellKnownAuthenticationSchemes
{
    /// <summary>The UTF-8 source literal of <see cref="Bearer"/>.</summary>
    public static ReadOnlySpan<byte> BearerUtf8 => "Bearer"u8;

    /// <summary>
    /// The OAuth 2.0 Bearer authentication scheme per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-2.1">RFC 6750 §2.1</see>.
    /// Used in <c>Authorization: Bearer &lt;access-token&gt;</c> and as the
    /// <c>token_type</c> value in token endpoint responses.
    /// </summary>
    public static readonly string Bearer = Utf8Constants.ToInternedString(BearerUtf8);

    /// <summary>The UTF-8 source literal of <see cref="DPoP"/>.</summary>
    public static ReadOnlySpan<byte> DPoPUtf8 => "DPoP"u8;

    /// <summary>
    /// The DPoP authentication scheme per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 §7.1</see>.
    /// Used in <c>Authorization: DPoP &lt;access-token&gt;</c> when the
    /// access token is bound to a DPoP proof.
    /// </summary>
    public static readonly string DPoP = Utf8Constants.ToInternedString(DPoPUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Basic"/>.</summary>
    public static ReadOnlySpan<byte> BasicUtf8 => "Basic"u8;

    /// <summary>
    /// The HTTP Basic authentication scheme per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1">RFC 6749 §2.3.1</see> /
    /// <see href="https://www.rfc-editor.org/rfc/rfc7617">RFC 7617</see>. Used in
    /// <c>Authorization: Basic &lt;base64(id:secret)&gt;</c> for <c>client_secret_basic</c> client
    /// authentication at the token endpoint.
    /// </summary>
    public static readonly string Basic = Utf8Constants.ToInternedString(BasicUtf8);


    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="scheme"/> is the
    /// <c>Bearer</c> scheme.
    /// </summary>
    public static bool IsBearer(string scheme) => Equals(scheme, Bearer);

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="scheme"/> is the
    /// <c>DPoP</c> scheme.
    /// </summary>
    public static bool IsDPoP(string scheme) => Equals(scheme, DPoP);

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="scheme"/> is the
    /// <c>Basic</c> scheme.
    /// </summary>
    public static bool IsBasic(string scheme) => Equals(scheme, Basic);


    /// <summary>
    /// Returns the canonical instance for <paramref name="scheme"/> when it
    /// matches one of the well-known schemes, otherwise the input unchanged.
    /// </summary>
    public static string GetCanonicalizedValue(string scheme) => scheme switch
    {
        var s when IsBearer(s) => Bearer,
        var s when IsDPoP(s) => DPoP,
        var s when IsBasic(s) => Basic,
        _ => scheme
    };


    /// <summary>
    /// Compares two authentication scheme names per the library's comparison
    /// rule (ordinal, case-insensitive — scheme names are case-insensitive
    /// per RFC 9110 §11.1).
    /// </summary>
    public static bool Equals(string schemeA, string schemeB) =>
        string.Equals(schemeA, schemeB, StringComparison.OrdinalIgnoreCase);
}
