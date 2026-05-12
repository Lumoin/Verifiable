using System.Diagnostics;

namespace Verifiable.OAuth;

/// <summary>
/// HTTP header name constants used by the OAuth surface, plus per-header
/// <c>IsXxx</c> predicates and a central <see cref="Equals"/> method
/// anchoring the comparison rule.
/// </summary>
/// <remarks>
/// <para>
/// HTTP header names are <strong>case-insensitive on the wire</strong> per
/// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.1">RFC 9110 §5.1</see>.
/// The canonical spellings here use the conventions established by their
/// defining specifications (<c>Authorization</c> per RFC 9110 §11.6.2,
/// <c>DPoP</c> and <c>DPoP-Nonce</c> per RFC 9449 §4 and §8). Comparisons
/// here use <see cref="StringComparison.OrdinalIgnoreCase"/> per the spec
/// rule, centralised in <see cref="Equals"/>.
/// </para>
/// <para>
/// Only headers the library currently composes or reads are listed. Other
/// HTTP headers (<c>Content-Type</c>, <c>Accept</c>, <c>WWW-Authenticate</c>,
/// <c>Retry-After</c>, …) are not added speculatively — they appear here
/// when a call site actually needs them.
/// </para>
/// </remarks>
[DebuggerDisplay("WellKnownHttpHeaderNames")]
public static class WellKnownHttpHeaderNames
{
    /// <summary>
    /// The <c>Authorization</c> request header per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.6.2">RFC 9110 §11.6.2</see>.
    /// Carries the credentials the client uses to authenticate to the server.
    /// </summary>
    public static readonly string Authorization = "Authorization";

    /// <summary>
    /// The <c>DPoP</c> request header per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4">RFC 9449 §4</see>.
    /// Carries the proof JWS bound to the request the client is making.
    /// </summary>
    public static readonly string DPoP = "DPoP";

    /// <summary>
    /// The <c>DPoP-Nonce</c> response header per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 §8</see>
    /// (AS) and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">§9</see> (RS).
    /// Carries a server-issued nonce the client must echo in the next proof's
    /// <c>nonce</c> claim.
    /// </summary>
    public static readonly string DPoPNonce = "DPoP-Nonce";


    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="name"/> is the
    /// <c>Authorization</c> header.
    /// </summary>
    public static bool IsAuthorization(string name) => Equals(name, Authorization);

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="name"/> is the
    /// <c>DPoP</c> header.
    /// </summary>
    public static bool IsDPoP(string name) => Equals(name, DPoP);

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="name"/> is the
    /// <c>DPoP-Nonce</c> header.
    /// </summary>
    public static bool IsDPoPNonce(string name) => Equals(name, DPoPNonce);


    /// <summary>
    /// Returns the canonical instance for <paramref name="name"/> when it
    /// matches one of the well-known headers, otherwise the input unchanged.
    /// </summary>
    public static string GetCanonicalizedValue(string name) => name switch
    {
        var n when IsAuthorization(n) => Authorization,
        var n when IsDPoP(n) => DPoP,
        var n when IsDPoPNonce(n) => DPoPNonce,
        _ => name
    };


    /// <summary>
    /// Compares two HTTP header names per the library's comparison rule
    /// (ordinal, case-insensitive — header names are case-insensitive per
    /// RFC 9110 §5.1).
    /// </summary>
    public static bool Equals(string nameA, string nameB) =>
        string.Equals(nameA, nameB, StringComparison.OrdinalIgnoreCase);
}
