using System.Diagnostics;
using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth;

/// <summary>
/// HTTP method name constants used by the Authorization Server's matchers,
/// plus per-method <c>IsXxx</c> predicates and a central <see cref="Equals"/>
/// method anchoring the comparison rule.
/// </summary>
/// <remarks>
/// <para>
/// HTTP methods are <strong>case-sensitive on the wire</strong> per
/// <see href="https://www.rfc-editor.org/rfc/rfc9110#name-method-overview">RFC 9110 §9.1</see>:
/// "The method token is case-sensitive because it might be used as a gateway to
/// object-based systems with case-sensitive method names." The standard tokens
/// (`GET`, `POST`, etc.) are upper-case strings. The library accepts the
/// canonical upper-case form only; deployments behind an HTTP server that
/// normalises method case typically receive the canonical form. Comparisons
/// here use <see cref="StringComparison.Ordinal"/> for that reason — the same
/// rule the matchers' inline call sites used before this refactor, now
/// centralised in <see cref="Equals"/>.
/// </para>
/// <para>
/// Only the methods the library currently dispatches on are listed. Other HTTP
/// methods (PUT, PATCH, DELETE) are not added speculatively — they appear here
/// when a matcher actually needs them.
/// </para>
/// </remarks>
[DebuggerDisplay("WellKnownHttpMethods")]
public static class WellKnownHttpMethods
{
    /// <summary>The UTF-8 source literal of <see cref="Get"/>.</summary>
    public static ReadOnlySpan<byte> GetUtf8 => "GET"u8;

    /// <summary>
    /// The HTTP <c>GET</c> method per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#name-get">RFC 9110 §9.3.1</see>.
    /// </summary>
    public static readonly string Get = Utf8Constants.ToInternedString(GetUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Post"/>.</summary>
    public static ReadOnlySpan<byte> PostUtf8 => "POST"u8;

    /// <summary>
    /// The HTTP <c>POST</c> method per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#name-post">RFC 9110 §9.3.3</see>.
    /// </summary>
    public static readonly string Post = Utf8Constants.ToInternedString(PostUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Put"/>.</summary>
    public static ReadOnlySpan<byte> PutUtf8 => "PUT"u8;

    /// <summary>
    /// The HTTP <c>PUT</c> method per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#name-put">RFC 9110 §9.3.4</see>.
    /// Used by RFC 7592 §2.2 client update requests.
    /// </summary>
    public static readonly string Put = Utf8Constants.ToInternedString(PutUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Delete"/>.</summary>
    public static ReadOnlySpan<byte> DeleteUtf8 => "DELETE"u8;

    /// <summary>
    /// The HTTP <c>DELETE</c> method per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#name-delete">RFC 9110 §9.3.5</see>.
    /// Used by RFC 7592 §2.3 client deregistration requests.
    /// </summary>
    public static readonly string Delete = Utf8Constants.ToInternedString(DeleteUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Patch"/>.</summary>
    public static ReadOnlySpan<byte> PatchUtf8 => "PATCH"u8;

    /// <summary>
    /// The HTTP <c>PATCH</c> method per
    /// <see href="https://www.rfc-editor.org/rfc/rfc5789">RFC 5789</see>.
    /// Used by SSF 1.0 §8.1.1.3 stream-configuration update requests.
    /// </summary>
    public static readonly string Patch = Utf8Constants.ToInternedString(PatchUtf8);


    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="method"/> is the
    /// HTTP <c>GET</c> token.
    /// </summary>
    public static bool IsGet(string method) => Equals(method, Get);

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="method"/> is the
    /// HTTP <c>POST</c> token.
    /// </summary>
    public static bool IsPost(string method) => Equals(method, Post);

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="method"/> is the
    /// HTTP <c>PUT</c> token.
    /// </summary>
    public static bool IsPut(string method) => Equals(method, Put);

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="method"/> is the
    /// HTTP <c>DELETE</c> token.
    /// </summary>
    public static bool IsDelete(string method) => Equals(method, Delete);

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="method"/> is the
    /// HTTP <c>PATCH</c> token.
    /// </summary>
    public static bool IsPatch(string method) => Equals(method, Patch);


    /// <summary>
    /// Returns the canonical instance for <paramref name="method"/> when it
    /// matches one of the well-known tokens, otherwise the input unchanged.
    /// </summary>
    /// <remarks>
    /// Useful as a normalisation step before logging or telemetry tagging —
    /// the canonical instance is reference-equal to the corresponding static
    /// readonly field, so downstream string interning / comparison
    /// optimisations apply.
    /// </remarks>
    public static string GetCanonicalizedValue(string method) => method switch
    {
        var m when IsGet(m) => Get,
        var m when IsPost(m) => Post,
        var m when IsPut(m) => Put,
        var m when IsDelete(m) => Delete,
        var m when IsPatch(m) => Patch,
        _ => method
    };


    /// <summary>
    /// Compares two HTTP method tokens per the library's comparison rule
    /// (ordinal, case-sensitive — the canonical tokens are upper-case per
    /// RFC 9110 §9.1).
    /// </summary>
    /// <remarks>
    /// Centralised so the rule is documented once. If a future deployment
    /// needs to accept lowercase method tokens (some legacy reverse proxies
    /// emit them), the rule changes here, not at every call site.
    /// </remarks>
    public static bool Equals(string methodA, string methodB) =>
        string.Equals(methodA, methodB, StringComparison.Ordinal);
}
