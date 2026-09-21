using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.WellKnown;

/// <summary>
/// The <c>code_challenge_method</c> wire values per
/// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.3">RFC 7636 §4.3</see>. Comparison is ordinal.
/// </summary>
public static class WellKnownCodeChallengeMethods
{
    /// <summary>The UTF-8 source literal of <see cref="S256"/>.</summary>
    public static ReadOnlySpan<byte> S256Utf8 => "S256"u8;

    /// <summary>
    /// The <c>S256</c> PKCE code challenge method (RFC 7636 §4.3): the only method this server accepts. OAuth 2.1 §7.5.2
    /// forbids the plain method, HAIP 1.0 requires S256, and RFC 9700 §2.1.1 recommends a method that does not expose the verifier.
    /// </summary>
    public static string S256 { get; } = Utf8Constants.ToInternedString(S256Utf8);


    /// <summary>Whether <paramref name="value"/> is <see cref="S256"/>.</summary>
    public static bool IsS256(string value) => string.Equals(value, S256, StringComparison.Ordinal);

    /// <summary>The UTF-8 source literal of <see cref="Plain"/>.</summary>
    public static ReadOnlySpan<byte> PlainUtf8 => "plain"u8;

    /// <summary>
    /// The RFC 7636 §4.3 <c>plain</c> wire name, retained for recognizing refused requests and
    /// reading remote metadata. The server refuses it under every profile per
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-7.5.2">OAuth 2.1 §7.5.2</see>:
    /// "The plain code challenge method, defined in [RFC7636], is explicitly forbidden in OAuth 2.1."
    /// </summary>
    public static string Plain { get; } = Utf8Constants.ToInternedString(PlainUtf8);


    /// <summary>
    /// Whether a refused request or remote metadata value names <see cref="Plain"/>;
    /// recognition does not enable this transformation at the server.
    /// </summary>
    public static bool IsPlain(string value) => string.Equals(value, Plain, StringComparison.Ordinal);
}
